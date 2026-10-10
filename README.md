# aaoracled

Daemon that enables an iOS/iPadOS device to be used as a sockpuppet/oracle
that passes App Attest challenges on behalf of other devices.

Created by [Parker Wahle](https://github.com/regulad). Anthropic's Claude 5 series models
(Fable, Opus, Sonnet & Haiku) were used to rapidly iterate.

## Install

You can either build `aaoracled` yourself or add my Cydia repo `https://ios.regulad.xyz`
to your package manager and install `xyz.regulad.aaoracled`.

## Building

`aaoracled` ships as a single Debian package (`xyz.regulad.aaoracled`)
containing both the `OracledDCPatch` tweak (injected into `devicecheckd`)
and the `aaoracled` CLI/daemon itself. See [SETUP.md](SETUP.md) first for
preparing the jailbroken test device and the laptop-side build toolchain
(theos).

Build it:

```bash
./build_and_sign.sh                  # debug build, auto-incrementing version
FINALPACKAGE=1 ./build_and_sign.sh   # final release build
```

This produces `packages/xyz.regulad.aaoracled_<version>_iphoneos-arm64e.deb`.

Install it on the device:

```bash
scp packages/xyz.regulad.aaoracled_*.deb <device-alias>:/tmp/aaoracled.deb
ssh <device-alias> 'sudo apt install /tmp/aaoracled.deb -y'
```

**Before installing, confirm your device's exact build.** `Tweak.x` hooks
`AppAttestInternal` at hardcoded, Ghidra-derived static offsets that are
only valid for one specific `dyld_shared_cache` build. This project's
offsets were extracted from, and are currently verified against, an
**iPad mini 4 (`iPad5,1`, A8/T7000) running iPadOS 15.8.8, build `19H422`.**
Installing on any other device model or OS build without first re-deriving
the offsets (see `AGENTS.md`'s Ghidra workflow) will either silently call
the wrong function or crash `devicecheckd`.

## Use

The full HTTP surface is documented as an OpenAPI 3.1 contract in
[`openapi.yaml`](openapi.yaml). Once installed, `aaoracled` listens on
`127.0.0.1:8181` on the device — reach it over an SSH tunnel
(`ssh -L 8181:127.0.0.1:8181 <device-alias>`) or `curl` it directly from an
on-device shell.

Create (mint + attest) a key under any App ID you choose — this is the core
oracle primitive:

```bash
CDH=$(openssl rand -base64 32)   # in real use: base64(SHA-256(server challenge))

curl -s -X POST http://127.0.0.1:8181/keys \
  -H 'Content-Type: application/json' \
  -d "{\"appId\": \"ABCDE12345.com.example.myapp\", \"environment\": \"development\", \"clientDataHash\": \"$CDH\"}"
```

If the relying party's app attests over its own key ID instead of a server
challenge (clientDataHash = SHA256 of the keyId, which can't be known before
the key exists), pass the literal string instead and the daemon derives it
after `generateKey`:

```bash
curl -s -X POST http://127.0.0.1:8181/keys \
  -H 'Content-Type: application/json' \
  -d "{\"appId\": \"ABCDE12345.com.example.myapp\", \"environment\": \"production\", \"clientDataHash\": \"sha256(keyId)\"}"
```

List every App Attest key resident on the device (not just ones `aaoracled`
itself minted — see Vulnerability & Mitigation below):

```bash
curl -s http://127.0.0.1:8181/keys
```

Sign an arbitrary challenge with any listed key. The `key` value returned
by `GET /keys` must be URL-encoded before it goes in a path — it contains
`:` plus base64's `+`/`/`/`=`:

```bash
KEY='aa:9Ur1MdQmPZZbOLudX+0T2lAbouGfiPZH1GQOIRyp88Y=d:...'
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$KEY")

curl -s -X POST "http://127.0.0.1:8181/keys/$ENC/sign" \
  -H 'Content-Type: application/json' \
  -d "{\"clientDataHash\": \"$CDH\"}"
```

Delete a key from the device permanently:

```bash
curl -s -X DELETE "http://127.0.0.1:8181/keys/$ENC"
```

## Vulnerability & Mitigation

Apple's [App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
service can be used to prove that a request has been sanctioned by a
genuine Apple iOS or iPadOS device (T2 and Apple Silicon Macs use a
different mechanism). When used exclusively for that purpose, it is
adequate, and can serve as an anchor to limit the number of sessions
launched by a specific device (Apple may rate-limit attestation key
creation attempts per device). However, commercial anti-tampering SDK
providers like [Radar](https://docs.radar.com/geofencing/fraud),
[Guardsquare](https://www.guardsquare.com/), and [Approov](https://approov.io/)
often place too much trust in App Attest's ability to vouch for a device's
or application's integrity. This is caused, at least in part, by Apple's
own marketing of App Attest, which does not clearly disclose that App
Attest is not fully qualified to attest to the integrity of a non-secure
environment.

`aaoracled` makes that shortfall concrete. It mints App Attest keys for
App IDs that the device it runs on could never run legitimately, turning
an old, jailbroken device into a sockpuppet that forges attestations for
apps that would otherwise require current hardware. Paired with an iOS
simulator or a stripped-down app runtime, a request attested by
`aaoracled` is indistinguishable from one emitted by a genuine, up-to-date
device: App Attest keys carry no device-specific metadata — no OS version
and no hardware model string — so a publisher cannot tell which device or
OS release minted a key. That gap matters because publishers routinely
raise the minimum OS version of their apps to keep unpatched or
known-compromised devices out, and an attestation minted below that floor
sails straight past the check. Apple *can* close it: it could refuse to
sign certificate requests emitted by `com.apple.devicecheckd` when the
SEP-backed key came from a device whose maximum supported iOS is lower
than the minimum iOS of the App ID named in the request. As of
publication, Apple's App Attest CSR-signing infrastructure performs no
such check and will sign any request carrying a well-formed App ID. The OS
floor is only the most legible casualty of a more general limit: what an
App Attest assertion actually proves is that a genuine Secure Enclave
exists somewhere behind the request — not which device holds it, not what
that device is running, and not what software asked it to sign.

If you are developing an app that needs to enforce the integrity of its
operating environment, please note the following when using App Attest:

1. App Attest can **only** be used to advocate for the presence of a
   legitimate, Apple-provisioned Secure Element *somewhere* that the
   request sender controls. It is a strong trust signal, but it can only be
   used to prove that a real Apple device is being used — never that your
   app or the OS is unmodified, since a device that has been completely
   compromised via a jailbreak still has a fully operational, functional
   Secure Enclave.
2. Use App Attest alongside other difficult-to-spoof checks, like
   MobileSubstrate/ElleKit detection — and always remember that **any
   client-side restriction can be bypassed; anything life-or-death *must*
   be enforced server-side!**

This issue was privately disclosed to Apple as Security Research
submission #OE1107928141015. The submission was allowed to close before
the publication of this research tool.

## License

All original work in this repository is licensed under
[AGPLv3](./LICENSE.md).
