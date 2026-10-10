# AGENTS.md — aaoracled

Instructions for an LLM agent working in this repository: what this project
is, the rules to follow, how the code is organized, and how to use the
Ghidra/Frida tooling to find and validate the offsets the tweak depends on.

For **human** environment setup (jailbreak, SSH, Frida install, confirming
device build), see `SETUP.md`. For the project pitch/outline, see
`README.md`. The detailed research narrative (session-by-session findings)
has been moved out of this repo as of the 2026-09-08 docs reorg — ask
Parker if you need it; it will eventually be distilled into `README.md`.

The build toolchain (theos) targets Linux/macOS; on Windows, run it inside
WSL. A ready-made WSL base image with the needed toolchain preinstalled is
published at
[`ghcr.io/regulad/dotfiles:latest-fedora`](https://github.com/regulad/dotfiles) —
see `SETUP.md` step 9 for the full build toolchain setup either way.

## Project

**aaoracled** — a research tool demonstrating that Apple App Attest's
identity binding is enforced entirely by hookable AP-side userspace code
(`devicecheckd`), not the Secure Enclave, on a jailbroken iPad mini 4. It
patches `devicecheckd` (via a tweak, `OracledDCPatch`) to accept a
caller-supplied App ID regardless of the calling process's actual
code-signing identity, and ships a REST daemon (`aaoracled`) that drives
`DCAppAttestService` directly to exercise that gap.

This is authorized security research. Parker owns all hardware and Apple
Developer credentials involved. This is not adversarial tooling aimed at a
third party. If anything significant is found, it will be responsibly
disclosed to Apple before any public presentation of this work.

## Scope constraints

1. **Only ever attest against an Apple Developer Team ID you are
   authorized to use.** For *this project's own* testing that means
   Parker's team (see `.claude/ENVIRONMENT.md` for the concrete value) and
   App/Bundle IDs Parker has created under it, plus the deliberate
   negative-control identities used for the identity-legitimacy matrix (a
   never-registered bundle; a random fake team).

   `aaoracled` is a published tool, so this constraint is about
   authorization, not about one specific team. A contributor or downstream
   user may hold a *different* Team ID they are legitimately authorized to
   exercise it against — their own team, an employer's, or one named in a
   red-team engagement — and that is their call to make and their
   authorization to hold, not something this repo can grant or verify.
   What stays non-negotiable: never target an identity you have no
   authorization for. When a contribution's testing narrative rests on an
   authorization that isn't visible in the diff (e.g. a PR reporting a
   mint under a team that isn't Parker's), that claim is the contributor's
   to substantiate — don't assume malice, and don't assume permission
   either; just get it on the record in the thread before the work is
   treated as validated.
2. **Only ever point the oracle at a relying-party server Parker controls.**
   Never send attestations/assertions produced by this tool to a third
   party's production backend, even "just to see."
3. **Only ever use hardware Parker owns.** Never use attestation material
   sourced from someone else's device.
4. Frame this as "App Attest fails open — here is the reproducible gap and
   here is the mitigation," not as a weaponized bypass tool. Every
   deliverable should pair the attack with server-side mitigation guidance.
5. All keys currently resident on the reference test device are Parker's
   own testing material — safe to list, sign with, and delete via the
   device-wide key endpoints. Don't assume this holds on any other device.

## Repository layout

One theos project at the repo root — no `poc/` or per-component
subdirectory:

- `Makefile`, `control`, `layout/` — the combined package definition. One
  flat Makefile declares two theos target instances in sequence
  (`TWEAK_NAME = OracledDCPatch`, then `TOOL_NAME = aaoracled`) sharing one
  `control`/`layout/`, producing exactly one `.deb`.
- `Tweak.x`, `OracledDCCommon.h`, `OracledDCPatch.plist` — the tweak,
  injected into `devicecheckd`. This is where the identity-forgery hooks,
  the Ghidra-derived offsets, and the sentinel-based list/sign/delete
  dispatch live.
- `oracled.m`, `Info.plist`, `entitlements.plist`, `openapi.yaml` — the
  `aaoracled` CLI/daemon: a REST server driving `DCAppAttestService` and,
  via the tweak's sentinel channel, the device-wide key operations. The
  OpenAPI contract in `openapi.yaml` is the source of truth for the HTTP
  surface — keep it and `oracled.m`'s `route()` in sync.
- `build_and_sign.sh` — builds and packages both targets into one `.deb`.
- `fixtures/` — the App A baseline app and the relying-party test harness
  (`fixtures/appa/`, `fixtures/harness/`), used to establish and re-verify
  the genuine, unforged control case the forgery work is measured against.
  Not part of the shipped `.deb`. See `fixtures/README.md`.
- `artifacts/` — codesigning material, gitignored.
- `packages/` — built `.deb` output, gitignored.

## Background — App Attest mechanics (don't re-derive)

`DCAppAttestService` generates an EC keypair in the Secure Enclave
(`generateKey()`), produces a WebAuthn-shaped CBOR attestation object over a
server challenge (`attestKey(_:clientDataHash:)`), and signs subsequent
requests with an incrementing counter
(`generateAssertion(_:clientDataHash:)`). The attestation's cert chains to
Apple's App Attest Root CA and cryptographically proves: (a) the key lives
in a genuine Apple SEP, (b) the key is bound to one App ID via
`rpIdHash = SHA256(TeamID.BundleID)`, (c) prod vs. dev environment (AAGUID),
(d) freshness (challenge folded into a credCert extension, OID
`1.2.840.113635.100.8.2`).

**What it does NOT prove:** no binary/OS integrity measurement, no
jailbreak detection, no device-model/SoC field anywhere in the attestation.
A compromised kernel can drive the SEP just as validly as stock iOS — the
SEP itself is untouched by application-processor jailbreaks (checkm8
included), so it signs whatever the calling process asks, authentically.
App Attest is a *key-possession + App-ID-binding* proof; treating it as a
device- or build-integrity proof is trusting a field that doesn't exist.

**Threat model:** the SEP is trusted; the entire AP (kernel, daemons,
`devicecheckd`, the calling app, all IPC) is attacker-controlled. That's
what the jailbreak buys, and it's honest — checkm8 compromises the AP while
leaving the SEP untouched, which is *why* the SEP keeps signing
authentically.

**Real call path:** `app ──XPC──▶ devicecheckd ──▶ SEP` (key gen/sign) and
`──▶ Apple App Attest CA` (cert issuance, network). `devicecheckd` derives
the caller's identity from the caller's kernel-attested audit token
(`SecTaskCreateWithAuditToken`) and from a LaunchServices bundle-record
lookup (`bundleRecordForAuditToken:`, both the public 2-arg and private
3-arg selectors) — not from anything the client passes in the XPC message
except an opaque per-installation UUID token
(`com.apple.DC.AppAttestAppUUID`, echoed back on every call, not an
identity claim).

## Current architecture

### Identity forgery (`Tweak.x`)

- `OracledForcedAppID()` (in `OracledDCCommon.h`) reads a file-based
  override: `jbroot(@"/var/mobile/Library/Preferences/xyz.regulad.aaoracled.forge-appid.txt")`.
  Presence = force this App ID for the next call devicecheckd handles;
  absence = pass through untouched. **This override is GLOBAL and
  UNSCOPED** — every caller devicecheckd services is affected while the
  file exists, not just the request under test. Write it immediately before
  a test call, delete it (or let `oracled.m`'s `clearForgeAppId()` do so)
  immediately after. Never leave it set between sessions.
- That file is a **property list**, not line-oriented text (changed
  2026-10-10). Keys are defined once in `OracledDCCommon.h`
  (`kOracledForgeKeyAppID`, and `kOracledForgeKeyEnvironment` which is
  RESERVED and deliberately unread) — reference those constants, never
  re-spell the key strings. A malformed or truncated file now parses as nil
  and reads as "no override", instead of the old behavior where any bytes at
  all became a forged App ID. The filename keeps its historical `.txt`
  spelling on purpose: libSandy's grant is path-exact, so renaming means
  editing `layout/Library/libSandy/OracledDCPatch.plist` too and re-verifying
  the sandbox grant on-device — and a grant that stops matching presents
  exactly like a broken forge.
- Both `%hook LSBundleRecord` selectors (`bundleRecordForAuditToken:error:`
  — public, 2-arg — and `_bundleRecordForAuditToken:checkNSBundleMainBundle:error:`
  — private, 3-arg) must be hooked; `AppAttest_AppAttestation_IsEligibleApplication`
  calls the public one specifically, and it's a genuinely separate,
  non-delegating implementation from the private one.
- The forged identity is served via `OracledFakeBundleRecord`, a *runtime*
  subclass of the real `LSApplicationRecord` (not `LSBundleRecord` — the
  `isKindOfClass:[LSApplicationRecord class]` check in
  `IsEligibleApplication` requires the actual ancestor, not a sibling; not
  `NSObject` — several `isKindOfClass:`/`respondsToSelector:` probes need
  genuine inheritance to succeed). Built via `objc_allocateClassPair`/
  `class_addMethod`/`objc_registerClassPair` at first use (a compile-time
  `@interface X : LSApplicationRecord` fails to link — that class lives in
  a private framework this project doesn't link against). Per-instance
  identity is stored via `objc_setAssociatedObject`, not real ivars.
  Overrides `-init` to `return self` (the inherited `LSRecord` initializer
  dereferences internal state a bare `+alloc` never populates and will
  crash the daemon), plus `applicationIdentifier`, `teamIdentifier`,
  `bundleIdentifier`, `entitlements`, `executableURL`, `description`,
  `isProfileValidated`, `isUPPValidated`, `appClipMetadata`, and a
  `methodSignatureForSelector:`/`forwardInvocation:` catch-all for anything
  else. **If a new caller-triggered selector shows up unhandled, add a real
  typed override — don't rely on the catch-all for anything BOOL-returning**:
  `methodSignatureForSelector:`'s catch-all always claims an 8-byte object
  return (`"@@:"`) regardless of the real target's signature, and an
  unoverridden inherited `BOOL` getter resolves through a real LSRecord
  accessor template that hard-asserts a live LaunchServices database
  session exists — which a fake object never has — producing a genuine
  `SIGABRT` (`__LSRECORD_IS_CRASHING_DUE_TO_A_CALLER_BUG__`), not a catchable
  exception. See the Frida workflow section below for how to find the
  missing selector when this happens.

### Device-wide key access (list / sign / delete any App Attest key)

AppAttestInternal stores *every* App Attest private key, from *every app*,
under one shared keychain service (`"com.apple.appattest.identities"`),
addressed by an opaque label with no per-app keychain access-group
isolation visible to `devicecheckd`. Since this project's premise is a
fully compromised `devicecheckd`, every key on the device is reachable, not
just ones this tool minted — this is a structural consequence of where App
Attest stores keys, not a separate vulnerability from the identity-forgery
finding above.

Reached via three private, non-exported AppAttestInternal functions, called
by computed address (see "Finding and validating offsets" below):

```c
id      _getAllCredentialKeychainLabels(void);
long    _copy_keychain_item(id service, id label, int *status, void **out);  // -> SecKeyRef
BOOL    _deleteCredentialKeychainWithLabel(id label);
```

`_deleteCredentialKeychainWithLabel` is **idempotent by Apple's own design**
(verified live via Frida): it returns success both when the key existed and
was removed, and when it was already gone (Apple's own
`_delete_keychain_item` treats `SecItemDelete`'s real success and
`errSecItemNotFound` as equally successful). `aaoracled`'s `DELETE
/keys/{key}` reflects this directly — 200 whether or not the key was
present, 500 only for a genuine underlying failure, no invented 404
bookkeeping on top.

**Dispatch mechanism — sentinel values smuggled through the existing
`appAttestationAssert:keyId:clientDataHash:completion:` selector**, checked
before the normal forge/`%orig` path (mirrors Apple's own hidden
`__debug_aa_kc_list__`/`__debug_aa_kc_cleanup__` debug commands, which are
gated behind `os_variant_allows_internal_security_policies()` — confirmed
always false on non-internal devices, so this project rolls its own
channel over the same already-proven-reliable completion callback instead).
All three sentinels live once in `OracledDCCommon.h`, shared by `Tweak.x`
and `oracled.m` — never duplicate them per-file (see the "don't duplicate
constants across files" lesson below):

```objc
kOracledListSEKeysSentinel   // -> lists every key on the device
kOracledRawLabelSignPrefix   // + <label> -> raw ECDSA sign with that key
kOracledRawLabelDeletePrefix // + <label> -> delete that key
```

`oracled.m`'s `GET/POST /keys`, `POST /keys/{key}/sign`, and
`DELETE /keys/{key}` are backed entirely by this mechanism — there is
deliberately **no in-memory key store** in `oracled.m`; a key that was just
minted shows up in the next `GET /keys` like any other, addressed by its
own opaque label (not the `keyId` `POST /keys` returned).

Keys are standard base64 (RFC 4648 §4, i.e. `+`/`/`/`=`, not URL-safe) plus
a literal `:` separator — percent-encode the whole value when putting one
in a URL path (`/` in particular must become `%2F`).

### Environment selection (dev vs prod / the AAGUID) — settled 2026-10-10

The App Attest environment is chosen by **one** private function, and it is
NOT chosen by the fake bundle record's `entitlements` dictionary (that
dictionary is never read — `-entitlements` is never even sent to the record
on the create path).

`generateEnvironmentByAppSigning(audit_token_t *)`, AppAttestInternal
`+0x8244` (static/unslid `0x1c32d1244` on iPad5,1 / 19H422). It returns an
int in `x0`, and that return value alone decides the environment:

| return | environment |
|--------|-------------|
| `0`    | development |
| `1`    | production  |

Verified by overriding the return live with Frida: forcing `0` where the
natural answer was `1` flipped the minted credential's label from `=p:` to
`=d:`. Two internal paths reach that return:

1. **Record path.** `[LSBundleRecord bundleRecordForAuditToken:error:]` —
   the selector the tweak already hooks — then `isKindOfClass:
   LSApplicationRecord`, then `-isProfileValidated`, `-isUPPValidated`, and
   `-isBeta`. A caller whose profile is NOT validated yields production
   (`+0x8410` → `mov w21, #1`); this is why ordinary jailbreak-signed apps
   mint production keys.
2. **SecTask fallback**, taken when the record is nil or not an
   `LSApplicationRecord`. `SecTaskCreateWithAuditToken` on the caller's
   token, then `SecTaskCopyValueForEntitlement` for
   `com.apple.developer.devicecheck.appattest-environment`
   (symbol `kAAAppAttestationEnvironmentOverride`), `caseInsensitiveCompare:`
   against `@"production"` / `@"development"` (symbols
   `KAAAppAttestationEnvironment{Production,Development}`). This is the path
   `entitlements.plist`'s own note describes, and it is the path **aaoracled
   itself** takes when unforged: aaoracled is a bare binary with no installed
   app bundle, so LaunchServices has no record for it, the record path bails,
   and its hardcoded `development` entitlement decides.

**Hook the return value, not either input.** Overriding
`generateEnvironmentByAppSigning`'s return sits downstream of *both* paths,
so it works regardless of whether a bundle record exists, what the fake
record answers for the validator selectors, or what entitlement the caller
carries. Driving it from the inputs instead means modelling that whole
branch tree — and note the fake record's `isProfileValidated`/
`isUPPValidated` overrides (added purely to stop an LSRecord getter from
hard-faulting) are themselves load-bearing for environment as a side
effect, which is the kind of coupling worth not depending on.

**The environment is observable for free.** It is baked into the credential
keychain label's `p`/`d` character at `generateKey` time (see
`openapi.yaml`'s `Key` schema), so `GET /keys` can report it per key with no
attestation and no network. That is the cheapest possible verification
surface for any environment work — one request, no CA involvement.

### Testing discipline

- Hardcode `OracledForcedAppID()`'s return value (or leave the forge file
  written) only for one deliberate, immediate test — then revert to
  file-absent pass-through and rebuild/redeploy before doing anything else.
  A stale forge file has caused real crashes and false "regression" scares
  by silently contaminating supposedly-unforced baseline checks.
- Verify App A's genuine (unforged) baseline still works after any change
  to `Tweak.x` — a silent regression here won't necessarily throw an error.
- Always `launchctl kickstart -k system/com.apple.devicecheckd` (and
  `system/xyz.regulad.aaoracled` if testing daemon-side state) immediately
  before a new Frida trace attempt, not just when a crash is suspected — a
  Frida session left attached across several earlier attach/detach cycles
  on the same long-lived process can silently stop delivering new hooks
  with no error.
- Don't trust `launchctl list`'s exit-status column as "currently dead" —
  it shows the *last* exit status, including one from a kickstart you just
  issued yourself. Confirm liveness via an actual `/health` curl or a live
  Frida `enumerate_processes()` check. Check status *before* issuing a new
  kickstart if you need the process's own real prior exit reason.

## Finding and validating offsets (Ghidra workflow)

`Tweak.x` calls several AppAttestInternal functions that are private
(non-exported, not `dlsym`-able) by hardcoded static address + ASLR slide.
These addresses are valid for exactly one `dyld_shared_cache` build and
**must be re-derived whenever the target device's OS build changes** (see
`SETUP.md` step 3). This is the methodology that works — black-box dynamic
tracing alone is not sufficient to find *which* function/selector is
responsible for a given behavior; use Ghidra for that, then Frida to
confirm the live address and behavior.

Tooling: [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp)
(see `SETUP.md` step 7 for installing it). Ghidra project name convention
for this device: `oracled`.

1. **Extract the target dylib out of the combined dyld shared cache — don't
   import the whole 2.7GB cache as one program.** Private frameworks like
   `AppAttestInternal` have no standalone file on disk; the real Mach-O
   lives inside the split
   `/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64*` set
   (reachable only via `/rootfs` over SSH). `scp` that set once, then use
   Ghidra's own scripting API (needs `GHIDRA_MCP_ALLOW_SCRIPTS=1` or
   equivalent) to pull just the one dylib you need:
   ```java
   FileSystemService fsService = FileSystemService.getInstance();
   FSRL containerFSRL = fsService.getLocalFSRL(new File(cachePath));
   FileSystemRef fsRef = fsService.probeFileForFilesystem(containerFSRL, TaskMonitor.DUMMY, null);
   GFileSystem fs = fsRef.getFilesystem(); // ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem
   // walk fs.getListing(...) recursively for the GFile whose .getPath() matches
   // e.g. "/System/Library/PrivateFrameworks/AppAttestInternal.framework/AppAttestInternal"
   FSRL targetFSRL = target.getFSRL(); // dyldcachev1:// protocol — required
   LoadResults results = AutoImporter.importByUsingBestGuess(targetFSRL, project, "/", this, log, TaskMonitor.DUMMY);
   results.save(TaskMonitor.DUMMY);
   ```
   Do **not** write the extracted bytes to a plain file and re-import that —
   Ghidra's Mach-O loader refuses it (lazy-bind/stub info only resolves
   correctly through the live `DyldCacheFileSystem`). Leaf frameworks (like
   `AppAttestInternal`) extract cleanly this way; umbrella/reexporting
   frameworks (like `CoreServices`) pull in a large combined multi-image
   program instead — for those, live Frida introspection is often faster
   than fighting Ghidra's addressing.
2. **Don't call `mcp__ghidra__open_program`.** It opens a GUI CodeBrowser
   tool window and blocks on an "analyze now?" dialog if the program hasn't
   been analyzed yet. Every other Ghidra MCP tool (`search_functions`,
   `decompile_function`, `disassemble_function`, `run_script_inline`, ...)
   accepts a program by name without it ever being "open" in a tool window.
3. **Decompile and read, don't guess selector names.** Use
   `mcp__ghidra__search_functions` to locate a candidate by name fragment,
   `mcp__ghidra__decompile_function` (pass the program name and address) to
   read its pseudocode. Follow the call graph outward from a known entry
   point (e.g. the exported `AppAttest_AppAttestation_CreateKey`) to find
   the private helpers it calls.
4. **Get real ObjC method type encodings from the live runtime, not from
   guessing.** Frida's high-level `.type` property can return `undefined`
   for some hooked methods — fall back to raw runtime calls:
   ```js
   const cls = ObjC.classes.SomeClass;
   const method = cls['- someSelector:'] ?? cls['+ someSelector:'];
   const encoding = method.implementation; // then class_getInstanceMethod/method_getTypeEncoding
   ```
   (`class_getInstanceMethod`/`class_getClassMethod` +
   `method_getTypeEncoding` via `new NativeFunction(...)`.) This is how the
   exact `audit_token_t`-by-value calling convention on
   `bundleRecordForAuditToken:` selectors was confirmed — an
   `audit_token_t` (8x `unsigned int`, from `<bsm/audit.h>`, already
   transitively defined via `<mach/message.h>` — don't redeclare it, that's
   a build error) passed by value, not as an opaque token object.
5. **Compute the live address from the static one via dyld's own reported
   slide — never hand-compute a slide.**
   ```objc
   // In Tweak.x production code:
   for each loaded image (_dyld_image_count()/_dyld_get_image_name(i)):
       if path contains "AppAttestInternal.framework/AppAttestInternal":
           slide = _dyld_get_image_vmaddr_slide(i);  // cache this
   liveAddr = staticGhidraAddr + slide;
   ```
   For live Frida verification instead of production code: get the live
   address of any **known exported** symbol in the same image via
   `Module.findExportByName('AppAttestInternal', '<name>')`, subtract its
   known static Ghidra address, apply that slide to the address of
   interest. A hand-computed slide has previously been off by 4 bytes while
   still looking plausible — always let dyld report its own slide.
6. **Call the resolved address directly from Frida to verify behavior
   before wiring it into `Tweak.x`:**
   ```js
   const fn = new NativeFunction(liveAddr, 'pointer', ['pointer']); // match the real signature
   const result = fn(someObjCObject.handle);
   const wrapped = new ObjC.Object(result); // to call methods on a returned pointer
   ```
7. **To find what a given Apple function calls internally, without knowing
   the answer up front** (e.g. "what selector does X call on this object"):
   hook `objc_msgSend` itself, filter `onEnter` by checking whether
   `this.returnAddress` falls inside the target module's `[base, base+size)`
   range (via `Process.findModuleByAddress`), and read
   `ObjC.selectorAsString(args[1])`/`new ObjC.Object(args[0]).$className`
   directly. This is more reliable than waiting on an async `send()`
   message from inside a completion-block hook, especially for a process
   like `devicecheckd` that exits shortly after servicing one request —
   async messages can arrive late, out of order, or be lost if the process
   tears down before Frida's transport flushes. Prefer synchronous, in-hook
   computation over anything depending on message ordering across two
   separate script lifetimes.
8. **When a hook causes a hard crash instead of a catchable exception**,
   read the actual `.ips` crash report
   (`/var/mobile/Library/Logs/CrashReporter/*.ips`, via `/rootfs`) rather
   than trying to catch it with `objc_exception_throw`/`abort` hooks — a
   deliberate hard fault (`abort_with_payload`, "Application Triggered
   Fault") doesn't go through those. `dmesg` showing `"Corpse allowed"` /
   `"Corpse released"` is the tell that a real crash (not a clean exit) just
   happened — `launchctl list`'s exit-status column can't distinguish the
   two. The `.ips` file is plain JSON-ish text; `grep -b -o` + `dd
   if=... bs=1 skip=<offset> count=<n>` works for pulling a window around a
   field of interest without a JSON parser on-device. The symbolicated
   `frames` array under the `"triggered":true` thread names the crashing
   selector directly for a real ObjC frame; if the getter call is inlined
   into a C helper instead, fall back to the `objc_msgSend`-filtered trace
   from step 7.

**Current hardcoded offsets** (in `Tweak.x`, with the exact target
device/build documented directly above the `#define`s — verify against
`SETUP.md` step 3 before trusting them on a different device):

```c
AAI_STATIC_getAllCredentialKeychainLabels
AAI_STATIC_copy_keychain_item
AAI_STATIC_deleteCredentialKeychainWithLabel
AAI_STATIC_generateEnvironmentByAppSigning   // 0x1c32d1244 — see
                                             // "Environment selection" above
```

Two Frida notes worth not re-learning, both from the 2026-10-10 session:

- **Private symbols resolve without Ghidra.** `DebugSymbol.fromAddress()`
  names non-exported AppAttestInternal functions on this build
  (`generateEnvironmentByAppSigning`, `extractApplicationIdentifiers`,
  `saveCredentialKeychain`, `isNSString`, …) even though
  `Module.enumerateSymbols()` returns almost nothing. Disassembling an
  exported entry point and naming its `bl` targets is therefore a fast way to
  map a call chain — that is how the environment function was located, in one
  pass, with the Ghidra MCP server unavailable. Data symbols resolve too, which
  is how the entitlement-key constant was identified by name.
- **Never `new ObjC.Object(p)` on a pointer that might not be an object.**
  `$className` dereferences the isa and SIGSEGVs the process — `launchctl
  list` then shows exit status `-11`. This killed devicecheckd twice: once on
  an `audit_token_t *` argument, once on raw string/data-slot addresses. It is
  NOT catchable by a JS try/catch. Read C strings with `readUtf8String()` (no
  length argument — a fixed-length read spans NULs into neighbouring literals
  and corrupts the result) and decode CFString constants by hand from the
  `__CFConstantString` layout (`const char *` at `+16`, length at `+24`).
  devicecheckd is launched on demand, so a crash is recoverable, but it costs
  a round trip and invalidates whatever trace was in flight.

## Other infra lessons (costly to re-learn)

- **No macOS-style `log` CLI on-device.** `log stream ...` fails
  (`zsh:log:1: too many arguments` — `log` resolves to an unrelated zsh
  builtin, not a real binary, which doesn't exist here). Use
  `oslog --info --debug -p <pid|name>` instead. `oslog -p <name>` resolves
  to a specific pid **once at start** and does not re-resolve if that
  process restarts — always re-resolve the current pid (`launchctl list |
  grep <name>`, the pid column, not the exit-status column) and reattach by
  pid after any reinstall/restart. Output can also appear empty for a few
  seconds after triggering the call before it flushes — don't conclude
  "nothing happened" from an immediate empty read.
- **`Stalker`-based call tracing has been unreliable** on this device for
  following a thread through a specific function call (`onLeave` failing to
  fire despite the traced function completing) — root cause not confirmed;
  prefer the Ghidra-first, `objc_msgSend`-filtered-trace-second workflow
  above instead of reaching for `Stalker`.
- **Don't duplicate shared constants across `oracled.m` and `Tweak.x`.**
  Both files must `#import`/reference the exact same definitions
  (`OracledDCCommon.h`) for anything that has to match between them (forge
  file path, sentinel strings) — a duplicated literal that drifts out of
  sync (e.g. one side gaining a `jbroot()` wrapper the other side lacks)
  fails silently, with a symptom indistinguishable from "the underlying
  mechanism is broken," and has cost a full day of debugging in this
  project already.
- **`apt remove` does not run any unload step for a LaunchDaemon** — it
  deletes files but can leave the daemon loaded in launchd's memory.
  Explicitly `launchctl remove <label>` after removing this package.
- **A rejected/interrupted tool call may have already taken effect** before
  the interruption reached it — don't assume a rejected `apt install` (or
  similar) definitely didn't run; check actual device state
  (`dpkg -l | grep <name>`) if it matters.
- **`dpkg -l` output doesn't anchor cleanly on package name** — version/
  arch/description follow on the same line, so an end-of-line-anchored
  grep against the package name silently never matches. Extract the name
  field first, or just remove the exact known package name directly.

See `README.md`'s Status section for the current state of the research.
