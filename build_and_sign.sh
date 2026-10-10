#!/usr/bin/env bash
# Build the combined aaoracled .deb (theos `make package`) — one package
# containing both the OracledDCPatch tweak (injected into devicecheckd) and
# the aaoracled CLI/daemon + its LaunchDaemon plist. Matches the
# ~/repositories/geoshim pattern, not a bare scp'd binary (that gets
# SIGKILLed at launch on this device; see entitlements.plist / Makefile
# comments for why).
#
# On Linux/macOS, just run this directly. On Windows, run it inside WSL as
# a LOGIN shell (for $THEOS + ldid on PATH), e.g.:
#   wsl -d <your-distro> -e bash -lc '/mnt/c/path/to/oracled/build_and_sign.sh'
# See SETUP.md step 9.
set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
export THEOS="${THEOS:-$HOME/theos}"
export PATH="$THEOS/toolchain/linux/iphone/bin:/usr/local/sbin:/usr/local/bin:$PATH"

command -v ldid >/dev/null || { echo "ldid not on PATH (need login shell / theos toolchain)"; exit 1; }
[ -d "$THEOS" ] || { echo "THEOS not found at $THEOS"; exit 1; }

# Prefer real dpkg-deb over theos' bundled dm.pl.
#
# theos defaults to dm.pl unconditionally (`_THEOS_PLATFORM_DPKG_DEB ?= dm.pl`
# in makefiles/package/deb.mk) — it never probes for dpkg-deb. Two reasons to
# override that when dpkg-deb exists:
#
#   * dm.pl's child processes lose FAKEROOTKEY under theos' own fakeroot.sh
#     wrapper (at least on Fedora/WSL), so packaging dies with
#     "libfakeroot: connect: Permission denied" and SIGPIPE, surfacing as
#     `make: *** [deb.mk:79: internal-package] Error 141`. Everything up to
#     and including signing succeeds, which makes it look like a build
#     failure when it is purely a packaging one.
#   * dm.pl emits data.tar.lzma, which current dpkg-deb cannot read back (the
#     CI workflow already degrades to `ar` for its smoke check because of it).
#
# Both variables are `?=` in deb.mk, so exporting them here takes precedence.
# Install dpkg (Fedora: `sudo dnf install dpkg`) to get this path.
if command -v dpkg-deb >/dev/null; then
    export _THEOS_PLATFORM_DPKG_DEB=dpkg-deb
    # theos defaults the compression to lzma, which dpkg-deb >= 1.21 dropped.
    export THEOS_PLATFORM_DEB_COMPRESSION_TYPE="${THEOS_PLATFORM_DEB_COMPRESSION_TYPE:-xz}"
    echo ">> packaging with dpkg-deb (compression: $THEOS_PLATFORM_DEB_COMPRESSION_TYPE)"
else
    echo ">> dpkg-deb not found; falling back to theos' dm.pl" >&2
fi

# theos' `make package` needs correct DEBIAN dir perms (<=0775), which the
# Windows/DrvFs 9p mount at /mnt/d does not reliably preserve via chmod. Build
# in a native WSL filesystem copy, then ship the .deb back out.
#
# Persist $BUILD/.theos across runs (only refresh source files over it) so
# theos' debug-package build-number counter stays monotonic — wiping it each
# run made every build "-1+debug" (identical version), which apt/dpkg then
# silently no-ops or ambiguously overwrites instead of cleanly upgrading.
BUILD="$HOME/.cache/oracled-build"
mkdir -p "$BUILD"
find "$BUILD" -mindepth 1 -maxdepth 1 ! -name '.theos' -exec rm -rf {} +

# Copy only what the theos project actually needs — NOT the whole repo (no
# .git, artifacts/, fixtures/, docs).
cp "$REPO"/Makefile "$REPO"/control "$REPO"/Tweak.x "$REPO"/OracledDCCommon.h \
   "$REPO"/OracledDCPatch.plist "$REPO"/oracled.m "$REPO"/Info.plist \
   "$REPO"/entitlements.plist "$BUILD/"
cp -a "$REPO"/layout "$BUILD/"

find "$BUILD/layout/DEBIAN" -type d -exec chmod 755 {} +
find "$BUILD/layout/DEBIAN" -type f -exec chmod 755 {} +
# launchd refuses a LaunchDaemon plist that is group/other-writable.
chmod 644 "$BUILD/layout/Library/LaunchDaemons/"*.plist

cd "$BUILD"
make clean >/dev/null 2>&1 || true

# Debug (non-final) package: theos auto-appends an incrementing build suffix
# (e.g. 0.1.1-3+debug), so every iteration is a genuinely new version apt will
# install over the last without manual version bumps. Pass FINALPACKAGE=1 for
# an actual release build.
make package

DEB="$(find "$BUILD/packages" -maxdepth 1 -name '*.deb' | sort -V | tail -1)"
[ -n "$DEB" ] || { echo "no .deb produced under $BUILD/packages"; exit 1; }
mkdir -p "$REPO/packages"
cp "$DEB" "$REPO/packages/"
DEB="$REPO/packages/$(basename "$DEB")"
echo ">> built: $DEB"
echo
echo "Deploy:"
echo "  scp \"$DEB\" <device-alias>:/tmp/aaoracled.deb"
echo "  ssh <device-alias> 'sudo apt install /tmp/aaoracled.deb -y'"
