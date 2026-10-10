#import <Foundation/Foundation.h>
#import <roothide.h>

// Shared file-based protocol between `oracled` (the client daemon, writes)
// and this tweak (injected into devicecheckd, reads).
//
// devicecheckd is sandboxed — confirmed by direct open()/write() probes from
// inside its own process: reads outside its container return ENOENT
// (sandbox-masked "doesn't exist"), creates return EPERM. This is true for
// /tmp too, so NOT a roothide path-namespace quirk, an actual Apple sandbox
// profile. Fix: a libSandy grant (see layout/Library/libSandy/OracledDCPatch.plist,
// applied via libSandy_applyProfile in Tweak.x's %ctor) gives devicecheckd
// read access to exactly this one namespaced path — never /tmp, which is a
// high-collision shared directory; this lives under our own reverse-DNS
// preferences path instead, matching ~/repositories/geoshim's convention.
//
// CORRECTED 2026-09-07 (root cause of the long-"unconfirmed" grant not
// working): roothide's libSandy fork jbroot()s the extension path *before*
// registering it with the kernel (confirmed via ~/repositories/geoshim's own
// documented convention: "sandyd jbroot()s it"; GSCommon.h reads through the
// exact same jbroot()'d path for this reason). devicecheckd's own open()
// call operates on the genuine, real filesystem — so its request must
// resolve to that SAME jbroot()'d path to match the granted extension, or
// the sandbox correctly denies it as a path that was never granted (ENOENT).
// Verified directly via Frida from inside devicecheckd's own process: the
// plain path -> errno 2 (ENOENT); the jbroot()'d path -> opens cleanly.
// `oracled`'s write side (oracled.m's own separate kForgePath constant) does
// NOT need this fix — it runs unsandboxed (no-sandbox entitlement), so both
// path spellings already resolve to the same file for it.
//
// Contents: a PROPERTY LIST dictionary (written binary, but
// +dictionaryWithContentsOfFile: reads XML just as happily, so a
// hand-written XML plist works for manual testing). Keys below. A readable
// dictionary carrying a non-empty appId = override active; a missing,
// unreadable, or non-dictionary file = pass through to the real
// (audit-token-derived) identity.
//
// This was a bare line-oriented text file until 2026-10-10. A plist removes a
// whole class of fragility that bit this project repeatedly: no trailing
// newline to strip, no CRLF hazard from a file touched on a non-Unix host, no
// ambiguity about what a second line means, and no silent truncation when a
// field needs to grow. Malformed input now fails as "nil dictionary" —
// unambiguously "no override" — rather than being interpreted as a
// legitimate-but-wrong App ID.
//
// The PATH deliberately keeps its historical `.txt` spelling even though the
// contents are now a plist. libSandy's grant
// (layout/Library/libSandy/OracledDCPatch.plist) is path-EXACT, and getting
// that grant to resolve correctly through roothide's jbroot()-ing fork cost
// this project a full day once already. Renaming the file means editing the
// grant too, and a grant that silently stops matching presents as "the forge
// mysteriously does nothing" — indistinguishable from the mechanism being
// broken. Not worth the cosmetics; rename it only alongside a deliberate
// on-device re-verification of the sandbox grant.
#define kOracledForgePath \
    jbroot(@"/var/mobile/Library/Preferences/xyz.regulad.aaoracled.forge-appid.txt")

// Keys inside the forge plist. Shared by both sides — never re-spell these as
// literals in oracled.m or Tweak.x (see the drift lesson in AGENTS.md).
static NSString *const kOracledForgeKeyAppID = @"appId";
// RESERVED, not yet consumed. The App Attest environment is NOT selected by
// any entitlement devicecheckd reads off the caller — confirmed by live trace
// on 2026-10-10 (iPad5,1 / 19H422): across isSupported and generateKey,
// `com.apple.developer.devicecheck.appattest-environment` is never read from
// the caller's SecTask, and -entitlements is never sent to the bundle record
// at all. Nothing should write or read this key until the real lever is
// identified, so that the plist never advertises a knob that does nothing.
static NSString *const kOracledForgeKeyEnvironment = @"environment";

// Sentinels smuggled through Assert's existing keyId param (same channel
// used by AppAttestInternal's own hidden __debug_aa_kc_list__/
// __debug_aa_kc_cleanup__ debug commands) to reach the tweak's
// enumerate/sign/delete-by-label handlers in Tweak.x, without any new XPC
// method or IPC file. Shared here (not duplicated in oracled.m and Tweak.x
// separately) after the forge-path duplication bug from earlier this
// session — one spelling, used by both sides.
static NSString *const kOracledListSEKeysSentinel = @"__oracled_list_se_keys__";
static NSString *const kOracledRawLabelSignPrefix = @"__oracled_sign_raw_label__:";
static NSString *const kOracledRawLabelDeletePrefix = @"__oracled_delete_raw_label__:";

static inline NSString *OracledForcedAppID(void) {
    // File-based, scoped per request by oracled (see oracled.m setForgeAppId/
    // clearForgeAppId). IMPORTANT: this override is GLOBAL and UNSCOPED at
    // the devicecheckd level — it affects every caller devicecheckd services
    // while the file is present, not just the one request under test. Never
    // hardcode a value here for a "quick test" and leave it in — do it
    // deliberately, for one test, then revert immediately (learned this the
    // hard way — see AGENTS.md history).
    // A non-plist, truncated, or otherwise unreadable file yields nil here,
    // which reads as "no override" — the safe direction. The old text format
    // had no such distinction: any bytes at all were taken as an App ID, so a
    // corrupt file forged a garbage identity instead of standing down.
    NSDictionary *forge = [NSDictionary dictionaryWithContentsOfFile:kOracledForgePath];
    if (![forge isKindOfClass:NSDictionary.class]) return nil;

    NSString *appId = forge[kOracledForgeKeyAppID];
    if (![appId isKindOfClass:NSString.class]) return nil;
    // Trimmed defensively: a hand-edited plist can still carry stray
    // whitespace inside the <string>, and an App ID never legitimately has
    // any. Everything else that used to need parsing is now the plist
    // reader's problem, not ours.
    appId = [appId stringByTrimmingCharactersInSet:
                 NSCharacterSet.whitespaceAndNewlineCharacterSet];
    return appId.length ? appId : nil;
}
