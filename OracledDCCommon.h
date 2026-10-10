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
// Contents: TWO lines. Line 1: the App ID (<TeamID>.<BundleID>) to force
// for the NEXT App Attest call devicecheckd handles. Line 2 (optional —
// a legacy single-line file still parses fine): the App Attest environment
// ("development" or "production") to present in the forged identity's
// entitlements, per OracledForcedEnvironment() below. Presence of line 1 =
// override active; absence of the file = pass through to the real
// (audit-token-derived) identity.
#define kOracledForgePath \
    jbroot(@"/var/mobile/Library/Preferences/xyz.regulad.aaoracled.forge-appid.txt")

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
    NSString *s = [NSString stringWithContentsOfFile:kOracledForgePath
                                             encoding:NSUTF8StringEncoding error:nil];
    // Line 1 ONLY. The file may now carry a second line (the environment,
    // see OracledForcedEnvironment()); returning the whole file contents
    // here would smuggle the newline + environment string into the forced
    // App ID itself, breaking every identity check downstream.
    NSString *appId = [s componentsSeparatedByString:@"\n"].firstObject;
    return appId.length ? appId : nil;
}

// Line 2 of the forge file: the App Attest environment to present in the
// forged identity's entitlements (consumed by OracledFakeBundleRecordFor in
// Tweak.x, which feeds devicecheckd's environment/AAGUID decision).
// "production" selects the production AAGUID; anything else - including an
// absent second line, i.e. a legacy single-line file - reads as development,
// matching the entitlement value hardcoded there before environments were
// plumbed through (2026-10-10: a live environment:"production" POST /keys
// came back with the appattestdevelop AAGUID, which is what prompted this).
static inline NSString *OracledForcedEnvironment(void) {
    NSString *s = [NSString stringWithContentsOfFile:kOracledForgePath
                                              encoding:NSUTF8StringEncoding error:nil];
    NSArray *lines = [s componentsSeparatedByString:@"\n"];
    return (lines.count > 1 && [lines[1] isEqualToString:@"production"])
        ? @"production" : @"development";
}
