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
// Contents: LINE 1 is the App ID (<TeamID>.<BundleID>) to force for the NEXT
// App Attest call devicecheckd handles. Presence of line 1 = override active;
// absence of the file = pass through to the real (audit-token-derived)
// identity. Any further lines are reserved for future per-request fields and
// are ignored by this revision — see OracledForcedAppID() on why line 1 is
// parsed out rather than the whole file being used verbatim.
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
    // LINE 1 ONLY, trimmed. Returning the whole file verbatim made the forced
    // App ID hostage to the file's exact byte layout: a trailing newline, a
    // CRLF from a file hand-edited on a non-Unix host, or any future second
    // line would all be smuggled into the identity string itself and break
    // every identity check downstream — silently, since a forced App ID that
    // doesn't match anything just looks like the forge not working. Parse out
    // line 1 and trim it so this stays correct whether the file is the
    // historical single bare line, a single line with a trailing newline, or
    // gains further reserved lines later. nil/empty file still means "no
    // override" (componentsSeparatedByString: on nil yields nil; .length on
    // nil is 0).
    NSString *appId = [[s componentsSeparatedByString:@"\n"].firstObject
        stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    return appId.length ? appId : nil;
}
