// aaoracled — on-device App Attest oracle.
//
// A headless tool that serves the OpenAPI contract in openapi.yaml on
// 127.0.0.1:8181 and drives DCAppAttestService -> com.apple.devicecheckd
// directly (no host-app UI). `appId` on POST /keys is a genuinely
// caller-chosen input, not just recorded/echoed: the companion devicecheckd
// tweak (see Tweak.x) makes devicecheckd present whatever App ID this
// process asks for on the next call, regardless of this process's own
// (ad-hoc, unentitled) code-signing identity — that's the whole point of
// the research.
//
// Routes: GET /health, GET /keys, POST /keys, POST /keys/{key}/sign,
// DELETE /keys/{key}.
//
// There is no in-memory key store. `/keys` is backed entirely by Apple's
// own device-wide App Attest keychain namespace (every key from every app,
// real or forged, addressed by an opaque label AppAttestInternal itself
// assigns) — see Tweak.x for the mechanism. A key this process just minted
// via POST /keys is immediately visible through GET /keys like any other;
// nothing here tracks "keys aaoracled created" separately from "keys that
// exist."
#import <Foundation/Foundation.h>
#import <DeviceCheck/DeviceCheck.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import "OracledDCCommon.h"

static const int kPort = 8181;

// Private SPI (confirmed present via M3 Frida recon on DCAppAttestService) —
// gives the actual NSError behind `isSupported == NO`, which the public API
// swallows.
@interface DCAppAttestService (OraclePrivate)
- (BOOL)_isSupportedReturningError:(NSError **)error;
@end

// aaoracled has no fixed App ID of its own — the whole point is that it
// forges whatever App ID the caller of POST /keys asks for (see Tweak.x).
// This label is purely for the startup log line below, not a real identity.
static NSString *const kOwnLabel = @"xyz.regulad.aaoracled (no fixed App ID — forges on request)";

#pragma mark - devicecheckd forge-identity protocol (see Tweak.x)

// Uses the SAME kOracledForgePath macro (jbroot()-resolved) as the tweak's
// OracledForcedAppID() reader, via the shared header imported above. This
// used to be a locally-duplicated plain-literal path here, which silently
// drifted out of sync when the read side was fixed to resolve through
// jbroot() (2026-09-07) — oracled kept writing the pre-jbroot literal path,
// so every write landed at a DIFFERENT file than devicecheckd ever read,
// making every forge attempt since that fix a silent no-op (discovered
// 2026-09-08 by hooking OracledForcedAppID() itself with Frida and seeing it
// return nil on every call despite setForgeAppId() having just run). Single
// source of truth now — no more duplicate constant to drift.

// Tells the injected devicecheckd tweak which App ID to present for the NEXT
// call. Cleared immediately after so an un-forged process elsewhere on the
// device isn't affected by a stale override.
static void setForgeAppId(NSString *appId, NSString *environment) {
    // Written as a binary plist (see OracledDCCommon.h for the key names and
    // for why the path keeps its historical `.txt` spelling). Binary rather
    // than XML purely so a partially-flushed file cannot look like a valid
    // document with a plausible-but-wrong value in it — a truncated binary
    // plist fails to parse outright, and the reader treats that as "no
    // override", which is the safe direction.
    NSError *err = nil;
    NSData *data = [NSPropertyListSerialization
        dataWithPropertyList:@{ kOracledForgeKeyAppID: appId,
                                kOracledForgeKeyEnvironment: environment }
                      format:NSPropertyListBinaryFormat_v1_0
                     options:0
                       error:&err];
    if (!data) {
        NSLog(@"[aaoracled] FATAL: could not serialize forge plist: %@", err);
        return;
    }
    // Atomic so devicecheckd never reads a half-written file: this lands in a
    // temp file and renames into place, and the rename target is the exact
    // path libSandy granted.
    if (![data writeToFile:kOracledForgePath
                   options:NSDataWritingAtomic
                     error:&err]) {
        NSLog(@"[aaoracled] FATAL: could not write forge plist to %@: %@",
              kOracledForgePath, err);
        return;
    }
    chmod(kOracledForgePath.UTF8String, 0666);
}
static void clearForgeAppId(void) {
    [NSFileManager.defaultManager removeItemAtPath:kOracledForgePath error:nil];
}

#pragma mark - Synchronous DCAppAttestService wrappers

static DCAppAttestService *svc(void) { return DCAppAttestService.sharedService; }

static NSString *dcGenerateKey(NSError **outErr) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    __block NSString *keyId; __block NSError *err;
    [svc() generateKeyWithCompletionHandler:^(NSString *k, NSError *e) {
        keyId = k; err = e; dispatch_semaphore_signal(s);
    }];
    dispatch_semaphore_wait(s, DISPATCH_TIME_FOREVER);
    if (outErr) *outErr = err;
    return keyId;
}

static NSData *dcAttest(NSString *keyId, NSData *cdh, NSError **outErr) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    __block NSData *att; __block NSError *err;
    [svc() attestKey:keyId clientDataHash:cdh completionHandler:^(NSData *a, NSError *e) {
        att = a; err = e; dispatch_semaphore_signal(s);
    }];
    dispatch_semaphore_wait(s, DISPATCH_TIME_FOREVER);
    if (outErr) *outErr = err;
    return att;
}

static NSData *dcAssert(NSString *keyId, NSData *cdh, NSError **outErr) {
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    __block NSData *asrt; __block NSError *err;
    [svc() generateAssertion:keyId clientDataHash:cdh completionHandler:^(NSData *a, NSError *e) {
        asrt = a; err = e; dispatch_semaphore_signal(s);
    }];
    dispatch_semaphore_wait(s, DISPATCH_TIME_FOREVER);
    if (outErr) *outErr = err;
    return asrt;
}

#pragma mark - HTTP plumbing

typedef struct { int status; NSDictionary *json; } Resp;
static Resp R(int status, NSDictionary *json) { return (Resp){status, json}; }
static Resp Err(int status, NSString *code, NSString *detail) {
    return R(status, detail ? @{@"error": code, @"detail": detail} : @{@"error": code});
}
// Full diagnostic dump of an NSError: domain, code, and the ENTIRE userInfo
// (recursing into any NSUnderlyingErrorKey chain) — .localizedDescription
// alone was hiding whatever devicecheckd/XPC actually says went wrong.
static NSString *fullErrorDump(NSError *e) {
    if (!e) return @"(nil)";
    NSMutableString *s = [NSMutableString string];
    NSError *cur = e;
    int depth = 0;
    while (cur && depth < 6) {
        [s appendFormat:@"[%d] domain=%@ code=%ld userInfo=%@\n",
            depth, cur.domain, (long)cur.code, cur.userInfo];
        cur = cur.userInfo[NSUnderlyingErrorKey];
        depth++;
    }
    return s;
}

static NSData *b64d(NSString *s) {
    return s ? [[NSData alloc] initWithBase64EncodedString:s options:0] : nil;
}
static NSString *b64e(NSData *d) { return [d base64EncodedStringWithOptions:0]; }

#pragma mark - Route handlers
//
// /keys is backed entirely by Apple's own device-wide App Attest keychain
// namespace via sentinel keyId strings the devicecheckd tweak intercepts
// (see Tweak.x) — not by anything tracked in this process. List and delete
// never need a forge active (the tweak answers before touching identity/
// forge state at all); create still does, since minting under a
// caller-chosen appId is the actual forgery primitive.

// The environment baked into a credential label, or nil if the label doesn't
// match the expected shape.
//
// AppAttestInternal encodes the environment as a single character immediately
// after the first base64 component's `=` padding: `aa:<b64>=d:<b64>=:...` for
// development, `...=p:...` for production. This is readable with no
// attestation, no network and no CA involvement, which makes it the cheapest
// possible check that an environment override actually took effect — the one
// that would have caught PR #1's non-functional plumbing in a single request.
static NSString *environmentFromLabel(NSString *label) {
    if (![label isKindOfClass:NSString.class]) return nil;
    if ([label rangeOfString:@"=d:"].location != NSNotFound) return @"development";
    if ([label rangeOfString:@"=p:"].location != NSNotFound) return @"production";
    return nil;
}

static Resp handleListKeys(void) {
    NSData *dummyHash = [NSMutableData dataWithLength:32];
    NSError *err = nil;
    NSData *result = dcAssert(kOracledListSEKeysSentinel, dummyHash, &err);
    if (!result) return Err(502, @"list_keys_failed", fullErrorDump(err));
    NSError *jsonErr = nil;
    id parsed = [NSJSONSerialization JSONObjectWithData:result options:0 error:&jsonErr];
    if (![parsed isKindOfClass:NSDictionary.class]) {
        return Err(502, @"list_keys_bad_response", jsonErr ? jsonErr.localizedDescription : @"non-JSON response");
    }

    // Enrich the tweak's raw label list: each entry becomes
    // {key, environment}. `environment` is null for a label whose shape we
    // don't recognize rather than guessed at — an unknown label layout is
    // worth seeing as unknown.
    NSArray *raw = parsed[@"keys"];
    if (![raw isKindOfClass:NSArray.class]) return R(200, parsed);
    NSMutableArray *entries = [NSMutableArray arrayWithCapacity:raw.count];
    for (NSString *label in raw) {
        NSString *env = environmentFromLabel(label);
        [entries addObject:@{ @"key": label ?: @"",
                              @"environment": env ?: NSNull.null }];
    }
    return R(200, @{ @"keys": entries });
}

static Resp handleCreateKey(NSDictionary *body) {
    NSString *appId = body[@"appId"];
    NSString *env = body[@"environment"] ?: @"development";
    NSData *cdh = b64d(body[@"clientDataHash"]);
    if (![appId isKindOfClass:NSString.class]) return Err(400, @"bad_request", @"appId required");
    // `?: @"development"` above does NOT cover a JSON `null`: that arrives as
    // NSNull, which is a live object and therefore truthy, so it sails past
    // the default and lands in `env` — as would a number, array or dict from
    // a malformed body. Today that only reaches the echoed 201 field, but it
    // is also the value the forge channel will carry once `environment` is
    // actually plumbed through to devicecheckd, where a non-string would be
    // %@-formatted into the forge file as something like "<null>". Validate
    // the shape AND the domain here, at the edge, rather than letting a
    // nonsense environment travel any further.
    if (![env isKindOfClass:NSString.class] ||
        ![@[@"development", @"production"] containsObject:env])
        return Err(400, @"bad_request", @"environment must be \"development\" or \"production\"");
    if (cdh.length != 32) return Err(400, @"bad_request", @"clientDataHash must be 32 bytes (base64)");

    // Forge lever: tells the injected devicecheckd tweak (Tweak.x) which App
    // ID to present AND which environment to force for these calls,
    // regardless of our own process's actual (ad-hoc, unentitled)
    // code-signing identity. Both generateKey and attestKey happen inside
    // this window: the environment is burned into the credential's keychain
    // label at generateKey time and into the AAGUID at attestKey time, so the
    // override has to stay armed across both — which it does, since
    // clearForgeAppId() runs only after dcAttest returns.
    setForgeAppId(appId, env);
    NSError *err = nil;
    NSString *keyId = dcGenerateKey(&err);
    if (!keyId) { clearForgeAppId(); return Err(502, @"generateKey_failed", fullErrorDump(err)); }
    NSData *att = dcAttest(keyId, cdh, &err);
    clearForgeAppId();
    if (!att) return Err(502, @"attestKey_failed", fullErrorDump(err));

    // Nothing stored: this response is a one-time snapshot of what was just
    // minted, not a promise it's retrievable again under this same keyId
    // later — GET /keys addresses it by its own opaque label from here on.
    return R(201, @{
        @"keyId": keyId, @"appId": appId, @"environment": env,
        @"attestation": b64e(att), @"counter": @0,
    });
}

static Resp handleSignKey(NSString *key, NSDictionary *body) {
    NSData *cdh = b64d(body[@"clientDataHash"]);
    if (key.length == 0)
        return Err(400, @"bad_request", @"key required in path (from GET /keys)");
    // Arbitrary length, not just 32 bytes: the tweak's raw-label sign path
    // (OracledHandleSignArbitraryKey) signs whatever bytes it is handed with
    // the SEP key via kSecKeyAlgorithmECDSASignatureMessageX962SHA256 — the
    // *Message* variant, which SHA-256s its input itself before signing. So a
    // full App Attest assertion message (authData || clientDataHash,
    // typically 69 bytes) handed in here yields a signature over
    // SHA256(authData || clientDataHash), which is exactly the real assertion
    // construction. The old 32-byte-only check was a web-layer assumption
    // inherited from clientDataHash conventions, and was the only thing
    // standing between this endpoint and assembling complete assertions
    // client-side (counter managed by the caller). Upper bound is purely
    // defensive; the HTTP body reader itself has no cap of its own.
    if (cdh.length == 0 || cdh.length > 4096)
        return Err(400, @"bad_request", @"clientDataHash must be 1..4096 bytes (base64)");

    NSString *sentinelKeyId = [kOracledRawLabelSignPrefix stringByAppendingString:key];
    NSError *err = nil;
    NSData *sig = dcAssert(sentinelKeyId, cdh, &err);
    if (!sig) return Err(502, @"sign_failed", fullErrorDump(err));
    return R(200, @{@"key": key, @"signature": b64e(sig)});
}

static Resp handleDeleteKey(NSString *key) {
    if (key.length == 0) return Err(400, @"bad_request", @"key required in path");

    // Ground truth (2026-09-08, live Frida call against a real label):
    // Apple's own delete returns TRUE for both "existed and was removed"
    // and "was already gone" (idempotent-delete semantics — see Tweak.x).
    // So the boolean alone decides 200 vs 500 here; there's no reliable way
    // to report 404 separately, and none is worth faking on top of it.
    NSString *sentinelKeyId = [kOracledRawLabelDeletePrefix stringByAppendingString:key];
    NSData *dummyHash = [NSMutableData dataWithLength:32];
    NSError *err = nil;
    NSData *result = dcAssert(sentinelKeyId, dummyHash, &err);
    if (!result) return Err(500, @"delete_failed", fullErrorDump(err));
    return R(200, @{@"key": key, @"deleted": @YES});
}

static Resp route(NSString *method, NSString *path, NSDictionary *body) {
    if ([path isEqualToString:@"/health"] && [method isEqualToString:@"GET"]) {
        NSError *supErr = nil;
        BOOL supported = [svc() _isSupportedReturningError:&supErr];
        // `defaultEnvironment: "development"` used to be hardcoded here. It
        // was right only by accident, and it is now the wrong concept
        // outright: the environment is chosen per call by devicecheckd (from
        // the caller's bundle record, or its entitlement when there is no
        // record), and POST /keys can force either one. There is no default
        // to report, so report what can actually be honored instead.
        NSMutableDictionary *r = [@{@"ok": @YES, @"appAttestSupported": @(supported),
                                     @"supportedEnvironments": @[@"development", @"production"],
                                     @"environmentForgery": @YES} mutableCopy];
        if (supErr) r[@"appAttestUnsupportedReason"] = fullErrorDump(supErr);
        return R(200, r);
    }
    if ([path isEqualToString:@"/keys"] && [method isEqualToString:@"GET"])
        return handleListKeys();
    if ([path isEqualToString:@"/keys"] && [method isEqualToString:@"POST"])
        return handleCreateKey(body);
    if ([path hasPrefix:@"/keys/"] && [path hasSuffix:@"/sign"] && [method isEqualToString:@"POST"]) {
        NSString *mid = [path substringWithRange:NSMakeRange(6, path.length - 6 - 5)];
        return handleSignKey([mid stringByRemovingPercentEncoding], body);
    }
    if ([path hasPrefix:@"/keys/"] && [method isEqualToString:@"DELETE"]) {
        NSString *key = [path substringFromIndex:6];
        return handleDeleteKey([key stringByRemovingPercentEncoding]);
    }
    return Err(404, @"not_found", nil);
}

#pragma mark - Minimal HTTP/1.1 server (loopback, one connection at a time)

static void writeAll(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) { ssize_t n = write(fd, buf + off, len - off); if (n <= 0) break; off += n; }
}

static void handleConn(int cfd) {
    // Read headers.
    NSMutableData *raw = [NSMutableData data];
    char buf[4096];
    NSRange sep;
    while (1) {
        ssize_t n = read(cfd, buf, sizeof(buf));
        if (n <= 0) return;
        [raw appendBytes:buf length:n];
        NSString *s = [[NSString alloc] initWithData:raw encoding:NSASCIIStringEncoding];
        sep = [s rangeOfString:@"\r\n\r\n"];
        if (sep.location != NSNotFound) break;
        if (raw.length > 1 << 20) return;
    }
    NSString *head = [[NSString alloc] initWithData:[raw subdataWithRange:NSMakeRange(0, sep.location)]
                                           encoding:NSASCIIStringEncoding];
    NSArray *lines = [head componentsSeparatedByString:@"\r\n"];
    NSArray *req = [lines[0] componentsSeparatedByString:@" "];
    if (req.count < 2) return;
    NSString *method = req[0], *path = req[1];

    // Content-Length + body.
    NSUInteger clen = 0;
    for (NSString *line in lines) {
        NSRange r = [line rangeOfString:@":"];
        if (r.location == NSNotFound) continue;
        NSString *key = [[line substringToIndex:r.location] lowercaseString];
        if ([key isEqualToString:@"content-length"])
            clen = [[[line substringFromIndex:r.location + 1]
                     stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet] integerValue];
    }
    NSUInteger bodyStart = sep.location + 4;
    NSMutableData *body = [[raw subdataWithRange:NSMakeRange(bodyStart, raw.length - bodyStart)] mutableCopy];
    while (body.length < clen) {
        ssize_t n = read(cfd, buf, sizeof(buf));
        if (n <= 0) break;
        [body appendBytes:buf length:n];
    }

    NSDictionary *json = nil;
    if (body.length)
        json = [NSJSONSerialization JSONObjectWithData:body options:0 error:nil];

    Resp resp;
    @try { resp = route(method, path, json ?: @{}); }
    @catch (NSException *e) { resp = Err(500, @"exception", e.reason); }

    NSData *out = [NSJSONSerialization dataWithJSONObject:resp.json
                    options:NSJSONWritingPrettyPrinted error:nil];
    NSString *hdr = [NSString stringWithFormat:
        @"HTTP/1.1 %d\r\nContent-Type: application/json\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",
        resp.status, (unsigned long)out.length];
    NSData *hd = [hdr dataUsingEncoding:NSASCIIStringEncoding];
    writeAll(cfd, hd.bytes, hd.length);
    writeAll(cfd, out.bytes, out.length);
}

static void serve(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        NSLog(@"[aaoracled] bind :%d failed: %s", kPort, strerror(errno)); exit(1);
    }
    listen(fd, 16);
    NSLog(@"[aaoracled] listening on 127.0.0.1:%d (%@)", kPort, kOwnLabel);
    while (1) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) continue;
        @autoreleasepool { handleConn(cfd); }
        close(cfd);
    }
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (!svc().isSupported) NSLog(@"[aaoracled] WARNING: DCAppAttestService.isSupported == NO");
        // Accept loop on a background queue; main thread runs the runloop so
        // DCAppAttestService completion handlers are serviced.
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{ serve(); });
        CFRunLoopRun();
    }
    return 0;
}
