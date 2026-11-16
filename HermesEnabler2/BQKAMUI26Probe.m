#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

// DIAGNOSTIC ONLY: no symlinks, path traversal, sandbox_extension_consume,
// file write access, cache modification, or token logging. Probe only whether
// containermanagerd returns a result / a token for the known system group.

typedef void *(*BQProbeCreate)(void);
typedef void (*BQProbeSetU64)(void *, uint64_t);
typedef void (*BQProbeSetObject)(void *, void *);
typedef void *(*BQProbeGetResult)(void *);
typedef char *(*BQProbeCopyToken)(void *);
typedef const char *(*BQProbeGetPath)(void *);
typedef void (*BQProbeFree)(void *);
typedef void *(*BQProbeLastError)(void *);
typedef int (*BQProbePosix)(void *);
typedef const char *(*BQProbeMessage)(void *);
typedef void *(*BQProbeMakeXPCString)(const char *);
typedef void (*BQProbeReleaseXPC)(void *);

static NSString *BQProbeErrorDescription(int e) {
    return [NSString stringWithFormat:@"%d (%s)", e, strerror(e)];
}

NSString *BQRunKAMUI26TokenProbe(void) {
    NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObjects:
        @"=== KAMUI 2.5.2 / watchOS 26 - Class 13 observation ===",
        @"No token is consumed. No sandbox privilege is acquired by this test.",
        @"No system files are opened for writing or modified.",
        @"This is NOT an exploit success test.",
        nil];

    NSOperatingSystemVersion os = NSProcessInfo.processInfo.operatingSystemVersion;
    NSString *target = BQMobileGestaltPath();
    NSString *caches = target.stringByDeletingLastPathComponent;
    BOOL looksLikeOwnAppGroup = [caches containsString:@"/var/mobile/Containers/Shared/AppGroup"];
    uint64_t kamuiFlag = (os.majorVersion == 26 && looksLikeOwnAppGroup)
                      ? 0x800000000ULL : 0x8100000000ULL;
    [lines addObject:[NSString stringWithFormat:@"OS=%@", NSProcessInfo.processInfo.operatingSystemVersionString]];
    [lines addObject:[NSString stringWithFormat:@"Bundle=%@", NSBundle.mainBundle.bundleIdentifier ?: @"(unknown)"]];
    [lines addObject:[NSString stringWithFormat:@"Target kind=%@", looksLikeOwnAppGroup ? @"AppGroup" : @"SystemGroup"]];
    [lines addObject:[NSString stringWithFormat:@"KAMUI 2.5.2 selected Class 7 flag for this target=0x%llx",
                      (unsigned long long)kamuiFlag]];
    [lines addObject:@"KAMUI's iOS 26 alternate Class 7 flag is only selected for AppGroup targets."];
    [lines addObject:@""];

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) {
        [lines addObject:[NSString stringWithFormat:@"STOP: libsystem_containermanager unavailable: %s", dlerror()]];
        return [lines componentsJoinedByString:@"\n"];
    }

    BQProbeCreate create = (BQProbeCreate)dlsym(mgr, "container_query_create");
    BQProbeSetU64 setClass = (BQProbeSetU64)dlsym(mgr, "container_query_set_class");
    BQProbeSetObject setGroups = (BQProbeSetObject)dlsym(mgr, "container_query_set_group_identifiers");
    BQProbeSetU64 setPart = (BQProbeSetU64)dlsym(mgr, "container_query_operation_set_part");
    BQProbeSetU64 setFlags = (BQProbeSetU64)dlsym(mgr, "container_query_operation_set_flags");
    BQProbeGetResult getResult = (BQProbeGetResult)dlsym(mgr, "container_query_get_single_result");
    BQProbeCopyToken copyToken = (BQProbeCopyToken)dlsym(mgr, "container_copy_sandbox_token");
    BQProbeGetPath getPath = (BQProbeGetPath)dlsym(mgr, "container_object_get_path");
    BQProbeFree freeQuery = (BQProbeFree)dlsym(mgr, "container_query_free");
    BQProbeLastError lastError = (BQProbeLastError)dlsym(mgr, "container_query_get_last_error");
    BQProbePosix getPOSIX = (BQProbePosix)dlsym(mgr, "container_error_get_posix_errno");
    BQProbeMessage getMessage = (BQProbeMessage)dlsym(mgr, "container_error_get_message");
    BQProbeMakeXPCString makeString = (BQProbeMakeXPCString)dlsym(RTLD_DEFAULT, "xpc_string_create");
    BQProbeReleaseXPC releaseXPC = (BQProbeReleaseXPC)dlsym(RTLD_DEFAULT, "xpc_release");

    if (!(create && setClass && setGroups && setPart && setFlags && getResult &&
          copyToken && freeQuery && makeString && releaseXPC)) {
        [lines addObject:@"STOP: required MCM symbols missing; no queries issued"];
        dlclose(mgr);
        return [lines componentsJoinedByString:@"\n"];
    }

    // The existing KAMUI Class 13 direct flags, plus the alternate flag that
    // physical 23U95 research found could return a system-group token.
    const struct { const char *label; uint64_t flags; } cases[] = {
        {"KAMUI Class 13 direct", 0x8100000000ULL},
        {"Reported iOS 26 Class 13 alternative", 0x0800000000ULL}
    };

    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        [lines addObject:[NSString stringWithFormat:@"[%s flags=0x%llx]",
                          cases[i].label, (unsigned long long)cases[i].flags]];
        void *query = create();
        if (!query) {
            [lines addObject:@"query_create=NULL"];
            continue;
        }
        void *id = makeString("systemgroup.com.apple.mobilegestaltcache");
        if (!id) {
            freeQuery(query);
            [lines addObject:@"xpc_string_create=NULL"];
            continue;
        }
        setClass(query, 13);
        setGroups(query, id);
        setPart(query, 3);
        setFlags(query, cases[i].flags);
        releaseXPC(id);

        void *result = getResult(query);
        if (!result) {
            [lines addObject:@"query_result=NO"];
            void *err = lastError ? lastError(query) : NULL;
            if (err) {
                int posix = getPOSIX ? getPOSIX(err) : 0;
                const char *msg = getMessage ? getMessage(err) : NULL;
                [lines addObject:[NSString stringWithFormat:@"MCM posix=%d message=%s",
                                  posix, msg ?: "(null)"]];
            }
        } else {
            [lines addObject:@"query_result=YES"];
            const char *path = getPath ? getPath(result) : NULL;
            [lines addObject:[NSString stringWithFormat:@"path_returned=%@",
                              path ? @"YES" : @"NO"]];
            char *token = copyToken(result);
            [lines addObject:[NSString stringWithFormat:@"token_returned=%@",
                              token ? @"YES" : @"NO"]];
            if (token) {
                // Never print token data or consume it. This test does not
                // grant or attempt to grant access to the protected system group.
                free(token);
                [lines addObject:@"token_discarded=YES (NOT consumed)"];
            }
        }
        freeQuery(query);
        [lines addObject:@""];
    }

    dlclose(mgr);
    [lines addObject:@"Interpretation: result/token presence is NOT a writable file descriptor."];
    [lines addObject:@"The separate write-gate report establishes whether the sandbox allows write-open."];
    NSString *report = [lines componentsJoinedByString:@"\n"];
    NSError *err = nil;
    NSString *save = [BQDocuments() stringByAppendingPathComponent:@"kamui26-token-probe.txt"];
    if (![report writeToFile:save atomically:YES
                   encoding:NSUTF8StringEncoding error:&err]) {
        report = [report stringByAppendingFormat:@"\nReport saving failed: %@", err.localizedDescription];
    }
    NSLog(@"[KAMUI26Probe]\n%@\n[/KAMUI26Probe]", report);
    return report;
}
