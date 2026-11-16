#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

// This is strictly a CONTROL test of the app's own entitled App Group.
// There are no symlinks, traversal paths, foreign identifiers or SystemGroup queries.
// It only compares how the standard Class 7 API responds to four flags.

typedef void *(*BQCreateQuery)(void);
typedef void (*BQSetNumber)(void *, uint64_t);
typedef void (*BQSetIdentifier)(void *, void *);
typedef void *(*BQGetResult)(void *);
typedef void (*BQFreeQuery)(void *);
typedef char *(*BQCopyToken)(void *);
typedef const char *(*BQGetContainerPath)(void *);
typedef void *(*BQXPCString)(const char *);
typedef void (*BQXPCRelease)(void *);
typedef int64_t (*BQConsumeToken)(const char *);
typedef int64_t (*BQReleaseToken)(int64_t);
typedef void *(*BQLastError)(void *);
typedef int (*BQErrorPOSIX)(void *);
typedef const char *(*BQErrorMessage)(void *);

static NSString *BQMatrixError(int code) {
    return [NSString stringWithFormat:@"%d (%s)", code, strerror(code)];
}

NSString *BQRunClass7ControlMatrix(void) {
    NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObjects:
        @"=== HermesEnabler Class 7 own-AppGroup flag matrix ===",
        @"No system containers, no symlinks, no protected file writes.",
        @"Each query is restricted to this app's existing App Group entitlement.",
        nil];

    NSString *groupID = BQGroupID();
    NSString *groupRoot = BQGroupRoot();
    if (!groupID.length || !groupRoot.length) {
        [lines addObject:@"STOP: Own App Group entitlement or container missing."];
        return [lines componentsJoinedByString:@"\n"];
    }
    [lines addObject:[NSString stringWithFormat:@"Group: %@", groupID]];
    [lines addObject:[NSString stringWithFormat:@"Root: %@", groupRoot]];

    void *lib = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        [lines addObject:[NSString stringWithFormat:@"STOP: containermanager unavailable: %s", dlerror()]];
        return [lines componentsJoinedByString:@"\n"];
    }

    BQCreateQuery create = (BQCreateQuery)dlsym(lib, "container_query_create");
    BQSetNumber setClass = (BQSetNumber)dlsym(lib, "container_query_set_class");
    BQSetIdentifier setGroup = (BQSetIdentifier)dlsym(lib, "container_query_set_group_identifiers");
    BQSetNumber setPart = (BQSetNumber)dlsym(lib, "container_query_operation_set_part");
    BQSetNumber setFlags = (BQSetNumber)dlsym(lib, "container_query_operation_set_flags");
    BQGetResult getResult = (BQGetResult)dlsym(lib, "container_query_get_single_result");
    BQCopyToken copyToken = (BQCopyToken)dlsym(lib, "container_copy_sandbox_token");
    BQGetContainerPath getPath = (BQGetContainerPath)dlsym(lib, "container_object_get_path");
    BQFreeQuery freeQuery = (BQFreeQuery)dlsym(lib, "container_query_free");
    BQLastError lastError = (BQLastError)dlsym(lib, "container_query_get_last_error");
    BQErrorPOSIX errorPOSIX = (BQErrorPOSIX)dlsym(lib, "container_error_get_posix_errno");
    BQErrorMessage errorMessage = (BQErrorMessage)dlsym(lib, "container_error_get_message");
    BQXPCString makeString = (BQXPCString)dlsym(RTLD_DEFAULT, "xpc_string_create");
    BQXPCRelease releaseString = (BQXPCRelease)dlsym(RTLD_DEFAULT, "xpc_release");
    BQConsumeToken consumeToken = (BQConsumeToken)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    BQReleaseToken releaseToken = (BQReleaseToken)dlsym(RTLD_DEFAULT, "sandbox_extension_release");

    if (!(create && setClass && setGroup && setPart && setFlags && getResult &&
          copyToken && freeQuery && makeString && releaseString)) {
        [lines addObject:@"STOP: One or more necessary Class 7/XPC API symbols unavailable."];
        dlclose(lib);
        return [lines componentsJoinedByString:@"\n"];
    }

    const struct {
        const char *name;
        uint64_t flags;
    } samples[] = {
        {"no extra flags",     0x0ULL},
        {"iOS 26 alternate",   0x0800000000ULL},
        {"standard",           0x8000000000ULL},
        {"original combined",  0x8100000000ULL}
    };

    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
        [lines addObject:[NSString stringWithFormat:@"\n[%s | 0x%llx]",
                          samples[i].name, (unsigned long long)samples[i].flags]];
        void *query = create();
        if (!query) {
            [lines addObject:@"query_create=NULL"];
            continue;
        }
        void *identifier = makeString(groupID.UTF8String);
        if (!identifier) {
            [lines addObject:@"xpc_string_create=NULL"];
            freeQuery(query);
            continue;
        }
        setClass(query, 7);
        setGroup(query, identifier);
        setPart(query, 3);
        setFlags(query, samples[i].flags);
        releaseString(identifier);

        void *result = getResult(query);
        if (!result) {
            [lines addObject:@"query_result=NULL (token not attempted)"];
            void *errorObject = lastError ? lastError(query) : NULL;
            if (errorObject) {
                int posix = errorPOSIX ? errorPOSIX(errorObject) : 0;
                const char *message = errorMessage ? errorMessage(errorObject) : NULL;
                [lines addObject:[NSString stringWithFormat:@"MCM last_error posix=%d message=%s",
                                  posix, message ?: "(null)"]];
            }
            freeQuery(query);
            continue;
        }
        [lines addObject:@"query_result=YES"];
        const char *rawPath = getPath ? getPath(result) : NULL;
        NSString *path = rawPath ? [NSString stringWithUTF8String:rawPath] : nil;
        [lines addObject:[NSString stringWithFormat:@"result_path=%@", path ?: @"(null)"]];
        char *token = copyToken(result);
        [lines addObject:[NSString stringWithFormat:@"token_present=%@", token ? @"YES" : @"NO"]];
        NSString *canonicalRoot = groupRoot.stringByStandardizingPath;
        NSString *canonicalPath = path.stringByStandardizingPath;
        BOOL insideOwnGroup = path.length &&
            ([canonicalPath isEqualToString:canonicalRoot] ||
             [canonicalPath hasPrefix:[canonicalRoot stringByAppendingString:@"/"]]);
        if (!insideOwnGroup) {
            [lines addObject:@"GUARD: returned path is not inside the own group; token not consumed"];
        }
        if (token && insideOwnGroup) {
            if (consumeToken && releaseToken) {
                errno = 0;
                int64_t handle = consumeToken(token);
                int consumeErr = errno;
                [lines addObject:[NSString stringWithFormat:@"consume=%@",
                                  handle >= 0 ? @"SUCCESS" : BQMatrixError(consumeErr)]];
                if (handle >= 0) {
                    int releaseStatus = releaseToken(handle);
                    [lines addObject:[NSString stringWithFormat:@"release=%d", releaseStatus]];
                }
            } else {
                [lines addObject:@"consume=SKIPPED (consume/release unavailable)"];
            }
        }
        if (token) free(token);
        freeQuery(query);
    }
    dlclose(lib);
    [lines addObject:@"\nNOTE: This only measures normal access to the application's own group."];
    [lines addObject:@"A token here does not prove SystemGroup or MobileGestalt write access."];
    [lines addObject:@"No system file was changed."];
    NSString *report = [lines componentsJoinedByString:@"\n"];
    NSString *reportPath = [BQDocuments() stringByAppendingPathComponent:@"class7-flag-matrix.txt"];
    NSError *error = nil;
    BOOL saved = [report writeToFile:reportPath atomically:YES
                           encoding:NSUTF8StringEncoding error:&error];
    if (!saved) report = [report stringByAppendingFormat:@"\nSave failure: %@", error.localizedDescription];
    NSLog(@"[Class7Matrix]\n%@\n[/Class7Matrix]", report);
    return report;
}
