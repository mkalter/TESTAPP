#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

// Non-destructive METHOD TEST, manually triggered by user.
// Tries two existing *direct* MCM class-13 token issuance variants for the
// known MobileGestalt SystemGroup, then checks effective write-open access.
// This file never calls write(), pwrite(), ftruncate(), unlink(), rename(),
// symlink(), or any cache rebuild function.

typedef void *(*BQWOCreate)(void);
typedef void (*BQWOSetNumber)(void *, uint64_t);
typedef void (*BQWOSetObject)(void *, void *);
typedef void *(*BQWOResult)(void *);
typedef char *(*BQWOToken)(void *);
typedef void (*BQWOFree)(void *);
typedef void *(*BQWOXPCString)(const char *);
typedef void (*BQWOXPCRelease)(void *);
typedef int64_t (*BQWOConsume)(const char *);
typedef int64_t (*BQWORelease)(int64_t);
typedef int (*BQWOCheck)(pid_t, const char *, int, ...);

static NSString *BQWOOpenOnly(NSString *path) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    int error = errno;
    if (fd < 0) {
        return [NSString stringWithFormat:@"DENIED errno=%d (%s)", error, strerror(error)];
    }
    close(fd);
    return @"ALLOWED (descriptor closed immediately, no data written)";
}

static NSString *BQWOSandboxStatus(BQWOCheck check, NSString *path) {
    if (!check) return @"UNKNOWN: sandbox_check unavailable";
    errno = 0;
    int r = check(getpid(), "file-write-data", 1, path.fileSystemRepresentation);
    int error = errno;
    if (r == 0) return @"ALLOW";
    if (r > 0) return [NSString stringWithFormat:@"DENY (%d)", r];
    return [NSString stringWithFormat:@"ERROR (%d: %s)", error, strerror(error)];
}

static NSString *BQWOMetadata(NSString *path) {
    struct stat s = {0};
    errno = 0;
    if (lstat(path.fileSystemRepresentation, &s) != 0) {
        int e = errno;
        return [NSString stringWithFormat:@"unavailable (%d: %s)", e, strerror(e)];
    }
    return [NSString stringWithFormat:@"inode=%llu size=%lld mode=%#o mtime=%lld",
            (unsigned long long)s.st_ino,
            (long long)s.st_size,
            (unsigned)(s.st_mode & 07777),
            (long long)s.st_mtimespec.tv_sec];
}

NSString *BQRunKAMUI26WriteOpenTest(void) {
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithObjects:
        @"=== watchOS26: class13 system-group write-open method test ===",
        @"Target: existing MobileGestalt.plist only.",
        @"NO symlinks, NO file creates, NO write() or cache modifications.",
        @"An allowed O_WRONLY alone does not prove safe persistent MG writes.",
        nil];

    NSString *path = BQMobileGestaltPath();
    NSString *before = BQWOMetadata(path);
    [out addObject:[NSString stringWithFormat:@"OS: %@", NSProcessInfo.processInfo.operatingSystemVersionString]];
    [out addObject:[NSString stringWithFormat:@"Target: %@", path]];
    [out addObject:[NSString stringWithFormat:@"Metadata before: %@", before]];

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) {
        [out addObject:@"STOP: container manager library not loadable"];
        return [out componentsJoinedByString:@"\n"];
    }
    BQWOCreate create = (BQWOCreate)dlsym(mgr, "container_query_create");
    BQWOSetNumber setClass = (BQWOSetNumber)dlsym(mgr, "container_query_set_class");
    BQWOSetObject setIDs = (BQWOSetObject)dlsym(mgr, "container_query_set_group_identifiers");
    BQWOSetNumber setPart = (BQWOSetNumber)dlsym(mgr, "container_query_operation_set_part");
    BQWOSetNumber setFlags = (BQWOSetNumber)dlsym(mgr, "container_query_operation_set_flags");
    BQWOResult one = (BQWOResult)dlsym(mgr, "container_query_get_single_result");
    BQWOToken token = (BQWOToken)dlsym(mgr, "container_copy_sandbox_token");
    BQWOFree releaseQuery = (BQWOFree)dlsym(mgr, "container_query_free");
    BQWOXPCString string = (BQWOXPCString)dlsym(RTLD_DEFAULT, "xpc_string_create");
    BQWOXPCRelease xpcRelease = (BQWOXPCRelease)dlsym(RTLD_DEFAULT, "xpc_release");
    BQWOConsume consume = (BQWOConsume)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    BQWORelease release = (BQWORelease)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    BQWOCheck check = (BQWOCheck)dlsym(RTLD_DEFAULT, "sandbox_check");
    void *sb = NULL;
    if (!check) {
        sb = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (sb) check = (BQWOCheck)dlsym(sb, "sandbox_check");
    }

    if (!(create && setClass && setIDs && setPart && setFlags && one && token &&
          releaseQuery && string && xpcRelease && consume && release)) {
        [out addObject:@"STOP: required MCM or sandbox APIs unavailable"];
    } else {
        [out addObject:[NSString stringWithFormat:@"Baseline policy=%@ write-open=%@",
                        BQWOSandboxStatus(check, path), BQWOOpenOnly(path)]];
        const struct { const char *name; uint64_t flags; } cases[] = {
            {"KAMUI-direct", 0x8100000000ULL},
            {"watchOS26-alternate", 0x0800000000ULL}
        };
        for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
            [out addObject:[NSString stringWithFormat:@"\n[%s flag=0x%llx]",
                            cases[i].name, (unsigned long long)cases[i].flags]];
            void *q = create();
            if (!q) {
                [out addObject:@"query-create=FAILED"];
                continue;
            }
            void *group = string("systemgroup.com.apple.mobilegestaltcache");
            if (!group) {
                [out addObject:@"group-identifier=FAILED"];
                releaseQuery(q);
                continue;
            }
            setClass(q, 13);
            setIDs(q, group);
            setPart(q, 3);
            setFlags(q, cases[i].flags);
            xpcRelease(group);
            void *res = one(q);
            [out addObject:[NSString stringWithFormat:@"MCM result=%@", res ? @"YES" : @"NO"]];
            char *raw = res ? token(res) : NULL;
            [out addObject:[NSString stringWithFormat:@"token=%@", raw ? @"YES" : @"NO"]];
            if (raw) {
                errno = 0;
                int64_t h = consume(raw);
                int err = errno;
                [out addObject:[NSString stringWithFormat:@"consume=%@",
                                h >= 0 ? @"SUCCESS" : [NSString stringWithFormat:@"FAILED errno=%d (%s)", err, strerror(err)]]];
                if (h >= 0) {
                    [out addObject:[NSString stringWithFormat:@"while consumed: policy=%@ write-open=%@",
                                    BQWOSandboxStatus(check, path), BQWOOpenOnly(path)]];
                    int64_t released = release(h);
                    [out addObject:[NSString stringWithFormat:@"release=%lld", (long long)released]];
                    [out addObject:[NSString stringWithFormat:@"after release: policy=%@",
                                    BQWOSandboxStatus(check, path)]];
                }
                free(raw);
            }
            releaseQuery(q);
        }
    }
    if (sb) dlclose(sb);
    dlclose(mgr);

    NSString *after = BQWOMetadata(path);
    [out addObject:[NSString stringWithFormat:@"\nMetadata after: %@", after]];
    [out addObject:[NSString stringWithFormat:@"Metadata unchanged=%@",
                    [before isEqualToString:after] ? @"YES" : @"NO/UNVERIFIABLE"]];
    [out addObject:@"No protected cache data was written by this method test."];
    NSString *report = [out componentsJoinedByString:@"\n"];
    NSError *error = nil;
    NSString *reportPath = [BQDocuments() stringByAppendingPathComponent:@"kamui26-write-open.txt"];
    if (![report writeToFile:reportPath atomically:YES
                  encoding:NSUTF8StringEncoding error:&error]) {
        report = [report stringByAppendingFormat:@"\nCould not save report: %@",
                  error.localizedDescription ?: @"unknown"];
    }
    NSLog(@"[KAMUI26WriteOpen]\n%@\n[/KAMUI26WriteOpen]", report);
    return report;
}
