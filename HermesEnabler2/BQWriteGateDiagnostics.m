#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <sys/mount.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <unistd.h>
#import <string.h>

// Non-destructive authorization evidence collection. Deliberately does not
// acquire MCM sandbox extensions, redirect symlinks, or alter protected paths.
typedef int (*BQGateSandboxCheck)(pid_t, const char *, int, ...);
typedef CFTypeRef (*BQGateTaskCreate)(CFAllocatorRef);
typedef CFTypeRef (*BQGateReadEntitlement)(CFTypeRef, CFStringRef, CFErrorRef *);
static const int BQGateFilterPath = 1; // SANDBOX_FILTER_PATH

static NSString *BQGateOSBuild(void) {
    char version[128] = {0};
    size_t size = sizeof(version);
    if (sysctlbyname("kern.osversion", version, &size, NULL, 0) == 0)
        return [NSString stringWithUTF8String:version] ?: @"unknown";
    return @"unavailable";
}

static NSString *BQGateErrno(int error) {
    return [NSString stringWithFormat:@"%d (%s)", error, strerror(error)];
}

static NSString *BQGateStat(NSString *path) {
    struct stat s = {0};
    errno = 0;
    if (lstat(path.fileSystemRepresentation, &s) < 0)
        return [@"lstat error: " stringByAppendingString:BQGateErrno(errno)];
    return [NSString stringWithFormat:
            @"uid=%lu gid=%lu mode=%#o flags=0x%lx type=%@ size=%lld",
            (unsigned long)s.st_uid, (unsigned long)s.st_gid,
            (unsigned)(s.st_mode & 07777), (unsigned long)s.st_flags,
            S_ISREG(s.st_mode) ? @"file" :
            (S_ISDIR(s.st_mode) ? @"directory" : (S_ISLNK(s.st_mode) ? @"symlink" : @"other")),
            (long long)s.st_size];
}

static NSString *BQGateMount(NSString *path) {
    struct statfs s = {0};
    errno = 0;
    if (statfs(path.fileSystemRepresentation, &s) != 0)
        return [@"statfs error: " stringByAppendingString:BQGateErrno(errno)];
    return [NSString stringWithFormat:@"fstype=%s mounted_from=%s readonly=%@ flags=0x%llx",
            s.f_fstypename, s.f_mntfromname,
            (s.f_flags & MNT_RDONLY) ? @"YES" : @"NO",
            (unsigned long long)s.f_flags];
}

static NSString *BQGateAccess(NSString *path, int mode) {
    errno = 0;
    int result = access(path.fileSystemRepresentation, mode);
    return result == 0 ? @"YES (not proof of open authorization)"
                       : [@"NO " stringByAppendingString:BQGateErrno(errno)];
}

static NSString *BQGateOpenNoWrite(NSString *path) {
    errno = 0;
    // Intentionally NO O_CREAT, NO O_TRUNC, NO write(), NO pwrite().
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return [NSString stringWithFormat:@"DENIED %@", BQGateErrno(errno)];
    close(fd);
    return @"ALLOWED (opened and closed without writing)";
}

static NSString *BQGatePolicy(BQGateSandboxCheck check,
                               NSString *operation, NSString *path) {
    if (!check) return @"unavailable";
    errno = 0;
    int result = check(getpid(), operation.UTF8String, BQGateFilterPath,
                       path.fileSystemRepresentation);
    if (result == 0) return @"ALLOW";
    if (result > 0) return [NSString stringWithFormat:@"DENY (%d)", result];
    return [@"ERROR " stringByAppendingString:BQGateErrno(errno)];
}

static NSDictionary<NSString *, NSString *> *BQGateEntitlements(void) {
    NSArray<NSString *> *names = @[
        @"com.apple.security.application-groups",
        @"com.apple.security.system-group-containers",
        @"com.apple.security.system-groups"
    ];
    NSMutableDictionary<NSString *, NSString *> *out = [NSMutableDictionary dictionary];
    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security",
                       RTLD_LAZY | RTLD_LOCAL);
    BQGateTaskCreate create = (BQGateTaskCreate)dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf");
    BQGateReadEntitlement read = (BQGateReadEntitlement)dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
    if (sec && !create) create = (BQGateTaskCreate)dlsym(sec, "SecTaskCreateFromSelf");
    if (sec && !read) read = (BQGateReadEntitlement)dlsym(sec, "SecTaskCopyValueForEntitlement");
    CFTypeRef task = (create && read) ? create(kCFAllocatorDefault) : NULL;
    for (NSString *name in names) {
        NSString *status = @"UNAVAILABLE (not evidence of absence)";
        if (task && read) {
            CFTypeRef val = read(task, (__bridge CFStringRef)name, NULL);
            if (val) {
                status = @"PRESENT";
                CFRelease(val);
            } else {
                status = @"NOT RETURNED (may be absent or inaccessible)";
            }
        }
        out[name] = status;
    }
    if (task) CFRelease(task);
    if (sec) dlclose(sec);
    return out;
}

NSString *BQRunWriteGateDiagnostics(void) {
    NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObjects:
        @"=== HermesEnabler Protected Write Authorization — Preflight ===",
        @"NO protected writes / NO sandbox escapes / NO symlink redirection",
        nil];
    [lines addObject:[NSString stringWithFormat:@"Time: %@", [NSDate date]]];
    [lines addObject:[NSString stringWithFormat:@"OS: %@ | build: %@",
                      [NSProcessInfo processInfo].operatingSystemVersionString, BQGateOSBuild()]];
    [lines addObject:[NSString stringWithFormat:@"bundle=%@", 
                      [NSBundle mainBundle].bundleIdentifier ?: @"unknown"]];
    [lines addObject:[NSString stringWithFormat:@"pid=%d real_uid=%lu effective_uid=%lu real_gid=%lu effective_gid=%lu",
                      getpid(), (unsigned long)getuid(), (unsigned long)geteuid(),
                      (unsigned long)getgid(), (unsigned long)getegid()]];
    NSString *mgFile = BQMobileGestaltPath();
    NSString *mgDir = [mgFile stringByDeletingLastPathComponent];
    NSString *systemGroupRoot = [mgDir stringByDeletingLastPathComponent];
    NSString *ownFile = BQLogPath();
    NSString *ownDocuments = BQDocuments();
    NSString *ownGroup = BQGroupRoot();
    [lines addObject:@"\n[Signed process entitlement presence (read-only)]"];
    NSDictionary *entitlements = BQGateEntitlements();
    for (NSString *name in @[@"com.apple.security.application-groups",
                            @"com.apple.security.system-group-containers",
                            @"com.apple.security.system-groups"]) {
        [lines addObject:[NSString stringWithFormat:@"%@ : %@", name, entitlements[name]]];
    }

    BQGateSandboxCheck check = (BQGateSandboxCheck)dlsym(RTLD_DEFAULT, "sandbox_check");
    void *sandboxLibrary = NULL;
    if (!check) {
        sandboxLibrary = dlopen("/usr/lib/system/libsystem_sandbox.dylib",
                               RTLD_LAZY | RTLD_LOCAL);
        if (sandboxLibrary)
            check = (BQGateSandboxCheck)dlsym(sandboxLibrary, "sandbox_check");
    }
    NSArray<NSDictionary *> *targets = @[
        @{@"name": @"Protected MG cache file", @"path": mgFile},
        @{@"name": @"Protected MG cache directory", @"path": mgDir},
        @{@"name": @"Protected SystemGroup Library", @"path": systemGroupRoot},
        @{@"name": @"Own Documents directory", @"path": ownDocuments ?: @""},
        @{@"name": @"Own log file (control)", @"path": ownFile ?: @""},
        @{@"name": @"Own App Group (control)", @"path": ownGroup ?: @""}
    ];
    NSArray<NSString *> *operations = @[
        @"file-read-data",
        @"file-write-data",
        @"file-write-create",
        @"file-write-unlink",
        @"file-write-mode",
        @"file-write-xattr"
    ];
    for (NSDictionary *target in targets) {
        NSString *path = target[@"path"];
        [lines addObject:[NSString stringWithFormat:@"\n[%@]", target[@"name"]]];
        if (!path.length) {
            [lines addObject:@"SKIPPED: missing path"];
            continue;
        }
        [lines addObject:[NSString stringWithFormat:@"path=%@", path]];
        [lines addObject:[NSString stringWithFormat:@"metadata=%@", BQGateStat(path)]];
        [lines addObject:[NSString stringWithFormat:@"filesystem=%@", BQGateMount(path)]];
        [lines addObject:[NSString stringWithFormat:@"access(R_OK)=%@", BQGateAccess(path, R_OK)]];
        [lines addObject:[NSString stringWithFormat:@"access(W_OK)=%@", BQGateAccess(path, W_OK)]];
        for (NSString *operation in operations) {
            [lines addObject:[NSString stringWithFormat:@"%@=%@",
                              operation, BQGatePolicy(check, operation, path)]];
        }
        if ([path isEqualToString:mgFile] || [path isEqualToString:ownFile]) {
            [lines addObject:[NSString stringWithFormat:@"open(O_WRONLY|O_NOFOLLOW), NO WRITE=%@",
                              BQGateOpenNoWrite(path)]];
        }
    }
    if (sandboxLibrary) dlclose(sandboxLibrary);
    [lines addObject:@"\nInterpretation:"];
    [lines addObject:@"- sandbox_check DENY + O_WRONLY EPERM: strong evidence of a sandbox authorization boundary."];
    [lines addObject:@"- private entitlement NOT RETURNED: does not prove entitlement impossibility."];
    [lines addObject:@"- mount readonly or immutable flags: separate filesystem restrictions."];
    [lines addObject:@"- own-container controls allow writes: signing works, SystemGroup permissions remain separate."];
    [lines addObject:@"- successful O_WRONLY would not prove that a safe MG modification is possible."];
    [lines addObject:@"- every probe above is read-only or an open/close without writes."];
    NSString *report = [lines componentsJoinedByString:@"\n"];
    NSString *path = [BQDocuments() stringByAppendingPathComponent:@"mg-write-gates.txt"];
    NSError *error = nil;
    if (![report writeToFile:path atomically:YES
                  encoding:NSUTF8StringEncoding error:&error]) {
        report = [report stringByAppendingFormat:@"\nCould not save to Documents: %@",
                  error.localizedDescription ?: @"unknown"];
    }
    NSLog(@"[MGWriteGates]\n%@\n[/MGWriteGates]", report);
    return report;
}
