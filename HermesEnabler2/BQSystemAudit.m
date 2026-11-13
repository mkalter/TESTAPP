#import "BQSystemAudit.h"
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <limits.h>

typedef int (*BQSandboxCheck)(pid_t, const char *, int, ...);
typedef CFTypeRef (*BQCreateSelfTask)(CFAllocatorRef);
typedef CFTypeRef (*BQCopyEntitlement)(CFTypeRef, CFStringRef, CFErrorRef *);

static NSString *BQAccessState(NSString *path, int mode) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation, mode | O_CLOEXEC | O_NOFOLLOW);
    int e = errno;
    if (fd < 0) return [NSString stringWithFormat:@"DENIED errno=%d (%s)", e, strerror(e)];
    struct stat st = {0};
    int rc = fstat(fd, &st);
    close(fd);
    return rc == 0
        ? [NSString stringWithFormat:@"OPEN OK size=%lld owner=%u:%u mode=%04o",
            (long long)st.st_size, st.st_uid, st.st_gid, (unsigned)(st.st_mode & 07777)]
        : @"OPEN OK (fstat failed)";
}

// 'sandbox_check' is a private diagnostic API on these platforms. Its decision
// is only a sandbox-policy indication; vnode permissions and other MAC hooks can
// still reject open(2). Never treat a permitted check as a verified write.
static BQSandboxCheck BQGetSandboxCheck(void) {
    static BQSandboxCheck check = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (!h) h = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_LAZY | RTLD_LOCAL);
        check = (BQSandboxCheck)dlsym(RTLD_DEFAULT, "sandbox_check");
        if (!check && h) check = (BQSandboxCheck)dlsym(h, "sandbox_check");
    });
    return check;
}

static NSString *BQSandboxPathDecision(BQSandboxCheck check,
                                        NSString *operation, NSString *path) {
    if (!check) return @"API unavailable";
    // SANDBOX_FILTER_PATH == 1 in the native sandbox filter enumeration.
    errno = 0;
    int rc = check(getpid(), operation.UTF8String, 1, path.fileSystemRepresentation);
    int e = errno;
    return rc == 0 ? @"ALLOW (policy)" :
        [NSString stringWithFormat:@"DENY/UNKNOWN rc=%d errno=%d", rc, e];
}

NSString *BQSandboxPolicySummary(NSString *path) {
    BQSandboxCheck check = BQGetSandboxCheck();
    if (!check) return @"sandbox_check symbol missing on this build";
    NSArray<NSString *> *ops = @[@"file-read-data", @"file-write-data", @"file-write-create", @"file-unlink"];
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    for (NSString *op in ops) {
        [out addObject:[NSString stringWithFormat:@"%@=%@",
            op, BQSandboxPathDecision(check, op, path)]];
    }
    return [out componentsJoinedByString:@"; "];
}

static NSString *BQEntitlementValueDescription(CFTypeRef value) {
    if (!value) return @"NOT PRESENT / unavailable";
    if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
        return CFBooleanGetValue((CFBooleanRef)value) ? @"TRUE" : @"FALSE";
    }
    if (CFGetTypeID(value) == CFArrayGetTypeID()) {
        return [NSString stringWithFormat:@"PRESENT (array count=%ld)", (long)CFArrayGetCount((CFArrayRef)value)];
    }
    if (CFGetTypeID(value) == CFDictionaryGetTypeID()) {
        return [NSString stringWithFormat:@"PRESENT (dictionary count=%ld)", (long)CFDictionaryGetCount((CFDictionaryRef)value)];
    }
    return [NSString stringWithFormat:@"PRESENT (typeID=%lu)", (unsigned long)CFGetTypeID(value)];
}

static void BQAppendEntitlementAudit(NSMutableString *out) {
    [out appendString:@"\n=== SIGNED ENTITLEMENTS (SELF ONLY) ===\n"];
    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security",
                       RTLD_LAZY | RTLD_LOCAL);
    BQCreateSelfTask create = (BQCreateSelfTask)dlsym(RTLD_DEFAULT, "SecTaskCreateFromSelf");
    BQCopyEntitlement copy = (BQCopyEntitlement)dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
    if (!create && sec) create = (BQCreateSelfTask)dlsym(sec, "SecTaskCreateFromSelf");
    if (!copy && sec) copy = (BQCopyEntitlement)dlsym(sec, "SecTaskCopyValueForEntitlement");
    if (!create || !copy) {
        [out appendString:@"SecTask entitlement API unavailable on this watchOS runtime. This is not proof of absent entitlements.\n"];
        return;
    }
    CFTypeRef task = create(kCFAllocatorDefault);
    if (!task) {
        [out appendString:@"SecTaskCreateFromSelf returned no task; entitlement state unknown.\n"];
        return;
    }
    NSArray<NSString *> *keys = @[
        @"com.apple.security.application-groups",
        @"com.apple.security.system-groups",
        @"get-task-allow",
        @"com.apple.private.security.container-manager",
        @"com.apple.private.security.storage.MobileGestalt",
        @"com.apple.private.MobileGestalt.AllowedProtectedKeys",
        @"com.apple.private.MobileGestalt.AllowedProtectedKeys2"
    ];
    for (NSString *key in keys) {
        CFErrorRef error = NULL;
        CFTypeRef value = copy(task, (__bridge CFStringRef)key, &error);
        [out appendFormat:@"%@ -> %@%@\n", key,
            BQEntitlementValueDescription(value),
            error ? @" (SecTask returned an error)" : @""];
        if (value) CFRelease(value);
        if (error) CFRelease(error);
    }
    CFRelease(task);
    [out appendString:@"The queried private keys are candidates, not confirmed watchOS entitlement requirements. No entitlement is changed.\n"];
}

static void BQAppendSystemFileAudit(NSMutableString *out) {
    [out appendString:@"\n=== FILESYSTEM / VNODE DIFFERENTIAL ===\n"];
    NSString *home = NSHomeDirectory();
    NSString *ownFile = [home stringByAppendingPathComponent:@"Documents/watchos26-audit-control.txt"];
    NSString *mg = @"/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist";
    NSString *mgAlias = [@"/var/" stringByAppendingString:[mg substringFromIndex:@"/private/var/".length]];
    NSArray<NSArray<NSString *> *> *targets = @[
        @[@"Watch MobileGestalt file", mg],
        @[@"Watch MobileGestalt /var alias", mgAlias],
        @[@"Watch MobileGestalt parent Caches", [mg stringByDeletingLastPathComponent]],
        @[@"Watch MobileGestalt SystemGroup", [mg stringByDeletingLastPathComponent].stringByDeletingLastPathComponent],
        @[@"Own application Documents directory", [home stringByAppendingPathComponent:@"Documents"]],
        @[@"Own application file (not created)", ownFile]
    ];
    for (NSArray<NSString *> *row in targets) {
        NSString *name = row[0], *path = row[1];
        struct stat st = {0};
        errno = 0;
        int rc = lstat(path.fileSystemRepresentation, &st);
        int e = errno;
        [out appendFormat:@"\n[%@]\nlstat=%@%@\n", name,
            rc == 0 ? [NSString stringWithFormat:@"OK owner=%u:%u mode=%04o inode=%llu link=%@",
                st.st_uid, st.st_gid, (unsigned)(st.st_mode & 07777),
                (unsigned long long)st.st_ino, S_ISLNK(st.st_mode) ? @"YES" : @"NO"] : @"DENIED/NOT FOUND",
            rc == 0 ? @"" : [NSString stringWithFormat:@" errno=%d", e]];
        [out appendFormat:@"O_RDONLY+O_NOFOLLOW=%@\nO_RDWR+O_NOFOLLOW=%@\nO_WRONLY+O_NOFOLLOW=%@\n",
            BQAccessState(path, O_RDONLY),
            BQAccessState(path, O_RDWR),
            BQAccessState(path, O_WRONLY)];
        [out appendFormat:@"sandbox policy: %@\n", BQSandboxPolicySummary(path)];
    }
    [out appendString:@"The own app control file is never created; ENOENT there is expected.\n"];
}

static void BQAppendDaemonSurfaceAudit(NSMutableString *out) {
    [out appendString:@"\n=== SYSTEM DAEMON / REACHABILITY SURFACE ===\n"];
    [out appendString:@"A policy ALLOW does NOT prove a service exists or accepts any caller. No XPC messages are sent.\n"];
    NSArray<NSString *> *names = @[
        @"com.apple.containermanagerd",
        @"com.apple.mobilegestalt.xpc",
        @"com.apple.MobileGestaltHelper",
        @"com.apple.geod",
        @"com.apple.installcoordinationd",
        @"com.apple.mobile.installd",
        @"com.apple.backupd",
        @"com.apple.mobilebackup2"
    ];
    BQSandboxCheck check = BQGetSandboxCheck();
    for (NSString *name in names) {
        if (!check) {
            [out appendFormat:@"%@ -> sandbox_check API unavailable\n", name];
            continue;
        }
        errno = 0;
        // SANDBOX_FILTER_GLOBAL_NAME == 2. Only checks this app's policy.
        int rc = check(getpid(), "mach-lookup", 2, name.UTF8String);
        [out appendFormat:@"%@ -> mach-lookup %@ (rc=%d errno=%d)\n",
            name, rc == 0 ? @"ALLOWED BY POLICY" : @"DENIED/UNKNOWN", rc, errno];
    }
    NSArray<NSString *> *executables = @[
        @"/usr/libexec/MobileGestaltHelper",
        @"/usr/libexec/installcoordinationd",
        @"/usr/libexec/containermanagerd",
        @"/usr/libexec/geod",
        @"/usr/libexec/BackupAgent2"
    ];
    for (NSString *path in executables) {
        struct stat st = {0};
        errno = 0;
        int rc = stat(path.fileSystemRepresentation, &st);
        [out appendFormat:@"path %@ -> %@%@\n", path,
             rc == 0 ? @"stat OK" : @"NOT VISIBLE / MISSING",
             rc == 0 ? @"" : [NSString stringWithFormat:@" errno=%d", errno]];
    }
}

NSString *BQSystemAudit(void) {
    NSMutableString *out = [NSMutableString stringWithString:
        @"\n=== WATCHOS SECURITY-BOUNDARY AUDIT v3 ===\n"];
    [out appendFormat:@"pid=%d uid=%u euid=%u sandbox=%@\n",
        getpid(), getuid(), geteuid(), BQGetSandboxCheck() ? @"available" : @"unavailable"];
    BQAppendEntitlementAudit(out);
    BQAppendSystemFileAudit(out);
    BQAppendDaemonSurfaceAudit(out);
    [out appendString:@"\nINTERPRETATION: This is passive capability reconnaissance, not a new sandbox exploit. No protected file, daemon, backup or system setting was modified.\n"];
    return out;
}
