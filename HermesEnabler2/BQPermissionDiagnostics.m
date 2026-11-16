#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>

typedef int (*BQSandboxCheckFn)(pid_t, const char *, int, ...);
// The value of SANDBOX_FILTER_PATH in Apple's sandbox.h.
static const int kBQSandboxFilterPath = 1;

static NSString *BQErrnoDescription(int code) {
    return [NSString stringWithFormat:@"%d (%s)", code, strerror(code)];
}

static NSString *BQPolicyResult(BQSandboxCheckFn check, NSString *operation,
                                NSString *path) {
    if (!check) return @"unavailable (sandbox_check symbol not exported)";
    errno = 0;
    int result = check(getpid(), operation.UTF8String, kBQSandboxFilterPath,
                       path.fileSystemRepresentation);
    if (result == 0) return @"ALLOW";
    if (result > 0) return [NSString stringWithFormat:@"DENY (%d)", result];
    return [NSString stringWithFormat:@"ERROR %@", BQErrnoDescription(errno)];
}

static NSString *BQOpenProbe(NSString *path, int flags, BOOL readOneByte) {
    errno = 0;
    // No O_CREAT and no O_TRUNC: protected paths will NEVER be modified.
    int fd = open(path.fileSystemRepresentation, flags | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return [NSString stringWithFormat:@"DENIED %@", BQErrnoDescription(errno)];
    NSString *result = @"ALLOWED (descriptor opened; no write performed)";
    if (readOneByte) {
        char oneByte = 0;
        errno = 0;
        ssize_t bytes = read(fd, &oneByte, 1);
        if (bytes < 0) result = [NSString stringWithFormat:@"OPEN ALLOWED; READ ERROR %@",
                                BQErrnoDescription(errno)];
        else result = [NSString stringWithFormat:@"ALLOWED (read %zd byte, value not logged)",
                       bytes];
    }
    close(fd);
    return result;
}

static NSString *BQStatProbe(NSString *path) {
    struct stat st;
    errno = 0;
    if (lstat(path.fileSystemRepresentation, &st) != 0)
        return [NSString stringWithFormat:@"UNAVAILABLE %@", BQErrnoDescription(errno)];
    return [NSString stringWithFormat:@"mode=%#o uid=%lu gid=%lu type=%@",
            (unsigned)(st.st_mode & 07777), (unsigned long)st.st_uid,
            (unsigned long)st.st_gid,
            S_ISDIR(st.st_mode) ? @"directory" : (S_ISREG(st.st_mode) ? @"file" : @"other")];
}

static NSString *BQOwnGroupControl(NSString *root) {
    if (!root.length) return @"SKIP (no accessible App Group root)";
    NSString *path = [root stringByAppendingPathComponent:
                      [@"mg-permission-control-" stringByAppendingString:NSUUID.UUID.UUIDString]];
    errno = 0;
    int fd = open(path.fileSystemRepresentation,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return [NSString stringWithFormat:@"CREATE FAILED %@",
                         BQErrnoDescription(errno)];
    const char payload[] = "OK";
    ssize_t wrote = write(fd, payload, 2);
    int writeErrno = errno;
    close(fd);
    if (wrote != 2) {
        unlink(path.fileSystemRepresentation);
        return [NSString stringWithFormat:@"WRITE FAILED %@",
                BQErrnoDescription(writeErrno)];
    }
    char bytes[2] = {0};
    errno = 0;
    int readFD = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (readFD < 0) {
        int error = errno;
        unlink(path.fileSystemRepresentation);
        return [NSString stringWithFormat:@"READBACK OPEN FAILED %@",
                BQErrnoDescription(error)];
    }
    ssize_t n = read(readFD, bytes, 2);
    close(readFD);
    BOOL matches = n == 2 && bytes[0] == 'O' && bytes[1] == 'K';
    errno = 0;
    int removed = unlink(path.fileSystemRepresentation);
    return [NSString stringWithFormat:@"create/write/readback=%@; cleanup=%@",
            matches ? @"PASS" : @"FAIL",
            removed == 0 ? @"PASS" : BQErrnoDescription(errno)];
}

static NSString *BQOSBuild(void) {
    char buf[128] = {0};
    size_t size = sizeof(buf);
    if (sysctlbyname("kern.osversion", buf, &size, NULL, 0) == 0)
        return [NSString stringWithUTF8String:buf] ?: @"unknown";
    return @"unavailable";
}

NSString *BQRunPermissionDiagnostics(void) {
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    [lines addObject:@"=== HermesEnabler permission diagnostics (safe preflight) ==="];
    [lines addObject:[NSString stringWithFormat:@"Time: %@", NSDate.date]];
    [lines addObject:[NSString stringWithFormat:@"OS: %@ | build: %@",
                      NSProcessInfo.processInfo.operatingSystemVersionString, BQOSBuild()]];
    [lines addObject:[NSString stringWithFormat:@"Bundle: %@",
                      NSBundle.mainBundle.bundleIdentifier ?: @"unknown"]];
    [lines addObject:[NSString stringWithFormat:@"App Group: %@",
                      BQGroupID() ?: @"not found"]];
    NSString *groupRoot = BQGroupRoot();
    [lines addObject:[NSString stringWithFormat:@"App Group root: %@",
                      groupRoot ?: @"not found"]];
    [lines addObject:@""];

    [lines addObject:@"[Control: own App Group (ONLY test that writes data)]"];
    [lines addObject:BQOwnGroupControl(groupRoot)];
    [lines addObject:@""];

    NSString *mgFile = BQMobileGestaltPath();
    NSString *mgDir = [mgFile stringByDeletingLastPathComponent];
    [lines addObject:@"[Protected MobileGestalt: metadata + read and open-only probes]"];
    [lines addObject:[NSString stringWithFormat:@"Directory: %@", mgDir]];
    [lines addObject:[NSString stringWithFormat:@"Directory lstat: %@", BQStatProbe(mgDir)]];
    [lines addObject:[NSString stringWithFormat:@"Directory open: %@",
                      BQOpenProbe(mgDir, O_RDONLY | O_DIRECTORY, NO)]];
    [lines addObject:[NSString stringWithFormat:@"Cache file: %@", mgFile]];
    [lines addObject:[NSString stringWithFormat:@"File lstat: %@", BQStatProbe(mgFile)]];
    [lines addObject:[NSString stringWithFormat:@"File read: %@",
                      BQOpenProbe(mgFile, O_RDONLY, YES)]];
    // O_WRONLY by itself does not alter file contents; fd is closed immediately.
    [lines addObject:[NSString stringWithFormat:@"File write-open (NO WRITES): %@",
                      BQOpenProbe(mgFile, O_WRONLY, NO)]];
    [lines addObject:@""];

    BQSandboxCheckFn check = (BQSandboxCheckFn)dlsym(RTLD_DEFAULT, "sandbox_check");
    void *library = NULL;
    if (!check) {
        library = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (library) check = (BQSandboxCheckFn)dlsym(library, "sandbox_check");
    }
    [lines addObject:@"[Sandbox authorization on protected file]"];
    for (NSString *operation in @[@"file-read-data", @"file-write-data",
                                   @"file-write-create", @"file-write-mode"]) {
        [lines addObject:[NSString stringWithFormat:@"%@: %@",
                          operation, BQPolicyResult(check, operation, mgFile)]];
    }
    if (library) dlclose(library);
    [lines addObject:@""];
    [lines addObject:@"No system file or cache contents were changed."];
    [lines addObject:@"No sandbox extension requested or consumed by this test."];
    [lines addObject:@"A successful write-open is NOT evidence of a safe MobileGestalt change."];
    NSString *report = [lines componentsJoinedByString:@"\n"];
    NSString *reportPath = [BQDocuments() stringByAppendingPathComponent:
                            @"mg-permission-diagnostics.txt"];
    NSError *error = nil;
    if (![report writeToFile:reportPath atomically:YES
                  encoding:NSUTF8StringEncoding error:&error]) {
        report = [report stringByAppendingFormat:@"\nCould not save report: %@",
                  error.localizedDescription ?: @"unknown error"];
    }
    NSLog(@"[MGDiagnostics]\n%@\n[/MGDiagnostics]", report);
    return report;
}
