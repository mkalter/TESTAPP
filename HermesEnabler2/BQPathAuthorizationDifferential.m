#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <unistd.h>
#import <string.h>

// This is an authorization-SEMANTICS experiment, not a sandbox escape.
// Only files created in this application's own containers are ever written.
// No protected file is opened for writing and no sandbox tokens are requested.
typedef int (*BQPathPolicy)(pid_t, const char *, int, ...);
static const int kPathFilter = 1;  // SANDBOX_FILTER_PATH

static NSString *PathErr(int e) {
    return [NSString stringWithFormat:@"%d (%s)", e, strerror(e)];
}
static NSString *Check(BQPathPolicy fn, NSString *operation, NSString *path) {
    if (!fn) return @"UNKNOWN: sandbox_check not exported";
    if (!path.length) return @"UNKNOWN: empty path";
    errno = 0;
    int rc = fn(getpid(), operation.UTF8String, kPathFilter, path.fileSystemRepresentation);
    int e = errno;
    if (rc == 0) return @"ALLOW";
    if (rc > 0) return [NSString stringWithFormat:@"DENY (%d)", rc];
    return [@"ERROR " stringByAppendingString:PathErr(e)];
}
static void Audit(NSMutableArray<NSString *> *out,
                  BQPathPolicy fn, NSString *label, NSString *path) {
    [out addObject:[NSString stringWithFormat:@"[%@]", label]];
    if (!path.length) {
        [out addObject:@"path unavailable (not tested)"];
        return;
    }
    // We record logical scope only, without disclosing random container UUIDs.
    for (NSString *operation in @[@"file-read-data", @"file-write-data",
                                  @"file-write-create", @"file-write-unlink"]) {
        [out addObject:[NSString stringWithFormat:@"%@=%@",
                        operation, Check(fn, operation, path)]];
    }
}

// The only actual create/write operations in this test happen at app-owned
// fresh paths. Each path is unique and cleaned up. Never use system paths.
static void OwnControl(NSMutableArray<NSString *> *out,
                       BQPathPolicy fn, NSString *label, NSString *directory) {
    if (!directory.length) {
        [out addObject:[NSString stringWithFormat:@"[%@] SKIP: unavailable", label]];
        return;
    }
    struct stat st = {0};
    if (lstat(directory.fileSystemRepresentation, &st) != 0 || !S_ISDIR(st.st_mode)) {
        [out addObject:[NSString stringWithFormat:@"[%@] SKIP: no existing owned directory", label]];
        return;
    }
    NSString *child = [directory stringByAppendingPathComponent:
        [NSString stringWithFormat:@"auth-semantics-%@.txt", NSUUID.UUID.UUIDString]];
    Audit(out, fn, [label stringByAppendingString:@" directory"], directory);
    Audit(out, fn, [label stringByAppendingString:@" future child"], child);

    const char payload[] = "OWNED-CONTROL";
    errno = 0;
    int fd = open(child.fileSystemRepresentation, O_CREAT | O_EXCL | O_RDWR |
                  O_CLOEXEC | O_NOFOLLOW, 0600);
    int openErr = errno;
    if (fd < 0) {
        [out addObject:[NSString stringWithFormat:@"own child create=DENIED %@",
                        PathErr(openErr)]];
        return;
    }
    [out addObject:@"own child create=ALLOW"];
    errno = 0;
    ssize_t written = write(fd, payload, sizeof(payload) - 1);
    int writeErr = errno;
    (void)fsync(fd);
    close(fd);
    [out addObject:[NSString stringWithFormat:@"own child write=%@",
                    written == sizeof(payload) - 1 ? @"PASS" : PathErr(writeErr)]];
    Audit(out, fn, [label stringByAppendingString:@" created child"], child);
    char readback[sizeof(payload)] = {0};
    errno = 0;
    int rd = open(child.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (rd < 0) {
        [out addObject:[NSString stringWithFormat:@"own child readback-open=DENIED %@",
                        PathErr(errno)]];
    } else {
        ssize_t got = read(rd, readback, sizeof(payload) - 1);
        close(rd);
        BOOL pass = got == sizeof(payload) - 1 &&
                    memcmp(payload, readback, sizeof(payload) - 1) == 0;
        [out addObject:[NSString stringWithFormat:@"own child readback=%@",
                        pass ? @"PASS" : @"FAIL"]];
    }
    errno = 0;
    int removed = unlink(child.fileSystemRepresentation);
    [out addObject:[NSString stringWithFormat:@"own child cleanup=%@",
                    removed == 0 ? @"PASS" : PathErr(errno)]];
}

NSString *BQRunPathAuthorizationDifferential(void) {
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithObjects:
        @"=== watchOS path authorization differential v1 ===",
        @"Goal: compare policy on a DIRECTORY vs the EXACT CHILD filename.",
        @"PROTECTED MOBILEGESTALT: sandbox_check only, no write-open or modification.",
        @"ONLY OWN CONTAINERS: fresh disposable file create/write/readback/cleanup.",
        [NSString stringWithFormat:@"OS=%@",
         NSProcessInfo.processInfo.operatingSystemVersionString], nil];

    BQPathPolicy check = (BQPathPolicy)dlsym(RTLD_DEFAULT, "sandbox_check");
    void *library = NULL;
    if (!check) {
        library = dlopen("/usr/lib/system/libsystem_sandbox.dylib",
                         RTLD_LAZY | RTLD_LOCAL);
        if (library) check = (BQPathPolicy)dlsym(library, "sandbox_check");
    }

    NSString *mg = BQMobileGestaltPath();
    NSString *mgDir = [mg stringByDeletingLastPathComponent];
    Audit(out, check, @"protected MG exact file (policy only)", mg);
    Audit(out, check, @"protected MG parent directory (policy only)", mgDir);

    OwnControl(out, check, @"own Documents", BQDocuments());
    OwnControl(out, check, @"own AppGroup root", BQGroupRoot());
    NSString *groupRoot = BQGroupRoot();
    NSString *groupLibrary = groupRoot.length
        ? [groupRoot stringByAppendingPathComponent:@"Library"] : nil;
    OwnControl(out, check, @"own AppGroup Library", groupLibrary);

    if (library) dlclose(library);
    [out addObject:@""];
    [out addObject:@"Interpretation: a DENY on a directory's file-write-data does not"];
    [out addObject:@"necessarily predict file-write-create on a new child path."];
    [out addObject:@"A successful own-AppGroup write says nothing about SystemGroup rights."];
    [out addObject:@"No protected-write authorization, sandbox escape or cache mutation attempted."];

    NSString *report = [out componentsJoinedByString:@"\n"];
    NSString *path = [BQDocuments() stringByAppendingPathComponent:
                      @"path-authorization-differential.txt"];
    NSError *error = nil;
    if (![report writeToFile:path atomically:YES
                  encoding:NSUTF8StringEncoding error:&error]) {
        report = [report stringByAppendingFormat:
                  @"\nCould not save report: %@",
                  error.localizedDescription ?: @"unknown"];
    }
    NSLog(@"[PathAuthorization]\n%@\n[/PathAuthorization]", report);
    return report;
}
