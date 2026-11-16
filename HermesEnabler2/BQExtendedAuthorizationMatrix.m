#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>

// Authorization observation only. This code never requests or consumes sandbox
// extensions and never writes, creates, removes, renames or truncates a
// protected file. The only output is a text report in the app's Documents.
typedef int (*BQMatrixSandboxCheck)(pid_t, const char *, int, ...);
static const int kBQMatrixPathFilter = 1;

static NSString *BQMatrixErr(int e) {
    return [NSString stringWithFormat:@"%d (%s)", e, strerror(e)];
}

static NSString *BQMatrixBuild(void) {
    char value[128] = {0};
    size_t length = sizeof(value);
    if (sysctlbyname("kern.osversion", value, &length, NULL, 0) == 0)
        return [NSString stringWithUTF8String:value] ?: @"unknown";
    return @"unknown";
}

static NSString *BQMatrixMetadata(NSString *path, BOOL *isDirectory) {
    struct stat st = {0};
    *isDirectory = NO;
    errno = 0;
    if (lstat(path.fileSystemRepresentation, &st) != 0)
        return [@"lstat: " stringByAppendingString:BQMatrixErr(errno)];
    *isDirectory = S_ISDIR(st.st_mode);
    return [NSString stringWithFormat:
            @"type=%@ mode=%04o uid=%u gid=%u inode=%llu size=%lld",
            S_ISREG(st.st_mode) ? @"file" :
                (S_ISDIR(st.st_mode) ? @"directory" :
                 (S_ISLNK(st.st_mode) ? @"symlink" : @"other")),
            (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid,
            (unsigned)st.st_gid, (unsigned long long)st.st_ino,
            (long long)st.st_size];
}

static NSString *BQMatrixReadOpen(NSString *path, BOOL isDirectory) {
    int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
    if (isDirectory) flags |= O_DIRECTORY;
    errno = 0;
    int fd = open(path.fileSystemRepresentation, flags);
    if (fd < 0)
        return [@"DENIED " stringByAppendingString:BQMatrixErr(errno)];
    struct stat st = {0};
    int statResult = fstat(fd, &st);
    int e = errno;
    close(fd);
    if (statResult != 0)
        return [@"OPENED but fstat failed " stringByAppendingString:BQMatrixErr(e)];
    return @"ALLOW (read-only descriptor opened and closed)";
}

NSString *BQRunExtendedAuthorizationMatrix(void) {
    NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObjects:
        @"=== HermesEnabler extended authorization matrix v1 ===",
        @"READ-ONLY POLICY AUDIT: no protected writes, token consumption, symlinks, traversal or exploitation.",
        @"Every sandbox_check result is an observation, NOT proof that an actual write would succeed.",
        [NSString stringWithFormat:@"Timestamp=%@", NSDate.date],
        [NSString stringWithFormat:@"OS=%@ build=%@",
            NSProcessInfo.processInfo.operatingSystemVersionString, BQMatrixBuild()],
        [NSString stringWithFormat:@"Bundle=%@", NSBundle.mainBundle.bundleIdentifier ?: @"unknown"],
        nil];

    NSString *mg = BQMobileGestaltPath();
    NSString *caches = [mg stringByDeletingLastPathComponent];
    NSString *systemLibrary = [caches stringByDeletingLastPathComponent];
    NSString *systemGroup = [systemLibrary stringByDeletingLastPathComponent];
    NSString *systemGroupParent = [systemGroup stringByDeletingLastPathComponent];
    NSString *docs = BQDocuments();
    NSString *home = NSHomeDirectory();
    NSString *ownCaches = [home stringByAppendingPathComponent:@"Library/Caches"];
    NSString *ownTmp = NSTemporaryDirectory();
    NSString *group = BQGroupRoot();

    // Existing target path and its actual parents, plus app-owned controls.
    // NO attacker-controlled input, aliases, symlinks, forged identifiers or
    // alternate path traversal is involved.
    NSMutableArray<NSDictionary<NSString *, NSString *> *> *targets =
        [NSMutableArray arrayWithArray:@[
            @{@"name": @"protected-mg-file", @"path": mg},
            @{@"name": @"protected-mg-caches", @"path": caches},
            @{@"name": @"protected-systemgroup-library", @"path": systemLibrary},
            @{@"name": @"protected-systemgroup-root", @"path": systemGroup},
            @{@"name": @"shared-systemgroups-parent", @"path": systemGroupParent},
            @{@"name": @"own-documents", @"path": docs},
            @{@"name": @"own-existing-log", @"path":
                [docs stringByAppendingPathComponent:@"bqtool.log"]},
            @{@"name": @"own-library-caches", @"path": ownCaches},
            @{@"name": @"own-temporary-directory", @"path": ownTmp},
            @{@"name": @"own-application-home", @"path": home}
        ]];
    if (group.length) {
        [targets addObject:@{@"name": @"own-entitled-appgroup", @"path": group}];
        [targets addObject:@{@"name": @"own-appgroup-library",
                              @"path": [group stringByAppendingPathComponent:@"Library"]}];
    }

    // Only operation names already used by the existing write gate audit.
    NSArray<NSString *> *operations = @[
        @"file-read-data", @"file-write-data", @"file-write-create",
        @"file-write-unlink", @"file-write-mode", @"file-write-xattr"
    ];

    BQMatrixSandboxCheck check = (BQMatrixSandboxCheck)dlsym(RTLD_DEFAULT, "sandbox_check");
    void *sandboxLib = NULL;
    if (!check) {
        sandboxLib = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (sandboxLib)
            check = (BQMatrixSandboxCheck)dlsym(sandboxLib, "sandbox_check");
    }

    NSUInteger allowed = 0, denied = 0, errors = 0, unknown = 0;
    [lines addObject:[NSString stringWithFormat:
        @"Targets=%lu | policy operations=%lu | combinations=%lu",
        (unsigned long)targets.count, (unsigned long)operations.count,
        (unsigned long)(targets.count * operations.count)]];
    if (!check)
        [lines addObject:@"WARNING: sandbox_check unavailable; policy decisions marked UNKNOWN"];

    for (NSDictionary<NSString *, NSString *> *target in targets) {
        NSString *path = target[@"path"];
        NSString *label = target[@"name"];
        if (!path.length) continue;
        [lines addObject:[NSString stringWithFormat:@"\n[%@]\npath=%@", label, path]];
        BOOL isDir = NO;
        [lines addObject:BQMatrixMetadata(path, &isDir)];
        errno = 0;
        int r = access(path.fileSystemRepresentation, R_OK);
        int e = errno;
        [lines addObject:[NSString stringWithFormat:@"access(R_OK)=%@",
            r == 0 ? @"YES" : [@"NO " stringByAppendingString:BQMatrixErr(e)]]];
        errno = 0;
        r = access(path.fileSystemRepresentation, W_OK);
        e = errno;
        [lines addObject:[NSString stringWithFormat:@"access(W_OK)=%@",
            r == 0 ? @"YES" : [@"NO " stringByAppendingString:BQMatrixErr(e)]]];
        [lines addObject:[@"open(O_RDONLY|O_NOFOLLOW)="
            stringByAppendingString:BQMatrixReadOpen(path, isDir)]];

        for (NSString *op in operations) {
            NSString *decision;
            if (!check) {
                decision = @"UNKNOWN (symbol missing)";
                unknown++;
            } else {
                errno = 0;
                int answer = check(getpid(), op.UTF8String, kBQMatrixPathFilter,
                                   path.fileSystemRepresentation);
                int errorCode = errno;
                if (answer == 0) {
                    decision = @"ALLOW";
                    allowed++;
                } else if (answer > 0) {
                    decision = [NSString stringWithFormat:@"DENY (%d)", answer];
                    denied++;
                } else {
                    decision = [@"ERROR " stringByAppendingString:BQMatrixErr(errorCode)];
                    errors++;
                }
            }
            [lines addObject:[NSString stringWithFormat:@"sandbox %@ = %@", op, decision]];
        }
    }

    if (sandboxLib) dlclose(sandboxLib);
    [lines addObject:[NSString stringWithFormat:
        @"\nSUMMARY checks=%lu allow=%lu deny=%lu error=%lu unknown=%lu",
        (unsigned long)(targets.count * operations.count),
        (unsigned long)allowed, (unsigned long)denied,
        (unsigned long)errors, (unsigned long)unknown]];
    [lines addObject:@"SUCCESS CRITERION: this matrix only observes permissions. Do not infer MG write ability from token/path/policy alone."];
    [lines addObject:@"ZERO protected file modifications attempted. No sandbox token requested or consumed."];
    NSString *report = [lines componentsJoinedByString:@"\n"];
    NSString *destination = [docs stringByAppendingPathComponent:@"extended-authorization-matrix.txt"];
    NSError *error = nil;
    if (![report writeToFile:destination atomically:YES
                   encoding:NSUTF8StringEncoding error:&error]) {
        report = [report stringByAppendingFormat:@"\nREPORT SAVE FAILED: %@",
                  error.localizedDescription ?: @"unknown"];
    }
    NSLog(@"[ExtendedAuthorization]\n%@\n[/ExtendedAuthorization]", report);
    return report;
}
