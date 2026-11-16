#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <limits.h>
#import <stdlib.h>
#import <string.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <unistd.h>

// watchOS 26 diagnostic: explain independent authorization gates. Read-only:
// no sandbox extension, write-open, write, rename, symlink, cache or system mutations.
typedef int (*BQRCCheck)(pid_t, const char *, int, ...);

static NSString *BQRCError(int e) {
    return [NSString stringWithFormat:@"errno=%d (%s)", e, strerror(e)];
}
static BOOL BQRCGroupMatch(gid_t fileGID) {
    if (getegid() == fileGID) return YES;
    int count = getgroups(0, NULL);
    if (count <= 0 || count > 256) return NO;
    gid_t *groups = calloc((size_t)count, sizeof(gid_t));
    if (!groups) return NO;
    int result = getgroups(count, groups);
    BOOL found = NO;
    for (int i = 0; i < result; ++i) {
        if (groups[i] == fileGID) { found = YES; break; }
    }
    free(groups);
    return found;
}
static NSString *BQRCDAC(const struct stat *st, BOOL directory) {
    if (geteuid() == 0) return @"SUPERUSER: DAC estimate inconclusive";
    mode_t bit;
    NSString *source;
    if (geteuid() == st->st_uid) {
        bit = directory ? S_IXUSR : S_IWUSR;
        source = @"owner";
    } else if (BQRCGroupMatch(st->st_gid)) {
        bit = directory ? S_IXGRP : S_IWGRP;
        source = @"group";
    } else {
        bit = directory ? S_IXOTH : S_IWOTH;
        source = @"other";
    }
    return [NSString stringWithFormat:@"%@ %@=%@ (ACL/MAC not included)",
        source, directory ? @"search" : @"write",
        (st->st_mode & bit) ? @"YES" : @"NO"];
}
static NSString *BQRCStat(NSString *path, BOOL directory) {
    struct stat st = {0};
    errno = 0;
    if (lstat(path.fileSystemRepresentation, &st) != 0)
        return [@"lstat FAILED " stringByAppendingString:BQRCError(errno)];
    NSString *type = S_ISREG(st.st_mode) ? @"regular-file" :
                     (S_ISDIR(st.st_mode) ? @"directory" :
                     (S_ISLNK(st.st_mode) ? @"symlink" : @"other"));
    NSMutableString *flags = [NSMutableString string];
#ifdef UF_IMMUTABLE
    if (st.st_flags & UF_IMMUTABLE) [flags appendString:@" UF_IMMUTABLE"];
#endif
#ifdef SF_IMMUTABLE
    if (st.st_flags & SF_IMMUTABLE) [flags appendString:@" SF_IMMUTABLE"];
#endif
#ifdef UF_RESTRICTED
    if (st.st_flags & UF_RESTRICTED) [flags appendString:@" UF_RESTRICTED"];
#endif
    if (!flags.length) [flags appendString:@" none-recognized"];
    return [NSString stringWithFormat:
        @"type=%@ owner=%u group=%u mode=%04o flags=0x%lx (%@) inode=%llu size=%lld; DAC=%@",
        type, (unsigned)st.st_uid, (unsigned)st.st_gid,
        (unsigned)(st.st_mode & 07777), (unsigned long)st.st_flags, flags,
        (unsigned long long)st.st_ino, (long long)st.st_size,
        BQRCDAC(&st, directory)];
}
static NSInteger BQRCPolicy(BQRCCheck check, NSString *op, NSString *path,
                             NSMutableArray<NSString *> *out) {
    if (!check) {
        [out addObject:[NSString stringWithFormat:@"policy %@ = UNKNOWN (sandbox_check unavailable)", op]];
        return -1;
    }
    errno = 0;
    int result = check(getpid(), op.UTF8String, 1, path.fileSystemRepresentation);
    int err = errno;
    [out addObject:[NSString stringWithFormat:@"policy %@ = %@",
        op, result == 0 ? @"ALLOW" :
        result > 0 ? [NSString stringWithFormat:@"DENY(%d)", result] :
                     [@"ERROR " stringByAppendingString:BQRCError(err)]]];
    return result;
}
static NSString *BQRCMount(NSString *path) {
    struct statfs st = {0};
    errno = 0;
    if (statfs(path.fileSystemRepresentation, &st) != 0)
        return [@"UNKNOWN " stringByAppendingString:BQRCError(errno)];
    return [NSString stringWithFormat:@"fstype=%s readonly=%@ flags=0x%llx",
        st.f_fstypename, (st.f_flags & MNT_RDONLY) ? @"YES" : @"NO",
        (unsigned long long)st.f_flags];
}
static NSString *BQRCAccess(NSString *path, int mode) {
    errno = 0;
    int result = access(path.fileSystemRepresentation, mode);
    return result == 0 ? @"ALLOWED (not proof of open)" :
        [@"DENIED " stringByAppendingString:BQRCError(errno)];
}
static NSString *BQRCReadDescriptor(NSString *path) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return [@"DENIED " stringByAppendingString:BQRCError(errno)];
    NSMutableString *result = [NSMutableString stringWithString:@"ALLOW"];
    struct stat st = {0};
    if (fstat(fd, &st) == 0)
        [result appendFormat:@", inode=%llu", (unsigned long long)st.st_ino];
#ifdef F_GETPROTECTIONCLASS
    errno = 0;
    int protectionClass = fcntl(fd, F_GETPROTECTIONCLASS);
    if (protectionClass >= 0)
        [result appendFormat:@", protectionClass=%d (read descriptor only)", protectionClass];
    else
        [result appendFormat:@", protectionClass=UNAVAILABLE %@", BQRCError(errno)];
#endif
    close(fd);
    return result;
}
static NSString *BQRCAlias(NSString *path) {
    NSString *alias = [path hasPrefix:@"/private/var/"]
        ? [@"/var/" stringByAppendingString:[path substringFromIndex:@"/private/var/".length]]
        : path;
    struct stat one = {0}, two = {0};
    int a = stat(path.fileSystemRepresentation, &one);
    int b = stat(alias.fileSystemRepresentation, &two);
    if (a != 0 || b != 0) return @"alias identity unavailable";
    return [NSString stringWithFormat:
        @"same-device=%@ same-inode=%@ (path aliases are NOT independent authorization routes)",
        one.st_dev == two.st_dev ? @"YES" : @"NO",
        one.st_ino == two.st_ino ? @"YES" : @"NO"];
}

NSString *BQRunDenialRootCauseDiagnostics(void) {
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithObjects:
        @"=== watchOS 26 protected-write root-cause v1 ===",
        @"Safety: no protected write-open, no token, no symlinks, no mutations.",
        [NSString stringWithFormat:@"OS=%@ bundle=%@",
            NSProcessInfo.processInfo.operatingSystemVersionString,
            NSBundle.mainBundle.bundleIdentifier ?: @"unknown"],
        [NSString stringWithFormat:
            @"pid=%d uid=%u euid=%u gid=%u egid=%u",
            getpid(), (unsigned)getuid(), (unsigned)geteuid(),
            (unsigned)getgid(), (unsigned)getegid()],
        nil];

    NSString *mg = BQMobileGestaltPath();
    NSString *dir = [mg stringByDeletingLastPathComponent];
    NSString *lib = [dir stringByDeletingLastPathComponent];
    NSString *root = [lib stringByDeletingLastPathComponent];
    NSString *ownDoc = BQDocuments();
    NSString *ownGroup = BQGroupRoot();
    NSArray<NSDictionary<NSString *, NSString *> *> *targets = @[
        @{@"name": @"MG existing cache file", @"path": mg, @"directory": @"0"},
        @{@"name": @"MG cache parent", @"path": dir, @"directory": @"1"},
        @{@"name": @"MG Library parent", @"path": lib, @"directory": @"1"},
        @{@"name": @"MG SystemGroup root", @"path": root, @"directory": @"1"},
        @{@"name": @"App Documents control", @"path": ownDoc ?: @"", @"directory": @"1"},
        @{@"name": @"Own App Group control", @"path": ownGroup ?: @"", @"directory": @"1"}
    ];
    void *sb = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_LAZY | RTLD_LOCAL);
    BQRCCheck check = (BQRCCheck)dlsym(RTLD_DEFAULT, "sandbox_check");
    if (!check && sb) check = (BQRCCheck)dlsym(sb, "sandbox_check");

    NSInteger filePolicy = -1;
    BOOL fileDACNo = NO, mountReadOnly = NO, immutable = NO;
    struct stat fileStat = {0};
    BOOL statGood = lstat(mg.fileSystemRepresentation, &fileStat) == 0;
    if (statGood) {
        fileDACNo = geteuid() != 0 &&
            ((geteuid() == fileStat.st_uid && !(fileStat.st_mode & S_IWUSR)) ||
             (geteuid() != fileStat.st_uid && BQRCGroupMatch(fileStat.st_gid) &&
              !(fileStat.st_mode & S_IWGRP)) ||
             (geteuid() != fileStat.st_uid && !BQRCGroupMatch(fileStat.st_gid) &&
              !(fileStat.st_mode & S_IWOTH)));
#ifdef UF_IMMUTABLE
        immutable = immutable || (fileStat.st_flags & UF_IMMUTABLE);
#endif
#ifdef SF_IMMUTABLE
        immutable = immutable || (fileStat.st_flags & SF_IMMUTABLE);
#endif
    }
    struct statfs mountInfo = {0};
    if (statfs(mg.fileSystemRepresentation, &mountInfo) == 0)
        mountReadOnly = (mountInfo.f_flags & MNT_RDONLY) != 0;

    for (NSDictionary<NSString *, NSString *> *item in targets) {
        NSString *path = item[@"path"];
        if (!path.length) continue;
        BOOL isDir = [item[@"directory"] isEqualToString:@"1"];
        [out addObject:[NSString stringWithFormat:@"\n[%@]\npath=%@", item[@"name"], path]];
        [out addObject:[@"metadata: " stringByAppendingString:BQRCStat(path, isDir)]];
        [out addObject:[@"mount: " stringByAppendingString:BQRCMount(path)]];
        [out addObject:[@"access(R_OK): " stringByAppendingString:BQRCAccess(path, R_OK)]];
        [out addObject:[@"access(W_OK): " stringByAppendingString:BQRCAccess(path, W_OK)]];
        if ([path isEqualToString:mg]) {
            [out addObject:[@"open(O_RDONLY): " stringByAppendingString:BQRCReadDescriptor(path)]];
            filePolicy = BQRCPolicy(check, @"file-write-data", path, out);
            BQRCPolicy(check, @"file-read-data", path, out);
            [out addObject:[@"identity: " stringByAppendingString:BQRCAlias(path)]];
        } else if ([path isEqualToString:dir]) {
            BQRCPolicy(check, @"file-write-create", path, out);
            BQRCPolicy(check, @"file-read-data", path, out);
        } else if ([path isEqualToString:ownDoc] || [path isEqualToString:ownGroup]) {
            BQRCPolicy(check, @"file-write-create", path, out);
        }
    }
    if (sb) dlclose(sb);

    [out addObject:@"\n[Decision tree: independent permission gates]"];
    [out addObject:[NSString stringWithFormat:@"sandbox_file_write=%@",
        filePolicy == 0 ? @"ALLOW (only a policy preflight)" :
        filePolicy > 0 ? @"DENY" : @"UNKNOWN"]];
    [out addObject:[NSString stringWithFormat:@"POSIX_DAC_write_estimate=%@",
        !statGood ? @"UNKNOWN" : (fileDACNo ? @"DENY" : @"ALLOW/INCONCLUSIVE")]];
    [out addObject:[NSString stringWithFormat:@"volume_readonly=%@ file_immutable=%@",
        mountReadOnly ? @"YES" : @"NO/UNKNOWN", immutable ? @"YES" : @"NO/UNKNOWN"]];
    if (filePolicy > 0) {
        [out addObject:@"PRIMARY EVIDENCE: sandbox file-write-data is denied. "
            @"A sandbox extension token or App Group entitlement alone does not change this outcome."];
    }
    if (fileDACNo) {
        [out addObject:@"SECOND INDEPENDENT BARRIER: Unix owner/group/other bits "
            @"do not allow this effective user to write the file. "
            @"Even changing sandbox policy alone would not establish write access."];
    }
    if (mountReadOnly || immutable) {
        [out addObject:@"ADDITIONAL BARRIER: read-only mount or immutable flag indicated."];
    }
    [out addObject:@"LIMITATIONS: ACLs, file protection, mandatory access control, "
        @"process privilege and kernel authorization cannot be deduced conclusively "
        @"from metadata or errno alone. One EPERM is not evidence of a specific bypass."];
    [out addObject:@"No protected content was modified."];
    return [out componentsJoinedByString:@"\n"];
}
