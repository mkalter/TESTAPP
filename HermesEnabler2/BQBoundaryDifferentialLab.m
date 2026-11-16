#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <stdlib.h>
#import <string.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <unistd.h>

// Boundary-differential lab. MG is opened READ-ONLY and metadata-only.
// Writes, creates and cleanup are limited to a randomized path in the app's
// own Documents / own entitled App Group. No sandbox extensions or XPC calls.

typedef int (*BQLabSandboxCheck)(pid_t, const char *, int, ...);
typedef ssize_t (*BQLabFListXattr)(int, char *, size_t, int);
typedef ssize_t (*BQLabListXattr)(const char *, char *, size_t, int);
typedef void *(*BQLabGetACL)(int);
typedef int (*BQLabACLEntry)(void *, int, void **);
typedef int (*BQLabACLFree)(void *);

static NSString *BQLabErr(int e) {
    return [NSString stringWithFormat:@"errno=%d (%s)", e, strerror(e)];
}
static NSString *BQLabPolicy(BQLabSandboxCheck check, NSString *op, NSString *path) {
    if (!check) return @"UNKNOWN (symbol unavailable)";
    errno = 0;
    int res = check(getpid(), op.UTF8String, 1, path.fileSystemRepresentation);
    if (res == 0) return @"ALLOW (preflight only)";
    if (res > 0) return [NSString stringWithFormat:@"DENY(%d) (preflight only)", res];
    return [@"ERROR " stringByAppendingString:BQLabErr(errno)];
}
static void BQLabPolicyRows(NSMutableArray<NSString *> *out, BQLabSandboxCheck check,
                            NSString *path, NSString *prefix) {
    for (NSString *op in @[@"file-read-data", @"file-write-data",
                           @"file-write-create", @"file-write-unlink",
                           @"file-write-xattr", @"file-write-mode"]) {
        [out addObject:[NSString stringWithFormat:@"%@ %@ = %@",
            prefix, op, BQLabPolicy(check, op, path)]];
    }
}
static NSString *BQLabXattrList(NSString *path, int fd, BOOL fdBased) {
    // Only attribute names, never values. Do not leak any security tokens.
    BQLabFListXattr fList = (BQLabFListXattr)dlsym(RTLD_DEFAULT, "flistxattr");
    BQLabListXattr pList = (BQLabListXattr)dlsym(RTLD_DEFAULT, "listxattr");
    if ((fdBased && !fList) || (!fdBased && !pList))
        return @"UNKNOWN: xattr list symbol absent";
    errno = 0;
    ssize_t count = fdBased ? fList(fd, NULL, 0, 0) :
                               pList(path.fileSystemRepresentation, NULL, 0, 0);
    if (count < 0) return [@"DENIED " stringByAppendingString:BQLabErr(errno)];
    if (count == 0) return @"EMPTY (no names returned)";
    if (count > 8192) return [NSString stringWithFormat:@"UNEXPECTED length=%lld (>8192; ignored)", (long long)count];
    char *buffer = calloc((size_t)count + 1, 1);
    if (!buffer) return @"UNKNOWN: allocation failed";
    errno = 0;
    ssize_t readSize = fdBased ? fList(fd, buffer, (size_t)count, 0) :
                                 pList(path.fileSystemRepresentation, buffer, (size_t)count, 0);
    if (readSize < 0) {
        NSString *err = BQLabErr(errno);
        free(buffer);
        return [@"DENIED " stringByAppendingString:err];
    }
    NSMutableArray<NSString *> *names = [NSMutableArray array];
    size_t used = 0, total = (size_t)readSize;
    while (used < total && names.count < 32) {
        size_t length = strnlen(buffer + used, total - used);
        if (length == total - used) break;
        NSString *name = [[NSString alloc] initWithBytes:buffer + used
                                                   length:length
                                                 encoding:NSUTF8StringEncoding];
        [names addObject:name ?: @"<undecodable>"];
        used += length + 1;
    }
    free(buffer);
    return [NSString stringWithFormat:@"names=%lu (values not read): %@",
        (unsigned long)names.count, [names componentsJoinedByString:@", "]];
}
static NSString *BQLabACL(int fd) {
    BQLabGetACL getACL = (BQLabGetACL)dlsym(RTLD_DEFAULT, "acl_get_fd");
    BQLabACLEntry getEntry = (BQLabACLEntry)dlsym(RTLD_DEFAULT, "acl_get_entry");
    BQLabACLFree release = (BQLabACLFree)dlsym(RTLD_DEFAULT, "acl_free");
    if (!getACL || !getEntry || !release) return @"UNKNOWN: ACL symbol(s) missing";
    errno = 0;
    void *acl = getACL(fd);
    if (!acl) return [@"UNAVAILABLE " stringByAppendingString:BQLabErr(errno)];
    int count = 0;
    void *entry = NULL;
    // POSIX ACL_FIRST_ENTRY == 0 and ACL_NEXT_ENTRY == -1 (Darwin).
    int id = 0, state = 0;
    while (count < 256 && (state = getEntry(acl, id, &entry)) == 1) {
        ++count;
        id = -1;
    }
    release(acl);
    if (state < 0) return [NSString stringWithFormat:@"entries-count=%d; enumeration error", count];
    return [NSString stringWithFormat:@"extended-ACL entries=%d (rights not inferred)", count];
}
static NSString *BQLabSHA256(int fd, off_t size) {
    // Bounded read of an already readable file; only its digest is logged.
    if (size < 0 || size > 131072)
        return @"SKIP: read-only SHA256 bounded to 128 KiB";
    unsigned char *buffer = malloc((size_t)size + 1);
    if (!buffer) return @"UNAVAILABLE: allocation failed";
    size_t consumed = 0;
    while (consumed < (size_t)size) {
        errno = 0;
        ssize_t n = pread(fd, buffer + consumed, (size_t)size - consumed, (off_t)consumed);
        if (n <= 0) {
            NSString *err = n < 0 ? BQLabErr(errno) : @"early EOF";
            free(buffer);
            return [@"UNAVAILABLE " stringByAppendingString:err];
        }
        consumed += (size_t)n;
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(buffer, (CC_LONG)consumed, digest);
    free(buffer);
    NSMutableString *hash = [NSMutableString string];
    for (size_t i=0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [hash appendFormat:@"%02x", digest[i]];
    return hash;
}
static NSString *BQLabInspectFile(NSMutableArray<NSString *> *out,
                                  NSString *path, NSString *label) {
    [out addObject:[NSString stringWithFormat:@"\n[%@] %@", label, path]];
    struct stat before={0};
    errno = 0;
    if (lstat(path.fileSystemRepresentation, &before) != 0) {
        [out addObject:[@"lstat=" stringByAppendingString:BQLabErr(errno)]];
        return @"";
    }
    [out addObject:[NSString stringWithFormat:@"lstat uid=%u gid=%u mode=%04o flags=0x%lx size=%lld inode=%llu",
        (unsigned)before.st_uid, (unsigned)before.st_gid,
        (unsigned)(before.st_mode & 07777), (unsigned long)before.st_flags,
        (long long)before.st_size, (unsigned long long)before.st_ino]];
    errno=0;
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) {
        [out addObject:[@"open(O_RDONLY) DENIED " stringByAppendingString:BQLabErr(errno)]];
        [out addObject:[@"listxattr(path)=" stringByAppendingString:BQLabXattrList(path,-1,NO)]];
        return @"";
    }
    struct stat opened={0};
    if (fstat(fd,&opened)==0) {
        [out addObject:[NSString stringWithFormat:@"fstat(opened) inode=%llu same-vnode=%@",
            (unsigned long long)opened.st_ino,
            (before.st_ino==opened.st_ino && before.st_dev==opened.st_dev)?@"YES":@"NO"]];
        [out addObject:[@"read-only content SHA256=" stringByAppendingString:BQLabSHA256(fd,opened.st_size)]];
    }
    [out addObject:[@"ACL via read descriptor=" stringByAppendingString:BQLabACL(fd)]];
    [out addObject:[@"flistxattr(read descriptor)=" stringByAppendingString:BQLabXattrList(path,fd,YES)]];
    [out addObject:[@"listxattr(path)=" stringByAppendingString:BQLabXattrList(path,fd,NO)]];
#ifdef F_GETPROTECTIONCLASS
    errno=0;
    int protection=fcntl(fd,F_GETPROTECTIONCLASS);
    [out addObject:[NSString stringWithFormat:@"F_GETPROTECTIONCLASS=%@",
        protection>=0?[NSString stringWithFormat:@"%d",protection]:BQLabErr(errno)]];
#endif
#ifdef F_GETPATH
    char buffer[MAXPATHLEN]={0};
    errno=0;
    int success=fcntl(fd,F_GETPATH,buffer);
    [out addObject:[NSString stringWithFormat:@"F_GETPATH=%@",
        success==0?([NSString stringWithUTF8String:buffer]?:@"UNKNOWN"):BQLabErr(errno)]];
#endif
    struct statfs fsm={0};
    errno=0;
    if (fstatfs(fd,&fsm)==0)
        [out addObject:[NSString stringWithFormat:@"fstatfs from read fd: type=%s readOnly=%@ flags=0x%llx",
            fsm.f_fstypename,(fsm.f_flags&MNT_RDONLY)?@"YES":@"NO",
            (unsigned long long)fsm.f_flags]];
    else [out addObject:[@"fstatfs=" stringByAppendingString:BQLabErr(errno)]];
    close(fd);
    struct stat after={0};
    if(lstat(path.fileSystemRepresentation,&after)==0)
        [out addObject:[NSString stringWithFormat:
            @"post-inspection metadata stable=%@ (inode/size/mtime)",
            (before.st_ino==after.st_ino && before.st_size==after.st_size &&
             before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec &&
             before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec)?@"YES":@"NO"]];
    return @"";
}
static void BQLabOwnedFileControl(NSMutableArray<NSString *> *out,
                                 NSString *root, NSString *name,
                                 BQLabSandboxCheck check) {
    [out addObject:[NSString stringWithFormat:@"\n[OWNED CONTROL: %@]",name]];
    if(!root.length) {
        [out addObject:@"SKIPPED: no root"];
        return;
    }
    // Controlled paths. The protected system group is never passed here.
    NSString *temp=[root stringByAppendingPathComponent:
        [@"boundary_lab_" stringByAppendingString:NSUUID.UUID.UUIDString]];
    NSString *nested=[temp stringByAppendingPathComponent:@"Library/Caches"];
    NSError *err=nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:nested
                            withIntermediateDirectories:YES attributes:nil error:&err]) {
        [out addObject:[NSString stringWithFormat:@"cannot create isolated control directory: %@",
                        err.localizedDescription ?: @"unknown"]];
        return;
    }
    NSString *file=[nested stringByAppendingPathComponent:@"dummy.plist"];
    BQLabPolicyRows(out,check,nested,@"policy(parent)");
    BQLabPolicyRows(out,check,file,@"policy(file before create)");
    errno=0;
    int fd=open(file.fileSystemRepresentation,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0644);
    if(fd<0){
        [out addObject:[@"actual create failed: " stringByAppendingString:BQLabErr(errno)]];
    } else {
        const char payload[]="TEST"; // only a disposable owned file
        errno=0;
        ssize_t written=write(fd,payload,sizeof(payload));
        [out addObject:[NSString stringWithFormat:@"actual write-own-file=%@",
            written==sizeof(payload)?@"PASS":[@"FAIL " stringByAppendingString:BQLabErr(errno)]]];
        close(fd);
        BQLabPolicyRows(out,check,file,@"policy(file after create)");
        [out addObject:[@"access(W_OK)=" stringByAppendingString:
            access(file.fileSystemRepresentation,W_OK)==0?@"YES":@"NO"]];
        errno=0;
        int writeFd=open(file.fileSystemRepresentation,O_WRONLY|O_NOFOLLOW|O_CLOEXEC);
        [out addObject:[NSString stringWithFormat:@"actual O_WRONLY own-file=%@",
            writeFd>=0?@"ALLOW":BQLabErr(errno)]];
        if(writeFd>=0)close(writeFd);
        BQLabInspectFile(out,file,@"OWNED control metadata & ACL");
    }
    err=nil;
    BOOL cleanup=[[NSFileManager defaultManager] removeItemAtPath:temp error:&err];
    [out addObject:[NSString stringWithFormat:@"control cleanup=%@%@",
        cleanup?@"PASS":@"FAIL",err?err.localizedDescription:@""]];
}
NSString *BQRunBoundaryDifferentialLab(void) {
    NSMutableArray<NSString *> *out=[NSMutableArray arrayWithObjects:
        @"=== watchOS 26 boundary differential lab v1 ===",
        @"MG: only read-descriptor, ACL, xattr names, SHA256, metadata; no protected write-open.",
        @"Own control: creates/writes/deletes isolated dummy files in entitled containers.",
        @"No MCM token requests, symlinks, XPC calls, sandbox escapes or protected mutations.",
        [NSString stringWithFormat:@"OS=%@ bundle=%@",
            NSProcessInfo.processInfo.operatingSystemVersionString,
            NSBundle.mainBundle.bundleIdentifier?:@"unknown"],nil];

    void *sb=dlopen("/usr/lib/system/libsystem_sandbox.dylib",RTLD_LAZY|RTLD_LOCAL);
    BQLabSandboxCheck check=(BQLabSandboxCheck)dlsym(RTLD_DEFAULT,"sandbox_check");
    if(!check&&sb)check=(BQLabSandboxCheck)dlsym(sb,"sandbox_check");

    NSString *mg=BQMobileGestaltPath();
    NSString *mgParent=[mg stringByDeletingLastPathComponent];
    NSString *ownDocs=BQDocuments();
    NSString *ownGroup=BQGroupRoot();

    BQLabPolicyRows(out,check,mg,@"MG policy");
    BQLabInspectFile(out,mg,@"PROTECTED MG FILE (READ ONLY)");
    BQLabPolicyRows(out,check,mgParent,@"MG parent policy");
    [out addObject:[NSString stringWithFormat:@"\n[PROTECTED MG PARENT] %@",mgParent]];
    struct stat st={0};
    errno=0;
    if(lstat(mgParent.fileSystemRepresentation,&st)==0)
        [out addObject:[NSString stringWithFormat:@"parent mode=%04o uid=%u gid=%u",
            (unsigned)(st.st_mode&07777),(unsigned)st.st_uid,(unsigned)st.st_gid]];
    else [out addObject:[@"parent lstat failed " stringByAppendingString:BQLabErr(errno)]];
    [out addObject:[@"parent listxattr=" stringByAppendingString:BQLabXattrList(mgParent,-1,NO)]];

    BQLabOwnedFileControl(out,ownDocs,@"Documents",check);
    BQLabOwnedFileControl(out,ownGroup,@"Entitled AppGroup",check);
    if(sb)dlclose(sb);
    [out addObject:@"\n[INTERPRETATION / STOP CONDITIONS]"];
    [out addObject:@"If MG ACL is empty and DAC owner allows, sandbox/MAC remains the observable gate; a negative sandbox_check cannot uniquely identify its source rule."];
    [out addObject:@"If own file operations succeed despite DENY policy preflights, sandbox_check is not a universal predictor in the current process. Use real ops on OWNED files only."];
    [out addObject:@"Extended attribute presence alone does not prove authorization or a write bypass; no values printed."];
    [out addObject:@"A protected cache SHA256 verifies file contents at read time, not authorization to modify."];
    [out addObject:@"No protected file or directory modification was attempted."];
    return [out componentsJoinedByString:@"\n"];
}
