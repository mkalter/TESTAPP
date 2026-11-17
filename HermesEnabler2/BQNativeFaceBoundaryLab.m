#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/task_special_ports.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <string.h>

// Native face boundary lab, Watch6,18 / 23U95.
// NO sandbox extensions, symlinks, file mutations, XPC messages, private
// entitlement requests, FaceBundle loads or MobileGestalt write-open tests.
// All Apple paths and services are constant and only probed for visibility.
// Actual reports are written ONLY to this app's own Documents directory.

typedef int (*NFBSandboxCheck)(pid_t, const char *, int, ...);
typedef kern_return_t (*NFBLaunchdLookup)(mach_port_t, const char *, mach_port_t *);

static const int NFBFilterPath = 1;          // SANDBOX_FILTER_PATH
static const int NFBFilterGlobalName = 2;    // SANDBOX_FILTER_GLOBAL_NAME

static NSString *NFBError(int code) {
    return [NSString stringWithFormat:@"%d (%s)", code, strerror(code)];
}
static NSString *NFBOSBuild(void) {
    char text[100] = {0};
    size_t length = sizeof(text);
    if (sysctlbyname("kern.osversion", text, &length, NULL, 0) == 0) {
        return [NSString stringWithUTF8String:text] ?: @"unknown";
    }
    return @"unknown";
}
static NSString *NFBHardware(void) {
    char text[100] = {0};
    size_t length = sizeof(text);
    if (sysctlbyname("hw.machine", text, &length, NULL, 0) == 0) {
        return [NSString stringWithUTF8String:text] ?: @"unknown";
    }
    return @"unknown";
}
static NSMutableArray<NSString *> *NFBStart(NSString *title) {
    return [NSMutableArray arrayWithObjects:
        [NSString stringWithFormat:@"=== Native Face Boundary Lab · %@ ===", title],
        [NSString stringWithFormat:@"Time=%@; machine=%@; OSbuild=%@",
            NSDate.date, NFBHardware(), NFBOSBuild()],
        [NSString stringWithFormat:@"App=%@",
            NSBundle.mainBundle.bundleIdentifier ?: @"unknown"],
        @"SCOPE: stock watchOS original Apple ClockFace gallery.",
        @"NOT an unlock; no FaceBundle import/add and no protected writes.",
        nil];
}
static NSString *NFBFinish(NSMutableArray<NSString *> *lines, NSString *name) {
    [lines addObject:@""];
    [lines addObject:@"No protected content changed, no sandbox token requested/consumed."];
    [lines addObject:@"An ALLOW preflight or Mach port is NOT face-library write authorization."];
    NSString *report = [lines componentsJoinedByString:@"\n"];
    NSString *destination = [BQDocuments() stringByAppendingPathComponent:name];
    NSError *error = nil;
    if (![report writeToFile:destination atomically:YES
                   encoding:NSUTF8StringEncoding error:&error]) {
        report = [report stringByAppendingFormat:@"\nReport save failed: %@",
                  error.localizedDescription ?: @"unknown"];
    }
    NSLog(@"[NativeFaceLab] %@\n[/NativeFaceLab]", report);
    return report;
}
static NFBSandboxCheck NFBCheckFunction(void) {
    NFBSandboxCheck check = (NFBSandboxCheck)dlsym(RTLD_DEFAULT, "sandbox_check");
    if (check) return check;
    static void *library;
    if (!library) library = dlopen("/usr/lib/system/libsystem_sandbox.dylib",
                                  RTLD_LAZY | RTLD_LOCAL);
    return library ? (NFBSandboxCheck)dlsym(library, "sandbox_check") : NULL;
}
static NSString *NFBCheck(NFBSandboxCheck check, NSString *operation,
                          int filter, NSString *target) {
    if (!check) return @"UNKNOWN (sandbox_check symbol missing)";
    errno = 0;
    int result = check(getpid(), operation.UTF8String, filter, target.UTF8String);
    if (result == 0) return @"ALLOW (preflight ONLY)";
    if (result > 0) return [NSString stringWithFormat:@"DENY (%d)", result];
    return [NSString stringWithFormat:@"ERROR %@", NFBError(errno)];
}
static NSArray<NSDictionary<NSString *, NSString *> *> *NFBServices(void) {
    return @[
        @{@"name":@"com.apple.ClockKit.CLKWatchFaceLibrary", @"role":@"ClockKit public face import control"},
        @{@"name":@"com.apple.NanoTimeKit.complication", @"role":@"NanoTimeKit generic allowlist control"},
        @{@"name":@"com.apple.nanofacegallery.librarybroker.server", @"role":@"native face library broker candidate"},
        @{@"name":@"com.apple.nanotimekit.replication.library.listener", @"role":@"native face replication listener"},
        @{@"name":@"com.apple.nanotimekit.facesupportserver", @"role":@"face assets service"},
        @{@"name":@"com.apple.nanotimekit.facesnapshotserver", @"role":@"snapshot service"},
        @{@"name":@"com.apple.Carousel.NTKServer", @"role":@"Carousel server candidate"},
        @{@"name":@"com.apple.mobilegestalt.xpc", @"role":@"MobileGestalt lookup control (no XPC)"}
    ];
}

NSString *BQRunNativeFaceMachPolicy(void) {
    NSMutableArray<NSString *> *lines = NFBStart(@"T1: mach-lookup sandbox preflight");
    NFBSandboxCheck check = NFBCheckFunction();
    [lines addObject:@"sandbox_check(getpid(), mach-lookup, GLOBAL_NAME=2, fixed service)"];
    for (NSDictionary<NSString *, NSString *> *item in NFBServices()) {
        NSString *service = item[@"name"];
        [lines addObject:[NSString stringWithFormat:@"[%@] %@", service, item[@"role"]]];
        [lines addObject:[NSString stringWithFormat:@"mach-lookup=%@",
            NFBCheck(check, @"mach-lookup", NFBFilterGlobalName, service)]];
    }
    [lines addObject:@"No XPC object, connection or Mach message was created."];
    return NFBFinish(lines, @"native-face-mach-policy.txt");
}

NSString *BQRunNativeFaceBootstrapLookup(void) {
    NSMutableArray<NSString *> *lines = NFBStart(@"T2: bootstrap name lookup only");
    [lines addObject:@"task_get_special_port(self,TASK_BOOTSTRAP_PORT) then bootstrap_look_up"];
    [lines addObject:@"Only resolves Mach names; no NSXPCConnection, protocol, messages or calls."];
    NFBLaunchdLookup lookup = (NFBLaunchdLookup)dlsym(RTLD_DEFAULT, "bootstrap_look_up");
    if (!lookup) {
        [lines addObject:@"bootstrap_look_up unavailable on this Watch process"];
        return NFBFinish(lines, @"native-face-bootstrap-lookup.txt");
    }
    mach_port_t boot = MACH_PORT_NULL;
    kern_return_t result = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &boot);
    [lines addObject:[NSString stringWithFormat:@"TASK_BOOTSTRAP_PORT status=%d", result]];
    if (result != KERN_SUCCESS || boot == MACH_PORT_NULL) {
        [lines addObject:@"Could not obtain own bootstrap port. No service queried."];
        return NFBFinish(lines, @"native-face-bootstrap-lookup.txt");
    }
    for (NSDictionary<NSString *, NSString *> *item in NFBServices()) {
        NSString *service = item[@"name"];
        mach_port_t target = MACH_PORT_NULL;
        kern_return_t kr = lookup(boot, service.UTF8String, &target);
        BOOL received = (kr == KERN_SUCCESS && target != MACH_PORT_NULL);
        [lines addObject:[NSString stringWithFormat:@"[%@] kr=%d port=%@",
            service, kr, received ? @"RECEIVED" : @"NONE"]];
        if (target != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), target);
    }
    mach_port_deallocate(mach_task_self(), boot);
    [lines addObject:@"Received ports were released immediately; no messages sent."];
    return NFBFinish(lines, @"native-face-bootstrap-lookup.txt");
}

static NSString *NFBMetadata(NSString *path, BOOL *isDirectory) {
    *isDirectory = NO;
    struct stat st = {0};
    errno = 0;
    if (lstat(path.fileSystemRepresentation, &st) != 0) {
        return [@"lstat=" stringByAppendingString:NFBError(errno)];
    }
    *isDirectory = S_ISDIR(st.st_mode);
    NSString *kind = S_ISDIR(st.st_mode) ? @"directory" :
                     (S_ISREG(st.st_mode) ? @"regular" :
                     (S_ISLNK(st.st_mode) ? @"symlink" : @"other"));
    return [NSString stringWithFormat:@"lstat=EXISTS type=%@ mode=%04o",
        kind, (unsigned)(st.st_mode & 07777)];
}
static NSString *NFBReadOpen(NSString *path, BOOL isDirectory) {
    int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (isDirectory ? O_DIRECTORY : 0);
    errno = 0;
    int fd = open(path.fileSystemRepresentation, flags);
    if (fd < 0) return [@"read-only open=" stringByAppendingString:NFBError(errno)];
    close(fd);
    return @"read-only open=ALLOWED; closed without reading contents";
}
static void NFBPathReport(NSMutableArray<NSString *> *lines,
                          NFBSandboxCheck check,
                          NSString *label, NSString *path) {
    if (!path.length) {
        [lines addObject:[NSString stringWithFormat:@"[%@] unavailable", label]];
        return;
    }
    BOOL isDirectory = NO;
    [lines addObject:[NSString stringWithFormat:@"[%@] %@", label, path]];
    [lines addObject:NFBMetadata(path, &isDirectory)];
    for (NSString *op in @[@"file-read-data", @"file-write-data", @"file-write-create"]) {
        [lines addObject:[NSString stringWithFormat:@"%@=%@",
            op, NFBCheck(check, op, NFBFilterPath, path)]];
    }
    [lines addObject:NFBReadOpen(path, isDirectory)];
}

NSString *BQRunNativeFaceStorePolicy(void) {
    NSMutableArray<NSString *> *lines = NFBStart(@"T3: native store paths");
    [lines addObject:@"Read-only lstat/open + sandbox_check; WRITE PRE-FLIGHT ONLY."];
    NFBSandboxCheck check = NFBCheckFunction();
    NSArray<NSDictionary<NSString *, NSString *> *> *paths = @[
        @{@"label":@"global NanoTimeKit root", @"path":@"/private/var/mobile/Library/NanoTimeKit"},
        @{@"label":@"FaceSupport directory", @"path":@"/private/var/mobile/Library/NanoTimeKit/FaceSupport"},
        @{@"label":@"FaceSupport assets", @"path":@"/private/var/mobile/Library/NanoTimeKit/FaceSupport/Assets"},
        @{@"label":@"FaceSupport date store", @"path":@"/private/var/mobile/Library/NanoTimeKit/FaceSupport/DateDatabase.db"},
        @{@"label":@"NanoTimeKit prefs candidate", @"path":@"/private/var/mobile/Library/Preferences/com.apple.NanoTimeKit.face.plist"},
        @{@"label":@"MobileGestalt comparison", @"path":BQMobileGestaltPath()},
        @{@"label":@"own Documents positive control", @"path":BQDocuments()}
    ];
    for (NSDictionary<NSString *, NSString *> *target in paths)
        NFBPathReport(lines, check, target[@"label"], target[@"path"]);
    NSString *group = BQGroupRoot();
    [lines addObject:[NSString stringWithFormat:@"Own entitled AppGroup=%@",
       BQGroupID() ?: @"none"]];
    if (group.length) NFBPathReport(lines, check, @"own AppGroup control", group);
    else [lines addObject:@"No entitled AppGroup root; cannot infer other AppGroup access."];
    [lines addObject:@"There was no O_WRONLY/O_RDWR/open-create/write/unlink at an Apple path."];
    return NFBFinish(lines, @"native-face-store-policy.txt");
}

NSString *BQRunNativeFaceBundleInventory(void) {
    NSMutableArray<NSString *> *lines = NFBStart(@"T4: Apple native bundle presence");
    [lines addObject:@"Fixed signed FaceBundle paths, lstat and read-only open only."];
    NFBSandboxCheck check = NFBCheckFunction();
    NSArray<NSDictionary<NSString *, NSString *> *> *paths = @[
        @{@"label":@"FaceBundle root", @"path":@"/System/Library/NanoTimeKit/FaceBundles"},
        @{@"label":@"Zeus original bundle directory", @"path":@"/System/Library/NanoTimeKit/FaceBundles/NTKZeusFaceBundle.bundle"},
        @{@"label":@"Zeus original Mach-O candidate", @"path":@"/System/Library/NanoTimeKit/FaceBundles/NTKZeusFaceBundle.bundle/NTKZeusFaceBundle"},
        @{@"label":@"Hermes2025 original directory", @"path":@"/System/Library/NanoTimeKit/FaceBundles/NTKHermes2025FaceBundle.bundle"},
        @{@"label":@"Hermes2025 original Mach-O candidate", @"path":@"/System/Library/NanoTimeKit/FaceBundles/NTKHermes2025FaceBundle.bundle/NTKHermes2025FaceBundle"},
        @{@"label":@"NanoTimeKit framework", @"path":@"/System/Library/PrivateFrameworks/NanoTimeKit.framework"},
        @{@"label":@"nanotimekitd process executable", @"path":@"/System/Library/PrivateFrameworks/NanoTimeKit.framework/nanotimekitd"}
    ];
    for (NSDictionary<NSString *, NSString *> *target in paths)
        NFBPathReport(lines, check, target[@"label"], target[@"path"]);
    [lines addObject:@"An absent candidate FILE PATH does not prove the signed bundle is missing: dyld/cry ptex layouts vary."];
    [lines addObject:@"No private library loaded; no face preview created."];
    return NFBFinish(lines, @"native-face-bundle-inventory.txt");
}
