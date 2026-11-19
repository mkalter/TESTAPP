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
typedef kern_return_t (*NFBSpecialPort)(mach_port_t, int, mach_port_t *);

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
        @{@"name":@"com.apple.nanofacegallery.gallerybroker.server", @"role":@"native gallery broker candidate"},
        @{@"name":@"com.apple.nanotimekit.collectionserver", @"role":@"native collection server candidate"},
        @{@"name":@"com.apple.nanotimekit.companionrelayserver", @"role":@"Watch/phone relay candidate"},
        @{@"name":@"com.apple.nanotimekit.replication.library.listener", @"role":@"native face replication listener"},
        @{@"name":@"com.apple.nanotimekit.facesupportserver", @"role":@"face assets service"},
        @{@"name":@"com.apple.nanotimekit.facesnapshotserver", @"role":@"snapshot service"},
        @{@"name":@"com.apple.Carousel.NTKServer", @"role":@"Carousel server candidate"},
        @{@"name":@"com.apple.mobilegestalt.xpc", @"role":@"MobileGestalt lookup control (no XPC)"},
        @{@"name":@"com.apple.tccd", @"role":@"TCC protected-file advisory candidate (no XPC)"},
        @{@"name":@"com.apple.mobile.softwareupdated", @"role":@"Software Update advisory candidate (no XPC)"}
    ];
}


/**
 * T5: read-only triage for separately published TCC / Software Update
 * protected-file advisories. This is NOT a vulnerability proof or XPC call.
 * Do not infer path traversal, arbitrary write, or native-face activation.
 */
NSString *BQRunProtectedWriterServiceGate(void) {
    NSMutableArray<NSString *> *lines = NFBStart(@"T5: protected-file service boundary");
    [lines addObject:@"Context: TCC (CVE-2026-86886) and Software Update (CVE-2026-84609)."];
    [lines addObject:@"Only own-process sandbox preflight and target lstat metadata."];
    [lines addObject:[NSString stringWithFormat:@"Caller uid=%lu euid=%lu gid=%lu egid=%lu",
                      (unsigned long)getuid(), (unsigned long)geteuid(),
                      (unsigned long)getgid(), (unsigned long)getegid()]];
    NFBSandboxCheck check = NFBCheckFunction();
    NSArray<NSDictionary<NSString *, NSString *> *> *services = @[
        @{@"name":@"com.apple.tccd", @"role":@"TCC (original 23U95 launchd name)"},
        @{@"name":@"com.apple.mobile.softwareupdated", @"role":@"Software Update (original 23U95 launchd name)"},
        @{@"name":@"com.apple.mobilegestalt.xpc", @"role":@"MobileGestalt helper control"},
        @{@"name":@"com.apple.ClockKit.CLKWatchFaceLibrary", @"role":@"ClockKit library control"}
    ];
    for (NSDictionary<NSString *, NSString *> *service in services) {
        NSString *name = service[@"name"];
        [lines addObject:[NSString stringWithFormat:@"[%@] %@", name, service[@"role"]]];
        [lines addObject:[NSString stringWithFormat:@"mach-lookup=%@",
                          NFBCheck(check, @"mach-lookup", NFBFilterGlobalName, name)]];
    }
    NSString *target = BQMobileGestaltPath();
    [lines addObject:[NSString stringWithFormat:@"Protected cache=%@", target]];
    struct stat st = {0};
    errno = 0;
    if (lstat(target.fileSystemRepresentation, &st) == 0) {
        [lines addObject:[NSString stringWithFormat:
            @"lstat type=%@ mode=%04o uid=%lu gid=%lu size=%lld",
            S_ISREG(st.st_mode) ? @"regular" : (S_ISLNK(st.st_mode) ? @"symlink" : @"other"),
            (unsigned)(st.st_mode & 07777), (unsigned long)st.st_uid,
            (unsigned long)st.st_gid, (long long)st.st_size]];
        [lines addObject:[NSString stringWithFormat:@"caller-owns-cache=%@ (POSIX only; NOT sandbox authorization)",
                          (st.st_uid == geteuid()) ? @"YES" : @"NO"]];
    } else {
        [lines addObject:[NSString stringWithFormat:@"target lstat=%@", NFBError(errno)]];
    }
    [lines addObject:[NSString stringWithFormat:@"cache file-write-data sandbox=%@",
                      NFBCheck(check, @"file-write-data", NFBFilterPath, target)]];
    [lines addObject:@"No bootstrap port lookup, XPC request, protected write-open or file mutation."];
    [lines addObject:@"Even ALLOW does not establish service-side entitlement authorization."];
    return NFBFinish(lines, @"protected-writer-service-gate.txt");
}


/**
 * T6: optional read-only effective policy differential for Apple daemon PIDs.
 * Discovery and sandbox_check may be denied; UNKNOWN is an expected outcome.
 * No XPC, no cross-process handle, no protected file write-open or mutation.
 */
NSString *BQRunTrustedDaemonPolicyDifferential(void) {
    NSMutableArray<NSString *> *lines = NFBStart(@"T6: effective Apple daemon policy");
    [lines addObject:@"Only runtime process names and sandbox_check(pid, path) preflight."];
    [lines addObject:@"No entitlement acquisition, XPC, file open or protected modification."];
    typedef int (*ListPidsFn)(void *, int);
    typedef int (*ProcNameFn)(int, void *, uint32_t);
    ListPidsFn list = (ListPidsFn)dlsym(RTLD_DEFAULT, "proc_listallpids");
    ProcNameFn procName = (ProcNameFn)dlsym(RTLD_DEFAULT, "proc_name");
    void *procLib = NULL;
    if (!list || !procName) {
        procLib = dlopen("/usr/lib/libproc.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (procLib) {
            if (!list) list = (ListPidsFn)dlsym(procLib, "proc_listallpids");
            if (!procName) procName = (ProcNameFn)dlsym(procLib, "proc_name");
        }
    }
    if (!list || !procName) {
        [lines addObject:@"UNKNOWN: libproc process-list API unavailable on this Watch."];
        if (procLib) dlclose(procLib);
        return NFBFinish(lines, @"trusted-daemon-policy-differential.txt");
    }
    errno = 0;
    int expected = list(NULL, 0);
    if (expected <= 0) {
        [lines addObject:[NSString stringWithFormat:@"UNKNOWN: proc_listallpids list failed=%@",
                          NFBError(errno)]];
        if (procLib) dlclose(procLib);
        return NFBFinish(lines, @"trusted-daemon-policy-differential.txt");
    }
    NSUInteger capacity = MIN((NSUInteger)4096, (NSUInteger)expected + 64);
    NSMutableData *buffer = [NSMutableData dataWithLength:capacity * sizeof(pid_t)];
    errno = 0;
    int count = list(buffer.mutableBytes, (int)buffer.length);
    if (count <= 0) {
        [lines addObject:[NSString stringWithFormat:@"UNKNOWN: pid enumeration denied=%@",
                          NFBError(errno)]];
        if (procLib) dlclose(procLib);
        return NFBFinish(lines, @"trusted-daemon-policy-differential.txt");
    }
    NFBSandboxCheck check = NFBCheckFunction();
    NSString *path = BQMobileGestaltPath();
    [lines addObject:[NSString stringWithFormat:@"Enumerated=%d; inspect up to %lu PIDs; path=%@",
                      count, (unsigned long)capacity, path]];
    NSUInteger matches = 0;
    pid_t *pids = (pid_t *)buffer.mutableBytes;
    for (NSUInteger i = 0; i < MIN((NSUInteger)count, capacity); i++) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == getpid()) continue;
        char process[128] = {0};
        if (procName(pid, process, sizeof(process)) <= 0) continue;
        NSString *name = [NSString stringWithUTF8String:process] ?: @"";
        if (![name isEqualToString:@"tccd"] &&
            ![name isEqualToString:@"softwareupdated"] &&
            ![name hasPrefix:@"MobileGestalt"]) continue;
        // Re-check process name immediately before querying to limit PID-reuse confusion.
        char before[128] = {0};
        if (procName(pid, before, sizeof(before)) <= 0 ||
            strcmp(before, process) != 0) continue;
        NSString *value = @"UNKNOWN: sandbox_check export missing";
        if (check) {
            errno = 0;
            int status = check(pid, "file-write-data", NFBFilterPath, path.fileSystemRepresentation);
            if (status == 0) value = @"ALLOW (preflight only; not a write proof)";
            else if (status > 0) value = [NSString stringWithFormat:@"DENY (%d)", status];
            else value = [@"UNKNOWN: remote sandbox_check failed " stringByAppendingString:NFBError(errno)];
        }
        char after[128] = {0};
        if (procName(pid, after, sizeof(after)) <= 0 ||
            strcmp(after, process) != 0) value = @"UNKNOWN (process changed during observation)";
        [lines addObject:[NSString stringWithFormat:@"[%@ pid=%d] MG file-write-data=%@",
                          name, pid, value]];
        matches++;
    }
    if (!matches) [lines addObject:@"UNKNOWN: no matching Apple daemons visible in this app namespace."];
    [lines addObject:@"A remote-process policy answer does not establish any usable XPC writer method."];
    if (procLib) dlclose(procLib);
    return NFBFinish(lines, @"trusted-daemon-policy-differential.txt");
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

static NSString *NFBDescribeBootstrapReturn(kern_return_t kr) {
    switch (kr) {
        case KERN_SUCCESS: return @"SUCCESS (Mach send right obtained; no service request)";
        case 1100: return @"BOOTSTRAP_NOT_PRIVILEGED (client is not authorized for name lookup)";
        case 1101: return @"BOOTSTRAP_NAME_IN_USE";
        case 1102: return @"BOOTSTRAP_UNKNOWN_SERVICE (name not found in this context)";
        case 1103: return @"BOOTSTRAP_SERVICE_ACTIVE";
        default: return [NSString stringWithFormat:@"OTHER (%d)", kr];
    }
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
    BOOL borrowed = NO;
    kern_return_t result = KERN_FAILURE;
    // Apple marks the direct task_get_special_port declaration unavailable
    // in the watchOS SDK. Runtime resolution keeps this test buildable and
    // reports UNAVAILABLE rather than assuming that the SPI exists.
    NFBSpecialPort special = (NFBSpecialPort)dlsym(RTLD_DEFAULT, "task_get_special_port");
    if (special) {
        result = special(mach_task_self(), TASK_BOOTSTRAP_PORT, &boot);
    } else {
        mach_port_t *selfBootstrap = (mach_port_t *)dlsym(RTLD_DEFAULT, "bootstrap_port");
        if (selfBootstrap && *selfBootstrap != MACH_PORT_NULL) {
            boot = *selfBootstrap;
            borrowed = YES;
            result = KERN_SUCCESS;
        }
    }
    [lines addObject:[NSString stringWithFormat:@"Own bootstrap source=%@ status=%d",
        borrowed ? @"bootstrap_port" : (special ? @"runtime task_get_special_port" : @"unavailable"),
        result]];
    if (result != KERN_SUCCESS || boot == MACH_PORT_NULL) {
        [lines addObject:@"Could not obtain own bootstrap port. No service queried."];
        return NFBFinish(lines, @"native-face-bootstrap-lookup.txt");
    }
    for (NSDictionary<NSString *, NSString *> *item in NFBServices()) {
        NSString *service = item[@"name"];
        mach_port_t target = MACH_PORT_NULL;
        kern_return_t kr = lookup(boot, service.UTF8String, &target);
        BOOL received = (kr == KERN_SUCCESS && target != MACH_PORT_NULL);
        [lines addObject:[NSString stringWithFormat:@"[%@] kr=%d (%@) port=%@",
            service, kr, NFBDescribeBootstrapReturn(kr), received ? @"RECEIVED" : @"NONE"]];
        if (target != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), target);
    }
    if (!borrowed) mach_port_deallocate(mach_task_self(), boot);
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
        @{@"label":@"NanoRegistry pref candidate", @"path":@"/private/var/mobile/Library/Preferences/com.apple.NanoRegistry.plist"},
        @{@"label":@"Paired registry root candidate", @"path":@"/private/var/mobile/Library/DeviceRegistry"},
        @{@"label":@"Paired registry state candidate", @"path":@"/private/var/mobile/Library/DeviceRegistry.state"},
        @{@"label":@"Paired registry secure history candidate", @"path":@"/private/var/mobile/Library/DeviceRegistry.state/historySecureProperties.plist"},
        @{@"label":@"Paired-sync preferences candidate", @"path":@"/private/var/mobile/Library/Preferences/com.apple.pairedsync.faces.plist"},
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


/**
 * T11: exact watchOS 23U95 TCC (CVE-2026-86886) reachability only.
 *
 * A path traversal advisory is NOT evidence of a caller-controllable path
 * in a trusted tccd RPC. We ask launchd only for the existing Mach service
 * name and release any port. No XPC request, path payload, vulnerable method,
 * sandbox extension, or Apple protected-file mutation.
 */
NSString *BQRunTCC86886Reachability(void) {
    NSMutableArray<NSString *> *lines=NFBStart(@"T11: CVE-2026-86886 TCC reachability");
    [lines addObject:@"CVE=2026-86886 component=TCC impact=protected-system-file modification (Apple advisory, not a confirmed local exploit)."];
    [lines addObject:@"Test measures real current-app service reachability only; DOES NOT trigger CVE or write MobileGestalt."];
    NFBSandboxCheck check=NFBCheckFunction();
    NSString *name=@"com.apple.tccd";
    [lines addObject:[NSString stringWithFormat:
        @"TCC mach-lookup sandbox=%@",NFBCheck(check,@"mach-lookup",NFBFilterGlobalName,name)]];
    NFBLaunchdLookup lookup=(NFBLaunchdLookup)dlsym(RTLD_DEFAULT,"bootstrap_look_up");
    NFBSpecialPort special=(NFBSpecialPort)dlsym(RTLD_DEFAULT,"task_get_special_port");
    mach_port_t boot=MACH_PORT_NULL;
    BOOL borrowed=NO;
    kern_return_t result=KERN_FAILURE;
    if (!lookup) {
        [lines addObject:@"UNKNOWN: bootstrap_look_up export missing; no service requested."];
    } else {
        if (special) result=special(mach_task_self(),TASK_BOOTSTRAP_PORT,&boot);
        else {
            mach_port_t *ptr=(mach_port_t *)dlsym(RTLD_DEFAULT,"bootstrap_port");
            if (ptr && *ptr!=MACH_PORT_NULL) {
                boot=*ptr;
                borrowed=YES;
                result=KERN_SUCCESS;
            }
        }
        [lines addObject:[NSString stringWithFormat:@"Own bootstrap port acquisition=%d",result]];
        if (result==KERN_SUCCESS && boot!=MACH_PORT_NULL) {
            mach_port_t service=MACH_PORT_NULL;
            kern_return_t kr=lookup(boot,name.UTF8String,&service);
            [lines addObject:[NSString stringWithFormat:
                @"TCC original Mach service kr=%d (%@) port=%@",
                kr,NFBDescribeBootstrapReturn(kr),
                (kr==KERN_SUCCESS && service!=MACH_PORT_NULL)?@"RECEIVED":@"NONE"]];
            if (service!=MACH_PORT_NULL) mach_port_deallocate(mach_task_self(),service);
            if (!borrowed) mach_port_deallocate(mach_task_self(),boot);
        }
    }
    NSString *mg=BQMobileGestaltPath();
    [lines addObject:[NSString stringWithFormat:
       @"Original MG cache file-write-data policy=%@",
       NFBCheck(check,@"file-write-data",NFBFilterPath,mg)]];
    [lines addObject:@"RESULT: TCC service availability is NOT TCC path traversal, privileged arbitrary-file write, or a successful MobileGestalt edit."];
    [lines addObject:@"No XPC method invoked; no payload, path traversal, protected open/write, or cache rebuild."];
    return NFBFinish(lines,@"cve-2026-86886-tcc-reachability.txt");
}

/**
 * T12: exact watchOS 23U95 CoreMedia (CVE-2026-86876) benign API check.
 *
 * Apple calls this an out-of-bounds write and a possible sandbox escape.
 * Neither vulnerable function nor input layout has been verified on this
 * hardware. Only the standard public empty CMBlockBuffer allocation API
 * is exercised, with no bytes, codecs, malformed descriptors or IPC.
 */
NSString *BQRunCoreMedia86876Reachability(void) {
    NSMutableArray<NSString *> *lines=NFBStart(@"T12: CVE-2026-86876 CoreMedia reachability");
    [lines addObject:@"CVE=2026-86876 component=CoreMedia impact=possible sandbox restrictions bypass (Apple advisory, not local proof)."];
    [lines addObject:@"Public, benign API control; no out-of-bounds input or kernel operation is requested."];
    NSString *path=@"/System/Library/Frameworks/CoreMedia.framework/CoreMedia";
    NFBSandboxCheck check=NFBCheckFunction();
    [lines addObject:[NSString stringWithFormat:
        @"CoreMedia framework file-read-data sandbox=%@",
        NFBCheck(check,@"file-read-data",NFBFilterPath,path)]];
    void *handle=dlopen(path.fileSystemRepresentation,RTLD_LAZY|RTLD_LOCAL);
    if (!handle) {
        const char *err=dlerror();
        [lines addObject:[NSString stringWithFormat:
            @"CoreMedia dlopen=FAILED %s",err?: "unknown"]];
        [lines addObject:@"UNKNOWN: framework not loaded; cannot evaluate this CVE's watchOS attack surface."];
        return NFBFinish(lines,@"cve-2026-86876-coremedia-reachability.txt");
    }
    [lines addObject:@"CoreMedia framework dlopen=SUCCESS (original signed Apple framework)."];
    typedef int32_t (*CMEmpty)(CFAllocatorRef,uint32_t,uint32_t,CFTypeRef *);
    CMEmpty empty=(CMEmpty)dlsym(handle,"CMBlockBufferCreateEmpty");
    void *createMemoryBlock=(void *)dlsym(handle,"CMBlockBufferCreateWithMemoryBlock");
    void *createSampleBuffer=(void *)dlsym(handle,"CMSampleBufferCreate");
    [lines addObject:[NSString stringWithFormat:
        @"Public symbols CMBlockBufferCreateEmpty=%@ CMBlockBufferCreateWithMemoryBlock=%@ CMSampleBufferCreate=%@",
        empty?@"PRESENT":@"ABSENT",
        createMemoryBlock?@"PRESENT":@"ABSENT",
        createSampleBuffer?@"PRESENT":@"ABSENT"]];
    if (empty) {
        CFTypeRef block=NULL;
        int32_t status=empty(kCFAllocatorDefault,0,0,&block);
        [lines addObject:[NSString stringWithFormat:
            @"Benign empty block creation returned OSStatus=%d block=%@",
            (int)status,block?@"PRESENT":@"NIL"]];
        if (block) CFRelease(block);
    } else {
        [lines addObject:@"SKIPPED: harmless empty CMBlockBuffer API unavailable."];
    }
    dlclose(handle);
    NSString *mg=BQMobileGestaltPath();
    [lines addObject:[NSString stringWithFormat:
       @"Original MG cache file-write-data sandbox=%@",
       NFBCheck(check,@"file-write-data",NFBFilterPath,mg)]];
    [lines addObject:@"RESULT: a functional CoreMedia API is NOT evidence of the CVE's OOB condition, escape, kernel rights or MG editing."];
    [lines addObject:@"No malformed buffer, codec parsing, race, exploit payload, protected file write or native gallery insertion."];
    return NFBFinish(lines,@"cve-2026-86876-coremedia-reachability.txt");
}
