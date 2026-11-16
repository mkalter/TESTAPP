#import "BQPermissionDiagnostics.h"
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/task_special_ports.h>
#import <errno.h>
#import <unistd.h>
#import <string.h>

// Inspection only: checks local sandbox policy, service name resolution, and
// current process entitlements. No XPC requests, no privileged operations,
// no cache writes, no cache rebuild or sentinel changes.
typedef int (*BQServiceSandboxCheck)(pid_t, const char *, int, ...);
typedef kern_return_t (*BQServiceLookup)(mach_port_t, const char *, mach_port_t *);
typedef const struct __BQServiceTask *BQServiceTaskRef;
typedef BQServiceTaskRef (*BQServiceCreateTask)(CFAllocatorRef);
typedef CFTypeRef (*BQServiceReadEntitlement)(BQServiceTaskRef, CFStringRef, CFErrorRef *);

static NSString *BQServiceDecision(int result, int err) {
    if (result == 0) return @"ALLOW (preflight only)";
    if (result > 0) return [NSString stringWithFormat:@"DENY (%d)", result];
    return [NSString stringWithFormat:@"ERROR errno=%d (%s)", err, strerror(err)];
}

NSString *BQRunServiceAuthorizationDiagnostics(void) {
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithObjects:
        @"=== MobileGestalt XPC service authorization (read-only) v1 ===",
        @"NO XPC messages sent, no helper selectors called, no MG cache writes.",
        @"A Mach service name lookup does NOT grant authorization to use privileged methods.",
        [NSString stringWithFormat:@"OS=%@ bundle=%@",
          NSProcessInfo.processInfo.operatingSystemVersionString,
          NSBundle.mainBundle.bundleIdentifier ?: @"unknown"],
        nil];

    NSString *name = @"com.apple.mobilegestalt.xpc";
    void *sandbox = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_LAZY | RTLD_LOCAL);
    BQServiceSandboxCheck check = (BQServiceSandboxCheck)dlsym(RTLD_DEFAULT, "sandbox_check");
    if (!check && sandbox)
        check = (BQServiceSandboxCheck)dlsym(sandbox, "sandbox_check");

    [out addObject:@"\n[Sandbox Mach service authorization]"];
    if (check) {
        errno = 0;
        // SANDBOX_FILTER_GLOBAL_NAME = 2, not the PATH filter (1).
        int response = check(getpid(), "mach-lookup", 2, name.UTF8String);
        int savedError = errno;
        [out addObject:[NSString stringWithFormat:@"mach-lookup %@: %@",
            name, BQServiceDecision(response, savedError)]];
    } else {
        [out addObject:@"mach-lookup: UNKNOWN (sandbox_check unavailable)"];
    }
    if (sandbox) dlclose(sandbox);

    [out addObject:@"\n[Bootstrap name lookup — NO message sent to service]"];
    void *system = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_LAZY | RTLD_LOCAL);
    BQServiceLookup lookup = (BQServiceLookup)dlsym(RTLD_DEFAULT, "bootstrap_look_up");
    if (!lookup && system) lookup = (BQServiceLookup)dlsym(system, "bootstrap_look_up");
    if (lookup) {
        mach_port_t bootstrap = MACH_PORT_NULL;
        kern_return_t k = task_get_bootstrap_port(mach_task_self(), &bootstrap);
        [out addObject:[NSString stringWithFormat:@"task_get_bootstrap_port kr=%d port=%@",
            (int)k, bootstrap == MACH_PORT_NULL ? @"NULL" : @"AVAILABLE"]];
        if (k == KERN_SUCCESS && bootstrap != MACH_PORT_NULL) {
            mach_port_t service = MACH_PORT_NULL;
            kern_return_t result = lookup(bootstrap, name.UTF8String, &service);
            [out addObject:[NSString stringWithFormat:
                @"bootstrap_look_up kr=%d service_send_right=%@",
                (int)result,
                (result == KERN_SUCCESS && service != MACH_PORT_NULL) ? @"YES" : @"NO"]];
            if (result == KERN_SUCCESS && service != MACH_PORT_NULL)
                mach_port_deallocate(mach_task_self(), service);
            mach_port_deallocate(mach_task_self(), bootstrap);
        }
    } else {
        [out addObject:@"bootstrap_look_up unavailable; service reachability UNKNOWN"];
    }
    if (system) dlclose(system);

    [out addObject:@"\n[Effective process entitlements vs native Apple helper]"];
    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security",
                       RTLD_LAZY | RTLD_LOCAL);
    BQServiceCreateTask create = sec ? (BQServiceCreateTask)dlsym(sec, "SecTaskCreateFromSelf") : NULL;
    BQServiceReadEntitlement read = sec ? (BQServiceReadEntitlement)dlsym(sec, "SecTaskCopyValueForEntitlement") : NULL;
    if (create && read) {
        BQServiceTaskRef task = create(kCFAllocatorDefault);
        if (task) {
            for (NSString *key in @[
                @"com.apple.private.security.storage.MobileGestaltCache",
                @"com.apple.security.system-groups",
                @"com.apple.security.system-group-containers",
                @"com.apple.security.application-groups"
            ]) {
                CFErrorRef err = NULL;
                CFTypeRef value = read(task, (__bridge CFStringRef)key, &err);
                NSString *state = err ? @"ERROR" : (value ? @"PRESENT" : @"ABSENT");
                [out addObject:[NSString stringWithFormat:@"%@ = %@", key, state]];
                if (value) CFRelease(value);
                if (err) CFRelease(err);
            }
            CFRelease(task);
        } else {
            [out addObject:@"SecTaskCreateFromSelf failed; entitlement state UNKNOWN"];
        }
    } else {
        [out addObject:@"SecTask symbols unavailable; entitlement state UNKNOWN"];
    }
    if (sec) dlclose(sec);

    [out addObject:@"\n[Interpretation]"];
    [out addObject:@"Service visible/lookup-success proves namespace reachability only."];
    [out addObject:@"Server answers are independently restricted by MobileGestalt descriptor policies."];
    [out addObject:@"This test does not send any XPC message or exercise rebuildCache/setCacheSentinel."];
    [out addObject:@"This test cannot grant any private entitlement or file-write permission."];
    return [out componentsJoinedByString:@"\n"];
}
