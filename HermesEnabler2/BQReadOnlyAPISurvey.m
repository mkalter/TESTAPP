#import "BQPermissionDiagnostics.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>

// Safe, non-executing API availability survey. Only loads libraries and checks
// whether relevant symbols are exported. It does not call any MG editing API,
// XPC service, sandbox query, or file-writing method.
static NSString *BQProbeLib(NSString *name, NSString *path,
                            NSArray<NSString *> *symbols) {
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    void *lib = dlopen(path.fileSystemRepresentation, RTLD_LAZY | RTLD_LOCAL);
    [lines addObject:[NSString stringWithFormat:@"[%@] load=%@", name,
        lib ? @"YES" : @"NO"]];
    if (!lib) {
        const char *why = dlerror();
        [lines addObject:[NSString stringWithFormat:
            @"  dynamic loader: %s", why ?: "unknown"];
        return [lines componentsJoinedByString:@"\n"];
    }
    for (NSString *symbol in symbols) {
        void *pointer = dlsym(lib, symbol.UTF8String);
        [lines addObject:[NSString stringWithFormat:
            @"  export %-46s %@",
            symbol.UTF8String, pointer ? @"PRESENT" : @"ABSENT"]];
    }
    dlclose(lib);
    return [lines componentsJoinedByString:@"\n"];
}

NSString *BQRunReadOnlyAPISurvey(void) {
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithObjects:
        @"=== watchOS 26 alternate API survey v1 ===",
        @"Only dlopen/dlsym. NO private method called. NO permissions requested.",
        @"Symbol presence does not grant authorization or prove a working write route.",
        [NSString stringWithFormat:@"OS=%@",
         NSProcessInfo.processInfo.operatingSystemVersionString],
        nil];

    [out addObject:BQProbeLib(@"MobileGestalt private framework",
        @"/System/Library/PrivateFrameworks/MobileGestalt.framework/MobileGestalt",
        @[@"MGCopyAnswer", @"MGCopyMultipleAnswers", @"MGGetBoolAnswer", @"MGSetAnswer"])];
    [out addObject:BQProbeLib(@"Container Manager",
        @"/usr/lib/system/libsystem_containermanager.dylib",
        @[@"container_query_create",
          @"container_query_set_class",
          @"container_query_operation_set_part_domain",
          @"container_query_get_single_result",
          @"container_copy_sandbox_token"])];
    [out addObject:BQProbeLib(@"Sandbox",
        @"/usr/lib/system/libsystem_sandbox.dylib",
        @[@"sandbox_check", @"sandbox_extension_consume",
          @"sandbox_extension_release"])];
    [out addObject:BQProbeLib(@"Security",
        @"/System/Library/Frameworks/Security.framework/Security",
        @[@"SecTaskCreateFromSelf", @"SecTaskCopyValueForEntitlement"])];
    [out addObject:BQProbeLib(@"System XPC client library",
        @"/usr/lib/system/libxpc.dylib",
        @[@"xpc_connection_create_mach_service", @"xpc_connection_send_message_with_reply_sync"])];
    [out addObject:@"\nInterpretation of distinct mechanisms:"];
    [out addObject:@"1. Library API: visibility is not evidence of a supported or authorized setter."];
    [out addObject:@"2. MCM: returning a SystemGroup token does not imply file-write-data permission."];
    [out addObject:@"3. Signing: SecTask shows effective claims; private keys missing are not grantable by plist editing."];
    [out addObject:@"4. XPC: client API availability is not evidence of any permitted server operation; no service contacted."];
    [out addObject:@"5. Existing-file permissions: filesystem DAC, sandbox and other mandatory policy gates are independent."];
    [out addObject:@"No protected cache data was read or changed in this survey."];
    return [out componentsJoinedByString:@"\n"];
}
