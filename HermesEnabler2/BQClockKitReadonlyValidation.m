// T7 — ClockKit read-only face-type validation via the already observed Mach name.
// A bounded, explicit opt-in RPC, NOT native face insertion or MobileGestalt write.
#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <errno.h>

@protocol BQClockKitReadOnlyValidation <NSObject>
- (void)validateFaceType:(NSString *)type
            faceBundleId:(NSString *)bundleID
       completionHandler:(void (^)(NSError * _Nullable error))reply;
@end

static NSString *BQCKRunName(NSString *name) {
    char buf[100] = {0};
    size_t len=sizeof(buf);
    return sysctlbyname(name.UTF8String,buf,&len,NULL,0)==0 ?
        ([NSString stringWithUTF8String:buf] ?: @"unknown") : @"unknown";
}
static NSString *BQCKWriteOwnReport(NSArray<NSString *> *lines) {
    NSString *out=[lines componentsJoinedByString:@"\n"];
    NSError *error=nil;
    NSString *dest=[BQDocuments() stringByAppendingPathComponent:@"clockkit-readonly-face-validation.txt"];
    if (![out writeToFile:dest atomically:YES encoding:NSUTF8StringEncoding error:&error])
        out=[out stringByAppendingFormat:@"\nOWN report write FAILED: %@",error];
    NSLog(@"[ClockKitReadOnly] %@\n[/ClockKitReadOnly]",out);
    return out;
}

static NSString *BQCKFaceType44(void) {
    typedef id (*NTKStyleToString)(NSInteger);
    NTKStyleToString fn=(NTKStyleToString)dlsym(RTLD_DEFAULT,"NTKFaceBundleStringFromFaceStyle");
    if (!fn) {
        void *handle=dlopen("/System/Library/PrivateFrameworks/NanoTimeKit.framework/NanoTimeKit",
                            RTLD_LAZY|RTLD_LOCAL);
        if (handle) fn=(NTKStyleToString)dlsym(handle,"NTKFaceBundleStringFromFaceStyle");
        // Keep dlopen handle alive while using its returned NSString.
    }
    if (!fn) return nil;
    id value=fn(44);
    return [value isKindOfClass:NSString.class] ? (NSString *)value : nil;
}
static NSString *BQCKSignedBundleIdentifier(NSString *bundlePath) {
    NSString *info=[bundlePath stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *plist=[NSDictionary dictionaryWithContentsOfFile:info];
    id bundleID=plist[@"CFBundleIdentifier"];
    return [bundleID isKindOfClass:NSString.class] && [bundleID length] ?
        bundleID : nil;
}
// This per-request proxy uses the *same* completion gate for both success
// and transport errors. 4099 must finish immediately rather than time out.
static NSString *BQCKRequestValidation(id connection,
                                        NSString *faceType, NSString *bundleID) {
    __block NSString *result=nil;
    dispatch_semaphore_t semaphore=dispatch_semaphore_create(0);
    NSObject *gate=[NSObject new];
    __block BOOL responded=NO;
    void (^finish)(NSString *)=^(NSString *value) {
        @synchronized (gate) {
            if (responded) return;
            responded=YES;
            result=[value copy];
            dispatch_semaphore_signal(semaphore);
        }
    };
    @try {
        id<BQClockKitReadOnlyValidation> proxy=
            [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
                NSString *debug=error.userInfo[@"NSDebugDescription"] ?: @"none";
                finish([NSString stringWithFormat:
                    @"TRANSPORT_ERROR domain=%@ code=%ld message=%@ debug=%@",
                    error.domain, (long)error.code,
                    error.localizedDescription ?: @"unknown",debug]);
            }];
        [proxy validateFaceType:faceType faceBundleId:bundleID
             completionHandler:^(NSError *error) {
            if (!error) finish(@"REPLY success (VALIDATION ONLY, NOT FACE ADD)");
            else finish([NSString stringWithFormat:
                  @"REPLY NSError domain=%@ code=%ld message=%@",
                  error.domain, (long)error.code, error.localizedDescription]);
        }];
    } @catch (NSException *exc) {
        return [NSString stringWithFormat:@"UNKNOWN: local invocation exception %@",exc.name];
    }
    long wait=dispatch_semaphore_wait(semaphore,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC));
    return wait==0 ? (result ?: @"UNKNOWN: completed without result") :
        @"UNKNOWN: timeout (no validated RPC completion)";
}

NSString *BQRunClockKitReadOnlyFaceValidation(void) {
    NSMutableArray<NSString *> *lines=[NSMutableArray arrayWithObjects:
       @"=== Native Face Boundary Lab · T7: ClockKit read-only validator ===",
       [NSString stringWithFormat:@"Time=%@; machine=%@; OSbuild=%@",
          NSDate.date,BQCKRunName(@"hw.machine"),BQCKRunName(@"kern.osversion")],
       [NSString stringWithFormat:@"App=%@",NSBundle.mainBundle.bundleIdentifier ?: @"unknown"],
       @"Explicit single opt-in; only validateFaceType:faceBundleId:completionHandler: RPC.",
       @"T7 revision 2: previously initWithServiceName returned transport 4099; now test Mach service initializer.",
       @"No openWatchFaceURL, no imports, addFace, library reset, protected write or token.",
       @"Even a successful validation DOES NOT enable an original native Hermès face.",nil];
    Class connClass=NSClassFromString(@"NSXPCConnection");
    Class ifaceClass=NSClassFromString(@"NSXPCInterface");
    [lines addObject:[NSString stringWithFormat:@"NSXPCConnection=%@ NSXPCInterface=%@",
       connClass ? @"present" : @"absent",ifaceClass ? @"present" : @"absent"]];
    Protocol *proto=objc_getProtocol("CLKWatchFaceLibraryServerInterface");
    [lines addObject:[NSString stringWithFormat:
       @"Apple protocol in current process=%@ (not required by explicit typed read-only subset)",
       proto ? @"present" : @"not loaded"]];
    if (!connClass || !ifaceClass)
        return BQCKWriteOwnReport([lines arrayByAddingObject:
                @"UNKNOWN: XPC classes unavailable in this watchOS process."]);
    NSString *style44=BQCKFaceType44();
    NSString *zeus=BQCKSignedBundleIdentifier(
        @"/System/Library/NanoTimeKit/FaceBundles/NTKZeusFaceBundle.bundle");
    NSString *hermes25=BQCKSignedBundleIdentifier(
        @"/System/Library/NanoTimeKit/FaceBundles/NTKHermes2025FaceBundle.bundle");
    [lines addObject:[NSString stringWithFormat:@"style44 face type=%@; Zeus bundle ID=%@; Hermes2025 ID=%@",
       style44 ?: @"unavailable",zeus ?: @"unavailable",hermes25 ?: @"unavailable"]];
    [lines addObject:@"If actual style or bundle metadata absent, native checks SKIPPED (no guesses)."];
    id connection=nil;
    @try {
        // T7 prior physical result: using initWithServiceName: on this global
        // Mach name gave NSCocoaErrorDomain 4099. That initializer targets a
        // bundle-scoped XPC service, not a launchd-managed Mach service.
        // Deliberately test the *different* Mach-service transport, without
        // claiming it bypasses the daemon's normal client authorization.
        SEL machInit=NSSelectorFromString(@"initWithMachServiceName:options:");
        if (![connClass instancesRespondToSelector:machInit]) {
            [lines addObject:@"UNKNOWN: Mach service initializer unavailable at runtime on watchOS"];
            return BQCKWriteOwnReport(lines);
        }
        id uninitialized=[connClass alloc];
        IMP impl=[uninitialized methodForSelector:machInit];
        if (!impl) {
            [lines addObject:@"UNKNOWN: Mach service initializer IMP unavailable"];
            return BQCKWriteOwnReport(lines);
        }
        typedef id (*MachServiceInit)(id,SEL,NSString *,NSUInteger);
        [lines addObject:@"Transport=initWithMachServiceName:options: options=0 (Mach lookup, NO privileged option)"];
        connection=((MachServiceInit)impl)(uninitialized,machInit,
            @"com.apple.ClockKit.CLKWatchFaceLibrary",0);
        if (!connection) {
            [lines addObject:@"UNKNOWN: runtime Mach service initializer returned nil"];
            return BQCKWriteOwnReport(lines);
        }
        id iface=[ifaceClass interfaceWithProtocol:@protocol(BQClockKitReadOnlyValidation)];
        [connection setRemoteObjectInterface:iface];
        [connection resume];
        // A transport failure is a transport failure, NOT a denied face.
        [lines addObject:@"CONTROL: intentionally nonexistent face type (no import)"];
        NSString *control=BQCKRequestValidation(connection,
          @"__HermesEnabler_ReadOnly_Invalid__", @"__invalid_bundle__");
        [lines addObject:control];
        if ([control hasPrefix:@"TRANSPORT_ERROR"] ||
            [control hasPrefix:@"UNKNOWN"]) {
            [lines addObject:@"SKIPPED: native face checks. No successful XPC reply for invalid control."];
        } else if (style44.length && (zeus.length || hermes25.length)) {
            for (NSString *bundle in @[zeus ?: @"", hermes25 ?: @""]) {
                if (!bundle.length) continue;
                [lines addObject:[NSString stringWithFormat:@"NATIVE VALIDATION only: type=%@ bundle=%@",
                                  style44,bundle]];
                NSString *out=BQCKRequestValidation(connection,style44,bundle);
                [lines addObject:out];
                if ([out hasPrefix:@"TRANSPORT_ERROR"] ||
                    [out hasPrefix:@"UNKNOWN"]) {
                    [lines addObject:@"STOP: XPC transport failed during native validation"];
                    break;
                }
            }
        }
    } @catch (NSException *exc) {
        [lines addObject:[NSString stringWithFormat:@"UNKNOWN: XPC setup exception %@ %@",exc.name,exc.reason]];
    } @finally {
        if (connection) [connection invalidate];
    }
    [lines addObject:@"No watchface added, no protected data changed, no sandbox token."];
    return BQCKWriteOwnReport(lines);
}
