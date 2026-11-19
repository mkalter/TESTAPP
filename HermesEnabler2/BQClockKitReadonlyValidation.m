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
static NSString *BQCKWriteOwnReportNamed(NSArray<NSString *> *lines,NSString *filename) {
    NSString *out=[lines componentsJoinedByString:@"\n"];
    NSError *error=nil;
    NSString *dest=[BQDocuments() stringByAppendingPathComponent:filename];
    if (![out writeToFile:dest atomically:YES encoding:NSUTF8StringEncoding error:&error])
        out=[out stringByAppendingFormat:@"\nOWN report write FAILED: %@",error];
    NSLog(@"[ClockKitReadOnly] %@\n[/ClockKitReadOnly]",out);
    return out;
}

static NSString *BQCKWriteOwnReport(NSArray<NSString *> *lines) {
    return BQCKWriteOwnReportNamed(lines,@"clockkit-readonly-face-validation.txt");
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
       @"T7 revision 3: exact original Watch6,18 ClockKit sets Mach XPC option 0x1000.",
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
        // Verified original Watch6,18/23U95 ClockKit XPC client:
        // -[CLKWatchFaceLibraryServer _queue_setupConnectionIfNeeded]
        // 0x49c64378: mov w3, #0x1000, followed by service initializer
        // 0x49c6437c: bl 0x49cccb20.
        // This option selects launchd's privileged bootstrap namespace;
        // it DOES NOT elevate our app or bypass any daemon authorization.
        const NSUInteger originalMachOptions = (NSUInteger)0x1000;
        [lines addObject:@"Transport=initWithMachServiceName:options: options=0x1000 (matches original ClockKit bootstrap selection)"];
        connection=((MachServiceInit)impl)(uninitialized,machInit,
            @"com.apple.ClockKit.CLKWatchFaceLibrary",originalMachOptions);
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


// T8: On-device positive-control differential. All local probes below use
// NTKFaceDescriptor's availability getter. The only XPC method called is
// the same read-only ClockKit face type validator already proven in T7.
static NSString *BQCKFaceTypeForStyle(NSInteger style) {
    typedef id (*StyleStringFn)(NSInteger);
    StyleStringFn fn=(StyleStringFn)dlsym(RTLD_DEFAULT,"NTKFaceBundleStringFromFaceStyle");
    if (!fn) {
        void *h=dlopen("/System/Library/PrivateFrameworks/NanoTimeKit.framework/NanoTimeKit",
                       RTLD_LAZY|RTLD_LOCAL);
        if (h) fn=(StyleStringFn)dlsym(h,"NTKFaceBundleStringFromFaceStyle");
    }
    if (!fn) return nil;
    id value=fn(style);
    return [value isKindOfClass:NSString.class] ? value : nil;
}

static NSDictionary<NSString *,id> *BQCKKnownAvailableStandardFace(
                     NSMutableArray<NSString *> *lines) {
    Class faceClass=NSClassFromString(@"NTKFaceDescriptor");
    Class deviceClass=NSClassFromString(@"CLKDevice");
    SEL currentSel=NSSelectorFromString(@"currentDevice");
    SEL initSel=NSSelectorFromString(@"initWithFaceStyle:");
    SEL availabilitySel=NSSelectorFromString(@"isAvailableForDevice:");
    Method currentMethod=deviceClass ? class_getClassMethod(deviceClass,currentSel) : NULL;
    Method initMethod=faceClass ? class_getInstanceMethod(faceClass,initSel) : NULL;
    Method availMethod=faceClass ? class_getInstanceMethod(faceClass,availabilitySel) : NULL;
    [lines addObject:[NSString stringWithFormat:
        @"Local NTKFaceDescriptor=%@ CLKDevice=%@ currentDevice=%@ initWithFaceStyle=%@ isAvailableForDevice=%@",
        faceClass ? @"present" : @"absent",deviceClass ? @"present" : @"absent",
        currentMethod ? @"present" : @"absent",initMethod ? @"present" : @"absent",
        availMethod ? @"present" : @"absent"]];
    if (!currentMethod || !initMethod || !availMethod) {
        [lines addObject:@"UNKNOWN: missing local Apple native-face availability API."];
        return nil;
    }
    typedef id (*CurrentFn)(id,SEL);
    typedef id (*DescriptorInitFn)(id,SEL,NSInteger);
    typedef BOOL (*AvailabilityFn)(id,SEL,id);
    id device=((CurrentFn)method_getImplementation(currentMethod))(deviceClass,currentSel);
    if (!device) {
        [lines addObject:@"UNKNOWN: currentDevice returned nil. No positive-control guess."];
        return nil;
    }
    AvailabilityFn isAvailable=(AvailabilityFn)method_getImplementation(availMethod);
    DescriptorInitFn instantiate=(DescriptorInitFn)method_getImplementation(initMethod);
    NSUInteger checked=0;
    // 44 is the special bundle faceStyle and is not a standard-style
    // positive control. Prefer well-established standard Chronograph (2).
    NSMutableArray<NSNumber *> *styles=[NSMutableArray arrayWithObject:@2];
    for (NSInteger style=0;style<44;style++) if (style!=2)
        [styles addObject:@(style)];
    for (NSNumber *num in styles) {
        NSInteger style=num.integerValue;
        NSString *type=BQCKFaceTypeForStyle(style);
        if (!type.length || [type isEqualToString:@"bundle"]) continue;
        BOOL allow=NO;
        @try {
            id descriptor=instantiate([faceClass alloc],initSel,style);
            if (!descriptor) continue;
            allow=isAvailable(descriptor,availabilitySel,device);
            checked++;
        } @catch (NSException *exception) {
            [lines addObject:[NSString stringWithFormat:
                @"LOCAL style=%ld availability threw %@ (ignored)",
                (long)style,exception.name]];
            continue;
        }
        if (allow) {
            [lines addObject:[NSString stringWithFormat:
                @"POSITIVE CONTROL selected local available style=%ld type=%@ after %lu descriptor checks",
                (long)style,type,(unsigned long)checked]];
            return @{@"style":num,@"type":type};
        }
    }
    [lines addObject:[NSString stringWithFormat:
        @"UNKNOWN: no locally available standard style among 0...43; inspected=%lu. No positive-control guess.",
        (unsigned long)checked]];
    return nil;
}

// Mirror the read-only bundle branch of NTKFaceDescriptor.isAvailableForDevice:
// for style=44, a bundle folder alone is insufficient; NanoTimeKit must
// actually resolve a compatible first-party FaceBundle for this CLKDevice.
static NSString *BQCKLocalBundleAvailability(NSString *bundleID) {
    if (!bundleID.length) return @"UNKNOWN (no real bundle identifier)";
    Class descriptorClass=NSClassFromString(@"NTKFaceDescriptor");
    Class deviceClass=NSClassFromString(@"CLKDevice");
    if (!descriptorClass || !deviceClass) return @"UNKNOWN (Apple class unavailable)";
    SEL current=NSSelectorFromString(@"currentDevice");
    SEL create=NSSelectorFromString(@"initWithBundleIdentifier:");
    SEL query=NSSelectorFromString(@"isAvailableForDevice:");
    Method cm=class_getClassMethod(deviceClass,current);
    Method im=class_getInstanceMethod(descriptorClass,create);
    Method qm=class_getInstanceMethod(descriptorClass,query);
    if (!cm || !im || !qm) return @"UNKNOWN (Apple getter unavailable)";
    @try {
        typedef id (*Current)(id,SEL);
        typedef id (*Create)(id,SEL,NSString *);
        typedef BOOL (*Query)(id,SEL,id);
        id device=((Current)method_getImplementation(cm))(deviceClass,current);
        if (!device) return @"UNKNOWN (CLKDevice currentDevice nil)";
        id descriptor=((Create)method_getImplementation(im))(
            [descriptorClass alloc],create,bundleID);
        if (!descriptor) return @"UNKNOWN (NTKFaceDescriptor init nil)";
        BOOL result=((Query)method_getImplementation(qm))(descriptor,query,device);
        return result ? @"AVAILABLE (local descriptor)" : @"NOT AVAILABLE (local descriptor)";
    } @catch(NSException *exception) {
        return [NSString stringWithFormat:@"UNKNOWN (local descriptor exception %@)",
                 exception.name];
    }
}

NSString *BQRunClockKitAvailabilityDifferential(void) {
    NSMutableArray<NSString *> *lines=[NSMutableArray arrayWithObjects:
        @"=== Native Face Boundary Lab · T8: native availability differential ===",
        [NSString stringWithFormat:@"Time=%@; machine=%@; OSbuild=%@",
          NSDate.date,BQCKRunName(@"hw.machine"),BQCKRunName(@"kern.osversion")],
        [NSString stringWithFormat:@"App=%@",NSBundle.mainBundle.bundleIdentifier ?: @"unknown"],
        @"Only Apple's original read-only ClockKit validateFaceType:faceBundleId:completionHandler: XPC.",
        @"One local NTKFaceDescriptor isAvailableForDevice positive control selected from real currentDevice.",
        @"No native face import, library insertion, protected writing or device spoofing.",nil];
    // Explicitly load Apple's NanoTimeKit image BEFORE resolving its
    // Objective-C runtime classes, including NTKFaceDescriptor.
    NSString *style44=BQCKFaceTypeForStyle(44);
    NSDictionary<NSString *,id> *positive=BQCKKnownAvailableStandardFace(lines);
    NSString *zeus=BQCKSignedBundleIdentifier(
        @"/System/Library/NanoTimeKit/FaceBundles/NTKZeusFaceBundle.bundle");
    NSString *hermes=BQCKSignedBundleIdentifier(
        @"/System/Library/NanoTimeKit/FaceBundles/NTKHermes2025FaceBundle.bundle");
    [lines addObject:[NSString stringWithFormat:
        @"Original native style44=%@ Zeus ID=%@ Hermès2025 ID=%@",
        style44 ?: @"unavailable", zeus ?: @"unavailable",hermes ?: @"unavailable"]];
    if ([style44 isEqualToString:@"bundle"]) {
        [lines addObject:[NSString stringWithFormat:
            @"LOCAL native Zeus availability: %@",BQCKLocalBundleAvailability(zeus)]];
        [lines addObject:[NSString stringWithFormat:
            @"LOCAL native Hermès2025 availability: %@",BQCKLocalBundleAvailability(hermes)]];
    }
    if (!positive) {
        [lines addObject:@"SKIPPED remote differential: no VERIFIED locally available standard control."];
        return BQCKWriteOwnReportNamed(lines,@"clockkit-availability-differential.txt");
    }
    Class connectionClass=NSClassFromString(@"NSXPCConnection");
    Class interfaceClass=NSClassFromString(@"NSXPCInterface");
    SEL machSel=NSSelectorFromString(@"initWithMachServiceName:options:");
    if (!connectionClass || !interfaceClass ||
        ![connectionClass instancesRespondToSelector:machSel]) {
        [lines addObject:@"UNKNOWN: required NSXPC Mach connection runtime not available."];
        return BQCKWriteOwnReportNamed(lines,@"clockkit-availability-differential.txt");
    }
    id connection=nil;
    @try {
        IMP imp=[[connectionClass alloc] methodForSelector:machSel];
        if (!imp) {
            [lines addObject:@"UNKNOWN: Mach initializer IMP missing."];
            return BQCKWriteOwnReportNamed(lines,@"clockkit-availability-differential.txt");
        }
        typedef id (*MachInit)(id,SEL,NSString *,NSUInteger);
        id uninitialized=[connectionClass alloc];
        connection=((MachInit)imp)(uninitialized,machSel,
          @"com.apple.ClockKit.CLKWatchFaceLibrary",0x1000);
        if (!connection) {
            [lines addObject:@"UNKNOWN: Mach service initializer returned nil."];
            return BQCKWriteOwnReportNamed(lines,@"clockkit-availability-differential.txt");
        }
        id iface=[interfaceClass interfaceWithProtocol:@protocol(BQClockKitReadOnlyValidation)];
        [connection setRemoteObjectInterface:iface];
        [connection resume];
        [lines addObject:@"Transport=real Apple Mach service options 0x1000; no privileged entitlement acquired."];
        NSString *validType=positive[@"type"];
        [lines addObject:[NSString stringWithFormat:
            @"POSITIVE remote control: original standard type=%@ style=%@ (locally available=YES)",
            validType,positive[@"style"]]];
        NSString *answer=BQCKRequestValidation(connection,validType,@"");
        [lines addObject:answer];
        if ([answer hasPrefix:@"TRANSPORT_ERROR"] || [answer hasPrefix:@"UNKNOWN"]) {
            [lines addObject:@"SKIPPED: all native comparisons because control never completed."];
        } else if ([answer hasPrefix:@"REPLY success"]) {
            [lines addObject:@"POSITIVE CONTROL PASS: ClockKit accepted known available standard style."];
            if ([style44 isEqualToString:@"bundle"]) {
                for (NSString *bid in @[zeus ?: @"",hermes ?: @""]) {
                    if (!bid.length) continue;
                    [lines addObject:[NSString stringWithFormat:
                        @"NATIVE Hermès comparison: style=bundle ID=%@",bid]];
                    NSString *result=BQCKRequestValidation(connection,style44,bid);
                    [lines addObject:result];
                    if ([result hasPrefix:@"TRANSPORT_ERROR"] ||
                        [result hasPrefix:@"UNKNOWN"]) {
                        [lines addObject:@"STOP: remote transport lost during comparison."];
                        break;
                    }
                }
            } else {
                [lines addObject:@"SKIPPED Hermès: actual style44 is not bundle."];
            }
        } else {
            [lines addObject:@"POSITIVE CONTROL FAILED: ClockKit rejected a locally available face. Hermès conclusions from same code 4 are not model-specific."];
            [lines addObject:@"SKIPPED Hermès comparisons because server/device availability contexts disagree."];
        }
    } @catch(NSException *exception) {
        [lines addObject:[NSString stringWithFormat:
            @"UNKNOWN: local availability/XPC exception %@ %@",exception.name,exception.reason]];
    } @finally {
        if (connection) [connection invalidate];
    }
    [lines addObject:@"No original face inserted or protected file modified."];
    return BQCKWriteOwnReportNamed(lines,@"clockkit-availability-differential.txt");
}


/**
 * T9 · Local Apple FaceBundle manager migration lookup differential.
 *
 * Exact original Watch6,18 23U95 NanoTimeKit
 * -[NTKFaceBundleManager faceBundleForBundleIdentifier:onDevice:forMigration:]
 * uses x4 to decide whether to call isRestrictedForDevice:. This is NOT
 * an authorized native face-library writer and must never be described so.
 *
 * The manager may load and cache signed Apple bundles IN THE CALLING PROCESS.
 * No store, sync, Carousel or protected file mutation is requested.
 */
static NSString *BQCKBundleObjectSummary(id bundle, id device) {
    if (!bundle) return @"NIL (no usable FaceBundle object)";
    SEL getFace=NSSelectorFromString(@"faceClass");
    if (![bundle respondsToSelector:getFace])
        return @"NONNIL (faceClass selector unavailable; not a face activation)";
    @try {
        typedef Class (*GetClass)(id,SEL);
        IMP get=[bundle methodForSelector:getFace];
        if (!get) return @"NONNIL (faceClass implementation unavailable)";
        Class face=((GetClass)get)(bundle,getFace);
        if (!face) return @"NONNIL (faceClass=nil; not a usable renderable face)";
        NSString *name=NSStringFromClass(face) ?: @"unnamed";
        SEL restriction=NSSelectorFromString(@"isRestrictedForDevice:");
        Method method=class_getClassMethod(face,restriction);
        if (!method)
            return [NSString stringWithFormat:@"NONNIL faceClass=%@ restriction=UNKNOWN (no class method)",name];
        typedef BOOL (*IsRestricted)(Class,SEL,id);
        BOOL restricted=((IsRestricted)method_getImplementation(method))(face,restriction,device);
        return [NSString stringWithFormat:
                @"NONNIL faceClass=%@ isRestrictedForDevice:%@",
                name,restricted?@"YES":@"NO"];
    } @catch (NSException *e) {
        return [NSString stringWithFormat:
                 @"NONNIL faceClass inspection exception %@",e.name];
    }
}

NSString *BQRunClockKitMigrationLookupDifferential(void) {
    NSMutableArray<NSString *> *lines=[NSMutableArray arrayWithObjects:
        @"=== Native Face Boundary Lab · T9: original FaceBundle migration lookup differential ===",
        [NSString stringWithFormat:@"Time=%@; machine=%@; OSbuild=%@",
         NSDate.date,BQCKRunName(@"hw.machine"),BQCKRunName(@"kern.osversion")],
        [NSString stringWithFormat:@"App=%@",NSBundle.mainBundle.bundleIdentifier?:@"unknown"],
        @"Opt-in LOCAL NanoTimeKit FaceBundle lookup. No XPC, FaceStore, library migration, import or protected write.",
        @"The original manager may load/cache Apple bundle metadata only inside THIS process.",
        @"A nonnil migration result would NOT enable or install a native Hermès face.",nil];
    // Force actual signed original framework to be loaded before private class lookup.
    NSString *type=BQCKFaceTypeForStyle(44);
    [lines addObject:[NSString stringWithFormat:@"Original runtime face style44=%@",type?:@"unavailable"]];
    if (![type isEqualToString:@"bundle"]) {
        [lines addObject:@"SKIPPED: no original bundle style; no guessed selector calls."];
        return BQCKWriteOwnReportNamed(lines,@"clockkit-migration-local-differential.txt");
    }
    Class managerClass=NSClassFromString(@"NTKFaceBundleManager");
    Class deviceClass=NSClassFromString(@"CLKDevice");
    SEL sharedSel=NSSelectorFromString(@"sharedManager");
    SEL deviceSel=NSSelectorFromString(@"currentDevice");
    SEL migrateSel=NSSelectorFromString(@"faceBundleForBundleIdentifier:onDevice:forMigration:");
    Method shared=managerClass?class_getClassMethod(managerClass,sharedSel):NULL;
    Method current=deviceClass?class_getClassMethod(deviceClass,deviceSel):NULL;
    Method mig=managerClass?class_getInstanceMethod(managerClass,migrateSel):NULL;
    [lines addObject:[NSString stringWithFormat:
        @"Runtime manager=%@ device=%@ sharedManager=%@ currentDevice=%@ forMigration selector=%@",
        managerClass?@"present":@"absent",deviceClass?@"present":@"absent",
        shared?@"present":@"absent",current?@"present":@"absent",
        mig?@"present":@"absent"]];
    if (!shared || !current || !mig) {
        [lines addObject:@"UNKNOWN: required original getter missing; no speculative method calls."];
        return BQCKWriteOwnReportNamed(lines,@"clockkit-migration-local-differential.txt");
    }
    @try {
        typedef id (*ClassGetter)(id,SEL);
        typedef id (*BundleLookup)(id,SEL,NSString *,id,BOOL);
        id device=((ClassGetter)method_getImplementation(current))(deviceClass,deviceSel);
        id manager=((ClassGetter)method_getImplementation(shared))(managerClass,sharedSel);
        if (!device || !manager) {
            [lines addObject:@"UNKNOWN: manager or currentDevice nil; no lookup attempted."];
            return BQCKWriteOwnReportNamed(lines,@"clockkit-migration-local-differential.txt");
        }
        BundleLookup lookup=(BundleLookup)method_getImplementation(mig);
        NSArray<NSArray<NSString *> *> *targets=@[
            @[@"Zeus/Poodle",
              @"/System/Library/NanoTimeKit/FaceBundles/NTKZeusFaceBundle.bundle"],
            @[@"Hermès2025",
              @"/System/Library/NanoTimeKit/FaceBundles/NTKHermes2025FaceBundle.bundle"]
        ];
        for (NSArray<NSString *> *target in targets) {
            NSString *identifier=BQCKSignedBundleIdentifier(target[1]);
            if (!identifier.length) {
                [lines addObject:[NSString stringWithFormat:
                     @"SKIPPED %@ (actual on-device Info.plist unavailable)",target[0]]];
                continue;
            }
            [lines addObject:[NSString stringWithFormat:
                @"TARGET %@ real Apple bundle ID=%@",target[0],identifier]];
            id normal=lookup(manager,migrateSel,identifier,device,NO);
            [lines addObject:[@"NORMAL forMigration=NO: " stringByAppendingString:
                BQCKBundleObjectSummary(normal,device)]];
            id migration=lookup(manager,migrateSel,identifier,device,YES);
            [lines addObject:[@"MIGRATION forMigration=YES: " stringByAppendingString:
                BQCKBundleObjectSummary(migration,device)]];
            id normalAgain=lookup(manager,migrateSel,identifier,device,NO);
            [lines addObject:[@"RECHECK NORMAL forMigration=NO: " stringByAppendingString:
                BQCKBundleObjectSummary(normalAgain,device)]];
            if (!normal && migration) {
                [lines addObject:@"DIFFERENTIAL: migration lookup returns FaceBundle where ordinary lookup does not."];
            } else if (!normal && !migration) {
                [lines addObject:@"NO BYPASS OBSERVED: neither local lookup resolves a FaceBundle in this process."];
            } else {
                [lines addObject:@"NO INFERRED UNLOCK: inspect normal/migration results independently."];
            }
        }
    } @catch(NSException *e) {
        [lines addObject:[NSString stringWithFormat:
            @"UNKNOWN: local Apple method threw %@ %@",e.name,e.reason?:@""]];
    }
    [lines addObject:@"No native FaceStore/Carousel mutation, FaceBundle import, sync, reboot or protected file write requested."];
    return BQCKWriteOwnReportNamed(lines,@"clockkit-migration-local-differential.txt");
}


/**
 * T10 — exact current CLKDevice identity attributes, read-only.
 *
 * Original 23U95 Hermes2025 eligibility uses deviceCategory whitelist
 * {2,3,5} before later collectionType=5 test. The same-build ClockKit
 * loader derives deviceCategory from sizeClass separately from DeviceBrand.
 * This checks the actual live getters without modifying MG/CLKDevice.
 */
NSString *BQRunOriginalHermes2025IdentityGates(void) {
    NSMutableArray<NSString *> *lines=[NSMutableArray arrayWithObjects:
      @"=== Native Face Boundary Lab · T10: original Hermes2025 identity gate ===",
      [NSString stringWithFormat:@"Time=%@; model=%@; build=%@",
       NSDate.date,BQCKRunName(@"hw.machine"),BQCKRunName(@"kern.osversion")],
      @"Read-only Apple CLKDevice getters; no MobileGestalt, FaceStore or system mutation.",
      @"Original 23U95 Hermes2025 deviceCategory whitelist={2,3,5}; collectionType=5 is later gate.",
      @"DeviceBrand=1 alone may change collectionType but does NOT necessarily change sizeClass/deviceCategory.",nil];
    (void)BQCKFaceTypeForStyle(44); // Load original watchOS NanoTimeKit image.
    Class deviceClass=NSClassFromString(@"CLKDevice");
    SEL current=NSSelectorFromString(@"currentDevice");
    Method currentMethod=deviceClass?class_getClassMethod(deviceClass,current):NULL;
    if (!currentMethod) {
       [lines addObject:@"UNKNOWN: original CLKDevice currentDevice unavailable."];
       return BQCKWriteOwnReportNamed(lines,@"hermes2025-live-identity-gates.txt");
    }
    typedef id (*CurrentGetter)(id,SEL);
    id device=((CurrentGetter)method_getImplementation(currentMethod))(deviceClass,current);
    if (!device) {
       [lines addObject:@"UNKNOWN: currentDevice=nil."];
       return BQCKWriteOwnReportNamed(lines,@"hermes2025-live-identity-gates.txt");
    }
    NSArray<NSString *> *names=@[
      @"sizeClass",@"deviceCategory",@"deviceBrand",
      @"collectionType",@"isUltra",@"supportsFall2025FacesCapability"
    ];
    NSMutableDictionary<NSString *,NSNumber *> *values=[NSMutableDictionary dictionary];
    for (NSString *key in names) {
        SEL selector=NSSelectorFromString(key);
        Method method=class_getInstanceMethod(object_getClass(device),selector);
        if (!method) {
           [lines addObject:[NSString stringWithFormat:@"%@=UNKNOWN (getter not present)",key]];
           continue;
        }
        @try {
           typedef unsigned long long (*ReadScalar)(id,SEL);
           unsigned long long raw=((ReadScalar)method_getImplementation(method))(device,selector);
           values[key]=@(raw);
           [lines addObject:[NSString stringWithFormat:@"%@=%llu (read-only, actual CLKDevice)",
                              key,raw]];
        } @catch (NSException *e) {
           [lines addObject:[NSString stringWithFormat:@"%@=UNKNOWN exception=%@",key,e.name]];
        }
    }
    NSNumber *category=values[@"deviceCategory"];
    NSNumber *collection=values[@"collectionType"];
    NSNumber *brand=values[@"deviceBrand"];
    if (category) {
        BOOL categoryAllowed=category.unsignedIntegerValue==2 ||
            category.unsignedIntegerValue==3 || category.unsignedIntegerValue==5;
        [lines addObject:categoryAllowed ?
          @"Hermes2025 category whitelist={2,3,5}: PASS for current device." :
          @"Hermes2025 category whitelist={2,3,5}: FAIL for current device."];
        if (!categoryAllowed) {
           [lines addObject:@"DEDUCTION: Changing DeviceBrand alone does not change the sizeClass-derived category under the ORIGINAL 23U95 ClockKit loader. Another gate remains."];
        }
    } else {
       [lines addObject:@"UNKNOWN: cannot evaluate original category gate without getter."];
    }
    if (collection) {
        [lines addObject:collection.unsignedIntegerValue==5 ?
           @"Hermes2025 collectionType=5 gate: CURRENTLY MATCHES." :
           @"Hermes2025 collectionType=5 gate: CURRENTLY DOES NOT MATCH."];
    }
    if (brand) [lines addObject:[NSString stringWithFormat:
       @"Current CLKDevice brand=%@; do not confuse this with changing the protected MG cache.",
       brand]];
    [lines addObject:@"No native face was added, reset, imported or made persistent."];
    return BQCKWriteOwnReportNamed(lines,@"hermes2025-live-identity-gates.txt");
}
