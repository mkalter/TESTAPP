#import "BQFaceAvailabilityProbe.h"
#import <Foundation/Foundation.h>
#import <WatchKit/WatchKit.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>

static BOOL HFHas(id obj, NSString *selector) {
    return obj && [obj respondsToSelector:NSSelectorFromString(selector)];
}
static id HFSend0(id obj, NSString *selector) {
    if (!HFHas(obj, selector)) return nil;
    return ((id (*)(id,SEL))objc_msgSend)(obj, NSSelectorFromString(selector));
}
static long long HFGetInt(id obj, NSString *selector, long long fallback) {
    if (!HFHas(obj, selector)) return fallback;
    return ((long long (*)(id,SEL))objc_msgSend)(obj, NSSelectorFromString(selector));
}
static BOOL HFGetBool(id obj, NSString *selector, BOOL *value) {
    if (!HFHas(obj, selector)) return NO;
    if (value) *value = ((BOOL (*)(id,SEL))objc_msgSend)(obj, NSSelectorFromString(selector));
    return YES;
}
static id HFBundle(id manager, NSString *identifier, id device, BOOL migrating) {
    NSString *selector = @"faceBundleForBundleIdentifier:onDevice:forMigration:";
    if (!HFHas(manager, selector)) return nil;
    return ((id (*)(id,SEL,id,id,BOOL))objc_msgSend)(
        manager, NSSelectorFromString(selector), identifier, device, migrating);
}
static NSString *HFStatus(id o) {
    return o ? [NSString stringWithFormat:@"FOUND (%@)", NSStringFromClass([o class])] : @"NIL";
}

NSString *BQRunWatchFaceAvailabilityProbe(void) {
    NSMutableString *out = [NSMutableString stringWithString:
        @"=== Hermès Native Face Eligibility: ON WATCH ===\n"
         "Observation only: no MobileGestalt writes, no face import, no settings changes.\n"];
    struct utsname system = {0};
    uname(&system);
    char build[64] = {0};
    size_t buildLength = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &buildLength, NULL, 0) != 0)
        strlcpy(build, "unknown", sizeof(build));
    [out appendFormat:@"watchOS=%@ build=%s model=%s\n",
        [WKInterfaceDevice currentDevice].systemVersion, build, system.machine];

    for (NSString *path in @[
        @"/System/Library/Frameworks/ClockKit.framework/ClockKit",
        @"/System/Library/PrivateFrameworks/NanoTimeKit.framework/NanoTimeKit"
    ]) {
        void *lib = dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
        [out appendFormat:@"load %@: %@\n", path.lastPathComponent,
            lib ? @"OK" : @"NO (not available to this app)"];
    }

    id clkDeviceClass = NSClassFromString(@"CLKDevice");
    id device = HFSend0(clkDeviceClass, @"currentDevice");
    id manager = HFSend0(NSClassFromString(@"NTKFaceBundleManager"), @"sharedManager");
    [out appendFormat:@"CLKDevice=%@ currentDevice=%@ faceBundleManager=%@\n",
        clkDeviceClass ? @"YES" : @"NO", HFStatus(device), HFStatus(manager)];

    if (device) {
        for (NSString *selector in @[
            @"deviceBrand", @"deviceCategory", @"collectionType", @"isUltra",
            @"isZeus10", @"supportsFall2025FacesCapability",
            @"supportsHermesFaces", @"supportsHermesFacesCapability"
        ]) {
            [out appendFormat:@"CLKDevice.%@ = %@\n", selector,
                HFHas(device, selector) ?
                    [NSString stringWithFormat:@"%lld", HFGetInt(device, selector, -1)] :
                    @"NOT EXPOSED"];
        }
    }

    if (!device || !manager) {
        [out appendString:@"INCONCLUSIVE: required runtime objects unavailable on this watchOS build.\n"];
        return out;
    }
    if (!HFHas(manager, @"faceBundleForBundleIdentifier:onDevice:forMigration:")) {
        [out appendString:@"INCONCLUSIVE: NanoTimeKit faceBundleForBundleIdentifier:onDevice:forMigration: not exposed on Watch.\n"];
        return out;
    }

    NSArray *identifiers = @[
        @"com.apple.Hermes2025Face",
        @"com.apple.NTKPoodleFaceBundle",
        @"com.apple.NTKHadesFaceBundle",
        @"com.apple.NTKSecretariatFaceBundle",
        @"com.apple.NTKBellonaFaceBundle",
        @"com.apple.NTKSquallFaceBundle"
    ];
    for (NSString *identifier in identifiers) {
        [out appendFormat:@"\n[%@]\n", identifier];
        @try {
            id ordinary = HFBundle(manager, identifier, device, NO);
            id migrating = HFBundle(manager, identifier, device, YES);
            [out appendFormat:@"normal=%@ migration=%@\n",
                HFStatus(ordinary), HFStatus(migrating)];
            id faceBundle = ordinary ?: migrating;
            if (!faceBundle) {
                [out appendString:@"Bundle not returned; cannot determine whether missing or device-filtered.\n"];
                continue;
            }
            NSString *getFaceClass = @"faceClass";
            Class faceClass = Nil;
            if (HFHas(faceBundle, getFaceClass)) {
                faceClass = ((Class (*)(id,SEL))objc_msgSend)(
                    faceBundle, NSSelectorFromString(getFaceClass));
            }
            [out appendFormat:@"faceClass=%@\n",
                faceClass ? NSStringFromClass(faceClass) : @"UNAVAILABLE"];
            // The Hermès 2025 implementation exposes a face-specific restriction.
            if (faceClass && [faceClass respondsToSelector:NSSelectorFromString(@"isRestrictedForDevice:")]) {
                BOOL restricted = ((BOOL (*)(id,SEL,id))objc_msgSend)(
                    faceClass, NSSelectorFromString(@"isRestrictedForDevice:"), device);
                [out appendFormat:@"isRestrictedForDevice=%@\n", restricted ? @"YES" : @"NO"];
            } else {
                [out appendString:@"isRestrictedForDevice=UNAVAILABLE / NOT EXPOSED\n"];
            }
            id descriptor = HFSend0(faceBundle, @"faceDescriptor");
            if (!descriptor) {
                [out appendString:@"faceDescriptor=UNAVAILABLE\n"];
            } else if (HFHas(descriptor, @"isAvailableForDevice:")) {
                BOOL available = ((BOOL (*)(id,SEL,id))objc_msgSend)(
                    descriptor, NSSelectorFromString(@"isAvailableForDevice:"), device);
                [out appendFormat:@"descriptor.isAvailableForDevice=%@\n",
                    available ? @"YES" : @"NO"];
            } else {
                [out appendString:@"descriptor.isAvailableForDevice=NOT EXPOSED\n"];
            }
        } @catch (NSException *exception) {
            [out appendFormat:@"Exception=%@ (%@)\n", exception.name, exception.reason];
        }
    }
    [out appendString:
        @"\nInterpretation: normal/migration FOUND on its own does NOT prove the face can be installed or rendered.\n"
         "A restrictive face-specific predicate or descriptor can reject the Watch after iPhone archive export.\n"
         "If no internal APIs are exposed, result is inconclusive, not a successful bypass.\n"];
    return out;
}
