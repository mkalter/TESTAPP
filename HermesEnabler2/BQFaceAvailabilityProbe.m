#import "BQFaceAvailabilityProbe.h"
#import <Foundation/Foundation.h>
#import <WatchKit/WatchKit.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <sys/utsname.h>
#import <string.h>
#import <sys/sysctl.h>
#import <stdbool.h>

static BOOL HFHas(id obj, NSString *selector) {
    return obj && [obj respondsToSelector:NSSelectorFromString(selector)];
}
static id HFSend0(id obj, NSString *selector) {
    if (!HFHas(obj, selector)) return nil;
    return ((id (*)(id,SEL))objc_msgSend)(obj, NSSelectorFromString(selector));
}
// Private getters have different return ABIs on different OS builds.
// In particular deviceBrand may return an NSNumber, not an integer.
static NSString *HFPropertyDescription(id object, NSString *name) {
    SEL selector = NSSelectorFromString(name);
    if (!HFHas(object, name)) return @"NOT EXPOSED";
    @try {
        NSMethodSignature *signature = [object methodSignatureForSelector:selector];
        if (!signature || signature.numberOfArguments != 2) return @"UNSUPPORTED SIGNATURE";
        const char *type = signature.methodReturnType;
        while (*type && strchr("rnNoORV", *type)) ++type;
        if (!*type) return @"UNKNOWN RETURN TYPE";
        NSInvocation *call = [NSInvocation invocationWithMethodSignature:signature];
        call.target = object;
        call.selector = selector;
        // Only invoke supported scalar/object getters.
        if (!strchr("@BcCsSiIlLqQ", *type))
            return [NSString stringWithFormat:@"UNSUPPORTED RETURN TYPE (%s)", type];
        [call invoke];
        if (*type == '@') {
            __unsafe_unretained id value = nil;
            [call getReturnValue:&value];
            if (!value) return @"nil (object)";
            if ([value isKindOfClass:NSNumber.class])
                return [NSString stringWithFormat:@"%@ (NSNumber)", [value stringValue]];
            return [NSString stringWithFormat:@"OBJECT (%@), not numeric", NSStringFromClass([value class])];
        }
#define HF_RETURN_CASE(encoding, nativeType) \
        case encoding: { nativeType value = 0; \
            [call getReturnValue:&value]; \
            return [NSString stringWithFormat:@"%@ (scalar %c)", @(value), *type]; }
        switch (*type) {
            HF_RETURN_CASE('B', bool)
            HF_RETURN_CASE('c', signed char)
            HF_RETURN_CASE('C', unsigned char)
            HF_RETURN_CASE('s', short)
            HF_RETURN_CASE('S', unsigned short)
            HF_RETURN_CASE('i', int)
            HF_RETURN_CASE('I', unsigned int)
            HF_RETURN_CASE('l', long)
            HF_RETURN_CASE('L', unsigned long)
            HF_RETURN_CASE('q', long long)
            HF_RETURN_CASE('Q', unsigned long long)
        }
#undef HF_RETURN_CASE
        return @"UNSUPPORTED RETURN TYPE";
    } @catch (NSException *exception) {
        return [NSString stringWithFormat:@"GETTER EXCEPTION (%@)", exception.name];
    }
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
                HFPropertyDescription(device, selector)];
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
