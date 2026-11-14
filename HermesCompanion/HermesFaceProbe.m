#import "HermesFaceProbe.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

static id HermesSend0(id obj, NSString *method) {
    SEL s = NSSelectorFromString(method);
    if (!obj || ![obj respondsToSelector:s]) return nil;
    return ((id (*)(id,SEL))objc_msgSend)(obj,s);
}
static BOOL HermesHas(id obj, NSString *method) {
    return obj && [obj respondsToSelector:NSSelectorFromString(method)];
}
static long long HermesInt0(id obj, NSString *method, long long missing) {
    SEL s = NSSelectorFromString(method);
    if (!HermesHas(obj,method)) return missing;
    return ((long long (*)(id,SEL))objc_msgSend)(obj,s);
}
static id HermesSendLookup(id manager, NSString *identifier, id device, BOOL migration) {
    SEL s = NSSelectorFromString(@"faceBundleForBundleIdentifier:onDevice:forMigration:");
    if (!HermesHas(manager, NSStringFromSelector(s))) return nil;
    return ((id (*)(id,SEL,id,id,BOOL))objc_msgSend)(manager,s,identifier,device,migration);
}
static NSString *HermesLookupStatus(id bundle) {
    if (!bundle) return @"NIL";
    NSString *cls = NSStringFromClass([bundle class]);
    NSString *face = @"unknown";
    if (HermesHas(bundle, @"faceClass")) {
        Class faceClass = ((Class (*)(id,SEL))objc_msgSend)(bundle, NSSelectorFromString(@"faceClass"));
        face = faceClass ? NSStringFromClass(faceClass) : @"nil";
    }
    return [NSString stringWithFormat:@"FOUND bundle=%@ faceClass=%@",cls,face];
}

NSString *HERMESRunMigrationEligibilityProbe(void) {
    NSMutableString *log = [NSMutableString stringWithString:
        @"=== Hermès FaceBundle migration eligibility probe (iPhone) ===\n"
         "Non-mutating: same device and bundle in both lookups.\n"];
    // iOS 27 has private NanoTimeKit APIs that may change by build. Resolve
    // everything dynamically, so unavailable interfaces produce logs instead
    // of fabricated success or an unconditional call into a missing symbol.
    NSArray<NSString *> *libraries = @[
        @"/System/Library/Frameworks/ClockKit.framework/ClockKit",
        @"/System/Library/PrivateFrameworks/NanoTimeKit.framework/NanoTimeKit",
        @"/System/Library/PrivateFrameworks/NanoTimeKitCompanion.framework/NanoTimeKitCompanion"
    ];
    for (NSString *lib in libraries) {
        void *handle = dlopen(lib.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
        [log appendFormat:@"framework %@: %@\n",lib.lastPathComponent,
            handle ? @"loaded" : @"unavailable (may be absent on this build)"];
        // Deliberately leave loaded framework resident during method calls.
    }
    Class clk = NSClassFromString(@"CLKDevice");
    Class ntk = NSClassFromString(@"NTKFaceBundleManager");
    [log appendFormat:@"CLKDevice=%@ NTKFaceBundleManager=%@\n",
        clk ? @"FOUND" : @"MISSING", ntk ? @"FOUND" : @"MISSING"];
    if (!clk || !ntk) {
        [log appendString:
            @"INCONCLUSIVE: required framework class unavailable. This is not a negative face eligibility result.\n"];
        return log;
    }
    id device = HermesSend0(clk, @"currentDevice");
    id manager = HermesSend0(ntk, @"sharedManager");
    if (!device || !manager) {
        [log appendString:@"INCONCLUSIVE: currentDevice or sharedManager returned nil.\n"];
        return log;
    }
    [log appendFormat:
        @"deviceClass=%@ isPaired=%lld deviceCategory=%lld collectionType=%lld isZeus10=%lld\n",
        NSStringFromClass([device class]),
        HermesInt0(device,@"isPaired",-1),
        HermesInt0(device,@"deviceCategory",-1),
        HermesInt0(device,@"collectionType",-1),
        HermesInt0(device,@"isZeus10",-1)];
    if (!HermesHas(manager,@"faceBundleForBundleIdentifier:onDevice:forMigration:")) {
        [log appendString:@"INCONCLUSIVE: forMigration selector absent in this iOS 27 build.\n"];
        return log;
    }
    NSArray<NSString *> *ids = @[
        @"com.apple.Hermes2025Face",
        @"com.apple.NTKPoodleFaceBundle",
        @"com.apple.NTKHadesFaceBundle",
        @"com.apple.NTKSecretariatFaceBundle",
        @"com.apple.NTKBellonaFaceBundle",
        @"com.apple.NTKSquallFaceBundle"
    ];
    NSUInteger bypassCount = 0;
    for (NSString *identifier in ids) {
        @try {
            id normal = HermesSendLookup(manager,identifier,device,NO);
            id migrated = HermesSendLookup(manager,identifier,device,YES);
            BOOL difference = normal == nil && migrated != nil;
            if (difference) bypassCount++;
            [log appendFormat:@"\n[%@]\nforMigration=NO: %@\nforMigration=YES: %@\n",
                identifier,HermesLookupStatus(normal),HermesLookupStatus(migrated)];
            [log appendFormat:@"MIGRATION_ELIGIBILITY_DIFFERENCE=%@\n",
                difference ? @"YES (iPhone bundle lookup only)" : @"NO"];
        } @catch (NSException *e) {
            [log appendFormat:@"\n[%@] OBJC EXCEPTION: %@ — inconclusive\n",
                identifier,e.name];
        }
    }
    [log appendFormat:@"\nObserved iPhone bundle-lookup differences: %lu\n",
        (unsigned long)bypassCount];
    [log appendString:
      @"IMPORTANT: FOUND only proves that the iPhone returned a FaceBundle object. "
       "It does NOT prove a valid face can be instantiated, synced, accepted, "
       "activated or rendered on the Watch.\n"
       "The test does not modify MobileGestalt, NanoRegistry, Watch files, or a face library.\n"];
    return log;
}
