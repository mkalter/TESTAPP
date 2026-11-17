#import "BQCore.h"
#import "BQPermissionDiagnostics.h"
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <errno.h>

// EXPERIMENTAL: This invokes a REAL, private MobileGestalt setter.
// Unlike sandbox_check probes, the setter itself may attempt a system write.
// It never modifies the plist with POSIX, filesystem replacement or symlinks.
// Do not run as part of the standard read-only diagnostics.
typedef int (*BQMGSetFn)(CFStringRef, CFTypeRef);
typedef CFTypeRef (*BQMGCopyFn)(CFStringRef, CFDictionaryRef);

static void *BQMGSymbol(const char *symbol) {
    void *address = dlsym(RTLD_DEFAULT, symbol);
    if (address) return address;
    static void *lib = NULL;
    if (!lib) {
        lib = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW | RTLD_LOCAL);
        if (!lib) {
            lib = dlopen("/System/Library/PrivateFrameworks/MobileGestalt.framework/MobileGestalt",
                         RTLD_NOW | RTLD_LOCAL);
        }
    }
    return lib ? dlsym(lib, symbol) : NULL;
}

static void BQMGLine(NSMutableArray<NSString *> *out, NSString *label, NSString *value) {
    [out addObject:[NSString stringWithFormat:@"%@=%@", label, value ?: @"(null)"]];
}
static NSString *BQMGCacheState(NSData *data) {
    if (!data.length) return @"UNREADABLE";
    id plist = [NSPropertyListSerialization propertyListWithData:data
                                                          options:0 format:NULL error:NULL];
    if (![plist isKindOfClass:NSDictionary.class]) return @"INVALID PLIST";
    if (![plist[@"CacheData"] isKindOfClass:NSData.class] ||
        ![plist[@"CacheExtra"] isKindOfClass:NSDictionary.class])
        return @"UNEXPECTED CACHE STRUCTURE";
    return [NSString stringWithFormat:@"VALID; bytes=%lu", (unsigned long)data.length];
}

static NSString *BQMGReport(NSMutableArray<NSString *> *out, NSString *name) {
    NSString *report = [out componentsJoinedByString:@"\n"];
    NSString *file = [BQDocuments() stringByAppendingPathComponent:name];
    NSError *error = nil;
    if (![report writeToFile:file atomically:YES
                  encoding:NSUTF8StringEncoding error:&error]) {
        report = [report stringByAppendingFormat:@"\nReport save failed: %@",
                  error.localizedDescription ?: @"unknown"];
    }
    NSLog(@"[MGSetAnswerExperiment]\n%@\n[/MGSetAnswerExperiment]", report);
    return report;
}

NSString *BQRunMGSetAnswerWriteExperiment(void) {
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithObjects:
        @"=== MobileGestalt direct setter experiment v1 ===",
        @"A REAL MGSetAnswer call, not a sandbox_check matrix.",
        @"WARNING: Apple-private API can change on watchOS; write side effects are unverified.",
        @"No POSIX protected writes, no filesystem replacement, no sandbox-token requests.",
        [NSString stringWithFormat:@"OS=%@", NSProcessInfo.processInfo.operatingSystemVersionString],
        nil];

    if (NSProcessInfo.processInfo.operatingSystemVersion.majorVersion != 26) {
        [out addObject:@"SKIP: not watchOS 26.x"];
        return BQMGReport(out, @"mgsetanswer-experiment.txt");
    }
    BQMGSetFn setter = (BQMGSetFn)BQMGSymbol("MGSetAnswer");
    BQMGCopyFn getter = (BQMGCopyFn)BQMGSymbol("MGCopyAnswer");
    BQMGLine(out, @"MGSetAnswer symbol", setter ? @"PRESENT" : @"MISSING");
    BQMGLine(out, @"MGCopyAnswer symbol", getter ? @"PRESENT" : @"MISSING");
    if (!setter || !getter) {
        [out addObject:@"Result: cannot attempt setter; symbols missing."];
        return BQMGReport(out, @"mgsetanswer-experiment.txt");
    }

    // Keep a validated original backup in the app-owned Documents container.
    NSString *backupError = nil;
    NSString *backup = BQCreateGestaltBackup(!BQBackupExists(), &backupError);
    BQMGLine(out, @"Verified pre-test backup",
             backup ?: [@"FAILED " stringByAppendingString:backupError ?: @"unknown"]);
    if (!backup) {
        [out addObject:@"NO setter called because pre-test backup failed."];
        return BQMGReport(out, @"mgsetanswer-experiment.txt");
    }

    NSString *mgPath = BQMobileGestaltPath();
    NSData *originalBytes = [NSData dataWithContentsOfFile:mgPath];
    BQMGLine(out, @"Before disk cache", BQMGCacheState(originalBytes));
    if (![BQMGCacheState(originalBytes) hasPrefix:@"VALID"]) {
        [out addObject:@"NO setter called: the protected cache did not parse."];
        return BQMGReport(out, @"mgsetanswer-experiment.txt");
    }

    // First a supported, normally assignable key with IDENTICAL old value.
    // No changed device name is requested. This distinguishes setter reachability
    // from errors with an unrecognized canary key.
    CFStringRef namedKey = CFSTR("UserAssignedDeviceName");
    CFTypeRef namedOld = getter(namedKey, NULL);
    if (namedOld && CFGetTypeID(namedOld) == CFStringGetTypeID()) {
        int result = setter(namedKey, namedOld);
        BQMGLine(out, @"MGSetAnswer(UserAssignedDeviceName, SAME value) return",
                 [NSString stringWithFormat:@"%d", result]);
        CFTypeRef namedNow = getter(namedKey, NULL);
        BQMGLine(out, @"Same-value readback", namedNow && CFEqual(namedOld, namedNow) ? @"MATCH" : @"MISMATCH");
        if (namedNow) CFRelease(namedNow);
    } else {
        BQMGLine(out, @"Same-value UserAssignedDeviceName", @"SKIPPED: original key is missing/non-string");
    }
    if (namedOld) CFRelease(namedOld);

    // A harmless, fixed test key lets a separate, later process check whether
    // MGSetAnswer was merely an in-process override or persisted somewhere.
    // It is NOT DeviceBrand or any feature/capability identifier.
    CFStringRef canaryKey = CFSTR("HermesEnablerMGSetAnswerWriteProof");
    CFStringRef canaryValue = CFSTR("20261117-watchOS26-canary");
    CFTypeRef canaryOld = getter(canaryKey, NULL);
    if (canaryOld) CFRelease(canaryOld);
    int setResult = setter(canaryKey, canaryValue);
    BQMGLine(out, @"MGSetAnswer(canary) return",
             [NSString stringWithFormat:@"%d", setResult]);
    CFTypeRef immediate = getter(canaryKey, NULL);
    BQMGLine(out, @"Canary same-process readback",
             immediate && CFEqual(immediate, canaryValue) ? @"MATCH" :
             (immediate ? @"DIFFERENT VALUE" : @"ABSENT"));
    if (immediate) CFRelease(immediate);

    // A returned 0 is NOT, by itself, proof of persistent write access.
    NSData *afterBytes = [NSData dataWithContentsOfFile:mgPath];
    BQMGLine(out, @"After disk cache", BQMGCacheState(afterBytes));
    BQMGLine(out, @"Disk bytes before/after",
             (afterBytes && [originalBytes isEqualToData:afterBytes]) ? @"IDENTICAL" :
             (afterBytes ? @"CHANGED" : @"UNREADABLE"));
    if (![BQMGCacheState(afterBytes) hasPrefix:@"VALID"]) {
        [out addObject:@"WARNING: post-test protected cache could not be validated. Do not run more tests."];
    }
    [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"BQMGSetAnswerCanaryWasAttempted"];
    [out addObject:@"Do not interpret same-process readback as a persistent system change."];
    [out addObject:@"For process persistence: fully terminate and reopen the Watch app, then run Check MGSetAnswer canary."];
    [out addObject:@"No direct MobileGestalt file mutation or privileged token was attempted."];
    return BQMGReport(out, @"mgsetanswer-experiment.txt");
}

NSString *BQCheckMGSetAnswerCanary(void) {
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithObjects:
        @"=== MobileGestalt setter: independent readback ===",
        @"READ ONLY; no setter invoked.",
        nil];
    if (![[NSUserDefaults standardUserDefaults] boolForKey:@"BQMGSetAnswerCanaryWasAttempted"]) {
        [out addObject:@"SKIP: no prior canary attempt registered in this app."];
        return BQMGReport(out, @"mgsetanswer-persistence.txt");
    }
    BQMGCopyFn getter = (BQMGCopyFn)BQMGSymbol("MGCopyAnswer");
    if (!getter) {
        [out addObject:@"MGCopyAnswer missing; no readback."];
        return BQMGReport(out, @"mgsetanswer-persistence.txt");
    }
    CFTypeRef value = getter(CFSTR("HermesEnablerMGSetAnswerWriteProof"), NULL);
    BQMGLine(out, @"Canary MGCopyAnswer in current process",
             value && CFEqual(value, CFSTR("20261117-watchOS26-canary")) ? @"MATCH" :
             (value ? @"DIFFERENT" : @"ABSENT"));
    if (value) CFRelease(value);
    NSData *disk = [NSData dataWithContentsOfFile:BQMobileGestaltPath()];
    BQMGLine(out, @"Protected cache", BQMGCacheState(disk));
    if ([BQMGCacheState(disk) hasPrefix:@"VALID"]) {
        id plist = [NSPropertyListSerialization propertyListWithData:disk
                                                           options:0 format:NULL error:NULL];
        NSDictionary *extra = plist[@"CacheExtra"];
        id answer = extra[@"HermesEnablerMGSetAnswerWriteProof"];
        BQMGLine(out, @"Canary CacheExtra on disk", answer ? @"PRESENT" : @"ABSENT");
    }
    [out addObject:@"Only a new-process result AND a persistent/disk change establish cross-process effects."];
    return BQMGReport(out, @"mgsetanswer-persistence.txt");
}
