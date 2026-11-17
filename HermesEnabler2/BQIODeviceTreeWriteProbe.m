#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <dlfcn.h>

// Completely separate mechanism from MobileGestalt API/MCM tokens:
// ask IOKit to assign the ALREADY EXISTING property value to the kernel
// IODeviceTree node which is used as DeviceBrand's underlying provider.
// This makes a real IOKit setter call but does not change the property bytes.
// The attempt is explicit, guarded, and NEVER part of standard diagnostics.
// A successful IOKit return is NOT a protected plist write or persistence proof.

typedef mach_port_t (*BQEntryFromPath)(mach_port_t, const char *);
typedef CFTypeRef (*BQEntryRead)(mach_port_t, CFStringRef, CFAllocatorRef, unsigned);
typedef kern_return_t (*BQEntrySetOne)(mach_port_t, CFStringRef, CFTypeRef);
typedef kern_return_t (*BQEntrySetMany)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*BQEntryRelease)(mach_port_t);
typedef kern_return_t (*BQServiceOpen)(mach_port_t, mach_port_t, uint32_t, mach_port_t *);
typedef kern_return_t (*BQServiceClose)(mach_port_t);
typedef kern_return_t (*BQConnectionSet)(mach_port_t, CFStringRef, CFTypeRef);

static void *BQFindIOKitSymbol(const char *name) {
    void *address = dlsym(RTLD_DEFAULT, name);
    if (address) return address;
    static void *library = NULL;
    if (!library) library = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                                    RTLD_NOW | RTLD_LOCAL);
    if (!library) library = dlopen("/System/Library/PrivateFrameworks/IOKit.framework/IOKit",
                                    RTLD_NOW | RTLD_LOCAL);
    return library ? dlsym(library, name) : NULL;
}

static NSString *BQReturn(kern_return_t r) {
    return [NSString stringWithFormat:@"0x%08x (%@)", (unsigned)r,
            r == KERN_SUCCESS ? @"SUCCESS" : @"DENIED/ERROR"];
}
static void BQRecord(NSMutableArray<NSString *> *rows, NSString *key, NSString *value) {
    [rows addObject:[NSString stringWithFormat:@"%@=%@", key, value ?: @"NIL"]];
}
static NSString *BQSaveRegistryReport(NSMutableArray<NSString *> *rows) {
    NSString *result = [rows componentsJoinedByString:@"\n"];
    NSString *destination = [BQDocuments() stringByAppendingPathComponent:@"iodevicetree-write-probe.txt"];
    NSError *error = nil;
    if (![result writeToFile:destination atomically:YES encoding:NSUTF8StringEncoding error:&error])
        result = [result stringByAppendingFormat:@"\nCould not save report: %@", error.localizedDescription];
    NSLog(@"[IODeviceTreeWriteProbe]\n%@\n[/IODeviceTreeWriteProbe]", result);
    return result;
}

NSString *BQRunIODeviceTreeWriteProbe(void) {
    NSMutableArray<NSString *> *rows = [NSMutableArray arrayWithObjects:
        @"=== IODeviceTree same-value write API tests ===",
        @"Three REAL IOKit setter methods; no MobileGestalt plist write.",
        @"NEVER changes marketing-software-behavior to a different value.",
        @"CAUTION: kernel / IOKit property setters are undocumented on watchOS.",
        @"Nothing is invoked automatically. Actual behavior on 23U95 is UNKNOWN.",
        [NSString stringWithFormat:@"OS=%@", NSProcessInfo.processInfo.operatingSystemVersionString],
        nil];

    if (NSProcessInfo.processInfo.operatingSystemVersion.majorVersion != 26) {
        [rows addObject:@"SKIP: watchOS 26 only"];
        return BQSaveRegistryReport(rows);
    }

    BQEntryFromPath fromPath = (BQEntryFromPath)BQFindIOKitSymbol("IORegistryEntryFromPath");
    BQEntryRead get = (BQEntryRead)BQFindIOKitSymbol("IORegistryEntryCreateCFProperty");
    BQEntrySetOne setOne = (BQEntrySetOne)BQFindIOKitSymbol("IORegistryEntrySetCFProperty");
    BQEntrySetMany setMany = (BQEntrySetMany)BQFindIOKitSymbol("IORegistryEntrySetCFProperties");
    BQEntryRelease release = (BQEntryRelease)BQFindIOKitSymbol("IOObjectRelease");
    BQServiceOpen openConnection = (BQServiceOpen)BQFindIOKitSymbol("IOServiceOpen");
    BQServiceClose closeConnection = (BQServiceClose)BQFindIOKitSymbol("IOServiceClose");
    BQConnectionSet setConnection = (BQConnectionSet)BQFindIOKitSymbol("IOConnectSetCFProperty");

    BQRecord(rows, @"IORegistryEntryFromPath", fromPath ? @"PRESENT" : @"MISSING");
    BQRecord(rows, @"IORegistryEntryCreateCFProperty", get ? @"PRESENT" : @"MISSING");
    BQRecord(rows, @"IORegistryEntrySetCFProperty", setOne ? @"PRESENT" : @"MISSING");
    BQRecord(rows, @"IORegistryEntrySetCFProperties", setMany ? @"PRESENT" : @"MISSING");
    BQRecord(rows, @"IOServiceOpen", openConnection ? @"PRESENT" : @"MISSING");
    BQRecord(rows, @"IOConnectSetCFProperty", setConnection ? @"PRESENT" : @"MISSING");

    if (!fromPath || !get || !release) {
        [rows addObject:@"STOP: necessary IOKit read/handle APIs missing; no writes attempted."];
        return BQSaveRegistryReport(rows);
    }

    // Backup validation is a hard prerequisite, even though the target is
    // a different kernel data source, not the original MobileGestalt cache.
    NSString *err = nil;
    NSString *backup = BQCreateGestaltBackup(!BQBackupExists(), &err);
    BQRecord(rows, @"pretest MobileGestalt backup", backup ? @"PASS" :
             [NSString stringWithFormat:@"FAIL: %@", err ?: @"unknown"]);
    if (!backup) {
        [rows addObject:@"STOP: backup verification failed; no IOKit writes attempted."];
        return BQSaveRegistryReport(rows);
    }

    mach_port_t entry = fromPath(MACH_PORT_NULL, "IODeviceTree:/chosen");
    BQRecord(rows, @"IODeviceTree:/chosen", entry != MACH_PORT_NULL ? @"ENTRY FOUND" : @"NOT ACCESSIBLE");
    if (entry == MACH_PORT_NULL) return BQSaveRegistryReport(rows);

    CFStringRef property = CFSTR("marketing-software-behavior");
    CFTypeRef original = get(entry, property, kCFAllocatorDefault, 0);
    if (!original || CFGetTypeID(original) != CFDataGetTypeID()) {
        [rows addObject:@"STOP: original property missing or not CFData; no IOKit writes attempted."];
        if (original) CFRelease(original);
        release(entry);
        return BQSaveRegistryReport(rows);
    }
    CFIndex originalSize = CFDataGetLength((CFDataRef)original);
    BQRecord(rows, @"original property type", [NSString stringWithFormat:@"CFData(%ld bytes)", (long)originalSize]);
    if (originalSize < 4 || originalSize > 64) {
        [rows addObject:@"STOP: unsafe/unknown property size; no IOKit writes attempted."];
        CFRelease(original);
        release(entry);
        return BQSaveRegistryReport(rows);
    }

    NSString *backupPath = [BQDocuments() stringByAppendingPathComponent:
                            @"iodevicetree-original-property.plist"];
    NSDictionary *backupDictionary = @{
        @"property": @"marketing-software-behavior",
        @"path": @"IODeviceTree:/chosen",
        @"originalCFData": (__bridge NSData *)original
    };
    NSError *saveError = nil;
    NSData *backupData = [NSPropertyListSerialization dataWithPropertyList:backupDictionary
                        format:NSPropertyListBinaryFormat_v1_0 options:0 error:&saveError];
    BOOL didBackup = backupData && [backupData writeToFile:backupPath options:NSDataWritingAtomic error:&saveError];
    BQRecord(rows, @"original IOKit property backup",
             didBackup ? @"PASS" : [NSString stringWithFormat:@"FAIL: %@", saveError.localizedDescription ?: @"unknown"]);
    if (!didBackup) {
        [rows addObject:@"STOP: cannot preserve original bytes, no IOKit writes attempted."];
        CFRelease(original);
        release(entry);
        return BQSaveRegistryReport(rows);
    }

    if (setOne) {
        kern_return_t result = setOne(entry, property, original);
        BQRecord(rows, @"route A IORegistryEntrySetCFProperty SAME VALUE", BQReturn(result));
    } else {
        BQRecord(rows, @"route A", @"SKIP: export unavailable");
    }

    if (setMany) {
        CFMutableDictionaryRef dictionary = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 1, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(dictionary, property, original);
        kern_return_t result = setMany(entry, dictionary);
        BQRecord(rows, @"route B IORegistryEntrySetCFProperties SAME VALUE", BQReturn(result));
        CFRelease(dictionary);
    } else {
        BQRecord(rows, @"route B", @"SKIP: export unavailable");
    }

    if (openConnection && closeConnection && setConnection) {
        mach_port_t connection = MACH_PORT_NULL;
        kern_return_t opened = openConnection(entry, mach_task_self(), 0, &connection);
        BQRecord(rows, @"route C IOServiceOpen", BQReturn(opened));
        if (opened == KERN_SUCCESS && connection != MACH_PORT_NULL) {
            kern_return_t result = setConnection(connection, property, original);
            BQRecord(rows, @"route C IOConnectSetCFProperty SAME VALUE", BQReturn(result));
            closeConnection(connection);
        } else {
            BQRecord(rows, @"route C IOConnectSetCFProperty", @"SKIP: no allowed user-client connection");
        }
    } else {
        BQRecord(rows, @"route C", @"SKIP: required connection API missing");
    }

    CFTypeRef after = get(entry, property, kCFAllocatorDefault, 0);
    BQRecord(rows, @"provider readback", after && CFEqual(original, after) ? @"ORIGINAL UNCHANGED" :
             (after ? @"DIFFERENT: STOP TESTING" : @"NO LONGER READABLE"));
    if (after) CFRelease(after);

    // Persistence requires a separate OS/boot boundary; a successful setter
    // return is NOT a proof of any persistent or global DeviceBrand override.
    [rows addObject:@"These are REAL IOKit setter calls, but only with IDENTICAL original CFData."];
    [rows addObject:@"No attempts to change the DeviceBrand byte, patch the protected cache, or modify a kernel service."];
    [rows addObject:@"SUCCESS here would prove only a property setter accepted an identical value."];
    CFRelease(original);
    release(entry);
    return BQSaveRegistryReport(rows);
}
