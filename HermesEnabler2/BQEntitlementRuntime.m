#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach/machine.h>
#import <libkern/OSByteOrder.h>

// Read-only inspection of our own signed Watch executable and process.
// No protected paths, sandbox extensions, cache writes or system calls to write files.

typedef const struct __BQSecTask *BQSecTaskRef;
typedef BQSecTaskRef (*BQTaskCreate)(CFAllocatorRef);
typedef CFTypeRef (*BQTaskValue)(BQSecTaskRef, CFStringRef, CFErrorRef *);

static NSArray<NSString *> *BQKeys(void) {
    return @[@"com.apple.private.security.storage.MobileGestaltCache",
             @"com.apple.security.system-groups",
             @"com.apple.security.system-group-containers",
             @"com.apple.security.application-groups",
             @"application-identifier",
             @"com.apple.developer.team-identifier",
             @"get-task-allow"];
}

static BOOL BQU32(NSData *data, NSUInteger index, uint32_t *value) {
    if (index > data.length || data.length - index < 4) return NO;
    memcpy(value, (const uint8_t *)data.bytes + index, 4);
    return YES;
}

static BOOL BQBE32(NSData *data, NSUInteger index, uint32_t *value) {
    uint32_t raw;
    if (!BQU32(data, index, &raw)) return NO;
    *value = OSSwapBigToHostInt32(raw);
    return YES;
}

// Parses LC_CODE_SIGNATURE -> SuperBlob -> XML entitlement blob, when present.
// XML is only a signed claim; never interpreted as a grant of write permission.
static BOOL BQBE64(NSData *data, NSUInteger index, uint64_t *value) {
    if (index > data.length || data.length - index < 8) return NO;
    uint64_t raw = 0;
    memcpy(&raw, (const uint8_t *)data.bytes + index, 8);
    *value = OSSwapBigToHostInt64(raw);
    return YES;
}

static BOOL BQFindMachOSlice(NSData *data, NSUInteger *sliceStart,
                              NSUInteger *sliceLength, NSMutableString *output) {
    uint32_t magic = 0;
    if (!BQU32(data, 0, &magic)) return NO;
    *sliceStart = 0;
    *sliceLength = data.length;
    // On a little-endian watch, on-disk CAFEBABE appears as FAT_CIGAM.
    BOOL bigEndianFAT = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
    BOOL littleEndianFAT = (magic == FAT_MAGIC || magic == FAT_MAGIC_64);
    if (!bigEndianFAT && !littleEndianFAT) return YES;
    BOOL fat64 = (magic == FAT_CIGAM_64 || magic == FAT_MAGIC_64);
    uint32_t count = 0;
    if (bigEndianFAT ? !BQBE32(data, 4, &count) : !BQU32(data, 4, &count)) return NO;
    NSUInteger stride = fat64 ? 32 : 20;
    if (count == 0 || count > 64 || data.length < 8 ||
        count > (data.length - 8) / stride) return NO;

    BOOL found = NO;
    int bestScore = -1;
    NSUInteger bestIndex = 0;
    for (uint32_t i = 0; i < count; ++i) {
        NSUInteger header = 8 + (NSUInteger)i * stride;
        uint32_t cpu = 0, offset32 = 0, size32 = 0;
        uint64_t offset64 = 0, size64 = 0;
        BOOL valid = bigEndianFAT ? BQBE32(data, header, &cpu) : BQU32(data, header, &cpu);
        if (fat64) {
            if (bigEndianFAT) {
                valid = valid && BQBE64(data, header + 8, &offset64) &&
                                  BQBE64(data, header + 16, &size64);
            } else {
                uint64_t raw = 0;
                if (header + 24 > data.length) return NO;
                memcpy(&raw, (const uint8_t *)data.bytes + header + 8, 8);
                offset64 = raw;
                memcpy(&raw, (const uint8_t *)data.bytes + header + 16, 8);
                size64 = raw;
            }
        } else {
            valid = valid && (bigEndianFAT ? BQBE32(data, header + 8, &offset32) :
                                            BQU32(data, header + 8, &offset32));
            valid = valid && (bigEndianFAT ? BQBE32(data, header + 12, &size32) :
                                            BQU32(data, header + 12, &size32));
            offset64 = offset32;
            size64 = size32;
        }
        if (!valid || offset64 > data.length || size64 > data.length - offset64 ||
            size64 < sizeof(struct mach_header)) continue;
        uint32_t thinMagic = 0;
        if (!BQU32(data, (NSUInteger)offset64, &thinMagic) ||
            (thinMagic != MH_MAGIC && thinMagic != MH_MAGIC_64)) continue;

        int score = 0;
#ifdef CPU_TYPE_ARM64_32
        if (cpu == CPU_TYPE_ARM64_32) score = 3;
#endif
        if (cpu == CPU_TYPE_ARM64) score = 2;
        if (!found || score > bestScore) {
            found = YES;
            bestScore = score;
            bestIndex = i;
            *sliceStart = (NSUInteger)offset64;
            *sliceLength = (NSUInteger)size64;
        }
    }
    if (!found) {
        [output appendFormat:@"FAT Mach-O (%u slices): no compatible thin slice found\n", count];
        return NO;
    }
    [output appendFormat:@"FAT Mach-O (%u slices): selected slice %lu, offset=%lu, length=%lu\n",
        count, (unsigned long)bestIndex, (unsigned long)*sliceStart,
        (unsigned long)*sliceLength];
    return YES;
}

// Parses the calling app's own LC_CODE_SIGNATURE; not protected system files.
// A signed XML blob may be absent (DER-only); SecTask is the definitive runtime query.
static NSDictionary *BQOwnSignatureXML(NSMutableString *output) {
    NSString *path = NSBundle.mainBundle.executablePath;
    NSData *data = path ? [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:NULL] : nil;
    if (!data) {
        [output appendString:@"Own executable unavailable; signature UNKNOWN\n"];
        return nil;
    }
    NSUInteger slice = 0, sliceLength = 0;
    if (!BQFindMachOSlice(data, &slice, &sliceLength, output)) return nil;
    uint32_t magic = 0, commands = 0, commandBytes = 0;
    if (!BQU32(data, slice, &magic)) return nil;
    BOOL is64 = magic == MH_MAGIC_64;
    if (!is64 && magic != MH_MAGIC) {
        [output appendFormat:@"Unsupported thin Mach-O magic 0x%08x\n", magic];
        return nil;
    }
    if (sliceLength < (is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header)) ||
        !BQU32(data, slice + 16, &commands) ||
        !BQU32(data, slice + 20, &commandBytes)) return nil;
    NSUInteger offset = slice + (is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
    if (commandBytes > sliceLength - (offset - slice) || commands > 2048) return nil;
    NSUInteger end = offset + commandBytes, signature = 0, signatureLength = 0;
    for (uint32_t i = 0; i < commands; ++i) {
        uint32_t command = 0, size = 0;
        if (offset > end || end - offset < 8 ||
            !BQU32(data, offset, &command) || !BQU32(data, offset + 4, &size) ||
            size < 8 || size > end - offset) return nil;
        if (command == LC_CODE_SIGNATURE && size >= 16) {
            uint32_t pos = 0, len = 0;
            if (!BQU32(data, offset + 8, &pos) || !BQU32(data, offset + 12, &len)) return nil;
            if (pos > sliceLength || len > sliceLength - pos) return nil;
            signature = slice + pos;
            signatureLength = len;
            break;
        }
        offset += size;
    }
    if (!signatureLength) {
        [output appendString:@"No LC_CODE_SIGNATURE in this slice (possibly unsigned)\n"];
        return nil;
    }
    uint32_t superMagic = 0, blobLength = 0, count = 0;
    if (!BQBE32(data, signature, &superMagic) ||
        !BQBE32(data, signature + 4, &blobLength) ||
        !BQBE32(data, signature + 8, &count) ||
        superMagic != 0xfade0cc0 || blobLength < 12 ||
        blobLength > signatureLength || count > (blobLength - 12) / 8) {
        [output appendString:@"Unsupported code signature SuperBlob\n"];
        return nil;
    }
    BOOL derFound = NO;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t position = 0, type = 0, length = 0;
        if (!BQBE32(data, signature + 12 + (NSUInteger)i * 8 + 4, &position) ||
            position > blobLength || blobLength - position < 8) continue;
        NSUInteger blob = signature + position;
        if (!BQBE32(data, blob, &type) || !BQBE32(data, blob + 4, &length) ||
            length < 8 || length > blobLength - position) continue;
        if (type == 0xfade7172) derFound = YES;
        if (type != 0xfade7171) continue;
        NSData *plistData = [data subdataWithRange:NSMakeRange(blob + 8, length - 8)];
        NSError *error = nil;
        id parsed = [NSPropertyListSerialization propertyListWithData:plistData options:0 format:NULL error:&error];
        if (![parsed isKindOfClass:NSDictionary.class]) {
            [output appendFormat:@"XML entitlement parse error: %@\n", error.localizedDescription ?: @"unknown"];
            return nil;
        }
        [output appendString:@"Own executable: XML entitlement blob found (signed claims only)\n"];
        return parsed;
    }
    [output appendFormat:@"No XML entitlement blob; DER entitlement blob=%@\n", derFound ? @"YES" : @"NO"];
    return nil;
}
static NSString *BQValue(id value) {
    if (!value) return @"ABSENT";
    return [NSString stringWithFormat:@"PRESENT %@", value];
}

NSString *BQRunRuntimeEntitlementDiagnostics(void) {
    NSMutableString *report = [NSMutableString stringWithFormat:
        @"=== watchOS entitlement audit v2 (FAT-aware) ===\nOS: %@\nBundle: %@\n"
        @"Read-only: self executable and self task only.\n\n",
        NSProcessInfo.processInfo.operatingSystemVersionString,
        NSBundle.mainBundle.bundleIdentifier ?: @"unknown"];

    NSDictionary *signedValues = BQOwnSignatureXML(report);
    for (NSString *key in BQKeys()) {
        [report appendFormat:@"[signed XML] %@: %@\n", key,
            signedValues ? BQValue(signedValues[key]) : @"UNKNOWN (no XML signature decoded)"];
    }

    [report appendString:@"\n[effective process entitlement query]\n"];
    void *handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY | RTLD_LOCAL);
    BQTaskCreate createTask = handle ? (BQTaskCreate)dlsym(handle, "SecTaskCreateFromSelf") : NULL;
    BQTaskValue copyValue = handle ? (BQTaskValue)dlsym(handle, "SecTaskCopyValueForEntitlement") : NULL;
    if (!createTask || !copyValue) {
        [report appendString:@"SecTask query API unavailable on this Watch; effective rights UNKNOWN.\n"];
    } else {
        BQSecTaskRef task = createTask(kCFAllocatorDefault);
        if (!task) {
            [report appendString:@"SecTaskCreateFromSelf failed; effective rights UNKNOWN.\n"];
        } else {
            for (NSString *key in BQKeys()) {
                CFErrorRef error = NULL;
                CFTypeRef result = copyValue(task, (__bridge CFStringRef)key, &error);
                if (error) {
                    [report appendFormat:@"[task] %@: ERROR %@\n", key, (__bridge NSError *)error];
                    CFRelease(error);
                } else {
                    [report appendFormat:@"[task] %@: %@\n", key, BQValue((__bridge id)result)];
                }
                if (result) CFRelease(result);
            }
            CFRelease(task);
        }
    }
    if (handle) dlclose(handle);
    [report appendString:@"\nSigned claims are NOT proof of authorized access.\n"
        @"Even effective entitlements do not guarantee MobileGestalt write permission.\n"];
    return report;
}
