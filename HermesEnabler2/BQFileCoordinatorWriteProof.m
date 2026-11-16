#import "BQPermissionDiagnostics.h"
#import "BQCore.h"
#import <Foundation/Foundation.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

// Experimental on-device proof. Does not use MCM/Class 7/Class 12/Class 13,
// does not request private entitlements, and never replaces/unlinks the MG file.
// IMPORTANT: NSFileCoordinator ordinarily coordinates access; it does NOT
// grant sandbox privileges. A positive result must be proven by pwrite + fsync.

static NSString *BQFCOpenOnly(NSString *path) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation,
                  O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        int e = errno;
        return [NSString stringWithFormat:@"O_RDWR=DENIED errno=%d (%s)",
                e, strerror(e)];
    }
    close(fd);
    return @"O_RDWR=ALLOW; immediately closed; no mutation";
}

static NSString *BQFCProbeWrite(NSString *path) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation,
                  O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        int e = errno;
        return [NSString stringWithFormat:@"O_RDWR=DENIED errno=%d (%s), no write",
                e, strerror(e)];
    }

    // This is an actual write test, but only writes the exact pre-existing byte
    // back to offset zero; never creates, resizes, truncates or changes the data.
    unsigned char first = 0;
    errno = 0;
    ssize_t got = pread(fd, &first, 1, 0);
    if (got != 1) {
        int e = errno;
        close(fd);
        return [NSString stringWithFormat:
                @"O_RDWR=ALLOW; pread=%ld errno=%d; write SKIPPED",
                (long)got, e];
    }

    errno = 0;
    ssize_t wrote = pwrite(fd, &first, 1, 0);
    int writeErrno = errno;
    int syncStatus = -1;
    int syncErrno = 0;
    if (wrote == 1) {
        errno = 0;
        syncStatus = fsync(fd);
        syncErrno = errno;
    }
    close(fd);

    return [NSString stringWithFormat:
            @"O_RDWR=ALLOW; pwrite-same-byte=%ld/1 errno=%d; fsync=%d errno=%d",
            (long)wrote, writeErrno, syncStatus, syncErrno];
}

NSString *BQRunFileCoordinatorWriteProof(void) {
    NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObjects:
        @"=== watchOS File Coordination: real write proof v1 ===",
        @"New API path: NSFileCoordinator (NOT MCM, KAMUI or SystemGroup token)",
        @"No unlink, rename, truncation, class switching, symlinks, or cache rebuild.",
        @"If writable: pwrite one IDENTICAL existing byte and fsync only.",
        @"Coordination is NOT a known sandbox bypass. Expect EPERM.",
        nil];
    [lines addObject:[NSString stringWithFormat:@"time=%@", [NSDate date]]];
    [lines addObject:[NSString stringWithFormat:@"os=%@",
                      [NSProcessInfo processInfo].operatingSystemVersionString]];
    [lines addObject:[NSString stringWithFormat:@"bundle=%@",
                      [NSBundle mainBundle].bundleIdentifier ?: @"unknown"]];

    NSString *mgPath = BQMobileGestaltPath();
    NSData *before = [NSData dataWithContentsOfFile:mgPath
                                           options:NSDataReadingMappedIfSafe
                                             error:NULL];
    if (!before || before.length < 1024) {
        [lines addObject:@"Protected MG read/backup unavailable or unexpectedly small. MG write SKIPPED."];
    } else {
        NSString *backup = [BQDocuments() stringByAppendingPathComponent:
                            @"MG-filecoord-original-23U95.plist"];
        NSData *previous = [NSData dataWithContentsOfFile:backup];
        BOOL backupOK = (previous && [previous isEqualToData:before]);
        if (!previous) {
            backupOK = [before writeToFile:backup atomically:YES];
            if (backupOK) {
                NSData *saved = [NSData dataWithContentsOfFile:backup];
                backupOK = [saved isEqualToData:before];
            }
        }
        // Never overwrite an existing backup with different bytes.
        [lines addObject:[NSString stringWithFormat:
                          @"MG read=%lu bytes; verified persistent backup=%@",
                          (unsigned long)before.length, backupOK ? @"YES" : @"NO"]];
        if (!backupOK) {
            [lines addObject:@"Backup failed/mismatched; protected write disabled."];
        }
    }

    NSString *controlPath = [BQDocuments() stringByAppendingPathComponent:
                             @"filecoord-write-control.bin"];
    NSData *controlBytes = [@"FILECOORD-CONTROL-v1" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *controlError = nil;
    BOOL controlOK = [controlBytes writeToFile:controlPath
                                       options:NSDataWritingAtomic
                                         error:&controlError];
    [lines addObject:[NSString stringWithFormat:@"own control create=%@ error=%@",
                      controlOK ? @"YES" : @"NO",
                      controlError.localizedDescription ?: @"none"]];

    BOOL backupVerified = NO;
    if (before && before.length >= 1024) {
        NSString *backup = [BQDocuments() stringByAppendingPathComponent:
                            @"MG-filecoord-original-23U95.plist"];
        backupVerified = [[NSData dataWithContentsOfFile:backup] isEqualToData:before];
    }

    NSArray<NSDictionary<NSString *, id> *> *targets = @[
        @{@"name": @"Own Documents CONTROL", @"path": controlPath,
          @"eligible": @(controlOK)},
        @{@"name": @"Protected MobileGestalt", @"path": mgPath,
          @"eligible": @(backupVerified)}
    ];

    for (NSDictionary<NSString *, id> *target in targets) {
        NSString *name = target[@"name"];
        NSString *path = target[@"path"];
        BOOL eligible = [target[@"eligible"] boolValue];

        [lines addObject:[NSString stringWithFormat:@"\n[%@]", name]];
        [lines addObject:[NSString stringWithFormat:@"baseline: %@",
                          BQFCOpenOnly(path)]];

        if (!eligible) {
            [lines addObject:@"coordination: SKIPPED (missing verified original/own control)"];
            continue;
        }

        NSFileCoordinator *coordinator =
            [[NSFileCoordinator alloc] initWithFilePresenter:nil];
        NSError *coordError = nil;
        __block BOOL accessorCalled = NO;
        __block NSString *result = @"accessor not called";
        [coordinator coordinateWritingItemAtURL:[NSURL fileURLWithPath:path]
                                         options:0
                                           error:&coordError
                                      byAccessor:^(NSURL *coordinatedURL) {
            accessorCalled = YES;
            if (!coordinatedURL.isFileURL ||
                ![coordinatedURL.path isEqualToString:path]) {
                result = [NSString stringWithFormat:
                          @"SKIPPED: coordinator redirected target to %@",
                          coordinatedURL.path ?: @"non-file URL"];
                return;
            }
            result = BQFCProbeWrite(coordinatedURL.path);
        }];
        [lines addObject:[NSString stringWithFormat:
                          @"coordination: accessor=%@; NSError=%@ (%ld) %@",
                          accessorCalled ? @"YES" : @"NO",
                          coordError.domain ?: @"none",
                          (long)(coordError ? coordError.code : 0),
                          coordError.localizedDescription ?: @"none"]];
        [lines addObject:result];
        [lines addObject:[NSString stringWithFormat:@"after: %@",
                          BQFCOpenOnly(path)]];
    }

    NSData *after = [NSData dataWithContentsOfFile:mgPath];
    if (before) {
        [lines addObject:[NSString stringWithFormat:
                          @"\nMG contents unchanged after probe=%@; before=%lu after=%lu",
                          [after isEqualToData:before] ? @"YES" : @"NO - INSPECT IMMEDIATELY",
                          (unsigned long)before.length, (unsigned long)after.length]];
    }
    [lines addObject:@"Proof threshold: MG O_RDWR allowed INSIDE coordination + pwrite=1 + fsync=0 + MG unchanged."];
    [lines addObject:@"If O_RDWR remains EPERM, this approach DOES NOT grant write access."];

    NSString *report = [lines componentsJoinedByString:@"\n"];
    NSString *reportPath = [BQDocuments()
                            stringByAppendingPathComponent:@"mg-filecoord-write-proof.txt"];
    NSError *error = nil;
    if (![report writeToFile:reportPath atomically:YES
                   encoding:NSUTF8StringEncoding error:&error]) {
        report = [report stringByAppendingFormat:@"\nReport save failed: %@",
                  error.localizedDescription];
    }
    BQLog(@"[FILECOORD]\n%@\n[/FILECOORD]", report);
    NSLog(@"[FILECOORD]\n%@\n[/FILECOORD]", report);
    return report;
}
