#import "NativeSystemFaceImportProbe.h"
#import <objc/runtime.h>

@implementation NativeSystemFaceImportProbe

+ (void)importFaceSkippingClientValidationAtURL:(NSURL *)url
                                   completion:(void (^)(NSError * _Nullable))completion {
    void (^answer)(NSError *) = [completion copy];
    if (!answer) return;
    if (!url.isFileURL || ![[url.pathExtension lowercaseString] isEqualToString:@"watchface"]) {
        answer([NSError errorWithDomain:@"HermesSystemFaceImportTest" code:1
                                 userInfo:@{NSLocalizedDescriptionKey:
                                     @"A local .watchface file is required."}]);
        return;
    }

    Class clockKit = NSClassFromString(@"CLKWatchFaceLibrary");
    SEL methodName = NSSelectorFromString(@"_addWatchFaceAtURL:shouldValidate:completionHandler:");
    Method method = clockKit ? class_getInstanceMethod(clockKit, methodName) : NULL;
    if (!method || method_getNumberOfArguments(method) != 5) {
        answer([NSError errorWithDomain:@"HermesSystemFaceImportTest" code:2
                                 userInfo:@{NSLocalizedDescriptionKey:
                                     @"This iOS version does not expose the expected private ClockKit import method."}]);
        return;
    }

    // Guard every explicit argument, not just BOOL. A nonmatching private
    // method ABI is a hard stop: calling the wrong IMP may crash the host.
    char *returns = method_copyReturnType(method);
    char *urlType = method_copyArgumentType(method, 2);
    char *check = method_copyArgumentType(method, 3);
    char *callbackType = method_copyArgumentType(method, 4);
    BOOL correctABI = returns && returns[0] == 'v' &&
                      urlType && urlType[0] == '@' &&
                      check && (check[0] == 'B' || check[0] == 'c') &&
                      callbackType && callbackType[0] == '@' &&
                      callbackType[1] == '?';
    if (returns) free(returns);
    if (urlType) free(urlType);
    if (check) free(check);
    if (callbackType) free(callbackType);
    if (!correctABI) {
        answer([NSError errorWithDomain:@"HermesSystemFaceImportTest" code:3
                                 userInfo:@{NSLocalizedDescriptionKey:
                                     @"ClockKit method signature differs; test aborted without calling the method."}]);
        return;
    }

    id library = [clockKit new];
    if (!library) {
        answer([NSError errorWithDomain:@"HermesSystemFaceImportTest" code:4
                                 userInfo:@{NSLocalizedDescriptionKey:
                                     @"Cannot initialize ClockKit library."}]);
        return;
    }

    // The signature (NSURL *, BOOL, NSError* callback) is taken from a
    // disassembly of iOS 26.1 ClockKit. Only execute after the ABI check.
    // Apple still validates suitability on its privileged server and Watch.
    typedef void (*ImportFunction)(id, SEL, NSURL *, BOOL, void (^)(NSError *));
    ImportFunction call = (ImportFunction)method_getImplementation(method);
    if (!call) {
        answer([NSError errorWithDomain:@"HermesSystemFaceImportTest" code:5
                                 userInfo:@{NSLocalizedDescriptionKey:
                                     @"ClockKit implementation is unavailable."}]);
        return;
    }

    @try {
        call(library, methodName, url, NO, answer);
    } @catch (NSException *exception) {
        answer([NSError errorWithDomain:@"HermesSystemFaceImportTest" code:6
                                 userInfo:@{NSLocalizedDescriptionKey:
                                     [NSString stringWithFormat:
                                      @"Private ClockKit invocation failed: %@",
                                      exception.reason ?: exception.name]}]);
    }
}
@end
