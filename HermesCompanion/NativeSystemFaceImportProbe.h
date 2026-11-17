#import <Foundation/Foundation.h>

// Experimental direct route to Apple's real ClockKit watch-face import handler.
// Skips only an early CLIENT-side availability pre-check, not the system's
// validation / Watch eligibility. Does not alter MobileGestalt or Carousel.
// The private selector is resolved and ABI-checked at runtime; fail closed.
@interface NativeSystemFaceImportProbe : NSObject
+ (void)importFaceSkippingClientValidationAtURL:(NSURL *)url
                                   completion:(void (^)(NSError * _Nullable error))completion
    NS_SWIFT_NAME(importFaceSkippingClientValidation(at:completion:));
@end
