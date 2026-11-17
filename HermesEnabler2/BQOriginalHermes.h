/* Adapted from mightywhite/HermesEnabler PR #93 (MIT license). */
#import <Foundation/Foundation.h>

// Experimental, app-local Apple NanoTimeKit face viewer. No system face-store
// changes, MobileGestalt writes, bundled artwork, or custom-rendered faces.
@interface BQOriginalHermes : NSObject
+ (NSString *)presentFaceAtIndex:(NSInteger)index;
+ (void)dismissFace;
+ (void)updateActualReducedLuminance:(BOOL)reduced;
/// Last face-mount trace. App-local information for troubleshooting, no system mutations.
+ (NSString *)lastDiagnostics;
@end
