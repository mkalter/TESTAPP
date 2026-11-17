/* Adapted from mightywhite/HermesEnabler PR #93 (MIT license). */
#import "BQOriginalHermes.h"
#import <CoreGraphics/CoreGraphics.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// Uses Apple's installed NanoTimeKit classes only. This feature never writes
// MobileGestalt or the first-party ClockFace/FaceCollection database.
// Private API is experimental, unsupported and intentionally opt-in.

static id sController;
static id sRoot;
static id sFace;
static NSMutableArray<NSString *> *sFaceTrace;

static void BQFaceNote(NSString *message) {
    if (message.length) [sFaceTrace addObject:message];
}
static NSString *BQFaceOutcome(NSString *result) {
    BQFaceNote([@"Result: " stringByAppendingString:result ?: @"(nil)"]);
    return result;
}

static BOOL Has(id object, NSString *name) {
    return object && [object respondsToSelector:NSSelectorFromString(name)];
}
static id Get(id object, NSString *name) {
    return Has(object, name)
        ? ((id(*)(id, SEL))objc_msgSend)(object, NSSelectorFromString(name)) : nil;
}
static unsigned GetUnsigned(id object, NSString *name) {
    return Has(object, name)
        ? ((unsigned(*)(id, SEL))objc_msgSend)(object, NSSelectorFromString(name)) : 0;
}
static void SetUnsigned(id object, NSString *name, unsigned value) {
    if (Has(object, name))
        ((void(*)(id, SEL, unsigned))objc_msgSend)(object, NSSelectorFromString(name), value);
}
static NSArray<NSDictionary<NSString *, NSString *> *> *Styles(void) {
    return @[
        @{@"name": @"Hermès Circulaire", @"bundle": @"com.apple.NTKPoodleFaceBundle",
          @"face": @"NTKPoodleFace", @"view": @"NTKPoodleFaceView"},
        @{@"name": @"Hermès", @"bundle": @"com.apple.NTKZeusFaceBundle.NTKZeusAnalogFaceBundle",
          @"face": @"NTKZeusAnalogFace", @"view": @"NTKZeusAnalogFaceView"},
        @{@"name": @"Hermès Radial", @"bundle": @"com.apple.NTKBellonaFaceBundle",
          @"face": @"NTKBellonaFace", @"view": @"NTKBellonaFaceView"},
        @{@"name": @"Hermès Circuit H", @"bundle": @"com.apple.NTKHadesFaceBundle",
          @"face": @"NTKHadesFace", @"view": @"NTKHadesFaceView"},
        @{@"name": @"Hermès Lucky Horse", @"bundle": @"com.apple.NTKSecretariatFaceBundle",
          @"face": @"NTKSecretariatFace", @"view": @"NTKSecretariatFaceView"},
        @{@"name": @"Hermès Faubourg Party", @"bundle": @"com.apple.Hermes2025Face",
          @"face": @"NTKHermes2025FaceBundle.Hermes2025Face",
          @"view": @"NTKHermes2025FaceBundle.Hermes2025FaceView"}
    ];
}
static BOOL LoadOriginalFrameworks(void) {
    if (!dlopen("/System/Library/Frameworks/ClockKit.framework/ClockKit", RTLD_LAZY))
        return NO;
    if (!dlopen("/System/Library/PrivateFrameworks/NanoTimeKit.framework/NanoTimeKit", RTLD_LAZY))
        return NO;
    NSString *root = @"/System/Library/NanoTimeKit/FaceBundles";
#if TARGET_OS_SIMULATOR
    const char *simRoot = getenv("SIMULATOR_ROOT");
    if (simRoot && simRoot[0])
        root = [@(simRoot) stringByAppendingPathComponent:@"System/Library/NanoTimeKit/FaceBundles"];
#endif
    for (NSString *name in @[@"NTKZeusFaceBundle.bundle", @"NTKHermes2025FaceBundle.bundle"]) {
        NSBundle *bundle = [NSBundle bundleWithPath:[root stringByAppendingPathComponent:name]];
        if (!bundle || ![bundle loadAndReturnError:nil])
            return NO;
    }
    return YES;
}
static id AppHost(void) {
    id app = Get(NSClassFromString(@"UIApplication"), @"sharedApplication");
    id windows = Get(app, @"windows");
    id window = [windows respondsToSelector:@selector(firstObject)] ? [windows firstObject] : nil;
    return Get(window, @"rootViewController");
}
static BOOL ValidOneArgumentVoidMethod(id object, SEL selector, const char *allowed) {
    Method m = object ? class_getInstanceMethod([object class], selector) : NULL;
    if (!m || method_getNumberOfArguments(m) != 3) return NO;
    char *ret = method_copyReturnType(m);
    char *arg = method_copyArgumentType(m, 2);
    BOOL valid = ret && ret[0] == 'v' && arg && strchr(allowed, arg[0]) != NULL;
    if (ret) free(ret);
    if (arg) free(arg);
    return valid;
}
// Keep the genuine OS-provided BacklightServices scene state. Do not create
// synthetic BLS objects or a pretend watchOS Always-On lifecycle.
static void ConnectOriginalBacklight(id controller) {
    id app = Get(NSClassFromString(@"UIApplication"), @"sharedApplication");
    Class nativeType = NSClassFromString(@"BLSBacklightSceneVisualState");
    if (!nativeType) return;
    for (id scene in Get(app, @"connectedScenes")) {
        id env = Get(scene, @"_backlightSceneEnvironment");
        id native = Get(env, @"visualState");
        SEL setter = NSSelectorFromString(@"setBacklightVisualState:");
        if ([native isKindOfClass:nativeType] &&
            ValidOneArgumentVoidMethod(controller, setter, "@")) {
            ((void(*)(id, SEL, id))objc_msgSend)(controller, setter, native);
            return;
        }
    }
}
static void UnmountOriginal(void) {
    if (Has(sController, @"resignActive"))
        ((void(*)(id, SEL))objc_msgSend)(sController, NSSelectorFromString(@"resignActive"));
    if (Has(sController, @"willMoveToParentViewController:"))
        ((void(*)(id, SEL, id))objc_msgSend)(
            sController, NSSelectorFromString(@"willMoveToParentViewController:"), nil);
    if (Has(sRoot, @"removeFromSuperview"))
        ((void(*)(id, SEL))objc_msgSend)(sRoot, NSSelectorFromString(@"removeFromSuperview"));
    if (Has(sController, @"removeFromParentViewController"))
        ((void(*)(id, SEL))objc_msgSend)(
            sController, NSSelectorFromString(@"removeFromParentViewController"));
    sController = nil;
    sRoot = nil;
    sFace = nil;
}
@implementation BQOriginalHermes
+ (NSString *)lastDiagnostics {
    return sFaceTrace.count ? [sFaceTrace componentsJoinedByString:@"\n"] : @"No face load has been attempted";
}
+ (NSString *)presentFaceAtIndex:(NSInteger)index {
    if (!NSThread.isMainThread) return @"Main thread required";
    NSArray *items = Styles();
    if (index < 0 || index >= (NSInteger)items.count) return @"Invalid Apple face selection";
    sFaceTrace = [NSMutableArray arrayWithObjects:
        @"=== Native Hermes FaceView diagnostics v2 ===",
        [NSString stringWithFormat:@"Face: %@ (index %ld)", items[index][@"name"], (long)index],
        [NSString stringWithFormat:@"OS: %@", NSProcessInfo.processInfo.operatingSystemVersionString],
        @"Scope: app-local FaceView only. No MobileGestalt or ClockFace writes.",
        nil];
    // 26.x is the known test family; any later generation needs fresh ABI tests.
    if (NSProcessInfo.processInfo.operatingSystemVersion.majorVersion != 26)
        return BQFaceOutcome(@"This experimental native viewer is validated for watchOS 26 only");
    if (!LoadOriginalFrameworks()) return BQFaceOutcome(@"Apple NanoTimeKit bundles unavailable");
    NSDictionary *spec = items[index];
    id device = Get(NSClassFromString(@"CLKDevice"), @"currentDevice");
    id manager = Get(NSClassFromString(@"NTKFaceBundleManager"), @"sharedManager");
    if (!device || !manager || !Has(device, @"setCollectionType:") ||
        !Has(manager, @"faceBundleForBundleIdentifier:onDevice:forMigration:"))
        return BQFaceOutcome(@"Original Apple FaceBundle API unavailable");

    id face = nil;
    id controller = nil;
    id root = nil;
    id nativeFaceView = nil;
    unsigned original = GetUnsigned(device, @"collectionType");
    // Ultra devices may have a different original collection type than Series watches.
    // Snapshot selection is process-local; always restore the observed original.
    if (original == 0 || original > 32)
        return BQFaceOutcome([NSString stringWithFormat:@"Unsupported CLKDevice collectionType=%u", original]);

    BQFaceNote([NSString stringWithFormat:@"CLKDevice: collectionType=%u, deviceCategory=%u",
                original, GetUnsigned(device, @"deviceCategory")]);
    // The temporary flag affects only this app process. It is always restored;
    // the actual device category, hardware identity and system clock are never changed.
    @try {
        SetUnsigned(device, @"setCollectionType:", 5);
        unsigned selected = GetUnsigned(device, @"collectionType");
        BQFaceNote([NSString stringWithFormat:@"Temporary collectionType=%u", selected]);
        if (selected == 5) {
            Class faceClass = NSClassFromString(spec[@"face"]);
            BQFaceNote([NSString stringWithFormat:@"Expected face class loaded=%@",
                        faceClass ? @"YES" : @"NO"]);
            // A normal lookup can reject styles that are not exposed in the
            // ordinary gallery. Migration lookup is a supported private API
            // variant; it is worth trying for these three faces IN THIS APP.
            // It does not grant first-party face installation rights.
            id bundle = ((id(*)(id, SEL, id, id, BOOL))objc_msgSend)(
                manager, NSSelectorFromString(@"faceBundleForBundleIdentifier:onDevice:forMigration:"),
                spec[@"bundle"], device, NO);
            BQFaceNote([NSString stringWithFormat:@"FaceBundle regular lookup=%@",
                        bundle ? NSStringFromClass([bundle class]) : @"NIL"]);
            if (!bundle && index >= 3) {
                bundle = ((id(*)(id, SEL, id, id, BOOL))objc_msgSend)(
                    manager, NSSelectorFromString(@"faceBundleForBundleIdentifier:onDevice:forMigration:"),
                    spec[@"bundle"], device, YES);
                BQFaceNote([NSString stringWithFormat:@"FaceBundle migration lookup=%@",
                            bundle ? NSStringFromClass([bundle class]) : @"NIL"]);
            }
            if (Has(bundle, @"defaultFaceForDevice:")) {
                face = ((id(*)(id, SEL, id))objc_msgSend)(
                    bundle, NSSelectorFromString(@"defaultFaceForDevice:"), device);
            }
            BQFaceNote([NSString stringWithFormat:@"Default face=%@",
                        face ? NSStringFromClass([face class]) : @"NIL"]);

            // Some bundles expose a gallery default even when the singular
            // factory returned nil; accept ONLY the exact native face class.
            if (!face && bundle && faceClass && index >= 3 && Has(bundle, @"galleryFacesForDevice:")) {
                id gallery = ((id(*)(id, SEL, id))objc_msgSend)(
                    bundle, NSSelectorFromString(@"galleryFacesForDevice:"), device);
                if ([gallery isKindOfClass:NSArray.class]) {
                    for (id candidate in gallery) {
                        if ([candidate isKindOfClass:faceClass]) {
                            face = candidate;
                            break;
                        }
                    }
                    BQFaceNote([NSString stringWithFormat:@"Gallery fallback candidates=%lu; match=%@",
                                (unsigned long)[gallery count], face ? @"YES" : @"NO"]);
                } else {
                    BQFaceNote(@"Gallery fallback did not return an array");
                }
            }
            if (face && faceClass && [face isKindOfClass:faceClass]) {
                id snapshotter = [NSClassFromString(@"NTKFaceSnapshotter") new];
                id defaults = Get(NSClassFromString(@"NTKFaceSnapshotter"),
                                  @"defaultModernSnapshotOptions");
                NSMutableDictionary *options = [defaults isKindOfClass:NSDictionary.class]
                    ? [defaults mutableCopy] : [NSMutableDictionary new];
                options[@"NTKSnapshotUseCanonicalContentKey"] = @NO;
                options[@"NTKSnapshotIgnoreSnapshotImages"] = @YES;
                if (Has(snapshotter, @"viewControllerForFace:withOptions:")) {
                    controller = ((id(*)(id, SEL, id, id))objc_msgSend)(
                        snapshotter, NSSelectorFromString(@"viewControllerForFace:withOptions:"),
                        face, options);
                }
                BQFaceNote([NSString stringWithFormat:@"Snapshot controller=%@",
                            controller ? NSStringFromClass([controller class]) : @"NIL"]);
                root = Get(controller, @"view");
                nativeFaceView = Get(controller, @"faceView");
                Class viewClass = NSClassFromString(spec[@"view"]);
                BQFaceNote([NSString stringWithFormat:@"Native view=%@; expected view class available=%@",
                            nativeFaceView ? NSStringFromClass([nativeFaceView class]) : @"NIL",
                            viewClass ? @"YES" : @"NO"]);
                if (!nativeFaceView || !viewClass ||
                    ![nativeFaceView isKindOfClass:viewClass]) {
                    BQFaceNote(@"FAIL stage=native-view-class-check");
                    controller = nil;
                    root = nil;
                }
            } else if (!bundle) {
                BQFaceNote(@"FAIL stage=face-bundle-lookup");
            } else if (!face) {
                BQFaceNote(@"FAIL stage=face-factory");
            } else {
                BQFaceNote([NSString stringWithFormat:@"FAIL stage=face-class-check; actual=%@",
                            NSStringFromClass([face class])]);
            }
        } else {
            BQFaceNote(@"FAIL stage=temporary-collection-type");
        }
    } @catch (NSException *exception) {
        BQFaceNote([NSString stringWithFormat:@"EXCEPTION stage=native-factory name=%@ reason=%@",
                    exception.name ?: @"unknown", exception.reason ?: @"unknown"]);
        controller = nil;
        root = nil;
    } @finally {
        SetUnsigned(device, @"setCollectionType:", original);
        BQFaceNote([NSString stringWithFormat:@"Restored collectionType=%u",
                    GetUnsigned(device, @"collectionType")]);
    }
    if (!controller || !root) return BQFaceOutcome(@"Genuine Apple FaceView unavailable (see trace: FaceBundle, face or view)");
    id host = AppHost();
    id hostView = Get(host, @"view");
    if (!hostView) return BQFaceOutcome(@"Unable to locate the Watch app host controller");
    UnmountOriginal();
    CGRect rect = ((CGRect(*)(id, SEL))objc_msgSend)(hostView, NSSelectorFromString(@"bounds"));
    if (Has(root, @"setFrame:"))
        ((void(*)(id, SEL, CGRect))objc_msgSend)(root, NSSelectorFromString(@"setFrame:"), rect);
    if (Has(root, @"setAutoresizingMask:"))
        ((void(*)(id, SEL, NSUInteger))objc_msgSend)(root, NSSelectorFromString(@"setAutoresizingMask:"), 18);
    ((void(*)(id, SEL, id))objc_msgSend)(host, NSSelectorFromString(@"addChildViewController:"), controller);
    ((void(*)(id, SEL, id))objc_msgSend)(hostView, NSSelectorFromString(@"addSubview:"), root);
    if (Has(controller, @"didMoveToParentViewController:"))
        ((void(*)(id, SEL, id))objc_msgSend)(controller, NSSelectorFromString(@"didMoveToParentViewController:"), host);
    if (Has(controller, @"unfreeze"))
        ((void(*)(id, SEL))objc_msgSend)(controller, NSSelectorFromString(@"unfreeze"));
    // The native snapshot controller starts in data mode 3. Original Apple
    // live data-mode propagation was physically verified for these five
    // classic faces; Faubourg Party's SceneEngine requires its snapshot mode.
    SEL mode = NSSelectorFromString(@"setDataMode:");
    if (index != 5 && ValidOneArgumentVoidMethod(controller, mode, "qQiI"))
        ((void(*)(id, SEL, NSInteger))objc_msgSend)(controller, mode, 1);
    if (Has(controller, @"becomeActive"))
        ((void(*)(id, SEL))objc_msgSend)(controller, NSSelectorFromString(@"becomeActive"));
    ConnectOriginalBacklight(controller);
    sController = controller;
    sRoot = root;
    sFace = face;
    Class pressClass = NSClassFromString(@"UILongPressGestureRecognizer");
    if (pressClass) {
        id recognizer = ((id(*)(id, SEL, id, SEL))objc_msgSend)(
            [pressClass alloc], NSSelectorFromString(@"initWithTarget:action:"),
            self, @selector(onOriginalLongPress:));
        if (Has(root, @"addGestureRecognizer:"))
            ((void(*)(id, SEL, id))objc_msgSend)(
                root, NSSelectorFromString(@"addGestureRecognizer:"), recognizer);
    }
    // Some SceneEngine views attach their subview during first layout.
    if (Has(hostView, @"layoutIfNeeded"))
        ((void(*)(id, SEL))objc_msgSend)(hostView, NSSelectorFromString(@"layoutIfNeeded"));
    BQFaceNote([NSString stringWithFormat:@"Native FaceView attached to window=%@",
                Get(nativeFaceView, @"window") ? @"YES" : @"NO"]);
    // A factory returning an object is not proof that it reached the display.
    // Fail closed if Apple's native FaceView is not attached to a real window.
    if (!Get(nativeFaceView, @"window")) {
        UnmountOriginal();
        return BQFaceOutcome(@"Genuine Apple FaceView was not attached to a window");
    }
    // Do not claim this is an Apple system Face Gallery selection.
    return BQFaceOutcome(@"native-face-mounted");
}
+ (void)onOriginalLongPress:(id)gesture {
    if (GetUnsigned(gesture, @"state") != 1) return;
    [self dismissFace];
    [NSNotificationCenter.defaultCenter
        postNotificationName:@"BQOriginalHermesDismissed" object:nil];
}
+ (void)dismissFace {
    if (!NSThread.isMainThread) return;
    UnmountOriginal();
}
+ (void)updateActualReducedLuminance:(BOOL)reduced {
    if (!NSThread.isMainThread || !sController) return;
    ConnectOriginalBacklight(sController);
    id animation = Get(sController, @"tritiumAnimationController");
    id tritium = Get(sController, @"tritiumController");
    id originalFaceView = Get(sController, @"faceView");
    if (!animation || Get(animation, @"tritiumController") != tritium ||
        Get(tritium, @"faceView") != originalFaceView ||
        !Get(originalFaceView, @"window")) return;
    SEL selector = NSSelectorFromString(@"setTritiumVisibleImmediately:");
    if (!ValidOneArgumentVoidMethod(animation, selector, "Bc")) return;
    // Invokes Apple's actual NTKTritiumAnimationController. No simulated
    // frames or handmade dimming. Does not guarantee first-party AOD timing.
    ((void(*)(id, SEL, BOOL))objc_msgSend)(animation, selector, reduced);
}
@end
