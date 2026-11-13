#import "HermesFaceProbe.h"
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <dlfcn.h>

static BOOL HR(id o,NSString *s){return o && [o respondsToSelector:NSSelectorFromString(s)];}
static id H0(id o,NSString *s){return HR(o,s)?((id(*)(id,SEL))objc_msgSend)(o,NSSelectorFromString(s)):nil;}
static id H1(id o,NSString *s,id a){return HR(o,s)?((id(*)(id,SEL,id))objc_msgSend)(o,NSSelectorFromString(s),a):nil;}
static id H2(id o,NSString *s,id a,id b){return HR(o,s)?((id(*)(id,SEL,id,id))objc_msgSend)(o,NSSelectorFromString(s),a,b):nil;}
static id H2B(id o,NSString *s,id a,BOOL b){return HR(o,s)?((id(*)(id,SEL,id,BOOL))objc_msgSend)(o,NSSelectorFromString(s),a,b):nil;}
static id H3B(id o,NSString *s,id a,id b,BOOL c){return HR(o,s)?((id(*)(id,SEL,id,id,BOOL))objc_msgSend)(o,NSSelectorFromString(s),a,b,c):nil;}
static BOOL HB(id o,NSString *s){return HR(o,s)&&((BOOL(*)(id,SEL))objc_msgSend)(o,NSSelectorFromString(s));}
static id HFaceJSON(id cls,NSDictionary *json,id device) {
    NSString *name=@"faceWithJSONObjectRepresentation:forDevice:forMigration:allowFallbackFromInvalidFaceStyle:";
    if(!HR(cls,name))return nil;
    return ((id(*)(id,SEL,id,id,BOOL,BOOL))objc_msgSend)(
       cls,NSSelectorFromString(name),json,device,YES,NO);
}
static void HSetFlag(id face) {
    if(HR(face,@"setForMigration:"))
        ((void(*)(id,SEL,BOOL))objc_msgSend)(face,NSSelectorFromString(@"setForMigration:"),YES);
}
static id HMakeFace(id bundle,id device,NSString *identifier,NSMutableString *log) {
    id face=H1(bundle,@"defaultFaceForDevice:",device);
    [log appendFormat:@"Default native face=%@\n",face?@"YES":@"NO"];
    if(face){
        NSDictionary *existing=H0(face,@"JSONObjectRepresentation");
        if([existing isKindOfClass:NSDictionary.class]){
            NSMutableDictionary *updated=[existing mutableCopy];
            updated[@"forMigration"]=@YES;
            id migrated=HFaceJSON(NSClassFromString(@"NTKFace"),updated,device);
            if(migrated)face=migrated;
            else HSetFlag(face);
        }else HSetFlag(face);
    }
    if(!face) {
        NSDictionary *json=@{@"version":@"4",@"face type":@"bundle",
            @"bundle id":identifier,@"customization":@{},
            @"complications":@{},@"forMigration":@YES};
        face=HFaceJSON(NSClassFromString(@"NTKFace"),json,device);
        [log appendFormat:@"JSON migration face=%@\n",face?@"YES":@"NO"];
    }
    NSDictionary *actual=H0(face,@"JSONObjectRepresentation");
    if(![actual isKindOfClass:NSDictionary.class]||
       ![actual[@"bundle id"] isEqualToString:identifier]||
       ![actual[@"forMigration"] boolValue]) {
        [log appendString:@"Native face failed bundle-ID/migration validation\n"];
        return nil;
    }
    [log appendFormat:@"Native face created: %@, migration=YES\n",NSStringFromClass([face class])];
    return face;
}
static BOOL HTryLibrary(id face,id device,NSMutableString *log) {
    id pairing=H0(device,@"pairingID");
    if(!pairing){[log appendString:@"Paired Watch library unavailable (no pairingID).\n"];return NO;}
    id manager=H0(NSClassFromString(@"NTKCompanionFaceCollectionsManager"),@"sharedInstance");
    id library=H2(manager,@"sharedFaceCollectionForDevice:forCollectionIdentifier:",
                   device,@"LibraryFaces");
    if(!library||!HB(library,@"hasLoaded")){
        [log appendString:@"Paired LibraryFaces not loaded/accessible.\n"];
        return NO;
    }
    if(!HR(library,@"appendFace:suppressingCallbackToObserver:")||
       !HR(library,@"setSelectedFace:suppressingCallbackToObserver:")){
        [log appendString:@"Library append/selection interfaces unavailable.\n"];return NO;
    }
    id copy=H0(face,@"deepCopy")?:face;
    ((void(*)(id,SEL,id,id))objc_msgSend)(
       library,NSSelectorFromString(@"appendFace:suppressingCallbackToObserver:"),copy,nil);
    ((void(*)(id,SEL,id,id))objc_msgSend)(
       library,NSSelectorFromString(@"setSelectedFace:suppressingCallbackToObserver:"),copy,nil);
    BOOL selected=H0(library,@"selectedFace")==copy;
    [log appendFormat:@"Library append+select executed, local selected=%@. Remote sync unverified.\n",
       selected?@"YES":@"NO"];
    return selected;
}
static NSURL *HCopyEncoded(id encoded,NSString *identifier,NSMutableString *log) {
    id url=H0(encoded,@"watchFaceDataUrl");
    if(![url isKindOfClass:NSURL.class]||![url isFileURL])return nil;
    NSFileManager *fm=NSFileManager.defaultManager;
    NSDictionary *attrs=[fm attributesOfItemAtPath:[url path] error:nil];
    unsigned long long size=[attrs[NSFileSize] unsignedLongLongValue];
    if(![attrs[NSFileType] isEqual:NSFileTypeRegular]||!size||size>16*1024*1024) return nil;
    NSURL *folder=[[fm URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
    NSString *name=[NSString stringWithFormat:@"Hermes-%@-%@.watchface",
                    identifier.lastPathComponent,NSUUID.UUID.UUIDString];
    NSURL *dest=[folder URLByAppendingPathComponent:name];
    NSError *error=nil;
    if(![fm copyItemAtURL:url toURL:dest error:&error]){
        [log appendFormat:@"Native archive copy failed: %@\n",error];return nil;
    }
    [log appendFormat:@"Native .watchface exported (%llu bytes).\n",size];
    return dest;
}
static NSURL *HNativeZip(id face,NSString *identifier,NSMutableString *log) {
    void *p=dlsym(RTLD_DEFAULT,"NTKDZipFileFromFace");
    if(!p){[log appendString:@"NTKDZipFileFromFace unavailable.\n"];return nil;}
    NSURL *folder=[[NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory
                                                      inDomains:NSUserDomainMask] firstObject];
    NSString *name=[NSString stringWithFormat:@"Hermes-%@-%@.watchface",
                    identifier.lastPathComponent,NSUUID.UUID.UUIDString];
    NSString *path=[[folder URLByAppendingPathComponent:name] path];
    BOOL ok=((BOOL(*)(id,id,id))p)(face,nil,path);
    NSDictionary *attrs=[NSFileManager.defaultManager attributesOfItemAtPath:path error:nil];
    NSUInteger bytes=[attrs[NSFileSize] unsignedIntegerValue];
    if(!ok||bytes==0||bytes>16*1024*1024){
        [log appendFormat:@"Native zip not generated: ok=%@ bytes=%lu\n",
             ok?@"YES":@"NO",(unsigned long)bytes];
        [NSFileManager.defaultManager removeItemAtPath:path error:nil];
        return nil;
    }
    [log appendFormat:@"Native zip exported (%lu bytes)\n",(unsigned long)bytes];
    return [NSURL fileURLWithPath:path];
}
void HERMESAttemptFaceActivation(void (^completion)(NSString *report,NSURL *url)) {
    if(!completion)return;
    dispatch_async(dispatch_get_main_queue(),^{
        NSMutableString *log=[NSMutableString stringWithString:
          @"=== Hermès native activation ===\n"
           "Creates a real native Hermès face, tries paired library, exports a watchface to open in Apple Watch.\n"];
        for(NSString *lib in @[
            @"/System/Library/Frameworks/ClockKit.framework/ClockKit",
            @"/System/Library/PrivateFrameworks/NanoTimeKit.framework/NanoTimeKit",
            @"/System/Library/PrivateFrameworks/NanoTimeKitCompanion.framework/NanoTimeKitCompanion"
        ])dlopen(lib.fileSystemRepresentation,RTLD_NOW|RTLD_LOCAL);
        id clk=NSClassFromString(@"CLKDevice");
        id pdr=H0(clk,@"activePDRDevice");
        id paired=pdr?H2B(clk,@"deviceForPDRDevice:forced:",pdr,NO):nil;
        id device=paired?:H0(clk,@"currentDevice");
        id manager=H0(NSClassFromString(@"NTKFaceBundleManager"),@"sharedManager");
        [log appendFormat:@"ActivePDR=%@ realPairedCLK=%@ pairingID=%@\n",
            pdr?@"YES":@"NO",paired?@"YES":@"NO",
            H0(device,@"pairingID")?@"YES":@"NO"];
        if(!device||!manager){
            [log appendString:@"No supported NanoTimeKit/CLKDevice context; unable to activate.\n"];
            completion([log copy],nil);return;
        }
        NSArray<NSString *> *candidates=@[
            @"com.apple.NTKPoodleFaceBundle",
            @"com.apple.NTKHadesFaceBundle",
            @"com.apple.NTKSecretariatFaceBundle",
            @"com.apple.NTKBellonaFaceBundle",
            @"com.apple.NTKSquallFaceBundle",
            @"com.apple.Hermes2025Face"
        ];
        id recipeClass=NSClassFromString(@"NTKGreenfieldDraftRecipe");
        id greenfield=NSClassFromString(@"NTKGreenfieldUtilities");
        __block BOOL finished=NO;
        __block NSUInteger index=0;
        __block void (^next)(void)=nil;
        void (^finish)(NSURL *)=^(NSURL *archive){
            if(finished)return;
            finished=YES;
            [log appendString:archive?
              @"Native watchface available; use the iOS share sheet to select Watch / Add to My Faces. Device acceptance still unverified.\n":
              @"No native archive could be created. No Watch activation verified.\n"];
            completion([log copy],archive);
            next=nil;
        };
        next=^{
            if(finished)return;
            if(index>=candidates.count){finish(nil);return;}
            NSString *identifier=candidates[index++];
            [log appendFormat:@"\n[%@]\n",identifier];
            @try{
                id bundle=H3B(manager,
                    @"faceBundleForBundleIdentifier:onDevice:forMigration:",
                    identifier,device,YES);
                if(!bundle){[log appendString:@"Migration bundle not available.\n"];next();return;}
                id face=HMakeFace(bundle,device,identifier,log);
                if(!face){next();return;}
                @try{ HTryLibrary(face,device,log); }
                @catch(NSException *e){[log appendFormat:@"Library exception: %@ %@\n",e.name,e.reason];}
                NSString *encoder=@"encodeRecipeFromDraftRecipe:completionBlock:";
                if(!recipeClass||!HR(greenfield,encoder)){
                    NSURL *zip=HNativeZip(face,identifier,log);
                    if(zip)finish(zip);else next();return;
                }
                id recipe=H1([recipeClass alloc],@"initWithFace:",face);
                if(!recipe){
                    [log appendString:@"Native recipe initialization refused.\n"];
                    NSURL *zip=HNativeZip(face,identifier,log);
                    if(zip)finish(zip);else next();return;
                }
                __block BOOL responded=NO;
                void (^cb)(id,id)=^(id encoded,id error){
                    dispatch_async(dispatch_get_main_queue(),^{
                        if(finished||responded)return;
                        responded=YES;
                        if(error)[log appendFormat:@"Greenfield returned error: %@\n",error];
                        NSURL *archive=HCopyEncoded(encoded,identifier,log);
                        if(!archive)archive=HNativeZip(face,identifier,log);
                        if(archive)finish(archive);else next();
                    });
                };
                ((void(*)(id,SEL,id,id))objc_msgSend)(
                    greenfield,NSSelectorFromString(encoder),recipe,[cb copy]);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,25*NSEC_PER_SEC),
                    dispatch_get_main_queue(),^{
                        if(finished||responded)return;
                        responded=YES;
                        [log appendString:@"Greenfield timed out: native zip fallback.\n"];
                        NSURL *archive=nil;
                        @try{archive=HNativeZip(face,identifier,log);}
                        @catch(NSException *e){[log appendFormat:@"Zip exception: %@\n",e.name];}
                        if(archive)finish(archive);else next();
                    });
            }@catch(NSException *e){
                [log appendFormat:@"Attempt exception: %@ %@\n",e.name,e.reason];
                next();
            }
        };
        next();
    });
}
