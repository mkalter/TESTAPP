# 18 November 2026 — Real CLKWatchFaceLibrary service: importer versus native gallery

**Objective:** Check whether the only ClockKit service that the developer-signed
Watch6,18 / 23U95 app can bootstrap lookup,
`com.apple.ClockKit.CLKWatchFaceLibrary` (`kr=0`), offers a *native Apple
Hermès face-library write/activation contract*, rather than the public
`.watchface` file importer.

## Directly observed on physical Ultra 1

T2: `com.apple.ClockKit.CLKWatchFaceLibrary`, `bootstrap_look_up kr=0`,
Mach send right returned and released. T5: `sandbox_check(mach-lookup)`
ALLOW. Neither result establishes any server entitlement, RPC authorization
or native face persistence.

## iOS 26.1 actual ClockKit implementation: strong negative lead

Original iOS 26.1 (`iPhone18,3/23B85`) ClockKit disassembly:
- [`CLKWatchFaceLibraryServer.mm`](https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/90aa0cfe59d9682b4265e1354c8b19ec3c7823ab/System/Library/Frameworks/ClockKit.framework/ClockKit/CLKWatchFaceLibraryServer.mm)
- [`CLKWatchFaceLibrary.mm`](https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/90aa0cfe59d9682b4265e1354c8b19ec3c7823ab/System/Library/Frameworks/ClockKit.framework/ClockKit/CLKWatchFaceLibrary.mm)
- [iOS 26 runtime protocol header](https://github.com/qingralf/iOS26-Runtime-Headers/blob/cbf1d4c4122f3c6807eba36693581882640e5c6c/protocols/CLKWatchFaceLibraryServerInterface.h)
- [iOS 18.2 companion XPC receiver implementation](https://github.com/EthanArbuckle/iPhone17-1_18.2_22C152_Restore/blob/e26ed4563f78871c59d2d96856756a65d62517e5/System/Library/Frameworks/ClockKit.framework/XPCServices/CLKCompanionWatchFaceLibraryService.xpc/CLKCompanionWatchFaceLibraryService.m)

**Exact two known interface methods**:
1. `validateFaceType:faceBundleId:completionHandler:`: returns error or
   success on basic `NTKGreenfieldUtilities validateFaceType:faceBundleId:`;
   this is a **validation service**, not native system-face insertion.
2. `openWatchFaceURLWithSecurityScopedURL:sourceApplicationBundleIdentifier:completionHandler:`:
   opens a user-supplied `.watchface` resource. The iOS client extracts
   `face.json` locally, reads `face type` and `bundle id`, validates
   these and forwards the security-scoped URL to the service.

There is no known `_queue_addFace:forUUID:`, `NTKDCollectionStore` write or
native Hermès device-eligibility override method in this protocol. **A
`bootstrap_look_up=0` therefore does not turn this name into a
native-face installer or a device-identity writer.**

**Strong qualification:** those exact Objective-C bodies were disassembled
from **iOS**, not Watch6,18 23U95. WatchOS might have a different service
host/exported interface. Require hash-grounded original watchOS extraction
before declaring it the same server. The independent watchOS original
`NTKZeusFaceBundle` `isRestrictedForDevice:` and
`_NTKCanAddWatchFace` remain independent gates even if import validates.

## 23U95 watchOS-specific audit (offline, non-destructive)

New workflow `.github/workflows/audit-23u95-clockkit-face-library-service.yml`
extracts original ClockKit framework, XPC bundle, launchd manifest candidates
and known FaceBundle Info.plists from Apple's matching Watch6,18/23U95 IPSW.
It publishes SHA256, plist metadata, short relevant selector/interface
strings, and **whether these specific files actually exist** (not original
Apple executable bytes). If ClockKit is only in dyld cache, the report must
say *NOT FOUND in standalone filesystem* rather than claim absence from watchOS.

### Decision criteria

- **If exactly these validation/import RPCs are watchOS-confirmed:** decline
  futile XPC brute force. Optional only-read validation might explain an
  import error but does not bypass original native Hermès restrictions.
- **If new watchOS-only read-only native gallery methods are independently
  found:** build opt-in diagnostic with known typed protocol and expected
  error handling; no mutating library reset or protected file calls.
- No use of fake `.watchface` ZIPs as evidence of authentic native
  FaceBundle enablement; no actual native watchface unlock has occurred.
