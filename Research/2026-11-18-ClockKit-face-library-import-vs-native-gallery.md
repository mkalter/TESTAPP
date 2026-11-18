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


## Genuine Watch6,18 / 23U95 original filesystem result

[Apple IPSW extraction run #44269491459](https://github.com/mkalter/TESTAPP/actions/runs/44269491459)
**SUCCESS** (three real, hash-pinned original Info.plists):

| Original installed source path | Verified CFBundleIdentifier | Plist SHA256 |
|---|---|---|
| `System/Library/Frameworks/ClockKit.framework/Info.plist` | `com.apple.ClockKit` | `9f560897edc43607fd03618dd255cba5f470fd54d7ebbb0ee087274b6aba8afd` |
| `System/Library/NanoTimeKit/FaceBundles/NTKZeusFaceBundle.bundle/Info.plist` | `com.apple.NTKZeusFaceBundle` | `aee1ca3ce7961975c63f1c99c2bcd6ebd1ee328ee88113035a468c1639ff5894` |
| `System/Library/NanoTimeKit/FaceBundles/NTKHermes2025FaceBundle.bundle/Info.plist` | `com.apple.Hermes2025Face` | `6b3f66dd9e8c662886e089a7c36ee56fe6281c548f508c99e87d3313b1468b7f` |

**Important discovery:** Hermès 2025's real bundle identifier is
`com.apple.Hermes2025Face`, **not** the filename
`NTKHermes2025FaceBundle`. This now enables proper targeted read-only
validation without guessed IDs.

The ClockKit framework's Info.plist is standalone, but **no standalone
ClockKit Mach-O or ClockKit .xpc executable** matched the original
filesystem paths in the same scan. This is NOT evidence the executable
doesn't exist; shared libraries can be resident in original ARM64_32
dyld shared caches. The new [original dyld-only scan #44270583446](https://github.com/mkalter/TESTAPP/actions/runs/44270583446)
tests exactly that, without touching the physical Watch.

## New optional physical T7 — read-only ClockKit XPC validator

A new `BQRunClockKitReadOnlyFaceValidation` in
`HermesEnabler2/BQClockKitReadonlyValidation.m` is exposed as a **single
separate opt-in** `T7 · ClockKit-validatie` button (not in "Alle 6 lezen en
meten"). Uses `NSXPCInterface` with **only**
`validateFaceType:faceBundleId:completionHandler:`. It attempts:
- One intentionally invalid face type control to distinguish method/proxy
  accessibility from native eligibility;
- Only when `NTKFaceBundleStringFromFaceStyle(44)` exists in the actual
  Watch's loaded NanoTimeKit, uses the actual style string (no guesses);
- Only when original FaceBundle `Info.plist` is present and readable on
  the *actual Watch*, validates `com.apple.NTKZeusFaceBundle` and/or
  `com.apple.Hermes2025Face`; otherwise safely SKIP native checks.

The operation is **read-only validation**: no `.watchface` resource
opened, no `openWatchFaceURL`, no native library add/reset, no
MobileGestalt modification. Includes 5-second bounded waits for each
request and iPhone-transferred own Documents report
`clockkit-readonly-face-validation.txt`.

**SDK limitation discovered during actual CI:** `NSXPCConnection
initWithServiceName:` is declared unavailable in watchOS. A naive
source-level call failed compile. The new version checks the actual
runtime instance selector/IMP before attempting the initializer; absence
returns UNKNOWN, avoiding reliance on an unsupported ABI.

**Interpretation**:
- A server error or timeout for deliberately invalid control does not
  show why Hermès is denied.
- Even a successful Hermès validation is **not** proof that the original
  signed face can be displayed in the stock gallery or persist.
- This test is not a request to bypass Apple's code signing, entitlement
  enforcement or protection of device identity.

### Why a successful XPC validation would still have limited value

An independently decompiled real iOS 18.2
`NTKGreenfieldUtilities.validateFaceType:faceBundleId:`:
1. Converts `face type` string to a numerical style via
   `NTKFaceBundleGetFaceStyleFromString`.
2. For style `44` specifically uses `initWithBundleIdentifier:`; other
   styles use `initWithFaceStyle:`.
3. Calls `NTKFaceDescriptor.isAvailableForDevice:` on the current device.

This is an *availability preflight*, not a privileged face insertion
or a cache-write method. Source:
https://github.com/EthanArbuckle/iPhone17-1_18.2_22C152_Restore/blob/e26ed4563f78871c59d2d96856756a65d62517e5/System/Library/PrivateFrameworks/NanoTimeKit.framework/NTKGreenfieldUtilities.m .
The original watchOS implementation is not yet independently traced.
