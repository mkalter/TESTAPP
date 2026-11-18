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


## Original 23U95 binary definitively recovered from genuine ARM64_32 dyld

[Verified original Watch6,18 / 23U95 run #44270583446](https://github.com/mkalter/TESTAPP/actions/runs/44270583446)
**SUCCESS**. SHA-256 of the extracted original
`/System/Library/Frameworks/ClockKit.framework/ClockKit` is:

`225c004e9a2288799cdad99228076a7b7761befb8686c48407f3f8d0dec59dad`

A separate standalone executable did not exist in the APFS file inventory,
but the original dyld cache did contain and export the matching `ClockKit`
image. This resolves the prior standalone-path uncertainty.

Concrete original binary indicator counts:
- `CLKWatchFaceLibrary`: 80;
- `CLKWatchFaceLibraryServer`: 35;
- `CLKWatchFaceLibraryServerInterface`: 11;
- `CLKCompanionWatchFaceLibraryService`: 6;
- `validateFaceType:faceBundleId:completionHandler:`: 5;
- `openWatchFaceURLWithSecurityScopedURL:`: 6;
- `addWatchFaceAtURL:`: 9;
- `face.json`: 3;
- `com.apple.ClockKit.CLKWatchFaceLibrary`: 1.
- `NTKDCollectionStore`, `_queue_addFace:forUUID:`, `_resetWithFaces:`:
  **no matching string** in the original exported ClockKit executable.

These are independently verified **binary strings**, not yet proof of exact
watchOS XPC protocol implementation. They align closely with the two-method
iOS 26 importer protocol and point away from native Apple collection-store
write authority in this particular service. A genuine native system face
still requires passing independent NanoTimeKit class restrictions, actual
Apple library persistence and Carousel rendering.

## New T7 unsigned iPhone + Watch build passed

[GitHub Actions #44270806397](https://github.com/mkalter/TESTAPP/actions/runs/44270806397)
**SUCCESS**, uploaded `unsigned-iphone-watch-ipa` artifact ID
`14411579760`. The code includes the separate opt-in button
`T7 · ClockKit-validatie` and the report
`clockkit-readonly-face-validation.txt`. Six original no-RPC diagnostics
remain separately runnable and in the six-test batch.

The first T7 code revision failed compilation because the public watchOS
SDK declares `-[NSXPCConnection initWithServiceName:]` unavailable; this
was corrected with a *checked, dynamically resolved runtime IMP*. If that
method is truly absent at runtime, T7 reports UNKNOWN and does not attempt
to call it. No private entitlement is added by this mechanism and the test
can still fail at the remote method-authority gate.

No persistent original Hermès face was inserted and no protected file changed.


## Physical T7-v1 result: XPC transport invalidation (08:58 UTC, Watch6,18 23U95)

The real developer-signed Watch app reported:
```
NSXPCConnection=present NSXPCInterface=present
Apple protocol in current process=present
style44 face type=bundle
Zeus bundle ID=com.apple.NTKZeusFaceBundle
Hermes2025 ID=com.apple.Hermes2025Face
CONTROL invalid face type -> UNKNOWN: timeout
Transport NSError domain=NSCocoaErrorDomain code=4099
Native Zeus validation -> UNKNOWN: timeout
Native Hermes2025 validation -> UNKNOWN: timeout
```

**Verdict: no completed validator RPC**, neither ALLOW nor DENY for Hermès.
`NSCocoaErrorDomain Code=4099` is an invalidated XPC connection.
The app had used the runtime `initWithServiceName:` initializer, which
usually names a bundle-scoped XPC service, not necessarily a global
`launchd` Mach service. Therefore T2's valid bootstrap Mach send right
was NOT evidence the chosen XPC transport was correct.

**T7-v1 design flaw:** the proxy transport error callback saved a message
but did not signal the semaphore used for each individual RPC; the app
then waited three 5-second periods and emitted misleading per-face
timeouts.

**Actual patch** in `BQClockKitReadonlyValidation.m`:
- Replace `initWithServiceName:` with a checked runtime call to
  `initWithMachServiceName:options:` using options 0, distinct from
  privileged namespace. Neither API confers server entitlement.
- Proxy error handler now calls the same completion gate as the validator
  reply and includes `localizedDescription`, `NSDebugDescription`
  and original domain/code. No unnecessary 5-second wait on 4099.
- A transport error or missing response to the deliberately invalid
  control causes the real Zeus and Hermès checks to be **SKIPPED**.
  This prevents labeling a disconnected transport as face rejection.
- The method still supports only
  `validateFaceType:faceBundleId:completionHandler:`; it never
  imports or adds a face or writes a protected cache.

[Source contract #44272030508](https://github.com/mkalter/TESTAPP/actions/runs/44272030508)
**SUCCESS**. [Unsigned iPhone + Watch build #44271968893](https://github.com/mkalter/TESTAPP/actions/runs/44271968893)
**SUCCESS**, artifact `unsigned-iphone-watch-ipa` ID `14412737902`.
**Physical T7-v2 is NOT yet run**. One only needs to repeat optional T7,
not T1–T6.

Apple documentation distinguishes [service-name initializer](https://developer.apple.com/documentation/foundation/nsxpcconnection/init%28servicename%3A%29)
from [Mach-service initializer](https://developer.apple.com/documentation/foundation/nsxpcconnection/init%28machservicename%3Aoptions%3A%29).
A successful Mach connection still doesn't prove the *server* accepts
ordinary Watch-app clients.

### Next offline check

The new original ClockKit dyld image trace in
[run #44272362451](https://github.com/mkalter/TESTAPP/actions/runs/44272362451)
will attempt SHA-pinned Objective-C IMP recovery from the exact
`225c004e9a2288799cdad99228076a7b7761befb8686c48407f3f8d0dec59dad`
original Watch ClockKit and trace the actual method
`_queue_setupConnectionIfNeeded`. This can distinguish the shipped
watchOS client initializer from our hypothesis without touching the Watch.


## Exact 23U95 ClockKit direct-selector ABI and fallback evidence

The SHA-pinned real ClockKit method list header at `0x49c9c0c0`
is **`0xc000000f`**, with 4 method entries.
As confirmed by Apple's ObjC runtime relative selector format, this sets:
- `0x80000000`: small/relative 12-byte method entries;
- `0x40000000`: **direct selectors**, not ordinary indirect selector
  references. The bottom value `0x0f` gives a stride of 12 after
  clearing 2 flag bits.

[Source diagnostics #44273180201](https://github.com/mkalter/TESTAPP/actions/runs/44273180201)
independently reported:
- first method's type offset resolves to `__objc_methtype`;
- its IMP resolves to original `__text` at `0x49c97d74`;
- but the name offset calculated as self-relative points to
  `__objc_methlist`, not `__objc_methname` (e.g.
  `name_vm=0x49c9c487`);
- next list's name VM `0x4a94c80d` is outside the extracted image.

This is **exact evidence that the earlier pre-dyld small-list decoder
cannot treat those optimized name offsets as in-image
`__objc_selrefs`**. It is a binary layout limitation, not evidence
that the watchOS ClockKit methods are absent.

An independent [LC_SYMTAB code-address audit #44273680584](https://github.com/mkalter/TESTAPP/actions/runs/44273680584)
was launched to recover `CLKWatchFaceLibraryServer
_queue_setupConnectionIfNeeded` from symbol names in the original
unmodified Mach-O where possible. It stays offline, SHA-guarded,
and records explicit symbol-count limitations instead of claiming
a bypass. No on-watch test repeats are necessary for this parser work.


## Breakthrough: exact Watch6,18 first-party ClockKit connection option

[Original ARM64_32 Mach-O symbol+disassembly run #44273680584](https://github.com/mkalter/TESTAPP/actions/runs/44273680584)
**SUCCESS**, source ClockKit SHA verified
`225c004e9a2288799cdad99228076a7b7761befb8686c48407f3f8d0dec59dad`.

Independent original `LC_SYMTAB` parsing found **8,478 valid symbols**,
**26 face-library-related original functions and actual IMPs** despite
unsupported dyld direct selectors in the original method-list parser.
It identified exact original implementation:

`-[CLKWatchFaceLibraryServer _queue_setupConnectionIfNeeded]`
at `0x49c64340`.

Verified relevant original ARM64 instructions:

```asm
0x49c64360 adrp x8, #0x71273000
0x49c64364 ldr  w0, [x8, #0xa38]  ; class-ptr setup
0x49c6436c adrp x8, #0x7416d000
0x49c64370 add  x8, x8, #0xf7c
0x49c64374 ldr  w2, [x8]          ; Apple ClockKit name
0x49c64378 mov  w3, #0x1000       ; NSXPCConnectionPrivileged bit
0x49c6437c bl   #0x49cccb20      ; ObjC client initializer stub
```

This directly proves that the original ClockKit watchOS setup passes
**a fourth argument of 0x1000 to an ObjC initializer**, consistent with
`initWithMachServiceName:options:` and
`NSXPCConnectionPrivileged`. The exact symbol name of the BL target
is separately being checked in [symbol-matching #44274797889](https://github.com/mkalter/TESTAPP/actions/runs/44274797889).
Do not overstate the selector identification before that check.

This exposes a more specific mismatch than T7-v1: the previously
built T7-v2 used Mach-service initialization with **options=0**,
where the genuine Apple Watch original uses **0x1000**. Corrected
T7-v3 now uses `initWithMachServiceName:options:` with option
`(NSUInteger)0x1000`, and logs that this selects launchd's
privileged namespace. The flag **does not grant entitlements** or
bypass server-side client auditing or face eligibility.

[Source contract run #44274693095](https://github.com/mkalter/TESTAPP/actions/runs/44274693095)
**SUCCESS**. [IPA CI #44274658480](https://github.com/mkalter/TESTAPP/actions/runs/44274658480)
started, with conclusion checked separately before providing an IPA.
Only T7 needs to be rerun on physical Watch after successful code signing;
T1–T6 remain unchanged. No proof of native Hermès unlock.
