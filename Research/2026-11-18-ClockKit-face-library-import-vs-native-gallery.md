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


## CONFIRMED: exact original XPC initializer selector and 0x1000 option

[Independent original symbol cross-reference #44274797889](https://github.com/mkalter/TESTAPP/actions/runs/44274797889)
**SUCCESS**; original ClockKit SHA matched exactly
`225c004e9a2288799cdad99228076a7b7761befb8686c48407f3f8d0dec59dad`.

The call at `0x49c6437c` resolves **not by guess but by the original
Mach-O `LC_SYMTAB` binding at `0x49cccb20`** to:

```
_objc_msgSend$initWithMachServiceName:options:
```

Paired with `mov w3,#0x1000` immediately preceding that call at
`0x49c64378`, this now **proves the genuine first-party Watch6,18
ClockKit client uses the privileged launchd Mach namespace option**.
The same original source function calls:
- `_CLKWatchFaceLibraryServerInterface` at `0x49c64390`;
- `setRemoteObjectInterface:` at `0x49c643a8`;
- `setInterruptionHandler:` at `0x49c64408`;
- `setInvalidationHandler:` at `0x49c64418`;
- `resume` at `0x49c64420`.

The genuine first-party read-only validator forwarding function
`-[CLKWatchFaceLibraryServer validateFaceType:faceBundleId:completionHandler:]`
at `0x49c64604` invokes:
```
0x49c64638 _objc_msgSend$_queue_setupConnectionIfNeeded
0x49c64680 _objc_msgSend$synchronousRemoteObjectProxyWithErrorHandler:
0x49c6469c _objc_msgSend$validateFaceType:faceBundleId:completionHandler:
```

Likewise, the original file importer invokes the separate
`openWatchFaceURLWithSecurityScopedURL:sourceApplicationBundleIdentifier:completionHandler:`
selector. These are distinct service operations; **the original
ClockKit client still exposes no verified arbitrary native Hermès
FaceBundle library writer**.

The current T7-v3 developer app intentionally connects with a
read-only subset of the validator interface and matches Apple's
`initWithMachServiceName:options:` plus `0x1000`, but this
**does not supply the original client signing identity, entitlement,
server authorization or native face eligibility**. Its only meaningful
next physical result is a real validator reply or a more specific
XPC error; native gallery persistence remains unproven.


## Physical T7-v3 result — first real ClockKit validator replies (18 Nov 09:27:05 UTC)

**Actual user-provided Watch6,18 / watchOS 26.6.1 (23U95) log:**

- Apple protocol available; style `44` string resolves to `bundle`, original Zeus `com.apple.NTKZeusFaceBundle`, Hermès2025 `com.apple.Hermes2025Face`, both actual signed Apple FaceBundles.
- Using **exact** original `initWithMachServiceName:options:` and `options=0x1000`, the ordinary development-signed app successfully receives **three ClockKit server RPC completions** (no 4099, no timeout).
- Intentionally nonexistent type control: `CLKWatchFaceLibraryErrorDomain code=4`.
- `type=bundle`, Zeus `com.apple.NTKZeusFaceBundle`: same domain/code=4.
- `type=bundle`, Hermès2025 `com.apple.Hermes2025Face`: same domain/code=4.
- No file opened/imported, no native library add/reset or cache write.

**Official Apple ClockKit error enum:** `CLKWatchFaceLibraryErrorCodeFaceNotAvailable = 4` (different from `InvalidFile=2` and `PermissionDenied=3`). Direct SDK header:
https://github.com/xybp888/iOS-SDKs/blob/4a48e5409f8ea6ac422c44d91b86fa0f8ae010ff/iPhoneOS26.4.sdk/System/Library/Frameworks/ClockKit.framework/Headers/CLKWatchFaceLibrary.h

**Interpretation:** genuine XPC authentication and method dispatch are now established
for the *read-only* validator. Both original Hermès FaceBundle identifiers
receive Apple's `FaceNotAvailable` answer in current device context, but the
deliberately nonexistent control gets the same error, so this observation
alone cannot distinguish an actual model restriction from a blanket
availability failure in the service's device context or a generic unmapped
validation error. A **known-good compatible first-party face** is needed
as positive control; this must be selected from actual on-device
style/FaceBundle availability metadata, not from an invented bundle ID.

**iOS 26.1 public reverse-engineered utility semantics, not yet verified
exact Watch binary**:
`+[NTKGreenfieldUtilities validateFaceType:faceBundleId:]` converts face-type
text to a style, constructs `NTKFaceDescriptor initWithFaceStyle:` for
non-44 styles, and `initWithBundleIdentifier:` for style 44, then calls
`isAvailableForDevice:[CLKDevice currentDevice]`. For style 44,
`-[NTKFaceDescriptor isAvailableForDevice:]` returns whether
`[NTKFaceBundleManager sharedManager]
faceBundleForBundleIdentifier:... onDevice:...` is non-nil;
it does **not** merely test whether a bundle directory exists.
See https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/90aa0cfe59d9682b4265e1354c8b19ec3c7823ab/System/Library/PrivateFrameworks/NanoTimeKit.framework/NanoTimeKit/NTKFaceDescriptor.mm
and the actual Greenfield decomp source.

**Next discriminator:** independently confirm these exact method implementations
in Apple's original Watch6,18 23U95 NanoTimeKit shared-cache image and add
a single bounded read-only positive control chosen from actual
available native non-bundle styles. Avoid a blind array of unknown
FaceBundle bundle IDs or any mutating API.


## The ACTUAL 23U95 NanoTimeKit authorization path, now independently recovered

[Original Watch6,18 Apple NanoTimeKit dyld disassembly #44277250878](https://github.com/mkalter/TESTAPP/actions/runs/44277250878)
**SUCCESS**. Original arm64_32 NanoTimeKit SHA256:
`e77ccd6c26b7413b2fba543207d9c20f5c33e97faaa2e5801050194f25b87d63`.
The original `LC_SYMTAB` parsed **51,803 symbols** and recovered
6 targeted implementations with real original code addresses and named calls.

1. `+[NTKGreenfieldUtilities validateFaceType:faceBundleId:]`
   at **0x543EAD88**:
   calls `_NTKFaceBundleGetFaceStyleFromString` at `0x543EADB8`;
   branches on parsed style==44; invokes
   `initWithBundleIdentifier:` at `0x543EADE4` for style44
   and `initWithFaceStyle:` at `0x543EAE04` for nonbundled styles;
   obtains `CLKDevice currentDevice` at `0x543EAE14`;
   calls `isAvailableForDevice:` at `0x543EAE2C` and,
   if that returned true, again at `0x543EAE3C`.
   A false result falls through returning false.
2. `-[NTKFaceDescriptor isAvailableForDevice:]`
   at **0x543D998C**:
   for style44 (branch `cmp w0,#0x2c` at `0x543D99B0`),
   obtains bundle identifier and `NTKFaceBundleManager sharedManager`,
   calls `faceBundleForBundleIdentifier:onDevice:` at `0x543D99EC`,
   then sets boolean from **non-null returned face bundle** at
   `0x543D9A00`/ `0x543D9A04`.
   For other face styles calls `_NTKFaceStyleIsAvailable` directly
   at `0x543D9A18`.
3. `-[NTKFaceBundleManager faceBundleForBundleIdentifier:onDevice:]`
   at **0x544B0DD4** delegates to its variant with `forMigration:`
   at **0x544B0DDC**, which loads the original signed bundle,
   examines the face class, legacy style and device/pairing identity,
   and invokes **`isRestrictedForDevice:` at 0x544B0F94**.
4. `_NTKFaceStyleIsAvailable` at **0x544392B0**
   consults hardware/device-category and collection properties,
   hardware/internal faces flags, other model capabilities and
   `isFaceStyleAvailableInternal:forDevice:`.

This code matches the major iOS behavior deduced previously, but now it is
**proved from the exact original Watch6,18/23U95 executable**, not analogy.

The visible `NTKFaceBundleManager` path asks a face class about
`isRestrictedForDevice:`. The original Hermès Poodle class previously
returned restricted for actual Ultra 1 properties. Hence adding or
copying `NTKZeusFaceBundle.bundle` alone is not sufficient; the
manager's device gate is involved.

**Practical T8 validation plan**: use a *locally available* non-bundle
style as positive control, derived from that same original
`NTKFaceDescriptor isAvailableForDevice:` function and actual
`CLKDevice currentDevice`. The subsequent XPC validator uses precisely
the matching Greenfield logic. T8 independently logs Hermès descriptors'
local availability before comparing their read-only XPC results.

The T8 source was corrected to load NanoTimeKit before resolving
private Objective-C class names, avoiding false missing-class
diagnostics. This is not a proof of remote device identity spoofing,
a path to arbitrary MobileGestalt writes or native Hermès insertion.


## New differential: forMigration bypasses one specific FaceBundle restriction check

The genuine original Watch6,18/23U95 `NanoTimeKit` implementation
of `-[NTKFaceBundleManager faceBundleForBundleIdentifier:onDevice:forMigration:]`
is at **0x544B0DDC** in the same SHA-256-verified dyld image
`e77ccd6c26b7413b2fba543207d9c20f5c33e97faaa2e5801050194f25b87d63`.
Its exact verified instruction sequence includes:

```asm
0x544B0DF8 mov  x22, x4              ; fourth explicit method arg (forMigration)
...
0x544B0F88 tbnz w22, #0, 0x544B0FA4 ; forMigration=true skips regular restriction query
0x544B0F8C mov  x0, x23              ; original signed bundle's faceClass
0x544B0F90 mov  x2, x20              ; target device
0x544B0F94 bl   0x548CE500          ; _objc_msgSend$isRestrictedForDevice:
0x544B0F98 cbz  w0, 0x544B0FA4
0x544B0F9C bl   0x55CE73DC          ; additional conditional gate
0x544B0FA0 tbz  w0, #0, 0x544B0FF0 ; reject/alternate path; not fully reconstructed
0x544B0FA4 ...                      ; shared retain/return path
```

**Narrow, verified inference:** Apple's *migration-specific bundle lookup*
skips the regular `isRestrictedForDevice:` call if `forMigration` is
truthy. This is an explicit in-firmware distinction and a **new research
lead** for how previously paired/recorded faces may survive migration.
It is NOT evidence that a third-party process can supply migration flags
to the authorized system daemon, or that native Hermès can be added to
the Carousel or rendered. The **normal** validation path
`NTKGreenfieldUtilities.validateFaceType` creates
`NTKFaceDescriptor`, whose style44 case calls only
`faceBundleForBundleIdentifier:onDevice:` (no migration flag), so normal
ClockKit `FaceNotAvailable=4` is fully consistent with this distinction.

Original native daemon:
[Verified `nanotimekitd` control-flow #44127029726](https://github.com/mkalter/TESTAPP/actions/runs/44127029726)
maps `_migrateBundleFacesInStore:` at `0x21D74` and
`_fromSyncResetWithFaces:orderedUUIDs:selectedUUID:` at `0x3E704`.
`_migrateBundleFacesInStore:` performs internal reconciliation on the
daemon's own store and calls `setOrderedUUIDs:` /
`synchronize` on a successful migration condition. Those operations
**must not** be called speculatively on the user's paired Watch:
they modify the native face library and could cause unwanted state loss.
The actual accepted XPC client protocol, collection mutation authority
and whether Apple gallery passes additional eligibility remain unknown.

The next safe check is therefore to audit how Apple's trusted migration
code passes `forMigration` to the bundle manager and what validates the
**incoming native face collection records**. Read-only physical T8 already
provides current ordinary-vs-Hermès availability without mutating anything.


## Physical T8 selective face rejection PROVEN and new in-process T9 probe (18 November)

**T8 live original Watch6,18/23U95 09:50:24 UTC**:
- The on-watch `NTKFaceDescriptor` and `CLKDevice` actually loaded and
  returned `utility` style 0 as locally available.
- The real first-party ClockKit server validated that actual standard
  Apple face via `initWithMachServiceName:options: (0x1000)`:
  **REPLY success**.
- Both original signed Hermès IDs `com.apple.NTKZeusFaceBundle` and
  `com.apple.Hermes2025Face` returned
  `CLKWatchFaceLibraryErrorDomain code=4 FaceNotAvailable`;
  their local descriptors independently returned
  **NOT AVAILABLE**. Thus this is a genuinely **selective**
  FaceBundle/device-availability gate, not a broken universal RPC
  validator. The exact per-face rejection branch beyond the
  manager lookup remains under investigation.

**T9** now added in
`HermesEnabler2/BQClockKitReadonlyValidation.m` as a separate opt-in
`Native Face Lab → T9 · Migratie-lookup`.
The method `BQRunClockKitMigrationLookupDifferential` performs only
in-process Apple NanoTimeKit
`faceBundleForBundleIdentifier:onDevice:forMigration:` lookups
`NO → YES → NO` on *actual original on-device bundle IDs*.
It records nil/non-nil, original `faceClass` and
`isRestrictedForDevice:`. It neither imports a `.watchface` nor
asks the native Carousel daemon to add/reset anything.
The bundled loader may populate a transient NSDictionary cache in the
Watch app process but no persistent gallery write is invoked.
T9 has **no physical result yet**.

### Full JSON migration consumer from exact original Watch6,18 firmware

[SHA-checked original NanoTimeKit firmware run #44280447358](https://github.com/mkalter/TESTAPP/actions/runs/44280447358)
**SUCCESS**, original SHA `e77ccd6c26b7413b2fba543207d9c20f5c33e97faaa2e5801050194f25b87d63`.
**51,803 symbols; 16 target symbol names; 14 verified code functions**.
The original
`+[NTKFace faceWithJSONObjectRepresentation:forDevice:forMigration:allowFallbackFromInvalidFaceStyle:]`
was mapped to **0x54477BD8**, and directly calls the original selector
`faceBundleForBundleIdentifier:onDevice:forMigration:` at PC
**0x54477FE4**, followed by original `faceClass` at
**0x54477FFC**. The same JSON constructor also invokes
`_applyConfiguration:allowFailure:forMigration:` at
**0x544781E8**. Thus `forMigration` is a real alternative
inside Apple's normal JSON face object reconstruction, not only a
dormant `NTKFaceBundleManager` method. The consumer does **not**
thereby imply that untrusted XPC clients may request a true migration
or persist native FaceStore records. The earlier verified normal
`NTKFaceDescriptor` and ClockKit validators still use the regular
`forMigration=NO` route.

These findings clarify a genuine *read-only diagnostic opportunity*
(T9), but are not a tested original Hermès face activation, nor a
protected cache write or authorized system gallery state change.
