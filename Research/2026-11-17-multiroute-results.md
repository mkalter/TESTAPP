# 17 November 2026 — Three independently executed research tracks

Device target: Apple Watch Ultra 1 / Watch6,18 / watchOS 26.6.1 (23U95).
**Actual native Hermès system face unlocked: NO.** No new on-watch result from this run.

## A. Functional Apple import paths (testable iPhone app)

Branch: `experiment/hermes-23u95-multiroute-evidence-20261117`.
Build: https://github.com/mkalter/TESTAPP/actions/runs/44151360048
Unsigned iPhone+Watch artifact `14358782701`, success.

The rebuilt companion contains:
- public `CLKWatchFaceLibrary.addWatchFace(at:completionHandler:)`;
- private `_addWatchFaceAtURL:shouldValidate:completionHandler:`, **only** if runtime method and argument ABI match;
- a generated diagnostic ZIP referencing native `NTKPoodleFaceBundle`, `forMigration=true` (this is a *hypothesis*, not a validated Apple face);
- separate persisted import evidence under the companion's own `Documents/NativeFaceEvidence/`; source filename, mode, clock, iOS version, SHA-256 and exact NSError domain/code; shareable after relaunch.

**Caveats:** This does not call the Watch's privileged face-store methods. It only exercises the client-side versus server-side ClockKit import path. A ZIP with valid CRC is not proof of valid face data. Source evidence that the private selector survives into an iOS 27.0 beta dyld symbol diff does not verify the method ABI/behavior on a specific iOS 27.3 phone:
https://github.com/blacktop/ipsw-diffs/blob/main/iOS/26_5_23F77_vs_27_0_24A5355q/DYLIBS/System/Library/Frameworks/ClockKit.framework/ClockKit.md

## B. Exact original nanotimekitd call analysis

Branch: `research/23u95-face-library-daemon-auth-20261117`.
Run: https://github.com/mkalter/TESTAPP/actions/runs/44152819900 (success).
Artifact: `watchos23u95-native-face-library-daemon-control-flow`, with `native-callgraph-authorization.json` and `.txt`.

Exact original source SHA-256: `103d9ed37894bac21ff30074ab9eaea8ed0f2932245b90dc67323ad914c026a6`.

A previous output had used too wide a decoding window and wrongly attributed nearby instructions to each listener. The source was corrected to stop after the first return and rerun against the SHA-verified original. This correctly limits its conclusions to bounded direct branches, **not** all possible alternate control flow or IPC authorization.

Observed:
- `NTKDSyncController listener:shouldAcceptNewConnection:` has an early `_onQueue_async:` dispatch and returns YES. That is not a caller-entitlement check and does **not** grant third-party Mach lookup.
- `NTKDDiagnosticExtentionHelper` configures `setExportedInterface:` / `setExportedObject:`; this is its own interface setup, not authorization for Apple face-library mutations.
- `_removeUnavailableFacesFromStore:` calls `_NTKFaceStyleIsAvailable` and `removeFaceForUUID:` in its actual loop. Distinct per-FaceBundle restrictions remain at other stages.

No client-authorized original Hermès face insertion proven. Do not confuse `NSXPCListener` accepting a connection with sandbox service reachability or remote method permission.

## C. Exact original MobileGestaltHelper ABI

Branch: `research/23u95-mobilegestalt-helper-abi-audit-20261117`.
Run: https://github.com/mkalter/TESTAPP/actions/runs/44152443271 (success).
Artifact: `watchos-23u95-userland-authority-audit`, files `mgh-abi-report.json` and `mgh-abi-report.txt`.

Original helper SHA-256: `0e0c05244a3d35753e948783372f18e615ae2032cf7b750dd7a9cc57cfb3626e`.

The current exact selector-implementation scan verified:
- `listener:shouldAcceptNewConnection:`, IMP `0x4bbc`;
- `rebuildCache:`, IMP `0x55f0`;
- `setCacheSentinel:`, IMP `0x5714`.

No client-supplied arbitrary DeviceBrand/key-value setter was demonstrated in this specific examined Objective-C method set. This is not a proof that no other dynamic IPC functionality exists or that no other trusted component can write protected MG content.

## Device verification needed before declaring a success

1. Verify basic public import with a known-good original *non-Hermès* exported watchface.
2. Compare public versus private import using the **same** authentic Hermès `.watchface`, with matching SHA-256 and distinct saved reports. Do not conclude anything from a failed synthetic ZIP alone.
3. Confirm result on the original native Apple Watch Carousel with the test app closed and, if a candidate appears, after reboot.
4. Treat earlier protected MG `open(O_RDWR) -> EPERM` and Class7/13 negative evidence as unchanged. A failed random-flag variant is not a new exploit.
5. No automatic native library reset, protected file patch, respring or signature-forgery operation was executed here.

**Conclusion:** improved testability and genuine original-binary analysis of three separate mechanisms; zero confirmed protected writes, system-face additions or Hermès activation.
