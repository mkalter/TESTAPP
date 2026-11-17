# watchOS 26.6.1 (23U95) — native face-library XPC and sandbox evidence

**Scope:** Apple Watch Ultra 1 / `Watch6,18`, native ClockFace/Carousel system gallery. This is a read-only comparison of exact Apple firmware, not a jailbreak, watchface install, or authorized XPC client test.

## 1. Correctly attributed listener class implementations

Original `nanotimekitd` SHA-256 `103d9ed37894bac21ff30074ab9eaea8ed0f2932245b90dc67323ad914c026a6`. The verified ARM64_32 Objective-C relative method lists and owning class metadata were extracted by [GitHub run #44129661345](https://github.com/mkalter/TESTAPP/actions/runs/44129661345), artifact `watchos23u95-native-face-library-daemon-control-flow`.

| Selector `listener:shouldAcceptNewConnection:` | Original IMP VM | Owning class |
| --- | --- | --- |
| Instance | `0x1113C` | `NTKDCollectionCoordinator` |
| Instance | `0x2A7D4` | `NTKDSyncController` |
| Instance | `0x315C8` | `NTKDFaceSnapshotCoordinator` |
| Instance | `0x44218` | `NTKDComplicationStoreCoordinator` |
| Instance | `0x45D54` | `NTKDDiagnosticExtentionHelper` |

For all five original methods the disassembled exit path returns the Objective-C boolean `YES`. In particular `NTKDSyncController` at `0x2A840` executes `mov w0,#1` and then `ret` at `0x2A850` after invoking a block that configures the connection.

**CRITICAL distinction:** returning YES is not proof that any arbitrary third-party watch app can connect. The caller must first satisfy launchd bootstrap namespace and the caller's effective `mach-lookup` sandbox rules; code inside the configured exported protocol or helper may enforce more restrictions. This analysis establishes only listener-level behavior.

## 2. New exact original watchOS sandbox-policy evidence

Original Watch6,18/23U95 kernelcache SHA-256 `ced56594d646bc39261c7f6d4cce8554accc9fd16cce6ec4aa70ad3d98f56261`. Decompiled `container.sb` and `baseline.sb` available in [GitHub Actions #44090713056](https://github.com/mkalter/TESTAPP/actions/runs/44090713056), artifact `real-watchos-23u95-sandbox-research`.

The `container.sb` general `(allow mach-lookup (require-any ...))` global-name allowlist near lines 10680–10900 explicitly includes:

- `com.apple.ClockKit.CLKWatchFaceLibrary`;
- `com.apple.NanoTimeKit.complication`.

It does **not** contain text matches for the proposed native library-broker and paired-sync service names:

- `com.apple.nanofacegallery.librarybroker.server`;
- `com.apple.nanotimekit.replication.library.listener`.

The same general allow rule also covers explicitly scoped extensions `com.apple.sandbox.application-group` and `com.apple.security.exception.mach-lookup.global-name` / `.local-name`. An AppGroup file access extension is **not** automatically authorization to look up an unrelated privileged Apple Mach service. A developer-signed app is not entitled to arbitrary `com.apple.security.exception.mach-lookup.*` grants.

**Bounded implication:** the original policy provides no evidence that HermesEnabler can directly connect to the native face library broker or library replication listener. The absence of a name in the broad allowlist is not a final effective-sandbox evaluation: conditional rules, inherited profiles, launchd service delegation, role-specific entitlements or audit-token checks still require analysis. Do not claim a confirmed `mach-lookup` denial without observing the process's *effective* sandbox or a physical Watch connection failure.

## 3. Why a direct library-store write is not the same as native eligibility

The store owner `NTKDCollectionStore` provides `_queue_addFace:forUUID:` and `_resetWithFaces:orderedUUIDs:selectedUUID:`, verified via Objective-C class-owner mapping. `NTKDSyncController` contains `_queue_validateLibraryFaces`, which dispatches an internal block at exact code address `0x2E100`. The native-store reset code dispatches its internal block at `0x3E0C4`.

These two internal blocks were added to the hash-guarded bounded disassembly workflow in commit `6e653107b39378bd0b68a715cfb1093acbd7faad`. [GitHub run #44134177637](https://github.com/mkalter/TESTAPP/actions/runs/44134177637) successfully disassembled the original blocks, showing the actual `0x2E100` validation callback and `0x3E0C4` store reset operations. A subsequent run decodes the direct imported Objective-C selectors to avoid inventing their semantics.

Separately, `_removeUnavailableFacesFromStore:` uses `_NTKFaceStyleIsAvailable` on a stored face's **style**, not a direct call to `NTKPoodleFace.isRestrictedForDevice:` at that callsite. Therefore a style-44 record *might* survive that one purge even while its native Poodle FaceBundle still fails independent availability/lookup/renderer checks.

## Status and release criterion

The only genuine goal is the stock watchOS **original native Hermès face in Apple's Carousel and Face Gallery** after quitting HermesEnabler and rebooting the Watch. No present result meets it.

No `bad_query` Class7/Class13 access to an authoritative native gallery store and no MobileGestalt write has been established. Treat any `NSXPCConnection` or sandbox query result as a *diagnostic* until an exact authorized client/server contract and actual device-state change are demonstrated.
