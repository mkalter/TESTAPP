# Native Hermès system faces on Ultra 1 / watchOS 26.6.1 — alternate writable-store and authorization audit

**Investigated 2026-11-17 | Target Watch6,18 / 23U95 | Scope: Apple native ClockFace/Carousel face gallery; NOT app-local FaceViews and NOT user-created .watchface ZIPs.**

## Experimental provenance

- Genuine Apple 23U95 full IPSW from `https://updates.cdn-apple.com/2026FallFCS/fullrestores/140-55248/8E7A8791-70C2-4E38-A107-EB6665AE3BCA/Watch6%2C18_26.6.1_23U95_Restore.ipsw`.
- Native-face binary extraction + bounded independent Capstone disassembly: [GitHub Actions #44111373781](https://github.com/mkalter/TESTAPP/actions/runs/44111373781); artifact `exact-23u95-native-face-policy-and-store-audit`.
- Kernel sandbox profile extraction: [GitHub Actions #44090713056](https://github.com/mkalter/TESTAPP/actions/runs/44090713056), originals `baseline.sb`, `containermanagerd.sb`, `cfprefsd.sb`. Decompiled from original Watch6,18/23U95 kernelcache SHA-256 `ced56594d646bc39261c7f6d4cce8554accc9fd16cce6ec4aa70ad3d98f56261`.
- Exact three checked FaceBundle executable hashes (all original ARM64_32 Mach-O):
  - `NTKZeusFaceBundle`: 663,040 bytes; SHA256 `2b34d3d411b77ee73f3892638f419eda83b7bedc4653ecf44adf7c975bbd72e4`.
  - `NTKHermes2025FaceBundle`: 1,184,176 bytes; SHA256 `ca8f29bd478483d5bfcd6a30cae9f324a37e2655e0515a27929596df4dc9af49`.
  - `ClockFace.app/ClockFace`: 405,520 bytes; metadata included in the artifact.
- The `NanoTimeKit.framework/NanoTimeKit` main binary **was not found at the expected path in this full IPSW extraction**. Exact NanoTimeKit gallery-manager disassembly below is grounded in the separately independently extracted **same build** OTA binary by [ZhuoXuan-MY](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V17-FaceBundle-Loading-Chain.md), SHA256 `bf3f7e360fe06ab7e513807bcb3b6ac695f38c6ea8cd8428b7aed579c2b58e1c`. Do not describe this part as our independently re-extracted binary.

## A. Native face visibility and addability are distinct, multi-stage decisions

1. **The signed native face implementation exists** on Watch6,18 / 23U95: `NTKZeusFaceBundle` contains original Poodle/Circulaire, Hades and Bellona class code. `NTKHermes2025FaceBundle` is also present.
2. **Gallery construction**: `NTKFaceBundleManager.enumerateFaceBundlesOnDevice:includingLegacy:withBlock:` calls `faceClass isRestrictedForDevice:` and skips restricted faces. `NTKGalleryCollection` can *additionally* exclude hardware-specific bundles. Having a valid bundle file or archive does not change the class return value.
3. **Lookup**: `faceBundleForBundleIdentifier:onDevice:forMigration:` rechecks class restriction in normal mode, and returns no bundle if restricted. Migration or a special snapshot-service predicate can bypass this one lookup check, but those contexts do **not** grant ordinary gallery listing or permission to add.
4. **Library addition**: exact 23U95 `_NTKCanAddWatchFace` separately checks `isValidConfigurationToAddToLibrary`, `NTKFaceDescriptor isAvailableForDevice:`, face-class restrictions, and more.
5. **Persistence**: successful export, a created face object, an import callback and the watch's real Carousel library are four different checkpoints. A native face needs to be present in the Apple Watch face switcher **with the app closed**.

Thus writing an arbitrary *gallery list*, *snapshot*, *ZIP package*, *FaceSupport asset*, or *complication store* is insufficient evidence of a true unlock.

## B. Exact original 23U95 Hermès face-class restrictions now independently verified

The matching `NTKZeusFaceBundle` SHA256 guard passed and its original `NTKPoodleFace isRestrictedForDevice:` at **0x13B4** disassembled successfully. The branch includes:

```text
0x13D0 cmp w0,#1       (reject category 1)
0x13E4 bl 0x469C0      (supportsPDRCapability: 0xD5DDA3E7)
0x13F4 cmp w0,#5       (collectionType 5 is accepted)
0x141C bl 0x340AC      (NTKShowHardwareSpecificFaces)
0x1420 eor w20,w0,#1   (restricted = !hardware-specific flag)
```

The actual live Watch6,18 data was `deviceCategory=4`, `collectionType=9`, `NTKShowHardwareSpecificFaces=false`. Prior exact Watch6,18 matching `ClockKit` static instruction check established that `-[CLKDevice supportsPDRCapability:]` returns true on 23U95. Consequently the Poodle face restriction independently evaluates **true** for this Ultra 1, even ignoring extra gallery and add checks.

The same SHA-guarded disassembly verifies:
- **Hades**: immediately rejects `deviceCategory=4` at **0x1328/0x132C**, regardless of later preference or collection settings.
- **Bellona**: separately checks category, other comparisons, PDR capability and `collectionType=5`, falling back to `NTKShowHardwareSpecificFaces`. No demonstrated acceptance for this Ultra1.
- **Hermès 2025**: the genuine `NTKHermes2025FaceBundle` original `isRestrictedForDevice:` at **0x3B2C** delegates to the helper at **0x46B8**. Both addresses were independently disassembled from the same hash-verified 23U95 Mach-O in [run #44112313325](https://github.com/mkalter/TESTAPP/actions/runs/44112313325). The helper checks additional conditions and explicitly compares a **device-derived return value to `5` at 0x4744**. It calls other still-unresolved functions and branches on their results, so **the precise Hermès 2025 authorization formula is NOT fully reconstructed from this disassembly**. A successful or failed comparison against 5 alone is not proof of an allowlist or device acceptance.

This is original signed Apple code; editing a JSON plist or feature preference does not patch these functions.

## C. Other files/containers potentially touched by bad_query: strict authorization map

Compiled actual Watch6,18/23U95 `containermanagerd` profile:

```scheme
(allow file-issue-extension
  (require-all
    (extension-class "com.apple.sandbox.application-group")
    (subpath "${ANY_USER_HOME}/Containers/Shared/AppGroup")))
(allow file-issue-extension
  (require-all
    (extension-class "com.apple.sandbox.system-group")
    (subpath "/private/var/containers/Shared/SystemGroup")))
(allow file-issue-extension
  (require-all
    (extension-class "com.apple.app-sandbox.read-write")
    (require-any
      (subpath "/private/var/mobile/Containers/Data/Application")
      (subpath "/private/var/mobile/Containers/Data/InternalDaemon")
      (subpath "/private/var/mobile/Containers/Data/PluginKitPlugin"))))
```

This is a deliberately **condensed display** of the issuer allow rules. It omits other permitted temporary/persona paths; the full decompiled profile is the authoritative source. The strings alone do not adjudicate all underlying client permissions.

| Candidate | Role in watchOS | Relationship to these permissions | Would writing it by itself unlock true Hermès? |
| --- | --- | --- | --- |
| `/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist` | Persistent DeviceBrand cache | Class 13 group token received but live `O_RDWR` returns `EPERM`; private `com.apple.security.system-groups` / `com.apple.security.system-group-containers` receiver entitlement absent | Relevant identity change, but not writable by demonstrated class13 strategy |
| `/private/var/mobile/Library/Preferences/com.apple.NanoTimeKit.face.plist` (candidate path, NOT independently located on Watch) | Potential preference storage for `com.apple.NanoTimeKit.face`, including `ShowInternalFaces` | Neither `com.apple.app-sandbox.read-write` issuer rule nor Class 13 SystemGroup issuer covers the global user preference directory. Actual per-domain cfprefsd policy is separately enforced; not verified | **No**: normal FaceBundleManager filters restricted bundles *before* an `NTKGalleryCollection` direct `ShowInternalFaces` setting |
| `/private/var/mobile/Library/NanoTimeKit/FaceSupport/` (conceptual `BSCurrentUserDirectory()/Library/NanoTimeKit/FaceSupport`) | Asset/extraction storage and date database | No authorized Class7/Class13 write to this particular directory established. Original `baseline.sb` lines ~706/1416/3669 include Apple-private NanoTimeKit Argon/FaceSupport entitlement names in read/map/metadata exception branches enabled by `common-debugging-rules`; this must **not** be generalized into ordinary app read/write authority | **No**, as a class-level restriction is still evaluated |
| `/System/Library/NanoTimeKit/FaceBundles/` | Apple's original signed native implementation bundles | Protected OS filesystem; not in class7 AppGroup or class13 systemgroup issuers; no demonstrated write | Replacing an Apple-signed executable is a separate code-signing/system-integrity problem |
| ClockFace / NanoTimeKit face collection persistence | Own native face records | Exact live root path and effective access policy **not** independently established by this run. User-container UUID and persisted global face collections need separate identification | Not automatically: system enumerates and validates device eligibility |
| NanoRegistry/PDR/CLKDevice device-capability data | Source of device category, collection, capability getters | `CLKDevice` reads paired-device/registry data; locations and privileges may differ on iPhone/watch. No confirmed ordinary app-group authorization or safe single-file override | Possibly influences real classification only if the system trust chain also accepts it; no proof |
| `IODeviceTree:/chosen` `marketing-software-behavior` | Static firmware MobileGestalt DeviceBrand provider probe | Physical watch had **no** such key; unrelated `software-behavior` was present. Zero kernel setters executed as their precondition was absent | No demonstrated route to the expected MobileGestalt persistent cache |

## C.1 New native ClockFace first-party FaceSupport entitlement evidence

The **exact original** watchOS 23U95 `/Applications/ClockFace.app/ClockFace` executable (405,520 bytes) was independently extracted from Apple's system image during [run #44111373781](https://github.com/mkalter/TESTAPP/actions/runs/44111373781). Its embedded code-signing text includes:

- **`com.apple.private.security.storage.NanoTimeKit.FaceSupport`**
- **`com.apple.nanotimekit.facesupportserver`**
- **`com.apple.nanotimekit.facesnapshotserver`**
- `com.apple.NanoTimeKit.face`
- `com.apple.Carousel.NTKServer`

The same build's kernel `baseline.sb` at the FaceSupport read/map/metadata exception branches, around lines **706**, **1416**, and **3669**, checks for one of:
- `com.apple.private.security.storage.NanoTimeKit.Argon`
- `com.apple.private.security.storage.NanoTimeKit.FaceSupport`

These are **specifically Apple-private authorizations**, not grants to a developer-signed HermesEnabler. The inspected branches are inside optional `common-debugging-rules` cases and **must not be misrepresented as a complete effective file-write policy**.

This independently demonstrates that the Apple ClockFace process has a legitimate relationship to FaceSupport system storage and owns face-related XPC service endpoints. An ordinary app merely connecting to one of those services does not prove it can request a trusted new Hermès gallery record. The actual service protocol's caller validation and native-library add predicate have not been independently traced in this research.

**Implication:** FaceSupport is a real native-system data plane worth studying, but the current `bad_query` / `worse_query` access classes have **no demonstrated write to it**, and it is not a proven way around signed Hermès class restrictions.

## D. Preference and internal-build controls are NOT interchangeable

Two real code paths were located in **iOS 26.1** decompiled NanoTimeKit and compared with the matching **23U95** static/watch evidence:

1. In `NTKGalleryCollection.galleryCollectionsForDevice:`, `com.apple.NanoTimeKit.face` preference `ShowInternalFaces` affects **the callback's** `_isInternalOnlyForDevice:` check, after `NTKFaceBundleManager.enumerateFaceBundlesOnDevice:` has already skipped `isRestrictedForDevice=true` bundles. Therefore this one pref cannot override Poodle.
2. The exact **23U95** `NTKShowHardwareSpecificFaces` implementation tests an `NTKInternalBuild` precondition **before** consuming its later `ShowHardwareSpecificFaces` pref/cached decision. The live 23U95 log returned `NTKInternalBuild=false`, `NTKShowHardwareSpecificFaces=false`, `NTKShowInternalFaces=false`. Therefore merely changing preference `ShowHardwareSpecificFaces` is unsupported as an unlock. The binary code uses early `cbz` to return false.

`cfprefsd.sb` in the 23U95 kernel allows the **Apple daemon** `file-write*`. That is expected for a preference daemon; it does **not** establish that an unsigned third-party app is permitted to control arbitrary other domains through cfprefsd IPC, and it would not fix the earlier native class restriction.

## E. Native Hermès dependency / potential future discriminators

A breakthrough must show all of:
- **Trusted data source or code path** changing an authoritative property consulted by ClockFace/NanoTimeKit in its *own* process; not merely a helper app's fake `CLKDevice`.
- **Real issuance and consumption of a compatible write authority** for that exact target, or an ordinary system-supported update API that legally accepts that data. AppGroup/Class7 token success alone is not sufficient.
- **Real native gallery enumeration and add-to-library acceptance**, including the Poodle/2025 class predicates.
- **Persistence across HermesEnabler termination and device/watch-face reload** (not a preview or a successful import callback).

Legitimate further static analysis includes locating the precise paired-device/category capability provider used by native `CLKDevice` on 23U95, the 2025 face-class helper, and the live face gallery persistence location with read-only logs. None has been independently connected to a safe, effective writable Class7/Class13 target.

**Verified outcome at this revision:** hard device-category/collection and internal-build gates; real native bundles and sandbox issuer rules extracted independently; **no successful MobileGestalt write, authorized alternate system store mutation, or native Hermès unlock**.


## F. Original watchOS 23U95 face-library daemon — newly verified from Apple firmware

A separate independent Apple-CDN partial-image extraction succeeded and is archived as [GitHub Actions #44113732424](https://github.com/mkalter/TESTAPP/actions/runs/44113732424), artifact `genuine-watch6-18-23u95-clockface-storage-and-support-audit` (the workflow status alone is not proof; extraction log shows 5 genuine files). The extraction used **124 HTTP range requests** and transferred **24,591,274 bytes** of the Watch6,18 / 23U95 IPSW. SHA-256 checksums and source paths are available for all original files in the artifact. The full 5 GB IPSW hash was not verified.

The actual extracted watchOS processes/libraries are:

| Original path / component | Size (bytes) | Distinguishing grounded evidence |
| --- | ---: | --- |
| `/System/Library/PrivateFrameworks/NanoTimeKit.framework/nanotimekitd` | 734,464 | Apple-signed native face-library/sync daemon; ObjC selectors for store maintenance and migration |
| `/System/Library/PrivateFrameworks/NanoFaceGallery.framework/NanoFaceGallery` | 1,482,608 | Actual Swift `FaceLibraryManager`, `ForYouFacesManager`, `allFacesGallery` |
| `/System/Library/CoreServices/Carousel.app/Carousel` | 185,312 | First-party watch UI and FaceSupport server entitlement |
| `/System/Library/LaunchDaemons/com.apple.nanotimekitd.plist` | 2,194 | Original daemon launch/service manifest |
| `/System/Library/LaunchDaemons/com.apple.carouselecomoded.plist` | 261 | Original Carousel companion service manifest |

### Critical original daemon methods and persisted-state behavior

The real `nanotimekitd` includes literal selector and diagnostics:

- `_removeUnavailableFacesFromStore:` and log **`Removing unavailable faces`**
- `_addDefaultFacesToStore:` and log **`Store is empty - adding default faces`**
- `_migrateBundleFacesInStore:`, `_migrateFacesInStore:`, `_fromSyncResetWithFaces:orderedUUIDs:selectedUUID:`
- `faceWithJSONObjectRepresentation:forDevice:forMigration:allowFallbackFromInvalidFaceStyle:`
- `com.apple.pairedsync.faces`, `_NTKFacePreferencesFaceLibraryKey`, `_NTKFacePreferencesFaceLibraryVersionKey`

**New evidence:** not only the gallery UI but the actual native **face-library daemon** has an explicit maintenance path for *removing unavailable faces*. Thus directly inserting an unsupported Hermès configuration into a library database/preference store (even if write access were obtained) has a separate lifecycle risk: the daemon can evaluate availability and remove it. A symbol/diagnostic name alone does **not** prove when or how often the removal method is invoked, or precisely which predicate it uses; disassembly/control flow would be required.

The `nanotimekitd` binary's own entitlement text includes `com.apple.private.security.storage.NanoTimeKit.FaceSupport`, `com.apple.nanotimekit.replicator.library.entitlement`, home-relative read-write exception **`/Library/NanoTimeKit/`**, and shared-preference read-write `com.apple.NanoTimeKit.face`. These grants belong to Apple's daemon, **not** HermesEnabler. They show there is a privileged writer of the native library, but do not confer a writable Class7 AppGroup target or a caller-authorized arbitrary-face IPC.

The original `Carousel` binary likewise embeds `com.apple.private.security.storage.NanoTimeKit.FaceSupport`, an exception for its home-relative `/Library/`, `com.apple.NanoTimeKit.face`, and several face-library/ClockKit XPC service names. `NanoFaceGallery` has a real `FaceLibraryManager` Swift type. All three are separate from the third-party app sandbox.

### Result for a bad_query alternate-store theory

**No evidence of a directly writable alternative store that switches Hermès on.** The native face-library state belongs to Apple daemons with private grants; `bad_query` Class7 can issue extensions for eligible AppGroup roots and Class13 for SystemGroup roots, but this does not grant the global per-user NanoTimeKit library. Even if a different primitive provided write access to the library, both the face-class checks and `_removeUnavailableFacesFromStore:` remain relevant.

The next meaningful discriminator is a **read-only disassembly of `_removeUnavailableFacesFromStore:` and its caller(s)**, together with the `nanotimekitd` library sync validators. Until those are independently verified, do not create another IPA that edits unspecified `*.plist`/SQLite files or reports a fabricated Hermès unlock.
