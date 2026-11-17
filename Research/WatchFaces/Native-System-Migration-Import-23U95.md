# Native Hermès system-face import — two independent early gates, 23U95

**Goal:** genuine Apple native Hermès face in the **Watch's system face switcher** and the paired iPhone's Watch app. An in-app NanoTimeKit FaceView does NOT meet the goal.

**Status:** Two independently grounded ways to reach the Apple system-import path are now executable. Neither is a proven Hermès unlock or a working on-device bypass yet.

## Finding 1: the real bundled-face migration bit is consumed by native NanoTimeKit

A genuine `Hermès Circulaire.watchface` has this structure in `face.json`:

```json
{"face type":"bundle","bundle id":"com.apple.NTKPoodleFaceBundle","forMigration":false}
```

The previously examined authentic source is documented with SHA-256 `d8364f574fbfcbf16a46d7ae07fbdf74267621a7f6ec2e7525e8018d2659fb03` in [the 23U95 archive report](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V20-Watchface-Archive-Import.md). The actual archive bytes are **not** in this repo.

Disassembled iOS 26.1 NanoTimeKit `NTKFace.mm` independently shows:

```objc
v18 = [representationCopy objectForKeyedSubscript:@"forMigration"];
bOOLValue = [v18 BOOLValue];
v31 = [manager faceBundleForBundleIdentifier:v13
                                    onDevice:deviceCopy
                                forMigration:bOOLValue];
```

In the **actual 23U95 NanoTimeKit** `faceBundleForBundleIdentifier:onDevice:forMigration:`, when its migration flag is true, it skips an early `isRestrictedForDevice:` check that normal bundle lookup performs. The later `_NTKCanAddWatchFace` path has independent availability and eligibility checks. Thus **migration flag bypassing one check does not prove a face can be installed**.

Original iOS 26.1 reverse-engineered source:
https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/NanoTimeKit.framework/NanoTimeKit/NTKFace.mm
Target Watch static disassembly:
https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V17-FaceBundle-Loading-Chain.md

## Finding 2: ClockKit's own Messages import bypasses only an initial client-side availability check

In iOS 26.1 `CLKWatchFaceLibrary.mm`:

```objc
shouldValidate =
    ![[[NSProcessInfo processInfo] processName].lowercaseString
          isEqualToString:@"mobilesms"];
[self _addWatchFaceAtURL:faceURL
          shouldValidate:shouldValidate
      completionHandler:callback];
```

`_addWatchFaceAtURL:shouldValidate:completionHandler:` invokes `_validateWatchFaceAtURL:` only when `shouldValidate` is true. This first validator reads `face.json` and calls the **iPhone-side** `CLKWatchFaceLibraryServer.validateFaceType:faceBundleId:` using the `com.apple.ClockKit.CLKWatchFaceLibrary` XPC endpoint. Even with `shouldValidate=false`, the import is still routed into the same Apple server and the Watch **may reject the face**.

This has only been independently traced in the iOS 26.1 sample. Availability of the private selector and behavior on the user's paired iPhone iOS version **must be checked on the actual iPhone**, not inferred.

Source:
https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/Frameworks/ClockKit.framework/ClockKit/CLKWatchFaceLibrary.mm

## What's new in the app

In the iPhone companion's **Native systeemwijzerplaat** card:

- **Normale systeemimport (controle)**: documented `CLKWatchFaceLibrary.addWatchFace`.
- **TEST: systeemimport zonder iPhone-voorcheck**: dynamically invokes the exact private `_addWatchFaceAtURL:shouldValidate:completionHandler:` with `shouldValidate=NO`, only if the method exists and has the ABI shape described by the inspected code.
- **Kopieer laatste echte importresultaat** copies the actual mode, selected file name, iOS build and exact result/error domain + numeric code.

The private call can be removed or have a different signature on future iOS. It runs only when tapped and uses only a user-selected local `.watchface` as input; it does not change protected MobileGestalt files or ClockFace databases directly. Apple's server and Watch still enforce independent checks.

## Test procedure: actual native system faces

**Required:** an existing, authentic, legitimate original Hermès `.watchface`, e.g. one exported/shared from a Hermès Apple Watch. Do NOT make up an archive from a thumbnail or rename another file.

1. Keep the original `Hermès Circulaire.watchface` untouched.
2. On Windows, drag it onto `Research/WatchFaces/Make-Migration-Face-Windows.cmd` (Python 3 installed). Or run `python Research/WatchFaces/make_migration_watchface.py "Hermès Circulaire.watchface"`.
3. The script creates a new `Hermès Circulaire-migration-test.watchface` where **only** `face.json.forMigration` is set to `true`. All other ZIP members are preserved, output ZIP CRC is verified and the original is left untouched. The archive is local, with no network calls. It does not claim to preserve signatures (none were examined) or face authorization.
4. Put both files in **Files on the iPhone**.
5. **Baseline:** select the original via **Normale systeemimport (controle)** and copy the result.
6. **New test A:** select the original via **TEST: systeemimport zonder iPhone-voorcheck**, copy result.
7. **New test B:** select the `-migration-test.watchface` via **TEST: systeemimport zonder iPhone-voorcheck**, copy result.
8. **Independent Apple first-party comparison, no private app call:** send the migration copy through **iMessage/Messages** to yourself or a trusted contact, receive/open the attachment inside Apple's Messages app and use the native Apple Watch Add Face flow (the disassembled client code treats processName `mobilesms` specially).
9. **Success requires observing the real face in the Apple Watch's native face switcher after HermesEnabler has been closed**; also inspect the iPhone Watch app. A success callback or face preview is insufficient. Record any actual `Niet beschikbaar op je Apple Watch` message and Apple error.

If both the in-app direct path and Messages reject the migration candidate, the independent **Watch-side** eligibility/add-to-library gate remains an unproven blocker. Do not keep changing byte offsets, MCM flags or renaming the files hoping to affect that gate.

## Expected limitations / previous findings

- Previous user attempts exported a Hermès `.watchface` but the Watch rejected it as **Niet beschikbaar op je Apple Watch**; that was **not** a verified import of the explicitly modified original archive through both client paths.
- Watch6,18 / 23U95 `DeviceBrand=0`, `deviceCategory=4`, `collectionType=9` and `NTKShowHardwareSpecificFaces=false`; Hermès family restrictions can be independent of `DeviceBrand`.
- Protected MobileGestalt write `O_RDWR` returns `EPERM`. The separate upstream 23U95 cache layout in PR15 removes a build-table gap but **does not grant permissions**.
- The new test changes only a copy of a watchface archive, with no jailbreak, protected cache write, system file replacement or re-pairing.

**No operating native Hermès system face has been demonstrated yet.**
