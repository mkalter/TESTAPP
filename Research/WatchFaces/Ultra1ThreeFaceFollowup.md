# Ultra 1 — Circuit H, Lucky Horse, Faubourg Party

2026-11-17. Context: on a Watch6,18 running watchOS 26.6.1, the in-app original
Hermès FaceView viewer loads Circulaire, Hermès Classic and Radial, but Circuit H,
Lucky Horse and Faubourg Party were reported not working.

## Evidence and hypothesis

The watchOS 23U95 firmware research reports:
- `CLKDevice.deviceCategory=4` for the Ultra 1.
- `CLKDevice.collectionType=9` before viewer initialization.
- Faubourg Party restricts access using a category whitelist / newer-face capability,
  independent of collectionType.
- The other newer Hermès bundles also evaluate their own device eligibility.

This explains why temporarily selecting `collectionType=5` may be insufficient
for these models. **It does not prove the exact failure in this viewer**.

Reference: https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X

## Experimental fix

Only for face indexes 3, 4 and 5:
1. Preserve the original normal FaceBundle lookup.
2. If it yields nil, retry the same, installed Apple bundle with
   `forMigration:YES`.
3. If the bundle exists but `defaultFaceForDevice:` yields nil, inspect native
   `galleryFacesForDevice:` for a Face instance of the **expected Apple class**.
4. Continue to reject substitutes, unrecognized view classes or results not
   attached to the actual Watch-app window.
5. Trigger a single layout pass before validating native window attachment.

This does **not** spoof `deviceCategory`, request private entitlements, modify
MobileGestalt or grant first-party ClockFace access.

## New device evidence collected

Every tap includes in the iPhone Watch Logs:
- Device category and original/temporary/restored collection type.
- Expected face class registration.
- Normal and migration FaceBundle results.
- The default-face object, and gallery fallback result if invoked.
- Snapshot controller and actual/expected Apple-native view class.
- First view attachment or a caught exception.
- A distinct failure-stage label, when available.

The report file remains `original-hermes-last-result.txt` in **Watch Logs**.

The current version is **not verified to fix** these faces on Ultra 1; it must
be built and tested on the actual watch. A successful on-device native mount
must be distinguished from a working native system face.

If the migration and gallery paths still yield nil and the device category
is 4, the next step is **not** another MobileGestalt write attempt: use the
logged stage and compare that specific FaceBundle's device eligibility
conditions against the watchOS 23U95 firmware.

MIT provenance for the original viewer:
https://github.com/mightywhite/HermesEnabler/tree/feature/original-hermes-watchos26
