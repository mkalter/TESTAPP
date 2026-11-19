# watchOS 26.6.1 · real system-face action track

Target: Apple Watch Ultra 1 (Watch6,18), watchOS 26.6.1 / 23U95. Goal: an **Apple system ClockFace**, not an in-app face preview.

## What worse_query actually teaches us

- forcequitOS/worse_query operates on iOS 26/27 and uses an app-owned App Group + container-manager queries. The README documents SystemGroup paths for **iOS 27** specifically; it does not claim watchOS 26 SystemGroup write permission.
- Its interesting architectural observation is the separation between *requested container*, *resolved filesystem path*, *issued capability*, and *effective kernel sandbox decision*. A name lookup or token alone is not a successful protected-file write.
- TESTAPP's previous on-device watchOS 26.6.1 reports showed protected MobileGestalt write checks denied with EPERM. Do not equate iOS eligibility with watchOS eligibility.
- Directly copying the iOS route does not prove working watchOS authorization and is not the basis of the new functional experiment.

Original source: https://github.com/forcequitOS/worse_query

## New **functional** action in the iPhone companion

File: `HermesCompanion/ContentView.swift`.

1. Open **HermesEnabler** on the paired iPhone.
2. Tap **Probeer wijzerplaat toe te voegen**.
3. Select an existing legitimate `.watchface` file from Files.
4. The app copies the file to its own temporary directory and invokes Apple's real `CLKWatchFaceLibrary.addWatchFace(at:completionHandler:)` API.
5. The returned Apple error domain/code or acceptance is displayed and saved in `Documents/native-watchface-import-last-result.txt`, shareable from the app.

This action requests an actual system watch-face addition. It does **not** alter MobileGestalt, does not grant private entitlements, does not manufacture an unsupported face file, and does not overcome Apple hardware restrictions. A successful API callback is acceptance of the import request, not proof the face is selected.

Apple documents that Nike and Hermès faces require the respective hardware. Error `faceNotAvailable` is therefore meaningful evidence of a remaining hardware check, not a sandbox problem.

API: https://developer.apple.com/documentation/clockkit/clkwatchfacelibrary/addwatchface(at:completionhandler:)

## Controlled comparison (two real API calls)

- **Positive control:** Export a normal, supported Apple watch face from your own Watch app and import that `.watchface`. If this fails, fix basic ClockKit/file-format/pairing first.
- **Target test:** Obtain a legitimate Hermès face export (a genuine `.watchface` file) and import that second. Compare exact ClockKit error domains and codes, using the same paired Ultra 1.
- The app must not claim a Hermès unlock unless the face is actually visible and persists in the **system** Watch Face Gallery on-device after a normal reboot.

## Outcome interpretation

| Observation | Proven | Not proven |
| --- | --- | --- |
| iPhone import accepted | Apple processed the .watchface import request | Hermès unlocked / face active |
| ClockKit face-not-available error | System import rejects the file for this watch | Cause is only MobileGestalt |
| ClockKit invalid-file error | Import input was not a valid .watchface | Hardware eligibility |
| Protected write-open EPERM | Watch app cannot write that protected file through the tested route | Every possible way of activating a face is impossible |
| Native FaceView visible in watch app | Apple-original renderer can run in the app | First-party system ClockFace persisted |

## The next distinct questions

1. Is a valid system-exported Hermès `.watchface` rejected by ClockKit on Ultra 1, and with what precise NSError code?
2. Do the existing on-watch T1–T4 probes reveal a usable first-party face import interface? They only measure reachability; any actual call needs a separately reviewed, narrowly-scoped test.
3. Is rejection at face descriptor eligibility, file import, paired-device sync, or first-party face-store acceptance? Those are different boundaries. Do not infer the cause from file-read access.

No on-device positive result has yet been observed for the new ClockKit action. The GitHub IPA must be signed and installed before testing.
