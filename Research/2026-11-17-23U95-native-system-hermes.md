# Native Hermès system faces on Watch6,18 / watchOS 26.6.1 (23U95)

Goal: add **real Apple system ClockFace/Hermès watch faces**, visible in the
Watch's face-switching interface and paired iPhone's Watch app, and still
present after HermesEnabler is closed. **An app-local NanoTimeKit FaceView is
NOT a solution to this goal.**

## Newly discovered independent code blocker

Before this branch, our fork's `HermesEnabler2/MGOffsets.plist` and
`HermesEnabler2/MGDefaults.plist` contained **no 23U95 entry**.
`BQSetHermesEnabled()` resolves the runtime build with
`bq_layoutForBuild(build)` and returns
`DeviceBrand CacheData layout is not verified` if it is missing.
Therefore the source did not support native system-model toggling on 23U95
even if another process independently obtained valid file-write authority.

The upstream official `pookjw/HermesEnabler` now supplies an exact
23U95 MobileGestalt descriptor and default:
- CacheUUID: `3BE19A76-F253-4CE4-AAC1-DF6D801CAAB1`
- CacheDataLength: `6309` / `0x18a5`
- DeviceBrandOffset: `824` / `0x338`
- DeviceBrandPresentOffset: `5711` / `0x164f`
- ScreenClassOffset: `3640` / `0xe38`
- ScreenClassPresentOffset: `6063` / `0x17af`
- PresenceBase: `5608` / `0x15e8`
- HermesEnabledDeviceBrand: `1`
- Ultra screen class choices: `29`, `38`
- RecoveryVerified: `false` (DO NOT claim recovery verification!)

This branch copies only the exact upstream 23U95 entries into the
existing data tables and adds build-specific assertions to
`tests/test_ultra_layouts.py`. The code still checks original cache UUID,
blob length, DeviceBrand-present flag, and a pre-existing original backup.
It does **not** bypass the watchOS sandbox or alter any live hardware in
GitHub Actions.

## Separate native-system installation candidate: official face sharing

Apple's public `CLKWatchFaceLibrary.addWatchFace(at:completionHandler:)`
API on the paired iPhone imports an existing **shared .watchface** file into
Apple's own Watch system. This is **not** a substitute in-app face viewer.

This branch adds an optional iPhone UI to select a user-provided, genuinely
shared `.watchface`, copies it from the security-scoped URL into a
temporary local file, and passes that URL to `CLKWatchFaceLibrary`.
It forwards Apple's actual error domain and error code and deletes the
temporary file afterward. It does **not** distribute or forge Hermès artwork,
modify the system ClockFace DB, or generate a watchface package.

Apple explicitly defines `faceNotAvailable` for a face not allowed on this
device. This means importing a Hermès-exclusive face **may be rejected even
though the API supports ordinary shared system faces**. There is not yet an
on-device success report for Hermès on this Ultra 1. Do not claim that
importing a face bypasses the Hermès model gate.

References:
- https://developer.apple.com/documentation/clockkit/clkwatchfacelibrary/addwatchface%28at%3Acompletionhandler%3A%29
- https://developer.apple.com/documentation/clockkit/clkwatchfacelibrary/errorcode/facenotavailable
- https://github.com/pookjw/HermesEnabler/blob/main/HermesEnabler2/MGOffsets.plist
- https://github.com/pookjw/HermesEnabler/blob/main/HermesEnabler2/MGDefaults.plist

## Remaining real blocker

Existing Watch6,18 / 23U95 logs consistently show:
`open(O_WRONLY/O_RDWR, com.apple.MobileGestalt.plist) -> EPERM`.
The independently extracted 23U95 sandbox issuer and receiver policy
requires private system-group write authorization; a MCM Class 13 token by
itself does not grant that right.

A successful local Xcode compile or a successful export of a MobileGestalt
backup cannot remove this blocker. On this build there is **no
independently verified persistent, native Hermès system-face activation**.

## What counts as success

- After reboot/respring, a Hermès face appears in Apple's face-switcher
  or iPhone Watch app **with HermesEnabler closed**.
- It remains a first-party native face with normal interactions;
  a FaceView embedded in HermesEnabler does not count.
- An official face importer callback alone is NOT sufficient unless the
  real face is observable on the Watch.
