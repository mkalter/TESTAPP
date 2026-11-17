# Multi-route MobileGestalt write investigation — watchOS 26.6.1 (23U95)
Date: 2026-11-17

## Observations on the target device
Watch6,18 / Apple Watch Ultra 1 / watchOS 26.6.1 (23U95):
- Protected MobileGestalt file read is allowed, write-open returns EPERM.
- Class 7 and Class 13 extensions do not grant effective protected file writes.
- MGSetAnswer is MISSING from the private dylib exports as seen by this
  app, while MGCopyAnswer is PRESENT. The prior MGSetAnswer test therefore
  NEVER invoked a setter; no positive or negative conclusion about a setter
  being callable in a more privileged process can be drawn from that failure.

## Different mechanisms (not variations of the same MCM flag)

| Family | Underlying write authority | Evidence / test on this hardware | What could genuinely prove it? |
| --- | --- | --- | --- |
| A: Direct MobileGestalt API | MGSetAnswer in a client library | MGSetAnswer export missing on this watch | Verified callable setter, persisted cache delta in a newly launched process |
| B: IOKit registry write | IODeviceTree:/chosen and kernel registry setter APIs | NEW opt-in test added to Watch app (three public IOKit function signatures invoked dynamically if exported) | Setter succeeds with identical bytes and readback matches; then assess persistence separately |
| C: MobileGestaltHelper XPC | Privileged helper service | Existing XPC tests returned error 9; 23U95 static inspection identifies rebuildCache: and setCacheSentinel: but not an arbitrary DeviceBrand setter | A verified helper selector accepting client-provided data; neither known method qualifies |
| D: MCM sandbox extension | File-issue-extension + received system group rights | Multiple Class 7/13 tests, consumed system-group tokens, O_WRONLY EPERM | Effective file-write-data permission and writable original file descriptor |
| E: Device restore service | Backup restore paths like BookRestore / SparseRestore | Known iOS support only through older 26.1/early 26.2 beta; not verified for watchOS 26.6.1 | An independently documented supported paired-Watch restore path that targets SystemGroup, with a fully reversible recovery procedure |
| F: MobileHouseArrest / MHA-C2 | Companion container access | iOS app-data mechanism; not evidence of SystemGroup write rights on Watch | Target-specific verified SystemGroup write, not merely other app containers |
| G: Installer / InstallCoordination | Privileged package/data installation | Prior PromiseStaging, DataPromises, Coordinator entry-token observations did not permit writable directory access | Actual authorized service accepts a targeted update; not just a token or directory pathname |
| H: Process-local identity model | CLKDevice collectionType and NanoTimeKit | Original Apple native FaceViews work in app for three styles | In-app rendering is achieved, but not a system ClockFace permission or persisted MobileGestalt write |

### B: NEW executable on-device IOKit experiment
File: HermesEnabler2/BQIODeviceTreeWriteProbe.m
Button: MG Diagnostics > TEST: IODeviceTree setters (3 routes)
Logs: iodevicetree-write-probe.txt, delivered via WatchConnectivity to
the iPhone's Watch Logs.

Source basis:
- Decompiled 23U95 MobileGestalt provider for DeviceBrand reads the property
  `marketing-software-behavior` from `IODeviceTree:/chosen`.
- Apple's IOKit library documents three different write entry points:
  `IORegistryEntrySetCFProperty`,
  `IORegistryEntrySetCFProperties`,
  `IOConnectSetCFProperty`.
- Exact ABI signatures for these functions are known (Apple developer docs).
- Public API existence on macOS DOES NOT prove symbol presence or permission
  on watchOS. The Watch test safely skips absent symbols.

The experiment reads the current provider data, refuses to continue unless
it is CFData of plausible size (4-64 bytes), records a verified MG backup
and saves the original provider property into its own Documents first. It
then calls three distinct documented write APIs using the IDENTICAL original
bytes, finally reading back the property and recording IOKit return codes.
The test does not attempt to change DeviceBrand, the provider data, or
the protected cache on disk.

**Limitations**:
- A setter returning success with the same value is not proof that changing
  that value is possible, or that the result survives reboot.
- An IOKit kernel setter is not a system-group filesystem entitlement.
- A setter may have side effects even with unchanged bytes, hence this
  test is manually opt-in and not run as part of complete diagnostics.
- Backup of the plist does NOT provide a hardware recovery or Watch reflash
  procedure if an Apple-private service were to misbehave.

### C: Why we do NOT invoke rebuildCache or setCacheSentinel
The extracted 23U95 helper shows that rebuildCache: invokes
_MGRebuildCache(), which can unlink the original cache; it cannot accept
an arbitrary DeviceBrand value. setCacheSentinel: writes a fixed boot UUID
to a fixed .rebuild path. Both are unrelated to a true editable MG setter.
Calling them would create risk without any reasonable way to achieve the
requested state change.

### E: Why paired-iPhone backup methods are a separate environment
BookRestore and SparseRestore are iOS/iPadOS backup mechanisms and a
proof for iOS 26.1 is not a proof for watchOS 26.6.1. They cannot be
implemented solely as a watchOS in-app API invocation. In addition, arbitrary
backup restore of system-group files has not been verified for this device.

### F: Why app-container file managers are not evidence
A returned App Group / application data path from 3105 or MHA-C2 is not
authorization to write systemgroup.com.apple.mobilegestaltcache on watchOS.

## Research references

- Apple IOKit API:
  https://developer.apple.com/documentation/iokit/1514882-ioregistryentrysetcfproperty
  https://developer.apple.com/documentation/iokit/1514414-ioregistryentrysetcfproperties
- Source and 23U95 binary analysis:
  https://github.com/pookjw/HermesEnabler/issues/7
- Code-backed experiments:
  https://github.com/murk-sus/kamui-escape
  https://github.com/GoldenNugget-Team/worstgestalt
- iOS restore compatibility:
  https://github.com/nxtcoreee3/Mobile-Gestalt-Exploits
  https://github.com/MNS82/nugget-iOS
- App-container access:
  https://github.com/YangJiiii/3105

## Success criteria
Do not collapse these distinct observations:
1. Function symbol presence.
2. A function is actually called with the correct ABI.
3. API reports a success code.
4. An actual device-readable answer changes.
5. The protected cache file changes and remains valid.
6. The value survives a newly started process.
7. A full Watch restart survives with native system ClockFace behavior.

This branch is a **multi-route investigation**, not a claimed new sandbox
escape or confirmed working protected file writer.
