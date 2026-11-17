# Original Hermès watch-face viewer — experimental

Added: 2026-11-17.

The Watch app can now **display six original Apple NanoTimeKit FaceViews inside the app** on watchOS 26:
Circulaire, Hermès (Zeus Analog), Radial, Circuit H, Lucky Horse and Faubourg Party.

**It does not install a system watch face, unlock Apple's Face Gallery, update MobileGestalt,
or replace the first-party ClockFace process.** The app remains open while the viewer is displayed.

## Where to find it

1. Install/sign the iPhone companion and embedded Watch app.
2. On the Watch, open HermesEnabler2.
3. With no MobileGestalt backup yet: select **Bekijk 6 originele wijzerplaten** on the MG Backups screen.
4. With an existing backup: select **Bekijk originele wijzerplaten** from the first section of the home screen or open Watch Faces.
5. Select a face; long-press the shown original FaceView to go back.

Unlike the main Hermès capability toggle, the viewer never requires a protected MobileGestalt write.
It loads Apple's installed NanoTimeKit/ClockKit components dynamically and temporarily selects the
Hermès collection type **within the app's process only**. The previous device collection type is
restored in a finally block. The returned face and view types are verified before mounting.

## Ultra models

Upstream's in-app viewer tested for the original collection type of a Series watch. This branch
avoids assuming a collection type equal to 1 on an Ultra; it checks for a plausible nonzero
value, briefly selects type 5 only while constructing the FaceView, then restores the
original value. **This compatibility adjustment has not been physically validated on
Watch6,18 / watchOS 26.6.1.**

## Diagnostics

The user-visible error remains on the Watch screen if an original FaceView fails to mount.
Every selection also writes `original-hermes-last-result.txt`, which is transferred to the
iPhone's existing **Watch Logs** page when WatchConnectivity is available. The report contains
the selected face, OS version, and result string.

Common outcomes:
- `native-face-mounted`: real Apple FaceView attached to the app window.
- `Apple NanoTimeKit bundles unavailable`: required system frameworks/bundles missing.
- `Original Apple FaceBundle API unavailable`: private API not found.
- `Genuine Apple FaceView unavailable (no replica)`: Apple did not return the expected native class.
- `Genuine Apple FaceView was not attached to a window`: controller returned but wasn't display-mounted.

The code contains no copied artwork, face binaries, DRM material, protected-file writes,
sandbox escapes, cache rebuilds or Apple-private entitlement requests.
It does **not** promise Apple complication support, Always-On fidelity, system face
switching or persistent face availability after closing the app.

## Build

The `Build unsigned iPhone + Watch IPA` workflow builds this feature branch and uploads
an unsigned IPA artifact containing the iPhone companion and embedded Watch app.
**Unsigned IPA files cannot be installed until appropriately signed and provisioned.**
The workflow is a compilation test, not a physical-watch test.

## Provenance

Based on [mightywhite/HermesEnabler, feature/original-hermes-watchos26](https://github.com/mightywhite/HermesEnabler/tree/feature/original-hermes-watchos26),
[HermesEnabler PR #93](https://github.com/pookjw/HermesEnabler/pull/93). That project
is MIT-licensed (copyright 2026 Jinwoo Kim); license terms are inherited here.
The PR reports six simulator views on watchOS 26.5 and separate physical-watch research
on 26.6; this particular integration into TESTAPP is new and not yet proven on hardware.
