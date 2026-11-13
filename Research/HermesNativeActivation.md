# Hermès native activation route (2026-11-13)

The iOS 27 migration eligibility probe returned five native Hermès bundles when forMigration was true: Poodle, Hades, Secretariat, Bellona, and Squall. The iPhone CLKDevice was isPaired=0, so the companion cannot assume access to a real paired device from currentDevice.

## One-action implementation

The iPhone home screen now has an **Activeer Hermès-wijzerplaat** button.

The action tries in sequence:
1. Load NanoTimeKit and ClockKit, then obtain activePDRDevice when available. Fall back to currentDevice for archive construction only.
2. For each of six Hermès bundle identifiers, request a bundle with forMigration YES and create a real face using defaultFaceForDevice: or the migration JSON initializer.
3. Confirm that the face retains the requested bundle id and forMigration value.
4. Only with a real pairingID, try LibraryFaces appendFace and setSelectedFace. Local selection does not prove Watch synchronization.
5. Export Apple's native watchface using NTKGreenfieldDraftRecipe and NTKGreenfieldUtilities; fall back to NTKDZipFileFromFace. If an archive is created, hand it to the iOS share sheet for Watch / Add to My Faces.
6. The first successful native export stops the remaining alternatives.

Actual Watch acceptance and rendering remain unverified. The installer must sign both the iPhone app and embedded Watch app. The action does not modify MobileGestalt or other protected system files.

## Relevant implementations
- HermesCompanion/HermesActivation.m
- HermesCompanion/ContentView.swift
- HermesCompanion/HermesFaceProbe.h

## Reverse engineering sources
- https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore
- https://github.com/LordixDemon/apple_watch_connector/blob/main/tools/probe_native_face_sharing.m
