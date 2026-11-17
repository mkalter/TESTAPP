# Self-contained native Hermès Circulaire watchface test — no file required

**Watch target:** Apple Watch Ultra 1 `Watch6,18` / watchOS 26.6.1 `23U95`.

## What is and is not extracted

On a non-Hermès Ultra 1, the genuine `com.apple.NTKPoodleFaceBundle` implementation can be present in the signed watchOS system image even though Apple prevents it from appearing in the face gallery. The system does **not** necessarily keep a ready-to-export `.watchface` ZIP for every hidden face. The ordinary ClockKit API adds a file supplied to it; it does not extract arbitrary hidden system faces. A sandboxed third-party Watch app cannot simply read the Watch system's protected face gallery or the iPhone Watch app's private Inbox.

Therefore this is **not an extraction** of Hermès face code, firmware, resources, or copyrighted artwork. It is an independently generated configuration ZIP referencing the native bundle identifier discovered in a previously authenticated `Hermès Circulaire.watchface`.

## New one-tap candidate

In the iPhone companion, tap **‘Maak en test Hermès Circulaire (zonder bestand)’**.

The iPhone constructs a ZIP locally containing:

- `face.json`: `face type=bundle`, `bundle id=com.apple.NTKPoodleFaceBundle`, `analytics id=poodle`, `forMigration=true`, `version=4`, default white customization.
- `metadata.json`: minimal schema with `version=2`, `device_size=2` and empty complication maps.
- `snapshot.png` and `no_borders_snapshot.png`: neutral generated 10:09 thumbnail, **not original Hermès artwork**.

A standalone ZIP STORE encoder creates proper local records, CRC-32 and central directory. The standalone encoder format was checked with Python's ZIP reader and `unzip -t`; this is **archive integrity evidence only**, not face compatibility.

The generated test is passed to the opt-in `CLKWatchFaceLibrary` private system import route that omits an initial **iPhone** client-side face-type precheck (when present). No protected files are modified. Apple's import server and the actual Watch still enforce their own restrictions.

The user may also tap **‘Deel gegenereerd testbestand via Berichten’** to try the separate first-party iMessage import path.

The last import log states `archive=GENERATED_NOT_EXTRACTED_FROM_WATCH`, `nativeBundle=com.apple.NTKPoodleFaceBundle`, `forMigration=true`, and any returned NSError domain/code. A callback without an error **does not prove native activation**.

## Evidence / limitation

- Source for FaceBundle identifier: genuine Circulaire file previously parsed in https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V20-Watchface-Archive-Import.md
- Target OS's independent face availability restrictions: https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V17-FaceBundle-Loading-Chain.md
- iOS 26.1 reverse-engineered import and representation: https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/tree/main/System/Library/Frameworks/ClockKit.framework/ClockKit

**Unsupported until real device testing:** Whether Apple accepts this minimal configuration schema, recognizes `forMigration` from the import pipeline on the user's paired iPhone, and can add the restricted Poodle face to Watch6,18 / 23U95.

**Success criterion:** an original Apple Hermès face in the system face carousel after closing HermesEnabler — not a black preview, screenshot, app face, or successful callback alone.
