import Foundation
import UIKit

/// Diagnostic-only watchface package built from a known watchOS FaceBundle ID.
/// This is NOT an extraction of an Apple Watch face, and does not bundle any
/// protected Apple/Hermès artwork or modify MobileGestalt.
enum HermesSystemFaceCandidate {
    private struct Member {
        let name: String
        let contents: Data
    }

    static func create(migration: Bool) throws -> URL {
        // Original Circulaire face.json was identified in prior offline research.
        // The actual 23U95 firmware bundles the native Poodle implementation,
        // but does NOT provide an installable .watchface ZIP for this Watch.
        let face: [String: Any] = [
            "analytics id": "poodle",
            "face type": "bundle",
            "bundle id": "com.apple.NTKPoodleFaceBundle",
            "forMigration": migration,
            "customization": ["color": "white"],
            "version": 4
        ]
        let metadata: [String: Any] = [
            "version": 2,
            "device_size": 2,
            "complication_sample_templates": [:],
            "complications_item_ids": [:],
            "complications_bundle_ids": [:],
            "complications_names": [:]
        ]

        let snapshot = placeholderSnapshot()
        let files = [
            Member(name: "face.json", contents: try JSONSerialization.data(withJSONObject: face, options: [.sortedKeys])),
            Member(name: "metadata.json", contents: try JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys])),
            Member(name: "snapshot.png", contents: snapshot),
            Member(name: "no_borders_snapshot.png", contents: snapshot)
        ]

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("HermesSystemFaceDiagnostics", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let basename = migration
            ? "Circulaire-GENERATED-migration-test"
            : "Circulaire-GENERATED-ordinary-control"
        let destination = directory.appendingPathComponent(basename).appendingPathExtension("watchface")
        try makeStoredZIP(files).write(to: destination, options: [.atomic])
        return destination
    }

    // A neutral placeholder is only the *import thumbnail*. If the native
    // FaceBundle is accepted, watchOS renders the real face itself.
    private static func placeholderSnapshot() -> Data {
        let size = CGSize(width: 300, height: 360)
        let renderer = UIGraphicsImageRenderer(size: size)
        return renderer.pngData { context in
            UIColor.black.setFill()
            context.fill(CGRect(origin: .zero, size: size))
            let frame = UIBezierPath(roundedRect: CGRect(x: 31, y: 26, width: 238, height: 308),
                                     cornerRadius: 56)
            UIColor(white: 0.18, alpha: 1).setStroke()
            frame.lineWidth = 4
            frame.stroke()
            let label = "10:09" as NSString
            let font = UIFont.monospacedDigitSystemFont(ofSize: 67, weight: .light)
            let attributes: [NSAttributedString.Key: Any] = [
                .font: font,
                .foregroundColor: UIColor.white
            ]
            let width = label.size(withAttributes: attributes).width
            label.draw(at: CGPoint(x: (size.width - width) / 2, y: 139), withAttributes: attributes)
        }
    }

    // ZIP STORE encoder: compatible with face sharing's ZIP container format.
    // No third-party dependencies, private file access, or sandbox privileges.
    private static func makeStoredZIP(_ members: [Member]) -> Data {
        var local = Data()
        var central = Data()

        for entry in members {
            let name = Data(entry.name.utf8)
            let n = UInt32(entry.contents.count)
            let check = crc32(entry.contents)
            let offset = UInt32(local.count)
            let count = UInt16(name.count)

            // Local file header
            add(UInt32(0x04034b50), to: &local)
            add(UInt16(20), to: &local)
            add(UInt16(0x0800), to: &local) // UTF-8
            add(UInt16(0), to: &local)      // no compression
            add(UInt16(0), to: &local)
            add(UInt16(0x0021), to: &local)
            add(check, to: &local)
            add(n, to: &local)
            add(n, to: &local)
            add(count, to: &local)
            add(UInt16(0), to: &local)
            local.append(name)
            local.append(entry.contents)

            // Central directory header
            add(UInt32(0x02014b50), to: &central)
            add(UInt16(20), to: &central)
            add(UInt16(20), to: &central)
            add(UInt16(0x0800), to: &central)
            add(UInt16(0), to: &central)
            add(UInt16(0), to: &central)
            add(UInt16(0x0021), to: &central)
            add(check, to: &central)
            add(n, to: &central)
            add(n, to: &central)
            add(count, to: &central)
            add(UInt16(0), to: &central)
            add(UInt16(0), to: &central)
            add(UInt16(0), to: &central)
            add(UInt16(0), to: &central)
            add(UInt32(0), to: &central)
            add(offset, to: &central)
            central.append(name)
        }

        let centralStart = UInt32(local.count)
        local.append(central)

        add(UInt32(0x06054b50), to: &local)
        add(UInt16(0), to: &local)
        add(UInt16(0), to: &local)
        add(UInt16(members.count), to: &local)
        add(UInt16(members.count), to: &local)
        add(UInt32(central.count), to: &local)
        add(centralStart, to: &local)
        add(UInt16(0), to: &local)
        return local
    }

    private static func add<T: FixedWidthInteger>(_ number: T, to data: inout Data) {
        var little = number.littleEndian
        withUnsafeBytes(of: &little) { bytes in
            data.append(contentsOf: bytes)
        }
    }

    private static func crc32(_ bytes: Data) -> UInt32 {
        var result: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            result ^= UInt32(byte)
            for _ in 0..<8 {
                result = (result & 1) != 0 ? (result >> 1) ^ 0xEDB8_8320 : result >> 1
            }
        }
        return result ^ 0xFFFF_FFFF
    }
}
