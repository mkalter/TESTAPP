import Foundation

/// Interprets existing, non-destructive diagnostics. It never acquires tokens,
/// opens a protected file, or changes any system state.
enum MGDiagnosticVerdict {
    private static func section(_ report: String, named name: String) -> [String] {
        let lines = report.components(separatedBy: .newlines)
        guard let start = lines.firstIndex(where: { $0.trimmingCharacters(in: .whitespaces) == "[\(name)]" }) else {
            return []
        }
        return Array(lines.dropFirst(start + 1).prefix {
            let line = $0.trimmingCharacters(in: .whitespaces)
            return !(line.hasPrefix("[") && line.hasSuffix("]"))
        })
    }

    private static func value(in lines: [String], prefix: String) -> String {
        guard let line = lines.first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix(prefix) }) else {
            return "UNKNOWN (not logged)"
        }
        return String(line.trimmingCharacters(in: .whitespaces).dropFirst(prefix.count))
    }

    static func summarize(gates: String, baseline: String) -> String {
        let protected = section(gates, named: "Protected MG cache file")
        let group = section(gates, named: "Own App Group (control)")

        let readPolicy = value(in: protected, prefix: "file-read-data=")
        let writePolicy = value(in: protected, prefix: "file-write-data=")
        let writeOpen = value(in: protected, prefix: "open(O_WRONLY|O_NOFOLLOW), NO WRITE=")
        let groupWritePolicy = value(in: group, prefix: "file-write-data=")
        let ownControl = baseline.contains("create/write/readback=PASS") ? "PASS" :
            (baseline.contains("create/write/readback=FAIL") ? "FAIL" : "UNKNOWN")

        let readAllowed = readPolicy.hasPrefix("ALLOW")
        let writeDenied = writePolicy.hasPrefix("DENY")
        let openDenied = writeOpen.hasPrefix("DENIED")
        let ownWorking = ownControl == "PASS"

        let assessment: String
        if readAllowed && writeDenied && openDenied {
            assessment = "READ AVAILABLE / PROTECTED WRITE DENIED"
        } else if writeDenied || openDenied {
            assessment = "PROTECTED WRITE RESTRICTED (partial evidence)"
        } else if writePolicy.hasPrefix("ALLOW") && writeOpen.hasPrefix("ALLOWED") {
            assessment = "WRITE-OPEN ALLOWED; PERSISTENT WRITE NOT TESTED"
        } else {
            assessment = "INCONCLUSIVE: inspect original logs"
        }

        var lines = [
            "=== MobileGestalt authorization verdict (read-only interpretation) ===",
            "Assessment: \(assessment)",
            "Protected read sandbox policy: \(readPolicy)",
            "Protected write sandbox policy: \(writePolicy)",
            "Protected O_WRONLY open/close: \(writeOpen)",
            "Own App Group sandbox write policy: \(groupWritePolicy)",
            "Own App Group write/readback control: \(ownControl)"
        ]

        if ownWorking && writeDenied && openDenied {
            lines.append("Interpretation: signing and own-container writes work; the protected SystemGroup write gate remains independent.")
        } else if !ownWorking {
            lines.append("Interpretation: own-container control is missing or failed; confirm provisioning separately.")
        }

        lines.append("A returned MCM path, a consumed sandbox token, or a successful read does NOT establish protected write permission.")
        lines.append("No protected file contents were modified by the source diagnostics or this interpretation.")
        lines.append("Do not treat an ALLOWED O_WRONLY open as proof of a persistent or safe cache change.")
        return lines.joined(separator: "\n")
    }
}
