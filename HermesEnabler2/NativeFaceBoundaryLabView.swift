import SwiftUI

/// Six baseline diagnostics, two ClockKit validator probes, one local migration lookup differential test of Apple's *native* watchOS
/// ClockFace / NanoTimeKit availability chain. No watch faces are installed.
struct NativeFaceBoundaryLabView: View {
    @State private var report = "Kies één test. De volledige log wordt naar de iPhone gestuurd."
    @State private var isRunning = false

    private let scenarios: [(String, String)] = [
        ("T1 · Mach-beleid", "Welke originele Apple-wijzerplaatdiensten staat de sandbox toe?"),
        ("T2 · Bootstrap-lookup", "Kunnen we de dienstnaam vinden, zonder XPC-berichten te sturen?"),
        ("T3 · Systeemopslag", "Bestaan de NanoTimeKit-mappen en welke lees-/schrijfrechten meldt het OS?"),
        ("T4 · Originele FaceBundles", "Zijn Zeus/Hermès2025-bundels op de Watch via het bestandssysteem zichtbaar?"),
        ("T5 · TCC / Software Update", "Controleren welke diensten bereikbaar lijken en wie MobileGestalt bezit."),
        ("T6 · Apple-daemonrechten", "Probeer uitsluitend te lezen of tccd zelf schrijfrechten heeft."),
        ("T7 · ClockKit-validatie", "Vraag Apple alleen of een wijzerplaattype geldig is; niets installeren."),
        ("T8 · Positieve Apple-controle", "Vergelijk een aantoonbaar beschikbare Apple-wijzerplaat met Hermès."),
        ("T9 · Migratie-lookup", "Vergelijk lokaal de gewone en Apple's migratiegerichte Hermès-FaceBundle-lookup."),
        ("T10 · Hermès 2025-apparaatcontrole", "Meet echte categorie, merk en collectie van de Watch zonder MobileGestalt te veranderen."),
        ("T11 · TCC CVE-2026-86886", "Controleer Apple's TCC-dienst en rechten, zonder pad-traversal of schrijven."),
        ("T12 · CoreMedia CVE-2026-86876", "Controleer CoreMedia-beschikbaarheid en een veilige lege buffer."),
        ("T13 · IOSurface CVE-2026-112477", "Controleer de echte IOSurfaceRoot-dienst zonder de kernelcrash te triggeren.")
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Native Hermès · systeemonderzoek")
                    .font(.headline)
                Text("T1–T6 meten rechten. T7–T10 onderzoeken native gezichten; T11–T13 controleren CVE-voorwaarden zonder race-exploits of systeemwijzigingen.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                ForEach(Array(scenarios.enumerated()), id: \.offset) { index, item in
                    VStack(alignment: .leading, spacing: 5) {
                        Button(item.0) { run(index) }
                            .buttonStyle(.borderedProminent)
                            .disabled(isRunning)
                        Text(item.1)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Button("Alle 6 lezen en meten") { runAll() }
                    .buttonStyle(.bordered)
                    .disabled(isRunning)

                if isRunning { ProgressView("Onderzoeken…") }

                Text(report)
                    .font(.system(size: 10, design: .monospaced))
            }
            .padding()
        }
        .navigationTitle("Native Face Lab")
    }

    private func run(_ index: Int) {
        guard !isRunning else { return }
        isRunning = true
        Task.detached(priority: .utility) {
            let (name, output): (String, String)
            switch index {
            case 0:
                name = "native-face-mach-policy.txt"
                output = BQRunNativeFaceMachPolicy() as String
            case 1:
                name = "native-face-bootstrap-lookup.txt"
                output = BQRunNativeFaceBootstrapLookup() as String
            case 2:
                name = "native-face-store-policy.txt"
                output = BQRunNativeFaceStorePolicy() as String
            case 4:
                name = "protected-writer-service-gate.txt"
                output = BQRunProtectedWriterServiceGate() as String
            case 5:
                name = "trusted-daemon-policy-differential.txt"
                output = BQRunTrustedDaemonPolicyDifferential() as String
            case 6:
                name = "clockkit-readonly-face-validation.txt"
                output = BQRunClockKitReadOnlyFaceValidation() as String
            case 7:
                name = "clockkit-availability-differential.txt"
                output = BQRunClockKitAvailabilityDifferential() as String
            case 8:
                name = "clockkit-migration-local-differential.txt"
                output = BQRunClockKitMigrationLookupDifferential() as String
            case 9:
                name = "hermes2025-live-identity-gates.txt"
                output = BQRunOriginalHermes2025IdentityGates() as String
            case 10:
                name = "cve-2026-86886-tcc-reachability.txt"
                output = BQRunTCC86886Reachability() as String
            case 11:
                name = "cve-2026-86876-coremedia-reachability.txt"
                output = BQRunCoreMedia86876Reachability() as String
            case 12:
                name = "cve-2026-112477-iosurface-service-preconditions.txt"
                output = BQRunIOSurface112477Reachability() as String
            default:
                name = "native-face-bundle-inventory.txt"
                output = BQRunNativeFaceBundleInventory() as String
            }
            let transfer = await WatchConnectivityManager.shared.sendDiagnosticReport(
                name: name, text: output
            )
            await MainActor.run {
                report = output + (transfer ? "\n\nNaar iPhone verzonden." : "\n\nLokaal opgeslagen; synchroniseer logs later.")
                isRunning = false
            }
        }
    }

    private func runAll() {
        guard !isRunning else { return }
        isRunning = true
        Task.detached(priority: .utility) {
            let results: [(String, String)] = [
                ("native-face-mach-policy.txt", BQRunNativeFaceMachPolicy() as String),
                ("native-face-bootstrap-lookup.txt", BQRunNativeFaceBootstrapLookup() as String),
                ("native-face-store-policy.txt", BQRunNativeFaceStorePolicy() as String),
                ("native-face-bundle-inventory.txt", BQRunNativeFaceBundleInventory() as String),
                ("protected-writer-service-gate.txt", BQRunProtectedWriterServiceGate() as String),
                ("trusted-daemon-policy-differential.txt", BQRunTrustedDaemonPolicyDifferential() as String)
            ]
            for (name, text) in results {
                _ = await WatchConnectivityManager.shared.sendDiagnosticReport(name: name, text: text)
            }
            await MainActor.run {
                report = results.map { $0.1 }.joined(separator: "\n\n")
                isRunning = false
            }
        }
    }
}
