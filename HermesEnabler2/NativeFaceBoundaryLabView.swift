import SwiftUI

/// Four independently runnable read-only tests of Apple's *native* watchOS
/// ClockFace / NanoTimeKit availability chain. No watch faces are installed.
struct NativeFaceBoundaryLabView: View {
    @State private var report = "Kies één test. De volledige log wordt naar de iPhone gestuurd."
    @State private var isRunning = false

    private let scenarios: [(String, String)] = [
        ("T1 · Mach-beleid", "Welke originele Apple-wijzerplaatdiensten staat de sandbox toe?"),
        ("T2 · Bootstrap-lookup", "Kunnen we de dienstnaam vinden, zonder XPC-berichten te sturen?"),
        ("T3 · Systeemopslag", "Bestaan de NanoTimeKit-mappen en welke lees-/schrijfrechten meldt het OS?"),
        ("T4 · Originele FaceBundles", "Zijn Zeus/Hermès2025-bundels op de Watch via het bestandssysteem zichtbaar?")
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Native Hermès · systeemonderzoek")
                    .font(.headline)
                Text("Deze tests controleren Apple's eigen ClockFace/Carousel. Het zijn geen nepwijzerplaten, imports of schrijfpogingen.")
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

                Button("Alle 4 lezen en meten") { runAll() }
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
                ("native-face-bundle-inventory.txt", BQRunNativeFaceBundleInventory() as String)
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
