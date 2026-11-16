import SwiftUI

/// Manually triggered, non-destructive tests; no BQEscape calls or system writes.
struct MGPermissionDiagnosticsView: View {
    @State private var report = "Run the test to distinguish App Group access, MobileGestalt reads and protected write authorization."
    @State private var running = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Permission Diagnostics")
                    .font(.headline)
                Text("Resultaten worden automatisch naar de iPhone gestuurd. Open HermesEnabler → Watch Logs voor de volledige rapporten.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                Button("Run complete diagnostics") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        // Run only once, in a fixed order. No protected writes.
                        let gates = BQRunWriteGateDiagnostics() as String
                        let baseline = BQRunPermissionDiagnostics() as String
                        let class7 = BQRunClass7ControlMatrix() as String
                        let kamui = BQRunKAMUI26TokenProbe() as String
                        let combined = [gates, baseline, class7, kamui].joined(separator: "\n\n")
                        _ = WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "complete-diagnostics.txt", text: combined
                        )
                        await MainActor.run {
                            report = combined
                            running = false
                        }
                    }
                }
                .disabled(running)

                Button(running ? "Testing…" : "Run one test") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        let output = BQRunPermissionDiagnostics() as String
                        _ = WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "mg-permission-diagnostics.txt", text: output
                        )
                        await MainActor.run {
                            report = output as String
                            running = false
                        }
                    }
                }
                .disabled(running)

                Button("Run Class 7 flag matrix") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        let output = BQRunClass7ControlMatrix() as String
                        _ = WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "class7-flag-matrix.txt", text: output
                        )
                        await MainActor.run {
                            report = output as String
                            running = false
                        }
                    }
                }
                .disabled(running)

                Button("Run KAMUI 26 token probe") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        let output = BQRunKAMUI26TokenProbe() as String
                        _ = WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "kamui26-token-probe.txt", text: output
                        )
                        await MainActor.run {
                            report = output as String
                            running = false
                        }
                    }
                }
                .disabled(running)

                Button("Test Class 13 write-open (no writes)") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        let output = BQRunKAMUI26WriteOpenTest() as String
                        _ = WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "kamui26-write-open.txt", text: output
                        )
                        await MainActor.run {
                            report = output as String
                            running = false
                        }
                    }
                }
                .disabled(running)

                Button("Run write-authorization matrix") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        let output = BQRunWriteGateDiagnostics() as String
                        _ = WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "mg-write-gates.txt", text: output
                        )
                        await MainActor.run {
                            report = output as String
                            running = false
                        }
                    }
                }
                .disabled(running)

                Button {
                    WatchConnectivityManager.shared.transferSavedDiagnosticReports()
                    report = "Opgeslagen logs in de wachtrij gezet voor de iPhone. Open HermesEnabler → Watch Logs op je iPhone."
                } label: {
                    Label("Send logs to iPhone", systemImage: "iphone.gen3")
                }
                .disabled(running)

                if running {
                    ProgressView()
                }

                Text(report)
                    .font(.system(size: 10, design: .monospaced))
                    .textSelection(.enabled)
            }
            .padding()
        }
        .navigationTitle("MG Diagnostics")
    }
}
