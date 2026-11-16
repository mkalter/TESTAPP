import SwiftUI

/// Non-destructive diagnostic tests; the manual legacy write-open probe is separate.
struct MGPermissionDiagnosticsView: View {
    @State private var report = "Run the test to distinguish App Group access, MobileGestalt reads and protected write authorization."
    @State private var running = false
    @State private var transferStatus = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Permission Diagnostics")
                    .font(.headline)
                Text("Resultaten worden automatisch naar de iPhone gestuurd. Open HermesEnabler → Watch Logs voor de volledige rapporten.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                if !transferStatus.isEmpty {
                    Label(transferStatus, systemImage: "iphone.gen3")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Button("Run complete diagnostics") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        // Run only once, in a fixed order. No protected writes.
                        let entitlements = BQRunRuntimeEntitlementDiagnostics() as String
                        let gates = BQRunWriteGateDiagnostics() as String
                        let baseline = BQRunPermissionDiagnostics() as String
                        let class7 = BQRunClass7ControlMatrix() as String
                        let kamui = BQRunKAMUI26TokenProbe() as String
                        let extended = BQRunExtendedAuthorizationMatrix() as String
                        let combined = [entitlements, gates, baseline, class7, kamui, extended].joined(separator: "\n\n")
                        _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
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
                        _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "mg-permission-diagnostics.txt", text: output
                        )
                        await MainActor.run {
                            report = output as String
                            running = false
                        }
                    }
                }
                .disabled(running)

                Button(running ? "Testing…" : "Check actual entitlements (new)") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        let output = BQRunRuntimeEntitlementDiagnostics() as String
                        let queued = WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "watch-entitlement-audit.txt", text: output
                        )
                        await MainActor.run {
                            report = output
                            transferStatus = queued
                                ? "Entitlement-rapport in de wachtrij voor je iPhone. Open HermesEnabler → Watch Logs."
                                : "Overdracht niet in wachtrij gezet. Open de iPhone-app en probeer 'Send logs to iPhone' opnieuw."
                            running = false
                        }
                    }
                }
                .disabled(running)

                Button("Run extended authorization matrix (60+ checks)") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        let output = BQRunExtendedAuthorizationMatrix() as String
                        _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "extended-authorization-matrix.txt", text: output
                        )
                        await MainActor.run {
                            report = output
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
                        _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
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
                        _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "kamui26-token-probe.txt", text: output
                        )
                        await MainActor.run {
                            report = output as String
                            running = false
                        }
                    }
                }
                .disabled(running)

                Button("Test Class 13 direct + file (no writes)") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        let output = BQRunKAMUI26WriteOpenTest() as String
                        _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
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
                        _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
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
                    transferStatus = "Overdracht van opgeslagen logs aangevraagd."
                    report = "Open HermesEnabler → Watch Logs op je iPhone. Tik eventueel op 'Vraag logs op van Apple Watch'."
                } label: {
                    Label("Send logs to iPhone", systemImage: "iphone.gen3")
                }
                .disabled(running)

                if running {
                    ProgressView()
                }

                Text(report)
                    .font(.system(size: 10, design: .monospaced))
            }
            .padding()
        }
        .navigationTitle("MG Diagnostics")
    }
}
