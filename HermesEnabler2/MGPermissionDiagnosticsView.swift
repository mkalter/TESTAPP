import SwiftUI

/// Non-destructive diagnostic tests; the manual legacy write-open probe is separate.
struct MGPermissionDiagnosticsView: View {
    @State private var report = "Run the test to distinguish App Group access, MobileGestalt reads and protected write authorization."
    @State private var running = false
    @State private var confirmMGSetter = false
    @State private var confirmIOKitWriter = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Permission Diagnostics")
                    .font(.headline)
                Text("Resultaten worden automatisch naar de iPhone gestuurd. Open HermesEnabler → Watch Logs voor de volledige rapporten.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                Text("EXPERIMENT · NIEUWE WRITE-ROUTE")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.orange)
                Text("Deze proef roept de echte private MGSetAnswer setter aan. Er wordt vooraf een back-up gemaakt. Dit is geen herhaling van de permissiematrix.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Text("ANDERE SCHRIJFROUTE · IOKit (3 methodes)")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.orange)
                Text("Controleer eerst of de DeviceBrand-broneigenschap werkelijk bestaat en welk datatype die heeft. Alleen bij een geldige originele CFData worden de drie IOKit-setters aangeroepen.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Button("TEST: IORegistry property + 3 setters") {
                    confirmIOKitWriter = true
                }
                .disabled(running)

                Button("TEST: MGSetAnswer schrijftest") {
                    confirmMGSetter = true
                }
                .disabled(running)

                Button("CHECK: MGSetAnswer na herstart") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        let output = BQCheckMGSetAnswerCanary() as String
                        _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "mgsetanswer-persistence.txt", text: output
                        )
                        await MainActor.run {
                            report = output
                            running = false
                        }
                    }
                }
                .disabled(running)

                Button("Run complete diagnostics") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        // Run only once, in a fixed order. No protected writes.
                        let gates = BQRunWriteGateDiagnostics() as String
                        let baseline = BQRunPermissionDiagnostics() as String
                        let class7 = BQRunClass7ControlMatrix() as String
                        let kamui = BQRunKAMUI26TokenProbe() as String
                        let extended = BQRunExtendedAuthorizationMatrix() as String
                        let combined = [gates, baseline, class7, kamui, extended].joined(separator: "\n\n")
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

                Button("Test path permissions (own files only)") {
                    guard !running else { return }
                    running = true
                    Task.detached(priority: .utility) {
                        let output = BQRunPathAuthorizationDifferential() as String
                        _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
                            name: "path-authorization-differential.txt", text: output
                        )
                        await MainActor.run {
                            report = output
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
            }
            .padding()
        }
        .navigationTitle("MG Diagnostics")
        .confirmationDialog(
            "Drie IOKit-schrijfproeven uitvoeren?",
            isPresented: $confirmIOKitWriter,
            titleVisibility: .visible
        ) {
            Button("Probeer drie IOKit-setters") {
                guard !running else { return }
                running = true
                Task.detached(priority: .utility) {
                    let output = BQRunIODeviceTreeWriteProbe() as String
                    _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
                        name: "iodevicetree-write-probe.txt", text: output
                    )
                    await MainActor.run {
                        report = output
                        running = false
                    }
                }
            }
            Button("Annuleren", role: .cancel) { }
        } message: {
            Text("De app leest eerst /chosen, / en /options. Alleen als marketing-software-behavior daadwerkelijk als CFData bestaat, worden IOKit-setters met identieke data aangeroepen. Geen ontbrekende eigenschap wordt aangemaakt.")
        }
        .confirmationDialog(
            "MGSetAnswer echt uitvoeren?",
            isPresented: $confirmMGSetter,
            titleVisibility: .visible
        ) {
            Button("Voer directe settertest uit") {
                guard !running else { return }
                running = true
                Task.detached(priority: .utility) {
                    let output = BQRunMGSetAnswerWriteExperiment() as String
                    _ = await WatchConnectivityManager.shared.sendDiagnosticReport(
                        name: "mgsetanswer-experiment.txt", text: output
                    )
                    await MainActor.run {
                        report = output
                        running = false
                    }
                }
            }
            Button("Annuleren", role: .cancel) { }
        } message: {
            Text("Deze proef roept daadwerkelijk een private Apple-setter aan. Er wordt alleen getest als een gevalideerde MG-back-up kan worden aangemaakt. De effecten op watchOS 26 zijn onbekend.")
        }
    }
}
