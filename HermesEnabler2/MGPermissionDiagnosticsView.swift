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
                Text("The first test checks permissions without requesting an extension. The Class 7 matrix tests extension behavior only for your own App Group, without symlinks or protected writes.")
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
                        let combined = [gates, baseline, class7].joined(separator: "\n\n")
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
                        let output = BQRunPermissionDiagnostics()
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
                        let output = BQRunClass7ControlMatrix()
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
                        let output = BQRunWriteGateDiagnostics()
                        await MainActor.run {
                            report = output as String
                            running = false
                        }
                    }
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
