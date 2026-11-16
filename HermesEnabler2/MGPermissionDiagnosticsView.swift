import SwiftUI

/// Manually triggered, non-destructive permission checks. No BQEscape calls.
struct MGPermissionDiagnosticsView: View {
    @State private var report = "Run the test to distinguish App Group access, MobileGestalt reads and protected write authorization."
    @State private var running = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Permission Diagnostics")
                    .font(.headline)
                Text("Tests permissions only. It never changes MobileGestalt or requests a sandbox extension. A temporary control file is created only inside your own App Group.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

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
