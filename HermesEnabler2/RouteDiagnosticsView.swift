import SwiftUI

/// Separately runnable sandbox-permission diagnostics. No MobileGestalt writes.
struct RouteDiagnosticsView: View {
    @State private var report = "Press Run Tests to inspect Class 13 and Class 12 access."
    @State private var running = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("WorstGestalt / Geod")
                    .font(.headline)
                Text("Compares the per-file Class 13 query with the Geod Class 12 query. The test opens the protected plist with O_RDONLY and O_RDWR, then closes it without writing.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Button {
                    runTests()
                } label: {
                    HStack {
                        if running { ProgressView() }
                        Text(running ? "Testing..." : "Run Tests")
                    }
                }
                .disabled(running)
                .buttonStyle(.borderedProminent)

                Text(report)
                    .font(.system(size: 10, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding()
        }
        .navigationTitle("Route Tests")
    }

    private func runTests() {
        guard !running else { return }
        running = true
        Task {
            let output = await Task.detached(priority: .userInitiated) {
                BQRunRouteDiagnostics() as String
            }.value
            report = output
            running = false
        }
    }
}
