import SwiftUI

/// One action scans every read-only route; existing feature controls are
/// available immediately when the user has an original backup.
struct RouteDiagnosticsView: View {
    let model: ContentModel

    @State private var report = "Diagnostics v3 compares token types, container root versus Caches, Geod direct access and the existing routes. Each query reports errors and file-open permissions."
    @State private var running = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("WatchOS 26 • Diagnostics v3")
                    .font(.headline)
                Text("Tests MCM routes plus independent system entitlement, sandbox-policy, daemon-surface and filesystem checks. The Watch's protected MobileGestalt file is never changed by the scan.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                Button {
                    runTests()
                } label: {
                    HStack {
                        if running { ProgressView() }
                        Text(running ? "Testing all routes…" : "Run All Routes")
                    }
                }
                .disabled(running)
                .buttonStyle(.borderedProminent)

                Divider()

                Text("Quick Settings").font(.headline)
                if !model.hasBackup {
                    Text("First create an original MobileGestalt backup. Diagnostics are available without one.")
                        .font(.footnote)
                    Button("Create Initial Backup") { model.perform(.backup) }
                        .disabled(running)
                } else {
                    Toggle("Hermès Faces", isOn: Binding(
                        get: { model.hermesEnabled },
                        set: { model.perform(.hermes($0)) }
                    ))
                    Toggle("Ultra Faces", isOn: Binding(
                        get: { model.ultraFacesEnabled },
                        set: { model.perform(.ultraFaces($0)) }
                    ))
                    NavigationLink {
                        WatchFacesView(model: model)
                    } label: {
                        Label("Watch Face Settings", systemImage: "clock")
                    }
                    NavigationLink {
                        DisplayAndControlsView(model: model)
                    } label: {
                        Label("Display & Controls", systemImage: "switch.2")
                    }
                }

                Text(model.message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Divider()
                Text("Test Report").font(.headline)
                Text(report)
                    .font(.system(size: 10, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding()
        }
        .navigationTitle("All Route Tests")
        .onAppear {
            if model.hasBackup { model.refreshCapabilityStates() }
        }
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
