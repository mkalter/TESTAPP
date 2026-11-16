import SwiftUI

/// Diagnostic reports transferred from the Apple Watch. Files are stored locally
/// on the iPhone so they remain readable even when the Watch is disconnected.
struct DiagnosticLogsView: View {
    @ObservedObject var manager: WatchConnectivityManager

    var body: some View {
        List {
            Section {
                Button {
                    manager.requestDiagnosticLogs()
                } label: {
                    Label("Vraag logs op van Apple Watch", systemImage: "arrow.down.circle")
                }
                .disabled(!manager.isPaired || !manager.isWatchAppInstalled)

                Text(manager.diagnosticsStatus)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Synchronisatie")
            } footer: {
                Text("Overdracht via WatchConnectivity. De Watch mag tijdelijk offline zijn. Open de Watch-app om de verzending te versnellen.")
            }

            Section {
                if manager.diagnosticLogs.isEmpty {
                    ContentUnavailableView(
                        "Nog geen logs",
                        systemImage: "doc.text.magnifyingglass",
                        description: Text("Voer op de Apple Watch een test uit, of vraag bestaande logs hierboven op.")
                    )
                } else {
                    ForEach(manager.diagnosticLogs) { log in
                        NavigationLink {
                            DiagnosticLogDetailView(manager: manager, log: log)
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(log.originalName)
                                    .font(.subheadline.weight(.semibold))
                                    .lineLimit(2)
                                HStack(spacing: 8) {
                                    Text(log.formattedDate)
                                    Text("·")
                                    Text(log.formattedSize)
                                }
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            }
                            .padding(.vertical, 3)
                        }
                    }
                }
            } header: {
                Text("Ontvangen logbestanden (\(manager.diagnosticLogs.count))")
            }
        }
        .navigationTitle("Watch Logs")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    manager.refreshDiagnosticLogs()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .accessibilityLabel("Ververs logs")
            }
        }
        .onAppear { manager.refreshDiagnosticLogs() }
    }
}

private struct DiagnosticLogDetailView: View {
    @ObservedObject var manager: WatchConnectivityManager
    let log: WatchConnectivityManager.DiagnosticLog
    @State private var content = "Logbestand laden…"

    var body: some View {
        ScrollView([.vertical, .horizontal]) {
            Text(content)
                .font(.system(size: 11, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
        }
        .background(Color(uiColor: .secondarySystemBackground))
        .navigationTitle(log.originalName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button {
                    UIPasteboard.general.string = content
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .accessibilityLabel("Kopieer log")

                if let url = manager.diagnosticURL(for: log) {
                    ShareLink(item: url) {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .accessibilityLabel("Deel logbestand")
                }
            }
        }
        .onAppear {
            guard let url = manager.diagnosticURL(for: log) else {
                content = "Het logbestand bestaat niet meer."
                return
            }
            do {
                content = try String(contentsOf: url, encoding: .utf8)
            } catch {
                content = "Logbestand lezen mislukt: \(error.localizedDescription)"
            }
        }
    }
}
