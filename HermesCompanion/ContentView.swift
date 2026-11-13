import SwiftUI
import UniformTypeIdentifiers

// MARK: - Content View

struct ContentView: View {

    @StateObject private var watchManager = WatchConnectivityManager()
    @Environment(\.scenePhase) private var scenePhase

    @State private var activationRunning = false
    @State private var activationReport = "Hermès-activering nog niet geprobeerd."
    @State private var showingHistory = false
    @State private var showingImporter = false
    @State private var shareURL: ShareItem?
    @State private var alertMessage = ""
    @State private var showingAlert = false

    var body: some View {

        NavigationStack {

            ScrollView {

                VStack(spacing: 22) {

                    WatchDeviceCard(watchManager: watchManager)
                    WatchInstallationCard(watchManager: watchManager)

                    VStack(alignment: .leading, spacing: 10) {
                        Button {
                            activateHermes()
                        } label: {
                            HStack {
                                if activationRunning { ProgressView() }
                                Label(activationRunning ? "Hermès voorbereiden…" :
                                    "Activeer Hermès-wijzerplaat", systemImage: "clock.badge.checkmark")
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 7)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(activationRunning)

                        Text("Maakt een echte Hermès-face, probeert de gekoppelde Watch-bibliotheek en biedt zo mogelijk een native .watchface aan om via Apple Watch toe te voegen.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        Text(activationReport)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    LatestBackupCard(watchManager: watchManager)

                    NavigationLink {
                        RemoteWatchControlView(manager: watchManager)
                    } label: {
                        Label("Watch Tests & Feature Switches", systemImage: "applewatch.side.right")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding()
                    }
                    .buttonStyle(.borderedProminent)

                    actionButtons
                }
                .padding()
                .frame(maxWidth: 600)
                .frame(maxWidth: .infinity)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("HermesEnabler")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        watchManager.loadBackupHistory()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .accessibilityLabel("Refresh")
                }
            }
        }
        .sheet(isPresented: $showingHistory) {
            BackupHistoryView(manager: watchManager)
        }
        .sheet(item: $shareURL) { item in
            ActivityViewController(activityItems: [item.url])
        }
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [.propertyList],
            allowsMultipleSelection: false
        ) { result in
            handleImport(result)
        }
        .alert("HermesEnabler", isPresented: $showingAlert) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(alertMessage)
        }
        .onChange(of: scenePhase) { _, newPhase in
            if newPhase == .active {
                watchManager.refreshConnectionStatus()
                watchManager.loadBackupHistory()
            }
        }
    }

    // MARK: - Hermès activation

    private func activateHermes() {
        guard !activationRunning else { return }
        activationRunning = true
        activationReport = "Maakt een native Hermès-wijzerplaat en bereidt import voor…"
        HERMESAttemptFaceActivation { report, fileURL in
            DispatchQueue.main.async {
                activationRunning = false
                activationReport = report ?? "Geen rapport ontvangen van NanoTimeKit."
                if let fileURL {
                    shareURL = ShareItem(url: fileURL)
                }
            }
        }
    }

    // MARK: - Main actions

    private var actionButtons: some View {

        VStack(spacing: 12) {

            Button {
                showingImporter = true
            } label: {
                Label(
                    "Import Backup",
                    systemImage: "square.and.arrow.down"
                )
                .frame(maxWidth: .infinity)
                .padding(.vertical, 5)
            }
            .buttonStyle(.borderedProminent)

            Button {
                guard let latest = watchManager.latestBackup else {
                    showMessage(String(localized: "No backup to export."))
                    return
                }

                exportBackup(latest)

            } label: {
                Label(
                    "Export Latest Backup",
                    systemImage: "square.and.arrow.up"
                )
                .frame(maxWidth: .infinity)
                .padding(.vertical, 5)
            }
            .buttonStyle(.bordered)

            Button {
                watchManager.loadBackupHistory()
                showingHistory = true
            } label: {
                Label(
                    "Backup History",
                    systemImage: "clock.arrow.circlepath"
                )
                .frame(maxWidth: .infinity)
                .padding(.vertical, 5)
            }
            .buttonStyle(.bordered)
        }
    }

    // MARK: - Import

    private func handleImport(
        _ result: Result<[URL], Error>
    ) {

        switch result {

        case .success(let urls):

            guard let url = urls.first else {
                return
            }

            do {
                switch try watchManager.importBackup(from: url) {

                case .imported(let record):

                    showMessage(
                        String(localized: "Backup imported successfully. Size: \(record.formattedSize).")
                    )

                case .duplicate:

                    showMessage(
                        String(localized: "An identical backup is already in the history.")
                    )
                }

            } catch {

                showMessage(
                    String(localized: "Could not import the backup:\n\(error.localizedDescription)")
                )
            }

        case .failure(let error):

            showMessage(
                String(localized: "Could not select the file:\n\(error.localizedDescription)")
            )
        }
    }

    // MARK: - Export

    private func exportBackup(
        _ record: WatchConnectivityManager.BackupRecord
    ) {

        guard let url = watchManager.exportURL(for: record) else {
            showMessage(String(localized: "The file to export could not be found."))
            return
        }

        shareURL = ShareItem(url: url)
    }

    // MARK: - Alert

    private func showMessage(_ message: String) {
        alertMessage = message
        showingAlert = true
    }
}
