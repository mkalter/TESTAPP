import SwiftUI
import UniformTypeIdentifiers
import ClockKit

// MARK: - Content View

struct ContentView: View {

    @StateObject private var watchManager = WatchConnectivityManager()
    @Environment(\.scenePhase) private var scenePhase

    @State private var showingHistory = false
    @State private var showingImporter = false
    @State private var showingSystemFaceImporter = false
    @State private var shareURL: ShareItem?
    @State private var alertMessage = ""
    @State private var showingAlert = false

    var body: some View {

        NavigationStack {

            ScrollView {

                VStack(spacing: 22) {

                    WatchDeviceCard(watchManager: watchManager)
                    WatchInstallationCard(watchManager: watchManager)
                    LatestBackupCard(watchManager: watchManager)

                    NavigationLink {
                        DiagnosticLogsView(manager: watchManager)
                    } label: {
                        HStack(spacing: 14) {
                            Image(systemName: "waveform.path.ecg.rectangle")
                                .font(.title2)
                                .foregroundStyle(.tint)
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Watch Logs")
                                    .font(.headline)
                                    .foregroundStyle(.primary)
                                Text("\(watchManager.diagnosticLogs.count) logbestanden · Bekijken, kopiëren en delen")
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer(minLength: 0)
                            Image(systemName: "chevron.right")
                                .font(.footnote.weight(.semibold))
                                .foregroundStyle(.tertiary)
                        }
                        .padding(16)
                        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
                    }
                    .buttonStyle(.plain)

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
        .fileImporter(
            isPresented: $showingSystemFaceImporter,
            allowedContentTypes: [UTType(filenameExtension: "watchface") ?? .data],
            allowsMultipleSelection: false
        ) { result in
            handleSystemFaceImport(result)
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
                watchManager.refreshDiagnosticLogs()
            }
        }
    }

    // MARK: - Main actions

    private var actionButtons: some View {

        VStack(spacing: 12) {

            VStack(alignment: .leading, spacing: 8) {
                Label("Native systeemwijzerplaat", systemImage: "applewatch.watchface")
                    .font(.headline)
                Text("Importeer een originele gedeelde .watchface via Apple's ClockKit. Dit probeert de wijzerplaat aan het systeem toe te voegen, niet aan HermesEnabler. Een exclusieve Hermès-wijzerplaat kan alsnog door Apple worden geweigerd.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Button {
                    showingSystemFaceImporter = true
                } label: {
                    Label("Importeer .watchface naar Apple Watch", systemImage: "square.and.arrow.down.on.square")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 5)
                }
                .buttonStyle(.bordered)
            }
            .padding(14)
            .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))

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

    // MARK: - Native Apple Watch system face import (not an in-app viewer)

    private func handleSystemFaceImport(_ result: Result<[URL], Error>) {
        switch result {
        case .failure(let error):
            showMessage("Bestand kiezen mislukt: \(error.localizedDescription)")
        case .success(let urls):
            guard let source = urls.first,
                  source.pathExtension.lowercased() == "watchface" else {
                showMessage("Selecteer een geldig .watchface-bestand dat vanaf een Apple Watch is gedeeld.")
                return
            }
            let accessed = source.startAccessingSecurityScopedResource()
            defer {
                if accessed { source.stopAccessingSecurityScopedResource() }
            }

            let temporary = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString)
                .appendingPathExtension("watchface")
            do {
                try FileManager.default.copyItem(at: source, to: temporary)
            } catch {
                showMessage("Kon .watchface niet lokaal openen: \(error.localizedDescription)")
                return
            }

            // This is Apple's first-party system face sharing API on the
            // paired iPhone, not a NanoTimeKit preview or MobileGestalt edit.
            CLKWatchFaceLibrary().addWatchFace(at: temporary) { error in
                DispatchQueue.main.async {
                    try? FileManager.default.removeItem(at: temporary)
                    if let error {
                        let nsError = error as NSError
                        self.showMessage(
                            "Apple heeft de systeemwijzerplaat geweigerd. " +
                            "Domein: \(nsError.domain), code: \(nsError.code). " +
                            nsError.localizedDescription +
                            "\nEen beperkte Hermès-wijzerplaat kan door de modelcontrole worden afgewezen."
                        )
                    } else {
                        self.showMessage(
                            "De systeemimport is door Apple verwerkt. Controleer de wijzerplaten in de Watch-app en op je Apple Watch."
                        )
                    }
                }
            }
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
