import SwiftUI
import UniformTypeIdentifiers
import ClockKit

// MARK: - Content View

struct ContentView: View {

    @StateObject private var watchManager = WatchConnectivityManager()
    @Environment(\.scenePhase) private var scenePhase

    @State private var showingHistory = false
    @State private var showingImporter = false
    @State private var showingFaceImporter = false
    @State private var faceImportInProgress = false
    @State private var faceImportOutcome = "Nog geen native import geprobeerd."
    @State private var faceImportLogURL: URL?
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
            isPresented: $showingFaceImporter,
            allowedContentTypes: [.item],
            allowsMultipleSelection: false
        ) { result in
            handleFaceImport(result)
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
                Text("Echte systeemimport · ClockKit")
                    .font(.headline)
                Text("Probeert een bestaande .watchface via Apple's officiële API aan de Watch-collectie toe te voegen. Geen preview of sandbox-test. Hermès wordt op niet-Hermès hardware doorgaans geweigerd.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Button {
                    showingFaceImporter = true
                } label: {
                    Label(
                        faceImportInProgress ? "ClockKit verwerkt verzoek…" : "Probeer wijzerplaat toe te voegen",
                        systemImage: "applewatch.watchface"
                    )
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(faceImportInProgress)

                Text(faceImportOutcome)
                    .font(.footnote)
                    .textSelection(.enabled)
                if let faceImportLogURL {
                    Button {
                        shareURL = ShareItem(url: faceImportLogURL)
                    } label: {
                        Label("Deel resultaatlog", systemImage: "square.and.arrow.up")
                    }
                    .buttonStyle(.bordered)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

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

    // MARK: - Functional system-face import (iPhone)
    //
    // Unlike the Watch-side read-only lab, this sends a genuine add request
    // to Apple's ClockKit system API. It does not bypass hardware eligibility.
    // Only a user-selected .watchface file is used; protected paths are untouched.

    private func handleFaceImport(_ result: Result<[URL], Error>) {
        switch result {
        case .failure(let error):
            recordFaceImport("Bestandskeuze mislukt: \(error.localizedDescription)", file: "(none)")
        case .success(let urls):
            guard let source = urls.first else {
                recordFaceImport("Geen bestand gekozen.", file: "(none)")
                return
            }
            guard source.pathExtension.lowercased() == "watchface" else {
                recordFaceImport("Geen .watchface-bestand: \(source.lastPathComponent)", file: source.lastPathComponent)
                return
            }

            let scoped = source.startAccessingSecurityScopedResource()
            defer { if scoped { source.stopAccessingSecurityScopedResource() } }
            let local = FileManager.default.temporaryDirectory
                .appendingPathComponent("native-face-\(UUID().uuidString).watchface")
            do {
                try FileManager.default.copyItem(at: source, to: local)
            } catch {
                recordFaceImport("Kan bestand niet lokaal kopiëren: \(error.localizedDescription)", file: source.lastPathComponent)
                return
            }

            let filename = source.lastPathComponent
            faceImportInProgress = true
            faceImportOutcome = "ClockKit.addWatchFace(at:) aangeroepen voor \(filename)…"
            CLKWatchFaceLibrary().addWatchFace(at: local) { error in
                DispatchQueue.main.async {
                    self.faceImportInProgress = false
                    if let error {
                        let nsError = error as NSError
                        self.recordFaceImport(
                            "AFGEWEZEN: \(error.localizedDescription)\nNSError domain=\(nsError.domain); code=\(nsError.code)",
                            file: filename
                        )
                    } else {
                        self.recordFaceImport(
                            "AANVAARD: ClockKit heeft de toevoeging verwerkt. Controleer de Watch-app; dit bewijst niet dat de wijzerplaat al actief is.",
                            file: filename
                        )
                    }
                    try? FileManager.default.removeItem(at: local)
                }
            }
        }
    }

    private func recordFaceImport(_ outcome: String, file: String) {
        faceImportOutcome = outcome
        let report = """
        === Native Watch Face · functional system import ===
        Time: \(ISO8601DateFormatter().string(from: Date()))
        Host: iOS companion
        API: CLKWatchFaceLibrary.addWatchFace(at:completionHandler:)
        Source: \(file)
        Result: \(outcome)

        Note: hardware restrictions (including Hermès) remain enforced by Apple.
        The operation modifies no MobileGestalt file or protected system store directly.
        """
        let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("native-watchface-import-last-result.txt")
        do {
            try report.write(to: url, atomically: true, encoding: .utf8)
            faceImportLogURL = url
        } catch {
            faceImportOutcome += "\nOpslaan log mislukt: \(error.localizedDescription)"
        }
        NSLog("[NativeFaceImport] %@", report)
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
