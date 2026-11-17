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
    @State private var omitClientFaceValidation = false
    @State private var latestNativeImportLog = ""
    @State private var latestGeneratedHermesURL: URL?
    @State private var importingGeneratedHermes = false
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
                Text("Je hoeft geen .watchface meer op te zoeken. Maak hieronder een testbestand dat verwijst naar Apple's bestaande NTKPoodleFaceBundle en probeer de systeemimport.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Button {
                    testGeneratedHermesFace()
                } label: {
                    Label("Maak en test Hermès Circulaire (zonder bestand)", systemImage: "applewatch.watchface")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 5)
                }
                .buttonStyle(.borderedProminent)
                .disabled(importingGeneratedHermes)
                if latestGeneratedHermesURL != nil {
                    Button {
                        if let url = latestGeneratedHermesURL {
                            shareURL = ShareItem(url: url)
                        }
                    } label: {
                        Label("Deel gegenereerd testbestand via Berichten", systemImage: "square.and.arrow.up")
                    }
                    .buttonStyle(.bordered)
                }
                Text("Dit maakt een nieuw ZIP-testbestand met de originele native bundel-ID en forMigration=true; het extraheert geen Hermès-wijzerplaat of afbeeldingen van je Watch. De systeemcontrole kan de import nog steeds weigeren.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Divider()
                Button {
                    omitClientFaceValidation = false
                    showingSystemFaceImporter = true
                } label: {
                    Label("Normale systeemimport (controle)", systemImage: "checkmark.shield")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 5)
                }
                .buttonStyle(.bordered)
                Button {
                    omitClientFaceValidation = true
                    showingSystemFaceImporter = true
                } label: {
                    Label("TEST: systeemimport zonder iPhone-voorcheck", systemImage: "applewatch.watchface")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 5)
                }
                .buttonStyle(.borderedProminent)
                Text("Gebruikt Apple's echte ClockKit-systeemimport, maar slaat de eerste clientvalidatie over. De Apple Watch kan Hermès alsnog weigeren. Alleen originele, vertrouwde .watchface-bestanden testen.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if !latestNativeImportLog.isEmpty {
                    Button {
                        UIPasteboard.general.string = latestNativeImportLog
                    } label: {
                        Label("Kopieer laatste echte importresultaat", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.bordered)
                    .font(.footnote)
                }
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

    // A self-contained import experiment. No Watch or iPhone private files
    // are accessed; the generated ZIP references the existing native bundle.
    private func testGeneratedHermesFace() {
        guard !importingGeneratedHermes else { return }
        let url: URL
        do {
            url = try HermesSystemFaceCandidate.create(migration: true)
        } catch {
            showMessage("Kon het synthetische watchface-testbestand niet maken: \(error.localizedDescription)")
            return
        }

        latestGeneratedHermesURL = url
        importingGeneratedHermes = true

        NativeSystemFaceImportProbe.importFaceSkippingClientValidation(at: url) { error in
            DispatchQueue.main.async {
                importingGeneratedHermes = false
                let status: String
                if let error {
                    let nsError = error as NSError
                    status = "DENIED domain=\(nsError.domain) code=\(nsError.code) description=\(nsError.localizedDescription)"
                } else {
                    status = "NO_IMMEDIATE_ERROR (not proof of installation)"
                }

                let log = """
                === Synthetic Circulaire native ClockKit test ===
                datetime=\(Date().formatted(.iso8601))
                iOS=\(ProcessInfo.processInfo.operatingSystemVersionString)
                file=\(url.lastPathComponent)
                archive=GENERATED_NOT_EXTRACTED_FROM_WATCH
                nativeBundle=com.apple.NTKPoodleFaceBundle
                forMigration=true
                clientPrevalidation=SKIPPED_IF_PRIVATE_API_EXISTS
                result=\(status)
                verifyActualNativeWatchFaceGallery=YES
                MobileGestaltWrites=NONE
                """
                latestNativeImportLog = log
                showMessage(log)
            }
        }
    }

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

            // Two real system import paths, both use Apple's ClockKit server.
            // The experimental route omits only the early iPhone-side precheck.
            // A callback without an error does not prove Watch installation.
            let testNoClientCheck = omitClientFaceValidation
            let finish: (Error?) -> Void = { error in
                DispatchQueue.main.async {
                    try? FileManager.default.removeItem(at: temporary)
                    let mode = testNoClientCheck
                        ? "TEST ZONDER IPHONE-VOORCHECK"
                        : "STANDAARD IMPORT"
                    let status: String
                    if let error {
                        let nsError = error as NSError
                        status = "result=DENIED domain=\(nsError.domain) code=\(nsError.code) description=\(nsError.localizedDescription)"
                    } else {
                        status = "result=NO_IMMEDIATE_ERROR (NOT proof of installation)"
                    }
                    let log = """
                    === Native Apple system ClockKit import ===
                    datetime=\(Date().formatted(.iso8601))
                    iOS=\(ProcessInfo.processInfo.operatingSystemVersionString)
                    file=\(source.lastPathComponent)
                    mode=\(mode)
                    \(status)
                    requires_actual_Apple_face_gallery_verification=YES
                    protected_MobileGestalt_writes=NONE
                    """
                    latestNativeImportLog = log
                    self.showMessage(log)
                }
            }

            if testNoClientCheck {
                NativeSystemFaceImportProbe.importFaceSkippingClientValidation(
                    at: temporary,
                    completion: finish
                )
            } else {
                CLKWatchFaceLibrary().addWatchFace(at: temporary, completionHandler: finish)
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
