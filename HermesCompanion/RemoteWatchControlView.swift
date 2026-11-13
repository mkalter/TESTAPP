import SwiftUI

/// All operations are sent to the paired Watch app using WatchConnectivity.
/// Nothing in this iPhone screen touches an iPhone MobileGestalt cache.
struct RemoteWatchControlView: View {
    @ObservedObject var manager: WatchConnectivityManager

    struct Feature: Identifiable {
        let id: String
        let title: String
    }
    struct Group: Identifiable {
        let id: String
        let features: [Feature]
    }

    private let groups: [Group] = [
        Group(id: "Watch Faces", features: [
            Feature(id: "hermes", title: "Hermès Faces"),
            Feature(id: "ultraFaces", title: "Ultra Faces")
        ]),
        Group(id: "Display & Controls", features: [
            Feature(id: "aod", title: "Always-On Display"),
            Feature(id: "aodSeconds", title: "AOD Seconds"),
            Feature(id: "actionButton", title: "Action Button"),
            Feature(id: "doubleTap", title: "Double Tap"),
            Feature(id: "watchKeyboard", title: "Watch Keyboard"),
            Feature(id: "aodVibrancy", title: "AOD Vibrancy"),
            Feature(id: "rotateToWake", title: "Rotate to Wake")
        ]),
        Group(id: "Sensors & Health", features: [
            Feature(id: "depth", title: "Depth Capability"),
            Feature(id: "absoluteAltimeter", title: "Absolute Altimeter"),
            Feature(id: "alwaysOnCompass", title: "Always-On Compass"),
            Feature(id: "periodicALSUpdates", title: "Periodic Ambient Light"),
            Feature(id: "continuousHeartRate", title: "Continuous Heart Rate"),
            Feature(id: "compassOrienteering", title: "Compass Orienteering"),
            Feature(id: "environmentalDosimetry", title: "Environmental Dosimetry"),
            Feature(id: "batteryInformation", title: "Battery Information"),
            Feature(id: "swimmingWorkouts", title: "Swimming Workouts")
        ]),
        Group(id: "Siri & Intelligence", features: [
            Feature(id: "raiseToSpeak", title: "Raise to Speak"),
            Feature(id: "alwaysListening", title: "Always Listening"),
            Feature(id: "appleIntelligence", title: "Apple Intelligence"),
            Feature(id: "onDeviceSiri", title: "On-Device Siri"),
            Feature(id: "audioIntelligence", title: "Audio Intelligence")
        ])
    ]

    var body: some View {
        List {
            Section("Connection") {
                LabeledContent("Watch", value: manager.isReachable ? "Connected" : "Not reachable")
                Text("Keep HermesEnabler open on the Watch. The iPhone requests actions; the Watch performs them.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Text(manager.remoteStatus)
                    .font(.footnote)
                if manager.remoteBusy { ProgressView() }
            }

            Section("Sandbox Route Diagnostics") {
                Button {
                    manager.runRemoteRouteScan()
                } label: {
                    Label("Run All Routes on Watch", systemImage: "stethoscope")
                }
                .disabled(manager.remoteBusy || !manager.isReachable)
                Text("Tests WorstGestalt, Geod and original HermesEnabler Class 13 / 7 / 2 routes. No system file is modified by the tests.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ForEach(groups) { group in
                Section(group.id) {
                    ForEach(group.features) { feature in
                        HStack {
                            Toggle(feature.title, isOn: Binding(
                                get: { manager.remoteFeatureStates[feature.id] ?? false },
                                set: { manager.setRemoteFeature(feature.id, enabled: $0) }
                            ))
                            .disabled(manager.remoteBusy || !manager.isReachable ||
                                      manager.remoteFeatureStates[feature.id] == nil)
                            Spacer(minLength: 5)
                            Button {
                                manager.refreshRemoteFeature(feature.id)
                            } label: {
                                Image(systemName: "arrow.clockwise")
                            }
                            .buttonStyle(.borderless)
                            .disabled(manager.remoteBusy || !manager.isReachable)
                            .accessibilityLabel("Read \(feature.title) from Watch")
                        }
                    }
                }
            }

            Section("Full Diagnostic Report") {
                Text(manager.remoteRouteReport)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
            }
        }
        .navigationTitle("Watch Route Tests")
        .onAppear { manager.refreshConnectionStatus() }
    }
}
