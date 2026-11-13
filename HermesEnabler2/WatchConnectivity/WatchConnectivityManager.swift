//
//  WatchConnectivityManager.swift
//  HermesEnabler2
//
//

import Foundation
import WatchKit
import WatchConnectivity
import Darwin
import CryptoKit

final class WatchConnectivityManager: NSObject, WCSessionDelegate {

    static let shared = WatchConnectivityManager()

    private override init() {
        super.init()
    }

    func activate() {
        guard WCSession.isSupported() else {
            print("[WC] WatchConnectivity not supported")
            return
        }

        let session = WCSession.default
        session.delegate = self
        session.activate()

        print("[WC] Activation requested")
    }

    func sendDeviceInformation() {
        let session = WCSession.default

        guard session.activationState == .activated else {
            print("[WC] Session not activated")
            return
        }

        let device = WKInterfaceDevice.current()
        let hardware = hardwareIdentifier()
        let build = systemBuild()

        var information: [String: Any] = [
            "deviceName": device.name,
            "model": device.model,
            "localizedModel": device.localizedModel,
            "systemName": device.systemName,
            "systemVersion": device.systemVersion,
            "hardwareIdentifier": hardware,
            "timestamp": Date().timeIntervalSince1970
        ]

        if let build {
            information["build"] = build
        }

        print("[WC] Sending information: \(information)")

        do {
            try session.updateApplicationContext(information)
            print("[WC] Application context updated")
        } catch {
            print("[WC] Sending error: \(error.localizedDescription)")
        }
    }

    private func hardwareIdentifier() -> String {
        sysctlValue("hw.machine") ?? "Unknown"
    }

    private func systemBuild() -> String? {
        sysctlValue("kern.osversion")
    }

    private func sysctlValue(_ key: String) -> String? {
        var size = 0

        guard sysctlbyname(key, nil, &size, nil, 0) == 0,
              size > 0 else {
            return nil
        }

        var buffer = [CChar](repeating: 0, count: size)

        guard sysctlbyname(key, &buffer, &size, nil, 0) == 0 else {
            return nil
        }

        return String(cString: buffer)
    }

    // MARK: - WCSessionDelegate

    func session(
        _ session: WCSession,
        activationDidCompleteWith activationState: WCSessionActivationState,
        error: Error?
    ) {
        print("[WC] Activation state: \(activationState.rawValue)")

        if let error {
            print("[WC] Activation error: \(error.localizedDescription)")
            return
        }

        if activationState == .activated {
            sendDeviceInformation()

            if BQBackupExists() {
                print("[WC] Session activated, checking original backup transfer")
                transferOriginalBackup()
            } else {
                print("[WC] No original backup available yet")
            }
        }
    }

    func sessionReachabilityDidChange(_ session: WCSession) {
        print("[WC] Reachability: \(session.isReachable)")

        if session.isReachable {
            sendDeviceInformation()
        }
    }

    func session(
        _ session: WCSession,
        didReceiveMessage message: [String: Any]
    ) {
        print("[WC] Message received: \(message)")
    }
    

    // MARK: - iPhone remote test and explicit feature controls
    private let routeCommandQueue = DispatchQueue(label: "HermesEnabler.route.commands")

    private func remoteReadFeature(_ key: String) -> [String: Any] {
        var error: NSString?
        var value = ObjCBool(false)
        let success: Bool
        switch key {
        case "hermes": success = BQGetHermesEnabled(&value, &error)
        case "ultraFaces": success = BQGetUltraFacesEnabled(&value, &error)
        case "aod": success = BQGetAODSupport(&value, &error)
        case "aodSeconds": success = BQGetAODSecondsSupport(&value, &error)
        case "actionButton": success = BQGetActionButton(&value, &error)
        case "doubleTap": success = BQGetDoubleTap(&value, &error)
        case "depth": success = BQGetDepthCapability(&value, &error)
        case "watchKeyboard": success = BQGetWatchKeyboard(&value, &error)
        case "raiseToSpeak": success = BQGetRaiseToSpeak(&value, &error)
        case "alwaysListening": success = BQGetAlwaysListening(&value, &error)
        case "appleIntelligence": success = BQGetAppleIntelligence(&value, &error)
        case "onDeviceSiri": success = BQGetOnDeviceSiri(&value, &error)
        case "audioIntelligence": success = BQGetAudioIntelligence(&value, &error)
        case "absoluteAltimeter": success = BQGetAbsoluteAltimeter(&value, &error)
        case "alwaysOnCompass": success = BQGetAlwaysOnCompass(&value, &error)
        case "aodVibrancy": success = BQGetAODVibrancy(&value, &error)
        case "periodicALSUpdates": success = BQGetPeriodicALSUpdates(&value, &error)
        case "continuousHeartRate": success = BQGetContinuousHeartRate(&value, &error)
        case "compassOrienteering": success = BQGetCompassOrienteering(&value, &error)
        case "environmentalDosimetry": success = BQGetEnvironmentalDosimetry(&value, &error)
        case "batteryInformation": success = BQGetBatteryInformation(&value, &error)
        case "rotateToWake": success = BQGetRotateToWake(&value, &error)
        case "swimmingWorkouts": success = BQGetSwimmingWorkouts(&value, &error)
        default:
            return ["ok": false, "error": "Unknown feature: \(key)"]
        }
        return success
            ? ["ok": true, "key": key, "enabled": value.boolValue]
            : ["ok": false, "key": key, "error": (error as String?) ?? "Cannot read this feature"]
    }

    private func remoteWriteFeature(_ key: String, enabled: Bool) -> [String: Any] {
        guard BQBackupExists() else {
            return ["ok": false, "key": key, "error": "Create the initial MobileGestalt backup on the Watch first."]
        }
        var error: NSString?
        let success: Bool
        switch key {
        case "hermes": success = BQSetHermesEnabled(enabled, &error)
        case "ultraFaces": success = BQSetUltraFacesEnabled(enabled, &error)
        case "aod": success = BQSetAODSupport(enabled, &error)
        case "aodSeconds": success = BQSetAODSecondsSupport(enabled, &error)
        case "actionButton": success = BQSetActionButton(enabled, &error)
        case "doubleTap": success = BQSetDoubleTap(enabled, &error)
        case "depth": success = BQSetDepthCapability(enabled, &error)
        case "watchKeyboard": success = BQSetWatchKeyboard(enabled, &error)
        case "raiseToSpeak": success = BQSetRaiseToSpeak(enabled, &error)
        case "alwaysListening": success = BQSetAlwaysListening(enabled, &error)
        case "appleIntelligence": success = BQSetAppleIntelligence(enabled, &error)
        case "onDeviceSiri": success = BQSetOnDeviceSiri(enabled, &error)
        case "audioIntelligence": success = BQSetAudioIntelligence(enabled, &error)
        case "absoluteAltimeter": success = BQSetAbsoluteAltimeter(enabled, &error)
        case "alwaysOnCompass": success = BQSetAlwaysOnCompass(enabled, &error)
        case "aodVibrancy": success = BQSetAODVibrancy(enabled, &error)
        case "periodicALSUpdates": success = BQSetPeriodicALSUpdates(enabled, &error)
        case "continuousHeartRate": success = BQSetContinuousHeartRate(enabled, &error)
        case "compassOrienteering": success = BQSetCompassOrienteering(enabled, &error)
        case "environmentalDosimetry": success = BQSetEnvironmentalDosimetry(enabled, &error)
        case "batteryInformation": success = BQSetBatteryInformation(enabled, &error)
        case "rotateToWake": success = BQSetRotateToWake(enabled, &error)
        case "swimmingWorkouts": success = BQSetSwimmingWorkouts(enabled, &error)
        default:
            return ["ok": false, "error": "Unknown feature: \(key)"]
        }
        if !success {
            return ["ok": false, "key": key,
                    "error": (error as String?) ?? "No writable MobileGestalt route found"]
        }
        // Re-read from the Watch, don't claim success just because a call returned.
        let verified = remoteReadFeature(key)
        if verified["ok"] as? Bool == true,
           verified["enabled"] as? Bool == enabled {
            return ["ok": true, "key": key, "enabled": enabled,
                    "message": "Saved and read back on Watch. Restart may be required."]
        }
        return ["ok": false, "key": key, "error": "Write returned success but read-back did not match."]
    }

    func session(_ session: WCSession,
                 didReceiveMessage message: [String: Any],
                 replyHandler: @escaping ([String: Any]) -> Void) {
        guard message["protocol"] as? String == "HermesRouteResearchV1",
              let command = message["command"] as? String else {
            replyHandler(["ok": false, "error": "Unrecognized command protocol"])
            return
        }
        routeCommandQueue.async {
            if !BQCoreInit() {
                replyHandler(["ok": false, "error": "MobileContainerManager unavailable"])
                return
            }
            switch command {
            case "daemonStagingWriteTest":
                replyHandler(["ok": true, "report": BQRunDaemonWriteProbe()])
            case "routes":
                replyHandler(["ok": true, "report": BQRunRouteDiagnostics()])
            case "relayProbe":
                // Observe that the iPhone can request app-sandbox writes on the
                // Watch, but this never confers permission for system-group files.
                let marker = UUID().uuidString
                let destination = FileManager.default.temporaryDirectory
                    .appendingPathComponent("watch-connectivity-relay-\(marker).txt")
                let data = Data(marker.utf8)
                do {
                    try data.write(to: destination, options: .atomic)
                    let verified = try Data(contentsOf: destination) == data
                    try? FileManager.default.removeItem(at: destination)
                    let protectedPath = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"
                    errno = 0
                    let fd = open(protectedPath, O_RDWR | O_CLOEXEC)
                    let code = errno
                    if fd >= 0 { close(fd) }
                    replyHandler([
                        "ok": verified,
                        "report": """
                        Phone → Watch command delivered: YES
                        Watch app-sandbox write and read-back: \(verified ? "OK" : "FAILED")
                        Temporary marker removed: YES (best effort)
                        Watch MobileGestalt O_RDWR: \(fd >= 0 ? "OPEN OK" : "DENIED errno=\(code)")
                        No protected system file was modified.
                        """
                    ])
                } catch {
                    replyHandler(["ok": false, "error": "App-sandbox relay test failed: \(error.localizedDescription)"])
                }

            case "createBackup":
                if BQBackupExists() {
                    replyHandler(["ok": true, "message": "Initial MobileGestalt backup already exists on Watch."])
                } else {
                    var error: NSString?
                    if BQCreateGestaltBackup(true, &error) != nil {
                        self.transferOriginalBackup()
                        replyHandler(["ok": true, "message": "Initial MobileGestalt backup saved on Watch."])
                    } else {
                        replyHandler(["ok": false,
                                      "error": (error as String?) ?? "Backup could not be created."])
                    }
                }
            case "respring":
                replyHandler(["ok": true, "message": "Restart Carousel requested on Watch."])
                DispatchQueue.global(qos: .userInitiated)
                    .asyncAfter(deadline: .now() + .milliseconds(300)) {
                        BQRespring()
                    }
            case "readFeature":
                guard let key = message["key"] as? String else {
                    replyHandler(["ok": false, "error": "Missing feature key"])
                    return
                }
                replyHandler(self.remoteReadFeature(key))
            case "setFeature":
                guard let key = message["key"] as? String,
                      let enabled = message["enabled"] as? Bool else {
                    replyHandler(["ok": false, "error": "Missing key / enabled"])
                    return
                }
                replyHandler(self.remoteWriteFeature(key, enabled: enabled))
            default:
                replyHandler(["ok": false, "error": "Unsupported command"])
            }
        }
    }

    struct PendingBackup {
        let id: String
        let data: Data
        let fileName: String
        let sha256: String
    }

    private var pendingDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("PendingMGBackups", isDirectory: true)
    }

    private func storePendingBackup(data: Data, fileName: String, sha256: String) throws {
        try FileManager.default.createDirectory(at: pendingDirectory, withIntermediateDirectories: true)
        let record: [String: Any] = ["data": data, "fileName": fileName, "sha256": sha256]
        let encoded = try PropertyListSerialization.data(fromPropertyList: record, format: .binary, options: 0)
        try encoded.write(to: pendingDirectory.appendingPathComponent(UUID().uuidString + ".plist"), options: .atomic)
    }

    func nextPendingBackup() -> PendingBackup? {
        guard let files = try? FileManager.default.contentsOfDirectory(at: pendingDirectory, includingPropertiesForKeys: [.creationDateKey]) else { return nil }
        let sorted = files.filter { $0.pathExtension == "plist" }.sorted {
            let a = (try? $0.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast
            let b = (try? $1.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast
            return a < b
        }
        for file in sorted {
            guard let encoded = try? Data(contentsOf: file),
                  let record = (try? PropertyListSerialization.propertyList(from: encoded, options: [], format: nil)) as? [String: Any],
                  let data = record["data"] as? Data, let name = record["fileName"] as? String,
                  let hash = record["sha256"] as? String else { continue }
            return PendingBackup(id: file.lastPathComponent, data: data, fileName: name, sha256: hash)
        }
        return nil
    }

    func removePendingBackup(id: String) {
        guard id == URL(fileURLWithPath: id).lastPathComponent else { return }
        do { try FileManager.default.removeItem(at: pendingDirectory.appendingPathComponent(id)) }
        catch { print("[WC] Could not remove pending backup: \(error.localizedDescription)") }
    }

    // MARK: - Receive external backup from iPhone

    func session(
        _ session: WCSession,
        didReceive file: WCSessionFile
    ) {
        let metadata = file.metadata ?? [:]

        guard let type = metadata["type"] as? String,
              type == "externalGestaltRestoreCandidate" else {
            print("[WC] Ignoring unrelated incoming file")
            return
        }

        print("[WC] External backup received from iPhone")

        do {
            let data = try Data(contentsOf: file.fileURL)

            guard !data.isEmpty else {
                print("[WC] Rejected empty backup")
                return
            }

            // Verify SHA-256 against the hash sent by the iPhone.
            guard let expectedHash = metadata["sha256"] as? String else {
                print("[WC] Missing SHA256 metadata. Backup rejected.")
                return
            }

            let actualHash = SHA256.hash(data: data)
                .map { String(format: "%02x", $0) }
                .joined()

            guard expectedHash.lowercased() == actualHash.lowercased() else {
                print("[WC] SHA256 mismatch. Backup rejected.")
                print("[WC] Expected: \(expectedHash)")
                print("[WC] Actual: \(actualHash)")
                return
            }

            // Validate the MobileGestalt property list structure.
            let propertyList = try PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            )

            guard let dictionary = propertyList as? [String: Any],
                  dictionary["CacheExtra"] is [String: Any],
                  dictionary["CacheData"] is Data else {
                print("[WC] Invalid MobileGestalt backup structure. Backup rejected.")
                return
            }

            let fileName = metadata["fileName"] as? String
                ?? file.fileURL.lastPathComponent

            print("[WC] External backup received and verified")
            print("[WC] File: \(fileName)")
            print("[WC] Size: \(data.count) bytes")
            print("[WC] SHA256: \(actualHash)")
            print("[WC] Waiting for user confirmation")

            try storePendingBackup(data: data, fileName: fileName, sha256: actualHash)
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: Notification.Name("HermesExternalBackupReceived"), object: nil)
            }

        } catch {
            print("[WC] Could not process received backup: \(error.localizedDescription)")
        }
    }

}

extension WatchConnectivityManager {
    
    func transferOriginalBackup() {
        let session = WCSession.default

        guard session.activationState == .activated else {
            print("[WC] Session not activated")
            return
        }

        guard BQBackupExists() else {
            print("[WC] Original backup does not exist")
            return
        }

        let sourceURL = URL(fileURLWithPath: BQBackupPath())

        guard FileManager.default.fileExists(atPath: sourceURL.path) else {
            print("[WC] Original backup file not found")
            return
        }

        guard let data = try? Data(contentsOf: sourceURL) else { return }
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let metadata: [String: Any] = [
            "sha256": hash,
            "type": "originalGestalt",
            "deviceName": WKInterfaceDevice.current().name,
            "hardwareIdentifier": hardwareIdentifier(),
            "watchOSVersion": WKInterfaceDevice.current().systemVersion,
            "build": systemBuild() ?? "Unknown",
            "transferDate": Date().timeIntervalSince1970
        ]
        
        print("[WC] Backup path: \(sourceURL.path)")
        print("[WC] Backup exists: \(FileManager.default.fileExists(atPath: sourceURL.path))")

        let transfer = session.transferFile(sourceURL, metadata: metadata)

        print("[WC] Original backup transfer queued")
        print("[WC] Transfer: \(transfer)")
        print("[WC] Transfer queued: \(transfer.isTransferring)")
    }
    
}
