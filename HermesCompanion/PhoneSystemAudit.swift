import Foundation
import UIKit
import Darwin

/// iOS-side control experiment. The Watch has a different filesystem and
/// sandbox; this probe NEVER tries to access it or to exploit the iPhone.
enum PhoneSystemAudit {
    private static let cacheFile =
        "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"

    private static func probe(_ path: String, flags: Int32) -> String {
        errno = 0
        let descriptor = open(path, flags | O_CLOEXEC | O_NOFOLLOW)
        let status = errno
        guard descriptor >= 0 else {
            return "DENIED errno=\(status) (\(String(cString: strerror(status))))"
        }
        var info = stat()
        let statOK = fstat(descriptor, &info) == 0
        close(descriptor)
        return statOK
            ? "OPEN OK size=\(info.st_size) uid=\(info.st_uid) gid=\(info.st_gid)"
            : "OPEN OK (fstat unavailable)"
    }

    static func report(watchConnected: Bool, watchVersion: String, watchHardware: String) -> String {
        var build = [CChar](repeating: 0, count: 128)
        var length = build.count
        let buildName: String = sysctlbyname("kern.osversion", &build, &length, nil, 0) == 0
            ? String(cString: build)
            : "unknown"
        return """
        === PAIRED-DEVICE BOUNDARY AUDIT ===

        IPHONE (this process)
        iOS: \(UIDevice.current.systemVersion)
        Build: \(buildName)
        Bundle: \(Bundle.main.bundleIdentifier ?? "unknown")
        File: \(cacheFile)
        O_RDONLY: \(probe(cacheFile, flags: O_RDONLY))
        O_RDWR: \(probe(cacheFile, flags: O_RDWR))

        WATCH (separate OS and sandbox)
        Reported watchOS: \(watchVersion)
        Hardware: \(watchHardware)
        Immediate WatchConnectivity reachability: \(watchConnected ? "YES" : "NO")

        Interpretation:
        The O_RDONLY / O_RDWR checks above refer ONLY to this iPhone's MobileGestalt cache.
        An iOS 27 sandbox escape on the iPhone does not grant Watch filesystem permissions.
        Apple Watch back-up/restore is a separate, OS-mediated pipeline: transferring a
        plist to a watch app is not equivalent to overwriting the protected watch cache.

        No system file was modified in this experiment.
        """
    }
}
