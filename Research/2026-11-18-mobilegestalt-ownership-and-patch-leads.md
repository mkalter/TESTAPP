# Watch6,18 / 23U95: Ownership reassessment and actual iOS 26 → 27 patch signals

## Crucial correction to a previous assumption: MobileGestaltHelper is not necessarily root

The **original watchOS 26.6.1 launchd plist** `com.apple.mobilegestalt.xpc.plist` extracted from Apple Watch6,18 IPSW was archived under GitHub Actions artifact `14360745184` (run #44152443271). It contains:

```
Label : com.apple.mobilegestalt.xpc
Program : /usr/libexec/MobileGestaltHelper
MachServices : {'com.apple.mobilegestalt.xpc': True}
UserName : {'#Else': 'mobile', '#IfFeatureFlagEnabled': 'UserManagement/SystemSessionD2', '#Then': '_mobilegestalthelper'}
```

Thus the helper **may execute as mobile** (or a separate service identity under a feature flag), not root. `tccd` and `softwareupdated` are also launched as mobile on this firmware (run #44252358717). The original protected cache has `mode=0644` in real Watch logs; its actual `st_uid`/`st_gid` has **not been measured**. It was premature to dismiss all mobile-identity XPC paths as doomed by POSIX ownership: an Apple helper might itself have created an owner-mobile cache. A working third-party write still needs to bypass the protected SystemGroup kernel sandbox and service-side authorization.

## Actual 26.6.2 → 27.0 iPhone Mach-O diff, not generic CVE speculation

Independent public original-firmware comparison:
https://github.com/0xjohnnydev/iPhone18-2-iOS-26.6.2-to-27.0-diff

- `MACHOS/filesystem/System/Library/PrivateFrameworks/TCC.framework/Support/tccd.md` shows **new imports** in 27.0:
  `_container_copy_from_path`, `_container_copy_sandbox_token`, `_container_get_path`, `_sandbox_extension_consume`, `_NSFilePosixPermissions`, and `_OBJC_CLASS_$_BSAuditToken`.
- This is a concrete revision of **TCC's container/permission handling** between vulnerable and patched releases. It is *consistent* with strengthened validation after CVE-2026-86886, but without caller-to-import mapping and an Apple fix commit **the change cannot be attributed to that CVE**.
- `DYLIBS/.../SoftwareUpdateCore.framework/SoftwareUpdateCore.md` adds `SUCoreSpaceCacheDeleteRequest` with `basePath` and `criticalModeEnabled`, and `+[SUCoreSpace cacheDeletePurgeWithRequest:completion:]`. Its exact relationship to Software Update CVE-2026-84609 is unproven.
- `MACHOS/.../softwareupdated.md` changes its path-cleanup XPC connection code (`copy_shared_cleanup_service_connection_with_restart`, `handle_perform_relaunch_cleanup_service_command`). There is no demonstrated unrestricted write to MobileGestalt in these diffs.

## Previously overlooked, actually present separate 23U95 XPC executable

Run [#44255332304](https://github.com/mkalter/TESTAPP/actions/runs/44255332304) successfully extracted
`/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/XPCServices/com.apple.MobileSoftwareUpdate.CleanupPreparePathService.xpc/`.

Its `Info.plist` identifies `ServiceType=System`, `CFBundleIdentifier=com.apple.MobileSoftwareUpdate.CleanupPreparePathService`; Mach-O `SHA256=2fc815ffa326fe1791428e73257c989fb33b0eb3cd47cd3c77dac11b62e3469e`, ARM64_32, 545,184 bytes. Path and cleanup primitives are present, including `realpath`, `removefile`, `_writeToRestoreLogFile`, stage state plist, and signed update state. A privileged **cleanup/deletion interface** is not an arbitrary-content, existing-plist writer. Exact XPC service eligibility and the targeted directory have not been proven.

## Current true blocker

The two officially acknowledged CVEs concern **possible modification of protected system files** on versions including watchOS 26.6.1, but no demonstrated third-party path/content API has been tied to the **already existing** `systemgroup.com.apple.mobilegestaltcache` plist. Class 7/12/13, file coordination, CFPrefsZeroFile and the default MG helper writer callback are previously investigated unsuccessful or insufficient paths. The iOS patch diff motivates following **TCC's specific new container/sandbox checks** and **Software Update's exact path-cleanup safety checks**, not another flag brute force.

**No protected cache modification / genuine native Hermès unlock has been achieved**. Never destroy or empty the original cache as a speculative test.
