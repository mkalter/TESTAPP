# Original same-model Watch7,5 watchOS 26.6 → 27.0 TCC path-authorization changes

**Date:** 18 November 2026. Purpose: independently check whether Apple's pre-watchOS27 TCC protected-system-file CVE (CVE-2026-86886) corresponds to a concrete changed code area. This is an **offline binary audit, not a successful exploit**.

## Results independently reproduced against original Apple watchOS firmware

A successful isolated run [#44255932619](https://github.com/mkalter/TESTAPP/actions/runs/44255932619) extracted and compared original `tccd` and `softwareupdated` executables on **the same Apple Watch7,5** hardware:

- Pre-fix watchOS 26.6 build **23U67**: [metadata from #44255691426](https://github.com/mkalter/TESTAPP/actions/runs/44255691426) artifact `14405263473` (the *full* dyld-cache matrix job failed only for the 27 side; the 26 extraction succeeded).
- Post-fix watchOS 27.0 build **24R364**: [successful daemon-only comparison #44255932619](https://github.com/mkalter/TESTAPP/actions/runs/44255932619), artifact `14405762683`.
- `tccd` original SHA256 26.6 = `1af100d82d929a5654cead0167a23501a9a6369c5a8901ec9868028e60dbdc97`; 27.0 = `bacc4887a5c9120bb9a59fcd6fc2f9104fcefbffc10b7bcfedbaf14ddad211c2`.
- `softwareupdated` original SHA256 26.6 = `6e26bf2e4c56623285f0cbf952f378b405514732ff1c53f2e2f9ff0068878435`; 27.0 = `52a6a7b4011d82fa230d3582eb483e23eb80d7b856d80716167637dafc348ee0`.

The compare was run on *real binary string contents*, not source-code speculation. Rechecked each entry individually in both downloadable artifacts:

| Exact TCC evidence | 26.6 `tccd` | 27.0 `tccd` |
|---|---|---|
| `validateExistingDatabaseAtPath:` | ABSENT | PRESENT |
| `TCCDDirectoryManager` class/method references | ABSENT | PRESENT (13 matching strings) |
| `checkLegacyDatabaseRegisteredAtPath:` | ABSENT | PRESENT |
| `cleanupLegacyDirectoryAtPath:` | ABSENT | PRESENT |
| `createTCCPathIfNeeded` | ABSENT | PRESENT |
| `_container_copy_from_path` | ABSENT | PRESENT |
| `_container_copy_sandbox_token` | ABSENT | PRESENT |
| `_container_get_path` | ABSENT | PRESENT |
| `_sandbox_extension_consume` | ABSENT | PRESENT |
| `_NSFilePosixPermissions` | ABSENT | PRESENT |
| `Skipping. Path appear to be current TCC directory` | ABSENT | PRESENT |
| `Skipping. Path doesn't appear to be TCC directory` | ABSENT | PRESENT |

**Interpretation:** the patched watchOS 27 TCC binary contains new dedicated *TCC database directory validation*, apparent checks of whether a path is the TCC directory, and container-bound token handling. These are meaningful, concrete path-safety hardening changes. That makes the old TCC directory management and database-migration/cleanup path a stronger reverse-engineering **candidate** than generic sandbox bypasses. Apple's advisory states CVE-2026-86886 is a path traversal fixed in watchOS27, **but a binary patch comparison alone cannot prove these exact changes implement that CVE fix**.

**Competing explanation:** TCC 27 added legitimate new database migration and functionality unrelated to the vulnerability. Must not assert exact vulnerability origin without callgraph or researcher writeup.

**Actual Ultra1 23U95:** the independently extracted pre-fix `tccd` (SHA `b885388cef4b25b4988b9b312d3ab6dd2b11d27b9baf0fefc3e18bb29d7dbf9d`) also lacks the listed new container symbols in its extracted selected strings. This corroborates the *pre-fix state* but does not prove the same entrypoint or exploitable path as on Watch7,5.

### Important limitations and unverified dependencies

- WatchOS26.6 `tccd` executable is **universal/fat Mach-O**. The parser in the comparison run reported `unrecognized Mach-O magic` when attempting *method-symbol body attribution*. WatchOS27 ARM64e `tccd` had no applicable named code symbols. Thus **the confirmed TCC difference is strings/imports and class/selector presence**, *not* a verified disassembled old-to-new function body patch. Never interpret the script's `changed_methods_count:0` as “no binary code changed.”
- watchOS27 no longer supplied the old expected `arm64_32` shared-cache path in the first matrix job. Consequently, the TCC.framework and SoftwareUpdateCore.framework full two-version diffs in this repository remain incomplete. The **daemon-only** run succeeded with validated binaries on both sides.
- Both TCC and Software Update launchd identities on original 23U95 are normally `mobile`, not root, and the protected MG-cache's owner UID is **not available in the existing report excerpt**. The pre-existing `BQRunPermissionDiagnostics()` function in `HermesEnabler2/BQPermissionDiagnostics.m` already performs `lstat` and logs `uid`, `gid`, and mode for the real target, so do not invent or rebuild that same diagnostic again.
- `TCCDSQLDatabase` is a database subsystem; accepting a TCC target path or replacing a SQLite database **does not automatically give arbitrary-controlled binary-plist writing** to the MobileGestalt SystemGroup. A separate valid data-to-file primitive and kernel sandbox permission would still be required.
- No live device privileged file mutation, no verified TCC escape to MobileGestalt, and no native Hermès unlock occurred in these offline runs.

## Distinct SoftwareUpdate observations

`softwareupdated` pre/post binaries both contain `_msu_client_is_entitled`. The watchOS27 binary introduces/changes cleanup-service restart and volume paths, but no verified control-flow evidence establishes a client-triggerable arbitrary-write to MG. Separately, the original 23U95 `com.apple.MobileSoftwareUpdate.CleanupPreparePathService` binary was extracted and SHA-pinned in successful run [#44255332304](https://github.com/mkalter/TESTAPP/actions/runs/44255332304); its demonstrated functionality is cleanup/deletion, not a controlled existing-plist writer.

## Next gating technical fact, not a guess

The key unresolved control is the **runtime authorization of a vulnerable TCC database/legacy-directory operation from a developer-signed watchOS app and whether it produces a controllable write destination inside MobileGestalt's SystemGroup**. A public 23U95 proof of concept or a bounded legitimate non-destructive test showing an accepted vulnerability-specific RPC would be necessary. A mere imported symbol or XPC port is not enough.

**VERDICT (as of 18 Nov):** new, reproducible TCC path-management patch delta on same Watch model; still no verified userland MobileGestalt writer. All previously attempted Class7/12/13 and CFPrefsZeroFile methods remain closed/insufficient.
