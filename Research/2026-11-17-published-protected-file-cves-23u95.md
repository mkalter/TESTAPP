# watchOS 26.6.1 / Watch6,18 — separate officially acknowledged protected-file modification bugs

**These are real published Apple security vulnerabilities, not a tested native Hermès unlock.**
The CVE version ranges include watchOS 26.6.1 and have fixes in watchOS 27; Apple Watch Ultra 1 cannot upgrade to watchOS 27.

**Correction verified against Apple's original security advisory:** watchOS 27 lists CVE-2026-86886 under **TCC**, not DataAccess. The earlier project note mislabelled its affected component and misprioritized the sandbox profile to inspect. Source: https://support.apple.com/en-us/149037 (TCC section).

## Two independent vulnerabilities not covered by MCM/CFPrefs probe history

| CVE | watchOS 27 vendor category | Advisory effect and fix | Current proof |
|---|---|---|---|
| [CVE-2026-86886](https://cve.circl.lu/vuln/CVE-2026-86886) | **TCC** (Apple's watchOS 27 advisory) | Path traversal / inadequate input validation; app may modify protected system files; fixed watchOS 27 | The affected-version claim is official; no public 23U95 exploitation or MobileGestalt write verified |
| [CVE-2026-84609](https://cve.circl.lu/vuln/CVE-2026-84609) | **Software Update** | Insufficient path validation; app may modify protected system files; fixed watchOS 27 | The affected-version claim is official; no public 23U95 exploitation or MobileGestalt write verified |
| [CVE-2026-86876](https://cve.circl.lu/vuln/CVE-2026-86876) | **CoreMedia** | Out-of-bounds write may enable sandbox escape; fixed watchOS 27 | Not a ready file-writer and may provide no extra POSIX permissions |

These are distinct from `bad_query`, `worse_query`, Class 12/13 MCM, `CFPrefsZeroFile` and `NSFileCoordinator`.

## Exact Apple Watch6,18 / 23U95 firmware audit completed

GitHub Actions: https://github.com/mkalter/TESTAPP/actions/runs/44175646728
Artifact: `exact-watchos26-dataaccess-softwareupdate-sandbox-boundaries`.
Original Apple kernelcache SHA-256: `ced56594d646bc39261c7f6d4cce8554accc9fd16cce6ec4aa70ad3d98f56261`.
This SHA matches the previously independently extracted original 23U95 kernelcache.

Decompiled profiles present and authenticated:
- `com.apple.tccd`: 529 lines. Original exact-watchOS policy shows explicit writes to its own `~/Library/TCC`, CompanionSync logs, and temporary directories; **NOT** an explicit unconditional grant for `systemgroup.com.apple.mobilegestaltcache`. The CVE affects **TCC**, not DataAccess. A path traversal in TCC is not proof it bypasses the kernel sandbox for the MobileGestalt target.
- `softwareupdated`: 571 lines. Explicit `file-write*` includes `/private/var/MobileSoftwareUpdate`, `/private/var/db/UpdateMetrics`, `/private/var/tmp` and own caches; **NO** unconditional write grant on the protected MobileGestalt SystemGroup.
- `dataaccessd` was inspected in the earlier run but is **not** the affected component for CVE-2026-86886. Its old analysis must not be used as evidence for the TCC CVE.
- `cfprefsd`: already separately investigated; original 23U95 CoreFoundation writer works for authorized preferences, and `validateMessage` invokes POSIX and sandbox checks.

**Important distinction:** The CVEs say a protected file could be modified somewhere. They do **not** establish that an app can choose the **exact already-existing** MobileGestalt plist as destination, or that a normal development-signed Watch app can exercise the vulnerable IPC selector. A deliberate delete/rename race against protected MG is unjustified without a demonstrated reversible writing primitive.

## 18 November — exact original executables and frameworks, not guessed components

Both new read-only GitHub Actions workflows completed successfully:

- [Original daemon executable and launchd identities, #44252358717](https://github.com/mkalter/TESTAPP/actions/runs/44252358717) — artifact `14404462717`
- [Original ARM64_32 TCC and SoftwareUpdate frameworks, #44251991042](https://github.com/mkalter/TESTAPP/actions/runs/44251991042) — artifact `14403314605`

The source is **Watch6,18 watchOS 26.6.1 (23U95)**, not iOS; the framework images and launch manifests were extracted from the corresponding original Apple IPSW. Reports only, no proprietary Apple Mach-O redistribution.

**Actual launchd process identity and Mach service**:

| Service | Exact original launch path | `UserName` | Mach service |
|---|---|---|---|
| TCC | `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` | `mobile` | `com.apple.tccd` |
| Software Update | `/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/Support/softwareupdated` | `mobile` | `com.apple.mobile.softwareupdated` |

Original `tccd` executable SHA-256 `b885388cef4b25b4988b9b312d3ab6dd2b11d27b9baf0fefc3e18bb29d7dbf9d`; `softwareupdated` SHA-256 `97d4ecb485e55a1a889d33291ad888c93776b3d20c1b0a991d3264d47cff0b63`.

**Actual framework code present**:
- TCC.framework/TCC SHA-256 `c7619df3ce83891423b5f0c07b6f0c8711ee15e22305f687d8419f370404d04f`; original nlist strings include `_TCCAccessSetForPathWithOptions` and `_tcc_authorization_check_audit_token`. This is TCC access-control API and NOT proof of arbitrary on-disk file writes.
- SoftwareUpdateCore.framework SHA-256 `08b40ee05a9e81f55d8534ee677998b6b17fa58d9ce91043cb662c9709f6fd74`; original paths and selectors are associated with staged update payloads, release notes and update volumes. No unconstrained MobileGestalt destination is established.
- MobileSoftwareUpdate.framework SHA-256 `ab2e6b114cb323367904eba519ab5bacd87dc7d6c7d595c489f07d1834498076`.
- Original `tccd` text contains `sandbox_check_by_audit_token` and checks for missing private entitlements.
- Original `softwareupdated` text contains `Client does not have entitlement %s` and `_xpc_connection_copy_entitlement_value`. Its client interface is not an unconstrained arbitrary-write service.

ARM64_32 Objective-C `ipsw class-dump` returned EOF while reading metadata on these images. Therefore method names gleaned from strings alone are NOT authenticated implementations; identifying exact vulnerable input requires disassembly or a researcher-released PoC. No on-Watch mutations were attempted.

**Two separate controls must be crossed** to make the requested MG write: privileged service must be reachable with an accepted request *and* the resolved protected destination must pass effective sandbox + POSIX checks. On this build both TCC and Software Update are configured as the **mobile** user; previous physical Watch measurements found MobileGestalt mode `0644` but **did not establish its owner UID**. The owner must be verified before concluding that a mobile-user exploit cannot write it. The vulnerable versions asserted by Apple do not by themselves bypass POSIX ownership.

The earlier initial fetch matched an irrelevant `dasd` launch manifest due to a broad `asd` substring. That was corrected in the subsequent verified extraction; it is **not** evidence about the App Store `asd` daemon.

## 18 November: exact kernel Mach lookup source check

[Original 23U95 `sb query mach-lookup` run #44253023952](https://github.com/mkalter/TESTAPP/actions/runs/44253023952), artifact `14403744371`, independently queried both `com.apple.tccd` and `com.apple.mobile.softwareupdated` in the original hash-verified kernel.

**Critical interpretation:** the parser's outputs contained **919 rule matches for *each* service**, with nearly identical profile counts and baseline/container guard trees despite different names. The tool is enumerating conditional rules / possible matches, **not resolving effective `mach-lookup` access for a developer-signed Watch app**. In particular, the `container` profile showed 35 candidate allow clauses for both names; these cannot be labelled reachable without fully evaluating global-name, xpc-service-name, entitlement, profile flag and exception predicates. The script's raw JSON is preserved for reproducibility. Neither TCC reachability nor Software Update reachability was established by this static tool.

A useful low-risk diagnostic on a real development-signed Watch build would be a **preflight-only** `sandbox_check` of `mach-lookup` for these exact names, without sending XPC messages or changing files. That result is **not yet available**. A positive preflight would still not bypass the service's own entitlement checks, the service's sandbox, or MobileGestalt POSIX permissions.

## Data required to identify a true new writer

1. An actual vulnerable service entrypoint with client-reachable IPC on **23U95** that accepts file path and **arbitrary content**.
2. Permission check after path resolution and POSIX ownership; on-device authorizer result, not just token issuance.
3. Controlled write to a separate disposable non-system owned file, then only with recoverability proof consider protected MG mutation.
4. Native Hermès eligibility is **another separate gate** even after an MG write.

**Proven outcome:** Three documented independent vulnerability classes and exact original sandbox constraints; **no live protected MG write, no generated working exploit, and no confirmed native Hermès unlock**.
