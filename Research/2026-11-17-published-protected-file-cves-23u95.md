# watchOS 26.6.1 / Watch6,18 — separate officially acknowledged protected-file modification bugs

**These are real published Apple security vulnerabilities, not a tested native Hermès unlock.**
The CVE version ranges include watchOS 26.6.1 and have fixes in watchOS 27; Apple Watch Ultra 1 cannot upgrade to watchOS 27.

## Two independent vulnerabilities not covered by MCM/CFPrefs probe history

| CVE | watchOS 27 vendor category | Advisory effect and fix | Current proof |
|---|---|---|---|
| [CVE-2026-86886](https://cve.circl.lu/vuln/CVE-2026-86886) | **DataAccess** (iOS lists TCC) | Path traversal / inadequate input validation; app may modify protected system files; fixed watchOS 27 | The affected-version claim is official; no public 23U95 exploitation or MobileGestalt write verified |
| [CVE-2026-84609](https://cve.circl.lu/vuln/CVE-2026-84609) | **Software Update** | Insufficient path validation; app may modify protected system files; fixed watchOS 27 | The affected-version claim is official; no public 23U95 exploitation or MobileGestalt write verified |
| [CVE-2026-86876](https://cve.circl.lu/vuln/CVE-2026-86876) | **CoreMedia** | Out-of-bounds write may enable sandbox escape; fixed watchOS 27 | Not a ready file-writer and may provide no extra POSIX permissions |

These are distinct from `bad_query`, `worse_query`, Class 12/13 MCM, `CFPrefsZeroFile` and `NSFileCoordinator`.

## Exact Apple Watch6,18 / 23U95 firmware audit completed

GitHub Actions: https://github.com/mkalter/TESTAPP/actions/runs/44175646728
Artifact: `exact-watchos26-dataaccess-softwareupdate-sandbox-boundaries`.
Original Apple kernelcache SHA-256: `ced56594d646bc39261c7f6d4cce8554accc9fd16cce6ec4aa70ad3d98f56261`.
This SHA matches the previously independently extracted original 23U95 kernelcache.

Decompiled profiles present and authenticated:
- `dataaccessd`: 1682 lines. Explicit destination writes to home-based DataAccess, Mail, Notes, Calendar, carrier caches, and `/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles`; **NOT** an explicit unconditional grant for sibling `systemgroup.com.apple.mobilegestaltcache`. A published vulnerable **path traversal** in its API is not proof it can reach that different SystemGroup through the kernel sandbox.
- `softwareupdated`: 571 lines. Explicit `file-write*` includes `/private/var/MobileSoftwareUpdate`, `/private/var/db/UpdateMetrics`, `/private/var/tmp` and own caches; **NO** unconditional write grant on the protected MobileGestalt SystemGroup.
- `com.apple.tccd`: 529 lines. Explicit own `/Library/TCC` write entries, temporary areas and entitlement/extension-gated additional paths, not an established direct MG writer.
- `cfprefsd`: already separately investigated; original 23U95 CoreFoundation writer works for authorized preferences, and `validateMessage` invokes POSIX and sandbox checks.

**Important distinction:** The CVEs say a protected file could be modified somewhere. They do **not** establish that an app can choose the **exact already-existing** MobileGestalt plist as destination, or that a normal development-signed Watch app can exercise the vulnerable IPC selector. A deliberate delete/rename race against protected MG is unjustified without a demonstrated reversible writing primitive.

## Data required to identify a true new writer

1. An actual vulnerable service entrypoint with client-reachable IPC on **23U95** that accepts file path and **arbitrary content**.
2. Permission check after path resolution and POSIX ownership; on-device authorizer result, not just token issuance.
3. Controlled write to a separate disposable non-system owned file, then only with recoverability proof consider protected MG mutation.
4. Native Hermès eligibility is **another separate gate** even after an MG write.

**Proven outcome:** Three documented independent vulnerability classes and exact original sandbox constraints; **no live protected MG write, no generated working exploit, and no confirmed native Hermès unlock**.
