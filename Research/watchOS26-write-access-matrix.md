# watchOS 26.6.1 / 23U95 — MobileGestalt write-access investigation

Updated: 2026-11-16. Scope: **write access**, not app signing, reading offsets, or activating Hermes without authorization.

## Claim taxonomy
- **DEVICE TEST**: explicitly reported result from a physical watch; linked to its source.
- **SOURCE**: source code or README observation; not a runtime result.
- **HYPOTHESIS**: technical inference requiring additional proof.
- **LOCAL**: what this repository's new diagnostic code can test. The code has **not** been compiled or run on the user's physical Watch from this environment.

## Tested results already available
| ID | Target/OS | Mechanism | Observed result | Status / source |
|---|---|---|---|---|
| E01 | Watch6,18 / 23U95 | Direct read of MG | Works; live plist validated | DEVICE TEST: [Issue #17](https://github.com/pookjw/HermesEnabler/issues/17) |
| E02 | Watch6,18 / 23U95 | Direct O_RDWR open of MG | EPERM before any pwrite | DEVICE TEST: [Issue #17](https://github.com/pookjw/HermesEnabler/issues/17) |
| E03 | Watch6,18 / 23U95 | Class 7 App Group symlink, three published flags | No usable token for target | DEVICE TEST: [Issue #17](https://github.com/pookjw/HermesEnabler/issues/17) |
| E04 | Watch6,18 / 23U95 | Class 12 Geod MCM query | Required container object unavailable | DEVICE TEST: [Issue #17](https://github.com/pookjw/HermesEnabler/issues/17) |
| E05 | Watch6,14 / 23U95 | Class 13 system-group token | Obtained and consumed; protected write still EPERM | DEVICE TEST: [Issue #7](https://github.com/pookjw/HermesEnabler/issues/7#issuecomment-6761033695) |
| E06 | Watch6,14 / 23U95 | Container sandbox policy | Read allow; write/create/metadata deny, including after token | DEVICE TEST: [Issue #7](https://github.com/pookjw/HermesEnabler/issues/7#issuecomment-6761033695) |
| E07 | Watch6,14 / 23U95 | Class 2 own-Library rename | Denied EPERM | DEVICE TEST: same issue |
| E08 | Watch6,14 / 23U95 | InstallCoordination entry paths | Extension consumed; tested directory open still EPERM | DEVICE TEST: same issue |
| E09 | Watch6,18 / 23U95 | MobileGestaltHelper XPC | Service responds, but investigated requests return error=9 | DEVICE TEST: [RO23 fork](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X) |
| E10 | iOS 26 vs 27 | worse_query SystemGroup paths | Upstream README lists SystemGroup access for iOS 27, not iOS 26 | SOURCE: [worse_query](https://github.com/forcequitOS/worse_query) |
| E11 | iOS 26 vs 27 | Independent WQFiles test | iOS 26 limits SystemGroup access; iOS 27 supports it | SOURCE/DEVICE TEST: [WQFiles](https://github.com/kolbicz/WQFiles) |
| E12 | Watch6,18 / 23U95 | DeviceBrand layout from static 23U95 firmware | Cached offset reported; older fork originally misidentified offset 0x670. Cannot treat read-only offsets as a writable permission | SOURCE: [RO23 fork](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X) |

Note: DeviceBrand values and cache offsets are not a substitute for obtaining write authorization. Do not attempt cache modifications based solely on an unverified offset.

## Why iOS/watchOS 26 may differ from 27

### H1 — Class 7 token availability differs by container category
- **Evidence**: published worse_query documentation confines SystemGroup access to iOS 27; iOS 26 reaches application and App Group containers.
- **Test**: compare public implementation documentation, and collect a *no-symlink, own-App-Group* baseline to confirm the Class 7 API works on the device.
- **Limit**: even an own-App-Group token does not grant SystemGroup access.

### H2 — Class 13 returns a narrower extension class
- **Evidence**: on 23U95, a Class 13 request returned a \`com.apple.sandbox.system-group\` extension that did not permit writing.
- **Test**: compare the published extension class against the effective sandbox policy and file-write operation results.
- **Limit**: a successful \`sandbox_extension_consume\` means that the token was accepted, not that the requested write is authorized.

### H3 — An additional private entitlement is required on 26
- **Evidence**: static sandbox rules from the 23U95 OTA were reported to require a SystemGroup token **and** one of the private entitlements \`com.apple.security.system-group-containers\` or \`com.apple.security.system-groups\` for \`file-write-data\`.
- **Test**: read the signed process's entitlement presence, compare \`sandbox_check\` for \`file-read-data\`, \`file-write-data\`, \`file-write-create\`; audit corresponding published policy findings for 27.
- **Limit**: this hypothesis is strongly supported for the tested extension route; it does not prove that every possible mechanism is impossible.

### H4 — Independent POSIX ownership or mount restriction
- **Evidence**: issue #7 reports that MG file ownership and mode are compatible with the app's UID and file flags do not explain EPERM.
- **Test**: record real/effective UID/GID, \`lstat\` mode/flags/owner, \`statfs\` read-only mount and non-mutating \`open(O_WRONLY|O_NOFOLLOW)\`. Compare with own-Documents/App-Group controls.
- **Limit**: a writable file descriptor opened and immediately closed does not prove an eventual safe/persistent cache update.

### H5 — Unsupported helper/XPC setter rather than a filesystem path
- **Evidence**: published MobileGestaltHelper analysis describes \`rebuildCache:\` as a rebuild operation without a caller-provided value; the RO23 fork observed error=9 for its tested helper calls.
- **Test**: review documented callable interfaces and error semantics *without invoking destructive methods*.
- **Limit**: no verified DeviceBrand setter on 23U95; \`rebuildCache:\` is **not** a harmless test because it may unlink the live cache.

### H6 — Incorrect application workflow hides distinct errors
- **Evidence**: earlier TESTAPP code repeatedly invoked BQEscape from capability-refresh calls and treated local fallback \`-5\` as though it were a platform error.
- **Test**: make read, token presence, token consumption, sandbox policy and attempted write-open separate report fields; manually trigger once.
- **Limit**: fixing instrumentation does not create rights.

### H7 — Another security layer (Data Protection, ACL, service policy, kernel MAC)
- **Evidence**: not ruled out solely by a POSIX error; a runtime sandbox deny plus ownership/mount checks increases confidence that the sandbox is the immediate boundary.
- **Test**: compare sandbox-check outcomes against POSIX results, check flags/mount/ownership, inspect authorized system logs for denials; do not assume any one subsystem without evidence.
- **Limit**: app-level diagnostics cannot fully classify all kernel policy decisions.

## Experimental matrix — what can be run on the user's watch

| Test | Module | What it distinguishes | Does it write MG? |
|---|---|---|---|
| T01 — signed app identity, build | BQPermissionDiagnostics / BQWriteGateDiagnostics | Wrong build or wrong bundle identity | No |
| T02 — own App Group create/write/read/delete | BQPermissionDiagnostics | Self-container rights versus system-group rights | No |
| T03 — lstat MG file, MG Caches, SystemGroup Library | BQWriteGateDiagnostics | Ownership/mode/flags vs path missing | No |
| T04 — statfs for MG and own containers | BQWriteGateDiagnostics | Mount read-only vs sandbox deny | No |
| T05 — read/cache-metadata checks | BQPermissionDiagnostics | Read permitted versus file absent | No |
| T06 — non-mutating write-descriptor open | BQPermissionDiagnostics / BQWriteGateDiagnostics | EPERM at open before any write | No (open+close only) |
| T07 — sandbox policy six operations, six paths | BQWriteGateDiagnostics | Read/write/create/unlink/mode/xattr policy asymmetry | No |
| T08 — entitlement presence | BQWriteGateDiagnostics | Signed App Group versus missing private SystemGroup entitlement | No |
| T09 — own App Group Class 7 flag matrix | BQClass7Matrix | Query result vs token vs consume, with no outside-container target | No |
| T10 — 26 vs 27 results | manual comparative review | Which authorization predicate changes across OS branches | No |
| T11 — matching OTA sandbox policy review | static research only | Whether entitlement + extension are conjunctive on 26 | No |
| T12 — diagnostic failure triage | report + Console logs | Kernel / policy / filesystem / application mismatch | No |

## Decision matrix for interpretation
1. **MG read ALLOW, write DENY, own-container write ALLOW, private entitlement unavailable**: prioritise policy entitlement gate. Do **not** infer a flag can remove it.
2. **MG write sandbox ALLOW but O_WRONLY EPERM**: evaluate non-sandbox restrictions using ownership/mount/flags; do **not** attempt a write.
3. **MG path ENOENT or different cache layout**: isolate path/build error first. Do not copy another model's cache offsets.
4. **Own App Group fails**: investigate entitlement/profile/runtime container failure independently of MG.
5. **MCM token consumed but write remains DENY**: do not repeat the same query combinations; record extension class and compare the policy criteria.

## Recommended verification standard
A claim of genuine 26.6.1 writing support requires a reproducible on-device result on the **exact target hardware/build**, an independently verified backup/recovery procedure, and post-operation integrity checks. Neither a path, token, valid plist layout, successful backup nor read access demonstrates this. This repository does not supply a protected-write payload or bypass.

## How to use this repository
1. Pull \`main\` and build the Watch target.
2. Open **MG Diagnostics** and select **Run complete diagnostics** (or each test separately).
3. Capture \`Documents/mg-write-gates.txt\`, \`Documents/mg-permission-diagnostics.txt\`, \`Documents/class7-flag-matrix.txt\`; also capture Xcode debugger output.
4. Compare these against Issue #7 and #17. Include exact build, model, timestamps, and note any \`sandbox_check\` API unavailable results.
5. If all three reports show independent sandbox denial of write, further repetition of identical flags is low value; focus static policy comparison and supported APIs instead.

## Excluded due to risk/poor diagnostic value
- Creating or modifying files inside the protected SystemGroup.
- Rebuilding or deleting the live MobileGestalt cache.
- Forging Apple-private entitlements or trying to bypass signature enforcement.
- Staging installation/system service payloads or exploiting new kernel vulnerabilities.
- Interpreting \`consume=-5\` as a real OS error when the app itself synthesizes it.
