# watchOS 26.6.1 SystemGroup authorization — test plan

## Scope
- Target: HermesEnabler2 on watchOS 26.6.1 (23U95), Watch6,18.
- This is **not** a sandbox exploit or a claim of successful MobileGestalt modification.
- Signing and App Group configuration are independent of authorization for the protected SystemGroup cache.
- The diagnostic screen runs without calling \`BQEscape\`, staging symlinks, or changing the system cache.

## Public-source comparison (checked 2026-11-16)
- [forcequitOS/worse_query](https://github.com/forcequitOS/worse_query): documents iOS 26 support for application/AppGroup containers, but marks \`/var/containers/Shared/SystemGroup/*\` **iOS 27 only**. Code uses a Class 7 query, an AppGroup path/symlink, and a variant flag on iOS 26.
- [forcequitOS/bad_query](https://github.com/forcequitOS/bad_query): its supported path table also labels SystemGroup as **iOS 27 only**. The existence of a token is not proof of RW authorization.
- [HermesEnabler issue #7](https://github.com/pookjw/HermesEnabler/issues/7): community tests on 23U95 obtained a Class 13 system-group token, yet \`file-write-data\` remained denied with EPERM. Sandbox-profile interpretation indicates an additional private system-group entitlement.
- [Watch6,18 research fork](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X): read/backup succeeded; writes blocked; tested helpers did not produce a working path.
- [HermesEnabler upstream](https://github.com/pookjw/HermesEnabler): watchOS 26 support remains experimental. Its build-specific cache offsets are *format knowledge*, not sandbox permissions.

## What the current code actually proves
The \`bq_query_escape\` function uses the application's own fallback \`-5\` if no token is copied:
\`\`\`objc
int64_t h = (tok && g.consume) ? g.consume(tok) : -5;
\`\`\`
Thus \`consume=-5\` alone is not an Apple sandbox error code. Check the preceding \`token=YES/NO\` value separately.

## Run once
1. Build the Watch target and launch the Watch app.
2. Open **MG Diagnostics** from the initial backup screen or the Utilities section.
3. Tap **Run one test**. Do not run toggles or restore/rebuild operations.
4. Get the resulting \`Documents/mg-permission-diagnostics.txt\` via Xcode's container export, or copy the \`[MGDiagnostics]\` block from the debugger.
5. Compare the read/write policy results to the control App Group file test.

## Interpretation matrix
| Finding | Interpretation |
|---|---|
| Own App Group control passes, protected read passes, write-open/policy denied | Strong evidence of an independent protected-container authorization boundary. |
| Own App Group fails | Inspect runtime entitlement and container provisioning, not MobileGestalt offsets. |
| Protected path returns ENOENT | Validate path spelling, exact build and filesystem layout first. |
| \`sandbox_check\` unavailable | Treat policy result as unknown; rely on POSIX read and open-only errors. |
| Protected write-open allowed | It proves a descriptor may open. **Do not write** without an independently verified recovery path. |

## Further analysis to establish a 26-versus-27 *cause*
1. Obtain original, same-device-family watchOS 26.6.1 and 27 firmware artifacts from lawful distribution.
2. Extract and compare relevant container sandbox policy operations for SystemGroups: \`file-read-data\`, \`file-write-data\`, \`file-write-create\`, and entitlement predicates. Record exact binaries/build hashes.
3. Compare extension class/predicate expectations, not merely whether \`container_copy_sandbox_token\` returned text.
4. Distinguish a kernel sandbox denial from MAC, data-protection, POSIX ownership, and service authorization.
5. Only make a feasibility claim when matching hardware/build runtime evidence agrees with the static policy comparison.

## Non-goals
No protected writes, file replacement, entitlement forgery, cache rebuilding, changes to provisioning/signing, or automatic exploit retries.


## New experimental test: Class 7 flag matrix (own App Group)
In the Watch UI, choose **MG Diagnostics → Run Class 7 flag matrix**.
This compares four flag settings used in published worse_query-related code,
but **only on the app's own entitled App Group**. There is no symlink
and no request for foreign application or SystemGroup access.

The matrix records per flag:
- MCM query result present or absent.
- Returned container path (expected: own App Group).
- Sandbox token present or absent.
- Extension consume and release results, when the APIs are available.

The test saves \`Documents/class7-flag-matrix.txt\` and prints \`[Class7Matrix]\`
in the Xcode console. A successful token is **not** evidence that protected
MobileGestalt writes are authorized.

### New evidence needed
The existing Watch log used the combined flag and a symlink; the new
control provides a no-symlink baseline for the iOS 26 alternate flag. If
the plain Class 7 group query can produce a token while the symlink query
cannot, the failure is *not* simply a missing App Group entitlement.
A denied SystemGroup file-write action must still be investigated
independently; this control does not test for an exploit or bypass.
