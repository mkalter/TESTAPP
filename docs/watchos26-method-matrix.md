# watchOS 26.6.1 (23U95): denial analysis and experiment matrix

**Scope:** device-side diagnostics on a stock Apple Watch. All new tests are observational; no protected cache writes, no symlinks, no sandbox bypass and no XPC mutation.

## Already measured in the Watch logs

| Boundary | Result | What it proves |
|---|---|---|
| Direct Class 13 (0x8100000000) | MCM YES, token NO | Container query success alone is insufficient |
| Direct Class 13 (0x0800000000) | MCM YES, token YES, consume SUCCESS | A system-group extension was obtained and consumed |
| Effective file-write-data with this extension | DENY and O_WRONLY EPERM | The token did not authorize a protected write-open |
| File-scoped Class 13 on /var and /private/var | MCM YES, token NO | Both tested domains failed to issue tokens |
| Private system-groups and system-group-containers | ABSENT (SecTask) | The running process does not hold the proposed private entitlements |
| Normal application-groups | PRESENT | The app's ordinary App Group entitlement is active |
| Cache metadata before/after | unchanged | No modification occurred |

**Critical rule:** MCM query != token issue != consumed token != authorized file-write != persistent safe cache update.

## New tests in the Watch app

| Watch button | Log file | Additional evidence |
|---|---|---|
| Root-cause: why EPERM? (new) | mg-denial-root-cause.txt | File owner, process UID/GID and supplemental groups, POSIX DAC estimate, file and volume flags, alias inode identity, sandbox file-write decision, read access |
| Survey alternative APIs (new) | mg-api-survey.txt | Presence of exported MG, MCM, Security, Sandbox, and XPC client symbols without invoking private services or editing methods |
| Check actual entitlements (new) | watch-entitlement-audit.txt | Runtime SecTask claims and FAT Mach-O-aware inspection of signed executable |
| Run complete diagnostics | complete-diagnostics.txt | All the read-only tests in one report |

The old Class 7 / Class 13 and sandbox matrices remain independently accessible. They are *controls*, not automatically evidence of a new write method.

## Independent hypotheses and acceptance criteria

### H1 — The extension lacks file-write-data authorization
Evidence: the token was consumed but the sandbox check remained DENY. The next report confirms whether the baseline policy remains denied. Do not treat a new token handle as write success.

### H2 — POSIX permissions also deny writes
The root-cause report computes a limited owner/group/other permission estimate from stat metadata, real/effective identity and supplemental groups. If POSIX DAC denies, that is a second independent barrier. If DAC permits, a sandbox/MAC gate is more likely. ACLs remain a limitation.

### H3 — Immutable flags, a read-only volume or file protection deny
The root-cause report checks volume and file flags and an available protection-class query from an existing read-only descriptor. The absence of those flags does not rule out all other mandatory access controls.

### H4 — The two path spellings identify separate filesystem objects
Compare /var and /private/var by device and inode. If identical, varying the path spelling does not create a new object or a new entitlement.

### H5 — A private entitlement is included in the requested plist but not in the actual process
Compare the signed executable claims with SecTask on the live Watch. Absent in SecTask means the signing route did not grant it. The presence of a key in a project source plist or an unsigned IPA does not suffice.

### H6 — A MobileGestalt framework export or system service offers a legitimate alternative
The API survey discovers which functions are present; it invokes none of them. A present export does NOT imply the operation is supported or authorized. The independent RO23 research reports MobileGestaltHelper's tested read-only XPC queries returning error 9, not an authorized cache editor.

### H7 — An iOS 26 container trick works unchanged on watchOS 26
The worstgestalt iOS 26 implementation and this Watch's results differ at the sandbox authorization stage. Compare the rules and rights, rather than repeating query flags with no distinct authorization hypothesis.

### H8 — A privileged daemon could write on behalf of the app
A daemon's privilege applies to authorized exposed operations only. The next research task is to study service-side access requirements in matching 23U95 firmware. Do not invoke speculative cache-rebuild or sentinel-changing methods on a working Watch.

## Interpreting the next outputs

| Observation | What to do next |
|---|---|
| Sandbox DENY, DAC estimates ALLOW, volume writable | Concentrate on sandbox authorization and authorized service interfaces |
| Sandbox DENY and DAC estimates DENY | Track both independent blockers; one token alone is insufficient |
| Sandbox ALLOW but protected write-open EPERM | Other filesystem, data protection or MAC checks may still reject |
| Runtime private entitlements ABSENT | Ordinary IPA re-signing cannot make these keys PRESENT |
| Framework symbol PRESENT | Only means the symbol exists; not evidence of write authorization |
| iPhone receives no log | Investigate WatchConnectivity, not the sandbox outcome |

## Recommended next run

On Watch: **MG Diagnostics → Root-cause: why EPERM?**; **Survey alternative APIs**; **Check actual entitlements**.

On iPhone: **HermesEnabler → Watch Logs**, copy or share the three new files. Use the existing Class 13 log as the baseline instead of needlessly rerunning it.

Research references:
- https://github.com/pookjw/HermesEnabler/issues/7
- https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X
- https://github.com/GoldenNugget-Team/worstgestalt
- https://developer.apple.com/library/archive/documentation/Security/Conceptual/AuthenticationAndAuthorizationGuide/Permissions/Permissions.html
