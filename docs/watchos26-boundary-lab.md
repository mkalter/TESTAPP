# watchOS 26.6.1 (23U95) — differential authorization experiments

**Source:** `HermesEnabler2/BQBoundaryDifferentialLab.m`  
**Watch UI:** MG Diagnostics → Differential security lab (ACL + controls)  
**iPhone output:** `mg-boundary-lab.txt`

## Why these tests are distinct

Already measured: owner UID 501, mode 0644, writable APFS, normal own-AppGroup write PASS, protected MobileGestalt `open(O_WRONLY)` EPERM, private cache entitlement absent, MCM system-group token consumed but no change to protected write authorization, Mach service reachable.

The new lab is NOT another MCM flag test or an attempt to write MobileGestalt. It compares **read-only facts about the protected object** against **real read/write behavior of two isolated app-owned replicas**. Specifically, it addresses the previously unresolved ACL, xattr, file-descriptor and sandbox-preflight mismatch.

## Test coverage

| Category | MobileGestalt target | Isolated own Documents and own App Group controls |
|---|---|---|
| sandbox_check | Read, write-data, create, unlink, chmod, xattr policy only | Same operations, before/after own-file create |
| file open | O_RDONLY only | O_CREAT/O_EXCL/O_RDWR, O_WRONLY and O_RDONLY |
| file contents | Bounded read + SHA256 digest only; never logged | Writes a disposable test payload and computes SHA256 |
| vnode identity | lstat before, fstat from read descriptor, lstat after | Same on created own file |
| ACL | acl_get_fd / acl_get_entry if exported | Same on own file |
| extended attributes | listxattr/flistxattr names only (no values) | Same on own file |
| file protection | F_GETPROTECTIONCLASS on existing read descriptor | Same |
| canonical path | F_GETPATH (if supported) | Same |
| filesystem | fstatfs flags on read fd | Same |
| cleanup | No MG cleanup/mutation | Removes randomly named control directory |

Security restrictions: **no sandbox tokens** requested or consumed; **no XPC request**; **no `O_WRONLY` on protected file**; **no protected write, rename, chmod, xattr modification or cache rebuild**. Writes are limited to random app-owned temporary file trees. Test control directories are removed even after a failed own-file create, and cleanup status is logged.

## Stop / interpretation criteria

**A — MG ACL has no entries; DAC owner write YES; mount writable; MG write-open EPERM.**  
This narrows causes to mandatory authorization (sandbox/storage class/other MAC) more than ACL or POSIX owner bits. It does **not** show that adding a private entitlement to a normal signing plist is sufficient.

**B — MG ACL has explicit entries; own controls differ.**  
ACL could contribute but its existence is not by itself proof of denial. More precise ACL flags would require a different, separately justified, read-only inspection.

**C — Path-based xattr read DENIED while descriptor-based xattr read ALLOWED.**  
The path traversal and already-open vnode permit different observations. This is *not* a protected write primitive.

**D — Own App Group sandbox_check DENY, but real own-file create/write PASS.**  
Shows that a sandbox-check result is not a definitive predictor of all actual filesystem calls. This disagreement was previously observed once at the App Group root; the control repeats it for a nested owned file with matched operation semantics.

**E — F_GETPROTECTIONCLASS protected vs own files differs.**  
Data Protection class may be relevant to *when* a file is accessible; it is different from authorization to write a system-group cache. The older log reported class 4 for MG; Apple documentation describes Class D as no special locked-state protection. Never infer an authorization bypass from class differences.

**F — All new controls and introspection agree with old observations.**  
No novel device-side route has been found. The next worthwhile work is exact watchOS 23U95 static sandbox/authorization analysis rather than further randomly chosen path/flag combinations.

## Why direct privilege acquisition is unresolved

Published exact-build MobileGestaltHelper binary inspection reports `com.apple.private.security.storage.MobileGestaltCache = true` and `com.apple.security.system-groups`; the current Watch app reports both absent via SecTask. The Helper exposes read queries and cache maintenance but no confirmed arbitrary value-specific setter. A service name lookup and consumed SystemGroup extension do not override the per-file cache security policy.

A confirmed write route would require independently verified authorization and safe behavior. No such route has been demonstrated; this lab does not claim one.

## References

- [Apple Platform Security: Data Protection classes](https://support.apple.com/guide/security/data-protection-classes-secb010e978a/web)
- [23U95 MobileGestaltHelper firmware analysis](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V08-Firmware-Analysis.md)
- [23U95 libMobileGestalt question/server authorization](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V09-MobileGestalt-Analysis.md)
- [iOS 27 Platform sandbox policy diff (not exact watchOS policy)](https://github.com/blacktop/ipsw-diffs/blob/main/iOS/27_2_24B115_vs_27_3_24C5037i/SANDBOX/Platform/platform.md)


## Device results: 2026-11-16, watchOS 26.6.1 / 23U95

The first on-watch execution of \`mg-boundary-lab.txt\` gave the following.

| Measurement | Protected MG cache | Own Documents control | Own App Group control |
|---|---|---|---|
| Owner/Unix mode | 501:501 / 0644 | 501:501 / 0644 | 501:501 / 0644 |
| ACL | 0 entries | acl_get_fd: ENOENT (none) | acl_get_fd: ENOENT (none) |
| Data Protection class (F_GETPROTECTIONCLASS) | 4 (= Class D, No Protection) | 3 (= Class C, protected until first authentication) | 3 (= Class C) |
| xattr names | com.apple.dataprotection.policy.exception-applied-by | none | none |
| APFS mount | writable | writable | writable |
| Before/after inode, size, mtime | unchanged | unchanged during inspection | unchanged during inspection |
| Sandbox policy file-write-data | DENY(1) | ALLOW after creation | ALLOW after creation |
| Actual O_WRONLY | EPERM in previous on-watch probe | ALLOW | ALLOW |
| Actual create/write/read/delete | not attempted | PASS | PASS |

Protected MG SHA256 at the time of observation: \`790bb8502e549411bca755fea769fc2af96f963565c867133564571402db5313\`; size 13,325 B; inode 467170. These values are **observational fingerprints**, not safe modification targets. They should not be treated as a backup or substituted for a recoverable original.

### What this rules out

- **Ordinary Unix DAC:** owner UID and mode alone allow writing. A POSIX ACL denial was not seen.
- **Read-only volume or immutable file:** mount is writable, file flags 0.
- **Wrong symlink / vnode:** \`lstat\`, \`fstat\`, and \`F_GETPATH\` refer to the same file.
- **Data Protection locking:** the MG file is *less* restrictive cryptographically (Class D) than own controls (Class C). Its read succeeds, so Class D does not explain EPERM.

The xattr name \`com.apple.dataprotection.policy.exception-applied-by\` appears in Apple's iOS system tools and a publicly analyzed app-backup encoder as a record identifying the party that applied a Data Protection exception. Its presence is **not** evidence of an authorization capability, an entitlement grant, or a bypass. This test did not read its value.

### Preflight clarification

The old apparent contradiction "sandbox DENY but own App Group actual-write PASS" is **not established for a single unchanged existing file**: in the new log, queries against the own control path **before it existed** returned DENY, but after creating the file every queried policy returned ALLOW and actual O_WRONLY was allowed. The earlier own App Group *root* preflight DENY is an independent observation that must not be conflated with these per-file controls.

For the existing MG file, preflight \`file-write-data=DENY\` and actual open \`EPERM\` agree. The lab still cannot identify the precise sandbox profile clause or prove that a private cache-storage entitlement alone would change the result.

### Next priority

Do **not** repeat Class 7/13, bootstrap lookups, or chmod/xattr mutations. The next genuine evidence would be a **matching watchOS 23U95 platform sandbox profile or equivalent authoritative code** that establishes the storage-class authorization predicate, plus a *documented authorized* value-specific system interface. An iOS 27 platform diff referencing \`storage-class "MobileGestaltCache"\` is circumstantial, not exact-watchOS proof.

Sources:
- [Apple XNU content protection definitions (Class C = 3, Class D = 4)](https://github.com/ravynsoft/ravynos/blob/main/Kernel/xnu/bsd/sys/content_protection.h)
- [Apple Platform Security: Data Protection classes](https://support.apple.com/guide/security/data-protection-classes-secb010e978a/web)
- [iOS 26 decompilation: exception-applied-by as an xattr](https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/usr/libexec/applekeystored/applekeystored_03.mm)
- [MobileBackup integrity checker: ignoring exception-applied-by on metadata comparison](https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/PrivateFrameworks/MobileBackup.framework/MobileBackup/MBSnapshotIntegrityVerifier.mm)
