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
