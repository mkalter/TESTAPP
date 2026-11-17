# Ultra 1 / watchOS 26.6.1: replacement-chain feasibility + genuinely distinct geod variant

## Asked replacement chain
Copy original `com.apple.MobileGestalt.plist` into app Documents; edit the copy; remove protected original; use `CFPrefsZeroFile-PoC` to create a new original; attempt to restore the modified content.

**Verdict: NOT a working chain under currently demonstrated capabilities.**

| Transition | On-device fact or source constraint | Verdict |
| --- | --- | --- |
| Read original cache | Existing real Watch6,18/23U95 `O_RDONLY` successful; original cache backup valid | AVAILABLE |
| Copy original into app Documents | Already verified real, local copy; preserves content and can be edited inside own sandbox | AVAILABLE |
| Build modified binary plist | Existing project cache-descriptor research verifies DeviceBrand index 103, type 5, offset 0x338 on this exact build | POSSIBLE OFFLINE; not proof of live eligibility |
| Delete the live protected original | `sandbox_check(file-write-unlink)=DENY(1)`; normal class7/13 and file-coordination do not open it writable | **BLOCKED** |
| Rename/exchange patched copy onto original | A file in own sandbox is not an authorised source for replacing the protected destination. Destination directory mutation is separate from copy permissions | **BLOCKED** |
| Run the external `CFPrefsZeroFile-PoC` | Documented bug creates a **missing**, **root-owned**, **zero-length** file only; **does not replace an existing file** | NOT APPLICABLE WHILE ORIGINAL EXISTS |
| Populate the newly created root-owned file | PoC itself explicitly cannot choose the file content; creating a blank cache is potentially damaging | **BLOCKED / UNSAFE** |
| Rebuild cache with privileged helper | `rebuildCache:` regenerates system-derived state rather than accepting a caller-supplied plist; might remove and recreate the cache | NOT A DEVICEBRAND SETTER |

A helper deleting the original would not by itself provide the missing controlled *write* into the replacement. There is **no reversible recovery guarantee** for deliberately deleting the only live system cache.

Sources:
- [Exact 23U95 firmware and cfprefsd research](Research/2026-11-17-exact-cfprefsd-write-boundary-findings.md).
- [On-device multi-route write audit](Research/2026-11-17-multi-route-mg-write-audit.md).
- [Original CFPrefs zero-file PoC](https://github.com/0xjohnnydev/CFPrefsZeroFile-PoC).
- [Exact geod read/write MCM PoC](https://github.com/0xjohnnydev/Geod-MCM-PoC).

## New and distinct actionable research finding

Original existing `BQCore.m` fallback at lines ~715–727 uses:
- Class 12, `com.apple.geod`, part 3, flags `0x8100000000`;
- **twelve** parent components followed by an **absolute** target string;
- raw `sandbox_extension_consume` against the copied sandbox token;
- does not use the original PoC's `container_object_sandbox_extension_activate`.

The August 2026 `Geod-MCM-PoC` instead uses:
- **six** parent components and a **relative** target suffix from `com.apple.geod/Library/Caches`;
- `container_object_sandbox_extension_activate(object, false)`;
- checks whether the resulting target actually opens `O_RDWR`, without modifying it.

These methods are NOT bit-for-bit or behaviorally equivalent. The pre-existing 'Class 12 geod failed' observation therefore **does not rule out the exact reference variant**. However an iOS 26 PoC is not proof that it succeeds on watchOS 26.6.1: the kernel issuer and receiver rules differ by OS and signing context.

## Actual new executable Watch test

Branch: `experiment/23u95-geod-exact-open-only-20261117`.
Files:
- `HermesEnabler2/BQKAMUI26WriteOpen.m`: **`BQRunGeodExactReadWriteOpenTest()`**.
- `HermesEnabler2/BQPermissionDiagnostics.h`: exported Watch function.
- `HermesEnabler2/MGPermissionDiagnosticsView.swift`: manual button **TEST: exacte geod-route (O_RDWR, geen wijzigingen)** and automatic iPhone Watch Logs transfer.
- `.github/workflows/build-unsigned-ipa.yml`: unsigned companion + Watch IPA build.

Strict behavior:
- Only runs on exact `23U95` watchOS 26 and the exact original SystemGroup target path.
- Requires all documented MCM symbol names; no guessed fallback ABI.
- Compares baseline sandbox `file-write-data` and actual `O_RDWR` before activation.
- Checks that MCM's returned path resolves to **only** the expected original cache directory before activating the container object.
- Measures effective sandbox policy **and actual** `O_RDWR` while the extension is active, then checks them again after freeing/revoking the object.
- Compares target `lstat` inode/size/mode/mtime before and after.
- **No `write`, `pwrite`, `ftruncate`, `unlink`, `rename`, symbolic link creation, or cache rebuilding.**
- Saves `geod-exact-open-only.txt` and transfers report to the iPhone.
- Reports success ONLY as an **actual writable descriptor**, **not** an editable/persistent cache. No live Watch result has been claimed.

## What would count as a real breakthrough

At minimum, an on-device result:
`Class12 query result=YES` + `Returned-path matches target=YES` +
`container_object_activate=YES` +
`Activated policy=ALLOW` +
`actual O_RDWR=ALLOWED`.

Even this would prove only effective descriptor authorization, not safe persistent control or native Hermès eligibility. A live file modification must preserve format, restore-ability and consumer semantics; a successful IPA build alone proves none of those.

**Current status:** exact Geod probe implemented; build/run must be checked separately. Protected cache was not touched by this work.
