# Independently extracted watchOS SystemGroup sandbox rules (2026-11-17)

**Status: confirmed firmware-level reason for the observed MobileGestalt EPERM on watchOS 26.6.1; NO working bypass demonstrated.**

## What was executed

This investigation used actual Apple-CDN IPSW archives and pinned **blacktop/ipsw v3.1.749** in isolated Ubuntu GitHub Actions runners. The runner extracted only the kernelcache over HTTP range requests and decompiled sandbox profiles from those exact kernels. No Apple Watch was modified. Neither full-IPSW SHA-1 checksum was verified because the 5–7 GB archive was queried remotely rather than downloaded in full. Kernelcache files and decompiled-profile SHA-256 digests were recorded.

Runs and raw results:
- [Watch6,18 / 26.6.1 / 23U95 exact hardware](https://github.com/mkalter/TESTAPP/actions/runs/44090713056) — `real-watchos-23u95-sandbox-research`
- [Watch7,5 / 26.6 / 23U67 versus 27.0 / 24R364 on the same hardware](https://github.com/mkalter/TESTAPP/actions/runs/44091320529) — `watch7-5-watchos26-vs27-real-policy-diff`

The reproducible workflow files are in `.github/workflows/research-watchos-23u95.yml` and `.github/workflows/compare-watchos-26-27.yml`. The prior repo already contains a sandbox rule parser in `Research/compare_systemgroup_policy.py`.

## Cryptographic provenance of extracted data

| Hardware / OS | Extracted kernelcache SHA-256 |
| --- | --- |
| Watch6,18 / 23U95 | `ced56594d646bc39261c7f6d4cce8554accc9fd16cce6ec4aa70ad3d98f56261` |
| Watch7,5 / 23U67 | `08d9ea967ac0c1b5d12405fd677a1cc20d4315d443f3a93e23776a70e9c57d0d` |
| Watch7,5 / 24R364 | `e1a8c551e0e17b8323ea75dd6b89cdfa8b38f520efa2463e5e84ce6d0f193cf8` |

All three extracted files were identified by the runner as Mach-O arm64e kernelcache files. Individual decompilation exit codes for `baseline`, `temporary-sandbox` and `containermanagerd` were **0**.

The **entire decompiled containermanagerd profile** of Watch6,18/23U95 and Watch7,5/23U67 has the *same* SHA-256 digest:
`a9775c9dd49f825ff6b1bced3f9b103fe64fb2e709dfd6c4586f32655569e077`.

This proves byte-identical *decompiled text*, not identical source Mach-O binary bytes.

## Finding A — containermanagerd extension issuer gates are different between 26 and 27

**Watch6,18 / 23U95** and **Watch7,5 / 23U67**, profile `containermanagerd`, line ~49:

```scheme
(allow file-issue-extension
  (require-all
    (extension-class "com.apple.sandbox.system-group")
    (subpath "/private/var/containers/Shared/SystemGroup")))
```

The distinct `com.apple.app-sandbox.read-write` issuer rule (line ~70) applies to `/private/var/mobile/Containers/Data/Application`, `InternalDaemon`, `PluginKitPlugin`, and equivalent temporary paths — **not SystemGroup**.

**Watch7,5 / 24R364**, same profile, line ~85:

```scheme
(allow file-issue-extension
  (require-all
    (subpath "/private/var/containers/Shared/SystemGroup")
    (require-any
      (extension-class "com.apple.app-sandbox.read")
      (extension-class "com.apple.app-sandbox.read-write")
      (extension-class "com.apple.sandbox.system-group"))))
```

The newer decompiled `containermanagerd` SHA-256 is
`7bdd5b71ff082d805a69de2218e34a9094a82907040f461ebb55e4a87d6fbe6a`.

**Conclusion:** the broader SystemGroup extension-class issuance is directly verified in **watchOS firmware**, not merely inferred from an iOS sandbox diff.

## Finding B — receiver-side SystemGroup checks still matter

In both the Watch7,5/23U67 and Watch7,5/24R364 decompiled `baseline` profiles, the `allow file-write-data` branches matching extension `com.apple.sandbox.system-group` still refer to the Apple-private entitlements:

- `com.apple.security.system-group-containers`
- `com.apple.security.system-groups`

The Watch6,18/23U95 `baseline` shows the same pair. For example, inspect `baseline.sb` around lines 5100 and 5296 in the 23U95 artifact (around 6074 and 6275 in the watchOS 27 comparator).

Another `baseline` branch admits `com.apple.app-sandbox.read-write` where the profile enables `generic-sandbox-extension-support`; this does **not** establish that a third-party app can obtain such a token for a particular SystemGroup target.

A token existing, its consumption returning success, the kernel allowing `file-write-data`, actual POSIX `open(O_RDWR)` and persistent modification are *separate* checkpoints.

## Finding C — what the path-write query actually says, and its limitations

The 23U95 `ipsw sb query path-write` on the exact MG cache path completed successfully, generating an output with **607 rule entries across 216 profile names**. Many are conditional generic extension rules or file-operation rules that do **not** establish effective permission on the exact path. The parser also warns: **65 related operations and 56 unrelated operations were skipped**, including oversized expressions.

Do **NOT** interpret the count of `allow` entries as 334 processes that are authorized to write MobileGestalt. The report is a candidate-rule inventory, **not** a validated effective permission calculation.

The kernel collection did not have profiles named `containermanagerd_system` or `MobileGestaltHelper`. That does not prove the processes or their executable-level policies are absent; a separate process may use a different named or embedded profile.

## Direct implication for bad_query / worse_query on 23U95

- `bad_query` Class 13 can resolve or yield a `com.apple.sandbox.system-group` token, but the 23U95 `baseline` write gate also requires Apple-private authorization. An unrelated user's physical-Watch experiments already observed `open(O_RDWR)` -> `EPERM` after successful token consumption.
- `worse_query` Class 7 App Group symlink works for eligible app-owned containers, but the 23U95 `containermanagerd` profile cannot issue a generic `com.apple.app-sandbox.read-write` extension for the MG SystemGroup by the inspected rule. This explains why copying successful iOS/watchOS 27 App Group paths has not produced write access on 26.
- Neither a different path string nor another `O_WRONLY` flag can overcome an unfulfilled sandbox entitlement condition.
- The watchOS 27.0 issuer expansion does not automatically make older watchOS 26.6.1 vulnerable or authorize a development-signed app. No new working exploit has been discovered.

## Limits and remaining research

This study independently reconstructed the **kernel policy** but has not independently extracted and audited the 23U95 `MobileGestaltHelper` XPC implementation or every executable's embedded sandbox policy. The published 23U95 helper audit reports `rebuildCache:` and `setCacheSentinel:` but no arbitrary data setter; that report remains third-party research, not independently verified here.

A separately trusted process that has a legitimate MobileGestalt write role is logically a different authority context, but discovering such a process alone is **not** an exploit. A caller-accessible interface accepting arbitrary user-controlled cache content has not been demonstrated.

**Final verified status:** exact 23U95 kernel and two same-hardware comparison kernels extracted; issuer and receiver profiles decompiled and compared; concrete 26-to-27 SystemGroup issuer change confirmed; no effective protected write access or native Hermès system face activation established.

Sources:
- Original implementations: https://github.com/forcequitOS/bad_query and https://github.com/forcequitOS/worse_query
- Physical-Watch logs/static helper claims: https://github.com/pookjw/HermesEnabler/issues/7
- Actual raw run outputs linked above (saved as GitHub Actions artifacts).
