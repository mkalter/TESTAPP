# Rust505/CVE-2026-112477 vs Ultra 1 on watchOS 26.6.1 — verified source review

Date: 19 November 2026. Target: original Ultra 1 `Watch6,18`,
`arm64_32`, watchOS `26.6.1 (23U95)`. Objective: original protected
MobileGestalt cache write for native Hermès. No cache write demonstrated.

## Repository provenance — current state and actual older source

Original user-provided repository:
https://github.com/Rust505/CVE-2026-112477

At inspection the default-branch tree contains only `README.md`,
`docs/ANALYSIS.md` and MIT `LICENSE` — **no source or build script**.
Git history:
- `f9d581b6e09bc8cb7557b7329106dec8d3040053` (2026-11-19
  08:30 UTC) did contain `src/entry_isurf_uaf.m` and `build.sh`.
- `4842aa9eaf4db908ba9812b376c1b98724f61b6b` (10:14 UTC)
  deleted `build.sh`.
- `d3333d56b78b6af4b711a0acbf7bd680a2112443` (12:34 UTC)
  deleted `src/entry_isurf_uaf.m`.

Current README refers to `./build.sh` and `src/entry_isurf_uaf.m`;
those directions cannot run against the latest tree. Historical
build.sh targets **iPhoneOS arm64** and even labels its IPA
`RUSTJailbreak`, whereas README explicitly says **no privilege
escalation, no kernel code execution** demonstrated.

## What the Rust505 repository actually establishes

- Reported tested environment: **iOS 26.4 build 23E246, arm64e**,
  explicitly *not* an original Watch Ultra 1.
- Author's reported controlled conditions: registry-lifetime
  / stale-entry result difference, 40/40 "dup success" with heap
  reclaim attempt vs 0/10 without. This is the author's report;
  we have not independently replayed it.
- Author explicitly states **entry field layout not mapped**, no
  kernel arbitrary read, no kernel arbitrary write, and no root or
  jailbreak. "dup=0x0" is a method return code, not proof that
  MobileGestalt is writable.
- The historical source includes a **race/panic-style** IOSurface
  harness with many attempts and memory recycling. It is not suitable
  to run unchanged on a daily paired Watch; no such code was copied
  into this test app.

## Independently verified true Ultra1 original firmware finding

GitHub Actions
https://github.com/mkalter/TESTAPP/actions/runs/44493672991
SUCCESS, with actual Apple 23U95 IPSW kernelcache ranged extraction:

- `kernelcache.release.Watch6,18`, size **50,151,424 bytes**.
- SHA256 `ced56594d646bc39261c7f6d4cce8554accc9fd16cce6ec4aa70ad3d98f56261`.
- Literal original binary contains `IOSurfaceRoot` **39** times,
  `IOSurfaceRootUserClient` **9** times, and
  `com.apple.iokit.IOSurface` **19** times.

**This is solid evidence that the exact Watch kernel contains the
relevant component family.** It is NOT sufficient to prove that
the same vulnerable user-client selector implementation exists,
that ordinary developer-signed watchOS apps can open that client,
or that any UAF occurs there. Pure string counts do not show control
flow, semantics, race behavior or security impact.

## T13 — actionable benign integration in our actual iPhone + Watch app

New independent Watch UI:
`Native Face Lab → T13 · IOSurface CVE-2026-112477`.

Implementation `BQRunIOSurface112477Reachability()` in the existing
`HermesEnabler2/BQNativeFaceBoundaryLab.m`:
- Locate genuine `IOKit.framework` functions dynamically;
- match actual `IOSurfaceRoot` kernel service by class;
- if found, attempt **one normal user-client type 0 open** and
  **immediate close** with no external method or buffer payload;
- report presence of `IOSurfaceCreate` and `IOSurfaceGetID` symbols
  in the genuine on-watch IOSurface framework, without creating a surface;
- report sandbox preflight for original protected MobileGestalt cache
  **without write-open**.

Report `cve-2026-112477-iosurface-service-preconditions.txt`,
transferred to iPhone by existing WatchConnectivity saved report flow.
The T13 code contains **no** `IOConnectCallMethod`,
`IOConnectCallAsyncMethod`, selector 17/18, surface registration
or deregistration, heap spray/groom, concurrent stress, private
entitlements, file mutation or cache rebuild.

Interpretation:
- Service not found: this app cannot resolve this original
  kernel class through the ordinary query; do not infer the
  class is absent from kernel (presence proven).
- Service found, open fails: watch app cannot open the relevant
  client in this regular context; not an exploit.
- Service found, ordinary type-0 open succeeds: user client is
  reachable, still **not** a UAF proof, kernel read/write primitive,
  jailbreak, sandbox escape or MobileGestalt writer.

## Actual route judgement

This project is *more promising as vulnerability research* than
a reproducible panic-only demo, since it claims controllable
stale-state validation. Nevertheless it is **not a working
MobileGestalt edit option**. Next inference requires an original
S8/23U95 implementation comparison and evidence that the vulnerability
works as a non-crashing, controlled primitive on that exact target
before considering any persistent protected-file change.

Do not run the historical crash/race PoC on the user's primary Watch.
No original FaceStore/Carousel state changed; no native Hermès
unlock claimed.
