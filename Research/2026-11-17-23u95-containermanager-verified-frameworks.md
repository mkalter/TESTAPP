# Watch6,18 / 23U95: actual ContainerManager framework extraction and authorization evidence

**Date:** 2026-11-17. **Status:** independently extracted and inspected actual 23U95 userland frameworks; **no working sandbox escape or MobileGestalt protected-write permission demonstrated**.

## Reproducible extraction

- Apple CDN full IPSW: `Watch6,18_26.6.1_23U95_Restore.ipsw`.
- The original Apple encrypted APFS was accessed via read-only HTTP byte ranges.
- `blacktop/ipsw` current source compiled with Go 1.27, actual commit recorded in the GitHub Actions artifact.
- Exact run: [GitHub Actions #44097945781](https://github.com/mkalter/TESTAPP/actions/runs/44097945781).
- Output artifact `watchos-23u95-userland-authority-audit` includes source path, SHA-256, size, Mach-O header, relevant strings and command logs, but **not** Apple's original binaries.
- Range access: **112 requests, 22,081,724 bytes transferred** from the ~5 GB IPSW.
- The entire IPSW's SHA digest was **not** verified. This is a remote partial-file extraction, not full-image verification.

## New: exact native ContainerManager frameworks on 23U95

The three expected frameworks could **not** be exported from the `arm64_32` dyld shared cache, but **do** exist as separate system-volume files. A targeted filesystem extraction recovered all four:

| Original path | Size | SHA-256 |
| --- | ---: | --- |
| `/System/Library/PrivateFrameworks/ContainerManagerCommon.framework/ContainerManagerCommon` | 2,291,216 | `6885a8e27e399b2e13cd7df4bf9ac4e18a4c4af2b85937f95ba0038d4cd4fbad` |
| `/System/Library/PrivateFrameworks/ContainerManagerSystem.framework/ContainerManagerSystem` | 35,136 | `3d1ae2bd56b0abd37e54c5925cafc1734055bbd1904d89e1b7954f42fd96f60a` |
| `/System/Library/PrivateFrameworks/ContainerManagerUser.framework/ContainerManagerUser` | 35,136 | `210360e4aa3ed10a7844162f0660f9fc83619a350701c9cf36ebd616021cf364` |
| `/System/Library/PrivateFrameworks/MobileContainerManager.framework/MobileContainerManager` | 131,264 | `233adbb184ef69588f4e2f4e8a088ab6f8557f694a2b6bfb3d74dc198267ca9b` |

All four are real **64_32-bit ARM64_32 Mach-O dynamically linked shared libraries**, with watchOS 26.6 minimum OS and SDK.

## Independently confirmed authorization implementation

The primary implementation is `ContainerManagerCommon.framework`, not the tiny daemon launchers:

- Its Mach-O header identifies `LC_SYMTAB` with **8,497 symbols**, unlike the thin `ContainerManagerSystem.framework` with only **2 symbols**.
- It dynamically loads `/usr/lib/libsandbox.1.dylib` and `/usr/lib/libMobileGestalt.dylib`.
- Its extracted text strings explicitly include `MCMSandboxExtensionType`, `MCMSandboxExtension`, `MCMEntitlementLookup`, `MCMEntitlementAccess`, `MCMXPCMessageQuery`, `MCMResultQuery`, `sandboxAffordances`, `requiredEntitlement`, `sandboxExtensionClass`, `ReplySandboxToken`, and `ReplyContainerTokens`.
- Critically, the actual binary contains literal diagnostics `Exception when authorizing or issuing sandbox extension; error = %s` and `Refusing to issue requested sandbox extension type %s to [%s]`.

These strings constitute **independent binary evidence of an explicit authorization/extension-class rejection mechanism**. They do not reveal every condition, the full control-flow graph or a vulnerability. A denied extension class cannot be made writable simply by changing a filename, returning a nonnull MCM result, or consuming a different token.

Prior independently extracted **kernel sandbox rules** from the same 23U95 build already show that `containermanagerd` can issue only `com.apple.sandbox.system-group` for SystemGroup targets, and the generic baseline write policy requires Apple-private system-group entitlements for that class. The now-extracted userland binary links this receiver/issuer policy to a real service implementation.

## What can and cannot be inferred about a new write mechanism

Confirmed:
- Real Apple-signed `MobileGestaltHelper` has the private `MobileGestaltCache` / `system-group` entitlements and exposes `com.apple.mobilegestalt.xpc`.
- Observed XPC selector names remain `rebuildCache:` and `setCacheSentinel:` — **neither established as an arbitrary device-brand setter**.
- `ContainerManagerCommon` handles MCM entitlement authorization and sandbox-extension type classification.
- The real 23U95 `libMobileGestalt.dylib` was separately extracted from ARM64_32 dyld cache, sha256 `a842db6add515926a9ef49da87bc7467974c8e8b52f7550e40f111c455c42bd0`, and contains the literal `setCacheValue`. That is a text string, **not yet proved callable or exported**.

Unverified:
- No independently validated 23U95 service protocol was found that accepts client-provided replacement MobileGestalt data.
- No bypass of `com.apple.security.system-groups` or alternate writable sandbox-extension issuance was demonstrated.
- Although the Mach-O symbol table is populated, `ipsw class-dump` could not parse these ARM64_32 binaries' ObjC metadata, so the selector inventory is **not exhaustive**.
- No successful `open(O_RDWR)`, cache change, system Hermès face installation or persistent unlock was demonstrated.

## Recommended next *research* discriminator, not another speculative Watch IPA

A **bounded, independent static disassembly** of the already-identified `ContainerManagerCommon` functions that generate the literal `Refusing to issue requested sandbox extension type` diagnostic would establish which call-side and entitlement conditions they check. Likewise an independent ObjC metadata pass on `MobileGestaltHelper` would establish its complete XPC protocol.

This source-level investigation can identify an actual security discrepancy if one exists; the present binaries and strings do **not** prove one. There is no justification for testing destructive protected-cache changes on the user's Watch at this stage.

## Reproduction and source pointers

- Original GitHub Actions workflow: `.github/workflows/audit-watchos23u95-userland.yml`
- Original dyld shared cache workflow and failed ContainerManager exports: `.github/workflows/audit-watchos23u95-dyld.yml`
- Detailed userland helper report: `Research/2026-11-17-23u95-userland-service-audit.md`
- Dyld MobileGestalt notes: `Research/2026-11-17-23u95-real-dyld-cache.md`
- Exact 26 vs 27 kernel sandbox issuer gate: `Research/2026-11-17-verified-watchos26-27-sandbox-diff.md`
- Original exploit examples: https://github.com/forcequitOS/bad_query , https://github.com/forcequitOS/worse_query

**Final status:** independently extracted and inspected actual watchOS 26.6.1 ContainerManager implementation framework; confirmed extension-class rejection mechanism; **no working protected-write bypass found**.
