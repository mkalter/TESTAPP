# Verified ARM64_32 dyld shared cache analysis: watchOS 26.6.1 (23U95)

**Device:** Apple Watch Ultra 1, `Watch6,18`  
**Source:** original Apple CDN IPSW, remote APFS reads; no modification of the Watch  
**Workflow run:** [#44096508111](https://github.com/mkalter/TESTAPP/actions/runs/44096508111)  
**Artifact:** `watchos23u95-containermanager-dyld-analysis`  
**Tools:** `blacktop/ipsw`, built from pinned source commit as recorded in workflow artifact

## Successfully extracted and verified

- The original `dyld_shared_cache_arm64_32` set, **31 sub-caches**, **1,571 images**. Only the individual main cache's checksum is in `dyld-cache-sha256.txt`, NOT an independent SHA-256 of all linked cache segments.
- Extraction requested **1,971 HTTP byte-range requests**, transferring **809,065,355 bytes** of the original 5 GB IPSW; the entire IPSW SHA was not verified.
- The exported real `/usr/lib/libMobileGestalt.dylib` is a **991,768-byte ARM64_32 Mach-O dylib**, watchOS 26.6 SDK, SHA-256 `a842db6add515926a9ef49da87bc7467974c8e8b52f7550e40f111c455c42bd0`.
- Mach-O contains **1,437 symbols** (1,132 external + 305 undefined according to `LC_DYSYMTAB`) and source name `MobileGestaltCache.c`.
- Extracted strings include `setCacheValue`, `__MGRebuildCache`, `__MGWriteRebuildCacheSentinel`, `__MGRebuildCache4PurpleRestore`, `_MGCopyAnswer`. `setCacheValue` appears as a text string, **not yet demonstrated as a dynamically exported setter or user-callable function**. It cannot be treated as an alternative to the absent `MGSetAnswer`.
- The extracted lib matches the live Watch user's observation that `MGCopyAnswer` is present while the `MGSetAnswer` setter was absent at runtime; this study has not independently verified a precise exports list.

## ContainerManager frameworks: target location unresolved

The daemon launchers are linked to these frameworks:

- `ContainerManagerCommon`
- `ContainerManagerSystem`
- `ContainerManagerUser`

The workflow checked the active cache image list and attempted to export all three under the expected `/System/Library/PrivateFrameworks/...framework/...` full install names. **All three returned `image not found in cache`**, while the same command successfully exported `libMobileGestalt.dylib`.

Thus, no ContainerManager framework code was disassembled in this run. That is not proof that they are absent from the complete system image: they may be ordinary filesystem executables, use different install names, or reside in another cache.

## Next independent physical APFS check

The existing `.github/workflows/audit-watchos23u95-userland.yml` now searches for the corresponding standalone `.framework` binaries in the same genuine watchOS 23U95 APFS source. In this investigation, **successful action status does not by itself imply a binary was located**: verify `extracted-files.txt`, Mach-O metadata, source hashes and per-command error codes before drawing any conclusion.

## Authorization finding remains unchanged

The exact 23U95 sandbox `containermanagerd` issuer rule limits SystemGroup to `com.apple.sandbox.system-group`, and the receiver-side `baseline` requires private system-group entitlements. Neither an existing `setCacheValue` string nor the ability to parse the dyld cache gives a third-party Watch app a protected write descriptor.

**No new bypass, no native Hermès activation, no destructive cache writes demonstrated.**
