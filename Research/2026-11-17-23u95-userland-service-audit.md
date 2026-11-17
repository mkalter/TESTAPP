# watchOS 26.6.1 / Watch6,18: independent userland MobileGestalt and MCM audit

**Date:** 2026-11-17. **Status:** exact extracted Apple userland executables examined, no working protected-write bypass identified.

## Reproducibility / evidence

- Firmware: Apple CDN IPSW `Watch6,18_26.6.1_23U95_Restore.ipsw` (5,047,247,336 bytes as reported by remote zip).
- Method: `blacktop/ipsw` current master built with Go 1.27 on an isolated GitHub Actions Ubuntu runner; `extract --remote --files --ranged` selected only relevant APFS files. This is a read-only analysis of the original watchOS image.
- Transfer: **59 HTTP range requests; 8,309,906 bytes**, from the original firmware. The *entire IPSW hash was not checked*; extracted-file SHA-256 hashes and real Mach-O metadata are recorded.
- Independently completed workflow: [run #44094221855](https://github.com/mkalter/TESTAPP/actions/runs/44094221855), artifact `watchos-23u95-userland-authority-audit`.
- Workflow source: `.github/workflows/audit-watchos23u95-userland.yml`. Raw Apple binaries are not included in uploaded artifact, only digest, metadata, selected strings, and launchd configuration.

### Exact extracted files

| Original filesystem path | Size | SHA-256 |
| --- | ---: | --- |
| `/usr/libexec/MobileGestaltHelper` | 76,112 B | `0e0c05244a3d35753e948783372f18e615ae2032cf7b750dd7a9cc57cfb3626e` |
| `/usr/libexec/containermanagerd` | 54,736 B | `b0c657cdb7b333fb5683c6b2a9cb1b1e9714de0bde2dbb9e047024b0ff93d4e6` |
| `/usr/libexec/containermanagerd_system` | 51,744 B | `4bfb41c65640c39ed9f7b31cf33020e63c30ff48c4a3eadf40db185017bf9fd2` |
| `/System/Library/LaunchDaemons/com.apple.mobilegestalt.xpc.plist` | 424 B | `d2a7063203015e2c371b65cc39fa566dff2c7046cc40366a2463c11c8d5ebd4c` |
| `/System/Library/LaunchDaemons/com.apple.containermanagerd.plist` | 722 B | `bc748c1c513a218da9b58f6a9435b5bb165da2be00bc8e72cd91c092d0220567` |

All three actual executables have **watchOS ARM64_32** Mach-O format, linked against the watchOS 26.6 SDK (the previously extracted *kernel* uses arm64e; don't confuse these architectures).

## MobileGestaltHelper: legitimate cache authority but no arbitrary DeviceBrand setter discovered

Original launchd file identifies:
- Label and MachServices: `com.apple.mobilegestalt.xpc`.
- Program: `/usr/libexec/MobileGestaltHelper`.
- User: `mobile` or `_mobilegestalthelper` selected by a feature flag.

The extracted helper's code-signature text reveals the Apple-private authorization names:
- `com.apple.private.security.storage.MobileGestaltCache`
- `com.apple.security.system-groups` with entry `systemgroup.com.apple.mobilegestaltcache`.

Mach-O imported symbols and ObjC method strings include:
- `NSXPCListener`, `NSXPCInterface`, `NSXPCListenerDelegate`
- `rebuildCache:`
- `setCacheSentinel:`
- `_MGCopyAnswer`, `__MGRebuildCache`

The inspected binary's selected strings **do not demonstrate** any method that accepts an arbitrary plist, key/value, or DeviceBrand override. This independently corroborates the previously published [Watch6,14 / 23U95 static analysis](https://github.com/pookjw/HermesEnabler/issues/7#issuecomment-6761033695).

**Limitation:** `ipsw class-dump` failed on this ARM64_32 binary with `failed to read __DATA_CONST.__objc_protolist pointers: unexpected EOF`. Method strings alone cannot prove the complete absence of dynamically constructed IPC handlers or behavior inside linked libraries. The accessible interface must not be claimed exhaustive until a working ObjC metadata/disassembly pass exists.

Do **not** call `rebuildCache:` as a write test: independently published disassembly reports that it can unlink the live MobileGestalt plist, without accepting replacement values.

## ContainerManager: real logic resides in separate frameworks

Original `com.apple.containermanagerd.plist` starts `/usr/libexec/containermanagerd` with `--runmode=normal`, `--user-container-mode=fixed`, `--system-container-mode=global` and `--system-container-owner=root`.

The same launchd configuration registers:
- `com.apple.containermanagerd`
- `com.apple.containermanagerd.system`
- `com.apple.containermanagerd.upcall` (HostSpecialPort 25)

Both `containermanagerd` and `containermanagerd_system` executables load:
- `ContainerManagerCommon.framework`
- `ContainerManagerSystem.framework`
- `ContainerManagerUser.framework`

Both are very small Mach-O entry-point programs. Therefore auditing these executables **alone** cannot determine MCM query result validation, sandbox extension issuance, path resolution or the full class 7/13 behavior; those need the linked framework implementations. This rules out chasing more random symbols in the stub binaries as meaningful progress.

The `containermanagerd` code-signature strings include Apple-private entitlements such as `com.apple.private.security.container-manager`, `com.apple.private.security.storage.MobileGestaltCache`, and `com.apple.private.sandbox.profile:embedded = containermanagerd`. They are **not** part of a normally developer-signed Watch app and are not transferable by an App Group.

## Independent link with the verified kernel policy

The earlier genuine Watch6,18/23U95 kernel decompilation proved its `containermanagerd` profile can issue only `com.apple.sandbox.system-group` for SystemGroup targets. The receiving baseline file-write rules require Apple-private system-group entitlements. Real Watch6,18 tests already reported an issued and consumed system-group token but `O_RDWR => EPERM`.

This userland audit establishes **which actual privileged process** has legitimate MobileGestalt system-group access, but not an exposed write operation. It cannot be turned into a practical sandbox bypass merely by obtaining its Mach service name.

## Next static-only code audit

An additional workflow `.github/workflows/audit-watchos23u95-dyld.yml` attempts to extract the genuine ARM64_32 dyld shared cache from the same Apple IPSW and inspect `ContainerManagerCommon`, `ContainerManagerSystem`, `ContainerManagerUser` and `libMobileGestalt`.

A completed build, successful cache export, framework extraction and actual source-level/disassembly findings are separate checkpoints. If the dyld extraction fails, report the exact error and do **not** claim to have inspected these frameworks.

**Final status:** Apple userland service identity, private entitlement names and XPC method-name evidence independently grounded in 23U95; no arbitrary writable MobileGestalt setter or working write authorization found.
