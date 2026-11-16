# watchOS 26.6.1 / 23U95 — actual MobileGestalt writer investigation

Date: 2026-11-16. Target: stock, normally signed Watch app. Goal: change the actual persistent MobileGestalt cache, not just resolve its path or read it.

## Executive technical answer

There are **two distinct protections** and **two types of writers**:

1. **Our app's direct file-write path:** For the examined 23U95 Watch app container sandbox, a system-group extension token by itself is insufficient. The decompiled 23U95 container policy reported in HermesEnabler issue #7 requires the system-group extension **and** a corresponding private system-group entitlement for the relevant file-write-data rule. Our app has consumed the extension but lacks the entitlement; both sandbox_check and actual O_WRONLY deny.
2. **Apple's privileged cache writer:** The matching 23U95 MobileGestaltHelper has two private entitlements: com.apple.private.security.storage.MobileGestaltCache=true and com.apple.security.system-groups including systemgroup.com.apple.mobilegestaltcache. It can regenerate the cache internally. Its known XPC interface does **not** accept an arbitrary replacement value, plist or output path.

It is therefore not useful to retry Class 7/13, normal signing keys, or an XPC service lookup. Those have already been measured. We need to identify an **authorized, input-controllable writer** or a distinct, independently validated security research finding. None has been confirmed.

## The two relevant sandbox boundaries

### 1. Exact-build container policy evidence (watchOS 23U95, external researcher)

In pookjw/HermesEnabler issue #7, a Series 8 / 23U95 researcher states that decompiled **container** profile rules require both:
- an active com.apple.sandbox.system-group extension; and
- com.apple.security.system-group-containers **or** com.apple.security.system-groups authorization.

This is an external research statement about the actual firmware, not a full raw profile independently extracted in our repository. Reproducing on the owner's hardware still requires the underlying compiled policy.

Our on-Watch SecTask and sandbox tests align with the denied behavior. We must not label the private group entitlement as *the only possible* authorization check.

### 2. Storage-class security (iOS 27 comparative data, not exact watchOS)

blacktop/ipsw-diffs includes platform policy logic for storage-class MobileGestaltCache and a condition referring to com.apple.private.security.storage.MobileGestaltCache. The native watchOS 23U95 Helper possesses that private entitlement. This supports an additional security-class hypothesis, but the iOS 27 policy itself is **not** proof of the exact watchOS 23U95 policy.

## Firmware-derived writer inventory

| Candidate in firmware | Demonstrated behavior | Arbitrary DeviceBrand or arbitrary plist input? | Assessment |
|---|---|---|---|
| MobileGestaltHelper / internal _MGWriteCache | Apple-privileged generation of cache | No known user-supplied value/path interface | Real writer; no configurable sink |
| MobileGestaltHelper / rebuildCache: | Calls _MGRebuildCache, which may unlink existing cache then regenerate | No value, plist or path argument | Real but dangerous maintenance operation; NOT a safe test |
| MobileGestaltHelper / setCacheSentinel: | Fixed rebuild marker updated using boot-derived state | No user-supplied data/path | Fixed-path maintenance, not MG setter |
| MobileGestaltHelper / getServerAnswerForQuestion:reply: | Server-side read query with per-key descriptor gate; prior XPC returned error=9 | No | Getter; not a writer |
| libMobileGestalt / MGCopyAnswer | Local cached reads and provider fallback | No | Read-only |
| libMobileGestalt / MGSetAnswer | Not exported by the Watch app's tested 23U95 dylib | No exposed implementation demonstrated | Not a route |
| MobileGestaltMigrator (iOS 26.1 decomp) | Invokes _MGWriteCacheOnHelper during migration | No arbitrary cache data accepted by the shown callback | Candidate to search for in **watchOS**; existence here unverified |
| DeviceBrand provider on watchOS 23U95 | Reads marketing-software-behavior from IODeviceTree:/chosen | Underlying source not writable by ordinary app | Explains why simple cache rebuild is not a value change |
| iPhone pairing/backup/restore | Apple supports restoring Watch data from paired iPhone | No evidence of user-controlled SystemGroup cache restore on 23U95 | Unverified; no demonstrated write target |
| Memory-local MobileGestalt override | Could affect a process's own lookup results | No persistence or system-wide watchface process effect shown | Not equivalent to editing file |
| Altered OTA / firmware image | Would require Apple's verified update/boot trust path | Ordinary developer signing cannot authorize image replacement | Not a stock Watch-app path |

### New source-level evidence behind the writer table

The publicly decompiled **iOS 26.1** MobileGestaltHelper shows startup calling _MGSetServer and, when _MGCacheValid is false, calls _MGWriteCache. In the iOS 26.1 libMobileGestalt cache writer implementation, _MGWriteCache constructs CacheData and CacheExtra using MobileGestalt answers rather than receiving an arbitrary plist from an XPC caller. The same source attempts to set backup-exclusion metadata on the cache container.

That is important because a *writable cache-generation operation* does not imply the caller can choose the generated values. It also makes an iPhone backup-restore overwrite hypothesis weaker. It does **not** prove identical call flow in watchOS; the exact watchOS _MGWriteCache function still needs matching-binary analysis.

The matching **watchOS 23U95** study verifies that its DeviceBrand provider derives the value from IODeviceTree:/chosen (marketing-software-behavior, byte offset 2) rather than a normal application preference. No alternate supported user-writable provider was found in the inspected code.

### Error=9 is not the file-write problem

The exact 23U95 helper calls _MGServerCopyAnswerWithError. Its DeviceBrand, ProductType and BuildVersion question descriptors in the analyzed library have flags 0x0C (the relevant server-eligibility flag is absent and the fallback callback is null). Prior calls returned error=9, explained by that per-question gate. The Helper is reachable, as our own bootstrap_look_up confirmed. None of this demonstrates a user-controlled write capability.

## Three genuinely distinct avenues to inspect next

### A. Find any OTHER privileged firmware component with a controllable MobileGestalt write sink (highest research priority)

Search **all executable images and extracted dylibs** in the matching watchOS firmware for private cache-storage entitlement, system group entitlement, _MGWriteCache, _MGWriteCacheOnHelper, _MGRebuildCache, and cache paths. For every candidate, inspect *actual method arguments and call sites*:

- Does the method permit a **specific replacement value** or merely trigger a rebuild?
- Does an authorized caller have any control over a content source?
- Is the operation defined for an ordinary client, or protected by a private entitlement?
- Can the resulting value persist across cache regeneration without defeating DeviceTree source rules?

A raw string or imported symbol is NOT evidence of reachable privileged functionality. The new read-only scanner at tools/mg_firmware_audit.py inventories candidates and profile excerpts from extracted firmware, but does not perform semantic call graph analysis.

**Evidence gate:** at least one analyzed call site must accept value-specific data and commit it to the protected cache under an authorized client contract. Nothing inspected so far meets that condition.

### B. Investigate alternate value *sources* rather than cache rebuilding

For DeviceBrand, the confirmed provider is IODeviceTree:/chosen, not SBTeaLeafOverrides.plist or OverrideSoftwareBehaviors.plist. The provider does not expose a normal writable preference override. A firmware study should search for other legitimate override sources *on the exact 23U95 build*, and confirm a dataflow from that source to DeviceBrand. Updating unrelated display preferences, pairing records or CacheExtra is not that evidence.

**Evidence gate:** find an authorized input and an actual dataflow to this specific MobileGestalt answer. Currently absent.

### C. Inspect watchOS system migration and restore paths offline

iOS 26.1 contains MobileGestaltMigrator calling _MGWriteCacheOnHelper. Apple Watch backups are stored with paired iPhone data, but that fact does not mean the backup can overwrite system-group cache files. Determine whether **watchOS 23U95** includes that migrator and whether any restore/migration method accepts a user-provided MobileGestalt cache replacement. Before proposing a test, establish destination allowlist, signing requirements, input validation and failure/recovery behavior from the exact firmware.

**Evidence gate:** a supported, value-specific operation on the actual watchOS build. No demonstrated method in this category yet.

## Scope exclusions — already tested, or not a new path

- Class 2/7/12/13 MCM tokens, traversal flags, app-group symlink candidates: investigated; no actual MG write.
- POSIX DAC, immutable flags, ACL, Data Protection class: tested; no ordinary filesystem explanation.
- MobileGestaltHelper reachability: proven by bootstrap lookup; connection access is not an arbitrary setter.
- Adding private entitlement strings to Xcode project/signature without Apple authorization: cannot grant effective rights.
- Calling rebuildCache/setCacheSentinel on live Watch: may modify or delete cache but cannot set desired value; should never be used as speculative validation.
- Reusing iOS 26.1 or watchOS 27 arbitrary offsets and sandbox claims without checking 23U95.

## Host-only scanner added to TESTAPP

Source: tools/mg_firmware_audit.py

Self-test: GitHub Actions workflow Verify offline MobileGestalt firmware audit, which validates a synthetic cache-write string, entitlement plist and sandbox text.

For a locally extracted, hardware-matched 23U95 directory:

    python3 tools/mg_firmware_audit.py --root /path/to/extracted/23U95 --build 23U95 --output mg-firmware-audit

Creates report.md and inventory.json. This is source inspection, does not send data or edit firmware. It skips files >64MiB, including raw dyld cache segments, so extracted individual dylibs are needed for meaningful coverage. It does not verify the input is actually from build 23U95.

**Current limitation:** no binary dataset from this user's own watchOS 23U95 firmware was supplied to, or available in, the working environment. The tool is tested on synthetic fixtures but has NOT scanned the entire target firmware; this report does not claim that it has.

## Primary evidence links

- Exact-build watch container policy and real denial: https://github.com/pookjw/HermesEnabler/issues/7
- Native 23U95 MobileGestaltHelper, methods/entitlements: https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V08-Firmware-Analysis.md
- Native 23U95 libMobileGestalt query/DeviceBrand provider: https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V09-MobileGestalt-Analysis.md
- iOS 26.1 Helper decomp: https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/usr/libexec/MobileGestaltHelper/MobileGestaltHelper.mm
- iOS 26.1 cache generation decomp: https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/usr/lib/libMobileGestalt/libMobileGestalt_03.mm
- iOS 26.1 migrator decomp: https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/main/System/Library/DataClassMigrators/MobileGestaltMigrator.migrator/MobileGestaltMigrator.mm
- iOS 27 platform sandbox policy comparison: https://github.com/blacktop/ipsw-diffs/blob/main/iOS/27_2_24B115_vs_27_3_24C5037i/SANDBOX/Platform/platform.md
- Apple Watch backups: https://support.apple.com/guide/watch/restore-apple-watch-from-a-backup-apdaa8cc32e8/26/watchos/26
- XPC service sink audit (other Apple platform and build; only comparative): https://github.com/dawgyg/AppleResearch/blob/main/agent_guidance/helper_sweep_results.md
