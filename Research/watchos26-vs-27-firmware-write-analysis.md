# watchOS 26 versus 27: MobileGestalt SystemGroup write authorization

Status: source-grounded analysis, 2026-11-16. **Not a successful write method**.

## Executive finding

For a normally development-signed Watch app on watchOS 26.6.1 (23U95), the examined Class 13 MCM path can return an accepted `com.apple.sandbox.system-group` token while `file-write-data` on the MobileGestalt cache remains denied. The reported 23U95 container sandbox profile requires **both** a system-group sandbox extension **and** an Apple-private system-group entitlement. This best explains the already observed `EPERM` before any bytes are written.

This is a first-hand **published investigation of an extracted Watch6,14 OTA**, not a raw decompiled profile reproduced in this repository. The binary itself has **not** been extracted or independently decompiled here. The relevant watchOS 27 sandbox profile also has **not** been extracted; a literal binary or decompiled-policy diff must not be claimed.

## Firmware pairs and why they matter

| Role | Model | OS build | Source |
|---|---|---|---|
| User target | Watch6,18 (Apple Watch Ultra 1) | watchOS 26.6.1 / 23U95 | [26.6.1 firmware catalog](https://theapplewiki.com/wiki/Firmware/Apple_Watch/26.x) |
| 26 counterpart | Watch7,5 (Apple Watch Ultra 2) | watchOS 26.6 / 23U67 | [26.x firmware catalog](https://theapplewiki.com/wiki/Firmware/Apple_Watch/26.x) |
| 27 counterpart | Watch7,5 (Apple Watch Ultra 2) | watchOS 27.0 / 24R364 | [27.x firmware catalog](https://theapplewiki.com/wiki/Firmware/Apple_Watch/27.x) |
| 27 later comparator | Watch7,5 (Apple Watch Ultra 2) | watchOS 27.2 / 24S118 | [27.x firmware catalog](https://theapplewiki.com/wiki/Firmware/Apple_Watch/27.x) |

Apple says [watchOS 27 is supported only on Series 9+, Ultra 2+ and SE 3](https://support.apple.com/nl-nl/108926); Ultra 1 is not eligible. Therefore no same-device Ultra 1 OS 26/27 runtime experiment exists.

**Correct controlled comparison:**
1. Compare Watch7,5 firmware 23U67 with Watch7,5 firmware 24R364 to isolate the OS generation on **the same hardware family**.
2. Separately compare Watch6,18/23U95 with Watch7,5/23U67 to identify possible hardware-generation or watchOS point-release differences.
3. Only then consider implications for Watch6,18/23U95.

The two Watch7,5 IPSW packages are about 7.0 GB and 5.6 GB respectively, according to the firmware catalogs. No complete extracted filesystem or independently verified binary diff is included in this repo. Do **not** substitute iOS/iPhone sandbox policy for watchOS policy.

## Observed 26 authorization evidence

Source: [HermesEnabler issue #7, research comment on Watch6,14/23U95](https://github.com/pookjw/HermesEnabler/issues/7#issuecomment-6761033695).

- Protected cache **read succeeds**; direct O_WRONLY and O_RDWR open return `EPERM`.
- App's own App Group is signed and accessible; a control file is writable.
- MCM Class 13 + alternate flag returned a sandbox extension; token consumption succeeded.
- The extension was identified as `com.apple.sandbox.system-group`, **not** a general `com.apple.app-sandbox.read-write` permission.
- Reported static policy for `file-write-data`: condition includes extension plus private entitlement `com.apple.security.system-group-containers` or `com.apple.security.system-groups`.
- `sandbox_check` before/after consume: read allowed; write/create/metadata denied.
- Effective UID, file owner, file mode 0644 and file flags do not explain the observed failure; reported denial aligns with sandbox policy.
- Class 7, Class 2 parent rename, Class 12 geod and InstallCoordination entry probes were unsuccessful in the tested conditions.

**Inference:** the Class 13 token on 26 is insufficient for system-cache writing. This does not demonstrate that *all* possible write mechanisms are impossible; it establishes a concrete gate for the inspected route.

## Newly verified iOS reference: blacktop/ipsw-diffs

**Source:** [blacktop/ipsw-diffs — iOS 26.5 (23F77) vs 27.0 beta 1 (24A5355q), Sandbox.md](https://github.com/blacktop/ipsw-diffs/blob/main/iOS/26_5_23F77_vs_27_0_24A5355q/Sandbox.md), in its `##### containermanagerd` section (around lines 36051–36117).

This is an actual textual diff of the **iOS sandbox policy**, not a watchOS extraction:

| Operation/predicate | iOS 26.5 side | iOS 27.0 beta 1 side |
|---|---|---|
| `allow file-issue-extension` for `/private/var/containers/Shared/SystemGroup` | `extension-class "com.apple.sandbox.system-group"` | `require-any` of `com.apple.app-sandbox.read`, `com.apple.app-sandbox.read-write`, and `com.apple.sandbox.system-group` |
| SystemData path | Its own separate class/predicate | Also generalized in the same diff to accept application read/read-write classes and a system-container class |
| App Group path | Earlier `com.apple.sandbox.application-group`-oriented rule | Other application sandbox classes also appear in the restructured issuer rules |

**Meaning:** on the inspected **iOS 27 beta**, the ContainerManager daemon's policy allows issuing a generic app-sandbox read-write extension for SystemGroup paths. The inspected iOS 26 policy's corresponding SystemGroup issuance rule lists only the system-group class. This gives a **specific possible explanation** for the broader iOS 27 `worse_query` SystemGroup support.

**Crucial distinction:** `file-issue-extension` authorizes an issuer to produce a token; it does *not* establish that an arbitrary calling app can request it, or that the receiving app's full sandbox policy will accept it for `file-write-data`. A SystemGroup-class token on 26 may still require the app's private entitlement. Do not equate issuing a token with a successful writable file descriptor.

Additional directly inspected references:

- [blacktop iOS 26.5 → 26.6 Sandbox.md](https://github.com/blacktop/ipsw-diffs/blob/main/iOS/26_5_23F77_vs_26_6_23G5028e/Sandbox.md), lines ~2391–2412: MobileGestalt plist is explicitly present in a `file-read*` rule, consistent with direct read succeeding.
- [blacktop iOS 27 beta sandbox `temporary-sandbox`](https://github.com/blacktop/ipsw-diffs/blob/main/iOS/27_0_24A5380h_vs_27_0_24A5390f/SANDBOX/Collection/temporary-sandbox.md), lines ~70–90: the **system-group extension class continues** to appear with `com.apple.security.system-group-containers` / `com.apple.security.system-groups` predicates. Therefore there is **no evidence** that iOS 27 removed *all* system-group entitlement restrictions.
- [blacktop iOS 27 beta `baseline` diff](https://github.com/blacktop/ipsw-diffs/blob/main/iOS/27_0_24A5370h_vs_27_0_24A5380h/SANDBOX/Collection/baseline.md), lines ~7–93 and ~216–274: SystemGroup and read-write-extension predicates are still represented; the diff also contains considerable rule reordering, which must not be mistaken for permission changes.
- [blacktop iOS 26.5 → 27.0 beta sandbox kernel version diff](https://github.com/blacktop/ipsw-diffs/blob/main/iOS/26_5_23F77_vs_27_0_24A5355q/KEXTS/com.apple.security.sandbox.md): kernel sandbox component version and section hashes changed. That metadata alone **does not determine effective permissions**.

**Confidence grading:**

1. **Verified from iOS text:** the 26 → 27 change in `containermanagerd`'s eligible extension classes for SystemGroup.
2. **Consistent with watchOS 26 runtime observations:** the system-group token alone does not permit writes to MobileGestalt on 23U95.
3. **Not verified:** that Watch6,18/23U95 and a watchOS 27 build have the same issuer policy text or accept the same extension classes as these iOS builds.
4. **Not verified:** that the broader iOS 27 issuance condition is sufficient by itself for successful MobileGestalt modifications.

The defensible next cross-check is matching **watchOS** `containermanagerd` issuer rules and the receiving app's `file-write-data` policy. iOS findings narrow the exact rule to compare, but do not provide an operational exploit for watchOS 26.

## 27 facts versus the 26/27 hypothesis

What is independently source-visible:
- [worse_query's official README](https://github.com/forcequitOS/worse_query) lists `/var/containers/Shared/SystemGroup/*` under iOS 27, but not iOS 26.
- [WQFiles](https://github.com/kolbicz/WQFiles) describes system groups as unavailable to its worse_query-based file browser on iOS 26.
- [KAMUI 2.5.2](https://github.com/murk-sus/kamui-escape) adds an iOS 26 App Group flag path but does **not** supply a verified watchOS 26.6.1 system-group write result.
- [HermesEnabler](https://github.com/pookjw/HermesEnabler) lists watchOS 26 support as experimental.

**Unverified hypothesis:** the same effective system group permission requirement is absent, relaxed, or reached by a different token route on watchOS 27. This has **not** been proven by a matching watchOS 27 sandbox binary comparison. A successful iOS 27 demonstration also does not prove watchOS 27 has identical policies.

## MobileGestaltHelper and DeviceBrand alternative path review

Source: [further static analysis from the Watch6,14/23U95 OTA](https://github.com/pookjw/HermesEnabler/issues/7#issuecomment-6761033695), backed by the publicly exposed [WebKit MobileGestalt SPI header](https://github.com/WebKit/WebKit/blob/main/Source/WebCore/PAL/pal/spi/ios/MobileGestaltSPI.h) for read/cache APIs.

| Candidate | Reported behavior | Assessment |
|---|---|---|
| `rebuildCache:` | Calls `_MGRebuildCache()`, accepts no caller-provided plist/DeviceBrand data; cache rebuild may unlink the live plist | **Not** a setter, potentially destructive |
| `setCacheSentinel:` | Writes a fixed boot-UUID marker to a fixed `.rebuild` path | **Not** a general data setter |
| `MGCopyAnswer` and `_MGCacheValid` | Read/query/cache APIs, not a writable DeviceBrand override | No write path shown |
| DeviceBrand provider | Reads `marketing-software-behavior` from `IODeviceTree:/chosen`, byte offset 2 | Read-only system-derived source; not a normal app setting |
| `SBTeaLeafOverrides.plist` | Inspected consumer controls `SBAllowSensitiveUI` | Not a DeviceBrand override |
| `OverrideSoftwareBehaviors.plist` | Inspected consumer controls FaceTime/VoIP behavior | Not a DeviceBrand override |
| `CacheExtra` | Read from protected MG plist | Merely changing an in-memory dictionary does not persist a new system cache |

These findings are **from the published static analysis of 23U95**, not independent decompilation performed in this chat. They identify no supported API for a third-party Watch app to write an arbitrary DeviceBrand value.

## What exactly is missing for a real binary comparison?

Use only legitimately obtained full firmware images and inspect them offline. Record:
1. Model identifier, build number, IPSW or OTA link and verified checksum for **all three** builds.
2. For the selected sandbox profile, its binary path and SHA-256, plus provenance of the decompiler or parser.
3. The full `file-write-data`, `file-write-create`, `file-write-unlink`, and `file-write-mode` rules affecting SystemGroup paths, including entitlement predicates and sandbox extension classes.
4. Whether the same rule is applicable to ordinary third-party Watch apps rather than only system daemons.
5. MobileGestaltHelper XPC method table, permission checks and accepted arguments from both versions. Do not call rebuild methods on a live watch as a mere connectivity test.
6. Actual sandbox denials and token classes from **each watchOS version**, not an iOS simulator.

To establish an OS-level cause, compare Watch7,5/23U67 → Watch7,5/24R364 and corroborate with Watch6,18/23U95. Any finding must be qualified if 23U67 and 23U95 policies differ.

No Watch7,5/24R364 sandbox profile dump was independently located and authenticated in this investigation. Therefore the exact text/byte change for system-group `file-write-data` is **unknown**.

## Current technical decision

1. The failure on 23U95 occurs at **protected file authorization**, not plist offsets, signing or the lack of a readable backup.
2. A **valid system-group token is insufficient** under the observed 26 policy unless the app also satisfies the separate authorization condition.
3. No verified MobileGestaltHelper or other supported DeviceBrand write API was identified.
4. Further repetition of the same Class 7/12/13 inputs does not provide evidence for a new write route.
5. A working 26.6.1 write method has **not** been found; no sandbox escape or protected-write payload is supplied here.

This document deliberately distinguishes **published evidence**, **source code**, **inference**, and **unperformed binary comparisons**.
