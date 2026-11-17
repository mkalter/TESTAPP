# Original watchOS 26.6.1 CoreFoundation cfprefsd write boundary — verified evidence
Date: 2026-11-17; target: Watch6,18 / 23U95. **Actual live protected MobileGestalt write: NOT achieved.** No on-watch changes executed in this investigation.

## Provenance, not inference
- Original 23U95 Apple IPSW, dyld cache ARM64_32, SHA256 `c1d91c5e756ac071643d10f05f89f6b8661447ee1675fefa9c15c80487e7c35e`.
- Extracted CoreFoundation Mach-O SHA256 `f08e572ddcdd26ce33704165a63992ce91fc57c4a90907432b15af7d373acb86`.
- Standalone `/usr/sbin/cfprefsd` SHA256 `2cdadf3bec4ddfc50dea990ac9351ad5223fc61fb701e6c32d2f3e5cc651efbb`. Its __text is only four bytes; the actual preferences logic is in CoreFoundation.
- Exact SHA-checked disassembly workflow success: [#44160988239](https://github.com/mkalter/TESTAPP/actions/runs/44160988239), artifact `14362064930`. Exact nlist symbol records: **13,918**; **21 relevant method implementations resolved**, three requested names absent or optimized out.
- Prior matching class issuer/receiver policy search success: [#44157818530](https://github.com/mkalter/TESTAPP/actions/runs/44157818530).
- One intermediate run #44160244248 could not reach Apple's WKMS FCS-key endpoint, a network timeout; not a firmware-analysis failure. Subsequent exact-hash run succeeded.

## Direct evidence in original firmware
| Apple-original function | VM address | Evidence |
| --- | --- | --- |
| `__CFPreferencesSetValueWithContainer` | `0x1beb10e0` | Validated C implementation; calls `-_CFXPreferences setValue:forKey:identifier:user:host:container:` |
| `__CFPreferencesSynchronizeWithContainer` | `0x1becf7bc` | Validated C implementation; calls `-_CFXPreferences synchronizeIdentifier:user:host:container:` |
| `__CFPrefsCopyFixedUpContainerForMessage` | `0x1bee2754` | Distinct path/container handling with `_withClientContext`, not an open writer for arbitrary clients |
| `__CFPrefsGetPathForTriplet` | `0x1be7dd9c` | Generates ordinary preference path using `__CFPrefsCreatePreferencesDirectoryURLForTriplet` |
| `__CFPrefsGetPathForManagedBundleID` | `0x1be983e8` | Separately generates managed preferences path |
| `+[CFPrefsDaemon _getUncanonicalizedSourcePath:withDomain:...]` | `0x1bea5c1c` | Calls either of those two path generators and normalizes the `/private` spelling |
| `-[CFPrefsDaemon handleSourceMessage:replyHandler:]` | `0x1beb7be4` | Calls client-context, fixed-up domain and container, entitlement and prefix-check helpers before choosing the source |
| `-[CFPDSource cacheFileInfoForWriting:euid:egid:didCreate:]` | `0x1beae3c4` | Real 471-instruction method; performs file/open/create path, not an established existing-file overwrite |
| `-[CFPDSource cleanUpIfNecessaryAfterCreatingPlist]` | `0x1bfdb814` | Distinct creation-cleanup method |
| `-[CFPrefsPlistSource attachSandboxExtensionTokenToMessage:forWriting:]` | `0x1bfd0014` | **Single RET**, not a write-token issuing method on this build |
| `-[CFPrefsPlistSource attachAccessTokenToMessage:accessType:]` | `0x1bf12f40` | Separate method with actual code; not equivalent to a SystemGroup writer |

These are **actual code addresses verified by Mach-O LC_SYMTAB and bounded Capstone disassembly**. Source: `Research/firmware-23u95/trace_cfpreferences_authority.py`. Method names and branch edges alone cannot establish bypassable conditions or a live write.

## External potential vulnerability, with a strict scope limit

An external proof of concept (not tested on Watch6,18/23U95) claims a `cfprefsd` prefix/canonicalization and symlink race that can create one **missing, root-owned, empty file** on iOS 26/27. Source:
https://github.com/Vibecode-organization/holy-videcode-project/tree/claude/blissful-thompson-o0n0dq/murk-sus/asuka4scape/07_PRIMITIVES/smith/intel/CFPrefsZeroFile-PoC

The author expressly says it **cannot overwrite an existing file or control the new file's content**. This matters because the original MobileGestalt cache **already exists and must retain valid serialized binary contents**. Claiming that this PoC unlocks native Hermès, modifies MobileGestalt, or gives arbitrary file writes would be false. Its claimed iOS success has **not been reproduced on 23U95 watchOS**.

## The actual missing condition
A working Watch6,18/23U95 MobileGestalt modification requires:
1. A trusted or newly authorized writer that can **replace existing** `/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist` content with deliberately controlled, valid bytes, not merely create a new empty file;
2. Verified persistent on-disk modification, current-process and post-restart readback;
3. Independent native Hermès availability checks (Poodle/Hermes2025 and first-party face library), which have already been observed restricted on this model.

**Current truthful state:** 0 verified protected writes / 0 native Hermès unlocks. This research does identify a **distinct trusted preferences-daemon authority path** and concretely maps the exact original implementation, but it has NOT demonstrated arbitrary-content authority for a normal Watch app. No protected write, race or reboot was executed on a physical Watch.
