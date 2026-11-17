# Native watchOS 26.6.1 (23U95) face-library daemon method mapping

**Scope:** original Apple `Watch6,18`/23U95 `/System/Library/PrivateFrameworks/NanoTimeKit.framework/nanotimekitd` (arm64_32). This analysis does not change the user's watch and does not imply a native Hermès unlock.

## Source integrity and recovered addresses

- Original daemon binary SHA-256: `103d9ed37894bac21ff30074ab9eaea8ed0f2932245b90dc67323ad914c026a6`.
- Real original byte size: **734,464**.
- GitHub Action [successful run #44124467196](https://github.com/mkalter/TESTAPP/actions/runs/44124467196), artifact `watchos23u95-native-face-library-daemon-control-flow`.
- Script `Research/firmware-23u95/resolve_daemon_objc.py` validates the binary SHA, decodes ARM64_32 Mach-O sections, reads selector references, and matches **relative Objective-C method-list triples**: selector field → `__objc_selrefs`; type field → valid type string; implementation field → `__TEXT,__text`. A method name found via `strings` alone is not sufficient.

| Exact selector | Verified implementation address (VM / original binary, *not* file offset) | Relative method-list entry | Type encoding |
| --- | ---: | ---: | --- |
| `_removeUnavailableFacesFromStore:` | `0x8134` | `0x7455C` | `v12@0:4@8` |
| `_addDefaultFacesToStore:` | `0x8594` | `0x74574` | `v12@0:4@8` |
| `_migrateFacesInStore:` | `0x18DD4` | `0x73044` | `v12@0:4@8` |
| `_migrateBundleFacesInStore:` | `0x21D74` | `0x7307C` | `v12@0:4@8` |
| `_updatePairedSyncState` | `0x34658` | `0x73CC8` | `v8@0:4` |
| `_fromSyncResetWithFaces:orderedUUIDs:selectedUUID:` | `0x3E704` | `0x7394C` | `v20@0:4@8@12@16` |

The Objective-C method field is in the original signed `__TEXT,__objc_methlist` and points to the original `__TEXT,__text` implementation. This is stronger provenance than a string-only grep and provides exact read-only disassembly entrypoints.

## Why it matters for native Hermès

The Poodle/Circulaire FaceBundle independently evaluates `isRestrictedForDevice:true` on the observed Ultra 1 properties (`deviceCategory=4`, `collectionType=9`, hardware-faces flag `false`), as demonstrated in earlier exact 23U95 research. Inserting a configuration into the daemon library could be ineffective if `_removeUnavailableFacesFromStore:` applies the same availability test. The existence of the method **does not prove its implementation or call frequency**: inspect its exact instructions and callers before asserting when it purges faces.

Importantly, neither `bad_query` Class7 AppGroup scope nor Class13 SystemGroup token issuance establishes authority to modify Apple's library database or the protected MobileGestalt cache. The demonstrated original protected MobileGestalt `open(O_RDWR)` still returns `EPERM`.

## Outstanding work / next actual discriminator

1. Extract bounded control-flow for `0x8134` (plus callers), using the original disassembly. A previous workflow processed 103,436 instructions but had an over-escaped regular-expression parser that matched zero PCs; follow-up corrects the parser.
2. Identify which helper the deletion loop invokes to determine availability for `NTKPoodleFace` and how to distinguish a migration-eligible face from an ordinary restricted face.
3. Locate the actual trusted per-watch face collection persistence. Do not infer it is an accessible AppGroup from a `NanoTimeKit` prefix.
4. A valid on-device success requires original Hermès face in native Carousel after app termination and watch restart, not an error-free return code or in-app preview.

**Status:** verified mapping, **no new exploit and no native Hermès unlock**.
