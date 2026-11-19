# 2026-11-18 — Which MobileGestalt edit options really apply to Watch6,18 / 23U95?

**Goal:** a persistent, verified change to the actual original
`systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist`
from the owner's Ultra 1, **not** merely an on-disk local editable backup.
This report is a *provenance and compatibility audit*; no new exploit is claimed.

## Hard platform restriction: cannot switch this Ultra 1 to working watchOS 27 branch

Apple's **18 November 2026** security releases explicitly assign
- **watchOS 26.6.1** to Apple Watch Series 6/7/8, SE 2 and **original Ultra**;
- **watchOS 27.2.1** to Series 9 and later.

Official: https://support.apple.com/en-us/100100

Upstream HermesEnabler supports some watchOS **27.0–27.3 beta 1** builds,
but *this Ultra 1 is not eligible to upgrade to watchOS 27*.
Therefore **do not recommend upgrading this user's Ultra 1 to 27 as a workaround**.
Upstream 1.6/1.6.1 reports for **watchOS 26.6.1**:
https://github.com/pookjw/HermesEnabler/issues/90
explicitly reproduced Class 7 no-token, Class 13 token but protected write `EPERM`.
The correct grant, not code signing or App Group alone, is missing.

## New public project compatibility audit

| Project/approach | What the source actually claims | Proven on Watch6,18/23U95? | Decision |
| --- | --- | --- | --- |
| HermesEnabler 1.6.x / KAMUI / Class 7+13 | Working for selected watchOS 27 builds, watchOS 26 is experimental | **NO**; physical write `EPERM` on watchOS26.6.1, independent reports | No repeat |
| worstgestalt / bad_query / worse_query | MobileGestalt editor for *iPhone/iPad* iOS26/27 using MCM bugs | **NO**; system-group token issued read-only on this Watch | No repeat |
| 3106 | iOS26.0–26.6.1 app-container write, but **explicitly disables system-group / MobileGestalt changes** on that version | **NO**, and not watchOS | Not an MG fix |
| GestaltX / GestaltEdit | iOS 27 MobileGestalt editor; purported watchOS variant has **watchOS26 system file editing blocked** | **NO** | Not an MG fix |
| iOS SparseRestore / BookRestore | Working iPhone/iPad backup restore on older versions, often only through iOS26.1 | **NO** Watch SystemGroup restoration | Do not infer phone-to-watch rights |
| macOS/iOS AirLift (AirTraffic) | Paired Mac→**iPhone** Media syncing file escape; targets iOS app/media filesystem | **NO** Watch6,18 SystemGroup write, and no direct trust bridge | Exclude |
| WatchOS 26.6.1 jailbreak | Public compatibility lists **no tool** | **NO** | Exclude |
| Apple MobileGestaltHelper | Real original signed privileged helper, but identified read-only getServerAnswerForQuestion: (error=9); cache rebuild/sentinel are not setters | **NO** arbitrary MobileGestalt write selector | Do not run rebuildCache |

Sources:
- https://github.com/GoldensHQ/worstgestalt
- https://github.com/QuinnTang74/3106/releases
- https://github.com/RoshanDev/gestaltx
- https://github.com/nxtcoreee3/Mobile-Gestalt-Exploits
- https://github.com/0xjohnnydev/airlift
- https://theapplewiki.com/wiki/Jailbreak/26.x
- https://github.com/pookjw/HermesEnabler/issues/7
- https://github.com/pookjw/HermesEnabler/issues/90

## Two genuine *research candidates* in Apple's security advisories

Apple explicitly documents two bugs **fixed on watchOS 27** with
impact *"An app may be able to modify protected system files"*:

1. **Software Update — CVE-2026-84609**: path/permissions validation bug.
2. **TCC — CVE-2026-86886**: path traversal bug.

Apple advisory:
https://support.apple.com/en-us/149037

But the 27 advisory explicitly refers to **Series 9 and later**.
It does NOT independently demonstrate exploitability of either bug on
**Ultra 1 23U95**. At the current date:
- Public GitHub literal-code queries for both CVEs found metadata/advisory
  mirrors, **not a reproducing watchOS26.6.1 PoC**.
- The current Watch app can look up `tccd` Mach name, but this does not
  imply a usable arbitrary-path write RPC. The original TCC DB migration
  paths audited in `2026-11-18-tccd-original-objective-c-path-audit.md`
  were internally constructed, not demonstrated caller-controlled.
- The original `softwareupdated` Mach bootstrap lookup was
  `BOOTSTRAP_NOT_PRIVILEGED` on this watch; an unrelated vulnerable
  service operation does not become directly callable because the CVE
  has the right general impact.
- The exact affected entry points and whether such a bug permits an
  arbitrary *existing* MobileGestalt-cache file write remain unknown.

**Status**: valid static research leads, **not usable edit options**.
We should not fabricate a working PoC from an advisory, invoke an
unknown daemon with system file paths, or perform a dangerous cache
rebuild without recovery.

## Why "edit a copy, then replace the original" is not a loophole

A plist saved in our own app Documents can be edited normally.
Replacing original requires `file-write-data`, `file-write-unlink`,
directory-create rights, a trusted file-restore service, or an accepted
privileged consumer protocol. The actual app sandbox denies all
relevant protected operations. `NSFileCoordinator`, copied xattrs,
Class7/13 tokens and renaming an app-owned file do not transfer authority.

Similarly an app's team ID, developer signature and App Group are
**not equivalent** to Apple's private
`com.apple.security.system-groups`/related SystemGroup receiver
entitlements. Their omission is intrinsic to normal developer signing.

## Independent dependency: is DeviceBrand=1 even enough?

Actual T7/T8 shows both original Hermès bundles selectively rejected
while the original utility face is accepted. T9 proves only a local
migration lookup for Hermes2025.

The genuine `NTKHermes2025FaceBundle` SHA-pinned disassembly
([run #44283136629](https://github.com/mkalter/TESTAPP/actions/runs/44283136629))
checks `CLKDevice.deviceCategory` whitelist **{2,3,5}**
*before* later `collectionType==5`.
Earlier exact same-build ClockKit V13 analysis finds category 4 or 6
for Ultra classification, separate from DeviceBrand-derived collection.
So an arbitrary working **DeviceBrand=1** edit would **not by itself
prove native Hermes2025 activation**.

The original `CLKDevice _loadDeviceInfo` SHA-verified callsite
[run #44284560059](https://github.com/mkalter/TESTAPP/actions/runs/44284560059)
uses `enumerateSizeClasses:`, `screenBoundsForSizeClass:`,
`screenScaleForSizeClass:` and
`screenCornerRadiusForSizeClass:`, plus separate `deviceBrand`
field interpretation. This suggests size-class input is distinct
from the MG brand but does **not** completely trace the NanoRegistry
provenance or establish whether `main-screen-class` overrides it.

New physical **T10** reads the actual on-watch
`sizeClass,deviceCategory,deviceBrand,collectionType,isUltra`
getters without any spoofing. It is a **compatibility discriminator**,
not an arbitrary system write. T10 IPA build
[44283783343](https://github.com/mkalter/TESTAPP/actions/runs/44283783343)
SUCCESS and requires normal developer signing.

## What would qualify as a *real* MobileGestalt edit discovery?

- Exact Watch6,18, 23U95, nonprivileged original process,
  **verified persistent write** to original plist with correct
  CacheUUID and offset layout, original SHA and rollback proof.
- Re-read with freshly started original system consumer, after
  permissions remain enforced (not just our app-local memory).
- No unsupported daemon operations or untested arbitrary path writes.
- *Separately*, actual native Hermès face shown in stock gallery after
  application exit/reboot. An MG cache byte difference alone is
  not sufficient.

### Conclusion (current public evidence)

**No verified MobileGestalt write exploit exists for this exact device/build
among the inspected public projects.** The new concrete research
candidates are the two Apple-advised older Software Update / TCC
protected-file vulnerability families, but **no public, tested Watch6,18
PoC or authorization path was found**. Avoid repeating the older
MCM/CFPrefsZeroFile/NSFileCoordinator write-open tests.
