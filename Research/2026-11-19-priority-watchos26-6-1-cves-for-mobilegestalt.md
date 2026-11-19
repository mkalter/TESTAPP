# Watch6,18 / 23U95: CVEs worth investigating for protected MobileGestalt edits
Date: 19 November 2026. Hardware: original Apple Watch Ultra 1 (S8); OS watchOS 26.6.1 build 23U95.

## Method
Review the exact Apple-authored CNA CVE 5.x records published 2026-09-14 and Apple security watchOS 27 advisory:
https://support.apple.com/en-us/149037
https://github.com/CVEProject/cvelistV5
Cross-check watchOS `affected` ranges from the **CNA** section, not merely similarity to iOS 26.
Cross-check code vs PoC claims on public GitHub searches, as of 2026-11-19.
Also compare with already checked original 23U95 on-device tests T5, T7–T10 and the earlier TCC + MobileGestaltHelper firmware audits.

## The most relevant as-disclosed candidates

| Priority | CVE | Apple component / official impact | Official watchOS affected version range | Relevance / limitation |
| --- | --- | --- | --- | --- |
| 1 | **CVE-2026-86886** | **TCC path traversal**; an app may modify protected system files. | `watchOS <27` | Closest *effect* to existing original MobileGestalt cache. But needs caller-controlled arbitrary existing path accepted by privileged tccd; previous 23U95 static analysis of TCC migration paths did NOT establish such input. No tested watchOS PoC found. |
| 2 | **CVE-2026-84609** | **Software Update** permissions/path validation; an app may modify protected system files. | `watchOS <27` | Equally relevant effect. But original user Watch `softwareupdated` bootstrap lookup previously returned `1100 BOOTSTRAP_NOT_PRIVILEGED`. No proven app-authorized write request or 23U95 PoC. |
| 3 | **CVE-2026-86876** | **CoreMedia** out-of-bounds write; a sandboxed process may circumvent sandbox restrictions. | `watchOS <27` | Best *general sandbox-bypass* candidate. Not necessarily an arbitrary existing SystemGroup file-write or privilege escalation; same-build CoreMedia vulnerable input and watch-app reachability require verification; no credible working Watch6,18 PoC found. |
| 4 | **CVE-2026-84607** | **AVEVideoEncoder** race; a sandboxed app may execute code with kernel privileges. | `watchOS <27` | High theoretical ceiling but needs reachable relevant AVE2 client on Ultra1 and complete exploit; no working 23U95 PoC found. Public `Ping-2o/ios.CVE-2026-84616-84607` documents iOS27 beta→GM code differences and explicitly says it has **no exploit code**, and that its fix-to-CVE mapping is an inference. |
| 5 | **CVE-2026-84523** | **APFS** out-of-bounds write; an app may write kernel memory or panic. | `watchOS <27` | Potential kernel attack surface, but no kernel-write primitive, no verified Watch6,18 reproduction; higher risk and indirect. |
| 6 | **CVE-2026-86903** | **Kernel** out-of-bounds read; an app may disclose kernel memory. | `watchOS <27` | At most an information-disclosure building block, **not** protected file-write authority. |
| Less useful | **CVE-2026-112477** | **IOSurface** race; kernel corruption/panic. | `watchOS <27.2` in CNA; actual 27.2 fixes for Series9+ | Public iPhone 17 Pro Max/iOS 27.0.1 PoC yielded 4/4 panics, **no controlled kernel read/write**. Watch code presence and applicability remain unknown. |

**Note**: Apple may fix bugs in branches with different version labels on different hardware. An official `watchOS <27` generic affected range makes 26.6.1 a credible candidate, but **does not establish same bug on S8/watchOS 23U95**, service reachability or functional exploitation.

## Exclude already fixed before 23U95
- **CVE-2026-28973** — libc integer overflow sandbox escape. Apple confirms fixed in **watchOS 26.6** (released 27 July 2026) at https://support.apple.com/en-us/128068. Running 26.6.1 should therefore include the fix.
- **CVE-2026-43813** — code signing enforcement bypass, fixed watchOS26.6, so not relevant to this already-patched build.
- **CVE-2026-43723** — MediaRemote privilege escalation, fixed watchOS26.6, also already patched.
- **CVE-2026-43785** — File Bookmark read-only-file modification is **NOT listed as affecting watchOS** in Apple CNA. A superficially perfect title is not evidence of watchOS applicability.
- **CVE-2026-65411** — protected filesystem write also is NOT listed as affecting watchOS. Reject absent matching watch build evidence.

## Actual proof-of-concept review
- GitHub exact CVE searches for `86886`, `84609`, and `86876` found the Apple CVE records, advisory mirrors and derived databases but **no demonstrated working original Ultra/23U95 exploit**.
- The only `84607` "PoC" aggregation links to [Ping-2o/ios.CVE-2026-84616-84607](https://github.com/Ping-2o/ios.CVE-2026-84616-84607); the project's **README explicitly states no exploit code included**, analyses are on iPhone 27 build and code/CVE attribution is not independently proven.
- The CVE record's severity/claimed impact is **not** evidence that an unsigned or developer-signed Watch app can simply call a named service to obtain write privileges.

## Practical priority for our goal

1. For direct protected cache modification, first investigate **TCC CVE-2026-86886** and **Software Update CVE-2026-84609** *statically*, with genuine target-service ABI/dataflow in exact original 23U95 firmware and **bounded benign read-only runtime queries only**. The earlier trusted `tccd` static write paths are internal constructs, not demonstrated arbitrary user input; `softwareupdated` client bootstrap is blocked.
2. For an unprivileged developer-signed app, investigate **CoreMedia CVE-2026-86876** as the most directly sandbox-oriented class of bug, but first verify CoreMedia original runtime availability and affected code. Its declared post-exploitation effect does not automatically grant existing SystemGroup file writes.
3. Do not run panic-producing AVE/IOSurface/APFS exploit code on the daily paired Watch until provenance, affected code, a recoverable test setup and a demonstrable benefit have all been established.
4. Even after successful MobileGestalt cache access, Hermès2025's original `isRestrictedForDevice:` checks **`deviceCategory in {2,3,5}` before `collectionType==5`**; `DeviceBrand=1` by itself is not guaranteed to make the face available. T10 can measure the current device identity values, read-only.

## Conclusion
**New best candidate CVE: CVE-2026-86876 CoreMedia for sandbox bypass. Best direct-target candidates: CVE-2026-86886 TCC and CVE-2026-84609 Software Update.** Apple formally lists watchOS <27 as affected for each, but **none is a known working MobileGestalt editor on Watch6,18/23U95**. We cannot claim native Hermès activation, writable cache, or bypassed EPERM. No protected data modified.
