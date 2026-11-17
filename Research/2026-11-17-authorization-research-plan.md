# watchOS 26.6.1: authorization evidence and next research questions

Date: 2026-11-17. Target: watchOS 26.6.1 (23U95).
Scope: distinguish observed results from hypotheses. This document does not
describe a working SystemGroup sandbox escape, grant private entitlements, or
provide code to modify Apple's protected MobileGestalt cache.

## Known baseline

- The protected MobileGestalt cache can be read on the tested watch.
- Ordinary protected O_WRONLY/O_RDWR opens return EPERM.
- Successful Class 13 path discovery or consumption of a system-group
  sandbox extension has not granted effective write access on 23U95.
- The own App Group control is a separate permission question.
- The published bad_query and worse_query readmes list SystemGroup access
  for iOS 27, not for iOS 26. Neither publication proves a watchOS 26 write.

References:
- https://github.com/forcequitOS/bad_query
- https://github.com/forcequitOS/worse_query
- https://github.com/pookjw/HermesEnabler/issues/7
- https://github.com/pookjw/HermesEnabler/issues/90

## Research tracks to prioritize (not bypass instructions)

| Track | Question | Existing evidence | Safe next measurement | Success criterion |
| --- | --- | --- | --- | --- |
| 1. Issuer/receiver policies | Does the daemon issue a different extension class in 26 vs 27, and does the app policy accept it? | iOS policy diff suggests an issuer change; watchOS pair not yet independently diffed | Offline comparison of matching watchOS policy text and source hashes | Exact matched watchOS policy predicates, not inferred from an iOS diff |
| 2. Entitlement boundary | Is the private SystemGroup entitlement independently required for file-write-data? | Reported 23U95 profile and runtime EPERM support this | Read signed entitlements + sandbox_check + control-file results | Clear conjunction of entitlement and extension requirements, without attempting entitlement forgery |
| 3. File protection and mount | Could Data Protection, mount flags, ACL or ownership also explain failure? | Existing lstat/statfs/access evidence points chiefly to sandbox | Analyze read-only metadata and compare known own-file controls | Distinct cause is demonstrated rather than guessed |
| 4. Runtime API semantics | Which results are local fallback errors versus genuine OS errors? | bq_query_escape uses an internal -5 when no token exists | Normalize result provenance and print token present/absent separately | No false positive from path returned, -5, consume or write-open |
| 5. MobileGestaltHelper | Is there a documented, authorized setter rather than only cache rebuilding? | No supported setter established; rebuildCache can change live state | Static interface inventory only; do not invoke destructive helpers | Public or authorized API demonstrably accepting desired value |
| 6. Face display without cache mutation | Can an app show the original-looking view without granting a system face? | Experimental NanoTimeKit view work | Compare rendered app preview to actual watch face capability and persistence | Clearly labeled app-only preview, not called a system watch face |

## New app behavior on this branch

The **Run complete diagnostics** button now prepends an evidence verdict to
the full existing diagnostic report, visible in the Watch app and exported to
the iPhone via the existing WatchConnectivity pipeline. It takes the results
of the existing BQRunWriteGateDiagnostics and
BQRunPermissionDiagnostics procedures and reports:

1. Protected file read policy.
2. Protected file write policy.
3. Actual protected O_WRONLY open/close result (without a write).
4. Own App Group write policy.
5. Own App Group create/write/read-back control.
6. A deliberately conservative verdict.

No new protected write, symlink, MCM query, XPC call, cache rebuild or token
consumption was introduced by this patch. It adds interpretation, not a new
privilege. The existing diagnostics continue to write only their own app
reports and disposable own-container control file.

## Interpretation examples

- Read=ALLOW, write=DENY, write-open=DENIED: **read available / protected
  write denied**.
- Token accepted but write still denied: **not a bypass**.
- Own App Group control=PASS while protected write denied:
  **provisioning is working for the owned group**, independent of SystemGroup.
- Write-open=ALLOWED: means a descriptor opened and closed; **not evidence
  that a persisted MobileGestalt change is safe or possible**.
- Missing symbols/log fields: **inconclusive**, never interpreted as permission.

## Remaining uncertainty

The repository contains summaries of firmware research, but does not itself
contain independently extracted, matching 26/27 watchOS sandbox policies.
Do not claim to have verified a literal watchOS policy diff until both
original binaries (plus hashes) and a reproducible extraction are available.

NanoTimeKit is a separate feature-rendering direction. A view displayed
inside an app is not a system-installable Hermès face.

Related existing investigations:
- [watchOS 26/27 policy analysis](watchos26-vs-27-firmware-write-analysis.md)
- [Write access matrix](watchOS26-write-access-matrix.md)
- [Permission investigation](watchOS26-permission-investigation.md)
