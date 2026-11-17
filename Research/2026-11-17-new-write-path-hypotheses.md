# watchOS 26.6.1 — alternative write-authorization hypotheses

Updated 2026-11-17. Scope: evidence-based research, NOT a working sandbox escape.

## Physical watch baseline

- MobileGestalt read policy ALLOW; protected write policy DENY.
- Protected O_WRONLY/O_RDWR open returns EPERM, even without attempted bytes.
- Own App Group create/write/readback control PASS despite a generic
  file-write-data sandbox_check DENY on the AppGroup DIRECTORY.
- A Class 13 token being issued or consumed has not granted a protected writable
  file descriptor in existing on-device tests.

We must distinguish separately: container query success, token issuance,
token acceptance, effective sandbox permission, writable file descriptor,
actual persistent write, and system ClockFace changes.

## Independent research tracks

| Track | Key question | Test that adds evidence | Current status |
| --- | --- | --- | --- |
| P1 Parent versus child | Does the App Group DENY come from testing the directory, not the exact file? | Test policy for the parent, nonexistent exact child and created exact child; write ONLY an owned disposable file | New on-device test implemented |
| P2 Entitlement receiver gate | Does file-write-data require both system-group extension and private entitlement? | Compare signed entitlement presence and published receiving process sandbox rules; no private entitlement modification | Supported by current denial and published research; not independently proven from watchOS binaries |
| P3 Daemon issuer gate | What policy changed for SystemGroup extension issuance from OS 26 to 27? | Offline compare exact containermanagerd rules in matching Watch7,5 26 and 27 firmware, with hashes | iOS diff exists, not yet matching watchOS diff |
| P4 Independent file restriction | Do POSIX modes, file flags, mount type or protection explain EPERM independently? | Existing lstat/statfs/access and sandbox checks, no protected mutation | APFS mount is writable; sandbox is immediate observed denial |
| P5 Authorized helper setter | Does a supported system interface set the intended MobileGestalt property? | Static read-only protocol audit; exclude rebuildCache because it can change cache state | No setter established, previous helper calls returned error |
| P6 Native viewer | Can the user-visible Hermès face goal be achieved inside an app? | Compare FaceBundle load and class-gate results for six native faces | Three work, three need separate model gate tests |
| P7 OS support | Would a newer officially supported watchOS change the model? | Verify Apple support and compare matching OS policy builds | watchOS 27 unsupported on first-generation Ultra |

## New executable experiment

Source: HermesEnabler2/BQPathAuthorizationDifferential.m

- Protected MobileGestalt path and parent: ONLY sandbox_check policy observations.
  No protected O_WRONLY attempts, tokens, symlinks or modifications.
- Own Documents, own AppGroup root, own AppGroup Library: parent policy,
  future child policy, actual creation/write/readback of a unique child,
  created child policy, cleanup.
- Watch UI button: Test path permissions (own files only).
- Output on iPhone Watch Logs: path-authorization-differential.txt.

Interpretation:
- Directory DENY and owned child write PASS can reflect operation/path
  semantics; it does NOT show a bypass into SystemGroup.
- Unknown sandbox_check availability is UNKNOWN, not an ALLOW.
- Protected file DENY combined with O_WRONLY EPERM from the previous report
  continues to mean no effective protected write access.

## Routes with negative evidence — do not blindly repeat

Class 7 symlinks and multiple flags; Class 13 direct/file-scoped tokens;
Class 12 geod; Class 2 swap; NSFileCoordinator; direct protected write opens;
the unsafe assumption that rebuilding the cache sets a requested property.
To justify repeating any, identify a changed independent precondition first.

## References

- https://github.com/forcequitOS/bad_query
- https://github.com/forcequitOS/worse_query
- https://github.com/pookjw/HermesEnabler/issues/7
- https://github.com/pookjw/HermesEnabler/issues/90
- Existing internal comparison: Research/watchos26-vs-27-firmware-write-analysis.md

This test improves evidence quality. It does not obtain new privileges.
