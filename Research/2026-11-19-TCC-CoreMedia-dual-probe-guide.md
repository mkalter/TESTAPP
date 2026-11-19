# Two independent Watch6,18/23U95 CVE entry-surface checks (T11/T12)

**Scope:** developer-signed combined HermesCompanion + HermesEnabler2 watch app, real Ultra1 S8 `Watch6,18` with watchOS `26.6.1` (`23U95`). Tested firmware code entry is **not** inferred from CVE labels.

## T11 — TCC / CVE-2026-86886

Watch UI: `Native Face Lab → T11 · TCC CVE-2026-86886`.

Watch → iPhone file: `cve-2026-86886-tcc-reachability.txt`.

It performs:
- Own-process `sandbox_check` Mach lookup preflight on the original `com.apple.tccd` name.
- A true `bootstrap_look_up` of that name (only a port, immediately released). Log is an **actual** Mach status, including `1100` vs `0`.
- A `file-write-data` sandbox preflight for the protected original MG cache.
- **NO** `NSXPCConnection`, no XPC request, no TCC DB schema manipulation, path-traversal strings, private entitlement forgery, or protected file write.

Interpretation:
- `kr=0` proves only service name lookup, not exploitability of TCC CVE-2026-86886.
- `file-write-data DENY` is expected and not a test failure.
- A real arbitrary protected-file write method requires an independently validated service protocol and target-specific proof; neither is supplied by the Apple CVE summary.

## T12 — CoreMedia / CVE-2026-86876

Watch UI: `Native Face Lab → T12 · CoreMedia CVE-2026-86876`.

Watch → iPhone file: `cve-2026-86876-coremedia-reachability.txt`.

It performs:
- Original on-device `CoreMedia.framework/CoreMedia` `dlopen`, with an explicit error if unavailable.
- Checks `CMBlockBufferCreateEmpty`, `CMBlockBufferCreateWithMemoryBlock` and `CMSampleBufferCreate` **symbol presence**.
- Calls **only** `CMBlockBufferCreateEmpty(kCFAllocatorDefault,0,0,&block)` as a harmless local API smoke test, and `CFRelease` if the allocation succeeded. Logs actual OSStatus. No malformed buffer or allocator payload, concurrent codec parser, or other bug trigger.
- Repeats the caller's own MG write-policy preflight, without a writable open.

Interpretation:
- Symbol/empty-buffer success proves accessible harmless API support, NOT the CoreMedia out-of-bounds write or a sandbox escape.
- `dlopen` failure means only the named framework could not be loaded in that process; it cannot prove absence of the vulnerability from other frameworks/processes.
- On-device hardware ABI and actual vulnerable method/dataflow need independent verified `23U95` static mapping before any further safety assessment.

## Explicit no-unlock claim

These are **two executable separate real-device probes**, not two CVE exploits. Neither grants system-group entitlements, changes the original MobileGestalt plist, disables a sandbox, installs a native Hermès FaceBundle, or writes to Apple's FaceStore. This distinction is intentional: for neither CVE is a working, publicly verified original Watch6,18/23U95 exploit entrypoint known.

Files:
- `HermesEnabler2/BQNativeFaceBoundaryLab.m`: `BQRunTCC86886Reachability`, `BQRunCoreMedia86876Reachability`.
- `HermesEnabler2/NativeFaceBoundaryLabView.swift`: isolated buttons T11/T12, neither in T1–T6 batch.
- `HermesEnabler2/WatchConnectivity/WatchConnectivityManager.swift`: file allowlist and saved-report retransmission.
- `Research/test_native_face_lab_contract.py`: verifies wiring and nonmutating scope.

The same file has [CVE priority research](2026-11-19-priority-watchos26-6-1-cves-for-mobilegestalt.md).
