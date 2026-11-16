# watchOS 26.6.1 (23U95) — MobileGestalt server-side authorization

**Research scope:** static analysis of published build-matched firmware reports, combined with actual on-Watch diagnostic reports from this TESTAPP project. No protected cache mutation, no system-service write request. Date: 2026-11-16.

## Executive result

The closest confirmed Apple system process is **`/usr/libexec/MobileGestaltHelper`**, registered under the Mach service **`com.apple.mobilegestalt.xpc`**. It is different from our development-signed Watch app in two ways:

- The Helper's Apple code signature contains `com.apple.private.security.storage.MobileGestaltCache = true` plus a private `com.apple.security.system-groups` array including `systemgroup.com.apple.mobilegestaltcache`. The researcher reported 16 total entitlement keys.
- The Helper executes its own server-mode MobileGestalt code and applies question-specific authorization. An XPC connection is **not** an invitation to execute arbitrary methods or change cache entries.

This is supported by published analysis of an extracted Watch6,18 / n199ap / 23U95 `MobileGestaltHelper` and `libMobileGestalt.dylib`. The exact model of the current TESTAPP owner has **not** been established here. Matching the OS build is useful, but these third-party static findings have not been reproduced independently from the owner's specific Watch model.

Sources:
- [RO23 V8: exact helper binary analysis](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V08-Firmware-Analysis.md)
- [RO23 V9: exact libMobileGestalt analysis](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V09-MobileGestalt-Analysis.md)
- [Original real-watch investigation](https://github.com/pookjw/HermesEnabler/issues/17)
- [Independent Series 8 research](https://github.com/pookjw/HermesEnabler/issues/7)

## A. Direct file access: this Watch's measured evidence

| Gate | Result | Meaning |
|---|---|---|
| App process real/effective UID/GID | 501/501 | Both identities belong to the mobile app account |
| Protected MG file owner / mode | 501:501 / 0644 | Simple Unix DAC estimate permits owner write |
| APFS volume | writable | Not a read-only mount |
| Immutable flags | none recognized | No immutable bit observed |
| Protected cache file read | allowed | Read path works |
| Protected cache O_WRONLY | EPERM | Actual protected write-open is denied |
| sandbox_check(file-write-data) | DENY (1) | Policy preflight explicitly denies the operation |
| own App Group file create/write/read/cleanup | PASS | App signing/ordinary group storage works |
| Class 13 extension token | obtained and consumed | No change to protected write authorization |
| private system-groups entitlements (SecTask) | ABSENT | Ordinary signing did not grant Apple's system rights |

`sandbox_check` is only a preflight: the Watch's own App Group previously reported a policy denial at its root, but an actual create/write/read/cleanup in that group succeeded. For protected MG, however, both the preflight and the actual open agree on denial. Consequently, one cannot assert which exact sandbox/MAC subrule produces the EPERM solely from these outputs.

## B. How MobileGestaltHelper handles a request

```text
Watch application (client)
   |
   | -- bootstrap/Mach lookup of com.apple.mobilegestalt.xpc -->
   v
MobileGestaltHelper (Apple-signed privileged daemon)
   |
   | -- getServerAnswerForQuestion:reply: --> libMobileGestalt
   |                                    _MGServerCopyAnswerWithError
   |                                         |
   |                                         +-- validate server context
   |                                         +-- locate descriptor for question
   |                                         +-- apply question-specific server gate
   |                                         +-- return answer or numerical error
   v
XPC reply: answer? error? logString?
```

The matching-firmware report establishes that `getServerAnswerForQuestion:reply:` calls `_MGServerCopyAnswerWithError` and forwards its error/result to the XPC reply. In previous live Ultra 1 experiments, bootstrap lookup and XPC replies succeeded, yet four tested ordinary questions returned `error=9`.

That number is **not** the same failure as file-open `EPERM`.

## C. Exact server-side error 9: what the disassembly supports

In the V9 build-matched library analysis, the Helper sets server mode with `_MGSetServer`, and the server-answer function checks descriptor eligibility. The tested descriptors include:

| Question | Observed descriptor flags | Server-eligible according to analyzed branch? |
|---|---|---|
| DeviceBrand | 0x0C | No; relevant server bit unset, access callback null |
| BuildVersion | 0x0C | No; same pattern |
| ProductType | 0x0C | No; same pattern |

The V9 study identifies an explicit `error=9` assignment for failed server-answer handling, and matching descriptor flags explain the prior live results. It did **not** trace the specific instruction branch for every XPC request. This is a strong static explanation, not a dynamic trace and not proof that *all* error-9 cases have the same cause.

**Inference:** attempting the same non-server questions with alternate string spellings or additional `NSXPCConnection` retries is not a new method. A missing client entitlement is **not** the demonstrated reason for these particular questions' `error=9`.

## D. Can the privileged Helper change DeviceBrand on our behalf?

| Published Helper operation | Actual behavior supported by the firmware report | Authorized arbitrary setter? |
|---|---|---|
| `getServerAnswerForQuestion:reply:` | Read/answer with descriptor-specific routing | No |
| `rebuildCache:` | Calls `_MGRebuildCache()`; accepts no replacement DeviceBrand value | No |
| `setCacheSentinel:` | Sets a fixed cache-rebuild marker based on boot state | No |
| internal `_MGWriteCache` import | Library dependency inside privileged executable | Import alone does not expose a client API |

**Do not send rebuild/sentinel requests as connectivity tests.** Analysis in HermesEnabler Issue #7 says rebuild can unlink the live MG cache before rebuilding it; this is not a safe no-op and does not provide a user-supplied cache value.

No public evidence in this analysis demonstrates a supported remote operation that replaces an arbitrary plist entry.

## E. The actual DeviceBrand source matters for persistence

The build-matched V9 library identifies a DeviceBrand provider reading the device-tree property `marketing-software-behavior` under `IODeviceTree:/chosen`. A value of zero is the observed normal result for the non-Hermès test device.

This matters because a cache rebuild is not equivalent to a persistent DeviceBrand override: cache regeneration may derive the value from the underlying provider rather than retain an unsupported cache edit. No client-writable override layer is established by the inspected provider. The exact 23U95 cache layout is build-specific; do not reuse old offsets on a different build.

## F. Other system services and face eligibility

MobileGestaltHelper is not the same as NanoTimeKit/ClockKit, which enforce additional native face-bundle eligibility. Public static analysis of the same firmware reports independent device category/collection restrictions. Therefore a hypothetical cache edit alone would not prove native Hermès face installation or persistence.

No other named privileged process in the reviewed evidence offers a confirmed authorized arbitrary MobileGestalt cache setter. A generic system XPC client library being exported is **not** proof that such a service is discoverable or will perform the operation.

## G. New on-Watch diagnostic added to this project

**Watch UI:** `MG Diagnostics → Inspect MG service authorization (new)`  
**Transferred report:** `mg-service-auth.txt`

The new test gathers only:

1. `sandbox_check` of **`mach-lookup`** for `com.apple.mobilegestalt.xpc` using the global-name filter.
2. A bootstrap **service-name lookup**; it does not send a message, invoke a service selector or modify a system file.
3. `SecTask` checks on our own live process for `com.apple.private.security.storage.MobileGestaltCache`, `com.apple.security.system-groups`, `com.apple.security.system-group-containers` and the ordinary App Group.

The entitlement audit itself now also includes the MobileGestaltCache key.

### How to interpret this new report

| Observation | What is established | What is NOT established |
|---|---|---|
| mach-lookup DENY | sandbox preflight suggests restricted name access | actual service RPC result |
| mach-lookup ALLOW | policy preflight permits the lookup | authorization to invoke any private method |
| bootstrap_look_up SUCCESS | launchd returns a service send right | method authorization or protected write permission |
| Cache-storage entitlement ABSENT | this signing path lacks that specific private claim | that the single missing claim is the *only* barrier |
| Native Helper has cache-storage entitlement | Apple deliberately signs its daemon with additional privilege | that a normal Xcode developer identity can acquire it |
| XPC error 9 for ordinary questions (previous research) | server query is rejected, plausibly by descriptor eligibility | direct file write behavior or generic XPC denial |

## G2. New measured runtime evidence from TESTAPP (2026-11-16)

The owner ran **Inspect MG service authorization (new)** on watchOS **26.6.1 / 23U95** and supplied:

| On-device measurement | Value |
|---|---|
| `sandbox_check mach-lookup com.apple.mobilegestalt.xpc` | `ALLOW` |
| `bootstrap_port` symbol / port | `AVAILABLE` / `AVAILABLE` |
| `bootstrap_look_up` | `kr=0` |
| Service send right | `YES` |
| `com.apple.private.security.storage.MobileGestaltCache` (SecTask) | `ABSENT` |
| `com.apple.security.system-groups` | `ABSENT` |
| `com.apple.security.system-group-containers` | `ABSENT` |
| `com.apple.security.application-groups` | `PRESENT` |

**New conclusion:** This particular app **can look up the legitimate MobileGestaltHelper Mach service**, despite missing the Helper's restricted cache entitlements. Name resolution / a send right is **not** an authorization decision for individual XPC methods. The earlier V5–V7 returned `error=9` for ordinary questions and the matching V9 descriptor analysis explain a *separate* server-side question eligibility barrier; do not label `error=9` as a denied bootstrap lookup.

**Research pivot:** Stop probing service-name reachability. Offline analysis should next differentiate:
- Listener connection acceptance (`listener:shouldAcceptNewConnection:`) from method-specific access checks. The published helper method address alone is **not** a decoded connection authorization proof.
- Question-specific `_MGServerCopyAnswerWithError` descriptor flags from a method that actually mutates arbitrary values, which is **not present in the published interface**.
- Private daemon cache-storage entitlement from an app's ordinary developer signature (absent here).
- A cache maintenance method (`rebuildCache:`, `setCacheSentinel:`) from a value-specific setter; do **not** invoke either on live production Watch.

No new on-device authorization route or protected write is demonstrated by this new log.

## H. Actual next research priorities, not repeated flag combinations

**High priority:** Corroborate the exact MobileGestaltHelper code-signature claims and the server-answer decision path against the **owner's own hardware-specific 23U95 image** if that binary becomes available. Preserve hashes and avoid treating iOS 26 implementation as an exact watchOS replacement.

**High priority:** Check any proposed *documented* interface for authorized, value-specific MobileGestalt changes. The methods published so far are getters or cache-maintenance routines, not arbitrary setters.

**Medium priority:** Compare publicly available watchOS 26 and watchOS 27 service-interface declarations and entitlement requirements offline. Changed names/ABI do not imply a bypass; look for an explicitly supported operation, not an incidental imported symbol.

**Low value:** Repeating Class 13 token consumption, changing the string representation of the same protected path, adding private plist keys to a normal signing profile, invoking destructive cache rebuilds or treating XPC connection establishment as write permission.

### Stop criteria

A route is **not working** unless the exact Watch build and signing context show:
- an authorized operation with a defined expected effect,
- confirmed safe readback/persistence without corrupting the system cache,
- and (for face goals) separate normal face eligibility.

No such write route has been established as of this report.

## External references

- [MobileGestaltHelper native methods and entitlements (RO23 V8)](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V08-Firmware-Analysis.md)
- [watchOS 23U95 question routing and error 9 (RO23 V9)](https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X/blob/main/research/RO23-V09-MobileGestalt-Analysis.md)
- [Series 8 static cache rebuild analysis](https://github.com/pookjw/HermesEnabler/issues/7)
- [Original watchOS 26 on-device research](https://github.com/pookjw/HermesEnabler/issues/17)
- [WebKit's platform sandbox profiles (read-only MobileGestalt)](https://chromium.googlesource.com/external/github.com/WebKit/webkit/+/56b42fa590de990d047149a2df9b3770420f28ad/Source/WebKit/Resources/SandboxProfiles/ios/com.apple.WebKit.Networking.sb)
