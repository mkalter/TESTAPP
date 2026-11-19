# Technical reassessment — native Hermès on Ultra 1 / watchOS 26.6.1 (23U95)
Date: 2026-11-17. Target Watch6,18. Purpose: stop repeating already-disproven experiments and make a reliable decision about what, if anything, needs device testing. **No working native unlock is claimed.**

## Explicit correction of prior assistant work

On 2026-11-17, `HermesCompanion/ContentView.swift` was given a basic `CLKWatchFaceLibrary.addWatchFace(at:)` import on the **native-face-boundary-lab** branch (commit `27c9251f`). That was described as new functional progress. This was a research mistake:
- An earlier branch, `fix/native-hermes-23u95-cache-layout-20261117`, **already implemented standard ClockKit .watchface import**.
- `experiment/native-hermes-system-import-bypass-gates-20261117` had already implemented a distinct private client-prevalidation-skip route and archive `forMigration` experiment.
- `experiment/self-contained-poodle-system-face-import-20261117` had already added a generated test candidate. Its ZIP verifies archive construction, **not compatibility or system import**.
- These are separate **diverged** branches, not a single line of improvement. Comparing self-contained Poodle `3a2c9d2` to native-face lab `b12c7b6` yields 57 commits ahead and 21 behind; a newer successful build is not necessarily more feature-complete.

Do not introduce another standard import button or say a successful unsigned build establishes functionality. The current branch's standard import is **redundant with earlier work**.

## What the firmware and actual-device record prove

1. Live Watch6,18/23U95 MobileGestalt read works; write-open returns `EPERM`. Existing Class7/Class13, file coordination and MCM variations have not produced effective protected-file write access.
2. Independently decompiled 23U95 `containermanagerd` issues the SystemGroup-specific extension class for SystemGroup paths. The receiver baseline checks Apple-private system-group entitlements. The watchOS 27 issuer expansion in matching comparison firmware is **not available on this 26.6.1 device**. See `Research/2026-11-17-verified-watchos26-27-sandbox-diff.md`.
3. Original 23U95 `NTKPoodleFace` checks device capability, collection type, and internal-build/hardware-face state. The measured Ultra 1 (`deviceCategory=4`, `collectionType=9`, `NTKShowHardwareSpecificFaces=false`) yields restricted. `NTKHadesFace` independently rejects category 4. Other faces have separate predicates. Setting DeviceBrand alone is **not a demonstrated universal unlock**.
4. `NTKFaceBundleManager` enumeration and lookup independently reject restricted bundles. `_NTKCanAddWatchFace` has further availability/configuration checks. The actual `nanotimekitd` `_removeUnavailableFacesFromStore:` loop calls `_NTKFaceStyleIsAvailable` (style-level) rather than directly calling `isRestrictedForDevice:` at its inspected callsite. That is a **difference between gates**, **not evidence that a restricted face can be installed or rendered**.
5. The original daemon's `NTKDCollectionStore` has internal native add/reset methods; XPC listeners returning YES does **not** establish that a third-party app may look up the service, call those methods or persist an arbitrary face.
6. Real 23U95 `MobileGestaltHelper` has private cache authorization but no proven caller-accessible, arbitrary DeviceBrand setter. Earlier `MGSetAnswer` tests did **not** invoke a setter because the symbol was absent in that process. `IODeviceTree:/chosen` lacked the expected provider key in a previous live report, so that experiment did **not** exercise an effective kernel setter.
7. All recent GitHub Actions validations, IPA packaging and offline disassembly occur on hosted runners. None proves device-side behavior. The newest lab T1–T4 do not yet have real Watch result logs.

## The insight and limit of worse_query

Read the upstream implementation, not just its name. It uses an entitled app-owned Class7 AppGroup and a `Library/Caches` symlink during container resolution; the token is a separate step from the ultimate kernel sandbox authorization. Upstream documents SystemGroup reach **for iOS 27**, not watchOS 26. Tests must distinguish MCM result, extension class, token consume, effective policy, writable FD and persistent data. The target's independent issuer/receiver constraints are not addressed by simply changing MCM flags or choosing a different path. Do **not** copy GPL code into MIT code without license review; the PoC itself mutates the owned App Group Caches directory.

## What the advanced existing experiment does — and what it does not

`experiment/self-contained-poodle-system-face-import-20261117` (build successful: run `44107600991`) already contains:
- Public ClockKit system import as a positive-control candidate.
- Private `_addWatchFaceAtURL:shouldValidate:completionHandler:`, with `shouldValidate=NO` if it exists and the limited Objective-C ABI check passes.
- A generated `com.apple.NTKPoodleFaceBundle` test archive with `forMigration=true` and neutral placeholder image.
- Notes for testing an authentic exported Hermès watchface against ordinary import and client prevalidation skip.

**Weaknesses requiring correction before drawing a negative conclusion:**
- The generated archive's `face.json`, `metadata.json` and dummy snapshot were never demonstrated to be a valid native face configuration on target hardware. An import rejection may be caused by a malformed candidate, not Hermès eligibility.
- The private method was traced in **iOS 26.1**, not verified for the user's actual iPhone OS. It checks basic method arity/return/BOOL encoding, **not the entire signature or downstream behavior**.
- Result output is mostly a volatile SwiftUI `@State` string; reliable run-to-run evidence needs persisted attempt records with distinct identifiers, exact error domain/code, input SHA, test mode and paired device context.
- A no-error completion confirms at most that an import stage accepted a request; it does not prove native Watch Carousel installation or persistence.
- The latest lab branch contains only the **simpler** public import; do not use its commit time as a ranking of experiment quality.

## Ranked next actions, based on information gain (not more UI buttons)

**A — Baseline validity, high confidence / low risk.** Run an actual original, known-good non-Hermès exported `.watchface` through standard ClockKit, and a genuine exported Hermès `.watchface` through the **same path**. Record raw errors and inspect Apple's actual face gallery after app exit. Without the positive control, a negative generated ZIP test means little.

**B — Prevalidation versus Watch-side gate, bounded.** On the advanced branch use exactly the same *authentic* Hermès input for public import and the already coded client-prevalidation-skip, keeping an immutable copy and separate report per attempt. A difference distinguishes an early iPhone rejection, but either path can still be rejected on the Watch by separate eligibility. No additional random 'shouldValidate' flags are justified.

**C — Finish static provenance, medium confidence.** Map the exact caller/context of the tested NanoTimeKit restricted-FaceBundle exception (external analysis suggests `_CLKIsFaceSnapshotService`, i.e. snapshot-only); determine whether any system import path enters the exception under ordinary app authorization. Similarly distinguish `NTKDCollectionStore` record insertion from live face render eligibility. No privileged store reset or injection on the live Watch based solely on a selector name.

**D — Authorization research only with new premises.** Further watchOS 26 sandbox-escape work is justified only by a demonstrably different issuer/receiver authorization primitive or independent vulnerability evidence for 23U95. Class7/13 flag permutations, symlink aliases and token consumption have already yielded negative effective write tests and should not be recycled.

## Explicit stop conditions

- Do not state that Hermès is unlocked without original Apple face visible in **system** Carousel with test app closed and still present after reboot.
- Do not claim an on-device result from CI builds, decompiled paths or accepted XPC listeners.
- Do not modify protected cache/store or run library reset methods without a tested recovery procedure. A backed-up plist is not a Watch recovery mechanism.
- Do not sacrifice app groups used for other app data merely to reproduce an existing iOS PoC.
- Keep original artefacts and negative result logs. Distinguish 'not tested' from 'tested and denied'.

## Source / provenance

- Runs: [lab IPA 44144953313](https://github.com/mkalter/TESTAPP/actions/runs/44144953313), [advanced import build 44107600991](https://github.com/mkalter/TESTAPP/actions/runs/44107600991), [exact daemon analysis 44135356997](https://github.com/mkalter/TESTAPP/actions/runs/44135356997).
- Docs: `Research/2026-11-17-verified-watchos26-27-sandbox-diff.md`, `Research/2026-11-17-23U95-native-face-XPC-sandbox.md`, `Research/2026-11-17-23U95-native-hermes-sandbox-alt-stores.md`.
- Advanced branches: `experiment/native-hermes-system-import-bypass-gates-20261117`, `experiment/self-contained-poodle-system-face-import-20261117`.
- Upstream: https://github.com/forcequitOS/worse_query , https://github.com/ZhuoXuan-MY/HermesEnabler--WatchOS26.X , https://github.com/pookjw/HermesEnabler .

**Result at review time:** deeper diagnosis of independent gates and an identified research-branch/process error; no new working watchOS sandbox escape, privileged write, or native Hermès system unlock was demonstrated.
