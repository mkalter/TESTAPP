# watchOS 26 entitlement experiment (read-only)

This repository has TWO entitlement request plists:

- `HermesEnabler2/HermesEnabler2.entitlements`: baseline, currently selected by the Watch target.
- `HermesEnabler2/EntitlementProbe.private.entitlements`: **experimental, opt-in only**. The `system-groups` and `system-group-containers` key/value formats here are hypotheses, not verified Apple-authorized values. This file is NOT selected automatically.

## Test A: source request comparison (Windows, macOS, Linux, or GitHub Actions)

```bash
python3 scripts/inspect_entitlements.py --source HermesEnabler2/HermesEnabler2.entitlements
python3 scripts/inspect_entitlements.py --source HermesEnabler2/EntitlementProbe.private.entitlements
```

Or go to **Actions → Entitlements audit → Run workflow** and choose baseline or private-probe. This checks plist *requests only*, not granted permissions.

## Test B: inspect a signed IPA (macOS required)

```bash
python3 scripts/inspect_entitlements.py --ipa /path/to/HermesEnabler.ipa
```

The tool reports entitlements in the code signature and in the embedded provisioning profile for **each** iPhone and Watch app. A profile mismatch means an entitlement cannot be considered authorized. A matching value does NOT establish that sandbox rules permit protected file writes.

## Test C: optional signing experiment (Xcode)

A preconfigured experiment branch is available: [experiment/private-entitlements-watch](https://github.com/mkalter/TESTAPP/tree/experiment/private-entitlements-watch). It switches the **Watch** target's Debug and Release `CODE_SIGN_ENTITLEMENTS` setting to the experimental plist; the iPhone companion target is unchanged. **main** retains the original signing settings.

1. Make a separate copy/branch of the project. Keep the baseline entitlement plist and the original Watch target setting unchanged.
2. For the **HermesEnabler2 Watch target only**, temporarily change **Build Settings → Code Signing Entitlements** from `HermesEnabler2/HermesEnabler2.entitlements` to `HermesEnabler2/EntitlementProbe.private.entitlements`.
3. Request a **development build signed by your own Apple Developer team**. Record the exact Xcode provisioning/signing error if it fails. Revert the setting afterward.
4. If you successfully produce a signed IPA, inspect it using Test B. Separate the iPhone and Watch results.

This is a test of entitlement *authorization*, not a method to grant private rights. Private Apple entitlements generally cannot be obtained with a Personal Team or an ordinary provisioning profile. A profile error is an expected, informative result. Do not infer sandbox write access from an entitlements plist, a signed build, or a consumed extension token.

No test here writes to MobileGestalt, alters caches, installs exploits, or bypasses signing.
