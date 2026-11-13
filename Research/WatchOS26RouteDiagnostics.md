# watchOS 26 diagnostic routes

Research fork of [pookjw/HermesEnabler](https://github.com/pookjw/HermesEnabler), with the upstream MIT/GPL/other license notices preserved as supplied. This is an **unverified research instrument**, not an announced watchOS 26 bypass.

## What is actually different

The existing HermesEnabler \`BQCore.m\` already contains a Class 12 Geod fallback and Class 13 traversal. Those routes are part of a combined escape sequence; therefore a failed save attempt does **not** isolate a single route. This fork adds independent access checks in \`BQRouteProbe.m\`:

1. **WorstGestalt Class 13 per-file**, using \`part=3\`, \`partDomain=dots(8)+file\`, \`flags=0x8000000000\` and the \`/var/\` path alias.
2. **WorstGestalt Class 13 per-file**, using the full \`/private/var/\` path.
3. **HermesEnabler Class 13 direct**, for comparison, \`flags=0x8100000000\`.
4. **Geod Class 12**, using the six-segment traversal reported in \`0xjohnnydev/Geod-MCM-PoC\`.

The probe prints: query result, returned path, sandbox token availability, token consumption result, \`O_RDONLY\`, \`O_RDWR\`, and errno. \`O_RDWR\` only opens the file; the code performs no write, truncate, rename, chmod, or cache modification. Handles are released. The original editor is not changed.

## Run the test

- Build and install the Watch app using Xcode and your own provisioning profile.
- Open **HermesEnabler → Route Tests**, or access the same view from **MG Backups** on a fresh install.
- Tap **Run All Routes**.
- Capture the full output including watchOS build and all eleven route results. Do not share the contents of the actual MobileGestalt cache.

**Interpretation:** \`token=YES\` is not success, \`consume>=0\` is not success, and \`O_RDONLY OPEN OK\` is not success. Only \`O_RDWR OPEN OK\` demonstrates writable-open permission; **no test writes anything**.

## Known limitations

- The tested source implementations were written primarily for iOS; this is only an API-level comparison on watchOS, not an exploit confirmation.
- Class 12 Geod previously returned no useful container in a Watch6,18 / 23U95 experiment. The separated probe is useful for reproducibility, not an expectation of success.
- The app's original first-run backup is a separate workflow. Diagnostics do not require generating or modifying a backup.
- Creating a token and checking file-open permission is distinct from bypassing NanoTimeKit eligibility for Hermès faces.
- A full watchOS SDK is necessary to compile. GitHub upload does not constitute a successful on-device test.

References:
- https://github.com/GoldenNugget-Team/worstgestalt/blob/main/Sources/WorseGestalt/BQCore.swift
- https://github.com/0xjohnnydev/Geod-MCM-PoC
- https://github.com/pookjw/HermesEnabler

2026-11-13 follow-up: A Series 8 researcher reported that `0x0800000000` returns a consumable `com.apple.sandbox.system-group` token but still denies `O_RDWR` due to system-group entitlement rules. Source: https://github.com/pookjw/HermesEnabler/issues/7#issuecomment-6761033695 .
