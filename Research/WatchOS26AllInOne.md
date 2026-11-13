# HermesEnabler watchOS 26 – all-in-one research build

This branch extends the original HermesEnabler with a single Watch + iPhone companion test interface. It is experimental, unsigned, and has not demonstrated writable MobileGestalt access on watchOS 26.6/26.6.1.

## Direct unsigned IPA

Download: https://github.com/mkalter/TESTAPP/releases/download/watchos26-all-in-one-test-20261113/HermesEnabler-watchOS26-route-tests.ipa

Sign the iPhone host and embedded Watch app with your own provisioning credentials before installation. Developer Mode must be enabled. An App Group entitlement may require a paid developer account.

## Single Run All Routes operation

The Watch executes nine individually selected MCM query variants:

1. WorstGestalt file Class 13 via /var alias, flags 0x8000000000.
2. WorstGestalt file Class 13 via /private/var, flags 0x8000000000.
3. HermesEnabler direct Class 13, flags 0x8100000000.
4. Geod Class 12 published six-level traversal.
5. HermesEnabler legacy Class 13 twelve-level traversal.
6. Class 7 App Group Caches symlink.
7. Class 2 staged symlink.
8. Class 2 subpath symlink.
9. Geod Class 12 legacy twelve-level traversal.

The Class 2 parent-Library rename is not run automatically because it can kill or destabilize the app. Bulk testing never writes to the protected cache. Each test logs extension results and O_RDONLY / O_RDWR access without writing bytes.

## Using the Watch app

Open Route Tests, press Run All Routes, and inspect the results. Create an initial backup (on the Watch or from the iPhone companion) before enabling any feature. Toggle Hermes or Ultra Faces directly in Route Tests or open the normal feature screens. The write operation searches for a validated writable-open route and verifies the on-disk result; when no route works, it returns an error.

## Using the iPhone companion

Open Watch Tests & Feature Switches while HermesEnabler is open on the paired Watch. Tap Run All Routes on Watch, then Create / Check Watch Backup. Tap the refresh icon beside any setting to read its state from the Watch. Then its toggle becomes interactive. There are 23 on/off feature controls in the companion; writes occur on the Watch via WatchConnectivity. Restart Watch Carousel is an explicit action.

The Watch and iPhone exchange immediate messages only when WCSession.isReachable is true. This is not a remote bypass of the Watch sandbox. A successful build or returned sandbox token is not evidence of writable access.

## Validation

GitHub Actions compiles the Watch scheme and packages a full unsigned iPhone-host-plus-Watch IPA, uploading it as an artifact and publishing the direct .ipa release asset. The original upstream Xcode 27 project format is preserved; Xcode 26.6 CI temporarily downgrades it only in the runner.

Sources:
- https://github.com/GoldenNugget-Team/worstgestalt
- https://github.com/0xjohnnydev/Geod-MCM-PoC
- https://github.com/pookjw/HermesEnabler
