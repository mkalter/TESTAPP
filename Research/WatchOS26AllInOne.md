# HermesEnabler watchOS 26 – all-in-one research build

This branch extends the original HermesEnabler with a single Watch + iPhone companion test interface. It is experimental, unsigned, and has not demonstrated writable MobileGestalt access on watchOS 26.6/26.6.1.

## Direct unsigned IPA

Download: https://github.com/mkalter/TESTAPP/releases/download/watchos26-all-in-one-test-20261113/HermesEnabler-watchOS26-route-tests.ipa

Sign the iPhone host and embedded Watch app with your own provisioning credentials before installation. Developer Mode must be enabled. An App Group entitlement may require a paid developer account.

## Single Run All Routes operation

The Watch executes eleven original route variants, sixteen MCM container/flag controls, three alternative entry-container probes, and an independent sandbox audit. Main routes:

1. WorstGestalt file Class 13 via /var alias, flags 0x8000000000.
2. WorstGestalt file Class 13 via /private/var, flags 0x8000000000.
3. HermesEnabler direct Class 13, flags 0x8100000000.
4. Direct system-group Class 13, LOWER flags 0x0800000000.
5. Per-file Class 13, LOWER flags 0x0800000000.
6. Geod Class 12 published six-level traversal.
7. HermesEnabler legacy Class 13 twelve-level traversal.
8. Class 7 App Group Caches symlink.
9. Class 2 staged symlink.
10. Class 2 subpath symlink.
11. Geod Class 12 legacy twelve-level traversal.

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

## Flag differential - 13 November 2026

The Watch6,18 / watchOS 26.6 log demonstrated that flags 0x8000000000 and 0x8100000000 return NO TOKEN or no Geod container, and the protected plist permits O_RDONLY but denies O_RDWR (EPERM). A separately published Series 8 watchOS 26.6.1 test obtained a consumable system-group token with DIFFERENT flags 0x0800000000; the sandbox still denied O_RDWR. This build now checks both lower-flag forms explicitly. The editor also tries lower-flag direct Class 13, but only accepts it when the real protected file passes an O_RDWR check. See https://github.com/pookjw/HermesEnabler/issues/7#issuecomment-6761033695 .

## v3 — Independent attack-surface diagnostics

The scan now includes:

* Sandbox permissions: passive sandbox_check comparison of read, write, create, and unlink on Watch's protected MobileGestalt cache and harmless own-app controls. These are policy hints; open(O_RDWR) is the final evidence.
* Signed entitlements: read-only SecTask inspection of the installed Watch app's application/system-group capabilities and candidate private entitlement keys. Unavailable APIs are reported explicitly.
* Vnode/permissions: stat, lstat, ownership, mode, inode, aliases, open(O_RDONLY), open(O_WRONLY), and open(O_RDWR) with O_NOFOLLOW. No bytes are written to system files.
* Daemon surface: passive mach-lookup policy checks for MobileGestalt, containermanagerd, geod, installcoordinationd and backups plus executable visibility checks. An ALLOW policy is not proof of daemon existence or exploitable XPC interface.
* New entry containers: Class 13 InstallCoordination (direct and DataPromises domain) and Class 12 eligibilityd NeverRestore requests; no promise graph, symlinks, persisted state or daemon-write operations are staged.
* iPhone iOS 27 differential: local iPhone MobileGestalt access control and controlled iPhone-to-Watch file relay using only a temporary Watch-app file, followed by protected Watch O_RDWR check.
* Evidence collection: labeled results, errors, and Copy Watch Report on iPhone.

The read-only scan is distinct from optional feature toggles, which require a backup, verified O_RDWR and post-write verification.

Watch Ultra 1 is not listed for watchOS 27, so upgrading the Watch to exploit watchOS 27 behavior is not a realistic solution for this hardware.

References:
* https://github.com/0xjohnnydev/InstallCoordination-PoC
* https://github.com/0xjohnnydev/MobileHouseArrest-PoC
* https://developer.apple.com/documentation/watchconnectivity/wcsessiondelegate
* https://support.apple.com/guide/watch/restore-apple-watch-from-a-backup-apdaa8cc32e8/26/watchos/26
