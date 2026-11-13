# Alternate writer investigation — 2026-11-13

## Executable test v2 (direct-create, 2026-11-13)
Watch UI: **Test Daemon Staging Writes**. The existing bulk scan stays read-only with respect to protected system data.
The new action tests InstallCoordination's PromiseStaging, DataPromises and Coordinators, using the published request and a type-1 comparison.

It first tests directory-based and direct-create canaries in the app's own Documents. For the fixed staging directories it records separate directory-read and direct-write results, before and after each MCM token. Direct-create uses a UUID path with O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW and does NOT call O_RDONLY | O_DIRECTORY first. It checks the byte count and file size from the written FD, attempts independent O_RDONLY readback (which is allowed to fail for a write-only token), then unlinks only its newly created name and checks absence. If cleanup cannot be verified, subsequent staging tests are stopped. No existing file is replaced. No install graph is created.

**STAGING DIRECT WRITES 3/3** means only direct canary creation/write/removal passed in separate leases. It does not prove that a persisted graph will deserialize, materialize, or write MobileGestalt. Readback failures are reported separately and do not invalidate write-only evidence. A negative result does not prove that every writer is impossible.
Report: Documents/watchos26-installcoord-entry.txt.
WatchConnectivity command: daemonStagingWriteTest. Both the Watch UI and iPhone remote controls have a Test Daemon Staging Writes button. The iPhone displays the returned report and supports copying it.

## Mechanisms examined
- InstallCoordination: daemon-side plist materialization is distinct from directly opening MobileGestalt. Published staging entry is still MCM-dependent. Tested on another Watch/23U95 and blocked; not assumed identical to this Watch/23U67.
- MobileHouseArrest: CodeDirectory identity confusion reaches app/app-group containers. The MG class-13 route is a separate primitive and upstream explicitly reports no working iOS 26 MG access. Merely changing this app's bundle ID is not a demonstrated solution.
- cfprefsd: published primitive creates an empty missing file; cannot replace the existing cache or choose its contents. No useful complete DeviceBrand chain was identified.
- MobileGestaltHelper: reported exact-watch disassembly shows rebuildCache takes a reply callback, not a custom plist. It removes/rebuilds the live cache. Calling it is not a setter or a harmless probe.
- Paired iPhone: transferring a file to the Watch app is not a privileged restore. No demonstrated restore API accepting caller-controlled MobileGestalt data was identified.

## Evidence
- https://github.com/0xjohnnydev/InstallCoordination-PoC/blob/main/poc.m
- https://github.com/0xjohnnydev/InstallCoordination-PoC/blob/main/promise_graph.m
- https://github.com/0xjohnnydev/MobileHouseArrest-PoC
- https://jftechllc.com/blog/ios27-red-wedding.html
- https://github.com/pookjw/HermesEnabler/issues/7#issuecomment-6761033695

No new vulnerability or successful watchOS 26.6 bypass is claimed. Build validation and physical-device results are separate.
