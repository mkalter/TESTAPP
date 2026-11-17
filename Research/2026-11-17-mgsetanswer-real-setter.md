# watchOS 26.6.1: real MobileGestalt setter experiment (new execution path)

This experiment does **not** repeat MCM Class 13, Class 7, NSFileCoordinator
or sandbox_check. It calls a different interface, the private MobileGestalt
setter `MGSetAnswer(CFStringRef question, CFTypeRef value)`.

Source: `HermesEnabler2/BQMobileGestaltSetterProbe.m`.

## Distinct mechanism

The existing tests all attempted to acquire or infer direct
filesystem write authorization for:
`SystemGroup/.../com.apple.MobileGestalt.plist`

Here we call a private API belonging to MobileGestalt itself. The API might:
- reject unauthorised keys,
- update only process state,
- delegate to MobileGestaltHelper,
- or persist an allowed key.

None is assumed without a real Watch test.

References:
- https://github.com/theos/headers/blob/master/MobileGestalt/MobileGestalt.h
- https://github.com/p-x9/swift-mobile-gestalt
- https://newosxbook.com/articles/guesstalt.html

Historical headers say **not all keys can be assigned** and
`UserAssignedDeviceName` is assignable while `ProductType` is not.
That still does not establish watchOS 26 support or DeviceBrand write access.

## Actual experiment (explicit, opt-in)

On the Watch, open **MG Diagnostics → TEST: MGSetAnswer schrijftest**.
The app:
1. Resolves MGSetAnswer and MGCopyAnswer symbols dynamically.
2. Creates a verified MobileGestalt backup in the app's own container.
   If backup fails, NO setter is invoked.
3. Reads and validates the original protected cache.
4. If present and string-typed, calls MGSetAnswer for
   `UserAssignedDeviceName` using its **unchanged existing value**.
5. Calls MGSetAnswer for a new app-specific canary
   `HermesEnablerMGSetAnswerWriteProof`, value
   `20261117-watchOS26-canary`, without altering DeviceBrand or any watch
   feature key.
6. Performs same-process MGCopyAnswer readback and a second read of the
   protected on-disk cache. Reports byte-for-byte equality or change and
   validity of the result.
7. Sends `mgsetanswer-experiment.txt` to iPhone Watch Logs.

To test persistence, **fully close/relaunch** the Watch app and press
**CHECK: MGSetAnswer na herstart**. This makes no writes and reports the
canary's current-process answer and whether it appears in the on-disk
CacheExtra dictionary (`mgsetanswer-persistence.txt`).

**Success hierarchy:**
- exported symbol: a method exists, nothing more;
- return code from setter: a function responded, nothing more;
- same-process readback: in-memory availability, not persistent write;
- on-disk cache diff plus valid structure: evidence of changed cache bytes;
- new-process canary and on-disk matching data: stronger persistence evidence;
- DeviceBrand set/unlocked system watch face: NOT tested or claimed.

## Risk

This invokes a private setter, which can be unsupported or side-effectful.
Unlike prior read-only diagnostic bundles, this experiment can actually
request a write. It does NOT call `_MGWriteCache` (unverified ABI and risks
forced cache regeneration), does not truncate or replace the protected file,
and does not attempt to modify DeviceBrand. A backup is required, but a
backup alone does not guarantee an unbootable device can be recovered.

The test must be manually started. It is NOT part of Run complete diagnostics.

## Remaining routes and ranking

- Privileged MCM SystemGroup extension: already directly tested, write denied.
- File coordination and InstallCoordination: previous negative tests, not new.
- MobileGestaltHelper XPC: reachable for read paths, existing attempts
  produced error 9; no publicly verified setter protocol on 23U95.
- Private direct flush API `_MGWriteCache`: symbol names alone do not prove
  a safe callable signature; not invoked.
- A patched system OS or debug entitlement: not available from a normally
  development-signed Watch app; a bypass claim requires a verifiable system
  vulnerability or already trusted system component.
- Apple's installed native NanoTimeKit FaceViews: demonstrably accessible
  in app for three styles; separate from protected persistent system faces.

This is a **genuinely different API mechanism** under test, but not a claim
that MobileGestalt system-cache writes will be granted.
