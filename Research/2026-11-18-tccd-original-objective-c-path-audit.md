# Original Watch6,18 / 23U95 TCC executable — actionable authorization audit

**18 November 2026.** Objective: distinguish TCC service reachability, normal
TCC database operations and hypothetical file writes to the protected existing
MobileGestalt cache without risking a user's paired Apple Watch.

## Real physical Watch results

- Developer-signed app process uid/euid/gid/egid **501**, matching MobileGestalt file `uid=501`, `gid=501`, `mode=0644`, `size=13325` (T5).
- `sandbox_check(file-write-data, com.apple.MobileGestalt.plist)=DENY(1)`. POSIX ownership alone has not conferred a direct write.
- `com.apple.tccd` and `com.apple.mobilegestalt.xpc`: both `mach-lookup=ALLOW` (T5) and `bootstrap_look_up kr=0` with Mach send right (T2). This **does not** prove acceptance of any XPC request.
- `com.apple.mobile.softwareupdated` and native NanoTimeKit broker names: `bootstrap_look_up kr=1100`, which means `BOOTSTRAP_NOT_PRIVILEGED` (not unknown service).
- No native Apple Hermès system face or persistent MG modification is demonstrated.

## Original executable actually extracted and reviewed

[GitHub Actions #44260852274](https://github.com/mkalter/TESTAPP/actions/runs/44260852274)
ran a SHA-pinned original Watch6,18 / watchOS 26.6.1 `tccd` audit:
- SHA256 `b885388cef4b25b4988b9b312d3ab6dd2b11d27b9baf0fefc3e18bb29d7dbf9d`.
- The script correctly identifies **thin ARM64_32** (not a fat binary in the extracted Ultra 1 image); `__TEXT.__objc_methlist`, `__objc_methname`, `__objc_selrefs` are present.
- It inventoried **1,490** regex-relevant original strings and method names.
- The previous class parser recovered **0 classes**, so it did not prove the caller/target of a suspicious method. This is a parser deficiency, not a conclusion about TCC.
- New independent parser `recover_arm64_32_objc_lists.py` now checks relative ObjC list entry names and bounds, and reports method **IMP locations** if validated; run [#44262179954](https://github.com/mkalter/TESTAPP/actions/runs/44262179954) was launched for this.

### Confirmed candidate families from actual original strings

| Verified strings/selectors | Meaning we may test offline | Remaining security question |
|---|---|---|
| `TCCDDatabaseRegistry`, `registerNewDBAtPath:`, `registry (abs_path ... trusted)` | Registers database locations | Which trusted client can supply the path, and is the target root canonicalized? |
| `getMigratedDBDir`, `getMigratedDBRelativeDirPath`, `-[TCCDMainDatabase migration:]` | Database migration path logic | Is any call reachable through an app-supplied operation? |
| `_sandbox_check_by_audit_token`, `_sandbox_extension_issue_file`, `_sandbox_extension_issue_generic` | Sandbox-specific authorization/delegation code exists | Which path, token class and caller entitlement are accepted? |
| `REQUEST_ACCESS_SERVICE_ENTITLEMENT`, `MANAGER_ENTITLEMENT_NAME`, `com.apple.private.tcc.allow` | Service-specific privilege checks exist | Can ordinary app invoke any relevant mutation? |
| `initWithPathToDatabase:initialSetup:migration:`, `_createDatabase:initialSetup:` | Database lifecycle helpers exist | Does any execution path permit a client-chosen *existing binary plist*? |

There are explicit denial strings such as `Requestor ... is not entitled to read database`,
`... not entitled to reset all permission`, `failed entitlement check`, and
`delegated service ... sandbox_check_by_audit_token fails`. A mach send right
must not be mistaken for an entitlement pass.

## Comparing to patched versions responsibly

The independently reviewed same-model Watch7,5 pre/post watchOS 26.6→27.0
strings indicate new `TCCDDirectoryManager`,
`validateExistingDatabaseAtPath:`,
`checkLegacyDatabaseRegisteredAtPath:`, and
container/sandbox-token imports. Apple credits CVE-2026-86886 as a TCC
path-traversal issue allowing protected-file modification, fixed in 27.
This **supports** prioritizing registry/directory/migration callgraphs but
**does not attribute these individual methods to that CVE**. An alternative
explanation is general database-migration refactoring.

Apple reference: https://support.apple.com/en-us/149037

## Decision gate before any new device probe

1. Establish original 23U95 class/method-to-implementation mappings, and what
   input derives from a remotely supplied request rather than Apple-internal state.
2. Demonstrate the *daemon's own* destination sandbox and client entitlement
   validation, not just the app's `mach-lookup`.
3. A write to a normal, disposable, app-owned file would be a safe scoped proof.
   **Do not call** TCC mutation APIs or touch existing protected caches until
   original code and recovery paths are known.
4. The native Hermès FaceBundle restriction is independent; even arbitrary MG
   bytes would not alone prove first-party watch-face persistence.

**Status:** original executable + real physical watch boundaries verified;
no accepted TCC path/content writer, no protected plist mutation, no native unlock.


## Updated: original IMPs and first codeflow (18 November)

The new chained-32bit selector pointer decoder is **validated against real
`__objc_selrefs` entries**. One raw word `0x0408766e` masks to target
`0x8766e`, yielding original `stringByResolvingRealPathWithError:`;
`0x04081acd` masks to `0x81acd`, yielding
`getMigratedDBRelativeDirPath`. This matches Apple's
`DYLD_CHAINED_PTR_32` 26-bit target representation; the pointer must then
land within the original method-name section or it is rejected.

- [Original firmware validated ObjC mapping run #44263100273](https://github.com/mkalter/TESTAPP/actions/runs/44263100273):
  **72 verified relative lists**, **1,232 method names with IMP addresses**,
  43 lists with security/path-related names.
- [Bounded SHA-checked ARM64 disassembly run #44263378895](https://github.com/mkalter/TESTAPP/actions/runs/44263378895):
  64 selected methods, genuine original instruction sequences, no execution.
- **`getMigratedDBRelativeDirPath`** at `0x5341c`: just
  `ADRP x0, 0x9c000; ADD x0, x0, 0x370; RET` — a fixed in-image
  location, **not a client-controlled path argument**.
- **`getMigratedDBDir`** at `0x53428`: constructs/looks up a directory
  through internal helper calls; observed instructions do not by themselves
  establish any client-supplied destination.
- **`registerNewDBAtPath:`** at `0x718c`: moves the method's
  `x2` argument into `x19`, later places it in a stack argument and
  dispatches to another Objective-C selector stub at `0x63860`.
  **This is the concrete next edge to resolve**, not proof of a vulnerability.
- The verified bytecode implements separate normal database creation helpers
  at `0x29830` and `0x59324`; their authorization and callers
  remain unproven.

The new `resolve_tccd_class_owners.py` recovers `class_t`→`class_ro`
and `baseMethods` pointers with bounded 32-bit fixups. The new
`resolve_tccd_selector_stubs.py` resolves original `ADRP/LDR` selector
references for this and other bounded methods. Both are strictly **offline**;
they do not submit any XPC request to the Watch.

**Interpretation:** the direct migrated-relative-directory getter is a poorer
vulnerability candidate than initially suspected, since it returns a
constant rather than accepting a path. The registry method still takes a
string argument; its caller and the object ultimately being updated must be
traced before considering a safe app-owned test. No current evidence that
`registerNewDBAtPath:` writes arbitrary existing binary plists.


## 18 November — resolved registry selector, revised assessment

[Exact original 23U95 selector-call trace #44264152563](https://github.com/mkalter/TESTAPP/actions/runs/44264152563)
completed successfully, verifying **133 original ObjC selector call-sites in
25 selected methods**.

The actual `registerNewDBAtPath:` implementation at `0x718c` preserves
its method `x2` path argument but dispatches at `0x7224` to original
selector stub `0x63860`, decoded as:

```
-[... registerNewDBAtPath:] -> evalDB:locked:bind:step:
```

This is an **internal TCC SQL database evaluation/bind path**, not an
identified arbitrary file-write or protected-system-file writer. The
caller-controlled path, where allowed, appears to be registered inside TCC's
database; the selector is **not** evidence the path is itself the destination
of a write. More investigation of a specific real vulnerability would require
its accepted IPC interface and daemon sandbox destination rights. The separate
`getMigratedDBDir` selector chain invokes `stateDirectory`,
`getMigratedDBRelativeDirPath`, `stringByAppendingPathComponent:` and
`UTF8String`. The getter is a fixed image-relative value, not an independent
client-selected path.

### New non-destructive T6 on real Watch

`BQRunTrustedDaemonPolicyDifferential` is installed on the experiment branch,
shown as **T6 · Apple-daemonrechten** within the native Watch Face Lab.
It attempts `proc_listallpids` / `proc_name` from the user Watch app,
only for visible Apple `tccd`, `softwareupdated`, `MobileGestalt*`
processes. If name visibility permits, it calls
`sandbox_check(pid, "file-write-data", SANDBOX_FILTER_PATH, MG path)`
for the **daemon's effective process sandbox**. It logs ALLOW/DENY/UNKNOWN
and exits. If watchOS denies enumeration or cross-PID inspection, this is
`UNKNOWN`, **not** evidence that TCC can or cannot write. No XPC
request, process injection, root entitlement, sandbox extension or protected
file mutation is attempted. A daemon's `ALLOW` would still not establish
an authorized remote write API.

The offline source regression contract for six Watch labs passed in
[GitHub Actions #44264840267](https://github.com/mkalter/TESTAPP/actions/runs/44264840267).
The iPhone+Watch unsigned build is separately checked in
[GitHub Actions #44264801111](https://github.com/mkalter/TESTAPP/actions/runs/44264801111).


## Final physical T6 + verified original helper authority (2026-11-18)

On Watch6,18 / 23U95, `BQRunTrustedDaemonPolicyDifferential` returned:
`UNKNOWN: proc_listallpids list failed=1 (Operation not permitted)`.
This **does not imply a TCC or MobileGestaltHelper DENY**. It prevented
cross-PID process identity and kernel policy checks entirely. No reason to
reissue this identical test.

An independently retrieved **exact original** Watch6,18/23U95
`com.apple.tccd.sb` (529 lines), from [kernel sandbox run #44175646728](https://github.com/mkalter/TESTAPP/actions/runs/44175646728)
explicitly grants TCC-local writes (`${HOME}/Library/TCC`, CompanionSync,
process temp). It has no direct unrestricted MG SystemGroup write grant.
The 8,078-line inherited `baseline` has `common-mobilegestalt-rules`
for **read**/metadata and conditional SystemGroup write authorization.
This does not resolve TCC's effective runtime entitlements/extensions.

### Actual MobileGestaltHelper CodeSignature entropy and ABI

[Original signed-authority run #44266845679](https://github.com/mkalter/TESTAPP/actions/runs/44266845679)
and [original method-IMP run #44267247147](https://github.com/mkalter/TESTAPP/actions/runs/44267247147)
both succeeded using original 76,112-byte
`/usr/libexec/MobileGestaltHelper`,
SHA-256 `0e0c05244a3d35753e948783372f18e615ae2032cf7b750dd7a9cc57cfb3626e`.

**Real Mach-O signature** (not mere strings):
`LC_CODE_SIGNATURE` SuperBlob offset 54,736 size 21,376, with XML slot
`CSSLOT_ENTITLEMENTS=5` and DER slot 7. XML entitlements actually say:
- `com.apple.private.security.storage.MobileGestaltCache=true`
- `com.apple.security.system-groups=[systemgroup.com.apple.mobilegestaltcache, systemgroup.com.apple.mobileactivationd]`
- `com.apple.security.system-group-containers` is absent.

The independently extracted original launchd manifest announces service
`com.apple.mobilegestalt.xpc` for the helper, normally UID identity
`mobile` or feature-flag-dependently `_mobilegestalthelper`.
T2 already established this specific Mach name can be looked up from the
development-signed app (`kr=0`), but this does not confer a client writer.

**Verified original ARM64_32 method list**: 1 relative list, 11 method
implementations. Among them:
- `listener:shouldAcceptNewConnection:` at `0x4bbc`: sets exported
  XPC interface/object, resumes connection, returns `YES`;
- `getServerAnswerForQuestion:reply:` at `0x5110`: read-only server
  MG-answer path, **already physically tested on this build** and replied
  with MobileGestalt application error **9**, no answer, for
  DeviceBrand, hashed DeviceBrand, BuildVersion and ProductType;
- `rebuildCache:` at `0x55f0`: reply-handler-only argument, invokes
  private cache-rebuild function (may unlink existing protected cache);
- `setCacheSentinel:` at `0x5714`: reply-handler-only argument,
  dispatches `setCacheSentinel` with a fixed destination;
- `getSpringboardRegionOverride:reply:` is another read-only
  method, not a cache-write API.

The three selected IMPs and their original selector calls were
independently inspected in the second artifact. The read-only XPC
server query returning error 9 was **already documented** at
https://github.com/pookjw/HermesEnabler/issues/17 and must not be
presented as a fresh test opportunity.

**Current decision:** helper's signed entitlement is real, but known
exported *mutators* are rebuild/sentinel-only. These do **not** accept
controlled replacement bytes for existing `com.apple.MobileGestalt.plist`.
T6 is not repeatable from this sandbox and no arbitrary-content helper
setter was established. The genuine stock native Hermès system-face
goal remains unsolved; no protected file mutation is justified.
