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
