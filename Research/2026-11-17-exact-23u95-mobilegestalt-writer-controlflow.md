# Exact watchOS 26.6.1 / 23U95 MobileGestalt writer and data-origin analysis

Date: 2026-11-17. Hardware `Watch6,18`, Apple Watch Ultra 1.
**Verified protected write by a normally signed Watch app: NO.**
**Original native Hermès system watchface: NOT unlocked.**

## Reproducible original-source evidence

Source: Apple's original `Watch6,18_26.6.1_23U95_Restore.ipsw`, extracted via read-only APFS range requests and original ARM64_32 dyld shared cache; no hardware mutated. Entire IPSW SHA-256 was not verified. Original `/usr/lib/libMobileGestalt.dylib` extracted byte-for-byte SHA-256:

`a842db6add515926a9ef49da87bc7467974c8e8b52f7550e40f111c455c42bd0`

Mach-O LC_SYMTAB: 1,437 records. Symbol addresses validated as actual `__TEXT,__text` executable instructions with Capstone. Source and reproducible workflow:

- [First exact writer disassembly, successful GitHub Actions #44167086841](https://github.com/mkalter/TESTAPP/actions/runs/44167086841), artifact `14365154428`.
- [Extended provider/helper audit, successful GitHub Actions #44168075534](https://github.com/mkalter/TESTAPP/actions/runs/44168075534), artifact `14366462220`.
- `Research/firmware-23u95/trace_mobilegestalt_authority.py`, `.github/workflows/audit-23u95-mobilegestalt-writer.yml`.

## Genuine concrete functions — not guessed strings

| Symbol | Verified VM address | Observed body / implications |
| --- | --- | --- |
| `__MGWriteCache` | `0x215F4608` | Real externally listed code; builds cache data in the current process, including calls to `_MGCopyAnswer`. An internal test at `0x215F4638` branches based on a Boolean. No directly evidenced caller-supplied modified plist argument |
| `__MGRebuildCache` | `0x215F4F88` | Direct calls to `__MGWriteCache` at `0x215F5018`; checks cache validity and internal state. No arbitrary DeviceBrand setter demonstrated |
| `__MGWriteCacheOnHelper` | `0x215C1254` | A **12-instruction late-bound dispatch thunk**. Loads a function pointer; if absent calls resolver `0x215B28F0` with identifiers `0x2E, 2`; then `br x0`. This body does not itself accept a plist or show data serialization; the *resolved implementation* was **not independently decoded** |
| `__MGSetServer` | `0x215BAA04` | **Exactly 4 instructions**: sets a process-local global byte to 1, then `ret`. This is neither a code-signature entitlement nor a sandbox extension, and does not promote a third-party process to Apple's privileged helper |
| `_MobileGestalt_get_deviceBrand` | `0x215E5704` | Actual wrapper calls `_MGCopyAnswer` at `0x215E5734`, converts the result from CFNumber to an integer and returns it; does not directly write registry or persistent plist |
| `__MGCacheCopyValueForKey` | `0x215F526C` | First nine instructions make a conditional read-path tail branch or return null; nearby disassembly beyond first `ret` belongs to following local functions and **must not be attributed** to this symbol |
| `__MGClearInProcessCache` | `0x215F4E8C` | Iterates and releases in-process cache entries; not a protected system-file writer |
| `__MGRebuildCache4PurpleRestore` | `0x215F4F84` | Exactly one `b 0x215F4E8C` to `__MGClearInProcessCache`, not an arbitrary restore or plist import |
| `__MGWriteRebuildCacheSentinel` | `0x215C1284` | Another late-bound thunk; no explicit caller-controlled cache data in visible wrapper |
| `MGSetAnswer` / `_MGSetAnswer` / `__MGSetAnswer` | NOT in target Mach-O nlist | Absence from this symbol table, consistent with prior development app's failed dlsym; absence is not proof no other privileged IPC setter exists |

### Checked assembly details

`__MGWriteCache`:
```asm
0x215f4638  bl   #0x215e128c
0x215f463c  tbz  w0, #0, #0x215f48ac
...
0x215f46b4  bl   #0x215b0d80    ; _MGCopyAnswer
```
There is an actual branch gate before the main cache-building work. Its exact semantic condition is **unknown** until `0x215E128C` is resolved, so the presence of an exported `__MGWriteCache` symbol is not evidence of a callable arbitrary write.

`__MGRebuildCache`:
```asm
0x215f5010  bl   #0x215e128c
0x215f5014  cbz  w0, #0x215f5020
0x215f5018  bl   #0x215f4608  ; __MGWriteCache
```

`__MGWriteCacheOnHelper`:
```asm
0x215c1254  adrp x8, #0x78a5c000
0x215c1258  ldr  w8, [x8, #0xf6c]
0x215c125c  ldr  w0, [x8, #0xb8]
0x215c1260  cbz  w0, #0x215c1268
0x215c1264  br   x0
0x215c1270  mov  w0, #0x2e
0x215c1274  mov  w1, #2
0x215c1278  bl   #0x215b28f0
0x215c1280  br   x0
```
The thunk is not a proven arbitrary-content setter. Its dynamic target may be a stub, IPC operation or privilege-specific implementation; **not resolved by this audit**.

`__MGSetServer`:
```asm
0x215baa04  adrp x8, #0x78a5d000
0x215baa08  mov  w9, #1
0x215baa0c  strb w9, [x8, #0x184]
0x215baa10  ret
```
This toggles a **local process variable**. It cannot add the Apple-private `com.apple.security.system-groups` or `com.apple.private.security.storage.MobileGestaltCache` to the Watch app.

## Reassessed path to a changed original cache

**Copy-edit-delete-recreate-via-CFPrefsZeroFile remains blocked.** The existing MobileGestalt file is protected against unlink/rename; the external CFPrefsZeroFile proof-of-concept can create a missing empty root-owned file, but cannot populate chosen bytes or overwrite the existing file. No path/entitlement upgrade results from creating a system-group-looking path.

**Calling `__MGWriteCache` isn't an arbitrary write API either.** The visible code pulls values with `_MGCopyAnswer` in the process context. A development-signed Watch app has already observed `EPERM` when opening the protected system cache for writes. Local cache state or invoking `__MGSetServer` cannot change the kernel's separate file-write authorization.

**Calling `__MGWriteCacheOnHelper` cannot yet be assumed useful.** Its public entry is a late-bound thunk and the actual resolved implementation/caller permissions have not been traced. No application-provided plist parameter was observed here. Do not call rebuild or sentinel on the physical Watch merely to test a connection: the helper may unlink/regenerate the live cache.

## Remaining precise questions (not yet positive results)

1. What does the actual routine at `0x215E128C` check before `__MGWriteCache` enters the cache-building branch? A semantic answer requires a bounded original-code disassembly and callers.
2. What implementation does the `0x215B28F0` late-binding resolver select for `__MGWriteCacheOnHelper` function identifier `0x2E` on 23U95? A 12-instruction thunk alone cannot determine whether a controllable data argument exists.
3. How is DeviceBrand's authoritative provider (`marketing-software-behavior` in earlier matching code) reconciled with an absent key on the physical Watch? A changed cache value could be regenerated from unmodified device data, and native Hermès still has independent availability gates.

**No writable original MobileGestalt file descriptor, persistent patch or first-party Hermès gallery installation was demonstrated.**
