# Kernel-R/W alternative to SystemGroup MCM: verified original Watch6,18 / 23U95 driver inventory

**18 November 2026. Actual result: original firmware extraction and AVE driver comparison executed; no working kernel exploit, sandbox bypass or MobileGestalt write.**

## Evidence tied to exact Watch hardware

- Device: Apple Watch Ultra (1st generation), `Watch6,18`; OS `watchOS 26.6.1`; build `23U95`.
- Apple CDN image: `Watch6,18_26.6.1_23U95_Restore.ipsw`.
- Independently repeated `kernelcache.release.Watch6,18` SHA256: `ced56594d646bc39261c7f6d4cce8554accc9fd16cce6ec4aa70ad3d98f56261`.
- SHA matches prior firmware sandbox audit; this is not an iPhone or simulator substitute.
- CLI `blacktop/ipsw 3.1.749`, build `a7dfadbcaca8375b424c12a68dae40767e5e07c1`.
- Workflow: [#44255953731](https://github.com/mkalter/TESTAPP/actions/runs/44255953731), artifact `14405373896`: original matching kernel and full kext listing.
- Workflow: [#44256194296](https://github.com/mkalter/TESTAPP/actions/runs/44256194296), artifact `14406386459`: actual AVEM9 kext extracted, SHA and code markers retained.

### Verified exact firmware kext list

| Kernel extension | Found / original kernel |
| --- | --- |
| `com.apple.driver.AppleAVE2` | **Not listed** |
| `com.apple.driver.AppleAVEM9` | **Present: version 460.4.0** |
| `com.apple.driver.AppleAVD` | Present: 962 |
| `com.apple.driver.AppleJPEGDriver` | Present: 8.1.3 |
| `com.apple.iokit.IOSurface` | Present: 393.5.8 |

The AVEM9 kext was independently extracted as `Mach-O arm64e kext`, length **935400** bytes, SHA256 `fe1e24b4c278172d16024ce3ea85ac7c3d7bda264e5b15445d43729059196072`. Confirmed source strings include `AppleAVEUserClient`, H.264 encoder commands and CAVE queue/controller state. Confirmed absent string markers `AppleAVE2`, `eEncType`, `sEnc.eType`, and `EncType mismatch with session`.

### Why this matters

CVE-2026-84607 is a documented AVEVideoEncoder kernel-race issue fixed by Apple in iOS 26.7 / watchOS 27. Reverse engineering of the **iPhone `AppleAVE2`** implementation identifies `eEncType` / `sEnc.eType` synchronization as a potential fixed guard. [Independent writeup](https://github.com/Ping-2o/ios.CVE-2026-84616-84607/blob/main/REPORT_AVE_84607.md) makes clear that precise attribution of this guard to CVE-2026-84607 is inference, not an Apple-confirmed mapping.

On **this Watch** the matching `AppleAVE2` driver is **absent**. The actual video encoder is the **different** `AppleAVEM9` with distinct user-client naming and code structure. Therefore blindly copying an iOS `AppleAVE2Driver` selector/race payload into the Watch app is invalid and may panic the device. The missing specific string markers do not prove AVEM9 vulnerable: it is a different driver family, not a changed version of AppleAVE2.

### Independent evaluation of a public purported 'kernel R/W' payload

`SonicSec/l0fck` `payloads/appleave2/appleave2_core.c` is designed explicitly for iPhone 16 Pro / A18 Pro `T8140` / iOS 26.6.1 `23G83`. It uses `IOServiceMatching("AppleAVE2Driver")` and therefore cannot even directly match the exact Watch6,18 driver inventory. Also, its `ave_verify_read_primitive` function sets `krw_ready=true` solely from a leak-like nonzero value inside a returned structure. **It does not demonstrate a second genuine kernel read and a verified kernel write/readback.** A possible pointer leak or a report's `krw_ready` flag is not proof of arbitrary kernel R/W. Source: https://github.com/SonicSec/l0fck/blob/main/payloads/appleave2/appleave2_core.c

The published Watch kernel read/write example [datalocaltmp/Peepo](https://github.com/datalocaltmp/Peepo) is hard-coded to Apple Watch Series 4 / watchOS 10.6.1/10.6.2 and warns that wrong hardware/offsets can panic the Watch. It does not apply to `Watch6,18` / `23U95`.

### Actual conclusion

**New verified route class:** a kernel exploit with genuine kernel read/write could bypass userland SystemGroup sandbox restrictions. **Tested current result:** the public `AppleAVE2` candidates are not portable because the original Watch6,18 build instead uses `AppleAVEM9`; no working AVEM9-specific exploit or root-equivalent write was found. No arbitrary system-cache write or Hermès unlock has been established. **Do not deploy guessed AVE selectors or crash/race payloads to the user’s physical watch.**

Investigating AVEM9 further would require independently verifying a real flaw in its own code and a safe recovery plan. A kext inventory, a returned kernel pointer, a build or a working file open is not yet the requested persistent MobileGestalt change.



## Independently cross-checked receiver IOKit policy — exact Watch6,18 23U95

Source: earlier original matching-kernel decompilation [GitHub run #44090713056](https://github.com/mkalter/TESTAPP/actions/runs/44090713056), artifact `14330888839`, under `commands/baseline.sb` and `commands/temporary-sandbox.sb`. This is a **new analysis** of the actual sandbox policy, not an iPhone policy or hypothetical entitlement.

For these exact three IOKit operations, the decompiled profiles contain the following rule counts:

| Operation | `baseline.sb` rules | `temporary-sandbox.sb` rules | AVEM9 / AVE2 class explicitly mentioned? |
| --- | ---: | ---: | --- |
| `iokit-open-user-client` | 4 | 10 | **No** |
| `iokit-open-service` | 4 | 10 | **No** |
| `iokit-set-properties` | 4 | 12 | **No** |

Relevant actual conditions:

- `baseline.sb:6290–6297`: `iokit-open-user-client` uses `autobox` and `autobox-client` profile flags, then an explicit `deny` fallback.
- `baseline.sb:6314–6328`: `iokit-set-properties` likewise uses autobox profile flags followed by an explicit `deny` fallback.
- `temporary-sandbox.sb:12351–12353`: a generic user-client exception is conditioned on the sandbox extension `com.apple.security.exception.iokit-user-client-class`; no visible AVEM9-specific allowance appears in that profile.
- The original kext contains `AppleAVEUserClient` strings and the kernelcache contains `com.apple.driver.AppleAVEM9`, but **these are not a grant of any IOKit access from a third-party developer-signed watch app**.

**Important limitations:** A complete runtime sandbox evaluation depends on dynamic process flags, entitlements, container profile inheritance and IOKit driver-specific checks. This textual profile audit does **not** prove that `IOServiceOpen` must fail or succeed. In particular, a generic extension class appearing in a rule is not evidence that a normal Watch app can obtain it. No on-device IOKit opens were attempted in this research.

Operational consequence: the claimed iPhone AppleAVE2 race is **not directly portable**, and even a genuine hypothetical `AppleAVEM9` race would require proving that the target Watch app can open the appropriate `AppleAVEUserClient` under its effective sandbox before it could be used. Guessed selectors, reported kbase pointers and a succesful build are not equivalent to that proof.
