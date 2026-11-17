# Apple Watch Ultra 1 / 23U95 — IOKit provider-property absence follow-up

## Device log (2026-11-17)
The previous test was able to resolve all six IOKit APIs and open
`IODeviceTree:/chosen`. It then stopped at:

```
STOP: original property missing or not CFData; no IOKit writes attempted.
```

**Critical correction:** This message combines two independent cases:
`IORegistryEntryCreateCFProperty(...,"marketing-software-behavior")` returned
NULL **or** returned a CoreFoundation value whose type ID is not `CFData`.
The old code did not disclose which. It therefore did not test any setter.

Static analysis in [HermesEnabler issue #7](https://github.com/pookjw/HermesEnabler/issues/7)
traced the 23U95 DeviceBrand provider to `IODeviceTree:/chosen`,
`marketing-software-behavior`, byte offset 2. The provider explicitly
returns zero when the property is missing or malformed. Thus its presence
in the firmware algorithm is not proof of presence on retail Watch6,18.

## What changed in the test

- Prints **exact actual CoreFoundation type** (CFData, CFNumber, CFString,
  CFBoolean, CFArray, CFDictionary, unknown, or absent). Data lengths are
  logged but not the property data itself.
- Dynamically checks `IORegistryEntryCreateCFProperties`.
- On existing `IODeviceTree:/chosen`, `IODeviceTree:/`, and
  `IODeviceTree:/options`, reads the direct property and any available
  property table, reporting **count, target type and matching key NAMES
  only**. No device identifiers or values are exported.
- If chosen's target is absent or not CFData, explicitly logs that **none
  of the three setter APIs was invoked**.
- If genuine CFData of the expected size exists, the existing opt-in
  same-value tests may proceed unchanged after the backup guards.
- Does not create a missing provider property, guess its value, modify
  system identity, or request any private entitlement.

## What the next report will answer

1. Does the chosen node have the key in its property snapshot?
2. Is the direct read NULL despite a key existing in the table?
3. Is the key on a different node?
4. Is it really CFData, and if so what size?
5. Did the native same-value IOKit setters run, or did the test skip?

A missing original property does NOT demonstrate denial by any IOKit
write API. A successful API call with the original value does NOT prove
persistent writable MobileGestalt access. The result must not be
described as a successful bypass without those further checks.

## References

- watchOS 23U95 physical Series 8 research and firmware analysis:
  https://github.com/pookjw/HermesEnabler/issues/7
- Apple IOKit read calls:
  https://developer.apple.com/documentation/iokit/1514293-ioregistryentrycreatecfproperty
  https://developer.apple.com/documentation/iokit/1514310-ioregistryentrycreatecfpropertie
