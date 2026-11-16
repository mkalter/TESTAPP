# watchOS 26.6.1 / 23U95 — experimental code-gap analysis

Comparison date: 2026-11-16.

Sources:
- mkalter/TESTAPP branch experiment/private-entitlements-watch: HermesEnabler2/BQCore.m
- pookjw/HermesEnabler main: HermesEnabler2/BQCore.m
- Upstream commit 7d84d97d96ee6e1690e5c3dcd76cbe2910a1508 (watchOS 26.6.1 experimental)
- Upstream release 1.6.2 (Nov 16) explicitly warns that watchOS 26 compatibility is not verified.

## The actual code difference (not another entitlement test)

| Component | Our TESTAPP BQCore.m | Updated upstream BQCore.m | Existing experimental observations |
|---|---|---|---|
| Class 7 main escape | Original combined flag | Special watchOS 26 flag, original fallback | Our read-only Class 7 own-AppGroup matrix already checks both flags; that **does not** test effect of target redirection or protected-file authorization |
| Class 13 traversal | Original traversal only | Original traversal plus an extra watchOS 26 query variant | Existing direct/file-scoped Class 13 probe used the protected plist path and measured no successful write; upstream has a different target-context path in the main escape routine |
| Code-signing | Ordinary App Group | Ordinary App Group | Apple-specific MobileGestaltCache and SystemGroup entitlements remain absent in the actual process |
| Actual SystemGroup write | Denied EPERM | Unverified by upstream (watchOS 26 is experimental) | Must not assert working based on release metadata |

**Important distinctions**
1. A matching numeric MCM flag is not proof that two experiments exercised the same context (class, container, target, link state, requested part, entitlement, resolved path).
2. Query success, token consumption, and write permission are different stages.
3. The user's direct MG read works; POSIX owner bit permits writing; APFS volume is writable; the sandbox denies MG file-write-data.
4. User's actual own-AppGroup control can create/write/read/delete; a sandbox policy preflight incorrectly predicted denial for its root. Therefore actual operations and file/sandbox metadata must be interpreted separately.
5. The new upstream changes are **not** proof of a working watchOS 26.6.1 escape: the author explicitly says their implementation has not been verified on a Watch running watchOS 26.

## Three distinguishable research hypotheses

**H1: Container query target-context mismatch.** Prior experimental logging used a protected file as the observation target, while the updated upstream escape implementation operates in a different path context. The relevant distinction is not the literal numeric flag but whether any granted capability corresponds to the protected vnode and requested operation. Analyze source and system-policy behavior offline first; no protected write test should be conflated with token presence.

**H2: Class 7 entitlement resolution may differ between ordinary App Group and redirected target.** The own-group flag matrix measured only a correctly entitled group, with no redirected path. It cannot establish or exclude the effect of upstream's distinct state. This is an unproven hypothesis, not a confirmed bypass. Source inspection shows the upstream method manipulates App Group paths and can interrupt access to group data; do not treat it as harmless on a production Watch.

**H3: There is a stronger cache-specific signature gate.** Matching build MobileGestaltHelper carries com.apple.private.security.storage.MobileGestaltCache and system-groups entitlements; our SecTask reports both absent. The Helper is reachable by bootstrap, but the published XPC methods expose reads and cache maintenance, not a value-specific setter. A distinct route must satisfy authorization for the requested operation, not merely launchd service lookup.

## Next useful research milestones

A. Offline structural comparison of the upstream watchOS 26 modifications with the actual tests already run. Document context differences rather than repeating identical MCM flag matrices.

B. Exact-build static examination of access policies and service method contracts to identify a **legitimately authorized** value-specific interface, if one exists; differentiate listener acceptance from per-question descriptor checks and file authorization.

C. If proposing an alternative, require an explicit success criterion involving operation-specific permissions and unchanged protected cache metadata before considering any write-bearing experiment. Existing production Watch cache data must remain untouched.

No sandbox escape, protected write, or persistent native face activation has been demonstrated in the observed logs.
