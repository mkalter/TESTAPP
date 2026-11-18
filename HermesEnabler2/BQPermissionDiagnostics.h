#pragma once
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
/// Read-only SystemGroup permission diagnostics. Writes only a disposable
/// control file in the app's own App Group and a report in Documents.
/// Never creates or modifies a protected MobileGestalt file.
FOUNDATION_EXPORT NSString *BQRunPermissionDiagnostics(void);
/// Compare Class 7 flags for the app's own App Group only (no protected target).
FOUNDATION_EXPORT NSString *BQRunClass7ControlMatrix(void);
/// Map write-authorization boundaries without protected writes or escapes.
FOUNDATION_EXPORT NSString *BQRunWriteGateDiagnostics(void);
/// Observes KAMUI Class 13 SystemGroup token issuance, never consumes tokens.
FOUNDATION_EXPORT NSString *BQRunKAMUI26TokenProbe(void);
/// Manually compare direct MCM Class 13 token consumption with actual write-open rights.
/// Opens protected file O_WRONLY then closes immediately, no bytes modified.
FOUNDATION_EXPORT NSString *BQRunKAMUI26WriteOpenTest(void);
/// Extended, non-destructive authorization matrix across protected/cache and own paths.
/// Does not request extensions or write protected data.
FOUNDATION_EXPORT NSString *BQRunExtendedAuthorizationMatrix(void);
/// Compare sandbox policy at parent/child path boundaries; real writes only in app-owned containers.
FOUNDATION_EXPORT NSString *BQRunPathAuthorizationDifferential(void);
/// Real Apple-private MGSetAnswer attempt, guarded by verified backup and recorded disk comparison.
FOUNDATION_EXPORT NSString *BQRunMGSetAnswerWriteExperiment(void);
/// Read-only persistence check after reopening Watch app.
FOUNDATION_EXPORT NSString *BQCheckMGSetAnswerCanary(void);
/// Real IOKit property set calls, using only the exact existing property bytes.
FOUNDATION_EXPORT NSString *BQRunIODeviceTreeWriteProbe(void);

//// Watch6,18 native FaceBundle / Carousel authorization lab (READ ONLY).
/// T1: effective sandbox mach-lookup preflight for known Apple face services.
FOUNDATION_EXPORT NSString *BQRunNativeFaceMachPolicy(void);
/// T2: bootstrap_look_up name resolution only; no XPC messages or method calls.
FOUNDATION_EXPORT NSString *BQRunNativeFaceBootstrapLookup(void);
/// T3: filesystem existence and read-only access to native store candidates.
FOUNDATION_EXPORT NSString *BQRunNativeFaceStorePolicy(void);
/// T6: read-only daemon PID visibility and effective sandbox preflight; may be unavailable.
FOUNDATION_EXPORT NSString *BQRunTrustedDaemonPolicyDifferential(void);
/// T5: read-only TCC/Software Update mach policy plus MobileGestalt ownership metadata.
FOUNDATION_EXPORT NSString *BQRunProtectedWriterServiceGate(void);
/// T10: read-only CLKDevice hardware category/collection and Hermes2025 eligibility gates.
FOUNDATION_EXPORT NSString *BQRunOriginalHermes2025IdentityGates(void);
/// T9: local original NanoTimeKit forMigration YES/NO FaceBundle lookup, no FaceStore write.
FOUNDATION_EXPORT NSString *BQRunClockKitMigrationLookupDifferential(void);
/// T8: opt-in positive-control comparison using local supported NTK style, then original Hermès.
FOUNDATION_EXPORT NSString *BQRunClockKitAvailabilityDifferential(void);
/// T7: explicit opt-in read-only ClockKit face validation XPC (no import, no face addition).
FOUNDATION_EXPORT NSString *BQRunClockKitReadOnlyFaceValidation(void);
/// T4: on-watch inventory of signed Apple FaceBundle path candidates.
FOUNDATION_EXPORT NSString *BQRunNativeFaceBundleInventory(void);
NS_ASSUME_NONNULL_END
