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
/// Read signed claims from this Watch executable and inspect process entitlements when supported.
/// Never requests privileges or accesses MobileGestalt files.
FOUNDATION_EXPORT NSString *BQRunRuntimeEntitlementDiagnostics(void);
/// Distinguish independent sandbox, Unix DAC, filesystem and path identity gates.
/// Read-only: no protected write-open, extension token or protected write.
FOUNDATION_EXPORT NSString *BQRunDenialRootCauseDiagnostics(void);
/// Survey API exports without calling write-related or cross-process operations.
FOUNDATION_EXPORT NSString *BQRunReadOnlyAPISurvey(void);
NS_ASSUME_NONNULL_END
