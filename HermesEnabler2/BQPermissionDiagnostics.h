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
NS_ASSUME_NONNULL_END
