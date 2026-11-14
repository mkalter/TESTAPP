#pragma once
#import <Foundation/Foundation.h>

// All tests are observational: no writes to protected resources.
FOUNDATION_EXPORT NSString *BQSystemAudit(void);
FOUNDATION_EXPORT NSString *BQSandboxPolicySummary(NSString *path);
