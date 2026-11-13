#pragma once
#import <Foundation/Foundation.h>

// No cache writes. Returns a detailed text report comparing explicitly
// selected MobileContainerManager queries and open(2) access results.
FOUNDATION_EXPORT NSString *BQRunRouteDiagnostics(void);
