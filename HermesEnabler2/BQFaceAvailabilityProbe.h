#pragma once
#import <Foundation/Foundation.h>

// Diagnostics execute on the physical Watch, never on the iPhone.
// Observe native NanoTimeKit/ClockKit device eligibility without mutation.
FOUNDATION_EXPORT NSString *BQRunWatchFaceAvailabilityProbe(void);
