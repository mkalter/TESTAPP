#import <Foundation/Foundation.h>

// Observational companion-side comparison. No Watch or iPhone system files
// are modified. Both lookups use the exact same paired CLKDevice object.
FOUNDATION_EXPORT NSString *HERMESRunMigrationEligibilityProbe(void);

// One action: real face creation, paired-library attempt, native watchface export.
FOUNDATION_EXPORT void HERMESAttemptFaceActivation(void (^completion)(NSString *report, NSURL * _Nullable watchFaceURL));
