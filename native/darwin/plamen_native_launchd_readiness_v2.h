#ifndef PLAMEN_NATIVE_LAUNCHD_READINESS_V2_H
#define PLAMEN_NATIVE_LAUNCHD_READINESS_V2_H

#include "plamen_broker_v2_install_receipt.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Execute the receipt-bound launcher in its fixed readiness-only mode.
 * A successful broker SERVICE_READY response is transitive proof of custody
 * readiness because the broker hard-stops before listening unless its
 * authenticated, session-bound custody status exchange succeeds.
 */
int plamen_native_launchd_authenticated_ready_v2(
    const struct plamen_install_receipt *, int generation_fd);

#ifdef __cplusplus
}
#endif

#endif
