#ifndef PLAMEN_NATIVE_CODE_IDENTITY_V2_H
#define PLAMEN_NATIVE_CODE_IDENTITY_V2_H

#include "plamen_broker_v2_install_receipt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Independently observe and match all receipt-bound signed members. */
int plamen_native_darwin_validate_signed_closure_v2(
    const struct plamen_install_receipt *, int generation_fd);

#ifdef PLAMEN_NATIVE_CODE_IDENTITY_V2_TESTING
typedef void (*plamen_native_code_identity_swap_hook_v2)(const char *);
void plamen_native_code_identity_test_swap_hook_v2(
    plamen_native_code_identity_swap_hook_v2);
#endif

#ifdef __cplusplus
}
#endif

#endif
