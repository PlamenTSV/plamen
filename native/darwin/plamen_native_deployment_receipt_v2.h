#ifndef PLAMEN_NATIVE_DEPLOYMENT_RECEIPT_V2_H
#define PLAMEN_NATIVE_DEPLOYMENT_RECEIPT_V2_H

#include "plamen_broker_v2_install_receipt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_SIZE 256U
#define PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_RELATIVE \
    "share/plamen/native-deployment-receipt-v2.bin"

int plamen_native_darwin_deployment_receipt_bytes_v2(
    const struct plamen_install_receipt *,
    uint8_t output[PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_SIZE]);
int plamen_native_darwin_deployment_receipt_validate_v2(int,
    const struct plamen_install_receipt *);

#ifdef __cplusplus
}
#endif

#endif
