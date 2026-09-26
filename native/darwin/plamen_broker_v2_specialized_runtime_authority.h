#ifndef PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_AUTHORITY_H
#define PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_AUTHORITY_H

#include "plamen_broker_v2_install_receipt.h"
#include "plamen_native_image_member_receipt_v2.h"
#include "plamen_native_builder_v2.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_AUTHORITY_VERSION 1U
#define PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_RECEIPT_PATH \
    "share/plamen/image-member-receipt-v2.bin"
#define PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_POLICY_PATH \
    "verification_policy/native_runtime_bindings.v2.json"

struct plamen_broker_v2_specialized_runtime_authority_open {
    uint32_t version;
    /* Retained installed-generation directory, never an ambient path. */
    int generation_fd;
    int runtime_manifest_fd;
    const struct plamen_install_receipt_member *runtime_manifest_member;
    int image_member_receipt_fd;
    const struct plamen_install_receipt_specialized_authority *auxiliary;
};

struct plamen_broker_v2_specialized_runtime_authority {
    uint32_t version;
    char oci_image_reference[
        PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_REFERENCE_BYTES];
    char oci_init_reference[
        PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_REFERENCE_BYTES];
    uint16_t target_arch;
    uint8_t runtime_manifest_sha256[32];
    uint8_t runtime_manifest_tree_sha256[32];
    uint8_t image_member_receipt_sha256[32];
    uint8_t member_roster_sha256[32];
    uint8_t frozen_policy_sha256[32];
    uint8_t frozen_policy_bytes_sha256[32];
    uint8_t authority_sha256[32];
    uint8_t runtime_digests
        [PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_COUNT][32];
    struct plamen_image_member_receipt_v2 image_members;
};

int plamen_broker_v2_specialized_runtime_authority_load(
    const struct plamen_broker_v2_specialized_runtime_authority_open *,
    struct plamen_broker_v2_specialized_runtime_authority *);

#ifdef __cplusplus
}
#endif

#endif
