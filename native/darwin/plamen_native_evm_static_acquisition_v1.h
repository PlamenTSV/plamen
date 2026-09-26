#ifndef PLAMEN_NATIVE_EVM_STATIC_ACQUISITION_V1_H
#define PLAMEN_NATIVE_EVM_STATIC_ACQUISITION_V1_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_NATIVE_EVM_STATIC_ACQUISITION_V1_VERSION 1U
#define PLAMEN_NATIVE_EVM_STATIC_ACQUISITION_V1_ROLE_COUNT 2U

struct plamen_native_evm_static_role_projection_v1 {
    uint16_t role;
    int payload_fd;
    int producer_receipt_fd;
    int source_manifest_fd;
    uint64_t payload_size;
    uint64_t producer_receipt_size;
    uint64_t source_manifest_size;
    uint8_t payload_sha256[32];
    uint8_t producer_receipt_sha256[32];
    uint8_t source_manifest_sha256[32];
};

struct plamen_native_evm_static_projection_v1 {
    struct plamen_native_evm_static_role_projection_v1 roles[
        PLAMEN_NATIVE_EVM_STATIC_ACQUISITION_V1_ROLE_COUNT];
};

/*
 * Produce only the fixed role-8/role-9 installed source-authority leaves.
 * The stage root and all four upstream inputs are retained descriptors; no
 * pathname, digest, policy, callback, environment, or network input exists.
 * Every output is created O_EXCL beneath the retained stage root, frozen to
 * 0400, reopened O_RDONLY, and returned in `projection`. On any failure all
 * leaves created by this call are removed before returning.
 */
int plamen_native_evm_static_acquisition_issue_v1(uid_t owner_uid,
    int staged_generation_root_fd, int medusa_archive_fd,
    int medusa_sigstore_bundle_fd, int solc_provider_index_fd,
    int solc_binary_fd,
    struct plamen_native_evm_static_projection_v1 *projection);

void plamen_native_evm_static_projection_dispose_v1(
    struct plamen_native_evm_static_projection_v1 *projection);

#ifdef __cplusplus
}
#endif

#endif
