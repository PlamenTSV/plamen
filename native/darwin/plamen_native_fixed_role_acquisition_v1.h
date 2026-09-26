#ifndef PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_H
#define PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_VERSION 1U
#define PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT 7U

/*
 * One already-materialized setup input.  Every descriptor must be a retained
 * O_RDONLY|CLOEXEC regular vnode owned by `owner_uid`.  The reviewed policy
 * descriptor is used only to rejoin its exact SHA-256 to the policy digest
 * compiled into the signed operation-4 executable.
 */
struct plamen_native_fixed_role_input_v1 {
    uint16_t role;
    uint16_t reserved;
    int payload_fd;
    int semantic_receipt_fd;
    int source_manifest_fd;
    int reviewed_policy_fd;
};

struct plamen_native_fixed_role_projection_row_v1 {
    uint16_t role;
    uint16_t reserved;
    int payload_fd;
    int producer_receipt_fd;
    int source_manifest_fd;
    uint64_t payload_size;
    uint64_t producer_receipt_size;
    uint64_t source_manifest_size;
    uint8_t policy_sha256[32];
    uint8_t payload_sha256[32];
    uint8_t producer_receipt_sha256[32];
    uint8_t source_manifest_sha256[32];
};

struct plamen_native_fixed_role_projection_v1 {
    struct plamen_native_fixed_role_projection_row_v1 roles[
        PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT];
};

/*
 * Publish roles 0-4, 7 and 10 below the retained private stage root.
 *
 * The only caller-selected values are retained descriptors.  Roles, names,
 * hashes, sizes, modes, schemas and footer bytes come from the compiled fixed
 * operation-4 policy.  Output producer receipts are exactly
 * `semantic_receipt || PLMOP4R1-footer`.  On any failure every leaf created by
 * this invocation is removed and `projection` owns no descriptors.
 */
int plamen_native_fixed_role_acquisition_issue_v1(uid_t owner_uid,
    int staged_generation_root_fd,
    const struct plamen_native_fixed_role_input_v1 inputs[
        PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT],
    struct plamen_native_fixed_role_projection_v1 *projection);

void plamen_native_fixed_role_projection_dispose_v1(
    struct plamen_native_fixed_role_projection_v1 *projection);

#ifdef __cplusplus
}
#endif

#endif
