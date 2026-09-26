#ifndef PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RECEIPT_H
#define PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RECEIPT_H

#include "plamen_broker_v2_specialized_output_census.h"
#include "plamen_broker_v2_specialized_request.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RECEIPT_VERSION 1U
#define PLAMEN_BROKER_V2_SPECIALIZED_DYNAMIC_IDENTITY_APPLE_CDHASH 1U

struct plamen_broker_v2_specialized_output_receipt {
    uint32_t version;
    uint16_t lane;
    uint16_t method;
    char operation[32];
    uint8_t request_sha256[32];
    uint8_t effects_binding_sha256[32];
    uint8_t worker_request_sha256[32];
    uint8_t lifecycle_receipt_sha256[32];
    uint32_t post_spawn_dynamic_identity_kind;
    uint32_t post_spawn_dynamic_identity_size;
    uint8_t post_spawn_dynamic_identity_sha256[32];
    uint8_t network_policy_sha256[32];
    uint8_t observed_egress_sha256[32];
    uint8_t provider_authenticated;
    uint8_t network_policy_enforced;
    uint8_t population_zero;
    uint8_t cleanup_complete;
    uint16_t tree_count;
    struct plamen_broker_v2_specialized_output_tree
        trees[PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_COUNT_MAX];
    uint8_t tree_roster_sha256[32];
    uint8_t receipt_hmac_sha256[32];
};

/* tree_roster_sha256 preimage, in order:
 * "PLAMEN-SPECIALIZED-OUTPUT-TREE-ROSTER-V1\0", big-endian tree_count,
 * then each name-sorted row as big-endian version/role, zero-padded
 * name[32], zero-padded relative_path[128], sha256 and big-endian counts.
 * receipt_hmac_sha256 uses the specialized lane session key, domain
 * "PLAMEN-SPECIALIZED-OUTPUT-RECEIPT-V1\0", and every scalar/digest above
 * through tree_roster_sha256 (the roster commits the complete row bodies).
 */

/* The codec supplies the exact closed specs; this function independently
 * opens and recensuses each output below the retained scratch FD. */
int plamen_broker_v2_specialized_output_receipt_build(
    const uint8_t session_key[32],
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const uint8_t lifecycle_receipt_sha256[32],
    uint32_t post_spawn_dynamic_identity_kind,
    uint32_t post_spawn_dynamic_identity_size,
    const uint8_t post_spawn_dynamic_identity_sha256[32],
    const uint8_t network_policy_sha256[32],
    const uint8_t observed_egress_sha256[32],
    uint8_t provider_authenticated,
    uint8_t network_policy_enforced,
    uint8_t population_zero,
    uint8_t cleanup_complete,
    int scratch_fd,
    const struct plamen_broker_v2_specialized_output_spec *specs,
    size_t spec_count,
    struct plamen_broker_v2_specialized_output_receipt *receipt);

/* Replays all immutable links and both digest layers without filesystem I/O. */
int plamen_broker_v2_specialized_output_receipt_validate(
    const struct plamen_broker_v2_specialized_output_receipt *receipt,
    const uint8_t session_key[32],
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const uint8_t lifecycle_receipt_sha256[32],
    const struct plamen_broker_v2_specialized_output_spec *specs,
    size_t spec_count);

#ifdef __cplusplus
}
#endif

#endif
