#include "plamen_broker_v2_specialized_output_receipt.h"
#include "plamen_broker_v2.h"

#include <string.h>

static int zero32(const uint8_t value[32])
{
    uint8_t aggregate = 0; size_t index;
    for (index = 0; index < 32U; ++index) aggregate |= value[index];
    return aggregate == 0;
}

static int equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0; size_t index;
    for (index = 0; index < size; ++index) difference |= left[index] ^ right[index];
    return difference == 0;
}

static void put16(uint8_t *output, uint16_t value)
{ output[0] = (uint8_t)(value >> 8); output[1] = (uint8_t)value; }

static void put32(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value >> 24); output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8); output[3] = (uint8_t)value;
}

static void put64(uint8_t *output, uint64_t value)
{
    size_t index;
    for (index = 0; index < 8U; ++index)
        output[index] = (uint8_t)(value >> ((7U - index) * 8U));
}

static int safe_fixed_string(const char *value, size_t capacity)
{
    size_t index, size;
    if (value == NULL || (size = strnlen(value, capacity)) == 0U
        || size >= capacity) return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < 0x20U || byte > 0x7eU || byte == '\\' || byte == '"')
            return 0;
    }
    return 1;
}

static int serialize_tree_roster(
    const struct plamen_broker_v2_specialized_output_receipt *receipt,
    uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-SPECIALIZED-OUTPUT-TREE-ROSTER-V1\0";
    uint8_t bytes[sizeof(domain) + 2U
        + PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_COUNT_MAX * 1144U];
    size_t offset = 0, index;
    memcpy(bytes + offset, domain, sizeof(domain)); offset += sizeof(domain);
    put16(bytes + offset, receipt->tree_count); offset += 2U;
    for (index = 0; index < receipt->tree_count; ++index) {
        const struct plamen_broker_v2_specialized_output_tree *tree =
            &receipt->trees[index];
        put32(bytes + offset, tree->version); offset += 4U;
        put16(bytes + offset, tree->role); offset += 2U;
        memcpy(bytes + offset, tree->name, sizeof(tree->name));
        offset += sizeof(tree->name);
        memcpy(bytes + offset, tree->relative_path,
            sizeof(tree->relative_path)); offset += sizeof(tree->relative_path);
        memcpy(bytes + offset, tree->tree_sha256, 32); offset += 32U;
        put64(bytes + offset, tree->entry_count); offset += 8U;
        put64(bytes + offset, tree->expanded_bytes); offset += 8U;
    }
    if (plamen_broker_v2_sha256(bytes, offset, output) != 0) {
        memset(bytes, 0, sizeof(bytes)); return -1;
    }
    memset(bytes, 0, sizeof(bytes)); return zero32(output) ? -1 : 0;
}

static int receipt_hmac(
    const struct plamen_broker_v2_specialized_output_receipt *receipt,
    const uint8_t key[32], uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-SPECIALIZED-OUTPUT-RECEIPT-V1\0";
    uint8_t bytes[4U + 2U + 2U + 32U + 32U * 8U + 4U + 4U + 4U];
    size_t offset = 0;
    put32(bytes + offset, receipt->version); offset += 4U;
    put16(bytes + offset, receipt->lane); offset += 2U;
    put16(bytes + offset, receipt->method); offset += 2U;
    memcpy(bytes + offset, receipt->operation, sizeof(receipt->operation));
    offset += sizeof(receipt->operation);
#define COPY(field) do { memcpy(bytes + offset, receipt->field, 32); offset += 32U; } while (0)
    COPY(request_sha256); COPY(effects_binding_sha256);
    COPY(worker_request_sha256); COPY(lifecycle_receipt_sha256);
    put32(bytes + offset, receipt->post_spawn_dynamic_identity_kind); offset += 4U;
    put32(bytes + offset, receipt->post_spawn_dynamic_identity_size); offset += 4U;
    COPY(post_spawn_dynamic_identity_sha256);
    COPY(network_policy_sha256); COPY(observed_egress_sha256);
    bytes[offset++] = receipt->provider_authenticated;
    bytes[offset++] = receipt->network_policy_enforced;
    bytes[offset++] = receipt->population_zero;
    bytes[offset++] = receipt->cleanup_complete;
    COPY(tree_roster_sha256);
#undef COPY
    if (plamen_broker_v2_hmac_sha256(key, domain, sizeof(domain),
            bytes, offset, output) != 0) {
        memset(bytes, 0, sizeof(bytes)); return -1;
    }
    memset(bytes, 0, sizeof(bytes)); return zero32(output) ? -1 : 0;
}

static int receipt_shape(
    const struct plamen_broker_v2_specialized_output_receipt *receipt)
{
    size_t index;
    if (receipt == NULL
        || receipt->version != PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RECEIPT_VERSION
        || receipt->lane == 0U || receipt->method == 0U
        || !safe_fixed_string(receipt->operation, sizeof(receipt->operation))
        || zero32(receipt->request_sha256)
        || zero32(receipt->effects_binding_sha256)
        || zero32(receipt->worker_request_sha256)
        || zero32(receipt->lifecycle_receipt_sha256)
        || receipt->post_spawn_dynamic_identity_kind
            != PLAMEN_BROKER_V2_SPECIALIZED_DYNAMIC_IDENTITY_APPLE_CDHASH
        || (receipt->post_spawn_dynamic_identity_size != 20U
            && receipt->post_spawn_dynamic_identity_size != 32U)
        || zero32(receipt->post_spawn_dynamic_identity_sha256)
        || zero32(receipt->network_policy_sha256)
        || zero32(receipt->observed_egress_sha256)
        || receipt->provider_authenticated != 1U
        || receipt->network_policy_enforced != 1U
        || receipt->population_zero != 1U
        || receipt->cleanup_complete != 1U
        || receipt->tree_count == 0U
        || receipt->tree_count > PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_COUNT_MAX
        || zero32(receipt->tree_roster_sha256)
        || zero32(receipt->receipt_hmac_sha256)) return 0;
    for (index = 0; index < receipt->tree_count; ++index) {
        const struct plamen_broker_v2_specialized_output_tree *tree =
            &receipt->trees[index];
        if (tree->version != PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_CENSUS_VERSION
            || tree->role != PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_ROLE_SCRATCH
            || !safe_fixed_string(tree->name, sizeof(tree->name))
            || !safe_fixed_string(tree->relative_path,
                sizeof(tree->relative_path))
            || zero32(tree->tree_sha256)) return 0;
        if (index > 0U && strcmp(receipt->trees[index - 1U].name,
                tree->name) >= 0) return 0;
    }
    return 1;
}

int
plamen_broker_v2_specialized_output_receipt_build(
    const uint8_t session_key[32],
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const uint8_t lifecycle_receipt_sha256[32],
    uint32_t identity_kind, uint32_t identity_size,
    const uint8_t identity_sha256[32],
    const uint8_t network_policy_sha256[32],
    const uint8_t observed_egress_sha256[32],
    uint8_t provider_authenticated, uint8_t network_policy_enforced,
    uint8_t population_zero, uint8_t cleanup_complete, int scratch_fd,
    const struct plamen_broker_v2_specialized_output_spec *specs,
    size_t spec_count,
    struct plamen_broker_v2_specialized_output_receipt *receipt)
{
    size_t index;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (session_key == NULL || zero32(session_key) || view == NULL
        || binding == NULL || lifecycle_receipt_sha256 == NULL
        || identity_sha256 == NULL || network_policy_sha256 == NULL
        || observed_egress_sha256 == NULL || specs == NULL || receipt == NULL
        || binding->version != PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_CODEC_VERSION
        || view->lane != binding->lane || view->method != binding->method
        || spec_count == 0U
        || spec_count > PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_COUNT_MAX)
        return -1;
    if (zero32(view->request_sha256)
        || zero32(binding->effects_binding_sha256)
        || zero32(binding->worker_request_sha256)
        || zero32(lifecycle_receipt_sha256)
        || zero32(identity_sha256) || zero32(network_policy_sha256)
        || zero32(observed_egress_sha256)
        || !safe_fixed_string(binding->operation, sizeof(binding->operation)))
        return -1;
    receipt->version = PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RECEIPT_VERSION;
    receipt->lane = view->lane; receipt->method = view->method;
    memcpy(receipt->operation, binding->operation,
        strnlen(binding->operation, sizeof(binding->operation)));
    memcpy(receipt->request_sha256, view->request_sha256, 32);
    memcpy(receipt->effects_binding_sha256, binding->effects_binding_sha256, 32);
    memcpy(receipt->worker_request_sha256, binding->worker_request_sha256, 32);
    memcpy(receipt->lifecycle_receipt_sha256, lifecycle_receipt_sha256, 32);
    receipt->post_spawn_dynamic_identity_kind = identity_kind;
    receipt->post_spawn_dynamic_identity_size = identity_size;
    memcpy(receipt->post_spawn_dynamic_identity_sha256, identity_sha256, 32);
    memcpy(receipt->network_policy_sha256, network_policy_sha256, 32);
    memcpy(receipt->observed_egress_sha256, observed_egress_sha256, 32);
    receipt->provider_authenticated = provider_authenticated;
    receipt->network_policy_enforced = network_policy_enforced;
    receipt->population_zero = population_zero;
    receipt->cleanup_complete = cleanup_complete;
    receipt->tree_count = (uint16_t)spec_count;
    if (plamen_broker_v2_specialized_output_recensus(scratch_fd, specs,
            spec_count, receipt->trees) != 0) goto fail;
    for (index = 0; index < spec_count; ++index)
        if (strcmp(receipt->trees[index].name, specs[index].name) != 0
            || strcmp(receipt->trees[index].relative_path,
                specs[index].relative_path) != 0) goto fail;
    if (serialize_tree_roster(receipt, receipt->tree_roster_sha256) != 0
        || receipt_hmac(receipt, session_key,
            receipt->receipt_hmac_sha256) != 0
        || !receipt_shape(receipt)) goto fail;
    return 0;
fail:
    memset(receipt, 0, sizeof(*receipt)); return -1;
}

int
plamen_broker_v2_specialized_output_receipt_validate(
    const struct plamen_broker_v2_specialized_output_receipt *receipt,
    const uint8_t session_key[32],
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const uint8_t lifecycle_receipt_sha256[32],
    const struct plamen_broker_v2_specialized_output_spec *specs,
    size_t spec_count)
{
    uint8_t roster[32], hmac[32]; size_t index; int valid;
    memset(roster, 0, sizeof(roster)); memset(hmac, 0, sizeof(hmac));
    if (!receipt_shape(receipt) || session_key == NULL || zero32(session_key)
        || view == NULL || binding == NULL || lifecycle_receipt_sha256 == NULL
        || specs == NULL || spec_count != receipt->tree_count)
        return -1;
    valid = receipt->lane == view->lane && receipt->method == view->method
        && binding->lane == view->lane && binding->method == view->method
        && strcmp(receipt->operation, binding->operation) == 0
        && equal(receipt->request_sha256, view->request_sha256, 32)
        && equal(receipt->effects_binding_sha256,
            binding->effects_binding_sha256, 32)
        && equal(receipt->worker_request_sha256,
            binding->worker_request_sha256, 32)
        && equal(receipt->lifecycle_receipt_sha256,
            lifecycle_receipt_sha256, 32)
        && serialize_tree_roster(receipt, roster) == 0
        && equal(roster, receipt->tree_roster_sha256, 32)
        && receipt_hmac(receipt, session_key, hmac) == 0
        && equal(hmac, receipt->receipt_hmac_sha256, 32);
    for (index = 0; valid && index < spec_count; ++index)
        valid = specs[index].version
                == PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_CENSUS_VERSION
            && specs[index].role
                == PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_ROLE_SCRATCH
            && strcmp(specs[index].name, receipt->trees[index].name) == 0
            && strcmp(specs[index].relative_path,
                receipt->trees[index].relative_path) == 0
            && receipt->trees[index].entry_count <= specs[index].max_entries
            && receipt->trees[index].expanded_bytes
                <= specs[index].max_expanded_bytes;
    memset(roster, 0, sizeof(roster)); memset(hmac, 0, sizeof(hmac));
    return valid ? 0 : -1;
}
