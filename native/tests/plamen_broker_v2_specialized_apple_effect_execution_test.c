#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_specialized_apple_effect_execution.h"
#include "plamen_broker_v2.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int run_count;
static int force_run_failure;
static int invalid_result_mode;

enum {
    INVALID_NONE = 0,
    INVALID_LIFECYCLE_DIGEST = 1,
    INVALID_CDHASH = 2,
    INVALID_PROCESS = 3,
    INVALID_REQUEST_LINK = 4,
    INVALID_POPULATION = 5,
    INVALID_CLEANUP = 6,
    INVALID_MOUNT_ROSTER = 7
};

static int nonzero32(const uint8_t value[32])
{
    uint8_t aggregate = 0U; size_t index;
    for (index = 0; index < 32U; ++index) aggregate |= value[index];
    return aggregate != 0U;
}

int plamen_broker_v2_apple_lifecycle_create_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt)
{
    return receipt != NULL && receipt->version == 1U
        && nonzero32(receipt->receipt_sha256)
        && nonzero32(receipt->mount_roster_sha256) ? 0 : -1;
}

int plamen_broker_v2_apple_lifecycle_start_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    return receipt != NULL && receipt->version ==
        PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
        && nonzero32(receipt->receipt_sha256) ? 0 : -1;
}

int plamen_broker_v2_apple_lifecycle_start_receipt_dynamic_identity_validate(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    return plamen_broker_v2_apple_lifecycle_start_receipt_validate(receipt) == 0
        && receipt->post_spawn_dynamic_identity_kind
            == PLAMEN_BROKER_V2_APPLE_DYNAMIC_IDENTITY_APPLE_CODEDIRECTORY_CDHASH
        && (receipt->post_spawn_dynamic_identity_size == 20U
            || receipt->post_spawn_dynamic_identity_size == 32U)
        && nonzero32(receipt->post_spawn_dynamic_identity_sha256) ? 0 : -1;
}

int plamen_broker_v2_apple_lifecycle_terminal_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    return receipt != NULL && receipt->version ==
        PLAMEN_BROKER_V2_APPLE_LIFECYCLE_TERMINAL_RECEIPT_VERSION
        && nonzero32(receipt->receipt_sha256) ? 0 : -1;
}

int plamen_broker_v2_apple_lifecycle_delete_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_delete_receipt *receipt)
{
    return receipt != NULL && receipt->version == 1U
        && nonzero32(receipt->receipt_sha256) ? 0 : -1;
}

int
plamen_broker_v2_specialized_runtime_handoff_authority_sha256(
    const struct plamen_broker_v2_specialized_runtime_handoff *handoff,
    uint8_t output[32])
{
    if (handoff == NULL || output == NULL) return -1;
    memset(output, 0x33, 32); return 0;
}

int
plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
    struct plamen_broker_v2_specialized_runtime_handoff *handoff,
    uint16_t lane, const char *member,
    struct plamen_broker_v2_specialized_apple_runtime *runtime)
{
    if (handoff == NULL || lane != PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        || member == NULL || strcmp(member, "managed_python") != 0
        || runtime == NULL)
        return -1;
    memset(runtime, 0, sizeof(*runtime)); runtime->version = 1U;
    memset(runtime->oci_image_sha256, 0x10, 32);
    memset(runtime->runtime_manifest_sha256, 0x11, 32);
    memset(runtime->worker_runtime_sha256, 0x12, 32);
    runtime->worker_runtime_size = 100U;
    memset(runtime->tool_image_member_sha256, 0x13, 32);
    runtime->tool_image_member_size = 200U;
    memset(runtime->js_offline_materializer_sha256, 0x14, 32);
    runtime->js_offline_materializer_size = 300U;
    return 0;
}

int
plamen_broker_v2_specialized_worker_launch_derive_apple(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_apple_runtime *runtime,
    struct plamen_broker_v2_specialized_derived_launch *derived)
{
    static const char *const nested[] = {"@fd:tool", "fixture"};
    if (view == NULL || runtime == NULL || derived == NULL) return -1;
    memset(derived, 0, sizeof(*derived)); derived->launch.version = 1U;
    derived->launch.provider_mode = PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER;
    derived->launch.request_id = "fixture-request";
    memcpy(derived->launch.worker_runtime_sha256,
        runtime->worker_runtime_sha256, 32);
    derived->launch.worker_runtime_size = runtime->worker_runtime_size;
    derived->launch.tool_anchor_id = "js-python";
    derived->launch.argv = nested; derived->launch.argc = 2U;
    derived->launch.cwd_role = PLAMEN_BROKER_V2_WORKER_SCRATCH;
    derived->launch.cwd_relative = ".";
    derived->launch.limits.duration_ms = 1000U;
    derived->launch.limits.memory_bytes = 1024U * 1024U;
    derived->launch.limits.open_fds = 32U;
    derived->launch.limits.output_bytes = 1024U;
    derived->launch.limits.output_files = 10U;
    derived->launch.limits.stderr_bytes = 1024U;
    derived->launch.limits.stdout_bytes = 1024U;
    return 0;
}

int
plamen_broker_v2_specialized_worker_request_build(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_fd *fds, size_t fd_count,
    const struct plamen_broker_v2_specialized_worker_launch *launch,
    uint8_t *output, size_t capacity, size_t *output_size,
    struct plamen_broker_v2_specialized_worker_request_binding *binding)
{
    static const uint8_t body[] = "{\"fixture\":true}";
    if (view == NULL || fds == NULL || fd_count != 5U || launch == NULL
        || output == NULL || capacity < sizeof(body) - 1U
        || output_size == NULL || binding == NULL)
        return -1;
    memcpy(output, body, sizeof(body) - 1U); *output_size = sizeof(body) - 1U;
    memset(binding, 0, sizeof(*binding)); binding->version = 1U;
    binding->provider_mode = PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER;
    binding->lane = view->lane; binding->method = view->method;
    memcpy(binding->operation, "OFFLINE_REPLAY",
        strlen("OFFLINE_REPLAY") + 1U);
    memcpy(binding->request_id, "fixture-request",
        strlen("fixture-request") + 1U);
    memset(binding->effects_binding_sha256, 0x21, 32);
    memset(binding->runtime_closure_sha256, 0x22, 32);
    memset(binding->worker_request_sha256, 0x23, 32);
    if (plamen_broker_v2_sha256(view->payload, view->payload_size,
            binding->method_payload_sha256) != 0)
        return -1;
    binding->limits = launch->limits; return 0;
}

int
plamen_broker_v2_specialized_worker_terminal_parse(const uint8_t *raw,
    size_t raw_size,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const struct plamen_broker_v2_specialized_worker_terminal_auth *auth,
    struct plamen_broker_v2_specialized_worker_terminal_observation *observed)
{
    if (raw == NULL || raw_size == 0U || binding == NULL || auth == NULL
        || observed == NULL || plamen_broker_v2_sha256(raw, raw_size,
            observed->terminal_sha256) != 0
        || plamen_broker_v2_sha256("[]", 2U,
            observed->observed_egress_sha256) != 0)
        return -1;
    observed->version = 1U;
    memcpy(observed->status, "COMPLETE", sizeof("COMPLETE"));
    observed->returncode = 0; return 0;
}

#ifndef PLAMEN_TEST_REAL_METHOD_CODEC
int plamen_broker_v2_specialized_method_output_specs(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    struct plamen_broker_v2_specialized_output_spec *specs, size_t *count)
{
    if (view == NULL || binding == NULL || specs == NULL || count == NULL
        || strcmp(binding->operation, "PREPARE_TOOLCHAIN") != 0) return -1;
    memset(specs, 0, sizeof(*specs)); specs[0].version = 1U;
    specs[0].role = PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_ROLE_SCRATCH;
    memcpy(specs[0].name, "toolchain", sizeof("toolchain"));
    memcpy(specs[0].relative_path, "toolchain", sizeof("toolchain"));
    specs[0].max_entries = 8U; specs[0].max_expanded_bytes = 4096U;
    *count = 1U; return 0;
}

int plamen_broker_v2_specialized_js_replay_terminal_binding(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32])
{
    (void)view;
    if (terminal != NULL) *terminal = NULL;
    if (terminal_size != NULL) *terminal_size = 0U;
    if (terminal_sha256 != NULL) memset(terminal_sha256, 0, 32U);
    return -1;
}
#endif

static void lifecycle_digest(
    const struct plamen_broker_v2_specialized_worker_result *result,
    uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-SPECIALIZED-WORKER-LIFECYCLE-V1\0";
    uint8_t bytes[sizeof(domain) + 128U]; size_t offset = 0U;
    memcpy(bytes + offset, domain, sizeof(domain)); offset += sizeof(domain);
    memcpy(bytes + offset, result->created.receipt_sha256, 32); offset += 32U;
    memcpy(bytes + offset, result->started.receipt_sha256, 32); offset += 32U;
    memcpy(bytes + offset, result->exited.receipt_sha256, 32); offset += 32U;
    memcpy(bytes + offset, result->deleted.receipt_sha256, 32); offset += 32U;
    assert(plamen_broker_v2_sha256(bytes, offset, output) == 0);
}

static int run_worker(void *context,
    const struct plamen_broker_v2_specialized_worker_request *request,
    struct plamen_broker_v2_specialized_worker_result *result)
{
    static const uint8_t terminal[] = "{\"guest\":true}";
    static const uint8_t domain[] =
        "PLAMEN-SPECIALIZED-WORKER-TERMINAL-V1\0";
    (void)context; ++run_count;
    if (force_run_failure) return -1;
    memset(result, 0, sizeof(*result)); result->version = 1U;
    result->guest_terminal = malloc(sizeof(terminal) - 1U);
    if (result->guest_terminal == NULL) return -1;
    memcpy(result->guest_terminal, terminal, sizeof(terminal) - 1U);
    result->guest_terminal_size = sizeof(terminal) - 1U;
    if (plamen_broker_v2_sha256(terminal, sizeof(terminal) - 1U,
            result->guest_terminal_sha256) != 0
        || plamen_broker_v2_hmac_sha256(request->terminal_hmac_key, domain,
            sizeof(domain), terminal, sizeof(terminal) - 1U,
            result->guest_terminal_hmac_sha256) != 0)
        return -1;
    result->created.version = 1U; result->started.version =
        PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION;
    result->exited.version =
        PLAMEN_BROKER_V2_APPLE_LIFECYCLE_TERMINAL_RECEIPT_VERSION;
    result->deleted.version = 1U;
    memcpy(result->created.container_id, "fixture", sizeof("fixture"));
    memcpy(result->started.container_id, "fixture", sizeof("fixture"));
    memcpy(result->exited.container_id, "fixture", sizeof("fixture"));
    memcpy(result->deleted.container_id, "fixture", sizeof("fixture"));
#define FILL_LINK(field, byte) do { \
    memset(result->created.field, byte, 32); \
    memset(result->started.field, byte, 32); \
    memset(result->exited.field, byte, 32); \
    memset(result->deleted.field, byte, 32); \
} while (0)
    FILL_LINK(request_fingerprint_sha256, 0x51);
    FILL_LINK(spec_sha256, 0x52);
#undef FILL_LINK
    memset(result->started.launch_request_sha256, 0x53, 32);
    memcpy(result->exited.launch_request_sha256,
        result->started.launch_request_sha256, 32);
    memset(result->started.start_operation_nonce, 0x54, 32);
    memcpy(result->exited.start_operation_nonce,
        result->started.start_operation_nonce, 32);
    memset(result->started.native_process_handle_sha256, 0x55, 32);
    memcpy(result->exited.native_process_handle_sha256,
        result->started.native_process_handle_sha256, 32);
    result->started.native_process_id = 8001;
    result->exited.native_process_id = result->started.native_process_id;
    memset(result->exited.cleanup_sha256, 0x56, 32);
    memcpy(result->deleted.cleanup_sha256, result->exited.cleanup_sha256, 32);
    memset(result->created.receipt_sha256, 0x61, 32);
    memset(result->created.mount_roster_sha256, 0x60, 32);
    memset(result->started.receipt_sha256, 0x62, 32);
    memset(result->exited.receipt_sha256, 0x63, 32);
    memset(result->deleted.receipt_sha256, 0x64, 32);
    memcpy(result->deleted.terminal_receipt_sha256,
        result->exited.receipt_sha256, 32);
    result->started.post_spawn_dynamic_identity_kind =
        PLAMEN_BROKER_V2_APPLE_DYNAMIC_IDENTITY_APPLE_CODEDIRECTORY_CDHASH;
    result->started.post_spawn_dynamic_identity_size = 20U;
    memset(result->started.post_spawn_dynamic_identity_sha256, 0x65, 32);
    result->created.rootfs_readonly = 1U; result->created.use_init = 1U;
    result->created.dns_disabled = 1U;
    result->exited.exit_code = 0; result->exited.descendants_extinct = 1U;
    result->exited.guest_process_extinct = 1U;
    result->exited.backend_egress_revoked = 1U;
    memset(result->exited.stop_argv_sha256, 0x66, 32);
    memset(result->exited.stop_stdout_sha256, 0x67, 32);
    memset(result->exited.stop_stderr_sha256, 0x68, 32);
    memset(result->exited.stopped_observation_sha256, 0x69, 32);
    memset(result->exited.guest_population_extinction_sha256, 0x6a, 32);
    result->exited.stop_control_process_reaped = 1U;
    result->exited.stop_control_process_group_extinct = 1U;
    result->exited.guest_population_zero = 1U;
    result->exited.container_vm_stopped = 1U;
    result->exited.terminal_durable = 1U; result->exited.deleted = 0U;
    result->deleted.descendants_extinct = 1U;
    result->deleted.guest_process_extinct = 1U;
    result->deleted.backend_egress_revoked = 1U; result->deleted.absent = 1U;
    lifecycle_digest(result, result->lifecycle_receipt_sha256);
    result->network_denied = 1U; result->population_zero = 1U;
    result->cleanup_complete = 1U;
    if (invalid_result_mode == INVALID_LIFECYCLE_DIGEST)
        result->lifecycle_receipt_sha256[0] ^= 1U;
    else if (invalid_result_mode == INVALID_CDHASH)
        memset(result->started.post_spawn_dynamic_identity_sha256, 0, 32);
    else if (invalid_result_mode == INVALID_PROCESS)
        result->exited.native_process_id += 1;
    else if (invalid_result_mode == INVALID_REQUEST_LINK)
        result->deleted.request_fingerprint_sha256[0] ^= 1U;
    else if (invalid_result_mode == INVALID_POPULATION)
        result->population_zero = 0U;
    else if (invalid_result_mode == INVALID_CLEANUP)
        result->cleanup_complete = 0U;
    else if (invalid_result_mode == INVALID_MOUNT_ROSTER)
        memset(result->created.mount_roster_sha256, 0, 32);
    return 0;
}

static void dispose_result(
    struct plamen_broker_v2_specialized_worker_result *result)
{
    if (result != NULL && result->guest_terminal != NULL) {
        memset(result->guest_terminal, 0, result->guest_terminal_size);
        free(result->guest_terminal); result->guest_terminal = NULL;
    }
}

static int render_terminal(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *observed,
    const struct plamen_broker_v2_specialized_output_receipt *receipt,
    const uint8_t session_key[32], const uint8_t lifecycle[32],
    uint8_t **terminal, size_t *terminal_size)
{
    static const char fixed[] =
        "1111111111111111111111111111111111111111111111111111111111111111";
    struct plamen_broker_v2_specialized_output_spec specs[2]; size_t count = 0U;
    char network[65], egress[65], body[8192];
    static const char digits[] = "0123456789abcdef";
    size_t index;
    int amount;
    if (terminal == NULL || terminal_size == NULL
        || plamen_broker_v2_specialized_method_output_specs(view, binding,
            specs, &count) != 0
        || plamen_broker_v2_specialized_output_receipt_validate(receipt,
            session_key, view, binding, lifecycle, specs, count) != 0) return -1;
    for (index = 0U; index < 32U; ++index) {
        network[index * 2U] = digits[receipt->network_policy_sha256[index] >> 4U];
        network[index * 2U + 1U] = digits[receipt->network_policy_sha256[index] & 15U];
        egress[index * 2U] = digits[receipt->observed_egress_sha256[index] >> 4U];
        egress[index * 2U + 1U] = digits[receipt->observed_egress_sha256[index] & 15U];
    }
    network[64] = '\0'; egress[64] = '\0';
    amount = snprintf(body, sizeof(body),
        "{\"bounds_enforced\":true,\"cleanup_complete\":true,"
        "\"contract_sha256\":\"%s\",\"dependency_expectation_sha256\":\"%s\","
        "\"duration_ms\":1,\"exclusive_operation_key_lease\":true,"
        "\"exhaustive_descendant_termination\":true,\"exit_code\":0,"
        "\"generation_id\":\"generation-1\",\"guest_execution_binding_sha256\":\"%s\","
        "\"launch_object_kind\":\"PRIVATE_IMMUTABLE_PROJECTED_CLOSURE\","
        "\"native_custody_receipt_sha256\":\"%s\","
        "\"native_deployment_receipt_sha256\":\"%s\","
        "\"native_module_sha256\":\"%s\",\"native_provider_authenticated\":true,"
        "\"network_authority_sha256\":\"%s\",\"network_mode\":\"NO_NETWORK\","
        "\"network_policy_sha256\":\"%s\",\"network_violation\":false,"
        "\"observed_egress_origins\":[],\"observed_egress_sha256\":\"%s\","
        "\"operation\":\"OFFLINE_REPLAY\",\"output_trees\":{},"
        "\"population_zero\":true,\"post_spawn_dynamic_identity_kind\":"
        "\"APPLE_CODEDIRECTORY_CDHASH\","
        "\"post_spawn_dynamic_identity_sha256\":\"%s\","
        "\"projected_closure_manifest_sha256\":\"%s\","
        "\"request_sha256\":\"%s\",\"schema\":"
        "\"plamen.js-dependency-native-terminal.v2\","
        "\"scratch_writes_only\":true,\"session_admission_sha256\":\"%s\","
        "\"source_read_only\":true,\"stderr_bytes\":0,\"stderr_sha256\":\"%s\","
        "\"stdout_bytes\":0,\"stdout_sha256\":\"%s\","
        "\"terminal_receipt_sha256\":\"%s\",\"timed_out\":false,"
        "\"toolchain_identity_sha256\":\"%s\"}\n",
        fixed, fixed, fixed, fixed, fixed, fixed, fixed, network, egress,
        fixed, fixed, fixed, fixed, fixed, fixed, fixed, fixed);
    if (amount <= 0 || (size_t)amount >= sizeof(body)) return -1;
    *terminal = malloc((size_t)amount);
    if (*terminal == NULL) return -1;
    memcpy(*terminal, body, (size_t)amount);
    *terminal_size = (size_t)amount;
    (void)observed;
    return 0;
}

struct plamen_test_effect_adapter {
    struct plamen_broker_v2_specialized_effect_store *store;
    struct plamen_broker_v2_specialized_runtime_handoff *handoff;
    uint8_t session_key[32];
    unsigned execute_calls;
    unsigned replay_calls;
    int last_status;
};

int
plamen_test_effect_adapter_open(int store_fd, const uint8_t session_key[32],
    const uint8_t runtime_authority_sha256[32],
    struct plamen_test_effect_adapter **out)
{
    struct plamen_test_effect_adapter *adapter = NULL;
    if (out != NULL) *out = NULL;
    if (store_fd < 0 || session_key == NULL || runtime_authority_sha256 == NULL
        || out == NULL || (adapter = calloc(1U, sizeof(*adapter))) == NULL
        || plamen_broker_v2_specialized_effect_store_open(store_fd,
            session_key, runtime_authority_sha256, &adapter->store) != 0) {
        free(adapter);
        return -1;
    }
    memcpy(adapter->session_key, session_key, 32U);
    adapter->handoff =
        (struct plamen_broker_v2_specialized_runtime_handoff *)(uintptr_t)1U;
    *out = adapter;
    return 0;
}

void
plamen_test_effect_adapter_close(struct plamen_test_effect_adapter *adapter)
{
    if (adapter == NULL) return;
    plamen_broker_v2_specialized_effect_store_close(adapter->store);
    memset(adapter, 0, sizeof(*adapter));
    free(adapter);
}

unsigned
plamen_test_effect_adapter_execute_calls(
    const struct plamen_test_effect_adapter *adapter)
{
    return adapter == NULL ? 0U : adapter->execute_calls;
}

unsigned
plamen_test_effect_adapter_replay_calls(
    const struct plamen_test_effect_adapter *adapter)
{
    return adapter == NULL ? 0U : adapter->replay_calls;
}

int
plamen_test_effect_adapter_worker_calls(void)
{
    return run_count;
}

int
plamen_test_effect_adapter_execute(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    struct plamen_test_effect_adapter *adapter = opaque;
    struct plamen_broker_v2_specialized_apple_effect_execution execution;
    if (adapter == NULL || view == NULL || evidence == NULL) return -1;
    ++adapter->execute_calls;
    memset(&execution, 0, sizeof(execution));
    execution.version =
        PLAMEN_BROKER_V2_SPECIALIZED_APPLE_EFFECT_EXECUTION_VERSION;
    execution.store = adapter->store;
    execution.runtime_handoff = adapter->handoff;
    execution.view = view;
    execution.session_key = adapter->session_key;
    execution.native_effects_context = adapter;
    execution.run = run_worker;
    execution.dispose_result = dispose_result;
    execution.render_terminal = render_terminal;
    adapter->last_status =
        plamen_broker_v2_specialized_apple_effect_execute_deny_all(
            &execution, evidence);
    return adapter->last_status;
}

int
plamen_test_effect_adapter_last_status(
    const struct plamen_test_effect_adapter *adapter)
{
    return adapter == NULL ? -999 : adapter->last_status;
}

int
plamen_test_effect_adapter_seed_projection(
    struct plamen_test_effect_adapter *adapter, uint8_t terminal_sha256[32])
{
    static const uint8_t terminal[] =
        "{\"schema\":\"plamen.private-analysis-projection-custody.v1\"}";
    static const uint8_t terminal_domain[] =
        "PLAMEN-SPECIALIZED-METHOD-TERMINAL-V1\0";
    struct plamen_broker_v2_specialized_effect_completion completion;
    uint8_t operation_key[32], request_sha256[32], terminal_key[32];
    int created = 0, result = -1;
    memset(&completion, 0, sizeof(completion));
    memset(operation_key, 0x81, sizeof(operation_key));
    memset(request_sha256, 0x82, sizeof(request_sha256));
    memset(terminal_key, 0, sizeof(terminal_key));
    if (adapter == NULL || terminal_sha256 == NULL
        || plamen_broker_v2_specialized_effect_store_prepare(adapter->store,
            PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION,
            PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT,
            operation_key, request_sha256, terminal_key, &created) != 0
        || created != 1)
        goto done;
    completion.version = PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_VERSION;
    completion.lane = PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION;
    completion.method = PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT;
    memcpy(completion.operation_key, operation_key, 32U);
    memcpy(completion.request_sha256, request_sha256, 32U);
    memset(completion.runtime_authority_sha256, 0x33, 32U);
    memset(completion.worker_request_sha256, 0x83, 32U);
    memset(completion.lifecycle_receipt_sha256, 0x84, 32U);
    memset(completion.network_policy_sha256, 0x85, 32U);
    memset(completion.observed_egress_sha256, 0x86, 32U);
    if (plamen_broker_v2_sha256(terminal, sizeof(terminal) - 1U,
            completion.terminal_sha256) != 0
        || plamen_broker_v2_hmac_sha256(terminal_key, terminal_domain,
            sizeof(terminal_domain), terminal, sizeof(terminal) - 1U,
            completion.terminal_hmac_sha256) != 0)
        goto done;
    completion.provider_authenticated = 1U;
    completion.network_policy_enforced = 1U;
    completion.population_zero = 1U;
    completion.cleanup_complete = 1U;
    if (plamen_broker_v2_specialized_effect_store_commit(adapter->store,
            &completion, terminal, sizeof(terminal) - 1U) != 0)
        goto done;
    memcpy(terminal_sha256, completion.terminal_sha256, 32U);
    result = 0;
done:
    memset(&completion, 0, sizeof(completion));
    memset(operation_key, 0, sizeof(operation_key));
    memset(request_sha256, 0, sizeof(request_sha256));
    memset(terminal_key, 0, sizeof(terminal_key));
    if (result != 0 && terminal_sha256 != NULL)
        memset(terminal_sha256, 0, 32U);
    return result;
}

int
plamen_test_effect_adapter_recover_projection(
    struct plamen_test_effect_adapter *adapter,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_specialized_effect_completion *completion,
    uint8_t **terminal, size_t *terminal_size)
{
    if (adapter == NULL) return -1;
    return plamen_broker_v2_specialized_apple_effect_recover_projection(
        adapter->store, view, completion, terminal, terminal_size);
}

int
plamen_test_effect_adapter_replay(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    struct plamen_test_effect_adapter *adapter = opaque;
    struct plamen_broker_v2_specialized_effect_completion completion;
    uint8_t *terminal = NULL;
    size_t terminal_size = 0U;
    if (adapter == NULL || view == NULL || evidence == NULL) return -1;
    ++adapter->replay_calls;
    adapter->last_status = -20;
    memset(&completion, 0, sizeof(completion));
    if (plamen_broker_v2_specialized_apple_effect_replay_js(adapter->store,
            view, &completion, &terminal, &terminal_size) != 0)
        return adapter->last_status;
    memcpy(evidence->effect_receipt_sha256,
        completion.terminal_hmac_sha256, 32U);
    memcpy(evidence->lifecycle_receipt_sha256,
        completion.lifecycle_receipt_sha256, 32U);
    memcpy(evidence->durable_operation_sha256,
        completion.operation_key, 32U);
    memcpy(evidence->network_policy_sha256,
        completion.network_policy_sha256, 32U);
    memcpy(evidence->observed_egress_sha256,
        completion.observed_egress_sha256, 32U);
    evidence->effect_authenticated = 1U;
    evidence->effect_completed = 1U;
    evidence->durable_operation = 1U;
    evidence->provider_authenticated = 1U;
    evidence->network_policy_enforced = 1U;
    evidence->population_zero = 1U;
    evidence->cleanup_complete = 1U;
    evidence->terminal = terminal;
    evidence->terminal_size = terminal_size;
    adapter->last_status = 0;
    return 0;
}

void
plamen_test_effect_adapter_dispose(void *opaque,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    (void)opaque;
    if (evidence != NULL && evidence->terminal != NULL) {
        memset((void *)evidence->terminal, 0, evidence->terminal_size);
        free((void *)evidence->terminal);
        evidence->terminal = NULL;
        evidence->terminal_size = 0U;
    }
}

static int open_role(int parent, const char *name)
{
    if (mkdirat(parent, name, 0700) != 0) return -1;
    return openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

int main(void)
{
    char template[] = "/tmp/plamen-specialized-apple-effect.XXXXXX";
    char *path = mkdtemp(template); uint8_t session[32], authority[32];
    uint8_t payload_sha[32]; int parent = -1, store_fd = -1, index, result = 1;
    struct plamen_broker_v2_specialized_effect_store *store = NULL;
    struct plamen_broker_v2_tool_effect_plan_view view;
    struct plamen_broker_v2_fd_metadata descriptors[4];
    int fds[4];
    struct plamen_broker_v2_specialized_apple_effect_execution execution;
    struct plamen_broker_v2_tool_effect_evidence evidence;
    static const uint16_t purposes[4] = {
        PLAMEN_BROKER_V2_FD_JS_SOURCE, PLAMEN_BROKER_V2_FD_JS_SCRATCH,
        PLAMEN_BROKER_V2_FD_JS_STATE, PLAMEN_BROKER_V2_FD_JS_ARCHIVE_ROOT
    };
    static const uint8_t access[4] = {
        PLAMEN_BROKER_V2_FD_READ, PLAMEN_BROKER_V2_FD_READ_WRITE,
        PLAMEN_BROKER_V2_FD_READ_WRITE, PLAMEN_BROKER_V2_FD_READ
    };
    memset(session, 0x41, 32); memset(authority, 0x33, 32);
    memset(payload_sha, 0x51, 32); memset(&view, 0, sizeof(view));
    memset(descriptors, 0, sizeof(descriptors)); memset(fds, -1, sizeof(fds));
    memset(&execution, 0, sizeof(execution));
    memset(&evidence, 0, sizeof(evidence));
    if (path == NULL || (parent = open(path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0
        || mkdirat(parent, "store", 0700) != 0
        || (store_fd = openat(parent, "store",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || plamen_broker_v2_specialized_effect_store_open(store_fd, session,
            authority, &store) != 0)
        goto done;
    view.version = PLAMEN_BROKER_V2_TOOL_EFFECT_PLAN_VERSION;
    view.lane = PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER;
    view.method = PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE;
    memset(view.authority_binding_sha256, 0x61, 32);
    memset(view.operation_nonce, 0x62, 32);
    memset(view.request_sha256, 0x63, 32);
    memset(view.effects_context_sha256, 0x64, 32);
    for (index = 0; index < 4; ++index) {
        char name[16]; int amount = snprintf(name, sizeof(name), "role-%d", index);
        if (amount <= 0 || (size_t)amount >= sizeof(name)
            || (fds[index] = open_role(parent, name)) < 0
            || plamen_broker_v2_fd_identity(fds[index],
                descriptors[index].identity) != 0)
            goto done;
        descriptors[index].purpose = purposes[index];
        descriptors[index].target = (uint16_t)(index + 1U);
        descriptors[index].access_mode = access[index];
    }
    if (mkdirat(fds[1], "toolchain", 0700) != 0) goto done;
    view.descriptors = descriptors; view.fds = fds; view.fd_count = 4U;
    execution.version = 1U; execution.store = store;
    execution.runtime_handoff =
        (struct plamen_broker_v2_specialized_runtime_handoff *)(uintptr_t)1U;
    execution.view = &view; execution.session_key = session;
    execution.run = run_worker;
    execution.dispose_result = dispose_result;
    execution.render_terminal = render_terminal;
    if (plamen_broker_v2_specialized_apple_effect_execute_deny_all(
            &execution, &evidence) != 0 || run_count != 1
        || evidence.terminal == NULL)
        goto done;
    memset((void *)evidence.terminal, 0, evidence.terminal_size);
    free((void *)evidence.terminal); memset(&evidence, 0, sizeof(evidence));
    if (plamen_broker_v2_specialized_apple_effect_execute_deny_all(
            &execution, &evidence) != 0 || run_count != 1
        || evidence.terminal == NULL)
        goto done;
    memset((void *)evidence.terminal, 0, evidence.terminal_size);
    free((void *)evidence.terminal); memset(&evidence, 0, sizeof(evidence));
    view.operation_nonce[0] = 0x6fU; view.request_sha256[0] = 0x7fU;
    descriptors[0].access_mode = PLAMEN_BROKER_V2_FD_READ_WRITE;
    if (plamen_broker_v2_specialized_apple_effect_execute_deny_all(
            &execution, &evidence) == 0 || run_count != 1)
        goto done;
    descriptors[0].access_mode = PLAMEN_BROKER_V2_FD_READ;
    for (invalid_result_mode = INVALID_LIFECYCLE_DIGEST;
            invalid_result_mode <= INVALID_CLEANUP; ++invalid_result_mode) {
        int before = run_count;
        view.operation_nonce[0] = (uint8_t)(0x70 + invalid_result_mode);
        view.request_sha256[0] = (uint8_t)(0x80 + invalid_result_mode);
        if (plamen_broker_v2_specialized_apple_effect_execute_deny_all(
                &execution, &evidence) == 0 || run_count != before + 1
            || evidence.terminal != NULL)
            goto done;
        if (invalid_result_mode == INVALID_LIFECYCLE_DIGEST
            && (plamen_broker_v2_specialized_apple_effect_execute_deny_all(
                    &execution, &evidence) == 0
                || run_count != before + 1 || evidence.terminal != NULL))
            goto done;
    }
    invalid_result_mode = INVALID_NONE;
    result = 0;
done:
    if (result != 0)
        fprintf(stderr, "failure run_count=%d invalid_mode=%d terminal=%p\n",
            run_count, invalid_result_mode, (const void *)evidence.terminal);
    if (evidence.terminal != NULL) {
        memset((void *)evidence.terminal, 0, evidence.terminal_size);
        free((void *)evidence.terminal);
    }
    for (index = 0; index < 4; ++index)
        if (fds[index] >= 0) close(fds[index]);
    plamen_broker_v2_specialized_effect_store_close(store);
    if (store_fd >= 0) close(store_fd);
    if (parent >= 0) close(parent);
    if (result == 0) puts("specialized apple effect execution: ok");
    return result;
}
