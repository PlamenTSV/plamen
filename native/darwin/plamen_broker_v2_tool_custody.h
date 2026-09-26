#ifndef PLAMEN_BROKER_V2_TOOL_CUSTODY_H
#define PLAMEN_BROKER_V2_TOOL_CUSTODY_H

#include "plamen_broker_v2_apple_container_lifecycle.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_TOOL_CUSTODY_VERSION 1U
#define PLAMEN_BROKER_V2_TOOL_ID_MAX 32U
#define PLAMEN_BROKER_V2_TOOL_RUN_ID_MAX 128U
#define PLAMEN_BROKER_V2_TOOL_GUEST_TERMINAL_SIZE 1024U
#define PLAMEN_BROKER_V2_TOOL_JSON_MAX 8192U
#define PLAMEN_BROKER_V2_TOOL_EFFECT_PLAN_VERSION 1U
#define PLAMEN_BROKER_V2_TOOL_EFFECT_EVIDENCE_VERSION 1U
#define PLAMEN_BROKER_V2_TOOL_EFFECT_EXACT_EXECUTOR_VERSION 1U

struct plamen_broker_v2_tool_effect_plan;

/*
 * C-only two-stage specialized-effect boundary.  The service has already
 * authenticated the peer/session and decoded the protocol request, but tool
 * custody repeats the exact wire digest and FD-identity checks before it
 * retains anything.  effects_context_sha256 is derived by the native effects
 * owner from the active interpreter registration, installed generation and
 * provider/custody admission; it is never supplied by Python.
 */
struct plamen_broker_v2_tool_effect_plan_input {
    uint32_t version;
    const struct plamen_broker_v2_specialized_request *request;
    const uint8_t *request_wire;
    size_t request_wire_size;
    uint8_t request_sha256[32];
    uint8_t effects_context_sha256[32];
    const int *fds;
    size_t fd_count;
};

struct plamen_broker_v2_tool_effect_plan_view {
    uint32_t version;
    uint16_t lane;
    uint16_t method;
    uint16_t flags;
    uint8_t authority_binding_sha256[32];
    uint8_t operation_nonce[32];
    uint8_t request_sha256[32];
    uint8_t effects_context_sha256[32];
    uint8_t archive_root_identity_sha256[32];
    uint8_t archive_manifest_sha256[32];
    uint8_t archive_census_sha256[32];
    const uint8_t *payload;
    size_t payload_size;
    const struct plamen_broker_v2_fd_metadata *descriptors;
    const int *fds;
    size_t fd_count;
};

/*
 * Evidence is accepted only from the native effects owner after the plan's
 * operation has actually completed.  Identity/read-only methods do not claim
 * provider lifecycle facts.  Mutation/execute methods additionally require
 * the method-specific booleans enforced by finalize below.  terminal is the
 * exact canonical no-LF method payload returned on the specialized wire.
 */
struct plamen_broker_v2_tool_effect_evidence {
    uint32_t version;
    uint16_t lane;
    uint16_t method;
    uint8_t authority_binding_sha256[32];
    uint8_t operation_nonce[32];
    uint8_t request_sha256[32];
    uint8_t effects_context_sha256[32];
    uint8_t effect_receipt_sha256[32];
    uint8_t lifecycle_receipt_sha256[32];
    uint8_t durable_operation_sha256[32];
    uint8_t network_policy_sha256[32];
    uint8_t observed_egress_sha256[32];
    uint8_t effect_authenticated;
    uint8_t effect_completed;
    uint8_t durable_operation;
    uint8_t provider_authenticated;
    uint8_t network_policy_enforced;
    uint8_t population_zero;
    uint8_t cleanup_complete;
    const uint8_t *terminal;
    size_t terminal_size;
};

typedef int (*plamen_broker_v2_tool_effect_execute_fn)(void *,
    const struct plamen_broker_v2_tool_effect_plan_view *,
    struct plamen_broker_v2_tool_effect_evidence *);
typedef void (*plamen_broker_v2_tool_effect_dispose_fn)(void *,
    struct plamen_broker_v2_tool_effect_evidence *);

/*
 * The only production bridge between custody and concrete native effects.
 * execute must be a native provider-effects callback over its authenticated
 * context.  It performs the real operation and fills observed evidence;
 * dispose releases callback-owned evidence after custody has copied or
 * rejected it.  Neither callback is exported through the CPython module.
 */
struct plamen_broker_v2_tool_effect_executor {
    uint32_t version;
    void *context;
    plamen_broker_v2_tool_effect_execute_fn execute;
    plamen_broker_v2_tool_effect_dispose_fn dispose;
};

/*
 * Append-only, method-exact executor table.  Production provider effects use
 * this boundary so an authenticated JS operation can never be accidentally
 * dispatched to (for example) a projection or snapshot callback.  The
 * generic executor above remains ABI-compatible for existing native tests;
 * this table is the production-strength contract for new integrations.
 */
struct plamen_broker_v2_tool_effect_exact_executor {
    uint32_t version;
    void *context;
    plamen_broker_v2_tool_effect_execute_fn js_authenticate;
    plamen_broker_v2_tool_effect_execute_fn js_runtime_identity;
    plamen_broker_v2_tool_effect_execute_fn js_prepare;
    plamen_broker_v2_tool_effect_execute_fn js_execute;
    plamen_broker_v2_tool_effect_execute_fn js_replay;
    plamen_broker_v2_tool_effect_execute_fn managed_evm_runtime_identity;
    plamen_broker_v2_tool_effect_execute_fn managed_evm_prepare;
    plamen_broker_v2_tool_effect_execute_fn managed_evm_execute;
    plamen_broker_v2_tool_effect_execute_fn managed_evm_project;
    plamen_broker_v2_tool_effect_execute_fn evm_projection_commit;
    plamen_broker_v2_tool_effect_execute_fn evm_projection_recover;
    plamen_broker_v2_tool_effect_execute_fn evm_projection_project;
    plamen_broker_v2_tool_effect_execute_fn snapshot_runtime_identity;
    plamen_broker_v2_tool_effect_execute_fn snapshot_acquire;
    plamen_broker_v2_tool_effect_execute_fn snapshot_prepare;
    plamen_broker_v2_tool_effect_execute_fn snapshot_execute;
    plamen_broker_v2_tool_effect_execute_fn fuzz_campaign_execute;
    plamen_broker_v2_tool_effect_execute_fn fuzz_service_admit;
    plamen_broker_v2_tool_effect_execute_fn fuzz_service_execute;
    plamen_broker_v2_tool_effect_dispose_fn dispose;
};

/* One exact entry point per append-only specialized method. */
int plamen_broker_v2_tool_effect_plan_js_authenticate(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_js_runtime_identity(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_js_prepare(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_js_execute(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_js_replay(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_managed_evm_runtime_identity(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_managed_evm_prepare(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_managed_evm_execute(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_managed_evm_project(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_evm_projection_commit(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_evm_projection_recover(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_evm_projection_project(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_snapshot_runtime_identity(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_snapshot_acquire(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_snapshot_prepare(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_snapshot_execute(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_fuzz_campaign_execute(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_fuzz_service_admit(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_fuzz_service_execute(
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);

int plamen_broker_v2_tool_effect_plan_view(
    const struct plamen_broker_v2_tool_effect_plan *,
    struct plamen_broker_v2_tool_effect_plan_view *);

/* Consumes the plan on every call, including rejected evidence. */
int plamen_broker_v2_tool_effect_plan_finalize(
    struct plamen_broker_v2_tool_effect_plan *,
    const struct plamen_broker_v2_tool_effect_evidence *,
    uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32]);
int plamen_broker_v2_tool_effect_plan_execute(
    struct plamen_broker_v2_tool_effect_plan *,
    const struct plamen_broker_v2_tool_effect_executor *,
    uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32]);
int plamen_broker_v2_tool_effect_plan_execute_exact(
    struct plamen_broker_v2_tool_effect_plan *,
    const struct plamen_broker_v2_tool_effect_exact_executor *,
    uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32]);

/*
 * PREPARE is the only cross-call descriptor handoff.  issue_lease validates
 * and emits its prepare receipt without closing the retained descriptors.
 * The matching *_execute_from_lease call consumes that lease, authenticates
 * the zero-FD follow-up request, and moves the retained inputs into a new
 * execute plan.  The service remains the capability authority; custody binds
 * the lease by lane, native effects context, authority and exact payload.
 */
int plamen_broker_v2_tool_effect_plan_issue_lease(
    struct plamen_broker_v2_tool_effect_plan *,
    const struct plamen_broker_v2_tool_effect_evidence *,
    uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32]);
int plamen_broker_v2_tool_effect_plan_js_execute_from_lease(
    struct plamen_broker_v2_tool_effect_plan *,
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_managed_evm_execute_from_lease(
    struct plamen_broker_v2_tool_effect_plan *,
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_snapshot_execute_from_lease(
    struct plamen_broker_v2_tool_effect_plan *,
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
int plamen_broker_v2_tool_effect_plan_fuzz_campaign_execute_from_lease(
    struct plamen_broker_v2_tool_effect_plan *,
    const struct plamen_broker_v2_tool_effect_plan_input *,
    struct plamen_broker_v2_tool_effect_plan **);
void plamen_broker_v2_tool_effect_plan_destroy(
    struct plamen_broker_v2_tool_effect_plan *);

/*
 * Host authority is intentionally split in two:
 *
 *  - the capability says which immutable Apple Container boundary may run;
 *  - the terminal joins host lifecycle evidence with an authenticated record
 *    emitted by the guest-native custodian after its cgroup is unpopulated.
 *
 * A stopped/absent container, by itself, never proves guest population zero or
 * network inactivity.  Those facts are accepted only from the keyed guest
 * terminal below and are then bound to the independently observed host create,
 * suspended-start, terminal, and delete receipts.
 */
struct plamen_broker_v2_tool_custody_capability_input {
    uint32_t version;
    const char *runtime_image_reference;
    uint8_t image_closure_sha256[32];
    uint8_t provider_admission_sha256[32];
    uint8_t rosetta_authority_sha256[32];
    uint8_t network_isolation_authority_sha256[32];
    uint8_t custody_receipt_sha256[32];
    uint8_t rosetta_required;
};

struct plamen_broker_v2_tool_execution_binding {
    uint32_t version;
    const char *tool_id;
    const char *run_id;
    uint8_t request_sha256[32];
    uint8_t custody_receipt_sha256[32];
    uint8_t materialization_receipt_sha256[32];
    uint8_t materialization_lineage_schema_sha256[32];
    uint8_t snapshot_sha256[32];
    uint8_t analysis_projection_sha256[32];
    uint64_t analysis_projection_bytes;
    uint8_t launch_object_sha256[32];
    uint64_t launch_object_bytes;
    uint8_t governance_sha256[32];
    uint8_t version_lock_sha256[32];
    uint8_t source_descriptor_identity_sha256[32];
    uint8_t source_scope_sha256[32];
    uint8_t argv_sha256[32];
    uint8_t environment_sha256[32];
    uint8_t cwd_sha256[32];
    uint8_t mounts_sha256[32];
    uint8_t native_runtime_identity_sha256[32];
    uint8_t network_authority_sha256[32];
    uint8_t allowed_path_manifest_sha256[32];
    uint64_t timeout_ms;
    uint64_t memory_bytes;
    uint64_t stdout_bound_bytes;
    uint64_t stderr_bound_bytes;
    uint64_t output_file_bound_bytes;
};

struct plamen_broker_v2_analysis_projection_custody {
    uint32_t version;
    uint8_t original_source_scope_sha256[32];
    uint8_t source_copy_closure_sha256[32];
    uint64_t source_copy_file_count;
    uint64_t source_copy_directory_count;
    uint64_t source_copy_bytes;
    uint8_t js_lock_selection_sha256[32];
    uint8_t dependency_materialization_receipt_sha256[32];
    uint8_t materialized_node_modules_closure_sha256[32];
    uint64_t materialized_node_modules_file_count;
    uint64_t materialized_node_modules_directory_count;
    uint64_t materialized_node_modules_bytes;
    uint8_t materialization_lineage_sha256[32];
    uint64_t materialization_lineage_byte_count;
    uint8_t native_materialization_request_sha256[32];
    uint8_t analysis_workspace_closure_sha256[32];
    uint64_t analysis_workspace_file_count;
    uint64_t analysis_workspace_directory_count;
    uint64_t analysis_workspace_bytes;
    uint8_t native_projection_custody_sha256[32];
    uint8_t host_descriptor_identity_sha256[32];
    uint8_t guest_mount_identity_sha256[32];
    uint8_t invocation_sha256[32];
};

struct plamen_broker_v2_tool_guest_terminal {
    uint32_t version;
    char tool_id[PLAMEN_BROKER_V2_TOOL_ID_MAX + 1U];
    uint8_t custody_receipt_sha256[32];
    uint8_t materialization_receipt_sha256[32];
    uint8_t snapshot_sha256[32];
    uint8_t launch_object_sha256[32];
    uint64_t launch_object_bytes;
    uint8_t post_spawn_dynamic_identity_sha256[32];
    uint8_t argv_sha256[32];
    uint8_t environment_sha256[32];
    uint8_t cwd_sha256[32];
    uint8_t mounts_sha256[32];
    int32_t returncode;
    uint64_t stdout_observed_bytes;
    uint64_t stdout_retained_bytes;
    uint8_t stdout_sha256[32];
    uint64_t stderr_observed_bytes;
    uint64_t stderr_retained_bytes;
    uint8_t stderr_sha256[32];
    uint8_t artifact_manifest_sha256[32];
    uint64_t artifact_count;
    uint64_t artifact_bytes;
    uint8_t network_denied;
    uint8_t population_zero;
    uint8_t cleanup_complete;
    uint64_t duration_ms;
    uint64_t peak_memory_bytes;
    uint8_t output_limit_exceeded;
    uint8_t record_hmac_sha256[32];
};

/* Canonical JSON accepted by managed-EVM's guest_execution_authority gate. */
int plamen_broker_v2_tool_custody_render_apple_authority(
    const struct plamen_broker_v2_tool_custody_capability_input *,
    uint8_t *, size_t, size_t *, uint8_t receipt_sha256[32]);

/* Canonical JSON accepted by admit_snapshot_bound_custody(). */
int plamen_broker_v2_tool_custody_render_snapshot_authority(
    const struct plamen_broker_v2_tool_custody_capability_input *,
    uint8_t *, size_t, size_t *, uint8_t receipt_sha256[32]);

/* Original snapshot -> immutable copied projection -> one RO guest mount. */
int plamen_broker_v2_tool_custody_render_analysis_projection(
    const struct plamen_broker_v2_analysis_projection_custody *,
    uint8_t *, size_t, size_t *, uint8_t receipt_sha256[32]);

/* Portable guest-native writer and host-native verifier for the exact record. */
int plamen_broker_v2_tool_guest_terminal_encode(
    const struct plamen_broker_v2_tool_execution_binding *,
    const struct plamen_broker_v2_tool_guest_terminal *, const uint8_t key[32],
    uint8_t output[PLAMEN_BROKER_V2_TOOL_GUEST_TERMINAL_SIZE]);
int plamen_broker_v2_tool_guest_terminal_decode(
    const uint8_t *, size_t, const uint8_t key[32],
    const struct plamen_broker_v2_tool_execution_binding *,
    struct plamen_broker_v2_tool_guest_terminal *);

/*
 * Produces canonical plamen.snapshot-bound-tool-execution-terminal.v3 only
 * when guest proof and all host lifecycle receipts form one exact chain.
 */
int plamen_broker_v2_tool_custody_render_terminal(
    const struct plamen_broker_v2_tool_execution_binding *,
    const struct plamen_broker_v2_tool_guest_terminal *,
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *,
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *,
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *,
    const struct plamen_broker_v2_apple_lifecycle_delete_receipt *,
    uint8_t *, size_t, size_t *, uint8_t terminal_sha256[32]);

#ifdef PLAMEN_BROKER_V2_TOOL_CUSTODY_TEST_ONLY
/* Exact-byte formatter KAT; production callers must use the lifecycle API. */
int plamen_broker_v2_tool_custody_test_render_terminal_v3(
    const struct plamen_broker_v2_tool_execution_binding *,
    const struct plamen_broker_v2_tool_guest_terminal *,
    uint8_t *, size_t, size_t *, uint8_t terminal_sha256[32]);
#endif

#ifdef __cplusplus
}
#endif

#endif
