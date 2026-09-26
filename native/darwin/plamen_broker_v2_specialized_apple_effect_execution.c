#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_specialized_apple_effect_execution.h"
#include "plamen_broker_v2.h"

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char python_path[] =
    "/usr/local/lib/plamen/python/bin/python3.12";
static const char worker_path[] =
    "/opt/plamen/scripts/posix_specialized_tool_worker.py";
static const char *const worker_arguments[] = {
    "-I", "-S", "-B", worker_path, "--apple-attached-stdio-v1"
};
static const uint8_t method_terminal_hmac_domain[] =
    "PLAMEN-SPECIALIZED-METHOD-TERMINAL-V1\0";

#define APPLE_CONTEXT_TOOL_PURPOSE UINT16_C(0x5008)
#define APPLE_CONTEXT_TOOL_TARGET UINT16_C(0x0108)

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

static int specialized_lifecycle_sha256(
    const struct plamen_broker_v2_specialized_worker_result *result,
    uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-SPECIALIZED-WORKER-LIFECYCLE-V1\0";
    uint8_t bytes[sizeof(domain) + 128U]; size_t offset = 0U;
    if (result == NULL || output == NULL) return -1;
    memcpy(bytes + offset, domain, sizeof(domain)); offset += sizeof(domain);
    memcpy(bytes + offset, result->created.receipt_sha256, 32); offset += 32U;
    memcpy(bytes + offset, result->started.receipt_sha256, 32); offset += 32U;
    memcpy(bytes + offset, result->exited.receipt_sha256, 32); offset += 32U;
    memcpy(bytes + offset, result->deleted.receipt_sha256, 32); offset += 32U;
    if (plamen_broker_v2_sha256(bytes, offset, output) != 0) {
        memset(bytes, 0, sizeof(bytes)); return -1;
    }
    memset(bytes, 0, sizeof(bytes)); return zero32(output) ? -1 : 0;
}

static int lifecycle_links_exact(
    const struct plamen_broker_v2_specialized_worker_result *result,
    uint8_t lifecycle_sha256[32])
{
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *created;
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *started;
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *exited;
    const struct plamen_broker_v2_apple_lifecycle_delete_receipt *deleted;
    if (result == NULL || lifecycle_sha256 == NULL) return -1;
    created = &result->created; started = &result->started;
    exited = &result->exited; deleted = &result->deleted;
    if (plamen_broker_v2_apple_lifecycle_create_receipt_validate(created) != 0
        || plamen_broker_v2_apple_lifecycle_start_receipt_dynamic_identity_validate(
            started) != 0
        || plamen_broker_v2_apple_lifecycle_terminal_receipt_validate(exited) != 0
        || plamen_broker_v2_apple_lifecycle_delete_receipt_validate(deleted) != 0
        || strcmp(created->container_id, started->container_id) != 0
        || strcmp(started->container_id, exited->container_id) != 0
        || strcmp(exited->container_id, deleted->container_id) != 0
        || !equal(created->request_fingerprint_sha256,
            started->request_fingerprint_sha256, 32)
        || !equal(started->request_fingerprint_sha256,
            exited->request_fingerprint_sha256, 32)
        || !equal(exited->request_fingerprint_sha256,
            deleted->request_fingerprint_sha256, 32)
        || !equal(created->spec_sha256, started->spec_sha256, 32)
        || !equal(started->spec_sha256, exited->spec_sha256, 32)
        || !equal(exited->spec_sha256, deleted->spec_sha256, 32)
        || !equal(started->launch_request_sha256,
            exited->launch_request_sha256, 32)
        || !equal(started->start_operation_nonce,
            exited->start_operation_nonce, 32)
        || !equal(started->native_process_handle_sha256,
            exited->native_process_handle_sha256, 32)
        || started->native_process_id != exited->native_process_id
        || !equal(exited->receipt_sha256,
            deleted->terminal_receipt_sha256, 32)
        || !equal(exited->cleanup_sha256, deleted->cleanup_sha256, 32)
        || zero32(created->mount_roster_sha256)
        || created->rootfs_readonly != 1U || created->use_init != 1U
        || created->network_attachment_count != 0U
        || created->dns_disabled != 1U
        || exited->exit_code != 0 || exited->descendants_extinct != 1U
        || exited->guest_process_extinct != 1U
        || exited->backend_egress_revoked != 1U
        || exited->stop_control_process_reaped != 1U
        || exited->stop_control_process_group_extinct != 1U
        || exited->guest_population_zero != 1U
        || exited->container_vm_stopped != 1U
        || zero32(exited->stop_argv_sha256)
        || zero32(exited->stop_stdout_sha256)
        || zero32(exited->stop_stderr_sha256)
        || zero32(exited->stopped_observation_sha256)
        || zero32(exited->guest_population_extinction_sha256)
        /* The terminal receipt is immutable before delete.  Deletion has its
         * own linked receipt and must never be forged by flipping this byte
         * after the terminal digest was committed. */
        || exited->terminal_durable != 1U || exited->deleted != 0U
        || deleted->descendants_extinct != 1U
        || deleted->guest_process_extinct != 1U
        || deleted->backend_egress_revoked != 1U || deleted->absent != 1U
        || specialized_lifecycle_sha256(result, lifecycle_sha256) != 0
        || !equal(lifecycle_sha256, result->lifecycle_receipt_sha256, 32))
        return -1;
    return 0;
}

static int js_scratch_fd(
    const struct plamen_broker_v2_tool_effect_plan_view *view)
{
    size_t index; int result = -1;
    if (view == NULL || view->descriptors == NULL || view->fds == NULL)
        return -1;
    for (index = 0; index < view->fd_count; ++index) {
        if (view->descriptors[index].purpose
                != PLAMEN_BROKER_V2_FD_JS_SCRATCH)
            continue;
        if (result >= 0 || view->fds[index] < 0
            || view->descriptors[index].access_mode
                != PLAMEN_BROKER_V2_FD_READ_WRITE)
            return -1;
        result = view->fds[index];
    }
    return result;
}

static int fd_for_purpose(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    uint16_t purpose)
{
    size_t index; int result = -1;
    if (view == NULL || view->descriptors == NULL || view->fds == NULL)
        return -1;
    for (index = 0U; index < view->fd_count; ++index) {
        if (view->descriptors[index].purpose != purpose) continue;
        if (result >= 0 || view->fds[index] < 0) return -1;
        result = view->fds[index];
    }
    return result;
}

static int read_regular_at(int directory_fd, const char *name,
    uint8_t **bytes, size_t *size)
{
    struct stat information, replay;
    uint8_t *raw = NULL; size_t offset = 0U; ssize_t amount; int fd = -1;
    if (bytes != NULL) *bytes = NULL;
    if (size != NULL) *size = 0U;
    memset(&information, 0, sizeof(information));
    memset(&replay, 0, sizeof(replay));
    if (directory_fd < 0 || name == NULL || bytes == NULL || size == NULL
        || (fd = openat(directory_fd, name,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || fstat(fd, &information) != 0 || !S_ISREG(information.st_mode)
        || information.st_nlink != 1 || information.st_size <= 0
        || information.st_size > 1048576)
        goto done;
    raw = malloc((size_t)information.st_size);
    if (raw == NULL) goto done;
    while (offset < (size_t)information.st_size) {
        amount = pread(fd, raw + offset,
            (size_t)information.st_size - offset, (off_t)offset);
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    if (fstat(fd, &replay) != 0
        || replay.st_dev != information.st_dev
        || replay.st_ino != information.st_ino
        || replay.st_size != information.st_size) goto done;
    *bytes = raw; *size = offset; raw = NULL;
done:
    if (fd >= 0) (void)close(fd);
    if (raw != NULL) {
        memset(raw, 0, (size_t)(information.st_size > 0
            ? information.st_size : 0));
        free(raw);
    }
    return *bytes == NULL ? -1 : 0;
}

static int render_projection_terminal(
    const struct plamen_broker_v2_specialized_apple_effect_execution *input,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const struct plamen_broker_v2_specialized_worker_result *worker_result,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *observed,
    const uint8_t network_policy_sha256[32],
    uint8_t **terminal, size_t *terminal_size)
{
    static const uint8_t custody_domain[] =
        "PLAMEN-EVM-PROJECTION-CUSTODY-V1\0";
    static const uint8_t mount_domain[] =
        "PLAMEN-EVM-PROJECTION-GUEST-MOUNT-V1\0";
    struct plamen_broker_v2_specialized_projection_observation projection;
    struct plamen_broker_v2_analysis_projection_custody custody;
    uint8_t *projection_raw = NULL, *lineage_raw = NULL, *rendered = NULL;
    size_t projection_size = 0U, lineage_size = 0U, rendered_size = 0U;
    uint8_t projection_sha256[32], lineage_sha256[32], lifecycle[32];
    uint8_t custody_preimage[sizeof(custody_domain) + 32U * 5U];
    uint8_t mount_preimage[sizeof(mount_domain) + 32U * 3U];
    int scratch_fd, state_fd, workspace_fd = -1, result = -1;
    memset(&projection, 0, sizeof(projection));
    memset(&custody, 0, sizeof(custody));
    memset(projection_sha256, 0, sizeof(projection_sha256));
    memset(lineage_sha256, 0, sizeof(lineage_sha256));
    memset(lifecycle, 0, sizeof(lifecycle));
    if (terminal != NULL) *terminal = NULL;
    if (terminal_size != NULL) *terminal_size = 0U;
    if (input == NULL || binding == NULL || worker_result == NULL
        || observed == NULL || network_policy_sha256 == NULL
        || terminal == NULL || terminal_size == NULL
        || input->view->lane != PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
        || input->view->method != PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
        || strcmp(binding->operation, "EVM_PROJECTION_COMMIT") != 0
        || strcmp(observed->status, "COMPLETE") != 0
        || observed->returncode != 0
        || lifecycle_links_exact(worker_result, lifecycle) != 0
        || (scratch_fd = fd_for_purpose(input->view,
            PLAMEN_BROKER_V2_FD_PROJECTION_SCRATCH)) < 0
        || (state_fd = fd_for_purpose(input->view,
            PLAMEN_BROKER_V2_FD_PROJECTION_STATE)) < 0
        || read_regular_at(state_fd, "projection-observation.json",
            &projection_raw, &projection_size) != 0
        || plamen_broker_v2_sha256(projection_raw, projection_size,
            projection_sha256) != 0
        || !equal(projection_sha256,
            observed->projection_observation_sha256, 32U)
        || plamen_broker_v2_specialized_projection_observation_parse(
            projection_raw, projection_size, &projection) != 0
        || read_regular_at(state_fd, "materialization-lineage.json",
            &lineage_raw, &lineage_size) != 0
        || plamen_broker_v2_sha256(lineage_raw, lineage_size,
            lineage_sha256) != 0
        || !equal(lineage_sha256,
            projection.materialization_lineage_sha256, 32U)
        || lineage_size != projection.materialization_lineage_byte_count
        || (workspace_fd = openat(scratch_fd, "analysis-workspace",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)) < 0)
        goto done;
    custody.version = 1U;
    memcpy(custody.original_source_scope_sha256,
        projection.original_source_scope_sha256, 32U);
    memcpy(custody.source_copy_closure_sha256,
        projection.source_copy_closure_sha256, 32U);
    custody.source_copy_file_count = projection.source_copy_file_count;
    custody.source_copy_directory_count = projection.source_copy_directory_count;
    custody.source_copy_bytes = projection.source_copy_bytes;
    memcpy(custody.js_lock_selection_sha256,
        projection.js_lock_selection_sha256, 32U);
    memcpy(custody.dependency_materialization_receipt_sha256,
        projection.dependency_materialization_receipt_sha256, 32U);
    memcpy(custody.materialized_node_modules_closure_sha256,
        projection.materialized_node_modules_closure_sha256, 32U);
    custody.materialized_node_modules_file_count =
        projection.materialized_node_modules_file_count;
    custody.materialized_node_modules_directory_count =
        projection.materialized_node_modules_directory_count;
    custody.materialized_node_modules_bytes =
        projection.materialized_node_modules_bytes;
    memcpy(custody.materialization_lineage_sha256,
        projection.materialization_lineage_sha256, 32U);
    custody.materialization_lineage_byte_count =
        projection.materialization_lineage_byte_count;
    memcpy(custody.native_materialization_request_sha256,
        projection.native_materialization_request_sha256, 32U);
    memcpy(custody.analysis_workspace_closure_sha256,
        projection.analysis_workspace_closure_sha256, 32U);
    custody.analysis_workspace_file_count =
        projection.analysis_workspace_file_count;
    custody.analysis_workspace_directory_count =
        projection.analysis_workspace_directory_count;
    custody.analysis_workspace_bytes = projection.analysis_workspace_bytes;
    if (plamen_broker_v2_fd_identity(workspace_fd,
            custody.host_descriptor_identity_sha256) != 0)
        goto done;
    memcpy(custody_preimage, custody_domain, sizeof(custody_domain));
    memcpy(custody_preimage + sizeof(custody_domain),
        input->view->request_sha256, 32U);
    memcpy(custody_preimage + sizeof(custody_domain) + 32U,
        binding->worker_request_sha256, 32U);
    memcpy(custody_preimage + sizeof(custody_domain) + 64U,
        lifecycle, 32U);
    memcpy(custody_preimage + sizeof(custody_domain) + 96U,
        custody.host_descriptor_identity_sha256, 32U);
    memcpy(custody_preimage + sizeof(custody_domain) + 128U,
        projection.analysis_workspace_closure_sha256, 32U);
    if (plamen_broker_v2_hmac_sha256(input->session_key, custody_domain,
            sizeof(custody_domain), custody_preimage,
            sizeof(custody_preimage),
            custody.native_projection_custody_sha256) != 0)
        goto done;
    memcpy(mount_preimage, mount_domain, sizeof(mount_domain));
    memcpy(mount_preimage + sizeof(mount_domain),
        custody.host_descriptor_identity_sha256, 32U);
    memcpy(mount_preimage + sizeof(mount_domain) + 32U,
        projection.analysis_workspace_closure_sha256, 32U);
    memcpy(mount_preimage + sizeof(mount_domain) + 64U,
        network_policy_sha256, 32U);
    if (plamen_broker_v2_sha256(mount_preimage, sizeof(mount_preimage),
            custody.guest_mount_identity_sha256) != 0)
        goto done;
    memcpy(custody.invocation_sha256, lifecycle, 32U);
    rendered = malloc(PLAMEN_BROKER_V2_TOOL_JSON_MAX);
    if (rendered == NULL
        || plamen_broker_v2_tool_custody_render_analysis_projection(&custody,
            rendered, PLAMEN_BROKER_V2_TOOL_JSON_MAX, &rendered_size,
            projection_sha256) != 0)
        goto done;
    *terminal = rendered; *terminal_size = rendered_size; rendered = NULL;
    result = 0;
done:
    if (workspace_fd >= 0) (void)close(workspace_fd);
    if (projection_raw != NULL) {
        memset(projection_raw, 0, projection_size); free(projection_raw);
    }
    if (lineage_raw != NULL) {
        memset(lineage_raw, 0, lineage_size); free(lineage_raw);
    }
    if (rendered != NULL) {
        memset(rendered, 0, PLAMEN_BROKER_V2_TOOL_JSON_MAX); free(rendered);
    }
    memset(&projection, 0, sizeof(projection));
    memset(&custody, 0, sizeof(custody));
    memset(custody_preimage, 0, sizeof(custody_preimage));
    memset(mount_preimage, 0, sizeof(mount_preimage));
    memset(projection_sha256, 0, sizeof(projection_sha256));
    memset(lineage_sha256, 0, sizeof(lineage_sha256));
    memset(lifecycle, 0, sizeof(lifecycle));
    return result;
}

static int build_authenticated_output_receipt(
    const struct plamen_broker_v2_specialized_apple_effect_execution *input,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const struct plamen_broker_v2_specialized_worker_result *worker_result,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *observed,
    const uint8_t network_policy_sha256[32],
    struct plamen_broker_v2_specialized_output_receipt *receipt)
{
    struct plamen_broker_v2_specialized_output_spec specs[2];
    uint8_t lifecycle[32], empty_egress[32]; size_t spec_count = 0U;
    int scratch_fd;
    memset(specs, 0, sizeof(specs)); memset(lifecycle, 0, sizeof(lifecycle));
    memset(empty_egress, 0, sizeof(empty_egress));
    if (input == NULL || input->view == NULL || input->session_key == NULL
        || binding == NULL || worker_result == NULL || observed == NULL
        || network_policy_sha256 == NULL || receipt == NULL
        || worker_result->version != PLAMEN_BROKER_V2_SPECIALIZED_WORKER_VERSION
        || worker_result->network_denied != 1U
        || worker_result->population_zero != 1U
        || worker_result->cleanup_complete != 1U
        || lifecycle_links_exact(worker_result, lifecycle) != 0
        || plamen_broker_v2_sha256("[]", 2U, empty_egress) != 0
        || !equal(empty_egress, observed->observed_egress_sha256, 32)
        || plamen_broker_v2_specialized_method_output_specs(input->view,
            binding, specs, &spec_count) != 0
        || (scratch_fd = js_scratch_fd(input->view)) < 0
        || plamen_broker_v2_specialized_output_receipt_build(
            input->session_key, input->view, binding, lifecycle,
            worker_result->started.post_spawn_dynamic_identity_kind,
            worker_result->started.post_spawn_dynamic_identity_size,
            worker_result->started.post_spawn_dynamic_identity_sha256,
            network_policy_sha256, empty_egress,
            1U, 1U, 1U, 1U, scratch_fd, specs, spec_count, receipt) != 0) {
        memset(specs, 0, sizeof(specs)); memset(lifecycle, 0, sizeof(lifecycle));
        memset(empty_egress, 0, sizeof(empty_egress)); return -1;
    }
    memset(specs, 0, sizeof(specs)); memset(lifecycle, 0, sizeof(lifecycle));
    memset(empty_egress, 0, sizeof(empty_egress)); return 0;
}

/* Snapshot output is the guest worker's exact HMAC-authenticated aggregate
 * manifest.  Host authority is limited to the independently verified Apple
 * lifecycle, network denial, and dynamic image identity; no missing census is
 * converted into a population-zero claim. */
static int build_snapshot_host_authority(
    const struct plamen_broker_v2_specialized_apple_effect_execution *input,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const struct plamen_broker_v2_specialized_worker_result *worker_result,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *observed,
    const uint8_t network_policy_sha256[32],
    struct plamen_broker_v2_specialized_output_receipt *authority)
{
    uint8_t lifecycle[32], empty_egress[32];
    memset(lifecycle, 0, sizeof(lifecycle));
    memset(empty_egress, 0, sizeof(empty_egress));
    if (authority != NULL) memset(authority, 0, sizeof(*authority));
    if (input == NULL || input->view == NULL || binding == NULL
        || worker_result == NULL || observed == NULL
        || network_policy_sha256 == NULL || authority == NULL
        || input->view->lane != PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        || input->view->method != PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE
        || strcmp(binding->operation, "SNAPSHOT_TOOL_EXECUTE") != 0
        || worker_result->version != PLAMEN_BROKER_V2_SPECIALIZED_WORKER_VERSION
        || worker_result->network_denied != 1U
        || worker_result->population_zero != 1U
        || worker_result->cleanup_complete != 1U
        || lifecycle_links_exact(worker_result, lifecycle) != 0
        || plamen_broker_v2_sha256("[]", 2U, empty_egress) != 0
        || !equal(empty_egress, observed->observed_egress_sha256, 32)
        || observed->version != 1U || strcmp(observed->status, "COMPLETE") != 0
        || observed->returncode != 0 || zero32(observed->output_manifest_sha256)
        || observed->output_file_count > binding->limits.output_files
        || observed->output_bytes > binding->limits.output_bytes)
        goto failed;
    authority->version = PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RECEIPT_VERSION;
    authority->lane = input->view->lane; authority->method = input->view->method;
    memcpy(authority->operation, binding->operation,
        strlen(binding->operation) + 1U);
    memcpy(authority->request_sha256, input->view->request_sha256, 32);
    memcpy(authority->effects_binding_sha256,
        binding->effects_binding_sha256, 32);
    memcpy(authority->worker_request_sha256,
        binding->worker_request_sha256, 32);
    memcpy(authority->lifecycle_receipt_sha256, lifecycle, 32);
    authority->post_spawn_dynamic_identity_kind =
        worker_result->started.post_spawn_dynamic_identity_kind;
    authority->post_spawn_dynamic_identity_size =
        worker_result->started.post_spawn_dynamic_identity_size;
    memcpy(authority->post_spawn_dynamic_identity_sha256,
        worker_result->started.post_spawn_dynamic_identity_sha256, 32);
    memcpy(authority->network_policy_sha256, network_policy_sha256, 32);
    memcpy(authority->observed_egress_sha256, empty_egress, 32);
    authority->provider_authenticated = 1U;
    authority->network_policy_enforced = 1U;
    authority->population_zero = 1U;
    authority->cleanup_complete = 1U;
    if (plamen_broker_v2_specialized_snapshot_host_authority_seal(
            authority, input->session_key) != 0)
        goto failed;
    memset(lifecycle, 0, sizeof(lifecycle));
    memset(empty_egress, 0, sizeof(empty_egress));
    return 0;
failed:
    if (authority != NULL) memset(authority, 0, sizeof(*authority));
    memset(lifecycle, 0, sizeof(lifecycle));
    memset(empty_egress, 0, sizeof(empty_egress));
    return -1;
}

static void put16(uint8_t output[2], uint16_t value)
{ output[0] = (uint8_t)(value >> 8); output[1] = (uint8_t)value; }

static void put32(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)(value >> 24); output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8); output[3] = (uint8_t)value;
}

static int execution_method(uint16_t lane, uint16_t method)
{
    return (lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
            && method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE)
        || (lane == PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM
            && method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE)
        || (lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
            && method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE)
        || (lane == PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
            && method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT);
}

static int retained_role_for_purpose(uint16_t lane, uint16_t purpose,
    uint16_t *role)
{
    if (role == NULL) return -1;
    if (lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL) {
        switch (purpose) {
        case PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE:
            *role = PLAMEN_BROKER_V2_WORKER_SOURCE; return 0;
        case PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH:
            *role = PLAMEN_BROKER_V2_WORKER_SCRATCH; return 0;
        case PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE:
            *role = PLAMEN_BROKER_V2_WORKER_STATE; return 0;
        case PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT:
            *role = PLAMEN_BROKER_V2_WORKER_PROJECT; return 0;
        default: return -1;
        }
    }
    if (lane == PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION) {
        switch (purpose) {
        case PLAMEN_BROKER_V2_FD_PROJECTION_PROJECT:
            *role = PLAMEN_BROKER_V2_WORKER_PROJECT; return 0;
        case PLAMEN_BROKER_V2_FD_PROJECTION_SCRATCH:
            *role = PLAMEN_BROKER_V2_WORKER_SCRATCH; return 0;
        case PLAMEN_BROKER_V2_FD_PROJECTION_STATE:
            *role = PLAMEN_BROKER_V2_WORKER_STATE; return 0;
        case PLAMEN_BROKER_V2_FD_PROJECTION_MODULES:
            *role = PLAMEN_BROKER_V2_WORKER_SOURCE; return 0;
        default: return -1;
        }
    }
    if (lane != PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER) return -1;
    switch (purpose) {
    case PLAMEN_BROKER_V2_FD_JS_SOURCE:
        *role = PLAMEN_BROKER_V2_WORKER_SOURCE; return 0;
    case PLAMEN_BROKER_V2_FD_JS_SCRATCH:
        *role = PLAMEN_BROKER_V2_WORKER_SCRATCH; return 0;
    case PLAMEN_BROKER_V2_FD_JS_STATE:
        *role = PLAMEN_BROKER_V2_WORKER_STATE; return 0;
    case PLAMEN_BROKER_V2_FD_JS_ARCHIVE_ROOT:
        *role = PLAMEN_BROKER_V2_WORKER_ACQUISITION; return 0;
    default: return -1;
    }
}

/* Convert only the custody-retained four-role plan plus the authenticated
 * image member into the codec roster.  Payload tuples are a fresh native
 * descriptor-relative census; caller or nested JSON values are never used. */
static int build_worker_fds(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_apple_runtime *runtime,
    struct plamen_broker_v2_specialized_worker_fd output[5])
{
    struct plamen_broker_v2_specialized_tree_identity census;
    uint8_t seen[PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ROLE_COUNT];
    size_t index;
    memset(output, 0, sizeof(*output) * 5U); memset(seen, 0, sizeof(seen));
    if (view == NULL || runtime == NULL
        || !((view->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
                && view->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE)
            || (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
                && view->method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE)
            || (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
                && view->method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT))
        || view->fds == NULL || view->descriptors == NULL
        || view->fd_count != 4U || zero32(runtime->tool_image_member_sha256)
        || runtime->tool_image_member_size == 0U) return -1;
    for (index = 0; index < view->fd_count; ++index) {
        const struct plamen_broker_v2_fd_metadata *descriptor =
            &view->descriptors[index];
        struct plamen_broker_v2_specialized_worker_fd *row = &output[index];
        uint16_t role; size_t role_index;
        if (view->fds[index] < 0 || descriptor->target != index + 1U
            || retained_role_for_purpose(view->lane, descriptor->purpose,
                &role) != 0)
            return -1;
        role_index = role - 1U;
        if (seen[role_index]
            || ((role == PLAMEN_BROKER_V2_WORKER_SOURCE
                    || role == PLAMEN_BROKER_V2_WORKER_ACQUISITION
                    || role == PLAMEN_BROKER_V2_WORKER_PROJECT)
                ? descriptor->access_mode != PLAMEN_BROKER_V2_FD_READ
                : descriptor->access_mode != PLAMEN_BROKER_V2_FD_READ_WRITE)
            || plamen_broker_v2_specialized_tree_recensus_fd(view->fds[index],
                65536U, UINT64_C(4294967296), &census) != 0)
            return -1;
        seen[role_index] = 1U; row->version = 1U; row->role = role;
        row->purpose = descriptor->purpose; row->target = descriptor->target;
        row->access_mode = descriptor->access_mode;
        row->kind = PLAMEN_BROKER_V2_WORKER_DIRECTORY;
        row->provenance = PLAMEN_BROKER_V2_WORKER_FD_FROM_PLAN;
        memcpy(row->native_identity, descriptor->identity, 32);
        row->host_fd = view->fds[index]; row->guest_fd = 0U;
        memcpy(row->payload_sha256, census.tree_sha256, 32);
        row->payload_bytes = census.expanded_bytes;
        row->payload_entries = census.entry_count;
        memset(&census, 0, sizeof(census));
    }
    if (!seen[PLAMEN_BROKER_V2_WORKER_SOURCE - 1U]
        || !seen[PLAMEN_BROKER_V2_WORKER_SCRATCH - 1U]
        || !seen[PLAMEN_BROKER_V2_WORKER_STATE - 1U]
        || (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
            ? !seen[PLAMEN_BROKER_V2_WORKER_ACQUISITION - 1U]
            : !seen[PLAMEN_BROKER_V2_WORKER_PROJECT - 1U])) return -1;
    output[4].version = 1U;
    output[4].role = PLAMEN_BROKER_V2_WORKER_TOOL;
    output[4].purpose = APPLE_CONTEXT_TOOL_PURPOSE;
    output[4].target = APPLE_CONTEXT_TOOL_TARGET;
    output[4].access_mode = PLAMEN_BROKER_V2_FD_READ;
    output[4].kind = PLAMEN_BROKER_V2_WORKER_IMAGE_MEMBER;
    output[4].provenance =
        PLAMEN_BROKER_V2_WORKER_FD_FROM_AUTHENTICATED_CONTEXT;
    output[4].host_fd = -1;
    memcpy(output[4].payload_sha256,
        runtime->tool_image_member_sha256, 32);
    output[4].payload_bytes = runtime->tool_image_member_size;
    output[4].payload_entries = 1U;
    return 0;
}

static int bind_slither_dependency_closure(
    struct plamen_broker_v2_specialized_runtime_handoff *handoff,
    const char *tool_member_id,
    struct plamen_broker_v2_specialized_apple_runtime *runtime)
{
    struct plamen_broker_v2_specialized_apple_runtime forge, solc, python;
    int result = -1;
    memset(&forge, 0, sizeof(forge)); memset(&solc, 0, sizeof(solc));
    memset(&python, 0, sizeof(python));
    if (handoff == NULL || tool_member_id == NULL || runtime == NULL)
        goto done;
    if (strcmp(tool_member_id, "slither") != 0) {
        result = 0; goto done;
    }
    if (plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
            handoff, PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
            "forge", &forge) != 0
        || plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
            handoff, PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
            "solc", &solc) != 0
        || plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
            handoff, PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
            "managed_python", &python) != 0
        || !equal(forge.oci_image_sha256, runtime->oci_image_sha256, 32U)
        || !equal(solc.oci_image_sha256, runtime->oci_image_sha256, 32U)
        || !equal(python.oci_image_sha256, runtime->oci_image_sha256, 32U)
        || !equal(forge.runtime_manifest_sha256,
            runtime->runtime_manifest_sha256, 32U)
        || !equal(solc.runtime_manifest_sha256,
            runtime->runtime_manifest_sha256, 32U)
        || !equal(python.runtime_manifest_sha256,
            runtime->runtime_manifest_sha256, 32U)
        || zero32(forge.tool_image_member_sha256)
        || forge.tool_image_member_size == 0U
        || zero32(solc.tool_image_member_sha256)
        || solc.tool_image_member_size == 0U
        || zero32(python.tool_image_member_sha256)
        || python.tool_image_member_size == 0U)
        goto done;
    memcpy(runtime->slither_forge_sha256,
        forge.tool_image_member_sha256, 32U);
    runtime->slither_forge_size = forge.tool_image_member_size;
    memcpy(runtime->slither_solc_sha256,
        solc.tool_image_member_sha256, 32U);
    runtime->slither_solc_size = solc.tool_image_member_size;
    memcpy(runtime->slither_python_sha256,
        python.tool_image_member_sha256, 32U);
    runtime->slither_python_size = python.tool_image_member_size;
    if (plamen_broker_v2_specialized_slither_internal_environment_sha256(
            runtime->slither_internal_environment_sha256) != 0)
        goto done;
    result = 0;
done:
    memset(&forge, 0, sizeof(forge)); memset(&solc, 0, sizeof(solc));
    memset(&python, 0, sizeof(python)); return result;
}

static int bind_projection_dependency_closure(
    struct plamen_broker_v2_specialized_runtime_handoff *handoff,
    uint16_t lane,
    struct plamen_broker_v2_specialized_apple_runtime *runtime)
{
    struct plamen_broker_v2_specialized_apple_runtime solc;
    int result = -1;
    memset(&solc, 0, sizeof(solc));
    if (lane != PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION) return 0;
    if (handoff == NULL || runtime == NULL
        || plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
            handoff, PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
            "solc", &solc) != 0
        || !equal(solc.oci_image_sha256, runtime->oci_image_sha256, 32U)
        || !equal(solc.runtime_manifest_sha256,
            runtime->runtime_manifest_sha256, 32U)
        || zero32(solc.tool_image_member_sha256)
        || solc.tool_image_member_size == 0U)
        goto done;
    memcpy(runtime->slither_solc_sha256,
        solc.tool_image_member_sha256, 32U);
    runtime->slither_solc_size = solc.tool_image_member_size;
    result = 0;
done:
    memset(&solc, 0, sizeof(solc));
    return result;
}

static int derive_operation_key(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const uint8_t runtime_authority_sha256[32], uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-SPECIALIZED-APPLE-EFFECT-OPERATION-V1\0";
    uint8_t bytes[sizeof(domain) + 2U + 2U + 32U * 4U]; size_t offset = 0;
    memcpy(bytes + offset, domain, sizeof(domain)); offset += sizeof(domain);
    put16(bytes + offset, view->lane); offset += 2U;
    put16(bytes + offset, view->method); offset += 2U;
    memcpy(bytes + offset, view->operation_nonce, 32); offset += 32U;
    memcpy(bytes + offset, view->request_sha256, 32); offset += 32U;
    memcpy(bytes + offset, view->effects_context_sha256, 32); offset += 32U;
    memcpy(bytes + offset, runtime_authority_sha256, 32); offset += 32U;
    if (plamen_broker_v2_sha256(bytes, offset, output) != 0) {
        memset(bytes, 0, sizeof(bytes)); return -1;
    }
    memset(bytes, 0, sizeof(bytes)); return zero32(output) ? -1 : 0;
}

static int derive_policy(const uint8_t operation_key[32],
    const uint8_t worker_request_bytes_sha256[32],
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-SPECIALIZED-APPLE-DENY-ALL-POLICY-V1\0";
    uint8_t bytes[sizeof(domain) + 32U * 4U]; size_t offset = 0;
    memcpy(bytes + offset, domain, sizeof(domain)); offset += sizeof(domain);
    memcpy(bytes + offset, operation_key, 32); offset += 32U;
    memcpy(bytes + offset, worker_request_bytes_sha256, 32); offset += 32U;
    memcpy(bytes + offset, binding->effects_binding_sha256, 32); offset += 32U;
    memcpy(bytes + offset, binding->runtime_closure_sha256, 32); offset += 32U;
    if (plamen_broker_v2_sha256(bytes, offset, output) != 0) {
        memset(bytes, 0, sizeof(bytes)); return -1;
    }
    memset(bytes, 0, sizeof(bytes)); return zero32(output) ? -1 : 0;
}

static int completion_digest(
    const struct plamen_broker_v2_specialized_effect_completion *completion,
    const char *domain, uint8_t output[32])
{
    uint8_t bytes[512]; size_t domain_size, offset = 0;
    if (completion == NULL || domain == NULL || output == NULL
        || (domain_size = strlen(domain) + 1U) > 96U)
        return -1;
    memset(bytes, 0, sizeof(bytes)); memcpy(bytes + offset, domain, domain_size);
    offset += domain_size; put16(bytes + offset, completion->lane); offset += 2U;
    put16(bytes + offset, completion->method); offset += 2U;
    put32(bytes + offset, completion->flags); offset += 4U;
#define COPY(field) do { memcpy(bytes + offset, completion->field, 32); offset += 32U; } while (0)
    COPY(operation_key); COPY(request_sha256); COPY(runtime_authority_sha256);
    COPY(worker_request_sha256); COPY(lifecycle_receipt_sha256);
    COPY(terminal_sha256); COPY(terminal_hmac_sha256);
    COPY(network_policy_sha256); COPY(observed_egress_sha256);
#undef COPY
    bytes[offset++] = completion->provider_authenticated;
    bytes[offset++] = completion->network_policy_enforced;
    bytes[offset++] = completion->population_zero;
    bytes[offset++] = completion->cleanup_complete;
    if (plamen_broker_v2_sha256(bytes, offset, output) != 0) {
        memset(bytes, 0, sizeof(bytes)); return -1;
    }
    memset(bytes, 0, sizeof(bytes)); return zero32(output) ? -1 : 0;
}

static int evidence_from_completion(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_effect_completion *completion,
    uint8_t *terminal, size_t terminal_size,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    if (view == NULL || completion == NULL || terminal == NULL
        || terminal_size < 2U || evidence == NULL
        || completion->lane != view->lane || completion->method != view->method
        || completion->flags != view->flags
        || !equal(completion->request_sha256, view->request_sha256, 32)
        || completion_digest(completion,
            "PLAMEN-SPECIALIZED-APPLE-EFFECT-RECEIPT-V1",
            evidence->effect_receipt_sha256) != 0
        || completion_digest(completion,
            "PLAMEN-SPECIALIZED-APPLE-DURABLE-OPERATION-V1",
            evidence->durable_operation_sha256) != 0)
        return -1;
    evidence->version = PLAMEN_BROKER_V2_TOOL_EFFECT_EVIDENCE_VERSION;
    evidence->lane = view->lane; evidence->method = view->method;
    memcpy(evidence->authority_binding_sha256,
        view->authority_binding_sha256, 32);
    memcpy(evidence->operation_nonce, view->operation_nonce, 32);
    memcpy(evidence->request_sha256, view->request_sha256, 32);
    memcpy(evidence->effects_context_sha256,
        view->effects_context_sha256, 32);
    memcpy(evidence->lifecycle_receipt_sha256,
        completion->lifecycle_receipt_sha256, 32);
    memcpy(evidence->network_policy_sha256,
        completion->network_policy_sha256, 32);
    memcpy(evidence->observed_egress_sha256,
        completion->observed_egress_sha256, 32);
    evidence->effect_authenticated = 1U; evidence->effect_completed = 1U;
    evidence->durable_operation = 1U;
    evidence->provider_authenticated = completion->provider_authenticated;
    evidence->network_policy_enforced = completion->network_policy_enforced;
    evidence->population_zero = completion->population_zero;
    evidence->cleanup_complete = completion->cleanup_complete;
    evidence->terminal = terminal; evidence->terminal_size = terminal_size;
    return 0;
}

static const char *mount_target(uint16_t lane, uint16_t role)
{
    if (lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER) {
        if (role == PLAMEN_BROKER_V2_WORKER_ACQUISITION)
            return "/workspace/acquisition";
        if (role == PLAMEN_BROKER_V2_WORKER_SOURCE)
            return "/workspace/project";
        if (role == PLAMEN_BROKER_V2_WORKER_SCRATCH)
            return "/workspace/scratch";
        if (role == PLAMEN_BROKER_V2_WORKER_STATE)
            return "/workspace/state";
        return NULL;
    }
    switch (role) {
    case PLAMEN_BROKER_V2_WORKER_ACQUISITION: return "/workspace/acquisition";
    case PLAMEN_BROKER_V2_WORKER_CACHE: return "/workspace/cache";
    case PLAMEN_BROKER_V2_WORKER_GENERATION: return "/workspace/generation";
    case PLAMEN_BROKER_V2_WORKER_PROJECT: return "/workspace/project";
    case PLAMEN_BROKER_V2_WORKER_SCRATCH: return "/workspace/scratch";
    case PLAMEN_BROKER_V2_WORKER_SOURCE: return "/workspace/source";
    case PLAMEN_BROKER_V2_WORKER_STATE: return "/workspace/state";
    default: return NULL;
    }
}

static int build_mounts(uint16_t lane,
    const struct plamen_broker_v2_specialized_worker_fd *worker_fds,
    size_t worker_fd_count,
    struct plamen_broker_v2_apple_lifecycle_mount *mounts,
    char source_paths[][PATH_MAX], size_t *mount_count)
{
    size_t index, count = 0;
    if (worker_fds == NULL || worker_fd_count == 0U || mounts == NULL
        || source_paths == NULL || mount_count == NULL)
        return -1;
    for (index = 0; index < worker_fd_count; ++index) {
        const struct plamen_broker_v2_specialized_worker_fd *item =
            &worker_fds[index];
        const char *target;
        struct stat information;
        if (item->kind == PLAMEN_BROKER_V2_WORKER_IMAGE_MEMBER) continue;
        target = mount_target(lane, item->role);
        if (target == NULL || item->host_fd < 0
            || item->kind != PLAMEN_BROKER_V2_WORKER_DIRECTORY
            || count >= PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX
            || fstat(item->host_fd, &information) != 0
            || !S_ISDIR(information.st_mode)
#ifdef F_GETPATH
            || fcntl(item->host_fd, F_GETPATH, source_paths[count]) != 0
#else
            || 1
#endif
            || source_paths[count][0] != '/')
            return -1;
        mounts[count].source_fd = item->host_fd;
        mounts[count].source_path = source_paths[count];
        mounts[count].target_path = target;
        memcpy(mounts[count].expected_identity_sha256,
            item->native_identity, 32);
        mounts[count].readonly =
            item->access_mode == PLAMEN_BROKER_V2_FD_READ ? 1U : 0U;
        ++count;
    }
    if (count == 0U) return -1;
    *mount_count = count; return 0;
}

int
plamen_broker_v2_specialized_apple_effect_execute_deny_all(
    const struct plamen_broker_v2_specialized_apple_effect_execution *input,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    struct plamen_broker_v2_specialized_apple_runtime runtime;
    struct plamen_broker_v2_specialized_derived_launch derived;
    struct plamen_broker_v2_specialized_worker_request_binding binding;
    struct plamen_broker_v2_specialized_worker_terminal_auth terminal_auth;
    struct plamen_broker_v2_specialized_worker_terminal_observation observed;
    struct plamen_broker_v2_specialized_output_receipt output_receipt;
    struct plamen_broker_v2_specialized_worker_request worker_request;
    struct plamen_broker_v2_specialized_worker_result worker_result;
    struct plamen_broker_v2_specialized_effect_completion completion;
    struct plamen_broker_v2_specialized_worker_fd worker_fds[5];
    struct plamen_broker_v2_apple_lifecycle_mount mounts[
        PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX];
    char source_paths[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX][PATH_MAX];
    uint8_t runtime_authority_sha256[32], operation_key[32];
    uint8_t worker_request_bytes_sha256[32], terminal_hmac_key[32];
    uint8_t *request_bytes = NULL, *terminal = NULL;
    size_t request_size = 0, terminal_size = 0, mount_count = 0;
    char tool_member_id[32];
    const char *cwd = NULL; int request_fd = -1, prepared_created = 0;
    int lookup_status, projection, result = -1;
    memset(&runtime, 0, sizeof(runtime)); memset(&derived, 0, sizeof(derived));
    memset(&binding, 0, sizeof(binding)); memset(&terminal_auth, 0, sizeof(terminal_auth));
    memset(&output_receipt, 0, sizeof(output_receipt));
    memset(&observed, 0, sizeof(observed)); memset(&worker_request, 0, sizeof(worker_request));
    memset(&worker_result, 0, sizeof(worker_result)); memset(&completion, 0, sizeof(completion));
    memset(worker_fds, 0, sizeof(worker_fds));
    memset(mounts, 0, sizeof(mounts)); memset(source_paths, 0, sizeof(source_paths));
    memset(runtime_authority_sha256, 0, sizeof(runtime_authority_sha256));
    memset(operation_key, 0, sizeof(operation_key));
    memset(worker_request_bytes_sha256, 0, sizeof(worker_request_bytes_sha256));
    memset(terminal_hmac_key, 0, sizeof(terminal_hmac_key));
    memset(tool_member_id, 0, sizeof(tool_member_id));
    if (evidence != NULL) memset(evidence, 0, sizeof(*evidence));
    if (input == NULL || input->version !=
            PLAMEN_BROKER_V2_SPECIALIZED_APPLE_EFFECT_EXECUTION_VERSION
        || evidence == NULL || input->store == NULL
        || input->runtime_handoff == NULL || input->view == NULL
        || input->session_key == NULL || zero32(input->session_key)
        || !execution_method(input->view->lane, input->view->method)
        || input->run == NULL || input->dispose_result == NULL
        || input->render_terminal == NULL
        || plamen_broker_v2_specialized_runtime_handoff_authority_sha256(
            input->runtime_handoff, runtime_authority_sha256) != 0
        || derive_operation_key(input->view, runtime_authority_sha256,
            operation_key) != 0)
        goto done;
    projection = input->view->lane
        == PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION;
    lookup_status = plamen_broker_v2_specialized_effect_store_lookup_operation(
        input->store, operation_key, input->view->request_sha256,
        &completion, &terminal, &terminal_size);
    if (lookup_status == PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_OK) {
        if (!equal(completion.runtime_authority_sha256,
                runtime_authority_sha256, 32)
            || evidence_from_completion(input->view, &completion,
                terminal, terminal_size, evidence) != 0)
            goto done;
        terminal = NULL; terminal_size = 0; result = 0; goto done;
    }
    if (lookup_status != PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_NOT_FOUND)
        goto done;
    if (plamen_broker_v2_specialized_worker_tool_anchor_id(input->view,
            tool_member_id) != 0
        || plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
            input->runtime_handoff, input->view->lane,
            (input->view->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
                || input->view->lane
                    == PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION)
                ? "managed_python" : tool_member_id,
            &runtime) != 0
        || bind_slither_dependency_closure(input->runtime_handoff,
            tool_member_id, &runtime) != 0
        || bind_projection_dependency_closure(input->runtime_handoff,
            input->view->lane, &runtime) != 0
        || build_worker_fds(input->view, &runtime, worker_fds) != 0
        || plamen_broker_v2_specialized_worker_launch_derive_apple(
            input->view, &runtime, &derived) != 0
        || plamen_broker_v2_specialized_worker_request_build(input->view,
            worker_fds, 5U, &derived.launch,
            (request_bytes = malloc(
                PLAMEN_BROKER_V2_SPECIALIZED_WORKER_REQUEST_MAX + 1U)),
            PLAMEN_BROKER_V2_SPECIALIZED_WORKER_REQUEST_MAX, &request_size,
            &binding) != 0
        || request_size == 0U
        || build_mounts(input->view->lane, worker_fds,
            5U, mounts, source_paths, &mount_count) != 0
        || (cwd = mount_target(input->view->lane,
            derived.launch.cwd_role)) == NULL)
        goto done;
    /* Outer attached-worker stdin is the exact canonical JSON, without LF.
     * Any stage-specific nested payload framing is already codec-bound. */
    if (plamen_broker_v2_specialized_effect_store_prepare(input->store,
            input->view->lane, input->view->method, operation_key,
            input->view->request_sha256, terminal_hmac_key,
            &prepared_created) != 0
        /* A prepared but uncommitted operation is explicit recovery debt.
         * Normal dispatch never retries or launches a second provider. */
        || !prepared_created
        || plamen_broker_v2_specialized_effect_store_stage_worker_request(
            input->store, operation_key, request_bytes, request_size,
            &request_fd, worker_request_bytes_sha256) != 0
        || derive_policy(operation_key, worker_request_bytes_sha256,
            &binding, worker_request.launch_policy_sha256) != 0)
        goto done;
    worker_request.version = PLAMEN_BROKER_V2_SPECIALIZED_WORKER_VERSION;
    worker_request.lane = input->view->lane; worker_request.method = input->view->method;
    memcpy(worker_request.operation_key, operation_key, 32);
    memcpy(worker_request.request_sha256, input->view->request_sha256, 32);
    memcpy(worker_request.effects_context_sha256,
        input->view->effects_context_sha256, 32);
    memcpy(worker_request.terminal_hmac_key, terminal_hmac_key, 32);
    worker_request.working_directory = cwd;
    worker_request.entrypoint = python_path;
    worker_request.arguments = worker_arguments;
    worker_request.argument_count = sizeof(worker_arguments) / sizeof(worker_arguments[0]);
    worker_request.mounts = mounts; worker_request.mount_count = mount_count;
    worker_request.stdin_fd = request_fd;
    worker_request.memory_bytes = derived.launch.limits.memory_bytes;
    worker_request.timeout_seconds = (uint32_t)
        ((derived.launch.limits.duration_ms + 999U) / 1000U);
    if (worker_request.timeout_seconds == 0U
        || input->run(input->native_effects_context,
            &worker_request, &worker_result) != 0)
        goto done;
    terminal_auth.version = PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_CODEC_VERSION;
    memcpy(terminal_auth.terminal_hmac_key, terminal_hmac_key, 32);
    memcpy(terminal_auth.terminal_hmac_sha256,
        worker_result.guest_terminal_hmac_sha256, 32);
    if (plamen_broker_v2_specialized_worker_terminal_parse(
            worker_result.guest_terminal, worker_result.guest_terminal_size,
            &binding, &terminal_auth, &observed) != 0
        || !equal(observed.terminal_sha256,
            worker_result.guest_terminal_sha256, 32)
        || (projection
            ? render_projection_terminal(input, &binding, &worker_result,
                &observed, worker_request.launch_policy_sha256,
                &terminal, &terminal_size)
            : ((input->view->lane
                    == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
                ? build_snapshot_host_authority(input, &binding,
                    &worker_result, &observed,
                    worker_request.launch_policy_sha256, &output_receipt)
                : build_authenticated_output_receipt(input, &binding,
                    &worker_result, &observed,
                    worker_request.launch_policy_sha256, &output_receipt)) != 0
                || input->render_terminal(input->view, &binding, &observed,
                    &output_receipt, input->session_key,
                    worker_result.lifecycle_receipt_sha256,
                    &terminal, &terminal_size) != 0))
        || terminal == NULL || terminal_size < 2U
        || terminal_size > PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_TERMINAL_MAX
        || (input->view->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
            ? (terminal_size < 3U || terminal[terminal_size - 1U] != '\n'
                || terminal[terminal_size - 2U] == '\n')
            : terminal[terminal_size - 1U] == '\n'))
        goto done;
    completion.version = PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_VERSION;
    completion.lane = input->view->lane; completion.method = input->view->method;
    completion.flags = input->view->flags;
    memcpy(completion.operation_key, operation_key, 32);
    memcpy(completion.request_sha256, input->view->request_sha256, 32);
    memcpy(completion.runtime_authority_sha256, runtime_authority_sha256, 32);
    memcpy(completion.worker_request_sha256, binding.worker_request_sha256, 32);
    memcpy(completion.lifecycle_receipt_sha256,
        worker_result.lifecycle_receipt_sha256, 32);
    if (plamen_broker_v2_sha256(terminal, terminal_size,
            completion.terminal_sha256) != 0
        || plamen_broker_v2_hmac_sha256(terminal_hmac_key,
            method_terminal_hmac_domain, sizeof(method_terminal_hmac_domain),
            terminal, terminal_size,
            completion.terminal_hmac_sha256) != 0)
        goto done;
    memcpy(completion.network_policy_sha256,
        worker_request.launch_policy_sha256, 32);
    memcpy(completion.observed_egress_sha256,
        observed.observed_egress_sha256, 32);
    completion.provider_authenticated = 1U;
    completion.network_policy_enforced = worker_result.network_denied;
    completion.population_zero = worker_result.population_zero;
    completion.cleanup_complete = worker_result.cleanup_complete;
    if (plamen_broker_v2_specialized_effect_store_commit(input->store,
            &completion, terminal, terminal_size) != 0
        || evidence_from_completion(input->view, &completion,
            terminal, terminal_size, evidence) != 0)
        goto done;
    terminal = NULL; terminal_size = 0; result = 0;
done:
    if (request_fd >= 0) (void)close(request_fd);
    if (input != NULL && input->dispose_result != NULL)
        input->dispose_result(&worker_result);
    if (request_bytes != NULL) {
        memset(request_bytes, 0,
            PLAMEN_BROKER_V2_SPECIALIZED_WORKER_REQUEST_MAX + 1U);
        free(request_bytes);
    }
    if (terminal != NULL) { memset(terminal, 0, terminal_size); free(terminal); }
    memset(&runtime, 0, sizeof(runtime)); memset(&derived, 0, sizeof(derived));
    memset(&binding, 0, sizeof(binding)); memset(&terminal_auth, 0, sizeof(terminal_auth));
    memset(&output_receipt, 0, sizeof(output_receipt));
    memset(&observed, 0, sizeof(observed)); memset(&worker_request, 0, sizeof(worker_request));
    memset(&worker_result, 0, sizeof(worker_result)); memset(&completion, 0, sizeof(completion));
    memset(worker_fds, 0, sizeof(worker_fds));
    memset(mounts, 0, sizeof(mounts)); memset(source_paths, 0, sizeof(source_paths));
    memset(runtime_authority_sha256, 0, sizeof(runtime_authority_sha256));
    memset(operation_key, 0, sizeof(operation_key));
    memset(worker_request_bytes_sha256, 0, sizeof(worker_request_bytes_sha256));
    memset(terminal_hmac_key, 0, sizeof(terminal_hmac_key));
    memset(tool_member_id, 0, sizeof(tool_member_id));
    if (result != 0 && evidence != NULL) memset(evidence, 0, sizeof(*evidence));
    return result;
}

int
plamen_broker_v2_specialized_apple_effect_replay_js(
    struct plamen_broker_v2_specialized_effect_store *store,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_specialized_effect_completion *completion,
    uint8_t **terminal, size_t *terminal_size)
{
    const uint8_t *embedded_terminal = NULL;
    uint8_t terminal_sha256[32];
    size_t embedded_terminal_size = 0U;
    int status = -1;
    if (completion != NULL) memset(completion, 0, sizeof(*completion));
    if (terminal != NULL) *terminal = NULL;
    if (terminal_size != NULL) *terminal_size = 0U;
    memset(terminal_sha256, 0, sizeof(terminal_sha256));
    if (store == NULL || view == NULL || completion == NULL
        || terminal == NULL || terminal_size == NULL
        || plamen_broker_v2_specialized_js_replay_terminal_binding(view,
            &embedded_terminal, &embedded_terminal_size,
            terminal_sha256) != 0
        || embedded_terminal == NULL || embedded_terminal_size < 2U
        || plamen_broker_v2_specialized_effect_store_lookup_terminal(store,
            terminal_sha256, completion, terminal, terminal_size)
            != PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_OK
        || completion->version != 1U
        || completion->lane
            != PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        || completion->method
            != PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE
        || completion->flags != 0U
        || completion->provider_authenticated != 1U
        || completion->network_policy_enforced != 1U
        || completion->population_zero != 1U
        || completion->cleanup_complete != 1U
        || zero32(completion->worker_request_sha256)
        || zero32(completion->lifecycle_receipt_sha256)
        || *terminal_size != embedded_terminal_size + 1U
        || (*terminal)[*terminal_size - 1U] != '\n'
        || (*terminal)[*terminal_size - 2U] == '\n'
        || memcmp(*terminal, embedded_terminal, embedded_terminal_size) != 0
        || !equal(completion->terminal_sha256, terminal_sha256, 32U))
        goto done;
    status = 0;
done:
    if (status != 0) {
        if (terminal != NULL && *terminal != NULL) {
            memset(*terminal, 0, *terminal_size);
            free(*terminal);
            *terminal = NULL;
        }
        if (terminal_size != NULL) *terminal_size = 0U;
        if (completion != NULL) memset(completion, 0, sizeof(*completion));
    }
    memset(terminal_sha256, 0, sizeof(terminal_sha256));
    return status;
}

int
plamen_broker_v2_specialized_apple_effect_recover_projection(
    struct plamen_broker_v2_specialized_effect_store *store,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_specialized_effect_completion *completion,
    uint8_t **terminal, size_t *terminal_size)
{
    static const uint8_t prefix[] = "{\"receipt_sha256\":\"";
    static const uint8_t suffix[] = "\"}";
    uint8_t terminal_sha256[32];
    size_t index;
    int status = -1;
    if (completion != NULL) memset(completion, 0, sizeof(*completion));
    if (terminal != NULL) *terminal = NULL;
    if (terminal_size != NULL) *terminal_size = 0U;
    memset(terminal_sha256, 0, sizeof(terminal_sha256));
    if (store == NULL || view == NULL || completion == NULL
        || terminal == NULL || terminal_size == NULL
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
        || view->method != PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER
        || view->flags != PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER
        || view->fd_count != 0U || view->payload == NULL
        || view->payload_size != sizeof(prefix) - 1U + 64U
            + sizeof(suffix) - 1U
        || memcmp(view->payload, prefix, sizeof(prefix) - 1U) != 0
        || memcmp(view->payload + sizeof(prefix) - 1U + 64U,
            suffix, sizeof(suffix) - 1U) != 0)
        goto done;
    for (index = 0U; index < 32U; ++index) {
        uint8_t high = view->payload[sizeof(prefix) - 1U + index * 2U];
        uint8_t low = view->payload[sizeof(prefix) + index * 2U];
        if (!((high >= '0' && high <= '9')
                || (high >= 'a' && high <= 'f'))
            || !((low >= '0' && low <= '9')
                || (low >= 'a' && low <= 'f')))
            goto done;
        terminal_sha256[index] = (uint8_t)(
            ((high <= '9' ? high - '0' : high - 'a' + 10U) << 4U)
            | (low <= '9' ? low - '0' : low - 'a' + 10U));
    }
    if (zero32(terminal_sha256)
        || plamen_broker_v2_specialized_effect_store_lookup_terminal(store,
            terminal_sha256, completion, terminal, terminal_size)
            != PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_OK
        || completion->version
            != PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_VERSION
        || completion->lane
            != PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
        || completion->method
            != PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
        || completion->flags != 0U
        || completion->provider_authenticated != 1U
        || completion->network_policy_enforced != 1U
        || completion->population_zero != 1U
        || completion->cleanup_complete != 1U
        || zero32(completion->worker_request_sha256)
        || zero32(completion->lifecycle_receipt_sha256)
        || zero32(completion->network_policy_sha256)
        || *terminal_size < 2U
        || (*terminal)[*terminal_size - 1U] == '\n'
        || !equal(completion->terminal_sha256, terminal_sha256, 32U))
        goto done;
    status = 0;
done:
    if (status != 0) {
        if (terminal != NULL && *terminal != NULL) {
            memset(*terminal, 0, *terminal_size);
            free(*terminal);
            *terminal = NULL;
        }
        if (terminal_size != NULL) *terminal_size = 0U;
        if (completion != NULL) memset(completion, 0, sizeof(*completion));
    }
    memset(terminal_sha256, 0, sizeof(terminal_sha256));
    return status;
}
