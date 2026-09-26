#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_fuzz_campaign.h"
#include "../include/plamen_broker_v2.h"

#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FUZZ_SERVICE_SESSION_MAGIC UINT64_C(0x504c4d46535f5331)
#define FUZZ_SERVICE_LEASE_MAGIC UINT64_C(0x504c4d46535f4c31)
#define FUZZ_SERVICE_TERMINAL_MAGIC UINT64_C(0x504c4d46535f5431)
#define FUZZ_SERVICE_MOUNT_COUNT 4U

struct plamen_broker_v2_fuzz_service_session {
    uint64_t magic;
    _Atomic uint8_t in_flight;
    struct plamen_broker_v2_fuzz_campaign_authority authority;
    struct plamen_broker_v2_apple_container_admission_receipt admission;
    char cli_path[1025];
    char runtime_image_reference[PLAMEN_BROKER_V2_APPLE_CONTAINER_REFERENCE_MAX];
};

struct plamen_broker_v2_fuzz_service_continuation {
    uint64_t magic;
    _Atomic uint8_t consumed;
    struct plamen_broker_v2_fuzz_service_session *session;
    _Atomic uint8_t owns_in_flight;
    struct plamen_broker_v2_fuzz_campaign_request request;
    struct plamen_broker_v2_apple_lifecycle_mount mounts[FUZZ_SERVICE_MOUNT_COUNT];
    char mount_paths[FUZZ_SERVICE_MOUNT_COUNT]
        [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX + 1U];
    char attempt_id[129];
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    char workspace_root[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX + 1U];
    char argv_text[PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX]
        [PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARGUMENT_TEXT_MAX];
    const char *argv[PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX];
    const char *environment[PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ENV_MAX];
    int mount_fds[FUZZ_SERVICE_MOUNT_COUNT];
    uint8_t *receipt_bytes;
    size_t receipt_size;
    uint8_t secure_receipt_sha256[32];
};

struct plamen_broker_v2_fuzz_service_terminal {
    uint64_t magic;
    uint8_t *bytes;
    size_t size;
    uint8_t sha256[32];
};

static int nonzero32(const uint8_t value[32])
{
    uint8_t joined = 0U; size_t index;
    if (value == NULL) return 0;
    for (index = 0U; index < 32U; ++index) joined |= value[index];
    return joined != 0U;
}

static int equal32(const uint8_t left[32], const uint8_t right[32])
{
    uint8_t joined = 0U; size_t index;
    if (left == NULL || right == NULL) return 0;
    for (index = 0U; index < 32U; ++index)
        joined |= (uint8_t)(left[index] ^ right[index]);
    return joined == 0U;
}

static int safe_json_text(const char *value, size_t maximum, int absolute)
{
    size_t size, index;
    if (value == NULL || (size = strlen(value)) == 0U || size > maximum
        || (absolute && value[0] != '/')) return 0;
    for (index = 0U; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < 0x20U || byte >= 0x7fU || byte == '"' || byte == '\\')
            return 0;
    }
    return strstr(value, "/../") == NULL
        && strncmp(value, "../", 3U) != 0
        && !(size >= 3U && strcmp(value + size - 3U, "/..") == 0);
}

static int duplicate_fd(int source)
{
#ifdef F_DUPFD_CLOEXEC
    return fcntl(source, F_DUPFD_CLOEXEC, 3);
#else
    int result = dup(source);
    if (result >= 0 && fcntl(result, F_SETFD, FD_CLOEXEC) != 0) {
        (void)close(result); result = -1;
    }
    return result;
#endif
}

static void hex32(const uint8_t input[32], char output[65])
{
    static const char alphabet[] = "0123456789abcdef"; size_t index;
    for (index = 0U; index < 32U; ++index) {
        output[index * 2U] = alphabet[input[index] >> 4U];
        output[index * 2U + 1U] = alphabet[input[index] & 15U];
    }
    output[64] = '\0';
}

static int derive(const uint8_t key[32], const char *domain,
    const uint8_t *payload, size_t payload_size, uint8_t output[32])
{
    return plamen_broker_v2_hmac_sha256(key,
        (const uint8_t *)domain, strlen(domain) + 1U,
        payload, payload_size, output) == 0 && nonzero32(output) ? 0 : -1;
}

static int authority_shape(
    const struct plamen_broker_v2_fuzz_campaign_authority *authority)
{
    return authority != NULL
        && authority->version == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_VERSION
        && authority->cli_fd >= 0 && authority->cwd_fd >= 0
        && authority->stdin_fd >= 0 && authority->state_directory_fd >= 0
        && safe_json_text(authority->cli_path, 1024U, 1)
        && authority->admission != NULL
        && plamen_broker_v2_apple_container_receipt_validate(
            authority->admission) == 0
        && authority->custody_client != NULL
        && nonzero32(authority->authority_binding_sha256)
        && safe_json_text(authority->runtime_image_reference,
            PLAMEN_BROKER_V2_APPLE_CONTAINER_REFERENCE_MAX - 1U, 0)
        && strcmp(authority->admission->runtime_image_reference,
            authority->runtime_image_reference) == 0;
}

int
plamen_broker_v2_fuzz_service_acquire(
    const struct plamen_broker_v2_fuzz_campaign_authority *authority,
    struct plamen_broker_v2_fuzz_service_session **output)
{
    struct plamen_broker_v2_fuzz_service_session *session = NULL;
    int duplicated[4] = {-1, -1, -1, -1}; int sources[4]; size_t index;
    if (output != NULL) *output = NULL;
    if (output == NULL || !authority_shape(authority)) return -1;
    session = calloc(1U, sizeof(*session));
    if (session == NULL) return -1;
    session->authority.cli_fd = -1; session->authority.cwd_fd = -1;
    session->authority.stdin_fd = -1; session->authority.state_directory_fd = -1;
    sources[0] = authority->cli_fd; sources[1] = authority->cwd_fd;
    sources[2] = authority->stdin_fd; sources[3] = authority->state_directory_fd;
    for (index = 0U; index < 4U; ++index) {
        duplicated[index] = duplicate_fd(sources[index]);
        if (duplicated[index] < 0) goto failed;
    }
    session->authority = *authority;
    session->authority.cli_fd = duplicated[0];
    session->authority.cwd_fd = duplicated[1];
    session->authority.stdin_fd = duplicated[2];
    session->authority.state_directory_fd = duplicated[3];
    session->admission = *authority->admission;
    session->authority.admission = &session->admission;
    memcpy(session->cli_path, authority->cli_path,
        strlen(authority->cli_path) + 1U);
    memcpy(session->runtime_image_reference, authority->runtime_image_reference,
        strlen(authority->runtime_image_reference) + 1U);
    session->authority.cli_path = session->cli_path;
    session->authority.runtime_image_reference = session->runtime_image_reference;
    memset(session->authority.provider_preflight_sha256, 0, 32U);
    session->magic = FUZZ_SERVICE_SESSION_MAGIC;
    atomic_init(&session->in_flight, 0U);
    *output = session;
    return 0;
failed:
    if (session != NULL) {
        for (index = 0U; index < 4U; ++index)
            if (duplicated[index] >= 0) (void)close(duplicated[index]);
        plamen_broker_v2_secure_zero(session, sizeof(*session)); free(session);
    }
    return -1;
}

void
plamen_broker_v2_fuzz_service_session_dispose(
    struct plamen_broker_v2_fuzz_service_session *session)
{
    if (session == NULL) return;
    if (session->magic == FUZZ_SERVICE_SESSION_MAGIC) {
        if (session->authority.cli_fd >= 0) (void)close(session->authority.cli_fd);
        if (session->authority.cwd_fd >= 0) (void)close(session->authority.cwd_fd);
        if (session->authority.stdin_fd >= 0) (void)close(session->authority.stdin_fd);
        if (session->authority.state_directory_fd >= 0)
            (void)close(session->authority.state_directory_fd);
    }
    plamen_broker_v2_secure_zero(session, sizeof(*session)); free(session);
}

static int admission_shape(
    const struct plamen_broker_v2_fuzz_service_admission_request *request)
{
    size_t index;
    if (request == NULL
        || request->version != PLAMEN_BROKER_V2_FUZZ_SERVICE_ADMISSION_VERSION
        || (request->tool != PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE
            && request->tool != PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_MEDUSA)
        || !nonzero32(request->authority_sha256)
        || !nonzero32(request->phase_io_binding_sha256)
        || !nonzero32(request->admission_request_sha256)
        || !nonzero32(request->provider_preflight_sha256)
        || !safe_json_text(request->attempt_id, 128U, 0)
        || !safe_json_text(request->workspace_root,
            PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX, 1)
        || request->guest_argv == NULL || request->guest_argc == 0U
        || request->guest_argc > PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX
        || request->timeout_seconds == 0U || request->timeout_seconds > 3600U
        || request->rosetta_required > 1U) return 0;
    for (index = 0U; index < request->guest_argc; ++index)
        if (!safe_json_text(request->guest_argv[index], 4096U,
                index == 0U)) return 0;
    return 1;
}

static int render_receipt(
    const struct plamen_broker_v2_fuzz_service_continuation *lease,
    const struct plamen_broker_v2_apple_lifecycle_commitments *commitments,
    const uint8_t payload_digest[32], int include_digest,
    uint8_t **bytes, size_t *size)
{
    char admission[65], authority[65], cli[65], executable[65], launch[65];
    char phase_io[65], preflight[65], provenance[65], spec[65], payload[65];
    static const char unsigned_format[] =
        "{\"apple_container_attempt_id\":\"%s\","
        "\"apple_container_cli_executable_sha256\":\"%s\","
        "\"apple_container_id\":\"%s\","
        "\"apple_container_launch_policy_sha256\":\"%s\","
        "\"apple_container_preflight_sha256\":\"%s\","
        "\"apple_container_provider_provenance_sha256\":\"%s\","
        "\"apple_container_spec_sha256\":\"%s\","
        "\"authority_digest\":\"%s\","
        "\"filesystem_policy\":\"READONLY_INPUTS_EXPLICIT_WRITE_LANES\","
        "\"guest_cwd\":\"%s\",\"guest_environment\":[\"%s\"],"
        "\"guest_executable\":\"%s\","
        "\"guest_executable_sha256\":\"%s\","
        "\"network_policy\":\"DENY\","
        "\"phase_io_binding_digest\":\"%s\","
        "\"process_tree_policy\":\"APPLE_CONTAINER_GUEST_VM_STOP_V2\","
        "\"rosetta_required\":%s,"
        "\"schema_version\":\"%s\",\"status\":\"ENFORCED\","
        "\"workspace_root\":\"%s\"}";
    static const char signed_format[] =
        "{\"apple_container_attempt_id\":\"%s\","
        "\"apple_container_cli_executable_sha256\":\"%s\","
        "\"apple_container_id\":\"%s\","
        "\"apple_container_launch_policy_sha256\":\"%s\","
        "\"apple_container_preflight_sha256\":\"%s\","
        "\"apple_container_provider_provenance_sha256\":\"%s\","
        "\"apple_container_spec_sha256\":\"%s\","
        "\"authority_digest\":\"%s\","
        "\"filesystem_policy\":\"READONLY_INPUTS_EXPLICIT_WRITE_LANES\","
        "\"guest_cwd\":\"%s\",\"guest_environment\":[\"%s\"],"
        "\"guest_executable\":\"%s\","
        "\"guest_executable_sha256\":\"%s\","
        "\"network_policy\":\"DENY\",\"payload_digest\":\"%s\","
        "\"phase_io_binding_digest\":\"%s\","
        "\"process_tree_policy\":\"APPLE_CONTAINER_GUEST_VM_STOP_V2\","
        "\"rosetta_required\":%s,"
        "\"schema_version\":\"%s\",\"status\":\"ENFORCED\","
        "\"workspace_root\":\"%s\"}";
    const char *anchor, *format; int needed, written; uint8_t *result;
    if (bytes != NULL) *bytes = NULL;
    if (size != NULL) *size = 0U;
    if (lease == NULL || commitments == NULL || bytes == NULL || size == NULL)
        return -1;
    anchor = lease->request.guest_executable;
    hex32(lease->request.request_sha256, admission);
    hex32(lease->request.authority_sha256, authority);
    hex32(lease->request.cli_executable_sha256, cli);
    hex32(lease->request.guest_executable_sha256, executable);
    hex32(lease->request.launch_policy_sha256, launch);
    hex32(lease->request.phase_io_binding_sha256, phase_io);
    hex32(lease->request.provider_preflight_sha256, preflight);
    hex32(lease->request.provider_provenance_sha256, provenance);
    hex32(commitments->spec_sha256, spec);
    if (include_digest) hex32(payload_digest, payload);
    format = include_digest ? signed_format : unsigned_format;
    if (include_digest)
        needed = snprintf(NULL, 0U, format,
            lease->attempt_id, cli, lease->container_id, launch, preflight,
            provenance, spec, authority, PLAMEN_BROKER_V2_FUZZ_CWD,
            PLAMEN_BROKER_V2_FUZZ_PATH, anchor, executable, payload, phase_io,
            lease->request.rosetta_required ? "true" : "false",
            PLAMEN_BROKER_V2_FUZZ_SERVICE_RECEIPT_SCHEMA,
            lease->workspace_root);
    else
        needed = snprintf(NULL, 0U, format,
            lease->attempt_id, cli, lease->container_id, launch, preflight,
            provenance, spec, authority, PLAMEN_BROKER_V2_FUZZ_CWD,
            PLAMEN_BROKER_V2_FUZZ_PATH, anchor, executable, phase_io,
            lease->request.rosetta_required ? "true" : "false",
            PLAMEN_BROKER_V2_FUZZ_SERVICE_RECEIPT_SCHEMA,
            lease->workspace_root);
    if (needed <= 0) return -1;
    result = malloc((size_t)needed + 1U);
    if (result == NULL) return -1;
    if (include_digest)
        written = snprintf((char *)result, (size_t)needed + 1U, format,
            lease->attempt_id, cli, lease->container_id, launch, preflight,
            provenance, spec, authority, PLAMEN_BROKER_V2_FUZZ_CWD,
            PLAMEN_BROKER_V2_FUZZ_PATH, anchor, executable, payload, phase_io,
            lease->request.rosetta_required ? "true" : "false",
            PLAMEN_BROKER_V2_FUZZ_SERVICE_RECEIPT_SCHEMA,
            lease->workspace_root);
    else
        written = snprintf((char *)result, (size_t)needed + 1U, format,
            lease->attempt_id, cli, lease->container_id, launch, preflight,
            provenance, spec, authority, PLAMEN_BROKER_V2_FUZZ_CWD,
            PLAMEN_BROKER_V2_FUZZ_PATH, anchor, executable, phase_io,
            lease->request.rosetta_required ? "true" : "false",
            PLAMEN_BROKER_V2_FUZZ_SERVICE_RECEIPT_SCHEMA,
            lease->workspace_root);
    if (written != needed) goto failed;
    *bytes = result; *size = (size_t)needed; return 0;
failed:
    plamen_broker_v2_secure_zero(result, (size_t)needed + 1U); free(result);
    return -1;
}

int
plamen_broker_v2_fuzz_service_admit(
    struct plamen_broker_v2_fuzz_service_session *session,
    const struct plamen_broker_v2_fuzz_service_admission_request *input,
    const struct plamen_broker_v2_apple_lifecycle_mount *mounts,
    size_t mount_count,
    struct plamen_broker_v2_fuzz_service_admission_receipt *receipt,
    struct plamen_broker_v2_fuzz_service_continuation **output)
{
    static const char *const targets[FUZZ_SERVICE_MOUNT_COUNT] = {
        "/workspace/source", "/workspace/scratch",
        "/workspace/state", "/workspace/project"
    };
    struct plamen_broker_v2_fuzz_service_continuation *lease = NULL;
    struct plamen_broker_v2_fuzz_campaign_authority authority;
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    uint8_t *unsigned_bytes = NULL; size_t unsigned_size = 0U, index;
    uint8_t payload_sha256[32], expected_in_flight = 0U;
    const uint8_t *tool_sha256;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (output != NULL) *output = NULL;
    memset(&authority, 0, sizeof(authority));
    memset(&commitments, 0, sizeof(commitments));
    memset(payload_sha256, 0, sizeof(payload_sha256));
    if (session == NULL || session->magic != FUZZ_SERVICE_SESSION_MAGIC
        || !admission_shape(input) || mounts == NULL
        || mount_count != FUZZ_SERVICE_MOUNT_COUNT
        || receipt == NULL || output == NULL) return -1;
    tool_sha256 = input->tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE
        ? session->authority.forge_executable_sha256
        : session->authority.medusa_executable_sha256;
    if (!nonzero32(tool_sha256)) return -1;
    lease = calloc(1U, sizeof(*lease));
    if (lease == NULL) return -1;
    for (index = 0U; index < FUZZ_SERVICE_MOUNT_COUNT; ++index)
        lease->mount_fds[index] = -1;
    atomic_init(&lease->owns_in_flight, 0U);
    if (!atomic_compare_exchange_strong_explicit(&session->in_flight,
            &expected_in_flight, 1U, memory_order_acq_rel,
            memory_order_acquire)) goto failed;
    lease->session = session;
    atomic_store_explicit(&lease->owns_in_flight, 1U, memory_order_release);
    memcpy(lease->attempt_id, input->attempt_id, strlen(input->attempt_id) + 1U);
    memcpy(lease->workspace_root, input->workspace_root,
        strlen(input->workspace_root) + 1U);
    for (index = 0U; index < input->guest_argc; ++index) {
        memcpy(lease->argv_text[index], input->guest_argv[index],
            strlen(input->guest_argv[index]) + 1U);
        lease->argv[index] = lease->argv_text[index];
    }
    lease->request.version = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_VERSION;
    lease->request.tool = input->tool;
    memcpy(lease->request.request_sha256, input->admission_request_sha256, 32U);
    memcpy(lease->request.authority_sha256, input->authority_sha256, 32U);
    memcpy(lease->request.prepared_campaign_sha256,
        input->admission_request_sha256, 32U);
    memcpy(lease->request.secure_launcher_sha256,
        input->admission_request_sha256, 32U);
    memcpy(lease->request.phase_io_binding_sha256,
        input->phase_io_binding_sha256, 32U);
    memcpy(lease->request.provider_preflight_sha256,
        input->provider_preflight_sha256, 32U);
    memcpy(lease->request.provider_provenance_sha256,
        session->admission.provider_provenance_sha256, 32U);
    memcpy(lease->request.cli_executable_sha256,
        session->admission.cli_sha256, 32U);
    memcpy(lease->request.guest_executable_sha256, tool_sha256, 32U);
    /* The RPC-authenticated session binding is the secret derivation key;
     * input->authority_sha256 is the public fuzz-workspace authority carried
     * into the receipt and container ID.  Conflating the two would sever the
     * Python workspace/phase-IO provenance chain. */
    if (derive(session->authority.authority_binding_sha256,
            "PLAMEN-FUZZ-SERVICE-OPERATION-V1",
            input->admission_request_sha256, 32U,
            lease->request.operation_key) != 0
        || derive(session->authority.authority_binding_sha256,
            "PLAMEN-FUZZ-SERVICE-LAUNCH-POLICY-V1",
            input->admission_request_sha256, 32U,
            lease->request.launch_policy_sha256) != 0
        || plamen_broker_v2_apple_container_derive_id(
            lease->request.authority_sha256, lease->request.operation_key,
            lease->container_id) != 0) goto failed;
    memcpy(lease->request.spec_sha256, input->admission_request_sha256, 32U);
    lease->request.container_id = lease->container_id;
    lease->request.attempt_id = lease->attempt_id;
    lease->request.guest_executable = input->tool
        == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE
        ? PLAMEN_BROKER_V2_FUZZ_FORGE_ANCHOR
        : PLAMEN_BROKER_V2_FUZZ_MEDUSA_ANCHOR;
    /* argv[0] is always service-derived; the caller supplies only its family
     * and arguments, so an alternate host/guest executable cannot be smuggled. */
    if (strcmp(lease->argv[0], lease->request.guest_executable) != 0)
        goto failed;
    lease->request.guest_argv = lease->argv;
    lease->request.guest_argc = input->guest_argc;
    lease->environment[0] = PLAMEN_BROKER_V2_FUZZ_PATH;
    lease->request.guest_environment = lease->environment;
    lease->request.guest_environment_count = 1U;
    lease->request.guest_cwd = PLAMEN_BROKER_V2_FUZZ_CWD;
    lease->request.timeout_seconds = input->timeout_seconds;
    lease->request.rosetta_required = input->rosetta_required;
    for (index = 0U; index < FUZZ_SERVICE_MOUNT_COUNT; ++index) {
        uint8_t identity[32];
        if (mounts[index].source_fd < 0 || mounts[index].source_path == NULL
            || mounts[index].target_path == NULL
            || strcmp(mounts[index].target_path, targets[index]) != 0
            || mounts[index].readonly != (index == 0U || index == 3U)
            || !safe_json_text(mounts[index].source_path,
                PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX, 1)
            || plamen_broker_v2_fd_identity(mounts[index].source_fd,
                identity) != 0
            || !equal32(identity, mounts[index].expected_identity_sha256))
            goto failed;
        lease->mount_fds[index] = duplicate_fd(mounts[index].source_fd);
        if (lease->mount_fds[index] < 0) goto failed;
        memcpy(lease->mount_paths[index], mounts[index].source_path,
            strlen(mounts[index].source_path) + 1U);
        lease->mounts[index] = mounts[index];
        lease->mounts[index].source_fd = lease->mount_fds[index];
        lease->mounts[index].source_path = lease->mount_paths[index];
    }
    lease->request.mounts = lease->mounts;
    lease->request.mount_count = FUZZ_SERVICE_MOUNT_COUNT;
    authority = session->authority;
    memcpy(authority.provider_preflight_sha256,
        input->provider_preflight_sha256, 32U);
    if (plamen_broker_v2_fuzz_campaign_prepare(
            &authority, &lease->request, &commitments) != 0) goto failed;
    memcpy(lease->request.spec_sha256, commitments.spec_sha256, 32U);
    if (plamen_broker_v2_fuzz_campaign_prepare(
            &authority, &lease->request, &commitments) != 0
        || render_receipt(lease, &commitments, payload_sha256, 0,
            &unsigned_bytes, &unsigned_size) != 0
        || plamen_broker_v2_sha256(unsigned_bytes, unsigned_size,
            payload_sha256) != 0
        || render_receipt(lease, &commitments, payload_sha256, 1,
            &lease->receipt_bytes, &lease->receipt_size) != 0
        || plamen_broker_v2_sha256(lease->receipt_bytes, lease->receipt_size,
            lease->secure_receipt_sha256) != 0) goto failed;
    lease->magic = FUZZ_SERVICE_LEASE_MAGIC;
    atomic_init(&lease->consumed, 0U);
    receipt->version = PLAMEN_BROKER_V2_FUZZ_SERVICE_ADMISSION_VERSION;
    memcpy(receipt->admission_request_sha256,
        input->admission_request_sha256, 32U);
    memcpy(receipt->authority_sha256, input->authority_sha256, 32U);
    memcpy(receipt->phase_io_binding_sha256,
        input->phase_io_binding_sha256, 32U);
    memcpy(receipt->provider_preflight_sha256,
        input->provider_preflight_sha256, 32U);
    memcpy(receipt->provider_provenance_sha256,
        session->admission.provider_provenance_sha256, 32U);
    memcpy(receipt->cli_executable_sha256,
        session->admission.cli_sha256, 32U);
    memcpy(receipt->guest_executable_sha256, tool_sha256, 32U);
    memcpy(receipt->spec_sha256, commitments.spec_sha256, 32U);
    memcpy(receipt->launch_policy_sha256,
        lease->request.launch_policy_sha256, 32U);
    memcpy(receipt->secure_receipt_sha256,
        lease->secure_receipt_sha256, 32U);
    memcpy(receipt->container_id, lease->container_id,
        strlen(lease->container_id) + 1U);
    receipt->canonical_secure_receipt = lease->receipt_bytes;
    receipt->canonical_secure_receipt_size = lease->receipt_size;
    *output = lease;
    plamen_broker_v2_secure_zero(unsigned_bytes, unsigned_size);
    free(unsigned_bytes);
    plamen_broker_v2_secure_zero(payload_sha256, sizeof(payload_sha256));
    return 0;
failed:
    if (unsigned_bytes != NULL) {
        plamen_broker_v2_secure_zero(unsigned_bytes, unsigned_size);
        free(unsigned_bytes);
    }
    plamen_broker_v2_secure_zero(payload_sha256, sizeof(payload_sha256));
    plamen_broker_v2_fuzz_service_continuation_dispose(lease);
    return -1;
}

int
plamen_broker_v2_fuzz_service_project_secure_receipt(
    const struct plamen_broker_v2_fuzz_service_continuation *lease,
    uint8_t **bytes, size_t *size)
{
    uint8_t *copy;
    if (bytes != NULL) *bytes = NULL;
    if (size != NULL) *size = 0U;
    if (lease == NULL || lease->magic != FUZZ_SERVICE_LEASE_MAGIC
        || bytes == NULL || size == NULL || lease->receipt_bytes == NULL
        || lease->receipt_size == 0U) return -1;
    copy = malloc(lease->receipt_size);
    if (copy == NULL) return -1;
    memcpy(copy, lease->receipt_bytes, lease->receipt_size);
    *bytes = copy; *size = lease->receipt_size; return 0;
}

int
plamen_broker_v2_fuzz_service_execute(
    struct plamen_broker_v2_fuzz_service_session *session,
    struct plamen_broker_v2_fuzz_service_continuation *lease,
    const uint8_t prepared_campaign_sha256[32],
    const uint8_t secure_receipt_sha256[32],
    struct plamen_broker_v2_fuzz_service_terminal **output)
{
    static const char domain[] = "PLAMEN-FUZZ-SERVICE-EXECUTE-V1";
    struct plamen_broker_v2_fuzz_service_terminal *terminal = NULL;
    struct plamen_broker_v2_fuzz_campaign_authority authority;
    struct plamen_broker_v2_fuzz_campaign_result result;
    uint8_t joined[96]; uint8_t expected = 0U;
    if (output != NULL) *output = NULL;
    memset(&authority, 0, sizeof(authority)); memset(&result, 0, sizeof(result));
    memset(joined, 0, sizeof(joined));
    if (session == NULL || session->magic != FUZZ_SERVICE_SESSION_MAGIC
        || lease == NULL || lease->magic != FUZZ_SERVICE_LEASE_MAGIC
        || lease->session != session || output == NULL
        || !nonzero32(prepared_campaign_sha256)
        || !equal32(secure_receipt_sha256, lease->secure_receipt_sha256)
        || !atomic_compare_exchange_strong_explicit(&lease->consumed,
            &expected, 1U, memory_order_acq_rel, memory_order_acquire))
        return -1;
    memcpy(lease->request.prepared_campaign_sha256,
        prepared_campaign_sha256, 32U);
    memcpy(lease->request.secure_launcher_sha256,
        secure_receipt_sha256, 32U);
    memcpy(joined, lease->request.request_sha256, 32U);
    memcpy(joined + 32U, prepared_campaign_sha256, 32U);
    memcpy(joined + 64U, secure_receipt_sha256, 32U);
    if (derive(session->authority.authority_binding_sha256, domain,
            joined, sizeof(joined), lease->request.request_sha256) != 0)
        goto failed;
    authority = session->authority;
    memcpy(authority.provider_preflight_sha256,
        lease->request.provider_preflight_sha256, 32U);
    if (plamen_broker_v2_fuzz_campaign_execute(
            &authority, &lease->request, &result) != 0) goto failed;
    terminal = calloc(1U, sizeof(*terminal));
    if (terminal == NULL
        || plamen_broker_v2_fuzz_campaign_result_render(
            &lease->request, &authority, &result,
            &terminal->bytes, &terminal->size) != 0
        || plamen_broker_v2_sha256(terminal->bytes, terminal->size,
            terminal->sha256) != 0) goto failed;
    terminal->magic = FUZZ_SERVICE_TERMINAL_MAGIC;
    *output = terminal; terminal = NULL;
    (void)atomic_exchange_explicit(
        &lease->owns_in_flight, 0U, memory_order_acq_rel);
    atomic_store_explicit(&session->in_flight, 0U, memory_order_release);
    plamen_broker_v2_fuzz_campaign_result_dispose(&result);
    plamen_broker_v2_secure_zero(joined, sizeof(joined));
    return 0;
failed:
    if (lease != NULL && atomic_exchange_explicit(
            &lease->owns_in_flight, 0U, memory_order_acq_rel) != 0U)
        atomic_store_explicit(&session->in_flight, 0U, memory_order_release);
    plamen_broker_v2_fuzz_campaign_result_dispose(&result);
    plamen_broker_v2_fuzz_service_terminal_dispose(terminal);
    plamen_broker_v2_secure_zero(joined, sizeof(joined));
    return -1;
}

int
plamen_broker_v2_fuzz_service_project_terminal(
    const struct plamen_broker_v2_fuzz_service_terminal *terminal,
    uint8_t **bytes, size_t *size)
{
    uint8_t observed[32], *copy;
    if (bytes != NULL) *bytes = NULL;
    if (size != NULL) *size = 0U;
    memset(observed, 0, sizeof(observed));
    if (terminal == NULL || terminal->magic != FUZZ_SERVICE_TERMINAL_MAGIC
        || bytes == NULL || size == NULL || terminal->bytes == NULL
        || terminal->size == 0U
        || plamen_broker_v2_sha256(terminal->bytes, terminal->size,
            observed) != 0 || !equal32(observed, terminal->sha256)) return -1;
    copy = malloc(terminal->size);
    if (copy == NULL) return -1;
    memcpy(copy, terminal->bytes, terminal->size);
    *bytes = copy; *size = terminal->size;
    plamen_broker_v2_secure_zero(observed, sizeof(observed)); return 0;
}

void
plamen_broker_v2_fuzz_service_continuation_dispose(
    struct plamen_broker_v2_fuzz_service_continuation *lease)
{
    size_t index;
    if (lease == NULL) return;
    if (atomic_exchange_explicit(
            &lease->owns_in_flight, 0U, memory_order_acq_rel) != 0U
        && lease->session != NULL
        && lease->session->magic == FUZZ_SERVICE_SESSION_MAGIC)
        atomic_store_explicit(
            &lease->session->in_flight, 0U, memory_order_release);
    for (index = 0U; index < FUZZ_SERVICE_MOUNT_COUNT; ++index)
        if (lease->mount_fds[index] >= 0) (void)close(lease->mount_fds[index]);
    if (lease->receipt_bytes != NULL) {
        plamen_broker_v2_secure_zero(lease->receipt_bytes, lease->receipt_size);
        free(lease->receipt_bytes);
    }
    plamen_broker_v2_secure_zero(lease, sizeof(*lease)); free(lease);
}

void
plamen_broker_v2_fuzz_service_terminal_dispose(
    struct plamen_broker_v2_fuzz_service_terminal *terminal)
{
    if (terminal == NULL) return;
    if (terminal->bytes != NULL) {
        plamen_broker_v2_secure_zero(terminal->bytes, terminal->size);
        free(terminal->bytes);
    }
    plamen_broker_v2_secure_zero(terminal, sizeof(*terminal)); free(terminal);
}
