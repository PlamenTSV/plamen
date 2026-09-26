#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_fuzz_campaign.h"
#include "../include/plamen_broker_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CPUS 2U
#define FUZZ_DEFAULT_MEMORY (4ULL * 1024ULL * 1024ULL * 1024ULL)
#define FUZZ_ENV_ENTRYPOINT "/usr/bin/env"
#define FUZZ_FORGE_ANCHOR PLAMEN_BROKER_V2_FUZZ_FORGE_ANCHOR
#define FUZZ_MEDUSA_ANCHOR PLAMEN_BROKER_V2_FUZZ_MEDUSA_ANCHOR
#define FUZZ_CWD PLAMEN_BROKER_V2_FUZZ_CWD
#define FUZZ_PATH PLAMEN_BROKER_V2_FUZZ_PATH

static int nonzero32(const uint8_t value[32])
{
    uint8_t aggregate = 0U; size_t index;
    if (value == NULL) return 0;
    for (index = 0U; index < 32U; ++index) aggregate |= value[index];
    return aggregate != 0U;
}

static int equal32(const uint8_t left[32], const uint8_t right[32])
{
    uint8_t aggregate = 0U; size_t index;
    if (left == NULL || right == NULL) return 0;
    for (index = 0U; index < 32U; ++index)
        aggregate |= (uint8_t)(left[index] ^ right[index]);
    return aggregate == 0U;
}

static int safe_text(const char *value, size_t maximum)
{
    size_t index, size;
    if (value == NULL || (size = strlen(value)) == 0U || size > maximum)
        return 0;
    for (index = 0U; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < 0x20U || byte == 0x7fU) return 0;
    }
    return 1;
}

static int safe_id(const char *value, size_t maximum)
{
    size_t index, size;
    if (!safe_text(value, maximum)) return 0;
    size = strlen(value);
    for (index = 0U; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (!((byte >= 'a' && byte <= 'z')
                || (byte >= 'A' && byte <= 'Z')
                || (byte >= '0' && byte <= '9')
                || byte == '.' || byte == '_' || byte == '-'))
            return 0;
    }
    return value[0] != '.' && value[0] != '-';
}

static const char *tool_anchor(uint16_t tool)
{
    if (tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE)
        return FUZZ_FORGE_ANCHOR;
    if (tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_MEDUSA)
        return FUZZ_MEDUSA_ANCHOR;
    return NULL;
}

int
plamen_broker_v2_fuzz_campaign_request_validate(
    const struct plamen_broker_v2_fuzz_campaign_request *request)
{
    const char *anchor; char expected_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    size_t index;
    if (request == NULL || request->version != PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_VERSION
        || (anchor = tool_anchor(request->tool)) == NULL
        || !nonzero32(request->request_sha256)
        || !nonzero32(request->operation_key)
        || !nonzero32(request->authority_sha256)
        || !nonzero32(request->prepared_campaign_sha256)
        || !nonzero32(request->secure_launcher_sha256)
        || !nonzero32(request->phase_io_binding_sha256)
        || !nonzero32(request->provider_preflight_sha256)
        || !nonzero32(request->provider_provenance_sha256)
        || !nonzero32(request->cli_executable_sha256)
        || !nonzero32(request->guest_executable_sha256)
        || !nonzero32(request->spec_sha256)
        || !nonzero32(request->launch_policy_sha256)
        || plamen_broker_v2_apple_container_id_validate(request->container_id) != 0
        || !safe_id(request->attempt_id, 128U)
        || request->guest_executable == NULL
        || strcmp(request->guest_executable, anchor) != 0
        || request->guest_argv == NULL || request->guest_argc == 0U
        || request->guest_argc > PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX
        || strcmp(request->guest_argv[0], anchor) != 0
        || request->guest_environment == NULL
        || request->guest_environment_count != 1U
        || strcmp(request->guest_environment[0], FUZZ_PATH) != 0
        || request->guest_cwd == NULL || strcmp(request->guest_cwd, FUZZ_CWD) != 0
        || request->timeout_seconds == 0U || request->timeout_seconds > 3600U
        || request->mounts == NULL || request->mount_count == 0U
        || request->mount_count > PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX
        || request->rosetta_required > 1U)
        return -1;
    memset(expected_id, 0, sizeof(expected_id));
    if (plamen_broker_v2_apple_container_derive_id(request->authority_sha256,
            request->operation_key, expected_id) != 0
        || strcmp(expected_id, request->container_id) != 0) {
        plamen_broker_v2_secure_zero(expected_id, sizeof(expected_id));
        return -1;
    }
    plamen_broker_v2_secure_zero(expected_id, sizeof(expected_id));
    for (index = 1U; index < request->guest_argc; ++index)
        if (!safe_text(request->guest_argv[index], 4096U)) return -1;
    return 0;
}

static int authority_validate(
    const struct plamen_broker_v2_fuzz_campaign_authority *authority,
    const struct plamen_broker_v2_fuzz_campaign_request *request)
{
    return authority != NULL
        && authority->version == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_VERSION
        && authority->cli_fd >= 0 && authority->cwd_fd >= 0
        && authority->stdin_fd >= 0 && authority->state_directory_fd >= 0
        && safe_text(authority->cli_path, 1024U)
        && authority->admission != NULL
        && plamen_broker_v2_apple_container_receipt_validate(
            authority->admission) == 0
        && authority->custody_client != NULL
        && nonzero32(authority->authority_binding_sha256)
        && nonzero32(authority->provider_preflight_sha256)
        && nonzero32(request->tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE
            ? authority->forge_executable_sha256
            : authority->medusa_executable_sha256)
        && safe_text(authority->runtime_image_reference,
            PLAMEN_BROKER_V2_APPLE_CONTAINER_REFERENCE_MAX - 1U)
        && equal32(authority->provider_preflight_sha256,
            request->provider_preflight_sha256)
        && equal32(request->guest_executable_sha256,
            request->tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE
                ? authority->forge_executable_sha256
                : authority->medusa_executable_sha256)
        && equal32(authority->admission->cli_sha256,
            request->cli_executable_sha256)
        && strcmp(authority->admission->runtime_image_reference,
            authority->runtime_image_reference) == 0;
}

static int lifecycle_sha256(
    const struct plamen_broker_v2_fuzz_campaign_result *result,
    uint8_t output[32])
{
    static const uint8_t domain[] = "PLAMEN-FUZZ-CAMPAIGN-LIFECYCLE-V1\0";
    CC_SHA256_CTX digest;
    if (result == NULL || output == NULL
        || CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, domain, sizeof(domain)) != 1
        || CC_SHA256_Update(&digest, result->request_sha256, 32U) != 1
        || CC_SHA256_Update(&digest, result->created.receipt_sha256, 32U) != 1
        || CC_SHA256_Update(&digest, result->started.receipt_sha256, 32U) != 1
        || CC_SHA256_Update(&digest, result->terminal.receipt_sha256, 32U) != 1
        || CC_SHA256_Update(&digest, result->deleted.receipt_sha256, 32U) != 1
        || CC_SHA256_Final(output, &digest) != 1)
        return -1;
    return nonzero32(output) ? 0 : -1;
}

int
plamen_broker_v2_fuzz_campaign_result_validate(
    const struct plamen_broker_v2_fuzz_campaign_request *request,
    const struct plamen_broker_v2_fuzz_campaign_result *result)
{
    uint8_t expected[32], retained_stdout[32], retained_stderr[32];
    memset(expected, 0, sizeof(expected));
    memset(retained_stdout, 0, sizeof(retained_stdout));
    memset(retained_stderr, 0, sizeof(retained_stderr));
    if (plamen_broker_v2_fuzz_campaign_request_validate(request) != 0
        || result == NULL
        || result->version != PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_RESULT_VERSION
        || !equal32(result->request_sha256, request->request_sha256)
        || plamen_broker_v2_apple_lifecycle_create_receipt_validate(
            &result->created) != 0
        || plamen_broker_v2_apple_lifecycle_start_receipt_validate(
            &result->started) != 0
        || plamen_broker_v2_apple_lifecycle_terminal_receipt_validate(
            &result->terminal) != 0
        || plamen_broker_v2_apple_lifecycle_delete_receipt_validate(
            &result->deleted) != 0
        || !equal32(result->commitments.launch_request_sha256,
            result->terminal.launch_request_sha256)
        || !equal32(result->created.spec_sha256,
            result->commitments.spec_sha256)
        || !equal32(result->started.spec_sha256,
            result->commitments.spec_sha256)
        || !equal32(result->terminal.spec_sha256,
            result->commitments.spec_sha256)
        || !equal32(result->deleted.spec_sha256,
            result->commitments.spec_sha256)
        || strcmp(result->created.container_id, request->container_id) != 0
        || strcmp(result->started.container_id, request->container_id) != 0
        || strcmp(result->terminal.container_id, request->container_id) != 0
        || strcmp(result->deleted.container_id, request->container_id) != 0
        || !equal32(result->started.launch_request_sha256,
            result->commitments.launch_request_sha256)
        || !equal32(result->terminal.launch_request_sha256,
            result->commitments.launch_request_sha256)
        || !equal32(result->started.start_operation_nonce,
            result->terminal.start_operation_nonce)
        || result->terminal.exit_code < 0 || result->terminal.exit_code > 255)
        return -1;
    /* The process handle must link start to terminal. */
    if (!equal32(result->started.native_process_handle_sha256,
            result->terminal.native_process_handle_sha256)
        || !equal32(result->terminal.receipt_sha256,
            result->deleted.terminal_receipt_sha256)
        || result->terminal.descendants_extinct != 1U
        || result->terminal.guest_process_extinct != 1U
        || result->terminal.backend_egress_revoked != 1U
        || !nonzero32(result->terminal.stop_argv_sha256)
        || !nonzero32(result->terminal.stop_stdout_sha256)
        || !nonzero32(result->terminal.stop_stderr_sha256)
        || !nonzero32(result->terminal.stopped_observation_sha256)
        || !nonzero32(result->terminal.guest_population_extinction_sha256)
        || result->terminal.stop_control_process_reaped != 1U
        || result->terminal.stop_control_process_group_extinct != 1U
        || result->terminal.guest_population_zero != 1U
        || result->terminal.container_vm_stopped != 1U
        || result->deleted.descendants_extinct != 1U
        || result->deleted.guest_process_extinct != 1U
        || result->deleted.backend_egress_revoked != 1U
        || result->deleted.absent != 1U
        || (result->terminal.stdout_retained_bytes != 0U
            && result->terminal.stdout_retained == NULL)
        || (result->terminal.stderr_retained_bytes != 0U
            && result->terminal.stderr_retained == NULL)
        || plamen_broker_v2_sha256(result->terminal.stdout_retained,
            result->terminal.stdout_retained_bytes, retained_stdout) != 0
        || plamen_broker_v2_sha256(result->terminal.stderr_retained,
            result->terminal.stderr_retained_bytes, retained_stderr) != 0
        || !equal32(retained_stdout,
            result->terminal.stdout_retained_sha256)
        || !equal32(retained_stderr,
            result->terminal.stderr_retained_sha256)
        || lifecycle_sha256(result, expected) != 0
        || !equal32(expected, result->lifecycle_sha256)) {
        plamen_broker_v2_secure_zero(expected, sizeof(expected));
        plamen_broker_v2_secure_zero(retained_stdout, sizeof(retained_stdout));
        plamen_broker_v2_secure_zero(retained_stderr, sizeof(retained_stderr));
        return -1;
    }
    plamen_broker_v2_secure_zero(expected, sizeof(expected));
    plamen_broker_v2_secure_zero(retained_stdout, sizeof(retained_stdout));
    plamen_broker_v2_secure_zero(retained_stderr, sizeof(retained_stderr));
    return 0;
}

static void build_outer_argv(
    const struct plamen_broker_v2_fuzz_campaign_request *request,
    const char *storage[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX],
    size_t *count)
{
    size_t index, offset = 0U;
    storage[offset++] = request->guest_environment[0];
    for (index = 0U; index < request->guest_argc; ++index)
        storage[offset++] = request->guest_argv[index];
    *count = offset;
}

static int build_native_spec(
    const struct plamen_broker_v2_fuzz_campaign_authority *authority,
    const struct plamen_broker_v2_fuzz_campaign_request *request,
    struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_apple_lifecycle_commitments *commitments,
    const char *outer_argv[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX])
{
    static const uint8_t start_domain[] = "PLAMEN-FUZZ-START-V1\0";
    static const uint8_t wait_domain[] = "PLAMEN-FUZZ-WAIT-V1\0";
    static const uint8_t revoke_domain[] = "PLAMEN-FUZZ-REVOKE-V1\0";
    size_t outer_argc = 0U, index;
    if (spec == NULL || commitments == NULL || outer_argv == NULL
        || plamen_broker_v2_fuzz_campaign_request_validate(request) != 0
        || !authority_validate(authority, request)
        || request->guest_argc + request->guest_environment_count
            > PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX)
        return -1;
    memset(spec, 0, sizeof(*spec)); memset(commitments, 0, sizeof(*commitments));
    memset(outer_argv, 0,
        sizeof(*outer_argv) * PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX);
    build_outer_argv(request, outer_argv, &outer_argc);
    spec->version = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_DYNAMIC_VERSION;
    spec->cli_fd = authority->cli_fd; spec->cli_path = authority->cli_path;
    spec->cwd_fd = authority->cwd_fd; spec->stdin_fd = authority->stdin_fd;
    spec->state_directory_fd = authority->state_directory_fd;
    spec->admission = authority->admission; spec->container_id = request->container_id;
    spec->runtime_image_reference = authority->runtime_image_reference;
    spec->working_directory = request->guest_cwd;
    spec->entrypoint = FUZZ_ENV_ENTRYPOINT;
    spec->arguments = outer_argv; spec->argument_count = outer_argc;
    spec->cpus = authority->cpus == 0U ? FUZZ_DEFAULT_CPUS : authority->cpus;
    spec->memory_bytes = authority->memory_bytes == 0U
        ? FUZZ_DEFAULT_MEMORY : authority->memory_bytes;
    spec->uid = 1000U; spec->gid = 1000U; spec->create_timeout_seconds = 120U;
    spec->driver_timeout_seconds = request->timeout_seconds;
    spec->stop_grace_seconds = 10U; spec->rosetta_required = request->rosetta_required;
    memcpy(spec->launch_policy_sha256, request->launch_policy_sha256, 32U);
    memcpy(spec->create_operation_key, request->operation_key, 32U);
    if (plamen_broker_v2_hmac_sha256(authority->authority_binding_sha256,
            start_domain, sizeof(start_domain), request->operation_key, 32U,
            spec->start_operation_nonce) != 0
        || plamen_broker_v2_hmac_sha256(authority->authority_binding_sha256,
            wait_domain, sizeof(wait_domain), request->operation_key, 32U,
            spec->wait_operation_nonce) != 0
        || plamen_broker_v2_hmac_sha256(authority->authority_binding_sha256,
            revoke_domain, sizeof(revoke_domain), request->operation_key, 32U,
            spec->revoke_operation_nonce) != 0)
        return -1;
    spec->mount_count = request->mount_count; spec->dynamic_mounts = 1U;
    for (index = 0U; index < request->mount_count; ++index)
        spec->mounts[index] = request->mounts[index];
    if (plamen_broker_v2_apple_lifecycle_derive_commitments(
            spec, commitments) != 0) return -1;
    memcpy(spec->spec_sha256, commitments->spec_sha256, 32U);
    memcpy(spec->launch_request_sha256, commitments->launch_request_sha256, 32U);
    memcpy(spec->driver_argv_sha256, commitments->driver_argv_sha256, 32U);
    memcpy(spec->driver_environment_sha256,
        commitments->driver_environment_sha256, 32U);
    memcpy(spec->driver_cwd_sha256, commitments->driver_cwd_sha256, 32U);
    memcpy(spec->driver_stdin_sha256, commitments->driver_stdin_sha256, 32U);
    memcpy(spec->pass_fd_roster_sha256, commitments->pass_fd_roster_sha256, 32U);
    return 0;
}

int
plamen_broker_v2_fuzz_campaign_prepare(
    const struct plamen_broker_v2_fuzz_campaign_authority *authority,
    const struct plamen_broker_v2_fuzz_campaign_request *request,
    struct plamen_broker_v2_apple_lifecycle_commitments *commitments)
{
    struct plamen_broker_v2_apple_lifecycle_spec spec;
    const char *outer_argv[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX];
    int result;
    memset(&spec, 0, sizeof(spec)); memset(outer_argv, 0, sizeof(outer_argv));
    result = build_native_spec(authority, request, &spec, commitments, outer_argv);
    plamen_broker_v2_secure_zero(&spec, sizeof(spec));
    plamen_broker_v2_secure_zero(outer_argv, sizeof(outer_argv));
    return result;
}

int
plamen_broker_v2_fuzz_campaign_execute(
    const struct plamen_broker_v2_fuzz_campaign_authority *authority,
    const struct plamen_broker_v2_fuzz_campaign_request *request,
    struct plamen_broker_v2_fuzz_campaign_result *result)
{
    struct plamen_broker_v2_apple_lifecycle_spec spec;
    struct plamen_broker_v2_apple_lifecycle *lifecycle = NULL;
    const char *outer_argv[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX];
    int stage = 0, status = -1, reopened;
    if (result != NULL) memset(result, 0, sizeof(*result));
    memset(&spec, 0, sizeof(spec)); memset(outer_argv, 0, sizeof(outer_argv));
    if (result == NULL || build_native_spec(authority, request, &spec,
            &result->commitments, outer_argv) != 0)
        goto done;
    reopened = plamen_broker_v2_apple_lifecycle_reopen_deleted(&spec,
        authority->custody_client, authority->authority_binding_sha256,
        &result->created, &result->started, &result->terminal,
        &result->deleted, &lifecycle);
    if (reopened == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) stage = 4;
    else if (reopened != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED) goto done;
    if (stage == 0) {
        reopened = plamen_broker_v2_apple_lifecycle_reopen_terminal(&spec,
            authority->custody_client, authority->authority_binding_sha256,
            &result->created, &result->started, &result->terminal, &lifecycle);
        if (reopened == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) stage = 3;
        else if (reopened != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED) goto done;
    }
    if (stage == 0) {
        reopened = plamen_broker_v2_apple_lifecycle_reopen_started(&spec,
            authority->custody_client, authority->authority_binding_sha256,
            &result->created, &result->started, &lifecycle);
        if (reopened == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) stage = 2;
        else if (reopened != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED) goto done;
    }
    if (stage == 0) {
        reopened = plamen_broker_v2_apple_lifecycle_reopen_created(&spec,
            authority->custody_client, authority->authority_binding_sha256,
            &result->created, &lifecycle);
        if (reopened == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) stage = 1;
        else if (reopened != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED) goto done;
    }
    if (stage == 0) {
        if (plamen_broker_v2_apple_lifecycle_create(&spec, &result->created,
                &lifecycle) != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
            || plamen_broker_v2_apple_lifecycle_bind_process_custody(lifecycle,
                authority->custody_client,
                authority->authority_binding_sha256) != 0)
            goto done;
        stage = 1;
    }
    if (stage == 1) {
        if (plamen_broker_v2_apple_lifecycle_start(lifecycle, &result->started)
                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) goto done;
        stage = 2;
    }
    if (stage == 2) {
        if (plamen_broker_v2_apple_lifecycle_wait(lifecycle, &result->terminal)
                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) goto done;
        stage = 3;
    }
    if (stage == 3) {
        if (plamen_broker_v2_apple_lifecycle_delete(lifecycle,
                &result->terminal, &result->deleted)
                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) goto done;
        stage = 4;
    }
    result->version = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_RESULT_VERSION;
    memcpy(result->request_sha256, request->request_sha256, 32U);
    if (lifecycle_sha256(result, result->lifecycle_sha256) != 0
        || plamen_broker_v2_fuzz_campaign_result_validate(request, result) != 0)
        goto done;
    status = 0;
done:
    if (status != 0 && lifecycle != NULL && stage < 4) {
        struct plamen_broker_v2_apple_lifecycle_terminal_receipt terminal;
        struct plamen_broker_v2_apple_lifecycle_delete_receipt deleted;
        memset(&terminal, 0, sizeof(terminal)); memset(&deleted, 0, sizeof(deleted));
        (void)plamen_broker_v2_apple_lifecycle_revoke_delete(lifecycle,
            &terminal, &deleted);
        plamen_broker_v2_apple_lifecycle_terminal_dispose(&terminal);
    }
    if (lifecycle != NULL)
        (void)plamen_broker_v2_apple_lifecycle_close(lifecycle);
    plamen_broker_v2_secure_zero(&spec, sizeof(spec));
    plamen_broker_v2_secure_zero(outer_argv, sizeof(outer_argv));
    if (status != 0 && result != NULL)
        plamen_broker_v2_fuzz_campaign_result_dispose(result);
    return status;
}

void
plamen_broker_v2_fuzz_campaign_result_dispose(
    struct plamen_broker_v2_fuzz_campaign_result *result)
{
    if (result == NULL) return;
    plamen_broker_v2_apple_lifecycle_terminal_dispose(&result->terminal);
    plamen_broker_v2_secure_zero(result, sizeof(*result));
}

struct fuzz_render_buffer {
    uint8_t *data;
    size_t size;
    size_t capacity;
    int failed;
};

static int fuzz_render_reserve(struct fuzz_render_buffer *buffer, size_t extra)
{
    uint8_t *grown; size_t capacity;
    if (buffer == NULL || buffer->failed
        || extra > SIZE_MAX - buffer->size - 1U) return -1;
    if (buffer->size + extra + 1U <= buffer->capacity) return 0;
    capacity = buffer->capacity == 0U ? 4096U : buffer->capacity;
    while (capacity < buffer->size + extra + 1U) {
        if (capacity > SIZE_MAX / 2U) return -1;
        capacity *= 2U;
    }
    grown = realloc(buffer->data, capacity);
    if (grown == NULL) return -1;
    buffer->data = grown; buffer->capacity = capacity; return 0;
}

static void fuzz_render_put(struct fuzz_render_buffer *buffer,
    const char *format, ...)
{
    va_list first, second; int needed, written;
    if (buffer == NULL || buffer->failed || format == NULL) return;
    va_start(first, format); va_copy(second, first);
    needed = vsnprintf(NULL, 0U, format, first); va_end(first);
    if (needed < 0 || fuzz_render_reserve(buffer, (size_t)needed) != 0) {
        buffer->failed = 1; va_end(second); return;
    }
    written = vsnprintf((char *)buffer->data + buffer->size,
        buffer->capacity - buffer->size, format, second);
    va_end(second);
    if (written != needed) { buffer->failed = 1; return; }
    buffer->size += (size_t)written;
}

static void fuzz_hex32(const uint8_t digest[32], char output[65])
{
    static const char alphabet[] = "0123456789abcdef"; size_t index;
    for (index = 0U; index < 32U; ++index) {
        output[index * 2U] = alphabet[digest[index] >> 4U];
        output[index * 2U + 1U] = alphabet[digest[index] & 15U];
    }
    output[64] = '\0';
}

static void fuzz_render_hex_bytes(struct fuzz_render_buffer *buffer,
    const uint8_t *bytes, size_t size)
{
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    if ((size != 0U && bytes == NULL)
        || fuzz_render_reserve(buffer, size * 2U) != 0) {
        buffer->failed = 1; return;
    }
    for (index = 0U; index < size; ++index) {
        buffer->data[buffer->size++] = alphabet[bytes[index] >> 4U];
        buffer->data[buffer->size++] = alphabet[bytes[index] & 15U];
    }
}

int
plamen_broker_v2_fuzz_campaign_result_render(
    const struct plamen_broker_v2_fuzz_campaign_request *request,
    const struct plamen_broker_v2_fuzz_campaign_authority *authority,
    const struct plamen_broker_v2_fuzz_campaign_result *result,
    uint8_t **terminal, size_t *terminal_size)
{
    struct fuzz_render_buffer out; char h[65];
    if (terminal != NULL) *terminal = NULL;
    if (terminal_size != NULL) *terminal_size = 0U;
    memset(&out, 0, sizeof(out)); memset(h, 0, sizeof(h));
    if (terminal == NULL || terminal_size == NULL
        || !authority_validate(authority, request)
        || plamen_broker_v2_fuzz_campaign_result_validate(request, result) != 0)
        return -1;
#define H(field) fuzz_hex32((field), h)
    H(request->request_sha256);
    fuzz_render_put(&out, "{\"deleted\":{");
    H(result->deleted.absence_sha256); fuzz_render_put(&out,
        "\"absence_sha256\":\"%s\",\"absent\":true,", h);
    H(result->deleted.cleanup_sha256); fuzz_render_put(&out,
        "\"backend_egress_revoked\":true,\"cleanup_sha256\":\"%s\","
        "\"container_id\":\"%s\",", h, request->container_id);
    H(result->deleted.receipt_sha256); fuzz_render_put(&out,
        "\"delete_receipt_sha256\":\"%s\","
        "\"descendants_extinct\":true,", h);
    H(request->guest_executable_sha256); fuzz_render_put(&out,
        "\"guest_executable_sha256\":\"%s\","
        "\"guest_process_extinct\":true,", h);
    H(request->provider_preflight_sha256); fuzz_render_put(&out,
        "\"provider_preflight_sha256\":\"%s\",", h);
    H(request->request_sha256); fuzz_render_put(&out,
        "\"request_sha256\":\"%s\",", h);
    H(result->commitments.spec_sha256); fuzz_render_put(&out,
        "\"schema\":\"plamen.apple-container.native-fuzz-delete.v1\","
        "\"spec_sha256\":\"%s\",", h);
    H(result->terminal.receipt_sha256); fuzz_render_put(&out,
        "\"terminal_receipt_sha256\":\"%s\"},\"launch\":{", h);
    H(request->cli_executable_sha256); fuzz_render_put(&out,
        "\"attempt_id\":\"%s\",\"cli_executable_sha256\":\"%s\","
        "\"container_id\":\"%s\",", request->attempt_id, h,
        request->container_id);
    H(result->created.receipt_sha256); fuzz_render_put(&out,
        "\"created_receipt_sha256\":\"%s\",", h);
    H(result->commitments.driver_argv_sha256); fuzz_render_put(&out,
        "\"driver_argv_sha256\":\"%s\",", h);
    H(result->commitments.driver_cwd_sha256); fuzz_render_put(&out,
        "\"driver_cwd_sha256\":\"%s\",", h);
    H(result->commitments.driver_environment_sha256); fuzz_render_put(&out,
        "\"driver_environment_sha256\":\"%s\",", h);
    H(result->commitments.driver_stdin_sha256); fuzz_render_put(&out,
        "\"driver_stdin_sha256\":\"%s\",", h);
    H(request->guest_executable_sha256); fuzz_render_put(&out,
        "\"guest_executable_sha256\":\"%s\",", h);
    H(request->launch_policy_sha256); fuzz_render_put(&out,
        "\"launch_policy_sha256\":\"%s\",", h);
    H(result->commitments.launch_request_sha256); fuzz_render_put(&out,
        "\"launch_request_sha256\":\"%s\",", h);
    H(result->commitments.mount_roster_sha256); fuzz_render_put(&out,
        "\"mount_roster_sha256\":\"%s\",", h);
    H(result->started.native_process_handle_sha256); fuzz_render_put(&out,
        "\"native_process_handle_sha256\":\"%s\",", h);
    fuzz_render_put(&out, "\"native_process_id\":%d,",
        result->started.native_process_id);
    H(result->commitments.pass_fd_roster_sha256); fuzz_render_put(&out,
        "\"pass_fd_roster_sha256\":\"%s\",", h);
    H(request->provider_preflight_sha256); fuzz_render_put(&out,
        "\"provider_preflight_sha256\":\"%s\",", h);
    H(request->provider_provenance_sha256); fuzz_render_put(&out,
        "\"provider_provenance_sha256\":\"%s\",", h);
    H(request->request_sha256); fuzz_render_put(&out,
        "\"request_sha256\":\"%s\",\"rosetta_required\":%s,", h,
        request->rosetta_required ? "true" : "false");
    H(result->commitments.spec_sha256); fuzz_render_put(&out,
        "\"schema\":\"plamen.apple-container.native-fuzz-launch.v1\","
        "\"spec_sha256\":\"%s\",", h);
    fuzz_render_put(&out, "\"start_monotonic_ms\":%llu,",
        (unsigned long long)result->started.start_monotonic_ms);
    H(result->started.start_operation_nonce); fuzz_render_put(&out,
        "\"start_operation_nonce\":\"%s\",", h);
    H(result->started.receipt_sha256); fuzz_render_put(&out,
        "\"start_receipt_sha256\":\"%s\"},", h);
    H(result->lifecycle_sha256); fuzz_render_put(&out,
        "\"lifecycle_sha256\":\"%s\",", h);
    H(result->commitments.mount_roster_sha256); fuzz_render_put(&out,
        "\"native_mount_roster_sha256\":\"%s\",", h);
    H(authority->admission->admission_sha256); fuzz_render_put(&out,
        "\"native_provider_admission_sha256\":\"%s\",", h);
    H(authority->admission->provider_provenance_sha256); fuzz_render_put(&out,
        "\"native_provider_provenance_sha256\":\"%s\",", h);
    H(result->commitments.spec_sha256); fuzz_render_put(&out,
        "\"native_spec_sha256\":\"%s\",", h);
    H(request->request_sha256); fuzz_render_put(&out,
        "\"request_sha256\":\"%s\","
        "\"schema\":\"plamen.apple-container.native-fuzz-bundle.v1\","
        "\"stderr_hex\":\"", h);
    fuzz_render_hex_bytes(&out, result->terminal.stderr_retained,
        result->terminal.stderr_retained_bytes);
    fuzz_render_put(&out, "\",\"stdout_hex\":\"");
    fuzz_render_hex_bytes(&out, result->terminal.stdout_retained,
        result->terminal.stdout_retained_bytes);
    fuzz_render_put(&out, "\",\"terminal\":{");
    fuzz_render_put(&out, "\"attempt_id\":\"%s\","
        "\"backend_egress_revoked\":true,", request->attempt_id);
    H(result->terminal.cleanup_sha256); fuzz_render_put(&out,
        "\"cleanup_sha256\":\"%s\",\"container_id\":\"%s\","
        "\"container_vm_stopped\":true,\"descendants_extinct\":true,", h,
        request->container_id);
    fuzz_render_put(&out, "\"end_monotonic_ms\":%llu,\"exit_code\":%d,",
        (unsigned long long)result->terminal.end_monotonic_ms,
        result->terminal.exit_code);
    H(request->guest_executable_sha256); fuzz_render_put(&out,
        "\"guest_executable_sha256\":\"%s\",", h);
    H(result->terminal.guest_population_extinction_sha256);
    fuzz_render_put(&out, "\"guest_population_extinction_sha256\":\"%s\","
        "\"guest_population_zero\":true,\"guest_process_extinct\":true,", h);
    H(result->terminal.launch_request_sha256); fuzz_render_put(&out,
        "\"launch_request_sha256\":\"%s\",", h);
    H(result->terminal.native_process_extinction_sha256); fuzz_render_put(&out,
        "\"native_process_extinction_sha256\":\"%s\",", h);
    H(result->terminal.native_process_handle_sha256); fuzz_render_put(&out,
        "\"native_process_handle_sha256\":\"%s\",", h);
    fuzz_render_put(&out, "\"native_process_id\":%d,",
        result->terminal.native_process_id);
    H(request->provider_preflight_sha256); fuzz_render_put(&out,
        "\"provider_preflight_sha256\":\"%s\",", h);
    H(request->provider_provenance_sha256); fuzz_render_put(&out,
        "\"provider_provenance_sha256\":\"%s\",", h);
    H(request->request_sha256); fuzz_render_put(&out,
        "\"request_sha256\":\"%s\",", h);
    H(result->terminal.revoke_operation_nonce); fuzz_render_put(&out,
        "\"revoke_operation_nonce\":\"%s\",\"rosetta_required\":%s,",
        h, request->rosetta_required ? "true" : "false");
    H(result->commitments.spec_sha256); fuzz_render_put(&out,
        "\"schema\":\"plamen.apple-container.native-fuzz-terminal.v1\","
        "\"spec_sha256\":\"%s\",\"start_monotonic_ms\":%llu,", h,
        (unsigned long long)result->terminal.start_monotonic_ms);
    H(result->terminal.start_operation_nonce); fuzz_render_put(&out,
        "\"start_operation_nonce\":\"%s\",", h);
    H(result->started.receipt_sha256); fuzz_render_put(&out,
        "\"start_receipt_sha256\":\"%s\","
        "\"stderr_observed_bytes\":%llu,\"stderr_retained_bytes\":%u,", h,
        (unsigned long long)result->terminal.stderr_observed_bytes,
        result->terminal.stderr_retained_bytes);
    H(result->terminal.stderr_retained_sha256); fuzz_render_put(&out,
        "\"stderr_retained_sha256\":\"%s\",", h);
    H(result->terminal.stderr_sha256); fuzz_render_put(&out,
        "\"stderr_sha256\":\"%s\",\"stderr_truncated\":%s,", h,
        result->terminal.stderr_truncated ? "true" : "false");
    fuzz_render_put(&out,
        "\"stdout_observed_bytes\":%llu,\"stdout_retained_bytes\":%u,",
        (unsigned long long)result->terminal.stdout_observed_bytes,
        result->terminal.stdout_retained_bytes);
    H(result->terminal.stdout_retained_sha256); fuzz_render_put(&out,
        "\"stdout_retained_sha256\":\"%s\",", h);
    H(result->terminal.stdout_sha256); fuzz_render_put(&out,
        "\"stdout_sha256\":\"%s\",\"stdout_truncated\":%s,", h,
        result->terminal.stdout_truncated ? "true" : "false");
    H(result->terminal.stop_argv_sha256); fuzz_render_put(&out,
        "\"stop_argv_sha256\":\"%s\","
        "\"stop_control_process_group_extinct\":true,"
        "\"stop_control_process_reaped\":true,", h);
    H(result->terminal.stop_stderr_sha256); fuzz_render_put(&out,
        "\"stop_stderr_sha256\":\"%s\",", h);
    H(result->terminal.stop_stdout_sha256); fuzz_render_put(&out,
        "\"stop_stdout_sha256\":\"%s\",", h);
    H(result->terminal.stopped_observation_sha256); fuzz_render_put(&out,
        "\"stopped_observation_sha256\":\"%s\",", h);
    H(result->terminal.receipt_sha256); fuzz_render_put(&out,
        "\"terminal_receipt_sha256\":\"%s\",", h);
    H(result->terminal.wait_operation_nonce); fuzz_render_put(&out,
        "\"wait_operation_nonce\":\"%s\"}}", h);
#undef H
    if (out.failed || out.size == 0U) goto failed;
    *terminal = out.data; *terminal_size = out.size;
    memset(h, 0, sizeof(h)); return 0;
failed:
    if (out.data != NULL) {
        plamen_broker_v2_secure_zero(out.data, out.capacity); free(out.data);
    }
    memset(h, 0, sizeof(h)); return -1;
}
