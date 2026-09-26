#define _DARWIN_C_SOURCE 1

#include "../darwin/plamen_broker_v2_fuzz_campaign.h"
#include "../include/plamen_broker_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct plamen_broker_v2_apple_lifecycle { int marker; };
struct plamen_broker_v2_process_custody_client { int marker; };

static struct plamen_broker_v2_apple_lifecycle singleton_lifecycle;
static int create_count, start_count, wait_count, delete_count, revoke_count;
static int reopen_stage;
static int fail_wait;
static uint8_t retained_stdout[] = {'o', 'k'};
static const struct plamen_broker_v2_apple_lifecycle_spec *active_spec;
static struct plamen_broker_v2_apple_lifecycle_start_receipt active_started;

static void fill(uint8_t value[32], uint8_t byte) { memset(value, byte, 32U); }
static int nonzero(const uint8_t value[32]) {
    size_t index; uint8_t aggregate = 0U;
    for (index = 0U; index < 32U; ++index) aggregate |= value[index];
    return aggregate != 0U;
}

void plamen_broker_v2_secure_zero(void *data, size_t size)
{
    volatile uint8_t *cursor = data;
    while (size-- != 0U) *cursor++ = 0U;
}

int plamen_broker_v2_sha256(const void *data, size_t size, uint8_t out[32])
{
    return CC_SHA256(data, (CC_LONG)size, out) != NULL ? 0 : -1;
}

int plamen_broker_v2_hmac_sha256(const uint8_t key[32], const void *first,
    size_t first_size, const void *second, size_t second_size, uint8_t out[32])
{
    static uint8_t discriminator = 0x70U;
    if (!nonzero(key) || first == NULL || first_size == 0U || second == NULL
        || second_size == 0U || out == NULL) return -1;
    fill(out, discriminator++); return 0;
}

int plamen_broker_v2_fd_identity(int fd, uint8_t out[32])
{
    struct stat info;
    CC_SHA256_CTX digest;
    if (fd < 0 || out == NULL || fstat(fd, &info) != 0
        || CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, &info.st_dev, sizeof(info.st_dev)) != 1
        || CC_SHA256_Update(&digest, &info.st_ino, sizeof(info.st_ino)) != 1
        || CC_SHA256_Update(&digest, &info.st_mode, sizeof(info.st_mode)) != 1
        || CC_SHA256_Final(out, &digest) != 1) return -1;
    return nonzero(out) ? 0 : -1;
}

int plamen_broker_v2_apple_container_id_validate(const char *value)
{
    size_t index;
    if (value == NULL || strlen(value) != 39U || strncmp(value, "plamen-", 7U) != 0)
        return -1;
    for (index = 7U; index < 39U; ++index)
        if (!((value[index] >= '0' && value[index] <= '9')
                || (value[index] >= 'a' && value[index] <= 'f'))) return -1;
    return 0;
}

int plamen_broker_v2_apple_container_derive_id(const uint8_t request[32],
    const uint8_t operation[32], char output[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE])
{
    static const char hex[] = "0123456789abcdef";
    static const uint8_t domain[] = "plamen.apple-container.id.v1";
    CC_SHA256_CTX digest; uint8_t observed[32]; size_t index;
    if (!nonzero(request) || !nonzero(operation) || output == NULL
        || CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, domain, sizeof(domain)) != 1
        || CC_SHA256_Update(&digest, request, 32U) != 1
        || CC_SHA256_Update(&digest, operation, 32U) != 1
        || CC_SHA256_Final(observed, &digest) != 1) return -1;
    memcpy(output, "plamen-", 7U);
    for (index = 0U; index < 16U; ++index) {
        output[7U + index * 2U] = hex[observed[index] >> 4U];
        output[8U + index * 2U] = hex[observed[index] & 15U];
    }
    output[39] = '\0'; return 0;
}

int plamen_broker_v2_apple_container_receipt_validate(
    const struct plamen_broker_v2_apple_container_admission_receipt *receipt)
{
    return receipt != NULL && receipt->version == 1U
        && receipt->lifecycle_authority_granted == 0U
        && nonzero(receipt->admission_sha256) ? 0 : -1;
}

int plamen_broker_v2_apple_lifecycle_create_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt)
{
    return receipt != NULL && receipt->version == 1U
        && nonzero(receipt->receipt_sha256) ? 0 : -1;
}

int plamen_broker_v2_apple_lifecycle_start_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    return receipt != NULL
        && receipt->version == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
        && nonzero(receipt->receipt_sha256) ? 0 : -1;
}

int plamen_broker_v2_apple_lifecycle_terminal_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    return receipt != NULL
        && receipt->version == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_TERMINAL_RECEIPT_VERSION
        && nonzero(receipt->receipt_sha256) ? 0 : -1;
}

int plamen_broker_v2_apple_lifecycle_delete_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_delete_receipt *receipt)
{
    return receipt != NULL && receipt->version == 1U
        && nonzero(receipt->receipt_sha256) ? 0 : -1;
}

int plamen_broker_v2_apple_lifecycle_derive_commitments(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_apple_lifecycle_commitments *commitments)
{
    assert(spec != NULL && commitments != NULL);
    assert(strcmp(spec->entrypoint, "/usr/bin/env") == 0);
    assert(strcmp(spec->arguments[0], PLAMEN_BROKER_V2_FUZZ_PATH) == 0);
    memset(commitments, 0, sizeof(*commitments));
    fill(commitments->spec_sha256, 0x22U);
    fill(commitments->launch_request_sha256, 0x23U);
    fill(commitments->driver_argv_sha256, 0x24U);
    fill(commitments->driver_environment_sha256, 0x25U);
    fill(commitments->driver_cwd_sha256, 0x26U);
    fill(commitments->driver_stdin_sha256, 0x27U);
    fill(commitments->pass_fd_roster_sha256, 0x28U);
    fill(commitments->mount_roster_sha256, 0x29U);
    active_spec = spec;
    return 0;
}

static void make_created(const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt)
{
    memset(receipt, 0, sizeof(*receipt)); receipt->version = 1U;
    strcpy(receipt->container_id, spec->container_id);
    memcpy(receipt->spec_sha256, spec->spec_sha256, 32U);
    fill(receipt->receipt_sha256, 0x31U);
}

static void make_started(const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    memset(receipt, 0, sizeof(*receipt));
    receipt->version = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION;
    strcpy(receipt->container_id, spec->container_id);
    memcpy(receipt->spec_sha256, spec->spec_sha256, 32U);
    memcpy(receipt->launch_request_sha256, spec->launch_request_sha256, 32U);
    memcpy(receipt->start_operation_nonce, spec->start_operation_nonce, 32U);
    fill(receipt->native_process_handle_sha256, 0x32U);
    fill(receipt->receipt_sha256, 0x33U); receipt->native_process_id = 123;
}

static void make_terminal(const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *started,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    memset(receipt, 0, sizeof(*receipt));
    receipt->version = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_TERMINAL_RECEIPT_VERSION;
    strcpy(receipt->container_id, spec->container_id);
    memcpy(receipt->spec_sha256, spec->spec_sha256, 32U);
    memcpy(receipt->launch_request_sha256, spec->launch_request_sha256, 32U);
    memcpy(receipt->start_operation_nonce, started->start_operation_nonce, 32U);
    memcpy(receipt->wait_operation_nonce, spec->wait_operation_nonce, 32U);
    memcpy(receipt->native_process_handle_sha256,
        started->native_process_handle_sha256, 32U);
    assert(plamen_broker_v2_sha256(retained_stdout, sizeof(retained_stdout),
        receipt->stdout_sha256) == 0);
    assert(plamen_broker_v2_sha256(NULL, 0U, receipt->stderr_sha256) == 0);
    memcpy(receipt->stdout_retained_sha256, receipt->stdout_sha256, 32U);
    memcpy(receipt->stderr_retained_sha256, receipt->stderr_sha256, 32U);
    receipt->stdout_observed_bytes = sizeof(retained_stdout);
    receipt->stdout_retained_bytes = sizeof(retained_stdout);
    receipt->stdout_retained = retained_stdout;
    fill(receipt->native_process_extinction_sha256, 0x42U);
    fill(receipt->cleanup_sha256, 0x43U);
    fill(receipt->stop_argv_sha256, 0x44U);
    fill(receipt->stop_stdout_sha256, 0x45U);
    fill(receipt->stop_stderr_sha256, 0x46U);
    fill(receipt->stopped_observation_sha256, 0x47U);
    fill(receipt->guest_population_extinction_sha256, 0x48U);
    receipt->descendants_extinct = 1U; receipt->guest_process_extinct = 1U;
    receipt->backend_egress_revoked = 1U;
    receipt->stop_control_process_reaped = 1U;
    receipt->stop_control_process_group_extinct = 1U;
    receipt->guest_population_zero = 1U; receipt->container_vm_stopped = 1U;
    fill(receipt->receipt_sha256, 0x49U);
}

static void make_deleted(const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *terminal,
    struct plamen_broker_v2_apple_lifecycle_delete_receipt *receipt)
{
    memset(receipt, 0, sizeof(*receipt)); receipt->version = 1U;
    strcpy(receipt->container_id, spec->container_id);
    memcpy(receipt->spec_sha256, spec->spec_sha256, 32U);
    memcpy(receipt->terminal_receipt_sha256, terminal->receipt_sha256, 32U);
    receipt->descendants_extinct = 1U; receipt->guest_process_extinct = 1U;
    receipt->backend_egress_revoked = 1U; receipt->absent = 1U;
    fill(receipt->receipt_sha256, 0x51U);
}

int plamen_broker_v2_apple_lifecycle_create(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt,
    struct plamen_broker_v2_apple_lifecycle **lifecycle)
{
    ++create_count; make_created(spec, receipt); *lifecycle = &singleton_lifecycle;
    return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

int plamen_broker_v2_apple_lifecycle_bind_process_custody(
    struct plamen_broker_v2_apple_lifecycle *lifecycle,
    struct plamen_broker_v2_process_custody_client *client, const uint8_t binding[32])
{ return lifecycle != NULL && client != NULL && nonzero(binding) ? 0 : -1; }

int plamen_broker_v2_apple_lifecycle_reopen_deleted(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_process_custody_client *client, const uint8_t binding[32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *started,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *terminal,
    struct plamen_broker_v2_apple_lifecycle_delete_receipt *deleted,
    struct plamen_broker_v2_apple_lifecycle **lifecycle)
{
    (void)client; (void)binding;
    if (reopen_stage != 4) return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    make_created(spec, created); make_started(spec, started);
    make_terminal(spec, started, terminal); make_deleted(spec, terminal, deleted);
    *lifecycle = &singleton_lifecycle; return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

int plamen_broker_v2_apple_lifecycle_reopen_terminal(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_process_custody_client *client, const uint8_t binding[32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *started,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *terminal,
    struct plamen_broker_v2_apple_lifecycle **lifecycle)
{
    (void)client; (void)binding;
    if (reopen_stage != 3) return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    make_created(spec, created); make_started(spec, started);
    make_terminal(spec, started, terminal); *lifecycle = &singleton_lifecycle;
    return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

int plamen_broker_v2_apple_lifecycle_reopen_started(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_process_custody_client *client, const uint8_t binding[32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *started,
    struct plamen_broker_v2_apple_lifecycle **lifecycle)
{
    (void)client; (void)binding;
    if (reopen_stage != 2) return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    make_created(spec, created); make_started(spec, started);
    *lifecycle = &singleton_lifecycle; return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

int plamen_broker_v2_apple_lifecycle_reopen_created(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_process_custody_client *client, const uint8_t binding[32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    struct plamen_broker_v2_apple_lifecycle **lifecycle)
{
    (void)client; (void)binding;
    if (reopen_stage != 1) return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    make_created(spec, created); *lifecycle = &singleton_lifecycle;
    return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

int plamen_broker_v2_apple_lifecycle_start(
    struct plamen_broker_v2_apple_lifecycle *lifecycle,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    ++start_count; assert(lifecycle != NULL); make_started(active_spec, receipt);
    active_started = *receipt; return 0;
}

int plamen_broker_v2_apple_lifecycle_wait(
    struct plamen_broker_v2_apple_lifecycle *lifecycle,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    ++wait_count; assert(lifecycle != NULL);
    if (fail_wait) return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    make_terminal(active_spec, &active_started, receipt); return 0;
}

int plamen_broker_v2_apple_lifecycle_delete(
    struct plamen_broker_v2_apple_lifecycle *lifecycle,
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *terminal,
    struct plamen_broker_v2_apple_lifecycle_delete_receipt *deleted)
{
    ++delete_count; assert(lifecycle != NULL); make_deleted(active_spec, terminal, deleted);
    return 0;
}

int plamen_broker_v2_apple_lifecycle_revoke_delete(
    struct plamen_broker_v2_apple_lifecycle *lifecycle,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *terminal,
    struct plamen_broker_v2_apple_lifecycle_delete_receipt *deleted)
{
    (void)lifecycle; (void)terminal; (void)deleted; ++revoke_count; return 0;
}

int plamen_broker_v2_apple_lifecycle_close(
    struct plamen_broker_v2_apple_lifecycle *lifecycle)
{ (void)lifecycle; return 0; }

void plamen_broker_v2_apple_lifecycle_terminal_dispose(
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{ if (receipt != NULL) { receipt->stdout_retained = NULL; receipt->stderr_retained = NULL; } }

static void reset(void)
{
    create_count = start_count = wait_count = delete_count = revoke_count = 0;
    reopen_stage = 0; fail_wait = 0; active_spec = NULL;
    memset(&active_started, 0, sizeof(active_started));
}

static void fixture(struct plamen_broker_v2_fuzz_campaign_request *request,
    struct plamen_broker_v2_fuzz_campaign_authority *authority,
    struct plamen_broker_v2_apple_container_admission_receipt *admission,
    struct plamen_broker_v2_apple_lifecycle_mount mounts[1], uint16_t tool)
{
    static const char *forge_argv[] = {
        PLAMEN_BROKER_V2_FUZZ_FORGE_ANCHOR, "test"};
    static const char *medusa_argv[] = {
        PLAMEN_BROKER_V2_FUZZ_MEDUSA_ANCHOR, "fuzz"};
    static const char *environment[] = {PLAMEN_BROKER_V2_FUZZ_PATH};
    static struct plamen_broker_v2_process_custody_client custody;
    memset(request, 0, sizeof(*request)); memset(authority, 0, sizeof(*authority));
    memset(admission, 0, sizeof(*admission)); memset(mounts, 0, sizeof(*mounts));
    request->version = 1U; request->tool = tool;
    fill(request->request_sha256, 0x10U); fill(request->operation_key, 0x11U);
    fill(request->authority_sha256, 0x12U); fill(request->prepared_campaign_sha256, 0x13U);
    fill(request->secure_launcher_sha256, 0x14U); fill(request->phase_io_binding_sha256, 0x15U);
    fill(request->provider_preflight_sha256, 0x16U);
    fill(request->provider_provenance_sha256, 0x17U);
    fill(request->cli_executable_sha256, 0x18U);
    fill(request->guest_executable_sha256, 0x19U); fill(request->spec_sha256, 0x22U);
    fill(request->launch_policy_sha256, 0x1bU);
    {
        static char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
        assert(plamen_broker_v2_apple_container_derive_id(
            request->authority_sha256, request->operation_key, container_id) == 0);
        request->container_id = container_id;
    }
    request->attempt_id = "dodo-fuzz-001";
    request->guest_executable = tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE
        ? forge_argv[0] : medusa_argv[0];
    request->guest_argv = tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE
        ? forge_argv : medusa_argv; request->guest_argc = 2U;
    request->guest_environment = environment; request->guest_environment_count = 1U;
    request->guest_cwd = "/workspace/scratch/fuzz/active";
    request->timeout_seconds = 600U; request->mounts = mounts; request->mount_count = 1U;
    mounts[0].source_fd = 20; mounts[0].source_path = "/private/tmp/fuzz";
    mounts[0].target_path = "/workspace/scratch/fuzz"; mounts[0].readonly = 0U;
    fill(mounts[0].expected_identity_sha256, 0x20U);
    admission->version = 1U; admission->lifecycle_authority_granted = 0U;
    fill(admission->cli_sha256, 0x18U); fill(admission->provider_provenance_sha256, 0x17U);
    fill(admission->admission_sha256, 0x60U);
    strcpy(admission->runtime_image_reference, "plamen/runtime@sha256:fixture");
    authority->version = 1U; authority->cli_fd = 10; authority->cli_path = "/usr/local/bin/container";
    authority->cwd_fd = 11; authority->stdin_fd = 12; authority->state_directory_fd = 13;
    authority->admission = admission; authority->custody_client = &custody;
    fill(authority->authority_binding_sha256, 0x61U);
    fill(authority->provider_preflight_sha256, 0x16U);
    fill(authority->forge_executable_sha256, 0x19U);
    fill(authority->medusa_executable_sha256, 0x19U);
    authority->runtime_image_reference = admission->runtime_image_reference;
}

static void test_tool_and_input_admission(void)
{
    struct plamen_broker_v2_fuzz_campaign_request request;
    struct plamen_broker_v2_fuzz_campaign_authority authority;
    struct plamen_broker_v2_apple_container_admission_receipt admission;
    struct plamen_broker_v2_apple_lifecycle_mount mounts[1];
    fixture(&request, &authority, &admission, mounts,
        PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE);
    assert(plamen_broker_v2_fuzz_campaign_request_validate(&request) == 0);
    request.guest_executable = "/tmp/forge";
    assert(plamen_broker_v2_fuzz_campaign_request_validate(&request) != 0);
    fixture(&request, &authority, &admission, mounts,
        PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_MEDUSA);
    assert(plamen_broker_v2_fuzz_campaign_request_validate(&request) == 0);
    request.timeout_seconds = 3601U;
    assert(plamen_broker_v2_fuzz_campaign_request_validate(&request) != 0);
}

static void test_full_lifecycle_and_recovery(void)
{
    struct plamen_broker_v2_fuzz_campaign_request request;
    struct plamen_broker_v2_fuzz_campaign_authority authority;
    struct plamen_broker_v2_fuzz_campaign_result result;
    struct plamen_broker_v2_apple_container_admission_receipt admission;
    struct plamen_broker_v2_apple_lifecycle_mount mounts[1];
    struct plamen_broker_v2_apple_lifecycle_commitments prepared;
    uint8_t *rendered = NULL;
    size_t rendered_size = 0U;
    fixture(&request, &authority, &admission, mounts,
        PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE);
    memset(&prepared, 0, sizeof(prepared));
    assert(plamen_broker_v2_fuzz_campaign_prepare(
        &authority, &request, &prepared) == 0);
    fill(request.spec_sha256, 0x7eU);
    assert(memcmp(prepared.spec_sha256, request.spec_sha256, 32U) != 0);
    reset();
    assert(plamen_broker_v2_fuzz_campaign_execute(&authority, &request, &result) == 0);
    assert(create_count == 1 && start_count == 1 && wait_count == 1
        && delete_count == 1 && revoke_count == 0);
    assert(plamen_broker_v2_fuzz_campaign_result_validate(&request, &result) == 0);
    assert(memcmp(result.commitments.spec_sha256,
        prepared.spec_sha256, 32U) == 0);
    assert(plamen_broker_v2_fuzz_campaign_result_render(
        &request, &authority, &result, &rendered, &rendered_size) == 0);
    assert(rendered != NULL && rendered_size != 0U);
    assert(fwrite(rendered, 1U, rendered_size, stdout) == rendered_size);
    free(rendered); rendered = NULL; rendered_size = 0U;
    {
        uint8_t saved[32];
#define REJECT_ZERO_DIGEST(field) do { \
        memcpy(saved, result.terminal.field, 32U); \
        memset(result.terminal.field, 0, 32U); \
        assert(plamen_broker_v2_fuzz_campaign_result_validate(&request, &result) != 0); \
        memcpy(result.terminal.field, saved, 32U); \
    } while (0)
        REJECT_ZERO_DIGEST(stop_argv_sha256);
        REJECT_ZERO_DIGEST(stop_stdout_sha256);
        REJECT_ZERO_DIGEST(stop_stderr_sha256);
        REJECT_ZERO_DIGEST(stopped_observation_sha256);
        REJECT_ZERO_DIGEST(guest_population_extinction_sha256);
#undef REJECT_ZERO_DIGEST
#define REJECT_FALSE(field) do { \
        result.terminal.field = 0U; \
        assert(plamen_broker_v2_fuzz_campaign_result_validate(&request, &result) != 0); \
        result.terminal.field = 1U; \
    } while (0)
        REJECT_FALSE(stop_control_process_reaped);
        REJECT_FALSE(stop_control_process_group_extinct);
        REJECT_FALSE(guest_population_zero);
        REJECT_FALSE(container_vm_stopped);
#undef REJECT_FALSE
        assert(plamen_broker_v2_fuzz_campaign_result_validate(&request, &result) == 0);
        plamen_broker_v2_secure_zero(saved, sizeof(saved));
    }
    retained_stdout[0] = 'x';
    assert(plamen_broker_v2_fuzz_campaign_result_validate(&request, &result) != 0);
    retained_stdout[0] = 'o';
    assert(plamen_broker_v2_fuzz_campaign_result_validate(&request, &result) == 0);
    plamen_broker_v2_fuzz_campaign_result_dispose(&result);
    reset(); reopen_stage = 3;
    assert(plamen_broker_v2_fuzz_campaign_execute(&authority, &request, &result) == 0);
    assert(create_count == 0 && start_count == 0 && wait_count == 0
        && delete_count == 1 && revoke_count == 0);
    plamen_broker_v2_fuzz_campaign_result_dispose(&result);
    reset(); fail_wait = 1;
    assert(plamen_broker_v2_fuzz_campaign_execute(&authority, &request, &result) != 0);
    assert(revoke_count == 1);
}

static void test_atomic_service_admission_and_one_shot_execute(void)
{
    static const char *const targets[4] = {
        "/workspace/source", "/workspace/scratch",
        "/workspace/state", "/workspace/project"
    };
    static const char *argv[] = {
        PLAMEN_BROKER_V2_FUZZ_FORGE_ANCHOR, "test"
    };
    struct plamen_broker_v2_fuzz_campaign_authority authority;
    struct plamen_broker_v2_apple_container_admission_receipt admission;
    struct plamen_broker_v2_fuzz_service_admission_request request;
    struct plamen_broker_v2_fuzz_service_admission_receipt receipt;
    struct plamen_broker_v2_fuzz_service_session *session = NULL;
    struct plamen_broker_v2_fuzz_service_continuation *lease = NULL;
    struct plamen_broker_v2_fuzz_service_continuation *second = NULL;
    struct plamen_broker_v2_fuzz_service_terminal *terminal = NULL;
    struct plamen_broker_v2_apple_lifecycle_mount mounts[4];
    struct plamen_broker_v2_process_custody_client custody;
    uint8_t *projected = NULL, *terminal_bytes = NULL;
    uint8_t prepared[32], wrong[32], observed[32], secure[32];
    size_t projected_size = 0U, terminal_size = 0U, index;
    char root[] = "/tmp/plamen-fuzz-service.XXXXXX";
    char paths[4][256];
    int mount_fds[4] = {-1, -1, -1, -1};
    int cli_fd = -1, cwd_fd = -1, stdin_fd = -1, state_fd = -1;

    assert(mkdtemp(root) != NULL);
    for (index = 0U; index < 4U; ++index) {
        assert(snprintf(paths[index], sizeof(paths[index]), "%s/%zu",
            root, index) > 0);
        assert(mkdir(paths[index], 0700) == 0);
        mount_fds[index] = open(paths[index], O_RDONLY | O_CLOEXEC);
        assert(mount_fds[index] >= 0);
    }
    cli_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    cwd_fd = open(root, O_RDONLY | O_CLOEXEC);
    stdin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    state_fd = open(paths[2], O_RDONLY | O_CLOEXEC);
    assert(cli_fd >= 0 && cwd_fd >= 0 && stdin_fd >= 0 && state_fd >= 0);

    memset(&authority, 0, sizeof(authority));
    memset(&admission, 0, sizeof(admission));
    memset(&request, 0, sizeof(request));
    memset(&receipt, 0, sizeof(receipt));
    memset(mounts, 0, sizeof(mounts));
    memset(&custody, 0, sizeof(custody));
    fill(prepared, 0xa1U); fill(wrong, 0xb2U);
    authority.version = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_VERSION;
    authority.cli_fd = cli_fd; authority.cli_path = "/usr/local/bin/container";
    authority.cwd_fd = cwd_fd; authority.stdin_fd = stdin_fd;
    authority.state_directory_fd = state_fd; authority.admission = &admission;
    authority.custody_client = &custody;
    fill(authority.authority_binding_sha256, 0x61U);
    fill(authority.forge_executable_sha256, 0x19U);
    fill(authority.medusa_executable_sha256, 0x1aU);
    admission.version = 1U; admission.lifecycle_authority_granted = 0U;
    fill(admission.cli_sha256, 0x18U);
    fill(admission.provider_provenance_sha256, 0x17U);
    fill(admission.admission_sha256, 0x60U);
    strcpy(admission.runtime_image_reference,
        "plamen/runtime@sha256:fixture");
    authority.runtime_image_reference = admission.runtime_image_reference;

    request.version = PLAMEN_BROKER_V2_FUZZ_SERVICE_ADMISSION_VERSION;
    request.tool = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE;
    /* The public fuzz-workspace authority is request provenance, while the
     * session's audit binding remains a distinct native HMAC key. */
    fill(request.authority_sha256, 0x62U);
    fill(request.phase_io_binding_sha256, 0x15U);
    fill(request.admission_request_sha256, 0x10U);
    fill(request.provider_preflight_sha256, 0x16U);
    request.attempt_id = "dodo-fuzz-service-001";
    request.workspace_root = root;
    request.guest_argv = argv; request.guest_argc = 2U;
    request.timeout_seconds = 600U;
    for (index = 0U; index < 4U; ++index) {
        mounts[index].source_fd = mount_fds[index];
        mounts[index].source_path = paths[index];
        mounts[index].target_path = targets[index];
        mounts[index].readonly = index == 0U || index == 3U;
        assert(plamen_broker_v2_fd_identity(mount_fds[index],
            mounts[index].expected_identity_sha256) == 0);
    }

    assert(plamen_broker_v2_fuzz_service_acquire(&authority, &session) == 0);
    assert(session != NULL);
    close(cli_fd); close(cwd_fd); close(stdin_fd); close(state_fd);
    cli_fd = cwd_fd = stdin_fd = state_fd = -1;
    assert(plamen_broker_v2_fuzz_service_admit(session, &request, mounts, 4U,
        &receipt, &lease) == 0);
    assert(lease != NULL && receipt.canonical_secure_receipt_size != 0U);
    assert(strstr((const char *)receipt.canonical_secure_receipt,
        "\"payload_digest\":") != NULL);
    assert(plamen_broker_v2_fuzz_service_project_secure_receipt(
        lease, &projected, &projected_size) == 0);
    assert(projected_size == receipt.canonical_secure_receipt_size
        && memcmp(projected, receipt.canonical_secure_receipt,
            projected_size) == 0
        && plamen_broker_v2_sha256(projected, projected_size, observed) == 0
        && memcmp(observed, receipt.secure_receipt_sha256, 32U) == 0);
    memcpy(secure, receipt.secure_receipt_sha256, 32U);
    free(projected); projected = NULL;

    /* One service session cannot mint two concurrent continuations. */
    assert(plamen_broker_v2_fuzz_service_admit(session, &request, mounts, 4U,
        &receipt, &second) != 0 && second == NULL);
    reset();
    assert(plamen_broker_v2_fuzz_service_execute(session, lease, prepared,
        wrong, &terminal) != 0 && terminal == NULL);
    assert(create_count == 0 && start_count == 0 && wait_count == 0
        && delete_count == 0);
    assert(plamen_broker_v2_fuzz_service_execute(session, lease, prepared,
        secure, &terminal) == 0);
    assert(terminal != NULL && create_count == 1 && start_count == 1
        && wait_count == 1 && delete_count == 1 && revoke_count == 0);
    assert(plamen_broker_v2_fuzz_service_project_terminal(
        terminal, &terminal_bytes, &terminal_size) == 0);
    assert(terminal_size != 0U
        && strstr((const char *)terminal_bytes,
            "\"container_vm_stopped\":true") != NULL);
    free(terminal_bytes); terminal_bytes = NULL;
    plamen_broker_v2_fuzz_service_terminal_dispose(terminal); terminal = NULL;
    assert(plamen_broker_v2_fuzz_service_execute(session, lease, prepared,
        secure, &terminal) != 0 && terminal == NULL);

    /* Identity mismatch is rejected and releases admission ownership. */
    plamen_broker_v2_fuzz_service_continuation_dispose(lease); lease = NULL;
    mounts[0].expected_identity_sha256[0] ^= 1U;
    assert(plamen_broker_v2_fuzz_service_admit(session, &request, mounts, 4U,
        &receipt, &lease) != 0 && lease == NULL);
    mounts[0].expected_identity_sha256[0] ^= 1U;
    assert(plamen_broker_v2_fuzz_service_admit(session, &request, mounts, 4U,
        &receipt, &lease) == 0);

    plamen_broker_v2_fuzz_service_continuation_dispose(lease);
    plamen_broker_v2_fuzz_service_session_dispose(session);
    for (index = 0U; index < 4U; ++index) {
        close(mount_fds[index]); assert(rmdir(paths[index]) == 0);
    }
    assert(rmdir(root) == 0);
}

int main(void)
{
    test_tool_and_input_admission();
    test_full_lifecycle_and_recovery();
    test_atomic_service_admission_and_one_shot_execute();
    return 0;
}
