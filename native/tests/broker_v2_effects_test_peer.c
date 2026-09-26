#ifndef __APPLE__
#error "broker_v2_effects_test_peer.c is Darwin-only"
#endif

#define _DARWIN_C_SOURCE 1

#include "../darwin/plamen_broker_v2_effects.h"
#include "../darwin/plamen_broker_v2_fuzz_campaign.h"
#include "../darwin/plamen_broker_v2_specialized_apple_effect_execution.h"
#include "../darwin/plamen_broker_v2_specialized_effect_store.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

static void
fill(uint8_t output[32], uint8_t value)
{
    memset(output, value, 32);
}

/* This harness exercises only the generic operations/effects boundary.  Keep
 * its specialized provider dependencies inert and explicit so additions to
 * the production specialized executor cannot silently expand this fixture. */
int
plamen_broker_v2_specialized_runtime_handoff_create(
    const struct plamen_broker_v2_specialized_runtime_handoff_open *open,
    struct plamen_broker_v2_specialized_runtime_handoff **output)
{
    if (open == NULL || output == NULL) return -1;
    *output = (struct plamen_broker_v2_specialized_runtime_handoff *)(uintptr_t)1;
    return 0;
}

int
plamen_broker_v2_specialized_runtime_handoff_revalidate(
    const struct plamen_broker_v2_specialized_runtime_handoff *handoff)
{
    return handoff == (const struct plamen_broker_v2_specialized_runtime_handoff *)(uintptr_t)1
        ? 0 : -1;
}

int
plamen_broker_v2_specialized_runtime_handoff_authority_sha256(
    const struct plamen_broker_v2_specialized_runtime_handoff *handoff,
    uint8_t output[32])
{
    if (handoff == NULL || output == NULL) return -1;
    fill(output, 0x5aU); return 0;
}

int
plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
    struct plamen_broker_v2_specialized_runtime_handoff *handoff,
    uint16_t lane, const char *member,
    struct plamen_broker_v2_specialized_apple_runtime *runtime)
{
    (void)handoff; (void)lane; (void)member; (void)runtime; return -1;
}

void
plamen_broker_v2_specialized_runtime_handoff_destroy(
    struct plamen_broker_v2_specialized_runtime_handoff *handoff)
{
    (void)handoff;
}

int
plamen_broker_v2_specialized_effect_store_open(int directory_fd,
    const uint8_t key[32], const uint8_t authority[32],
    struct plamen_broker_v2_specialized_effect_store **store)
{
    (void)directory_fd; (void)key; (void)authority; (void)store; return -1;
}

void
plamen_broker_v2_specialized_effect_store_close(
    struct plamen_broker_v2_specialized_effect_store *store)
{
    (void)store;
}

int
plamen_broker_v2_specialized_apple_effect_execute_deny_all(
    const struct plamen_broker_v2_specialized_apple_effect_execution *execution,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    (void)execution; (void)evidence; return -1;
}

int
plamen_broker_v2_specialized_apple_effect_replay_js(
    struct plamen_broker_v2_specialized_effect_store *store,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_specialized_effect_completion *completion,
    uint8_t **terminal, size_t *terminal_size)
{
    (void)store; (void)view; (void)completion;
    (void)terminal; (void)terminal_size; return -1;
}

int
plamen_broker_v2_specialized_apple_effect_recover_projection(
    struct plamen_broker_v2_specialized_effect_store *store,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_specialized_effect_completion *completion,
    uint8_t **terminal, size_t *terminal_size)
{
    (void)store; (void)view; (void)completion;
    (void)terminal; (void)terminal_size; return -1;
}

#define INERT_RENDER(name) \
int name(const struct plamen_broker_v2_tool_effect_plan_view *view, \
    const struct plamen_broker_v2_specialized_worker_request_binding *binding, \
    const struct plamen_broker_v2_specialized_worker_terminal_observation *observation, \
    const struct plamen_broker_v2_specialized_output_receipt *receipt, \
    const uint8_t left[32], const uint8_t right[32], \
    uint8_t **terminal, size_t *terminal_size) \
{ \
    (void)view; (void)binding; (void)observation; (void)receipt; \
    (void)left; (void)right; (void)terminal; (void)terminal_size; return -1; \
}
INERT_RENDER(plamen_broker_v2_specialized_js_method_terminal_render)
INERT_RENDER(plamen_broker_v2_specialized_snapshot_method_terminal_render)
#undef INERT_RENDER

int
plamen_broker_v2_fuzz_campaign_request_decode(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_fuzz_campaign_request_storage *storage)
{
    (void)view; (void)storage; return -1;
}

int
plamen_broker_v2_fuzz_campaign_execute(
    const struct plamen_broker_v2_fuzz_campaign_authority *authority,
    const struct plamen_broker_v2_fuzz_campaign_request *request,
    struct plamen_broker_v2_fuzz_campaign_result *result)
{
    (void)authority; (void)request; (void)result; return -1;
}

int
plamen_broker_v2_fuzz_campaign_prepare(
    const struct plamen_broker_v2_fuzz_campaign_authority *authority,
    const struct plamen_broker_v2_fuzz_campaign_request *request,
    struct plamen_broker_v2_apple_lifecycle_commitments *commitments)
{
    (void)authority; (void)request; (void)commitments; return -1;
}

int
plamen_broker_v2_fuzz_campaign_result_render(
    const struct plamen_broker_v2_fuzz_campaign_request *request,
    const struct plamen_broker_v2_fuzz_campaign_authority *authority,
    const struct plamen_broker_v2_fuzz_campaign_result *result,
    uint8_t **terminal, size_t *terminal_size)
{
    (void)request; (void)authority; (void)result;
    (void)terminal; (void)terminal_size; return -1;
}

void
plamen_broker_v2_fuzz_campaign_result_dispose(
    struct plamen_broker_v2_fuzz_campaign_result *result)
{
    (void)result;
}

struct plamen_broker_v2_fuzz_service_session { int marker; };
struct plamen_broker_v2_fuzz_service_continuation { int marker; };
struct plamen_broker_v2_fuzz_service_terminal { int marker; };

int
plamen_broker_v2_fuzz_service_admission_request_decode(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_fuzz_service_admission_storage *storage)
{
    (void)view; (void)storage; return -1;
}

int
plamen_broker_v2_fuzz_service_execute_request_decode(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_fuzz_service_execute_request *request)
{
    (void)view; (void)request; return -1;
}

int
plamen_broker_v2_fuzz_service_acquire(
    const struct plamen_broker_v2_fuzz_campaign_authority *authority,
    struct plamen_broker_v2_fuzz_service_session **session)
{
    (void)authority; (void)session; return -1;
}

int
plamen_broker_v2_fuzz_service_admit(
    struct plamen_broker_v2_fuzz_service_session *session,
    const struct plamen_broker_v2_fuzz_service_admission_request *request,
    const struct plamen_broker_v2_apple_lifecycle_mount *mounts,
    size_t mount_count,
    struct plamen_broker_v2_fuzz_service_admission_receipt *receipt,
    struct plamen_broker_v2_fuzz_service_continuation **continuation)
{
    (void)session; (void)request; (void)mounts; (void)mount_count;
    (void)receipt; (void)continuation; return -1;
}

int
plamen_broker_v2_fuzz_service_project_secure_receipt(
    const struct plamen_broker_v2_fuzz_service_continuation *continuation,
    uint8_t **bytes, size_t *size)
{
    (void)continuation; (void)bytes; (void)size; return -1;
}

int
plamen_broker_v2_fuzz_service_execute(
    struct plamen_broker_v2_fuzz_service_session *session,
    struct plamen_broker_v2_fuzz_service_continuation *continuation,
    const uint8_t prepared[32], const uint8_t secure[32],
    struct plamen_broker_v2_fuzz_service_terminal **terminal)
{
    (void)session; (void)continuation; (void)prepared; (void)secure;
    (void)terminal; return -1;
}

int
plamen_broker_v2_fuzz_service_project_terminal(
    const struct plamen_broker_v2_fuzz_service_terminal *terminal,
    uint8_t **bytes, size_t *size)
{
    (void)terminal; (void)bytes; (void)size; return -1;
}

void plamen_broker_v2_fuzz_service_session_dispose(
    struct plamen_broker_v2_fuzz_service_session *session)
{ (void)session; }

void plamen_broker_v2_fuzz_service_continuation_dispose(
    struct plamen_broker_v2_fuzz_service_continuation *continuation)
{ (void)continuation; }

void plamen_broker_v2_fuzz_service_terminal_dispose(
    struct plamen_broker_v2_fuzz_service_terminal *terminal)
{ (void)terminal; }

static int
read_projection(const char *path, uint8_t **output, size_t *output_size)
{
    struct stat information;
    uint8_t *value = NULL;
    size_t completed = 0;
    int descriptor = -1;
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_size <= 0
        || information.st_size > (off_t)PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX)
        goto fail;
    value = malloc((size_t)information.st_size + 1U);
    if (value == NULL)
        goto fail;
    while (completed < (size_t)information.st_size) {
        ssize_t amount = read(descriptor, value + completed,
            (size_t)information.st_size - completed);
        if (amount <= 0)
            goto fail;
        completed += (size_t)amount;
    }
    value[completed] = 0;
    (void)close(descriptor);
    *output = value;
    *output_size = completed;
    return 0;
fail:
    if (descriptor >= 0)
        (void)close(descriptor);
    free(value);
    return -1;
}

static void
encode_hex32(const uint8_t input[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32; ++index) {
        output[index * 2U] = digits[input[index] >> 4];
        output[index * 2U + 1U] = digits[input[index] & 15U];
    }
    output[64] = '\0';
}

static int
replace_projection_identity(uint8_t *projection, size_t projection_size,
    const char *field_prefix, int descriptor)
{
    uint8_t identity[32];
    char hex[65];
    char *field;
    size_t prefix_size = strlen(field_prefix);
    if (projection == NULL || descriptor < 0
        || plamen_broker_v2_fd_identity(descriptor, identity) != 0)
        return -1;
    field = strstr((char *)projection, field_prefix);
    if (field == NULL
        || (size_t)(field - (char *)projection) + prefix_size + 64U
            > projection_size)
        return -1;
    encode_hex32(identity, hex);
    memcpy(field + prefix_size, hex, 64U);
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    plamen_broker_v2_secure_zero(hex, sizeof(hex));
    return 0;
}

static int
bind_projection_authorities(uint8_t *projection, size_t projection_size,
    const int fds[14])
{
    return replace_projection_identity(projection, projection_size,
            "\"retained_source_handle\":\"opaque:", fds[0]) == 0
        && replace_projection_identity(projection, projection_size,
            "\"target_identity_sha256\":\"", fds[1]) == 0
        && replace_projection_identity(projection, projection_size,
            "\"export_destination_identity_sha256\":\"", fds[4]) == 0
        ? 0 : -1;
}

static int
make_registration(struct plamen_broker_v2_service_registration *registration,
    const uint8_t *projection, size_t projection_size, const int fds[14])
{
    struct plamen_broker_v2_commitment commitment;
    size_t commitment_size = 0;
    size_t index;
    memset(registration, 0, sizeof(*registration));
    memset(&commitment, 0, sizeof(commitment));
    if (plamen_broker_v2_request_projection_derive_exact(projection,
            projection_size, &commitment, registration->commitment,
            sizeof(registration->commitment), &commitment_size,
            registration->request_projection_sha256,
            registration->commitment_sha256) != 0
        || commitment_size > UINT16_MAX)
        return -1;
    registration->commitment_size = (uint16_t)commitment_size;
    registration->request_projection_size = (uint32_t)projection_size;
    memcpy(registration->audit_request_fingerprint,
        commitment.request_fingerprint, 32);
    for (index = 0; index < 14; ++index) {
        if (fds[index] < 0)
            continue;
        registration->authority_presence_mask |=
            (uint16_t)(UINT16_C(1) << index);
        registration->authority_descriptors[index].purpose =
            (uint16_t)(PLAMEN_BROKER_V2_FD_AUTHORITY_CONFIG + index);
        registration->authority_descriptors[index].target =
            (uint16_t)(index + 1U);
        registration->authority_descriptors[index].access_mode =
            PLAMEN_BROKER_V2_FD_READ;
        if (plamen_broker_v2_fd_identity(fds[index],
                registration->authority_descriptors[index].identity) != 0)
            return -1;
    }
    return 0;
}

static int
open_authorities(char **paths, int fds[14])
{
    static const uint8_t slots[] = { 0, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    size_t index;
    for (index = 0; index < 14; ++index)
        fds[index] = -1;
    for (index = 0; index < sizeof(slots); ++index) {
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
        if (slots[index] == 1 || slots[index] == 4)
            flags |= O_DIRECTORY;
        fds[slots[index]] = open(paths[index], flags);
        if (fds[slots[index]] < 0)
            return -1;
        if (slots[index] == PLAMEN_BROKER_V2_RETAINED_CREDENTIAL
            && unlink(paths[index]) != 0)
            return -1;
    }
    return 0;
}

static int
run_test(int argc, char **argv)
{
    struct plamen_broker_v2_service_registration registration;
    struct plamen_broker_v2_effects_open open_request;
    struct plamen_broker_v2_effects_context *context = NULL;
    const struct plamen_broker_v2_operations_effects *effects;
    struct plamen_broker_v2_operations_effect_request request;
    struct plamen_broker_v2_operations_effect_result result;
    struct plamen_broker_v2_operations_argument argument;
    struct plamen_broker_v2_operations_replay_state replay_in, replay_out;
    struct plamen_broker_v2_commitment decoded_commitment;
    struct plamen_install_receipt_member runtime_member;
    struct plamen_install_receipt_specialized_authority runtime_auxiliary;
    uint8_t *projection = NULL;
    uint8_t operation_key[32], request_sha[32], conflict_sha[32];
    uint8_t replay_wire[32], kind = 0;
    size_t projection_size = 0, replay_wire_size = 0, index;
    int fds[14], sockets[2] = { -1, -1 }, state_fd = -1, writer = -1;
    int status;
    CHECK(argc == 14);
    CHECK(read_projection(argv[1], &projection, &projection_size) == 0);
    CHECK(open_authorities(&argv[3], fds) == 0);
    CHECK(bind_projection_authorities(projection, projection_size, fds) == 0);
    CHECK(make_registration(&registration, projection, projection_size, fds)
        == 0);
    memset(&decoded_commitment, 0, sizeof(decoded_commitment));
    memset(&runtime_member, 0, sizeof(runtime_member));
    memset(&runtime_auxiliary, 0, sizeof(runtime_auxiliary));
    CHECK(plamen_broker_v2_request_projection_validate_exact(projection,
        projection_size, registration.request_projection_sha256,
        registration.commitment, registration.commitment_size,
        registration.commitment_sha256, &decoded_commitment) == 0);
    CHECK(plamen_broker_v2_service_registration_descriptors_valid(
        &registration));
    state_fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(state_fd >= 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    CHECK(fcntl(sockets[0], F_SETFD, FD_CLOEXEC) == 0);
    CHECK(fcntl(sockets[1], F_SETFD, FD_CLOEXEC) == 0);
    memset(&open_request, 0, sizeof(open_request));
    open_request.version = PLAMEN_BROKER_V2_EFFECTS_VERSION;
    open_request.registration = &registration;
    open_request.request_projection = projection;
    open_request.request_projection_size = projection_size;
    open_request.state_parent_fd = state_fd;
    open_request.generation_fd = state_fd;
    open_request.runtime_manifest_fd = fds[6];
    open_request.runtime_manifest_member = &runtime_member;
    open_request.image_member_receipt_fd = fds[5];
    open_request.specialized_runtime_auxiliary = &runtime_auxiliary;
    open_request.custody_client =
        (struct plamen_broker_v2_process_custody_client *)(uintptr_t)1;
    open_request.cancellation_fd = sockets[0];
    open_request.authority_fds = fds;
    open_request.authority_fd_count = 14;

    /* A failed create consumes no caller descriptor. */
    CHECK(plamen_broker_v2_effects_create(&open_request, &context) != 0);
    CHECK(context == NULL);
    for (index = 0; index < 14; ++index) {
        int present = (registration.authority_presence_mask
            & (uint16_t)(UINT16_C(1) << index)) != 0;
        CHECK(present ? fds[index] >= 0 : fds[index] == -1);
    }

    fill(open_request.authority_binding_sha256, 9);
    CHECK(plamen_broker_v2_effects_create(&open_request, &context) == 0);
    CHECK(context != NULL);
    for (index = 0; index < 14; ++index)
        CHECK(fds[index] == -1);
    effects = plamen_broker_v2_effects_operations(context);
    CHECK(effects != NULL && effects->version
        == PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION);
    CHECK(effects->revalidate(effects->context,
        registration.audit_request_fingerprint,
        registration.request_projection_sha256,
        open_request.authority_binding_sha256, 4,
        PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND) == 0);

    memset(&request, 0, sizeof(request));
    memset(&result, 0, sizeof(result));
    memset(&argument, 0, sizeof(argument));
    request.version = PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION;
    request.member = PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE;
    request.method = PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET;
    memcpy(request.request_fingerprint_sha256,
        registration.audit_request_fingerprint, 32);
    request.monotonic_deadline_ms = effects->monotonic_ms(effects->context)
        + UINT64_C(10000);
    argument.name = "request";
    argument.type = "AuditRequest";
    fill(argument.commitment_sha256, 14);
    request.arguments = &argument;
    request.argument_count = 1;
    CHECK(effects->execute(effects->context, &request, &result)
        == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK);
    CHECK(result.canonical_result_size > sizeof("{\"$type\":\"TargetLease\"")
        && memcmp(result.canonical_result, "{\"$type\":\"TargetLease\"",
            sizeof("{\"$type\":\"TargetLease\"") - 1U) == 0);
    CHECK(result.effect_applied == 0 && result.durability_proven == 1);
    effects->dispose_result(effects->context, &result);

    memset(&request, 0, sizeof(request));
    memset(&result, 0, sizeof(result));
    request.version = PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION;
    request.member = 4;
    request.method = PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND;
    memcpy(request.request_fingerprint_sha256,
        registration.audit_request_fingerprint, 32);
    request.monotonic_deadline_ms = effects->monotonic_ms(effects->context)
        + UINT64_C(10000);
    CHECK(effects->execute(effects->context, &request, &result)
        == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK);
    CHECK(result.canonical_result_size == 50);
    CHECK(memcmp(result.canonical_result,
        "{\"$enum\":\"ProviderKind\",\"value\":\"APPLE_CONTAINER\"}", 50)
        == 0);
    CHECK(result.effect_applied == 0 && result.durability_proven == 1);
    effects->dispose_result(effects->context, &result);

    memset(&replay_in, 0, sizeof(replay_in));
    replay_in.version = PLAMEN_BROKER_V2_OPERATIONS_VERSION;
    fill(replay_in.current_checkpoint_sha256, 10);
    replay_in.journal_opened = 1;
    fill(operation_key, 11);
    fill(request_sha, 12);
    fill(conflict_sha, 13);
    CHECK(effects->replay_commit(effects->context, operation_key, request_sha,
        PLAMEN_BROKER_V2_OPERATIONS_RESPONSE, (const uint8_t *)"true", 4,
        &replay_in) == 0);
    memset(&replay_out, 0xa5, sizeof(replay_out));
    CHECK(effects->replay_lookup(effects->context, operation_key, request_sha,
        &kind, replay_wire, sizeof(replay_wire), &replay_wire_size,
        &replay_out) == PLAMEN_BROKER_V2_OPERATIONS_REPLAY_FOUND);
    CHECK(kind == PLAMEN_BROKER_V2_OPERATIONS_RESPONSE
        && replay_wire_size == 4 && memcmp(replay_wire, "true", 4) == 0
        && memcmp(&replay_in, &replay_out, sizeof(replay_in)) == 0);
    CHECK(effects->replay_lookup(effects->context, operation_key, conflict_sha,
        &kind, replay_wire, sizeof(replay_wire), &replay_wire_size,
        &replay_out) == PLAMEN_BROKER_V2_OPERATIONS_REPLAY_CONFLICT);

    /* Retained identity drift burns revalidation before another effect. */
    writer = open(argv[3], O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    CHECK(writer >= 0 && write(writer, "x", 1) == 1 && close(writer) == 0);
    writer = -1;
    status = effects->revalidate(effects->context,
        registration.audit_request_fingerprint,
        registration.request_projection_sha256,
        open_request.authority_binding_sha256, 4,
        PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND);
    CHECK(status != 0);

    plamen_broker_v2_effects_destroy(context);
    free(projection);
    (void)close(sockets[0]);
    (void)close(sockets[1]);
    (void)close(state_fd);
    return 0;
}

int
main(int argc, char **argv)
{
    int line = run_test(argc, argv);
    if (line != 0)
        fprintf(stderr, "effects test failed at line %d\n", line);
    return line == 0 ? 0 : 1;
}
