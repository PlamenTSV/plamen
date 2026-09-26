#include "plamen_broker_v2_operations.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #value); \
    return 1; \
} } while (0)

struct replay_row {
    uint8_t key[32];
    uint8_t request[32];
    uint8_t kind;
    uint8_t *wire;
    size_t wire_size;
};

struct fake_context {
    struct replay_row rows[64];
    size_t row_count;
    unsigned int execute_count;
    unsigned int revalidate_count;
    int revalidate_failure;
    int cancelled;
    uint64_t now;
    uint64_t last_deadline;
};

static int
same(const uint8_t *left, const uint8_t *right)
{
    return memcmp(left, right, 32) == 0;
}

static void
fill(uint8_t value[32], uint8_t byte)
{
    memset(value, byte, 32);
}

static int
revalidate(void *opaque, const uint8_t fingerprint[32],
    const uint8_t projection[32], const uint8_t authority[32],
    uint16_t member, uint16_t method)
{
    struct fake_context *context = opaque;
    (void)member;
    (void)method;
    ++context->revalidate_count;
    return context->revalidate_failure || fingerprint[0] != 0x11
        || projection[0] != 0x33 || authority[0] != 0x44 ? -1 : 0;
}

static uint64_t
monotonic_ms(void *opaque)
{
    return ((struct fake_context *)opaque)->now;
}

static int
cancelled(void *opaque)
{
    return ((struct fake_context *)opaque)->cancelled;
}

static const char *
result_for(uint16_t method)
{
    switch (method) {
    case PLAMEN_BROKER_V2_METHOD_RUNTIME_AUTHENTICATE:
        return "{\"$type\":\"AuthenticatedRuntimeImageLayout\",\"fields\":{\"authenticated\":true,\"docs_handle\":null,\"docs_sha256\":null,\"driver_path\":null,\"guest_architecture\":null,\"guest_os\":null,\"image_closure_sha256\":null,\"image_handle\":null,\"image_manifest_digest\":null,\"immutable\":true,\"python_path\":null,\"runtime_handle\":null,\"runtime_layout_sha256\":null}}";
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET:
        return "{\"$type\":\"TargetLease\",\"fields\":{\"authenticated\":true,\"content_sha256\":null,\"identity_sha256\":null,\"readonly\":true,\"scratchpad_absent\":true,\"target_handle\":null}}";
    case PLAMEN_BROKER_V2_METHOD_BACKEND_AUTHENTICATE:
        return "{\"$type\":\"BackendContext\",\"fields\":{\"authenticated\":true,\"backend\":null,\"backend_admission_sha256\":null,\"context_handle\":null,\"context_sha256\":null,\"credential_handle\":null,\"credential_isolation_sha256\":null,\"credential_sha256\":null,\"egress_admission_sha256\":null,\"egress_policy_sha256\":null,\"inherited_environment\":{\"$tuple\":[]},\"network_mode\":null}}";
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND:
        return "{\"$enum\":\"ProviderKind\",\"value\":\"APPLE_CONTAINER\"}";
    case PLAMEN_BROKER_V2_METHOD_JOURNAL_OPEN:
        return "{\"$type\":\"JournalOpenReceipt\",\"fields\":{\"checkpoint\":null,\"pending\":null,\"status\":null}}";
    case PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM:
        return "{\"$type\":\"MutationTicket\",\"fields\":{\"attempt_id\":null,\"authenticated\":true,\"before_checkpoint_sha256\":null,\"nonce\":null,\"operation\":null,\"request_fingerprint_sha256\":null,\"sequence\":1}}";
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_PREPARE_LAYOUT:
        return "{\"$type\":\"AttemptLayout\",\"fields\":{\"attempt_id\":null,\"control_handle\":null,\"export_destination_handle\":null,\"export_destination_identity_sha256\":null,\"layout_handle\":null,\"merged_handle\":null,\"private_attempt_owned\":true,\"run_id\":null,\"run_store_outside_target\":true,\"scope_handle\":null,\"scope_sha256\":null,\"scratch_handle\":null,\"seccomp_handle\":null,\"seccomp_sha256\":null,\"state_handle\":null,\"target_identity_sha256\":null,\"target_lower_handle\":null,\"target_lower_readonly\":true,\"upper_handle\":null,\"work_handle\":null}}";
    case PLAMEN_BROKER_V2_METHOD_JOURNAL_COMMIT:
    case PLAMEN_BROKER_V2_METHOD_JOURNAL_RESOLVE:
    case PLAMEN_BROKER_V2_METHOD_JOURNAL_FINISH:
        return "true";
    default:
        return NULL;
    }
}

static int
execute(void *opaque,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct fake_context *context = opaque;
    const char *wire = result_for(request->method);
    ++context->execute_count;
    context->last_deadline = request->monotonic_deadline_ms;
    if (wire == NULL) return PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    result->canonical_result = (const uint8_t *)wire;
    result->canonical_result_size = strlen(wire);
    fill(result->result_commitment_sha256,
        (uint8_t)((request->method & 0xffU) == 0
            ? 0x5aU : request->method & 0xffU));
    fill(result->durable_checkpoint_sha256, 0x99);
    result->durable_stage = PLAMEN_BROKER_V2_OPERATIONS_STAGE_EMPTY;
    result->effect_applied = 1;
    result->durability_proven = 1;
    return PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
}

static void
dispose_result(void *opaque,
    struct plamen_broker_v2_operations_effect_result *result)
{
    (void)opaque;
    memset(result, 0, sizeof(*result));
}

static int
replay_lookup(void *opaque, const uint8_t key[32],
    const uint8_t request[32], uint8_t *kind, uint8_t *wire,
    size_t capacity, size_t *wire_size,
    struct plamen_broker_v2_operations_replay_state *state)
{
    struct fake_context *context = opaque;
    size_t index;
    for (index = 0; index < context->row_count; ++index) {
        if (!same(context->rows[index].key, key)) continue;
        if (!same(context->rows[index].request, request))
            return PLAMEN_BROKER_V2_OPERATIONS_REPLAY_CONFLICT;
        if (context->rows[index].wire_size > capacity) return -1;
        *kind = context->rows[index].kind;
        *wire_size = context->rows[index].wire_size;
        memcpy(wire, context->rows[index].wire, *wire_size);
        memset(state, 0, sizeof(*state));
        state->version = PLAMEN_BROKER_V2_OPERATIONS_VERSION;
        fill(state->current_checkpoint_sha256, 0x55);
        return PLAMEN_BROKER_V2_OPERATIONS_REPLAY_FOUND;
    }
    return PLAMEN_BROKER_V2_OPERATIONS_REPLAY_MISS;
}

static int
replay_commit(void *opaque, const uint8_t key[32],
    const uint8_t request[32], uint8_t kind, const uint8_t *wire,
    size_t wire_size,
    const struct plamen_broker_v2_operations_replay_state *state)
{
    struct fake_context *context = opaque;
    struct replay_row *row;
    (void)state;
    if (context->row_count >= 64) return -1;
    row = &context->rows[context->row_count++];
    row->wire = malloc(wire_size);
    if (row->wire == NULL) return -1;
    memcpy(row->key, key, 32);
    memcpy(row->request, request, 32);
    memcpy(row->wire, wire, wire_size);
    row->wire_size = wire_size;
    row->kind = kind;
    return 0;
}

static struct plamen_broker_v2_operations_effects
effects(struct fake_context *context)
{
    struct plamen_broker_v2_operations_effects value;
    memset(&value, 0, sizeof(value));
    value.version = PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION;
    value.context = context;
    value.revalidate = revalidate;
    value.monotonic_ms = monotonic_ms;
    value.cancelled = cancelled;
    value.execute = execute;
    value.dispose_result = dispose_result;
    value.replay_lookup = replay_lookup;
    value.replay_commit = replay_commit;
    return value;
}

static struct plamen_broker_v2_operations_open
open_value(struct plamen_broker_v2_operations_effects *effect)
{
    struct plamen_broker_v2_operations_open open;
    size_t index;
    memset(&open, 0, sizeof(open));
    open.version = PLAMEN_BROKER_V2_OPERATIONS_VERSION;
    fill(open.request_fingerprint_sha256, 0x11);
    fill(open.request_commitment_sha256, 0x22);
    fill(open.projection_sha256, 0x33);
    fill(open.authority_binding_sha256, 0x44);
    fill(open.initial_checkpoint_sha256, 0x55);
    open.authority_bundle.role = PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    open.authority_bundle.member_count =
        PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT;
    fill(open.authority_bundle.registration_sha256, 0x66);
    fill(open.authority_bundle.issuance_checkpoint_sha256, 0x55);
    for (index = 0; index < PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT;
            ++index)
        fill(open.authority_bundle.member_sha256[index],
            (uint8_t)(index + 1));
    open.effects = effect;
    return open;
}

static void
hex32(const uint8_t digest[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32; ++index) {
        output[index * 2] = digits[digest[index] >> 4];
        output[index * 2 + 1] = digits[digest[index] & 15];
    }
    output[64] = 0;
}

static int
string_commitment(const char *value, char output[65])
{
    uint8_t digest[32];
    size_t size = strlen(value);
    uint8_t *canonical = malloc(size + 3);
    canonical[0] = '"';
    memcpy(canonical + 1, value, size);
    canonical[size + 1] = '"';
    canonical[size + 2] = '\n';
    if (canonical == NULL) return -1;
    if (plamen_broker_v2_sha256(canonical, size + 3, digest) != 0) {
        free(canonical);
        return -1;
    }
    hex32(digest, output);
    free(canonical);
    return 0;
}

static char *
call0(const char *member, const char *operation)
{
    uint8_t digest[32];
    char commitment[65], fingerprint[65];
    char *value = malloc(1024);
    fill(digest, 0x22); hex32(digest, commitment);
    fill(digest, 0x11); hex32(digest, fingerprint);
    snprintf(value, 1024,
        "{\"arguments\":[],\"member\":\"%s\",\"operation\":\"%s\",\"receipt_commitments\":[],\"request_commitment_sha256\":\"%s\",\"request_fingerprint_sha256\":\"%s\",\"schema\":\"plamen.native-supervisor-call.v1\"}\n",
        member, operation, commitment, fingerprint);
    return value;
}

static char *
call_request(const char *member, const char *operation)
{
    uint8_t digest[32];
    char commitment[65], fingerprint[65];
    char *value = malloc(2048);
    fill(digest, 0x22); hex32(digest, commitment);
    fill(digest, 0x11); hex32(digest, fingerprint);
    snprintf(value, 2048,
        "{\"arguments\":[{\"commitment_sha256\":\"%s\",\"name\":\"request\",\"type\":\"AuditRequest\"}],\"member\":\"%s\",\"operation\":\"%s\",\"receipt_commitments\":[],\"request_commitment_sha256\":\"%s\",\"request_fingerprint_sha256\":\"%s\",\"schema\":\"plamen.native-supervisor-call.v1\"}\n",
        commitment, member, operation, commitment, fingerprint);
    return value;
}

static char *
call_arm(const uint8_t checkpoint[32])
{
    uint8_t digest[32];
    char commitment[65], fingerprint[65];
    char checkpoint_hex[65], operation_sha[65], checkpoint_sha[65];
    char *value = malloc(4096);
    hex32(checkpoint, checkpoint_hex);
    fill(digest, 0x22); hex32(digest, commitment);
    fill(digest, 0x11); hex32(digest, fingerprint);
    if (string_commitment("PREPARE_LAYOUT", operation_sha) != 0
        || string_commitment(checkpoint_hex, checkpoint_sha) != 0) {
        free(value);
        return NULL;
    }
    snprintf(value, 4096,
        "{\"arguments\":[{\"commitment_sha256\":\"%s\",\"name\":\"request\",\"type\":\"AuditRequest\"},{\"commitment_sha256\":\"%s\",\"name\":\"operation\",\"type\":\"MutationOperation\",\"value\":\"PREPARE_LAYOUT\"},{\"commitment_sha256\":\"%s\",\"name\":\"before_checkpoint_sha256\",\"type\":\"str\",\"value\":\"%s\"}],\"member\":\"journal\",\"operation\":\"arm\",\"receipt_commitments\":[],\"request_commitment_sha256\":\"%s\",\"request_fingerprint_sha256\":\"%s\",\"schema\":\"plamen.native-supervisor-call.v1\"}\n",
        commitment, operation_sha, checkpoint_sha, checkpoint_hex,
        commitment, fingerprint);
    return value;
}

static char *
call_prepare(const uint8_t ticket[32])
{
    uint8_t digest[32];
    char ticket_hex[65], commitment[65], fingerprint[65], target[65];
    char *value = malloc(4096);
    hex32(ticket, ticket_hex);
    fill(digest, 0x22); hex32(digest, commitment);
    fill(digest, 0x11); hex32(digest, fingerprint);
    fill(digest, 0x02); hex32(digest, target);
    snprintf(value, 4096,
        "{\"arguments\":[{\"commitment_sha256\":\"%s\",\"name\":\"request\",\"type\":\"AuditRequest\"},{\"commitment_sha256\":\"%s\",\"name\":\"target\",\"type\":\"TargetLease\"},{\"commitment_sha256\":\"%s\",\"name\":\"ticket\",\"type\":\"MutationTicket\"}],\"member\":\"workspace\",\"operation\":\"prepare_layout\",\"receipt_commitments\":[{\"name\":\"target\",\"sha256\":\"%s\",\"type\":\"TargetLease\"},{\"name\":\"ticket\",\"sha256\":\"%s\",\"type\":\"MutationTicket\"}],\"request_commitment_sha256\":\"%s\",\"request_fingerprint_sha256\":\"%s\",\"schema\":\"plamen.native-supervisor-call.v1\"}\n",
        commitment, target, ticket_hex, target, ticket_hex, commitment,
        fingerprint);
    return value;
}

static char *
call_commit(const uint8_t ticket[32], const uint8_t checkpoint[32])
{
    uint8_t digest[32];
    char ticket_hex[65], checkpoint_hex[65], commitment[65], fingerprint[65];
    char *value = malloc(4096);
    hex32(ticket, ticket_hex);
    hex32(checkpoint, checkpoint_hex);
    fill(digest, 0x22); hex32(digest, commitment);
    fill(digest, 0x11); hex32(digest, fingerprint);
    snprintf(value, 4096,
        "{\"arguments\":[{\"commitment_sha256\":\"%s\",\"name\":\"request\",\"type\":\"AuditRequest\"},{\"commitment_sha256\":\"%s\",\"name\":\"ticket\",\"type\":\"MutationTicket\"},{\"commitment_sha256\":\"%s\",\"name\":\"checkpoint\",\"type\":\"SupervisorCheckpoint\"}],\"member\":\"journal\",\"operation\":\"commit\",\"receipt_commitments\":[{\"name\":\"ticket\",\"sha256\":\"%s\",\"type\":\"MutationTicket\"},{\"name\":\"checkpoint\",\"sha256\":\"%s\",\"type\":\"SupervisorCheckpoint\"}],\"request_commitment_sha256\":\"%s\",\"request_fingerprint_sha256\":\"%s\",\"schema\":\"plamen.native-supervisor-call.v1\"}\n",
        commitment, ticket_hex, checkpoint_hex, ticket_hex, checkpoint_hex,
        commitment, fingerprint);
    return value;
}

static int
dispatch(struct plamen_broker_v2_operations_session *session,
    uint16_t member, uint16_t method, uint8_t key_byte,
    const uint8_t prior[32], char *call,
    struct plamen_broker_v2_operations_dispatch_result *result,
    struct plamen_broker_v2_operation_request *saved)
{
    struct plamen_broker_v2_operation_request request;
    uint8_t *encoded;
    uint8_t request_sha[32];
    size_t encoded_size = 0;
    memset(&request, 0, sizeof(request));
    request.authority_role = PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    request.member = member;
    request.method = method;
    fill(request.operation_key, key_byte);
    fill(request.request_fingerprint, 0x11);
    memcpy(request.prior_checkpoint_sha256, prior, 32);
    request.payload = (const uint8_t *)call;
    request.payload_size = (uint32_t)strlen(call);
    CHECK(plamen_broker_v2_sha256(request.payload, request.payload_size,
        request.payload_sha256) == 0);
    encoded = malloc(PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE
        + request.payload_size);
    CHECK(encoded != NULL);
    CHECK(plamen_broker_v2_operation_request_encode(&request, encoded,
        PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE + request.payload_size,
        &encoded_size) == 0);
    CHECK(plamen_broker_v2_sha256(encoded, encoded_size, request_sha) == 0);
    free(encoded);
    if (saved != NULL) *saved = request;
    return plamen_broker_v2_operations_dispatch(session, &request, request_sha,
        request.payload, request.payload_size, result);
}

static void
free_context(struct fake_context *context)
{
    size_t index;
    for (index = 0; index < context->row_count; ++index)
        free(context->rows[index].wire);
}

int
main(void)
{
    struct fake_context context;
    struct plamen_broker_v2_operations_effects effect;
    struct plamen_broker_v2_operations_open open;
    struct plamen_broker_v2_operations_session *session = NULL;
    struct plamen_broker_v2_operations_dispatch_result result, replayed;
    struct plamen_broker_v2_operation_response response;
    struct plamen_broker_v2_operation_error error;
    struct plamen_broker_v2_operation_request saved;
    uint8_t checkpoint[32], ticket[32], wrong_ticket[32];
    char *call;
    unsigned int executions;

    memset(&context, 0, sizeof(context));
    context.now = 1000;
    effect = effects(&context);
    open = open_value(&effect);
    CHECK(plamen_broker_v2_operations_session_open(&open, &session) == 0);
    CHECK(session != NULL && context.revalidate_count == 1);

    /* Provider identity is rejected before prerequisite authentication. */
    fill(checkpoint, 0x55);
    call = call0("provider", "provider_kind");
    CHECK(dispatch(session, 4, PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND,
        1, checkpoint, call, &result, NULL) == 0);
    CHECK(result.kind == PLAMEN_BROKER_V2_OPERATIONS_ERROR);
    CHECK(plamen_broker_v2_operation_error_decode(result.wire,
        result.wire_size, &error) == 0);
    CHECK(error.error_code == PLAMEN_BROKER_V2_OPERATIONS_ERR_ORDER);
    plamen_broker_v2_operations_dispatch_result_dispose(&result);
    free(call);

    call = call_request("runtime", "authenticate");
    CHECK(dispatch(session, 1, PLAMEN_BROKER_V2_METHOD_RUNTIME_AUTHENTICATE,
        2, checkpoint, call, &result, NULL) == 0);
    CHECK(result.kind == PLAMEN_BROKER_V2_OPERATIONS_RESPONSE);
    CHECK(context.last_deadline == 61000);
    plamen_broker_v2_operations_dispatch_result_dispose(&result);
    free(call);

    call = call_request("workspace", "admit_target");
    CHECK(dispatch(session, 2, PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET,
        3, checkpoint, call, &result, NULL) == 0);
    plamen_broker_v2_operations_dispatch_result_dispose(&result);
    free(call);
    call = call_request("backend", "authenticate");
    CHECK(dispatch(session, 3, PLAMEN_BROKER_V2_METHOD_BACKEND_AUTHENTICATE,
        4, checkpoint, call, &result, NULL) == 0);
    plamen_broker_v2_operations_dispatch_result_dispose(&result);
    free(call);

    call = call0("provider", "provider_kind");
    CHECK(dispatch(session, 4, PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND,
        5, checkpoint, call, &result, &saved) == 0);
    CHECK(result.kind == PLAMEN_BROKER_V2_OPERATIONS_RESPONSE);
    CHECK(plamen_broker_v2_operation_response_decode(result.wire,
        result.wire_size, &response) == 0);
    executions = context.execute_count;
    /* Same operation key/request is byte-identically replayed without effect. */
    CHECK(dispatch(session, 4, PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND,
        5, checkpoint, call, &replayed, NULL) == 0);
    CHECK(replayed.replayed == 1 && replayed.wire_size == result.wire_size);
    CHECK(memcmp(replayed.wire, result.wire, result.wire_size) == 0);
    CHECK(context.execute_count == executions);
    plamen_broker_v2_operations_dispatch_result_dispose(&replayed);
    plamen_broker_v2_operations_dispatch_result_dispose(&result);
    free(call);

    call = call_request("journal", "open");
    CHECK(dispatch(session, 9, PLAMEN_BROKER_V2_METHOD_JOURNAL_OPEN,
        6, checkpoint, call, &result, NULL) == 0);
    CHECK(plamen_broker_v2_operation_response_decode(result.wire,
        result.wire_size, &response) == 0);
    memcpy(checkpoint, response.next_checkpoint_sha256, 32);
    CHECK(checkpoint[0] == 0x99);
    plamen_broker_v2_operations_dispatch_result_dispose(&result);
    free(call);

    call = call_arm(checkpoint);
    CHECK(dispatch(session, 9, PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM,
        7, checkpoint, call, &result, NULL) == 0);
    CHECK(context.last_deadline == 1801000);
    fill(ticket, (uint8_t)(PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM & 0xff));
    plamen_broker_v2_operations_dispatch_result_dispose(&result);
    free(call);

    /* A Python-supplied ticket commitment cannot select another authority. */
    fill(wrong_ticket, 0xaa);
    call = call_prepare(wrong_ticket);
    CHECK(dispatch(session, 2,
        PLAMEN_BROKER_V2_METHOD_WORKSPACE_PREPARE_LAYOUT, 8, checkpoint,
        call, &result, NULL) == 0);
    CHECK(result.kind == PLAMEN_BROKER_V2_OPERATIONS_ERROR);
    plamen_broker_v2_operations_dispatch_result_dispose(&result);
    free(call);

    call = call_prepare(ticket);
    CHECK(dispatch(session, 2,
        PLAMEN_BROKER_V2_METHOD_WORKSPACE_PREPARE_LAYOUT, 9, checkpoint,
        call, &result, NULL) == 0);
    CHECK(result.kind == PLAMEN_BROKER_V2_OPERATIONS_RESPONSE);
    plamen_broker_v2_operations_dispatch_result_dispose(&result);
    free(call);

    fill(wrong_ticket, 0xab);
    call = call_commit(ticket, wrong_ticket);
    CHECK(dispatch(session, 9, PLAMEN_BROKER_V2_METHOD_JOURNAL_COMMIT,
        10, checkpoint, call, &result, NULL) == 0);
    CHECK(plamen_broker_v2_operation_response_decode(result.wire,
        result.wire_size, &response) == 0);
    CHECK(same(response.next_checkpoint_sha256, wrong_ticket));
    memcpy(checkpoint, response.next_checkpoint_sha256, 32);
    plamen_broker_v2_operations_dispatch_result_dispose(&result);
    free(call);

    /* Reusing an operation key with different bytes is a fatal conflict. */
    call = call0("provider", "not_provider_kind");
    CHECK(dispatch(session, 4, PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND,
        5, checkpoint, call, &result, NULL) != 0);
    CHECK(result.wire == NULL);
    free(call);

    plamen_broker_v2_operations_session_close(session);
    free_context(&context);

    /* Missing descriptor-custody effects and failed revalidation are refused. */
    memset(&context, 0, sizeof(context));
    context.now = 1;
    effect = effects(&context);
    open = open_value(&effect);
    open.effects = NULL;
    CHECK(plamen_broker_v2_operations_session_open(&open, &session) != 0);
    open.effects = &effect;
    context.revalidate_failure = 1;
    CHECK(plamen_broker_v2_operations_session_open(&open, &session) != 0);
    context.revalidate_failure = 0;

    /* Cancellation before an effect burns the native session with no reply. */
    CHECK(plamen_broker_v2_operations_session_open(&open, &session) == 0);
    context.cancelled = 1;
    fill(checkpoint, 0x55);
    call = call_request("runtime", "authenticate");
    CHECK(dispatch(session, 1, PLAMEN_BROKER_V2_METHOD_RUNTIME_AUTHENTICATE,
        10, checkpoint, call, &result, NULL) != 0);
    CHECK(result.wire == NULL);
    free(call);
    plamen_broker_v2_operations_session_close(session);
    free_context(&context);
    (void)saved;
    return 0;
}
