#include "plamen_broker_v2_operations.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CALL_SCHEMA "plamen.native-supervisor-call.v1"
#define RESPONSE_SCHEMA "plamen.native-supervisor-response.v1"
#define MAX_JSON_DEPTH 64U
#define MAX_JSON_NODES 131072U
#define MAX_JSON_KEY 128U

struct argument_spec {
    const char *name;
    const char *type;
    uint8_t receipt;
    uint8_t scalar;
};

struct method_spec {
    uint16_t member;
    uint16_t method;
    const char *member_name;
    const char *operation_name;
    const char *result_type;
    const struct argument_spec *arguments;
    uint8_t argument_count;
    uint8_t result_kind; /* 1 dataclass, 2 enum, 3 true */
    uint8_t mutation_operation;
    uint8_t observational;
};

struct parsed_argument {
    char name[64];
    char type[64];
    uint8_t commitment[32];
    char scalar[PLAMEN_BROKER_V2_OPERATIONS_SCALAR_MAX + 1U];
    size_t scalar_size;
    uint8_t scalar_present;
};

struct parsed_call {
    struct parsed_argument arguments[PLAMEN_BROKER_V2_OPERATIONS_MAX_ARGUMENTS];
    size_t argument_count;
};

struct json_cursor {
    const uint8_t *data;
    size_t size;
    size_t offset;
    size_t nodes;
};

struct plamen_broker_v2_operations_session {
    uint8_t request_fingerprint[32];
    uint8_t request_commitment[32];
    uint8_t projection_sha256[32];
    uint8_t authority_binding_sha256[32];
    uint8_t current_checkpoint[32];
    uint8_t pending_ticket[32];
    struct plamen_broker_v2_authority_bundle_binding bundle;
    const struct plamen_broker_v2_operations_effects *effects;
    uint16_t stage;
    uint16_t pending_operation;
    uint8_t journal_opened;
    uint8_t runtime_authenticated;
    uint8_t target_admitted;
    uint8_t backend_authenticated;
    uint8_t provider_known;
    uint8_t pending_effect_seen;
    uint8_t recovery_seen;
    uint8_t recovery_applied;
    uint8_t finished;
    uint8_t burned;
    uint32_t new_rpc_count;
};

#define ARG(name_, type_, receipt_, scalar_) \
    { name_, type_, receipt_, scalar_ }

static const struct argument_spec a_request[] = {
    ARG("request", "AuditRequest", 0, 0)
};
static const struct argument_spec a_request_target[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("target", "TargetLease", 1, 0)
};
static const struct argument_spec a_prepare_layout[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("target", "TargetLease", 1, 0),
    ARG("ticket", "MutationTicket", 1, 0)
};
static const struct argument_spec a_resume_layout[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("layout", "AttemptLayout", 1, 0)
};
static const struct argument_spec a_write_config[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("layout", "AttemptLayout", 1, 0),
    ARG("config", "GuestConfig", 0, 0),
    ARG("ticket", "MutationTicket", 1, 0)
};
static const struct argument_spec a_recensus[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("target", "TargetLease", 1, 0),
    ARG("layout", "AttemptLayout", 1, 0),
    ARG("runtime", "AuthenticatedRuntimeImageLayout", 1, 0),
    ARG("backend", "BackendContext", 1, 0),
    ARG("configured", "ConfigReceipt", 1, 0),
    ARG("phase", "str", 0, 1)
};
static const struct argument_spec a_create[] = {
    ARG("spec", "GuestCreateSpec", 0, 0),
    ARG("ticket", "MutationTicket", 1, 0)
};
static const struct argument_spec a_created[] = {
    ARG("created", "GuestCreatedReceipt", 1, 0)
};
static const struct argument_spec a_resume_guest[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("created", "GuestCreatedReceipt", 1, 0)
};
static const struct argument_spec a_start[] = {
    ARG("created", "GuestCreatedReceipt", 1, 0),
    ARG("admission", "GuestAdmissionReceipt", 1, 0),
    ARG("launch", "DriverLaunch", 0, 0),
    ARG("ticket", "MutationTicket", 1, 0)
};
static const struct argument_spec a_wait[] = {
    ARG("created", "GuestCreatedReceipt", 1, 0),
    ARG("started", "DriverStartReceipt", 1, 0),
    ARG("ticket", "MutationTicket", 1, 0)
};
static const struct argument_spec a_delete[] = {
    ARG("created", "GuestCreatedReceipt", 1, 0),
    ARG("terminal", "ExtinctionReceipt", 1, 0),
    ARG("ticket", "MutationTicket", 1, 0)
};
static const struct argument_spec a_admit[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("created", "GuestCreatedReceipt", 1, 0),
    ARG("observation", "GuestObservation", 1, 0),
    ARG("postcreate", "LayoutRecensus", 1, 0),
    ARG("ticket", "MutationTicket", 1, 0)
};
static const struct argument_spec a_resume_admission[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("created", "GuestCreatedReceipt", 1, 0),
    ARG("admission", "GuestAdmissionReceipt", 1, 0)
};
static const struct argument_spec a_extinguish[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("created", "GuestCreatedReceipt", 1, 0),
    ARG("exited", "DriverExitReceipt", 1, 0),
    ARG("ticket", "MutationTicket", 1, 0)
};
static const struct argument_spec a_census[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("layout", "AttemptLayout", 1, 0),
    ARG("exited", "DriverExitReceipt", 1, 0),
    ARG("terminal", "ExtinctionReceipt", 1, 0),
    ARG("ticket", "MutationTicket", 1, 0)
};
static const struct argument_spec a_export[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("layout", "AttemptLayout", 1, 0),
    ARG("census", "ArtifactCensus", 1, 0),
    ARG("ticket", "MutationTicket", 1, 0)
};
static const struct argument_spec a_arm[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("operation", "MutationOperation", 0, 1),
    ARG("before_checkpoint_sha256", "str", 0, 1)
};
static const struct argument_spec a_commit[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("ticket", "MutationTicket", 1, 0),
    ARG("checkpoint", "SupervisorCheckpoint", 1, 0)
};
static const struct argument_spec a_finish[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("checkpoint_sha256", "str", 0, 1)
};
static const struct argument_spec a_recover[] = {
    ARG("request", "AuditRequest", 0, 0),
    ARG("ticket", "MutationTicket", 1, 0),
    ARG("before", "SupervisorCheckpoint", 1, 0)
};

#define METHOD(member_, method_, member_name_, operation_, result_, args_, \
    kind_, mutation_, observation_) \
    { member_, method_, member_name_, operation_, result_, args_, \
      (uint8_t)(sizeof(args_) / sizeof((args_)[0])), kind_, mutation_, \
      observation_ }
#define METHOD0(member_, method_, member_name_, operation_, result_, kind_, \
    observation_) \
    { member_, method_, member_name_, operation_, result_, NULL, 0, kind_, 0, \
      observation_ }

static const struct method_spec methods[] = {
    METHOD(1, PLAMEN_BROKER_V2_METHOD_RUNTIME_AUTHENTICATE, "runtime",
        "authenticate", "AuthenticatedRuntimeImageLayout", a_request, 1, 0, 1),
    METHOD(2, PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET, "workspace",
        "admit_target", "TargetLease", a_request, 1, 0, 1),
    METHOD(2, PLAMEN_BROKER_V2_METHOD_WORKSPACE_REVALIDATE_TARGET, "workspace",
        "revalidate_target", "TargetRecensus", a_request_target, 1, 0, 1),
    METHOD(2, PLAMEN_BROKER_V2_METHOD_WORKSPACE_PREPARE_LAYOUT, "workspace",
        "prepare_layout", "AttemptLayout", a_prepare_layout, 1, 1, 0),
    METHOD(2, PLAMEN_BROKER_V2_METHOD_WORKSPACE_RESUME_LAYOUT, "workspace",
        "resume_layout", "AttemptLayout", a_resume_layout, 1, 0, 1),
    METHOD(2, PLAMEN_BROKER_V2_METHOD_WORKSPACE_WRITE_GUEST_CONFIG, "workspace",
        "write_guest_config", "ConfigReceipt", a_write_config, 1, 2, 0),
    METHOD(2, PLAMEN_BROKER_V2_METHOD_WORKSPACE_RECENSUS_LAYOUT, "workspace",
        "recensus_layout", "LayoutRecensus", a_recensus, 1, 0, 1),
    METHOD(3, PLAMEN_BROKER_V2_METHOD_BACKEND_AUTHENTICATE, "backend",
        "authenticate", "BackendContext", a_request, 1, 0, 1),
    METHOD0(4, PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND, "provider",
        "provider_kind", "ProviderKind", 2, 1),
    METHOD(4, PLAMEN_BROKER_V2_METHOD_PROVIDER_CREATE_STOPPED, "provider",
        "create_stopped", "GuestCreatedReceipt", a_create, 1, 3, 0),
    METHOD(4, PLAMEN_BROKER_V2_METHOD_PROVIDER_INSPECT_STOPPED, "provider",
        "inspect_stopped", "GuestObservation", a_created, 1, 0, 1),
    METHOD(4, PLAMEN_BROKER_V2_METHOD_PROVIDER_RESUME_GUEST, "provider",
        "resume_guest", "GuestCreatedReceipt", a_resume_guest, 1, 0, 1),
    METHOD(4, PLAMEN_BROKER_V2_METHOD_PROVIDER_START_DRIVER, "provider",
        "start_driver", "DriverStartReceipt", a_start, 1, 5, 0),
    METHOD(4, PLAMEN_BROKER_V2_METHOD_PROVIDER_WAIT_DRIVER, "provider",
        "wait_driver", "DriverExitReceipt", a_wait, 1, 6, 0),
    METHOD(4, PLAMEN_BROKER_V2_METHOD_PROVIDER_DELETE_GUEST, "provider",
        "delete_guest", "DeleteReceipt", a_delete, 1, 10, 0),
    METHOD(5, PLAMEN_BROKER_V2_METHOD_GUEST_ADMIT_STOPPED, "guest_admission",
        "admit_stopped_guest", "GuestAdmissionReceipt", a_admit, 1, 4, 0),
    METHOD(5, PLAMEN_BROKER_V2_METHOD_GUEST_RESUME_ADMISSION, "guest_admission",
        "resume_admission", "GuestAdmissionReceipt", a_resume_admission, 1, 0, 1),
    METHOD(6, PLAMEN_BROKER_V2_METHOD_EXTINCTION_EXTINGUISH, "extinction",
        "extinguish", "ExtinctionReceipt", a_extinguish, 1, 7, 0),
    METHOD(7, PLAMEN_BROKER_V2_METHOD_ARTIFACT_CENSUS, "artifacts",
        "census", "ArtifactCensus", a_census, 1, 8, 0),
    METHOD(8, PLAMEN_BROKER_V2_METHOD_EXPORT_EXPORT, "exporter",
        "export", "ExportReceipt", a_export, 1, 9, 0),
    METHOD(9, PLAMEN_BROKER_V2_METHOD_JOURNAL_OPEN, "journal",
        "open", "JournalOpenReceipt", a_request, 1, 0, 1),
    METHOD(9, PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM, "journal",
        "arm", "MutationTicket", a_arm, 1, 0, 0),
    METHOD(9, PLAMEN_BROKER_V2_METHOD_JOURNAL_COMMIT, "journal",
        "commit", "bool", a_commit, 3, 0, 0),
    METHOD(9, PLAMEN_BROKER_V2_METHOD_JOURNAL_RESOLVE, "journal",
        "resolve", "bool", a_commit, 3, 0, 0),
    METHOD(9, PLAMEN_BROKER_V2_METHOD_JOURNAL_FINISH, "journal",
        "finish", "bool", a_finish, 3, 0, 0),
    METHOD(10, PLAMEN_BROKER_V2_METHOD_RECOVERY_RECOVER, "recovery",
        "recover", "RecoveryResolution", a_recover, 1, 0, 0)
};

static int
constant_equal(const void *left_value, const void *right_value, size_t size)
{
    const uint8_t *left = left_value;
    const uint8_t *right = right_value;
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < size; ++index)
        difference |= (uint8_t)(left[index] ^ right[index]);
    return difference == 0;
}

static int
all_zero(const uint8_t value[32])
{
    uint8_t aggregate = 0;
    size_t index;
    for (index = 0; index < 32; ++index)
        aggregate |= value[index];
    return aggregate == 0;
}

static int
hex_digit(uint8_t value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static int
parse_hex32(const uint8_t *value, size_t size, uint8_t output[32])
{
    size_t index;
    if (value == NULL || size != 64) return -1;
    for (index = 0; index < 32; ++index) {
        int high = hex_digit(value[index * 2]);
        int low = hex_digit(value[index * 2 + 1]);
        if (high < 0 || low < 0) return -1;
        output[index] = (uint8_t)((high << 4) | low);
    }
    return all_zero(output) ? -1 : 0;
}

static void
encode_hex32(const uint8_t value[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32; ++index) {
        output[index * 2] = digits[value[index] >> 4];
        output[index * 2 + 1] = digits[value[index] & 15U];
    }
    output[64] = '\0';
}

static int
expect(struct json_cursor *cursor, const char *literal)
{
    size_t size = strlen(literal);
    if (cursor->offset > cursor->size || size > cursor->size - cursor->offset
        || memcmp(cursor->data + cursor->offset, literal, size) != 0)
        return -1;
    cursor->offset += size;
    return 0;
}

/* Call-document strings are all ASCII by schema. */
static int
parse_call_string(struct json_cursor *cursor, char *output, size_t capacity,
    size_t *output_size)
{
    size_t used = 0;
    if (capacity == 0 || expect(cursor, "\"") != 0) return -1;
    while (cursor->offset < cursor->size) {
        uint8_t value = cursor->data[cursor->offset++];
        if (value == '"') {
            output[used] = '\0';
            if (output_size != NULL) *output_size = used;
            return 0;
        }
        if (value < 0x20U || value > 0x7eU || value == '\\'
            || used + 1 >= capacity)
            return -1;
        output[used++] = (char)value;
    }
    return -1;
}

static const struct method_spec *
find_method(uint16_t member, uint16_t method)
{
    size_t index;
    for (index = 0; index < sizeof(methods) / sizeof(methods[0]); ++index)
        if (methods[index].member == member && methods[index].method == method)
            return &methods[index];
    return NULL;
}

static int
scalar_commitment_valid(const char *value, size_t size,
    const uint8_t expected[32])
{
    uint8_t *canonical;
    uint8_t digest[32];
    int result = 0;
    if (value == NULL || size == 0
        || size > PLAMEN_BROKER_V2_OPERATIONS_SCALAR_MAX)
        return 0;
    canonical = malloc(size + 3U);
    if (canonical == NULL) return 0;
    canonical[0] = '"';
    memcpy(canonical + 1, value, size);
    canonical[size + 1] = '"';
    canonical[size + 2] = '\n';
    if (plamen_broker_v2_sha256(canonical, size + 3U, digest) == 0
        && constant_equal(digest, expected, 32))
        result = 1;
    plamen_broker_v2_secure_zero(canonical, size + 3U);
    free(canonical);
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return result;
}

static int
parse_argument(struct json_cursor *cursor, struct parsed_argument *argument,
    const struct argument_spec *spec)
{
    char commitment[65];
    size_t commitment_size = 0;
    memset(argument, 0, sizeof(*argument));
    if (expect(cursor, "{\"commitment_sha256\":") != 0
        || parse_call_string(cursor, commitment, sizeof(commitment),
            &commitment_size) != 0
        || parse_hex32((const uint8_t *)commitment, commitment_size,
            argument->commitment) != 0
        || expect(cursor, ",\"name\":") != 0
        || parse_call_string(cursor, argument->name, sizeof(argument->name),
            NULL) != 0
        || expect(cursor, ",\"type\":") != 0
        || parse_call_string(cursor, argument->type, sizeof(argument->type),
            NULL) != 0
        || strcmp(argument->name, spec->name) != 0
        || strcmp(argument->type, spec->type) != 0)
        return -1;
    if (spec->scalar) {
        if (expect(cursor, ",\"value\":") != 0
            || parse_call_string(cursor, argument->scalar,
                sizeof(argument->scalar), &argument->scalar_size) != 0
            || !scalar_commitment_valid(argument->scalar,
                argument->scalar_size, argument->commitment))
            return -1;
        argument->scalar_present = 1;
    }
    return expect(cursor, "}");
}

static int
parse_receipt(struct json_cursor *cursor,
    const struct parsed_argument *argument, const struct argument_spec *spec)
{
    char name[64], sha[65], type[64];
    uint8_t digest[32];
    size_t sha_size = 0;
    int result;
    if (expect(cursor, "{\"name\":") != 0
        || parse_call_string(cursor, name, sizeof(name), NULL) != 0
        || expect(cursor, ",\"sha256\":") != 0
        || parse_call_string(cursor, sha, sizeof(sha), &sha_size) != 0
        || parse_hex32((const uint8_t *)sha, sha_size, digest) != 0
        || expect(cursor, ",\"type\":") != 0
        || parse_call_string(cursor, type, sizeof(type), NULL) != 0
        || expect(cursor, "}") != 0)
        return -1;
    result = strcmp(name, spec->name) == 0 && strcmp(type, spec->type) == 0
        && constant_equal(digest, argument->commitment, 32) ? 0 : -1;
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return result;
}

static int
parse_call(const uint8_t *data, size_t size, const struct method_spec *method,
    const uint8_t request_commitment[32],
    const uint8_t request_fingerprint[32], struct parsed_call *call)
{
    struct json_cursor cursor;
    char text[129];
    uint8_t digest[32];
    size_t text_size = 0, index, receipt_index = 0;
    int result = -1;
    memset(call, 0, sizeof(*call));
    memset(&cursor, 0, sizeof(cursor));
    cursor.data = data;
    cursor.size = size;
    if (data == NULL || size < 2 || size > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX
        || data[size - 1] != '\n'
        || expect(&cursor, "{\"arguments\":[") != 0)
        goto done;
    for (index = 0; index < method->argument_count; ++index) {
        if (index != 0 && expect(&cursor, ",") != 0) goto done;
        if (parse_argument(&cursor, &call->arguments[index],
                &method->arguments[index]) != 0)
            goto done;
    }
    call->argument_count = method->argument_count;
    for (index = 0; index < method->argument_count; ++index)
        if (strcmp(method->arguments[index].type, "AuditRequest") == 0
            && !constant_equal(call->arguments[index].commitment,
                request_commitment, 32))
            goto done;
    if (expect(&cursor, "],\"member\":") != 0
        || parse_call_string(&cursor, text, sizeof(text), NULL) != 0
        || strcmp(text, method->member_name) != 0
        || expect(&cursor, ",\"operation\":") != 0
        || parse_call_string(&cursor, text, sizeof(text), NULL) != 0
        || strcmp(text, method->operation_name) != 0
        || expect(&cursor, ",\"receipt_commitments\":[") != 0)
        goto done;
    for (index = 0; index < method->argument_count; ++index) {
        if (!method->arguments[index].receipt) continue;
        if (receipt_index != 0 && expect(&cursor, ",") != 0) goto done;
        if (parse_receipt(&cursor, &call->arguments[index],
                &method->arguments[index]) != 0)
            goto done;
        ++receipt_index;
    }
    if (expect(&cursor, "],\"request_commitment_sha256\":") != 0
        || parse_call_string(&cursor, text, sizeof(text), &text_size) != 0
        || parse_hex32((const uint8_t *)text, text_size, digest) != 0
        || !constant_equal(digest, request_commitment, 32)
        || expect(&cursor, ",\"request_fingerprint_sha256\":") != 0
        || parse_call_string(&cursor, text, sizeof(text), &text_size) != 0
        || parse_hex32((const uint8_t *)text, text_size, digest) != 0
        || !constant_equal(digest, request_fingerprint, 32)
        || expect(&cursor, ",\"schema\":") != 0
        || parse_call_string(&cursor, text, sizeof(text), NULL) != 0
        || strcmp(text, CALL_SCHEMA) != 0
        || expect(&cursor, "}\n") != 0 || cursor.offset != cursor.size)
        goto done;
    result = 0;
done:
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    if (result != 0) plamen_broker_v2_secure_zero(call, sizeof(*call));
    return result;
}

static int validate_json_value(struct json_cursor *, unsigned int);

static int
parse_json_string(struct json_cursor *cursor, char *key, size_t key_capacity,
    size_t *key_size, int is_key)
{
    size_t used = 0;
    if (expect(cursor, "\"") != 0) return -1;
    while (cursor->offset < cursor->size) {
        uint8_t value = cursor->data[cursor->offset++];
        if (value == '"') {
            if (is_key) {
                if (used == 0 || used >= key_capacity) return -1;
                key[used] = '\0';
                *key_size = used;
            }
            return 0;
        }
        if (value >= 0x20U && value <= 0x7eU && value != '\\') {
            if (is_key) {
                if (used + 1 >= key_capacity) return -1;
                key[used++] = (char)value;
            }
            continue;
        }
        if (value != '\\' || cursor->offset >= cursor->size)
            return -1;
        {
            uint8_t escape = cursor->data[cursor->offset++];
            if (escape == '"' || escape == '\\') {
                if (is_key) return -1;
                continue;
            }
            if (escape != 'u' || cursor->offset + 4 > cursor->size)
                return -1;
            int a = hex_digit(cursor->data[cursor->offset]);
            int b = hex_digit(cursor->data[cursor->offset + 1]);
            int c = hex_digit(cursor->data[cursor->offset + 2]);
            int d = hex_digit(cursor->data[cursor->offset + 3]);
            unsigned int code;
            if (a < 0 || b < 0 || c < 0 || d < 0 || is_key) return -1;
            code = (unsigned int)((a << 12) | (b << 8) | (c << 4) | d);
            cursor->offset += 4;
            if (code < 0x7fU || (code >= 0xd800U && code <= 0xdbffU)) {
                if (code < 0x7fU || cursor->offset + 6 > cursor->size
                    || cursor->data[cursor->offset] != '\\'
                    || cursor->data[cursor->offset + 1] != 'u')
                    return -1;
                a = hex_digit(cursor->data[cursor->offset + 2]);
                b = hex_digit(cursor->data[cursor->offset + 3]);
                c = hex_digit(cursor->data[cursor->offset + 4]);
                d = hex_digit(cursor->data[cursor->offset + 5]);
                if (a < 0 || b < 0 || c < 0 || d < 0
                    || ((unsigned int)((a << 12) | (b << 8) | (c << 4) | d)
                        < 0xdc00U)
                    || ((unsigned int)((a << 12) | (b << 8) | (c << 4) | d)
                        > 0xdfffU))
                    return -1;
                cursor->offset += 6;
            } else if (code >= 0xdc00U && code <= 0xdfffU) {
                return -1;
            }
        }
    }
    return -1;
}

static int
validate_json_number(struct json_cursor *cursor)
{
    size_t start = cursor->offset;
    uint64_t magnitude = 0;
    int negative = 0;
    if (cursor->offset < cursor->size && cursor->data[cursor->offset] == '-')
        negative = 1, ++cursor->offset;
    if (cursor->offset >= cursor->size) return -1;
    if (cursor->data[cursor->offset] == '0') {
        ++cursor->offset;
        if (cursor->offset < cursor->size
            && cursor->data[cursor->offset] >= '0'
            && cursor->data[cursor->offset] <= '9')
            return -1;
    } else {
        if (cursor->data[cursor->offset] < '1'
            || cursor->data[cursor->offset] > '9')
            return -1;
        do {
            uint8_t digit = (uint8_t)(cursor->data[cursor->offset] - '0');
            if (magnitude > UINT64_MAX / 10U
                || (magnitude == UINT64_MAX / 10U
                    && digit > UINT64_MAX % 10U))
                return -1;
            magnitude = magnitude * 10U + digit;
            ++cursor->offset;
        } while (cursor->offset < cursor->size
            && cursor->data[cursor->offset] >= '0'
            && cursor->data[cursor->offset] <= '9');
    }
    if (cursor->data[start + (size_t)negative] == '0') magnitude = 0;
    if ((negative && magnitude == 0)
        || (!negative && magnitude > (uint64_t)INT64_MAX)
        || (negative && magnitude > (uint64_t)INT64_MAX + UINT64_C(1)))
        return -1;
    return 0;
}

static int
validate_json_object(struct json_cursor *cursor, unsigned int depth)
{
    char previous[MAX_JSON_KEY + 1U], key[MAX_JSON_KEY + 1U];
    size_t previous_size = 0, key_size = 0;
    int first = 1;
    if (expect(cursor, "{") != 0) return -1;
    if (cursor->offset < cursor->size && cursor->data[cursor->offset] == '}') {
        ++cursor->offset;
        return 0;
    }
    for (;;) {
        if (!first && expect(cursor, ",") != 0) return -1;
        if (parse_json_string(cursor, key, sizeof(key), &key_size, 1) != 0
            || (!first && strcmp(previous, key) >= 0)
            || expect(cursor, ":") != 0
            || validate_json_value(cursor, depth + 1U) != 0)
            return -1;
        memcpy(previous, key, key_size + 1U);
        previous_size = key_size;
        (void)previous_size;
        first = 0;
        if (cursor->offset >= cursor->size) return -1;
        if (cursor->data[cursor->offset] == '}') {
            ++cursor->offset;
            return 0;
        }
    }
}

static int
validate_json_array(struct json_cursor *cursor, unsigned int depth)
{
    int first = 1;
    if (expect(cursor, "[") != 0) return -1;
    if (cursor->offset < cursor->size && cursor->data[cursor->offset] == ']') {
        ++cursor->offset;
        return 0;
    }
    for (;;) {
        if (!first && expect(cursor, ",") != 0) return -1;
        if (validate_json_value(cursor, depth + 1U) != 0) return -1;
        first = 0;
        if (cursor->offset >= cursor->size) return -1;
        if (cursor->data[cursor->offset] == ']') {
            ++cursor->offset;
            return 0;
        }
    }
}

static int
validate_json_value(struct json_cursor *cursor, unsigned int depth)
{
    if (depth > MAX_JSON_DEPTH || ++cursor->nodes > MAX_JSON_NODES
        || cursor->offset >= cursor->size)
        return -1;
    switch (cursor->data[cursor->offset]) {
    case '{': return validate_json_object(cursor, depth);
    case '[': return validate_json_array(cursor, depth);
    case '"': return parse_json_string(cursor, NULL, 0, NULL, 0);
    case 't': return expect(cursor, "true");
    case 'f': return expect(cursor, "false");
    case 'n': return expect(cursor, "null");
    default: return validate_json_number(cursor);
    }
}

static int
expected_fields(const char *type, const char *const **fields, size_t *count)
{
    static const char *runtime[] = {"authenticated","docs_handle","docs_sha256","driver_path","guest_architecture","guest_os","image_closure_sha256","image_handle","image_manifest_digest","immutable","python_path","runtime_handle","runtime_layout_sha256"};
    static const char *target[] = {"authenticated","content_sha256","identity_sha256","readonly","scratchpad_absent","target_handle"};
    static const char *target_recensus[] = {"content_sha256","identity_sha256","readonly","scratchpad_absent","target_handle"};
    static const char *layout[] = {"attempt_id","control_handle","export_destination_handle","export_destination_identity_sha256","layout_handle","merged_handle","private_attempt_owned","run_id","run_store_outside_target","scope_handle","scope_sha256","scratch_handle","seccomp_handle","seccomp_sha256","state_handle","target_identity_sha256","target_lower_handle","target_lower_readonly","upper_handle","work_handle"};
    static const char *config[] = {"attempt_id","config_handle","config_sha256","guest_config","run_id","source_config_sha256","startup_decision_receipt_sha256"};
    static const char *recensus[] = {"attempt_id","components","layout_handle","layout_sha256","phase","target_content_sha256","target_identity_sha256","target_lower_readonly","workload_nonexecuting"};
    static const char *backend[] = {"authenticated","backend","backend_admission_sha256","context_handle","context_sha256","credential_handle","credential_isolation_sha256","credential_sha256","egress_admission_sha256","egress_policy_sha256","inherited_environment","network_mode"};
    static const char *created[] = {"attempt_id","create_spec","guest_id","mount_roster_sha256","provider_kind","provider_mounts_sha256","state","workload_started"};
    static const char *observation[] = {"guest_id","mount_roster_sha256","provider_kind","provider_mounts_sha256","spec_sha256","state","workload_process_count"};
    static const char *admission[] = {"admission_handle","admission_sha256","allowed_delta_sha256","attempt_id","guest_id","postcreate_recensus","precreate_recensus","replay_consumed","spec_sha256","workload_nonexecuting"};
    static const char *started[] = {"attempt_id","driver_process_count","driver_process_id","guest_id","launch_sha256"};
    static const char *exited[] = {"attempt_id","exit_code","guest_id","launch_sha256","wait_sha256"};
    static const char *deleted[] = {"absent","attempt_id","guest_id","provider_kind","terminal_sha256"};
    static const char *extinct[] = {"attempt_id","cgroup_populated","exact_attempt","guest_id","process_count","terminal_sha256"};
    static const char *census[] = {"attempt_id","census_handle","census_sha256","dispositions","driver_exit_code","entries","exact","immutable_lease","run_id","terminal_sha256"};
    static const char *exported[] = {"attempt_id","census_sha256","complete","destination_handle","destination_identity_sha256","export_sha256","exported_bytes","exported_count","manifest_sha256","run_id"};
    static const char *opened[] = {"checkpoint","pending","status"};
    static const char *ticket[] = {"attempt_id","authenticated","before_checkpoint_sha256","nonce","operation","request_fingerprint_sha256","sequence"};
    static const char *recovery[] = {"checkpoint","proof_sha256","status","ticket"};
#define FIELDS(type_, array_) do { \
    if (strcmp(type, type_) == 0) { \
        *fields = array_; *count = sizeof(array_) / sizeof((array_)[0]); \
        return 0; \
    } \
} while (0)
    FIELDS("AuthenticatedRuntimeImageLayout", runtime);
    FIELDS("TargetLease", target);
    FIELDS("TargetRecensus", target_recensus);
    FIELDS("AttemptLayout", layout);
    FIELDS("ConfigReceipt", config);
    FIELDS("LayoutRecensus", recensus);
    FIELDS("BackendContext", backend);
    FIELDS("GuestCreatedReceipt", created);
    FIELDS("GuestObservation", observation);
    FIELDS("GuestAdmissionReceipt", admission);
    FIELDS("DriverStartReceipt", started);
    FIELDS("DriverExitReceipt", exited);
    FIELDS("DeleteReceipt", deleted);
    FIELDS("ExtinctionReceipt", extinct);
    FIELDS("ArtifactCensus", census);
    FIELDS("ExportReceipt", exported);
    FIELDS("JournalOpenReceipt", opened);
    FIELDS("MutationTicket", ticket);
    FIELDS("RecoveryResolution", recovery);
#undef FIELDS
    return -1;
}

static int
result_json_valid(const uint8_t *data, size_t size,
    const struct method_spec *method)
{
    struct json_cursor cursor;
    const char *const *fields = NULL;
    size_t field_count = 0, index, key_size = 0;
    char text[MAX_JSON_KEY + 1U];
    if (data == NULL || size == 0
        || size > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX)
        return 0;
    if (method->result_kind == 3)
        return size == 4 && memcmp(data, "true", 4) == 0;
    memset(&cursor, 0, sizeof(cursor));
    cursor.data = data;
    cursor.size = size;
    if (method->result_kind == 2) {
        return expect(&cursor, "{\"$enum\":") == 0
            && parse_json_string(&cursor, text, sizeof(text), &key_size, 1) == 0
            && strcmp(text, method->result_type) == 0
            && expect(&cursor, ",\"value\":") == 0
            && parse_json_string(&cursor, text, sizeof(text), &key_size, 1) == 0
            && (strcmp(text, "APPLE_CONTAINER") == 0
                || strcmp(text, "PODMAN") == 0)
            && expect(&cursor, "}") == 0 && cursor.offset == size;
    }
    if (expected_fields(method->result_type, &fields, &field_count) != 0
        || expect(&cursor, "{\"$type\":") != 0
        || parse_json_string(&cursor, text, sizeof(text), &key_size, 1) != 0
        || strcmp(text, method->result_type) != 0
        || expect(&cursor, ",\"fields\":{") != 0)
        return 0;
    for (index = 0; index < field_count; ++index) {
        if ((index != 0 && expect(&cursor, ",") != 0)
            || parse_json_string(&cursor, text, sizeof(text), &key_size, 1) != 0
            || strcmp(text, fields[index]) != 0
            || expect(&cursor, ":") != 0
            || validate_json_value(&cursor, 2) != 0)
            return 0;
    }
    return expect(&cursor, "}}") == 0 && cursor.offset == size;
}

static int
mutation_from_text(const char *value, size_t size, uint16_t *operation)
{
    static const char *names[] = {
        "PREPARE_LAYOUT", "WRITE_CONFIG", "CREATE_GUEST", "ADMIT_GUEST",
        "START_DRIVER", "WAIT_DRIVER", "EXTINGUISH", "CENSUS_ARTIFACTS",
        "EXPORT_ARTIFACTS", "DELETE_GUEST"
    };
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index)
        if (strlen(names[index]) == size && memcmp(names[index], value, size) == 0) {
            *operation = (uint16_t)(index + 1U);
            return 0;
        }
    return -1;
}

static int
scalar_is_checkpoint(const struct parsed_argument *argument,
    const uint8_t checkpoint[32])
{
    uint8_t decoded[32];
    int result = parse_hex32((const uint8_t *)argument->scalar,
        argument->scalar_size, decoded) == 0
        && constant_equal(decoded, checkpoint, 32);
    plamen_broker_v2_secure_zero(decoded, sizeof(decoded));
    return result;
}

static int
ticket_matches(const struct plamen_broker_v2_operations_session *session,
    const struct method_spec *method, const struct parsed_call *call)
{
    size_t index;
    if (session->pending_operation == 0) return 1;
    for (index = 0; index < method->argument_count; ++index)
        if (strcmp(method->arguments[index].name, "ticket") == 0)
            return constant_equal(call->arguments[index].commitment,
                session->pending_ticket, 32);
    return method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM
        || method->observational;
}

static int
effect_order_valid(const struct plamen_broker_v2_operations_session *session,
    const struct method_spec *method, const struct parsed_call *call)
{
    uint16_t operation = 0;
    if (method->method == PLAMEN_BROKER_V2_METHOD_RUNTIME_AUTHENTICATE)
        return !session->runtime_authenticated && !session->journal_opened;
    if (method->method == PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET)
        return session->runtime_authenticated && !session->target_admitted
            && !session->journal_opened;
    if (method->method == PLAMEN_BROKER_V2_METHOD_BACKEND_AUTHENTICATE)
        return session->runtime_authenticated && session->target_admitted
            && !session->backend_authenticated && !session->journal_opened;
    if (method->method == PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND)
        return session->runtime_authenticated && session->target_admitted
            && session->backend_authenticated && !session->provider_known;
    if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_OPEN)
        return session->runtime_authenticated && session->target_admitted
            && session->backend_authenticated && session->provider_known
            && !session->journal_opened;
    if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM) {
        return session->journal_opened && !session->finished
            && session->pending_operation == 0
            && call->argument_count == 3
            && mutation_from_text(call->arguments[1].scalar,
                call->arguments[1].scalar_size, &operation) == 0
            && operation == (uint16_t)(session->stage + 1U)
            && scalar_is_checkpoint(&call->arguments[2],
                session->current_checkpoint);
    }
    if (method->mutation_operation != 0)
        return session->journal_opened && !session->finished
            && session->pending_operation == method->mutation_operation
            && !session->pending_effect_seen
            && session->stage + 1U == method->mutation_operation
            && ticket_matches(session, method, call);
    if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_COMMIT)
        return session->pending_operation != 0 && session->pending_effect_seen
            && ticket_matches(session, method, call);
    if (method->method == PLAMEN_BROKER_V2_METHOD_RECOVERY_RECOVER)
        return session->pending_operation != 0
            && ticket_matches(session, method, call);
    if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_RESOLVE)
        return session->pending_operation != 0
            && session->recovery_seen
            && ticket_matches(session, method, call);
    if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_FINISH)
        return session->journal_opened && session->pending_operation == 0
            && session->stage == PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED
            && scalar_is_checkpoint(&call->arguments[1],
                session->current_checkpoint);
    if (method->method == PLAMEN_BROKER_V2_METHOD_WORKSPACE_RESUME_LAYOUT)
        return session->journal_opened && session->stage >= 1
            && session->stage < PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED;
    if (method->method == PLAMEN_BROKER_V2_METHOD_PROVIDER_RESUME_GUEST)
        return session->journal_opened && session->stage >= 3
            && session->stage < PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED;
    if (method->method == PLAMEN_BROKER_V2_METHOD_GUEST_RESUME_ADMISSION)
        return session->journal_opened
            && session->stage == PLAMEN_BROKER_V2_OPERATIONS_STAGE_GUEST_ADMITTED;
    if (session->finished) return 0;
    if (method->method == PLAMEN_BROKER_V2_METHOD_WORKSPACE_REVALIDATE_TARGET)
        return session->target_admitted;
    if (method->method == PLAMEN_BROKER_V2_METHOD_WORKSPACE_RECENSUS_LAYOUT)
        return session->journal_opened && session->stage >= 2
            && session->stage < PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED;
    if (method->method == PLAMEN_BROKER_V2_METHOD_PROVIDER_INSPECT_STOPPED)
        return session->journal_opened && session->stage >= 3
            && session->stage < PLAMEN_BROKER_V2_OPERATIONS_STAGE_DRIVER_STARTED;
    return method->observational;
}

static int
make_error(const struct plamen_broker_v2_operations_session *session,
    const struct plamen_broker_v2_operation_request *request,
    const uint8_t request_sha256[32], uint16_t code, uint16_t flags,
    struct plamen_broker_v2_operations_dispatch_result *result)
{
    struct plamen_broker_v2_operation_error error;
    result->wire = malloc(PLAMEN_BROKER_V2_OPERATION_ERROR_SIZE);
    if (result->wire == NULL) return -1;
    memset(&error, 0, sizeof(error));
    error.authority_role = request->authority_role;
    error.member = request->member;
    error.method = request->method;
    error.error_code = code;
    error.flags = flags;
    memcpy(error.operation_key, request->operation_key, 32);
    memcpy(error.request_sha256, request_sha256, 32);
    memcpy(error.current_checkpoint_sha256, session->current_checkpoint, 32);
    if (plamen_broker_v2_operation_error_encode(&error, result->wire) != 0) {
        plamen_broker_v2_operations_dispatch_result_dispose(result);
        return -1;
    }
    result->kind = PLAMEN_BROKER_V2_OPERATIONS_ERROR;
    result->wire_size = PLAMEN_BROKER_V2_OPERATION_ERROR_SIZE;
    return 0;
}

static int
build_response(const struct plamen_broker_v2_operations_session *session,
    const struct plamen_broker_v2_operation_request *request,
    const uint8_t request_sha256[32], const struct method_spec *method,
    const struct plamen_broker_v2_operations_effect_result *effect,
    uint16_t disposition, uint16_t state, const uint8_t next_checkpoint[32],
    struct plamen_broker_v2_operations_dispatch_result *result)
{
    struct plamen_broker_v2_operation_response response;
    uint8_t call_sha[32], payload_sha[32];
    char call_hex[65], fingerprint_hex[65], commitment_hex[65];
    char prefix[640], middle[256], suffix[192];
    int prefix_size, middle_size, suffix_size;
    size_t payload_size, wire_size = 0;
    uint8_t *payload = NULL;
    if (plamen_broker_v2_sha256(request->payload, request->payload_size,
            call_sha) != 0)
        return -1;
    encode_hex32(call_sha, call_hex);
    encode_hex32(session->request_fingerprint, fingerprint_hex);
    encode_hex32(effect->result_commitment_sha256, commitment_hex);
    prefix_size = snprintf(prefix, sizeof(prefix),
        "{\"call_sha256\":\"%s\",\"member\":\"%s\",\"operation\":\"%s\",",
        call_hex, method->member_name, method->operation_name);
    middle_size = snprintf(middle, sizeof(middle),
        "\"request_fingerprint_sha256\":\"%s\",\"result\":",
        fingerprint_hex);
    suffix_size = snprintf(suffix, sizeof(suffix),
        ",\"result_commitment_sha256\":\"%s\",\"schema\":\"%s\"}\n",
        commitment_hex, RESPONSE_SCHEMA);
    if (prefix_size <= 0 || middle_size <= 0 || suffix_size <= 0
        || (size_t)prefix_size >= sizeof(prefix)
        || (size_t)middle_size >= sizeof(middle)
        || (size_t)suffix_size >= sizeof(suffix))
        return -1;
    payload_size = (size_t)prefix_size + (size_t)middle_size
        + effect->canonical_result_size + (size_t)suffix_size;
    if (payload_size > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX)
        return -1;
    payload = malloc(payload_size);
    result->wire = malloc(PLAMEN_BROKER_V2_OPERATION_RESPONSE_PREFIX_SIZE
        + payload_size);
    if (payload == NULL || result->wire == NULL) goto fail;
    memcpy(payload, prefix, (size_t)prefix_size);
    memcpy(payload + prefix_size, middle, (size_t)middle_size);
    memcpy(payload + prefix_size + middle_size, effect->canonical_result,
        effect->canonical_result_size);
    memcpy(payload + prefix_size + middle_size + effect->canonical_result_size,
        suffix, (size_t)suffix_size);
    if (plamen_broker_v2_sha256(payload, payload_size, payload_sha) != 0)
        goto fail;
    memset(&response, 0, sizeof(response));
    response.authority_role = request->authority_role;
    response.member = request->member;
    response.method = request->method;
    response.disposition = disposition;
    response.state = state;
    memcpy(response.operation_key, request->operation_key, 32);
    memcpy(response.request_sha256, request_sha256, 32);
    memcpy(response.prior_checkpoint_sha256, session->current_checkpoint, 32);
    memcpy(response.next_checkpoint_sha256, next_checkpoint, 32);
    memcpy(response.payload_sha256, payload_sha, 32);
    response.payload_size = (uint32_t)payload_size;
    response.payload = payload;
    if (plamen_broker_v2_operation_response_encode(&response, result->wire,
            PLAMEN_BROKER_V2_OPERATION_RESPONSE_PREFIX_SIZE + payload_size,
            &wire_size) != 0)
        goto fail;
    result->kind = PLAMEN_BROKER_V2_OPERATIONS_RESPONSE;
    result->wire_size = wire_size;
    plamen_broker_v2_secure_zero(payload, payload_size);
    free(payload);
    plamen_broker_v2_secure_zero(call_sha, sizeof(call_sha));
    plamen_broker_v2_secure_zero(payload_sha, sizeof(payload_sha));
    return 0;
fail:
    if (payload != NULL) {
        plamen_broker_v2_secure_zero(payload, payload_size);
        free(payload);
    }
    plamen_broker_v2_operations_dispatch_result_dispose(result);
    plamen_broker_v2_secure_zero(call_sha, sizeof(call_sha));
    plamen_broker_v2_secure_zero(payload_sha, sizeof(payload_sha));
    return -1;
}

static int
snapshot_state(const struct plamen_broker_v2_operations_session *session,
    struct plamen_broker_v2_operations_replay_state *state)
{
    memset(state, 0, sizeof(*state));
    state->version = PLAMEN_BROKER_V2_OPERATIONS_VERSION;
    memcpy(state->current_checkpoint_sha256, session->current_checkpoint, 32);
    memcpy(state->pending_ticket_sha256, session->pending_ticket, 32);
    state->stage = session->stage;
    state->pending_operation = session->pending_operation;
    state->journal_opened = session->journal_opened;
    state->runtime_authenticated = session->runtime_authenticated;
    state->target_admitted = session->target_admitted;
    state->backend_authenticated = session->backend_authenticated;
    state->provider_known = session->provider_known;
    state->pending_effect_seen = session->pending_effect_seen;
    state->recovery_seen = session->recovery_seen;
    state->recovery_applied = session->recovery_applied;
    state->finished = session->finished;
    state->burned = session->burned;
    return 0;
}

static int
replay_state_valid(const struct plamen_broker_v2_operations_replay_state *state)
{
    return state->version == PLAMEN_BROKER_V2_OPERATIONS_VERSION
        && !all_zero(state->current_checkpoint_sha256)
        && state->stage <= PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED
        && state->pending_operation <= 10
        && (state->pending_operation == 0
            ? all_zero(state->pending_ticket_sha256)
            : (state->pending_operation == state->stage + 1U
                && !all_zero(state->pending_ticket_sha256)))
        && state->journal_opened <= 1 && state->runtime_authenticated <= 1
        && state->target_admitted <= 1 && state->backend_authenticated <= 1
        && state->provider_known <= 1 && state->pending_effect_seen <= 1
        && state->recovery_seen <= 1 && state->recovery_applied <= 1
        && state->finished <= 1 && state->burned <= 1
        && (!state->journal_opened || (state->runtime_authenticated
            && state->target_admitted && state->backend_authenticated
            && state->provider_known))
        && (!state->finished
            || (state->stage == PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED
                && state->pending_operation == 0));
}

static int
merge_replay_state(struct plamen_broker_v2_operations_session *session,
    const struct plamen_broker_v2_operations_replay_state *state,
    const uint8_t response_prior[32], const uint8_t response_next[32])
{
    if (!replay_state_valid(state)) return -1;
    if (constant_equal(session->current_checkpoint, response_prior, 32)
        && !constant_equal(response_prior, response_next, 32)) {
        memcpy(session->current_checkpoint, state->current_checkpoint_sha256,
            32);
        session->stage = state->stage;
        session->pending_operation = state->pending_operation;
        memcpy(session->pending_ticket, state->pending_ticket_sha256, 32);
        session->journal_opened = state->journal_opened;
        session->pending_effect_seen = state->pending_effect_seen;
        session->recovery_seen = state->recovery_seen;
        session->recovery_applied = state->recovery_applied;
        session->finished = state->finished;
        session->burned = state->burned;
    } else if (constant_equal(session->current_checkpoint, response_next, 32)) {
        if (state->stage < session->stage) return 0;
        if (state->stage == session->stage && session->pending_operation != 0
            && state->pending_operation != 0
            && session->pending_operation != state->pending_operation)
            return -1;
        if (state->stage > session->stage) session->stage = state->stage;
        if (session->pending_operation == 0 && state->pending_operation != 0) {
            session->pending_operation = state->pending_operation;
            memcpy(session->pending_ticket, state->pending_ticket_sha256, 32);
        }
        session->journal_opened |= state->journal_opened;
        session->pending_effect_seen |= state->pending_effect_seen;
        session->recovery_seen |= state->recovery_seen;
        session->recovery_applied |= state->recovery_applied;
        session->finished |= state->finished;
        session->burned |= state->burned;
    }
    session->runtime_authenticated |= state->runtime_authenticated;
    session->target_admitted |= state->target_admitted;
    session->backend_authenticated |= state->backend_authenticated;
    session->provider_known |= state->provider_known;
    return 0;
}

static int
persist_result(struct plamen_broker_v2_operations_session *session,
    const struct plamen_broker_v2_operation_request *request,
    const uint8_t request_sha256[32],
    struct plamen_broker_v2_operations_dispatch_result *result)
{
    struct plamen_broker_v2_operations_replay_state state;
    snapshot_state(session, &state);
    if (session->effects->replay_commit(session->effects->context,
            request->operation_key, request_sha256, result->kind,
            result->wire, result->wire_size, &state) != 0) {
        plamen_broker_v2_secure_zero(&state, sizeof(state));
        return -1;
    }
    plamen_broker_v2_secure_zero(&state, sizeof(state));
    ++session->new_rpc_count;
    return 0;
}

static int
load_replay(struct plamen_broker_v2_operations_session *session,
    const struct plamen_broker_v2_operation_request *request,
    const uint8_t request_sha256[32],
    struct plamen_broker_v2_operations_dispatch_result *result)
{
    struct plamen_broker_v2_operations_replay_state replay_state;
    uint8_t prior[32], next[32];
    size_t size = 0;
    uint8_t kind = 0;
    int status;
    result->wire = malloc(PLAMEN_BROKER_V2_MAX_PAYLOAD);
    if (result->wire == NULL) return -1;
    memset(&replay_state, 0, sizeof(replay_state));
    memset(prior, 0, sizeof(prior));
    memset(next, 0, sizeof(next));
    status = session->effects->replay_lookup(session->effects->context,
        request->operation_key, request_sha256, &kind, result->wire,
        PLAMEN_BROKER_V2_MAX_PAYLOAD, &size, &replay_state);
    if (status == PLAMEN_BROKER_V2_OPERATIONS_REPLAY_MISS) {
        plamen_broker_v2_operations_dispatch_result_dispose(result);
        return 0;
    }
    if (status == PLAMEN_BROKER_V2_OPERATIONS_REPLAY_CONFLICT) {
        plamen_broker_v2_operations_dispatch_result_dispose(result);
        return 2;
    }
    if (status != PLAMEN_BROKER_V2_OPERATIONS_REPLAY_FOUND
        || (kind != PLAMEN_BROKER_V2_OPERATIONS_RESPONSE
            && kind != PLAMEN_BROKER_V2_OPERATIONS_ERROR)
        || size == 0 || size > PLAMEN_BROKER_V2_MAX_PAYLOAD) {
        plamen_broker_v2_operations_dispatch_result_dispose(result);
        return -1;
    }
    if (kind == PLAMEN_BROKER_V2_OPERATIONS_RESPONSE) {
        struct plamen_broker_v2_operation_response response;
        if (plamen_broker_v2_operation_response_decode(result->wire, size,
                &response) != 0
            || response.authority_role != request->authority_role
            || response.member != request->member
            || response.method != request->method
            || !constant_equal(response.operation_key,
                request->operation_key, 32)
            || !constant_equal(response.request_sha256, request_sha256, 32)) {
            plamen_broker_v2_operations_dispatch_result_dispose(result);
            return -1;
        }
        memcpy(prior, response.prior_checkpoint_sha256, 32);
        memcpy(next, response.next_checkpoint_sha256, 32);
    } else {
        struct plamen_broker_v2_operation_error error;
        if (plamen_broker_v2_operation_error_decode(result->wire, size,
                &error) != 0
            || error.authority_role != request->authority_role
            || error.member != request->member
            || error.method != request->method
            || !constant_equal(error.operation_key,
                request->operation_key, 32)
            || !constant_equal(error.request_sha256, request_sha256, 32)) {
            plamen_broker_v2_operations_dispatch_result_dispose(result);
            return -1;
        }
        memcpy(prior, error.current_checkpoint_sha256, 32);
        memcpy(next, error.current_checkpoint_sha256, 32);
    }
    if (merge_replay_state(session, &replay_state, prior, next) != 0) {
        plamen_broker_v2_operations_dispatch_result_dispose(result);
        return -1;
    }
    result->kind = kind;
    result->wire_size = size;
    result->replayed = 1;
    plamen_broker_v2_secure_zero(&replay_state, sizeof(replay_state));
    plamen_broker_v2_secure_zero(prior, sizeof(prior));
    plamen_broker_v2_secure_zero(next, sizeof(next));
    return 1;
}

static void
fill_effect_request(const struct plamen_broker_v2_operations_session *session,
    const struct plamen_broker_v2_operation_request *request,
    const struct method_spec *method, const struct parsed_call *call,
    struct plamen_broker_v2_operations_effect_request *effect)
{
    size_t index;
    uint64_t now, timeout;
    memset(effect, 0, sizeof(*effect));
    effect->version = PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION;
    effect->member = request->member;
    effect->method = request->method;
    effect->flags = request->flags;
    effect->stage = session->stage;
    effect->pending_operation = session->pending_operation;
    memcpy(effect->request_fingerprint_sha256, session->request_fingerprint, 32);
    memcpy(effect->operation_key, request->operation_key, 32);
    (void)plamen_broker_v2_sha256(request->payload, request->payload_size,
        effect->call_sha256);
    memcpy(effect->current_checkpoint_sha256, session->current_checkpoint, 32);
    now = session->effects->monotonic_ms(session->effects->context);
    timeout = request->method == PLAMEN_BROKER_V2_METHOD_PROVIDER_WAIT_DRIVER
        ? PLAMEN_BROKER_V2_OPERATIONS_WAIT_TIMEOUT_MS
        : (method->observational
            ? PLAMEN_BROKER_V2_OPERATIONS_QUICK_TIMEOUT_MS
            : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_TIMEOUT_MS);
    effect->monotonic_deadline_ms = now <= UINT64_MAX - timeout
        ? now + timeout : 0;
    effect->canonical_call = request->payload;
    effect->canonical_call_size = request->payload_size;
    effect->argument_count = call->argument_count;
    effect->arguments = calloc(call->argument_count,
        sizeof(*effect->arguments));
    if (effect->arguments == NULL) return;
    for (index = 0; index < call->argument_count; ++index) {
        struct plamen_broker_v2_operations_argument *target =
            (struct plamen_broker_v2_operations_argument *)effect->arguments;
        target[index].name = call->arguments[index].name;
        target[index].type = call->arguments[index].type;
        memcpy(target[index].commitment_sha256,
            call->arguments[index].commitment, 32);
        target[index].scalar = call->arguments[index].scalar_present
            ? call->arguments[index].scalar : NULL;
        target[index].scalar_size = call->arguments[index].scalar_size;
        target[index].is_receipt = method->arguments[index].receipt;
    }
}

static void
dispose_effect_request(struct plamen_broker_v2_operations_effect_request *effect)
{
    if (effect->arguments != NULL) {
        plamen_broker_v2_secure_zero((void *)effect->arguments,
            effect->argument_count * sizeof(*effect->arguments));
        free((void *)effect->arguments);
    }
    plamen_broker_v2_secure_zero(effect, sizeof(*effect));
}

int
plamen_broker_v2_operations_session_open(
    const struct plamen_broker_v2_operations_open *open,
    struct plamen_broker_v2_operations_session **output)
{
    struct plamen_broker_v2_operations_session *session;
    if (output != NULL) *output = NULL;
    if (open == NULL || output == NULL
        || open->version != PLAMEN_BROKER_V2_OPERATIONS_VERSION
        || all_zero(open->request_fingerprint_sha256)
        || all_zero(open->request_commitment_sha256)
        || all_zero(open->projection_sha256)
        || all_zero(open->authority_binding_sha256)
        || all_zero(open->initial_checkpoint_sha256)
        || open->authority_bundle.role
            != PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR
        || open->authority_bundle.member_count
            != PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT
        || open->effects == NULL
        || open->effects->version
            != PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION
        || open->effects->context == NULL || open->effects->revalidate == NULL
        || open->effects->monotonic_ms == NULL
        || open->effects->cancelled == NULL
        || open->effects->execute == NULL
        || open->effects->dispose_result == NULL
        || open->effects->replay_lookup == NULL
        || open->effects->replay_commit == NULL)
        return -1;
    if (open->effects->revalidate(open->effects->context,
            open->request_fingerprint_sha256, open->projection_sha256,
            open->authority_binding_sha256, 0, 0) != 0)
        return -1;
    session = calloc(1, sizeof(*session));
    if (session == NULL) return -1;
    memcpy(session->request_fingerprint, open->request_fingerprint_sha256, 32);
    memcpy(session->request_commitment, open->request_commitment_sha256, 32);
    memcpy(session->projection_sha256, open->projection_sha256, 32);
    memcpy(session->authority_binding_sha256,
        open->authority_binding_sha256, 32);
    memcpy(session->current_checkpoint, open->initial_checkpoint_sha256, 32);
    session->bundle = open->authority_bundle;
    session->effects = open->effects;
    *output = session;
    return 0;
}

int
plamen_broker_v2_operations_dispatch(
    struct plamen_broker_v2_operations_session *session,
    const struct plamen_broker_v2_operation_request *request,
    const uint8_t request_frame_payload_sha256[32],
    const uint8_t *canonical_call, size_t canonical_call_size,
    struct plamen_broker_v2_operations_dispatch_result *result)
{
    const struct method_spec *method;
    struct parsed_call call;
    struct plamen_broker_v2_operations_effect_request effect_request;
    struct plamen_broker_v2_operations_effect_result effect_result;
    uint8_t *encoded_request = NULL;
    uint8_t encoded_sha[32], next_checkpoint[32];
    size_t encoded_size = 0;
    uint16_t disposition = PLAMEN_BROKER_V2_OPERATION_OBSERVED;
    uint16_t state = PLAMEN_BROKER_V2_OPERATION_STATE_UNCHANGED;
    int replay, effect_status, status = -1;
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (session == NULL || request == NULL
        || request_frame_payload_sha256 == NULL || canonical_call == NULL
        || result == NULL || session->burned
        || request->authority_role
            != PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR
        || request->member == 0
        || request->member > PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT
        || request->payload != canonical_call
        || request->payload_size != canonical_call_size
        || !constant_equal(request->request_fingerprint,
            session->request_fingerprint, 32))
        goto burn;
    method = find_method(request->member, request->method);
    if (method == NULL
        || plamen_broker_v2_authority_method_valid(request->authority_role,
            request->member, request->method, request->flags) == 0)
        goto burn;
    encoded_request = malloc(PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE
        + request->payload_size);
    if (encoded_request == NULL
        || plamen_broker_v2_operation_request_encode(request, encoded_request,
            PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE
                + request->payload_size, &encoded_size) != 0
        || plamen_broker_v2_sha256(encoded_request, encoded_size,
            encoded_sha) != 0
        || !constant_equal(encoded_sha, request_frame_payload_sha256, 32))
        goto burn;
    replay = load_replay(session, request, request_frame_payload_sha256, result);
    if (replay == 1) {
        status = 0;
        goto done;
    }
    if (replay < 0) goto burn;
    if (replay == 2) {
        session->burned = 1;
        goto burn;
    }
    if (session->new_rpc_count >= PLAMEN_BROKER_V2_RPC_REPLAY_MAX_ENTRIES) {
        /* The protocol forbids eviction and a non-journaled 4097th reply. */
        goto burn;
    }
    if (!constant_equal(request->prior_checkpoint_sha256,
            session->current_checkpoint, 32)) {
        if (make_error(session, request, request_frame_payload_sha256,
                PLAMEN_BROKER_V2_OPERATIONS_ERR_BINDING,
                PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED,
                result) != 0
            || persist_result(session, request, request_frame_payload_sha256,
                result) != 0)
            goto burn;
        status = 0;
        goto done;
    }
    if (parse_call(canonical_call, canonical_call_size, method,
            session->request_commitment, session->request_fingerprint,
            &call) != 0) {
        if (make_error(session, request, request_frame_payload_sha256,
                PLAMEN_BROKER_V2_OPERATIONS_ERR_CALL,
                PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED,
                result) != 0
            || persist_result(session, request, request_frame_payload_sha256,
                result) != 0)
            goto burn;
        session->burned = 1;
        status = 0;
        goto done;
    }
    if (!effect_order_valid(session, method, &call)) {
        if (make_error(session, request, request_frame_payload_sha256,
                session->pending_operation != 0
                    ? PLAMEN_BROKER_V2_OPERATIONS_ERR_PENDING
                    : PLAMEN_BROKER_V2_OPERATIONS_ERR_ORDER,
                PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED,
                result) != 0
            || persist_result(session, request, request_frame_payload_sha256,
                result) != 0)
            goto burn;
        status = 0;
        goto done;
    }
    if (session->effects->revalidate(session->effects->context,
            session->request_fingerprint, session->projection_sha256,
            session->authority_binding_sha256, request->member,
            request->method) != 0)
        goto burn;
    memset(&effect_request, 0, sizeof(effect_request));
    memset(&effect_result, 0, sizeof(effect_result));
    fill_effect_request(session, request, method, &call, &effect_request);
    if ((call.argument_count != 0 && effect_request.arguments == NULL)
        || effect_request.monotonic_deadline_ms == 0
        || session->effects->cancelled(session->effects->context) != 0)
        goto burn_effect;
    effect_status = session->effects->execute(session->effects->context,
        &effect_request, &effect_result);
    if (session->effects->cancelled(session->effects->context) != 0)
        effect_status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS;
    if (effect_status == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS) {
        session->burned = 1;
        goto burn_effect;
    }
    if (effect_status != PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK
        || !effect_result.durability_proven) {
        if (make_error(session, request, request_frame_payload_sha256,
                effect_status == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED
                    ? PLAMEN_BROKER_V2_OPERATIONS_ERR_EFFECT
                    : PLAMEN_BROKER_V2_OPERATIONS_ERR_DURABILITY,
                PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED,
                result) != 0
            || persist_result(session, request, request_frame_payload_sha256,
                result) != 0)
            goto burn_effect;
        status = 0;
        goto done_effect;
    }
    if (!result_json_valid(effect_result.canonical_result,
            effect_result.canonical_result_size, method)
        || all_zero(effect_result.result_commitment_sha256))
        goto burn_effect;
    memcpy(next_checkpoint, session->current_checkpoint, 32);
    if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_OPEN) {
        if (all_zero(effect_result.durable_checkpoint_sha256)
            || effect_result.durable_stage
                > PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED
            || effect_result.durable_pending_operation > 10
            || (effect_result.durable_pending_operation == 0
                ? !all_zero(effect_result.durable_pending_ticket_sha256)
                : (effect_result.durable_pending_operation
                        != effect_result.durable_stage + 1U
                    || all_zero(effect_result.durable_pending_ticket_sha256))))
            goto burn_effect;
        memcpy(next_checkpoint, effect_result.durable_checkpoint_sha256, 32);
        disposition = PLAMEN_BROKER_V2_OPERATION_COMMITTED;
        state = PLAMEN_BROKER_V2_OPERATION_STATE_COMMITTED;
    } else if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM) {
        disposition = PLAMEN_BROKER_V2_OPERATION_COMMITTED;
        state = PLAMEN_BROKER_V2_OPERATION_STATE_PREPARED;
    } else if (method->mutation_operation != 0) {
        if (!effect_result.effect_applied) goto burn_effect;
        disposition = PLAMEN_BROKER_V2_OPERATION_COMMITTED;
        state = PLAMEN_BROKER_V2_OPERATION_STATE_EFFECTED;
    } else if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_COMMIT
        || method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_RESOLVE) {
        memcpy(next_checkpoint,
            call.arguments[2].commitment, 32);
        disposition = PLAMEN_BROKER_V2_OPERATION_COMMITTED;
        state = PLAMEN_BROKER_V2_OPERATION_STATE_COMMITTED;
    } else if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_FINISH) {
        disposition = PLAMEN_BROKER_V2_OPERATION_COMMITTED;
        state = PLAMEN_BROKER_V2_OPERATION_STATE_FINISHED;
    } else if (method->method == PLAMEN_BROKER_V2_METHOD_RECOVERY_RECOVER
        || method->method == PLAMEN_BROKER_V2_METHOD_WORKSPACE_RESUME_LAYOUT
        || method->method == PLAMEN_BROKER_V2_METHOD_PROVIDER_RESUME_GUEST
        || method->method == PLAMEN_BROKER_V2_METHOD_GUEST_RESUME_ADMISSION) {
        disposition = PLAMEN_BROKER_V2_OPERATION_RECOVERED;
    }
    if (build_response(session, request, request_frame_payload_sha256, method,
            &effect_result, disposition, state, next_checkpoint, result) != 0)
        goto burn_effect;
    if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_OPEN) {
        session->journal_opened = 1;
        session->stage = effect_result.durable_stage;
        memcpy(session->current_checkpoint, next_checkpoint, 32);
        session->pending_operation = effect_result.durable_pending_operation;
        if (session->pending_operation != 0)
            memcpy(session->pending_ticket,
                effect_result.durable_pending_ticket_sha256, 32);
    } else if (method->method
        == PLAMEN_BROKER_V2_METHOD_RUNTIME_AUTHENTICATE) {
        session->runtime_authenticated = 1;
    } else if (method->method
        == PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET) {
        session->target_admitted = 1;
    } else if (method->method
        == PLAMEN_BROKER_V2_METHOD_BACKEND_AUTHENTICATE) {
        session->backend_authenticated = 1;
    } else if (method->method == PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND) {
        session->provider_known = 1;
    } else if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM) {
        if (mutation_from_text(call.arguments[1].scalar,
                call.arguments[1].scalar_size,
                &session->pending_operation) != 0)
            goto burn_effect;
        memcpy(session->pending_ticket,
            effect_result.result_commitment_sha256, 32);
        session->pending_effect_seen = 0;
    } else if (method->mutation_operation != 0) {
        session->pending_effect_seen = 1;
    } else if (method->method == PLAMEN_BROKER_V2_METHOD_RECOVERY_RECOVER) {
        session->recovery_seen = 1;
        session->recovery_applied = effect_result.effect_applied ? 1 : 0;
    } else if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_COMMIT
        || method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_RESOLVE) {
        if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_COMMIT
            || session->recovery_applied) {
            ++session->stage;
        }
        memcpy(session->current_checkpoint, next_checkpoint, 32);
        session->pending_operation = 0;
        session->pending_effect_seen = 0;
        session->recovery_seen = 0;
        session->recovery_applied = 0;
        plamen_broker_v2_secure_zero(session->pending_ticket,
            sizeof(session->pending_ticket));
    } else if (method->method == PLAMEN_BROKER_V2_METHOD_JOURNAL_FINISH) {
        session->finished = 1;
    }
    if (persist_result(session, request, request_frame_payload_sha256,
            result) != 0)
        goto burn_effect;
    status = 0;
    goto done_effect;
burn_effect:
    status = -1;
done_effect:
    session->effects->dispose_result(session->effects->context, &effect_result);
    dispose_effect_request(&effect_request);
    plamen_broker_v2_secure_zero(&call, sizeof(call));
    goto done;
burn:
    if (session != NULL) session->burned = 1;
    status = -1;
done:
    if (encoded_request != NULL) {
        plamen_broker_v2_secure_zero(encoded_request, encoded_size);
        free(encoded_request);
    }
    plamen_broker_v2_secure_zero(encoded_sha, sizeof(encoded_sha));
    plamen_broker_v2_secure_zero(next_checkpoint, sizeof(next_checkpoint));
    if (status != 0)
        plamen_broker_v2_operations_dispatch_result_dispose(result);
    return status;
}

void
plamen_broker_v2_operations_dispatch_result_dispose(
    struct plamen_broker_v2_operations_dispatch_result *result)
{
    if (result == NULL) return;
    if (result->wire != NULL) {
        plamen_broker_v2_secure_zero(result->wire, result->wire_size);
        free(result->wire);
    }
    memset(result, 0, sizeof(*result));
}

void
plamen_broker_v2_operations_session_close(
    struct plamen_broker_v2_operations_session *session)
{
    if (session == NULL) return;
    plamen_broker_v2_secure_zero(session, sizeof(*session));
    free(session);
}
