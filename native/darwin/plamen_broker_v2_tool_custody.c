#include "plamen_broker_v2_tool_custody.h"
#include "../include/plamen_broker_v2.h"

#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <CommonCrypto/CommonDigest.h>

#define GUEST_HMAC_OFFSET 992U
#define TOOL_STREAM_OBSERVED_MAX (512ULL * 1024ULL * 1024ULL)
#define TOOL_STREAM_RETAINED_MAX (64ULL * 1024ULL * 1024ULL)

struct json_writer {
    uint8_t *bytes;
    size_t capacity;
    size_t size;
};

#define TOOL_EFFECT_PLAN_MAGIC 0x504c4d544f4f4c31ULL
#define TOOL_FD_JS_ARCHIVE_ROOT UINT16_C(0x4004)

struct plamen_broker_v2_tool_effect_plan {
    uint64_t magic;
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
    uint8_t *payload;
    size_t payload_size;
    struct plamen_broker_v2_fd_metadata descriptors[PLAMEN_BROKER_V2_MAX_FDS];
    int fds[PLAMEN_BROKER_V2_MAX_FDS];
    size_t fd_count;
    uint8_t issued;
    uint8_t consumed;
};

static void hex32(const uint8_t digest[32], char output[65]);
static int effect_archive_root_validate(
    const struct plamen_broker_v2_specialized_request *, int,
    uint8_t [32], uint8_t [32], uint8_t [32]);
static int effect_plan_archive_root_stable(
    const struct plamen_broker_v2_tool_effect_plan *);

static int
constant_equal(const void *left_value, const void *right_value, size_t size)
{
    const uint8_t *left = left_value, *right = right_value;
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < size; ++index)
        difference |= left[index] ^ right[index];
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
method_has_lane(uint16_t lane, uint16_t method)
{
    switch (lane) {
    case PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER:
        return method >= PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE
            && method <= PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_RUNTIME_IDENTITY;
    case PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM:
        return method >= PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_RUNTIME_IDENTITY
            && method <= PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PROJECT;
    case PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION:
        return method >= PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
            && method <= PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_PROJECT;
    case PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL:
        return method >= PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_RUNTIME_IDENTITY
            && method <= PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE;
    default:
        return 0;
    }
}

static int
method_recovery_flag_valid(uint16_t method, uint16_t flags)
{
    int recovery = method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY
        || method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER;
    return flags == (recovery
        ? PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER : 0U);
}

static int
method_issues_capability(uint16_t method)
{
    return method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE
        || method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY
        || method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE
        || method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
        || method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER
        || method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE
        || method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT;
}

static uint16_t
method_disposition(uint16_t method)
{
    if (method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY)
        return PLAMEN_BROKER_V2_SPECIALIZED_REPLAYED;
    if (method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER)
        return PLAMEN_BROKER_V2_SPECIALIZED_RECOVERED;
    if (method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE
        || method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE
        || method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
        || method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE
        || method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT)
        return PLAMEN_BROKER_V2_SPECIALIZED_ISSUED;
    return PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED;
}

static void
effect_plan_clear(struct plamen_broker_v2_tool_effect_plan *plan)
{
    size_t index;
    if (plan == NULL) return;
    for (index = 0; index < plan->fd_count; ++index) {
        if (plan->fds[index] >= 0) (void)close(plan->fds[index]);
        plan->fds[index] = -1;
    }
    if (plan->payload != NULL) {
        plamen_broker_v2_secure_zero(plan->payload, plan->payload_size);
        free(plan->payload);
        plan->payload = NULL;
    }
    plan->payload_size = 0U;
    plan->fd_count = 0U;
}

static int
effect_descriptor_shape_valid(
    const struct plamen_broker_v2_specialized_request *request,
    const int *fds, size_t fd_count)
{
    static const uint16_t managed_purposes[5] = {
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_POLICY,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_PROJECT,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_CACHE,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_GENERATIONS,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_ACQUISITION_RECEIPT
    };
    static const uint8_t managed_access[5] = {
        PLAMEN_BROKER_V2_FD_READ, PLAMEN_BROKER_V2_FD_READ,
        PLAMEN_BROKER_V2_FD_READ_WRITE, PLAMEN_BROKER_V2_FD_READ_WRITE,
        PLAMEN_BROKER_V2_FD_READ
    };
    static const uint16_t snapshot_purposes[4] = {
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT
    };
    static const uint8_t snapshot_access[4] = {
        PLAMEN_BROKER_V2_FD_READ, PLAMEN_BROKER_V2_FD_READ_WRITE,
        PLAMEN_BROKER_V2_FD_READ_WRITE, PLAMEN_BROKER_V2_FD_READ
    };
    static const uint16_t projection_purposes[4] = {
        PLAMEN_BROKER_V2_FD_PROJECTION_PROJECT,
        PLAMEN_BROKER_V2_FD_PROJECTION_SCRATCH,
        PLAMEN_BROKER_V2_FD_PROJECTION_STATE,
        PLAMEN_BROKER_V2_FD_PROJECTION_MODULES
    };
    static const uint8_t projection_access[4] = {
        PLAMEN_BROKER_V2_FD_READ, PLAMEN_BROKER_V2_FD_READ_WRITE,
        PLAMEN_BROKER_V2_FD_READ_WRITE, PLAMEN_BROKER_V2_FD_READ
    };
    static const uint16_t js_purposes[4] = {
        PLAMEN_BROKER_V2_FD_JS_SOURCE, PLAMEN_BROKER_V2_FD_JS_SCRATCH,
        PLAMEN_BROKER_V2_FD_JS_STATE, TOOL_FD_JS_ARCHIVE_ROOT
    };
    static const uint8_t js_access[4] = {
        PLAMEN_BROKER_V2_FD_READ, PLAMEN_BROKER_V2_FD_READ_WRITE,
        PLAMEN_BROKER_V2_FD_READ_WRITE, PLAMEN_BROKER_V2_FD_READ
    };
    const uint16_t *purposes = NULL;
    const uint8_t *access = NULL;
    size_t expected = 0U, index;
    if (request == NULL || fd_count != request->fd_count
        || (fd_count != 0U && fds == NULL))
        return 0;
    if (request->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE
        || request->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY) {
        purposes = js_purposes; access = js_access; expected = 4U;
    } else if (request->method
            == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE) {
        purposes = managed_purposes; access = managed_access; expected = 5U;
    } else if (request->method
            == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE
        || request->method == PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT) {
        purposes = snapshot_purposes; access = snapshot_access; expected = 4U;
    } else if (request->method
            == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT) {
        purposes = projection_purposes; access = projection_access;
        expected = 4U;
    } else {
        return 1;
    }
    if (fd_count != expected) return 0;
    for (index = 0U; index < expected; ++index) {
        struct stat information;
        uint8_t identity[32];
        int regular, directory, valid_shape;
        if (fds[index] < 0
            || request->descriptors[index].purpose != purposes[index]
            || request->descriptors[index].target != (uint16_t)(index + 1U)
            || request->descriptors[index].access_mode != access[index]
            || fstat(fds[index], &information) != 0
            || plamen_broker_v2_fd_identity(fds[index], identity) != 0
            || !constant_equal(identity,
                request->descriptors[index].identity, 32U))
            return 0;
        regular = S_ISREG(information.st_mode) && information.st_nlink == 1;
        directory = S_ISDIR(information.st_mode);
        if (request->method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE)
            valid_shape = (index == 0U || index == 4U) ? regular : directory;
        else if (request->method
                == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE
            || request->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY)
            valid_shape = directory;
        else if (request->method
                == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT)
            valid_shape = directory;
        else
            valid_shape = index == 0U ? (regular || directory) : directory;
        if (!valid_shape) return 0;
    }
    return 1;
}

void
plamen_broker_v2_tool_effect_plan_destroy(
    struct plamen_broker_v2_tool_effect_plan *plan)
{
    if (plan == NULL) return;
    effect_plan_clear(plan);
    plamen_broker_v2_secure_zero(plan, sizeof(*plan));
    free(plan);
}

static int
effect_plan_create(
    const struct plamen_broker_v2_tool_effect_plan_input *input,
    uint16_t lane, uint16_t method,
    struct plamen_broker_v2_tool_effect_plan **out)
{
    struct plamen_broker_v2_tool_effect_plan *plan = NULL;
    uint8_t observed_sha256[32];
    uint8_t archive_root_identity[32], archive_manifest[32], archive_census[32];
    uint8_t *encoded = NULL;
    size_t encoded_size = 0U, encoded_capacity, index, prior;
    int copied_fds[PLAMEN_BROKER_V2_MAX_FDS];
    int result = -1;
    memset(archive_root_identity, 0, sizeof(archive_root_identity));
    memset(archive_manifest, 0, sizeof(archive_manifest));
    memset(archive_census, 0, sizeof(archive_census));
    if (out != NULL) *out = NULL;
    for (index = 0; index < PLAMEN_BROKER_V2_MAX_FDS; ++index)
        copied_fds[index] = -1;
    if (input == NULL || out == NULL
        || input->version != PLAMEN_BROKER_V2_TOOL_EFFECT_PLAN_VERSION
        || input->request == NULL || input->request_wire == NULL
        || input->request_wire_size == 0U
        || input->request_wire_size > PLAMEN_BROKER_V2_SPECIALIZED_PAYLOAD_MAX
            + PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE
            + PLAMEN_BROKER_V2_MAX_FDS
                * PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE
        || input->request->lane != lane || input->request->method != method
        || !method_has_lane(lane, method)
        || !method_recovery_flag_valid(method, input->request->flags)
        || input->fd_count != input->request->fd_count
        || input->fd_count > PLAMEN_BROKER_V2_MAX_FDS
        || !effect_descriptor_shape_valid(input->request, input->fds,
            input->fd_count)
        || all_zero(input->request_sha256)
        || all_zero(input->effects_context_sha256))
        return -1;
    encoded_capacity = input->request_wire_size;
    encoded = malloc(encoded_capacity);
    if (encoded == NULL
        || plamen_broker_v2_specialized_request_encode(input->request,
            encoded, encoded_capacity, &encoded_size) != PLAMEN_BROKER_V2_OK
        || encoded_size != input->request_wire_size
        || !constant_equal(encoded, input->request_wire, encoded_size)
        || plamen_broker_v2_sha256(encoded, encoded_size, observed_sha256)
            != PLAMEN_BROKER_V2_OK
        || !constant_equal(observed_sha256, input->request_sha256, 32U)
        || plamen_broker_v2_specialized_request_validate_fds(input->request,
            (int *)input->fds, input->fd_count) != PLAMEN_BROKER_V2_OK)
        goto done;
    if ((method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE
            || method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY)
        && effect_archive_root_validate(input->request, input->fds[3],
            archive_root_identity, archive_manifest, archive_census) != 0)
        goto done;
    plan = calloc(1U, sizeof(*plan));
    if (plan == NULL) goto done;
    for (index = 0; index < PLAMEN_BROKER_V2_MAX_FDS; ++index)
        plan->fds[index] = -1;
    if (input->request->payload_size != 0U) {
        plan->payload = malloc(input->request->payload_size);
        if (plan->payload == NULL) goto done;
        memcpy(plan->payload, input->request->payload,
            input->request->payload_size);
    }
    plan->payload_size = input->request->payload_size;
    for (index = 0; index < input->fd_count; ++index) {
        struct stat current, earlier;
        int duplicate = fcntl(input->fds[index], F_DUPFD_CLOEXEC, 3);
        if (duplicate < 0 || fstat(duplicate, &current) != 0) {
            if (duplicate >= 0) (void)close(duplicate);
            goto done;
        }
        for (prior = 0; prior < index; ++prior) {
            if (fstat(copied_fds[prior], &earlier) != 0
                || (current.st_dev == earlier.st_dev
                    && current.st_ino == earlier.st_ino)) {
                (void)close(duplicate);
                goto done;
            }
        }
        copied_fds[index] = duplicate;
    }
    plan->magic = TOOL_EFFECT_PLAN_MAGIC;
    plan->lane = lane;
    plan->method = method;
    plan->flags = input->request->flags;
    memcpy(plan->authority_binding_sha256,
        input->request->authority_binding_sha256, 32U);
    memcpy(plan->operation_nonce, input->request->operation_nonce, 32U);
    memcpy(plan->request_sha256, input->request_sha256, 32U);
    memcpy(plan->effects_context_sha256, input->effects_context_sha256, 32U);
    memcpy(plan->archive_root_identity_sha256, archive_root_identity, 32U);
    memcpy(plan->archive_manifest_sha256, archive_manifest, 32U);
    memcpy(plan->archive_census_sha256, archive_census, 32U);
    memcpy(plan->descriptors, input->request->descriptors,
        input->fd_count * sizeof(plan->descriptors[0]));
    memcpy(plan->fds, copied_fds, input->fd_count * sizeof(plan->fds[0]));
    plan->fd_count = input->fd_count;
    for (index = 0; index < input->fd_count; ++index) copied_fds[index] = -1;
    *out = plan;
    plan = NULL;
    result = 0;
done:
    for (index = 0; index < input->fd_count; ++index)
        if (copied_fds[index] >= 0) (void)close(copied_fds[index]);
    if (encoded != NULL) {
        plamen_broker_v2_secure_zero(encoded, encoded_capacity);
        free(encoded);
    }
    plamen_broker_v2_secure_zero(observed_sha256, sizeof(observed_sha256));
    plamen_broker_v2_secure_zero(archive_root_identity,
        sizeof(archive_root_identity));
    plamen_broker_v2_secure_zero(archive_manifest, sizeof(archive_manifest));
    plamen_broker_v2_secure_zero(archive_census, sizeof(archive_census));
    plamen_broker_v2_tool_effect_plan_destroy(plan);
    return result;
}

#define DEFINE_EFFECT_PLAN(name, lane_value, method_value) \
int plamen_broker_v2_tool_effect_plan_##name( \
    const struct plamen_broker_v2_tool_effect_plan_input *input, \
    struct plamen_broker_v2_tool_effect_plan **plan) \
{ \
    return effect_plan_create(input, lane_value, method_value, plan); \
}

DEFINE_EFFECT_PLAN(js_authenticate,
    PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER,
    PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE)
DEFINE_EFFECT_PLAN(js_runtime_identity,
    PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER,
    PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_RUNTIME_IDENTITY)
DEFINE_EFFECT_PLAN(js_prepare,
    PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER,
    PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE)
DEFINE_EFFECT_PLAN(js_execute,
    PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER,
    PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE)
DEFINE_EFFECT_PLAN(js_replay,
    PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER,
    PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY)
DEFINE_EFFECT_PLAN(managed_evm_runtime_identity,
    PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM,
    PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_RUNTIME_IDENTITY)
DEFINE_EFFECT_PLAN(managed_evm_prepare,
    PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM,
    PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE)
DEFINE_EFFECT_PLAN(managed_evm_execute,
    PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM,
    PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE)
DEFINE_EFFECT_PLAN(managed_evm_project,
    PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM,
    PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PROJECT)
DEFINE_EFFECT_PLAN(evm_projection_commit,
    PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION,
    PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT)
DEFINE_EFFECT_PLAN(evm_projection_recover,
    PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION,
    PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER)
DEFINE_EFFECT_PLAN(evm_projection_project,
    PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION,
    PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_PROJECT)
DEFINE_EFFECT_PLAN(snapshot_runtime_identity,
    PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
    PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_RUNTIME_IDENTITY)
DEFINE_EFFECT_PLAN(snapshot_acquire,
    PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
    PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE)
DEFINE_EFFECT_PLAN(snapshot_prepare,
    PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
    PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE)
DEFINE_EFFECT_PLAN(snapshot_execute,
    PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
    PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE)
DEFINE_EFFECT_PLAN(fuzz_campaign_execute,
    PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
    PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE)
DEFINE_EFFECT_PLAN(fuzz_service_admit,
    PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
    PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT)
DEFINE_EFFECT_PLAN(fuzz_service_execute,
    PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
    PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE)

#undef DEFINE_EFFECT_PLAN

int
plamen_broker_v2_tool_effect_plan_view(
    const struct plamen_broker_v2_tool_effect_plan *plan,
    struct plamen_broker_v2_tool_effect_plan_view *view)
{
    if (plan == NULL || view == NULL || plan->magic != TOOL_EFFECT_PLAN_MAGIC
        || plan->consumed != 0U)
        return -1;
    memset(view, 0, sizeof(*view));
    view->version = PLAMEN_BROKER_V2_TOOL_EFFECT_PLAN_VERSION;
    view->lane = plan->lane;
    view->method = plan->method;
    view->flags = plan->flags;
    memcpy(view->authority_binding_sha256,
        plan->authority_binding_sha256, 32U);
    memcpy(view->operation_nonce, plan->operation_nonce, 32U);
    memcpy(view->request_sha256, plan->request_sha256, 32U);
    memcpy(view->effects_context_sha256, plan->effects_context_sha256, 32U);
    memcpy(view->archive_root_identity_sha256,
        plan->archive_root_identity_sha256, 32U);
    memcpy(view->archive_manifest_sha256,
        plan->archive_manifest_sha256, 32U);
    memcpy(view->archive_census_sha256,
        plan->archive_census_sha256, 32U);
    view->payload = plan->payload;
    view->payload_size = plan->payload_size;
    view->descriptors = plan->descriptors;
    view->fds = plan->fds;
    view->fd_count = plan->fd_count;
    return 0;
}

static const uint8_t *
find_bytes(const uint8_t *haystack, size_t haystack_size,
    const char *needle, size_t needle_size)
{
    size_t index;
    if (haystack == NULL || needle == NULL || needle_size == 0U
        || haystack_size < needle_size)
        return NULL;
    for (index = 0; index <= haystack_size - needle_size; ++index)
        if (memcmp(haystack + index, needle, needle_size) == 0)
            return haystack + index;
    return NULL;
}

static int
contains_once(const uint8_t *bytes, size_t size, const char *fragment)
{
    const uint8_t *first, *second;
    size_t fragment_size = strlen(fragment), remaining;
    first = find_bytes(bytes, size, fragment, fragment_size);
    if (first == NULL) return 0;
    remaining = size - (size_t)(first - bytes) - fragment_size;
    second = find_bytes(first + fragment_size, remaining,
        fragment, fragment_size);
    return second == NULL;
}

static int
contains_digest_field(const uint8_t *bytes, size_t size,
    const char *field, const uint8_t digest[32])
{
    char expected[160], hex[65];
    int amount;
    hex32(digest, hex);
    amount = snprintf(expected, sizeof(expected), "\"%s\":\"%s\"",
        field, hex);
    return amount > 0 && (size_t)amount < sizeof(expected)
        && contains_once(bytes, size, expected);
}

static int
take_literal(const uint8_t **cursor, const uint8_t *end, const char *literal)
{
    size_t size = strlen(literal);
    if ((size_t)(end - *cursor) < size
        || memcmp(*cursor, literal, size) != 0)
        return 0;
    *cursor += size;
    return 1;
}

static int
take_hex64(const uint8_t **cursor, const uint8_t *end)
{
    size_t index;
    if ((size_t)(end - *cursor) < 64U) return 0;
    for (index = 0; index < 64U; ++index) {
        uint8_t value = (*cursor)[index];
        if (!((value >= '0' && value <= '9')
            || (value >= 'a' && value <= 'f')))
            return 0;
    }
    *cursor += 64U;
    return 1;
}

static int
take_safe_relative_path(const uint8_t **cursor, const uint8_t *end)
{
    const uint8_t *start = *cursor;
    size_t component = 0U;
    if (start == end || *start == '/') return 0;
    while (*cursor < end && **cursor != '"') {
        uint8_t value = **cursor;
        if (!((value >= 'a' && value <= 'z')
            || (value >= 'A' && value <= 'Z')
            || (value >= '0' && value <= '9')
            || value == '_' || value == '-' || value == '.' || value == '/'))
            return 0;
        if (value == '/') {
            if (component == 0U
                || (component == 1U && (*cursor)[-1] == '.')
                || (component == 2U && (*cursor)[-1] == '.'
                    && (*cursor)[-2] == '.'))
                return 0;
            component = 0U;
        } else {
            ++component;
        }
        ++*cursor;
    }
    if (*cursor == start || component == 0U
        || (component == 1U && (*cursor)[-1] == '.')
        || (component == 2U && (*cursor)[-1] == '.'
            && (*cursor)[-2] == '.'))
        return 0;
    return 1;
}

#define JS_ARCHIVE_COUNT 2U
#define JS_ARCHIVE_MANIFEST_MAX 16384U
#define JS_ARCHIVE_BYTES_MAX (512ULL * 1024ULL * 1024ULL)

struct js_archive_row {
    const char *artifact_id;
    char filename[73];
    uint8_t sha256[32];
    uint64_t size;
    uint8_t magic[6];
    size_t magic_size;
};

static int
hex_decode_32(const uint8_t *value, uint8_t output[32])
{
    size_t index;
    for (index = 0U; index < 32U; ++index) {
        uint8_t high = value[index * 2U], low = value[index * 2U + 1U];
        if (!((high >= '0' && high <= '9')
                || (high >= 'a' && high <= 'f'))
            || !((low >= '0' && low <= '9')
                || (low >= 'a' && low <= 'f')))
            return 0;
        high = high <= '9' ? (uint8_t)(high - '0')
            : (uint8_t)(high - 'a' + 10U);
        low = low <= '9' ? (uint8_t)(low - '0')
            : (uint8_t)(low - 'a' + 10U);
        output[index] = (uint8_t)((high << 4U) | low);
    }
    return 1;
}

static int
take_u64_decimal(const uint8_t **cursor, const uint8_t *end, uint64_t *value)
{
    uint64_t result = 0U;
    const uint8_t *start = *cursor;
    if (start == end || **cursor < '0' || **cursor > '9') return 0;
    if (**cursor == '0' && *cursor + 1U < end
        && (*cursor)[1] >= '0' && (*cursor)[1] <= '9')
        return 0;
    while (*cursor < end && **cursor >= '0' && **cursor <= '9') {
        uint8_t digit = (uint8_t)(**cursor - '0');
        if (result > (UINT64_MAX - digit) / 10U) return 0;
        result = result * 10U + digit;
        ++*cursor;
    }
    if (*cursor == start) return 0;
    *value = result;
    return 1;
}

static int
js_archive_manifest_parse(const uint8_t *bytes, size_t size,
    struct js_archive_row rows[JS_ARCHIVE_COUNT],
    uint8_t census_sha256[32])
{
    static const char *artifact_ids[JS_ARCHIVE_COUNT] = {
        "node-linux-x86_64", "yarn-classic-noarch"
    };
    static const uint8_t node_magic[6] = { 0xfd, '7', 'z', 'X', 'Z', 0x00 };
    static const uint8_t yarn_magic[3] = { 0x1f, 0x8b, 0x08 };
    const uint8_t *cursor = bytes, *end = bytes + size, *claimed;
    const uint8_t *array_start, *array_end;
    uint64_t count;
    size_t index;
#define TAKE_ARCHIVE(value) do { \
    if (!take_literal(&cursor, end, value)) return 0; \
} while (0)
    TAKE_ARCHIVE("{\"archive_census_sha256\":\"");
    claimed = cursor;
    if (!take_hex64(&cursor, end)) return 0;
    TAKE_ARCHIVE("\",\"archive_count\":");
    if (!take_u64_decimal(&cursor, end, &count) || count != JS_ARCHIVE_COUNT)
        return 0;
    TAKE_ARCHIVE(",\"archives\":");
    array_start = cursor;
    TAKE_ARCHIVE("[");
    for (index = 0U; index < JS_ARCHIVE_COUNT; ++index) {
        const uint8_t *sha_text;
        char expected_filename[73];
        size_t artifact_size = strlen(artifact_ids[index]);
        if (index != 0U) TAKE_ARCHIVE(",");
        TAKE_ARCHIVE("{\"artifact_id\":\"");
        if ((size_t)(end - cursor) < artifact_size
            || memcmp(cursor, artifact_ids[index], artifact_size) != 0)
            return 0;
        cursor += artifact_size;
        TAKE_ARCHIVE("\",\"filename\":\"");
        sha_text = cursor;
        if (!take_hex64(&cursor, end)) return 0;
        TAKE_ARCHIVE(".archive\",\"sha256\":\"");
        if ((size_t)(end - cursor) < 64U
            || memcmp(cursor, sha_text, 64U) != 0
            || !hex_decode_32(cursor, rows[index].sha256))
            return 0;
        cursor += 64U;
        TAKE_ARCHIVE("\",\"size\":");
        if (!take_u64_decimal(&cursor, end, &rows[index].size)
            || rows[index].size == 0U
            || rows[index].size > JS_ARCHIVE_BYTES_MAX)
            return 0;
        TAKE_ARCHIVE("}");
        memcpy(expected_filename, sha_text, 64U);
        memcpy(expected_filename + 64U, ".archive", 9U);
        memcpy(rows[index].filename, expected_filename,
            sizeof(expected_filename));
        rows[index].artifact_id = artifact_ids[index];
        if (index == 0U) {
            memcpy(rows[index].magic, node_magic, sizeof(node_magic));
            rows[index].magic_size = sizeof(node_magic);
        } else {
            memcpy(rows[index].magic, yarn_magic, sizeof(yarn_magic));
            rows[index].magic_size = sizeof(yarn_magic);
        }
    }
    TAKE_ARCHIVE("]");
    array_end = cursor;
    TAKE_ARCHIVE(",\"schema\":\"plamen.js-archive-root-manifest.v1\"}");
    if (cursor != end
        || plamen_broker_v2_sha256(array_start,
            (size_t)(array_end - array_start), census_sha256) != 0) return 0;
    {
        uint8_t claimed_digest[32];
        int valid = hex_decode_32(claimed, claimed_digest)
            && constant_equal(claimed_digest, census_sha256, 32U);
        plamen_broker_v2_secure_zero(claimed_digest,
            sizeof(claimed_digest));
        if (!valid) return 0;
    }
#undef TAKE_ARCHIVE
    return 1;
}

static int
stat_snapshot_equal(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino
        && left->st_mode == right->st_mode && left->st_nlink == right->st_nlink
        && left->st_uid == right->st_uid && left->st_gid == right->st_gid
        && left->st_size == right->st_size
        && left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec
        && left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec
        && left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec
        && left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
}

static int
read_small_regular_at(int root_fd, const char *name,
    uint8_t **bytes, size_t *size, struct stat *identity)
{
    struct stat before, after;
    uint8_t *output = NULL;
    size_t offset = 0U;
    int fd = -1, result = -1;
    memset(&before, 0, sizeof(before));
    memset(&after, 0, sizeof(after));
    if (bytes != NULL) *bytes = NULL;
    if (size != NULL) *size = 0U;
    if (bytes == NULL || size == NULL || identity == NULL) return -1;
    fd = openat(root_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_nlink != 1 || before.st_size <= 0
        || (uint64_t)before.st_size > JS_ARCHIVE_MANIFEST_MAX)
        goto done;
    output = malloc((size_t)before.st_size);
    if (output == NULL) goto done;
    while (offset < (size_t)before.st_size) {
        ssize_t amount = pread(fd, output + offset,
            (size_t)before.st_size - offset, (off_t)offset);
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    if (fstat(fd, &after) != 0 || !stat_snapshot_equal(&before, &after))
        goto done;
    *bytes = output; output = NULL; *size = offset; *identity = after;
    result = 0;
done:
    if (fd >= 0) (void)close(fd);
    if (output != NULL) {
        plamen_broker_v2_secure_zero(output,
            before.st_size > 0 ? (size_t)before.st_size : 0U);
        free(output);
    }
    return result;
}

static int
archive_file_validate(int root_fd, const struct js_archive_row *row,
    struct stat *identity)
{
    CC_SHA256_CTX context;
    struct stat before, after;
    uint8_t buffer[65536], digest[32], prefix[6];
    uint64_t total = 0U;
    int fd = -1, result = -1;
    ssize_t amount;
    memset(&context, 0, sizeof(context)); memset(prefix, 0, sizeof(prefix));
    fd = openat(root_fd, row->filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_nlink != 1 || (uint64_t)before.st_size != row->size
        || CC_SHA256_Init(&context) != 1)
        goto done;
    while ((amount = read(fd, buffer, sizeof(buffer))) > 0) {
        if (total == 0U) {
            size_t prefix_size = (size_t)amount < sizeof(prefix)
                ? (size_t)amount : sizeof(prefix);
            memcpy(prefix, buffer, prefix_size);
        }
        if ((uint64_t)amount > row->size - total
            || CC_SHA256_Update(&context, buffer, (CC_LONG)amount) != 1)
            goto done;
        total += (uint64_t)amount;
    }
    if (amount != 0 || total != row->size
        || memcmp(prefix, row->magic, row->magic_size) != 0
        || CC_SHA256_Final(digest, &context) != 1
        || !constant_equal(digest, row->sha256, 32U)
        || fstat(fd, &after) != 0 || !stat_snapshot_equal(&before, &after))
        goto done;
    *identity = after;
    result = 0;
done:
    if (fd >= 0) (void)close(fd);
    plamen_broker_v2_secure_zero(&context, sizeof(context));
    plamen_broker_v2_secure_zero(buffer, sizeof(buffer));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return result;
}

static int
request_archive_binding_valid(
    const struct plamen_broker_v2_specialized_request *request,
    const uint8_t *manifest, size_t manifest_size,
    const uint8_t manifest_sha256[32], const uint8_t census_sha256[32])
{
    static const char object_marker[] = "\"archives\":{";
    static const char rows_marker[] = "\"archives\":";
    static const char binding_marker[] = ",\"binding_sha256\":\"";
    const uint8_t *object, *binding, *claimed, *object_end;
    const uint8_t *rows, *rows_end, *row_match;
    uint8_t observed[32], claimed_digest[32], *body = NULL;
    size_t object_remaining, body_prefix_size, body_size;
    int valid = 0;
    object = find_bytes(request->payload, request->payload_size,
        object_marker, sizeof(object_marker) - 1U);
    if (object == NULL || find_bytes(object + sizeof(object_marker) - 1U,
            request->payload_size - (size_t)(object - request->payload)
                - (sizeof(object_marker) - 1U),
            object_marker, sizeof(object_marker) - 1U) != NULL)
        goto done;
    object += sizeof(object_marker) - 2U; /* Retain the opening `{`. */
    object_remaining = request->payload_size
        - (size_t)(object - request->payload);
    binding = find_bytes(object, object_remaining, binding_marker,
        sizeof(binding_marker) - 1U);
    if (binding == NULL) goto done;
    claimed = binding + sizeof(binding_marker) - 1U;
    if ((size_t)(request->payload + request->payload_size - claimed) < 66U
        || !hex_decode_32(claimed, claimed_digest)
        || claimed[64] != '"' || claimed[65] != '}')
        goto done;
    object_end = claimed + 65U;
    if (object_end + 1U < request->payload + request->payload_size
        && object_end[1] != ',' && object_end[1] != '}')
        goto done;
    body_prefix_size = (size_t)(binding - object);
    if (body_prefix_size == 0U || body_prefix_size == SIZE_MAX) goto done;
    body_size = body_prefix_size + 1U;
    body = malloc(body_size);
    if (body == NULL) goto done;
    memcpy(body, object, body_prefix_size);
    body[body_prefix_size] = '}';
    if (plamen_broker_v2_sha256(body, body_size, observed) != 0
        || !constant_equal(observed, claimed_digest, 32U)
        || !contains_digest_field(object,
            (size_t)(object_end + 1U - object),
            "archive_census_sha256", census_sha256)
        || !contains_digest_field(object,
            (size_t)(object_end + 1U - object),
            "archive_manifest_sha256", manifest_sha256)
        || !contains_once(object, (size_t)(object_end + 1U - object),
            "\"archive_count\":2")
        || !contains_once(object, (size_t)(object_end + 1U - object),
            "\"archive_root\":\"/"))
        goto done;
    rows = find_bytes(manifest, manifest_size, rows_marker,
        sizeof(rows_marker) - 1U);
    if (rows == NULL) goto done;
    rows += sizeof(rows_marker) - 1U;
    rows_end = find_bytes(rows, manifest_size - (size_t)(rows - manifest),
        ",\"schema\":", sizeof(",\"schema\":") - 1U);
    if (rows_end == NULL || rows_end == rows)
        goto done;
    row_match = find_bytes(object, (size_t)(object_end + 1U - object),
        (const char *)rows, (size_t)(rows_end - rows));
    if (row_match == NULL
        || find_bytes(row_match + (size_t)(rows_end - rows),
            (size_t)(object_end + 1U - row_match)
                - (size_t)(rows_end - rows),
            (const char *)rows, (size_t)(rows_end - rows)) != NULL)
        goto done;
    valid = 1;
done:
    if (body != NULL) {
        plamen_broker_v2_secure_zero(body, body_size);
        free(body);
    }
    plamen_broker_v2_secure_zero(observed, sizeof(observed));
    plamen_broker_v2_secure_zero(claimed_digest, sizeof(claimed_digest));
    return valid;
}

static int
effect_archive_root_validate(
    const struct plamen_broker_v2_specialized_request *request, int root_fd,
    uint8_t root_identity[32], uint8_t manifest_sha256[32],
    uint8_t census_sha256[32])
{
    struct js_archive_row rows[JS_ARCHIVE_COUNT];
    struct stat root_before, root_after, manifest_identity, archive_identity[2];
    uint8_t *manifest = NULL;
    size_t manifest_size = 0U, index, entries = 0U, found[3] = { 0U, 0U, 0U };
    DIR *directory = NULL;
    struct dirent *entry;
    int directory_fd = -1, result = -1;
    memset(rows, 0, sizeof(rows)); memset(&manifest_identity, 0,
        sizeof(manifest_identity)); memset(archive_identity, 0,
        sizeof(archive_identity));
    if (request == NULL || root_fd < 0 || fstat(root_fd, &root_before) != 0
        || !S_ISDIR(root_before.st_mode) || root_before.st_uid != geteuid()
        || (root_before.st_mode & 0077) != 0
        || plamen_broker_v2_fd_identity(root_fd, root_identity) != 0
        || read_small_regular_at(root_fd, "archive-manifest.json", &manifest,
            &manifest_size, &manifest_identity) != 0
        || plamen_broker_v2_sha256(manifest, manifest_size,
            manifest_sha256) != 0
        || !js_archive_manifest_parse(manifest, manifest_size, rows,
            census_sha256)
        || !request_archive_binding_valid(request, manifest, manifest_size,
            manifest_sha256, census_sha256))
        goto done;
    for (index = 0U; index < JS_ARCHIVE_COUNT; ++index)
        if (archive_file_validate(root_fd, &rows[index],
                &archive_identity[index]) != 0
            || (index != 0U
                && archive_identity[index].st_dev
                    == archive_identity[0].st_dev
                && archive_identity[index].st_ino
                    == archive_identity[0].st_ino))
            goto done;
    directory_fd = openat(root_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0 || (directory = fdopendir(directory_fd)) == NULL)
        goto done;
    directory_fd = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        ++entries;
        if (strcmp(entry->d_name, "archive-manifest.json") == 0) ++found[0];
        else if (strcmp(entry->d_name, rows[0].filename) == 0) ++found[1];
        else if (strcmp(entry->d_name, rows[1].filename) == 0) ++found[2];
        else goto done;
    }
    if (errno != 0 || entries != 3U || found[0] != 1U || found[1] != 1U
        || found[2] != 1U || fstat(root_fd, &root_after) != 0
        || !stat_snapshot_equal(&root_before, &root_after))
        goto done;
    result = 0;
done:
    if (directory != NULL) (void)closedir(directory);
    else if (directory_fd >= 0) (void)close(directory_fd);
    if (manifest != NULL) {
        plamen_broker_v2_secure_zero(manifest, manifest_size); free(manifest);
    }
    plamen_broker_v2_secure_zero(rows, sizeof(rows));
    return result;
}

static int
effect_plan_archive_root_stable(
    const struct plamen_broker_v2_tool_effect_plan *plan)
{
    struct plamen_broker_v2_specialized_request retained_request;
    uint8_t root[32], manifest[32], census[32];
    int js_archive = plan != NULL && plan->fd_count == 4U
        && (plan->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE
            || plan->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE
            || plan->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY);
    int result;
    memset(&retained_request, 0, sizeof(retained_request));
    memset(root, 0, sizeof(root));
    memset(manifest, 0, sizeof(manifest));
    memset(census, 0, sizeof(census));
    if (!js_archive) return 1;
    retained_request.payload = plan->payload;
    retained_request.payload_size = (uint32_t)plan->payload_size;
    result = effect_archive_root_validate(&retained_request, plan->fds[3],
            root, manifest, census) == 0
        && constant_equal(root, plan->archive_root_identity_sha256, 32U)
        && constant_equal(manifest, plan->archive_manifest_sha256, 32U)
        && constant_equal(census, plan->archive_census_sha256, 32U);
    plamen_broker_v2_secure_zero(root, sizeof(root));
    plamen_broker_v2_secure_zero(manifest, sizeof(manifest));
    plamen_broker_v2_secure_zero(census, sizeof(census));
    return result;
}

static int
js_runtime_identity_exact(const uint8_t *bytes, size_t size)
{
    const uint8_t *cursor = bytes, *end = bytes + size;
#define TAKE(value) do { if (!take_literal(&cursor, end, value)) return 0; } while (0)
#define HEX_FIELD(value) do { TAKE(value); if (!take_hex64(&cursor, end)) return 0; TAKE("\""); } while (0)
    TAKE("{\"anchor_relative_path\":\"");
    if (!take_safe_relative_path(&cursor, end)) return 0;
    TAKE("\",");
    HEX_FIELD("\"anchor_sha256\":\"");
    TAKE(",");
    HEX_FIELD("\"custody_receipt_sha256\":\"");
    TAKE(",");
    HEX_FIELD("\"install_provenance_sha256\":\"");
    TAKE(",");
    HEX_FIELD("\"native_deployment_receipt_sha256\":\"");
    TAKE(",");
    HEX_FIELD("\"native_extension_sha256\":\"");
    TAKE(",");
    HEX_FIELD("\"offline_network_denial_sha256\":\"");
    TAKE(",");
    HEX_FIELD("\"online_network_admission_sha256\":\"");
    TAKE(",\"schema\":\"plamen.js-dependency-materializer-runtime-identity.v1\",");
    HEX_FIELD("\"source_census_sha256\":\"");
    TAKE(",\"trust_boundary\":\"AUTHENTICATED_INSTALLER_LAUNCHER_BOUNDARY_V1\"}");
#undef HEX_FIELD
#undef TAKE
    return cursor == end;
}

static int
method_terminal_schema_valid(uint16_t method,
    const uint8_t *terminal, size_t terminal_size)
{
    const char *schema = NULL;
    switch (method) {
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_RUNTIME_IDENTITY:
        return js_runtime_identity_exact(terminal, terminal_size);
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE:
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY:
        schema = "plamen.js-dependency-native-terminal.v2";
        break;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_RUNTIME_IDENTITY:
        schema = "plamen.managed-evm-toolchain-runtime-identity.v1";
        break;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE:
        schema = "plamen.managed-evm-python-native-result.v1";
        break;
    case PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT:
    case PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER:
    case PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_PROJECT:
        schema = "plamen.private-analysis-projection-custody.v1";
        break;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_RUNTIME_IDENTITY:
        schema = "plamen.darwin-tool-runtime-identity.v1";
        break;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE:
        schema = "plamen.snapshot-bound-tool-execution-terminal.v3";
        break;
    case PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE:
        schema = "plamen.apple-container.native-fuzz-bundle.v1";
        break;
    case PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT:
        return contains_once(terminal, terminal_size,
            "\"schema_version\":\"plamen.secure-fuzz-launcher-receipt.v1\"");
    case PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE:
        schema = "plamen.apple-container.native-fuzz-bundle.v1";
        break;
    default:
        break;
    }
    if (schema != NULL) {
        char fragment[128];
        int amount = snprintf(fragment, sizeof(fragment),
            "\"schema\":\"%s\"", schema);
        return amount > 0 && (size_t)amount < sizeof(fragment)
            && contains_once(terminal, terminal_size, fragment);
    }
    return contains_once(terminal, terminal_size, "\"schema\":\"");
}

static int
origin_object_valid(const uint8_t *object, size_t size)
{
    static const char prefix[] = "{\"host\":\"";
    static const char suffix[] = "\",\"port\":443,\"scheme\":\"https\"}";
    size_t index, host_size;
    if (size <= sizeof(prefix) - 1U + sizeof(suffix) - 1U
        || memcmp(object, prefix, sizeof(prefix) - 1U) != 0
        || memcmp(object + size - (sizeof(suffix) - 1U), suffix,
            sizeof(suffix) - 1U) != 0)
        return 0;
    host_size = size - (sizeof(prefix) - 1U) - (sizeof(suffix) - 1U);
    if (host_size == 0U || host_size > 253U) return 0;
    for (index = 0; index < host_size; ++index) {
        uint8_t value = object[sizeof(prefix) - 1U + index];
        if (!((value >= 'a' && value <= 'z')
            || (value >= '0' && value <= '9')
            || value == '.' || value == '-'))
            return 0;
    }
    return 1;
}

static int
origin_array_bounds(const uint8_t *json, size_t size, const char *field,
    const uint8_t **content, size_t *content_size)
{
    char marker[96];
    const uint8_t *start, *end;
    size_t marker_size, remaining;
    int amount = snprintf(marker, sizeof(marker), "\"%s\":[", field);
    if (amount <= 0 || (size_t)amount >= sizeof(marker)) return 0;
    marker_size = (size_t)amount;
    start = find_bytes(json, size, marker, marker_size);
    if (start == NULL
        || find_bytes(start + marker_size,
            size - (size_t)(start - json) - marker_size,
            marker, marker_size) != NULL)
        return 0;
    start += marker_size;
    remaining = size - (size_t)(start - json);
    end = memchr(start, ']', remaining);
    if (end == NULL) return 0;
    *content = start;
    *content_size = (size_t)(end - start);
    return 1;
}

static int
origin_member(const uint8_t *array, size_t array_size,
    const uint8_t *object, size_t object_size)
{
    const uint8_t *found = array;
    size_t remaining = array_size;
    while ((found = find_bytes(found, remaining, (const char *)object,
                object_size)) != NULL) {
        size_t offset = (size_t)(found - array);
        int left = offset == 0U || array[offset - 1U] == ',';
        int right = offset + object_size == array_size
            || array[offset + object_size] == ',';
        if (left && right) return 1;
        offset += object_size;
        if (offset > array_size) return 0;
        found = array + offset;
        remaining = array_size - offset;
    }
    return 0;
}

static int
origin_array_valid(const uint8_t *array, size_t size,
    const uint8_t *allowed, size_t allowed_size)
{
    size_t cursor = 0U, start;
    if (size == 0U) return 1;
    while (cursor < size) {
        start = cursor;
        if (array[cursor] != '{') return 0;
        while (cursor < size && array[cursor] != '}') ++cursor;
        if (cursor == size) return 0;
        ++cursor;
        if (!origin_object_valid(array + start, cursor - start)
            || (allowed != NULL && !origin_member(allowed, allowed_size,
                array + start, cursor - start)))
            return 0;
        if (cursor == size) return 1;
        if (array[cursor] != ',') return 0;
        ++cursor;
    }
    return 0;
}

static int
js_egress_subset_valid(const struct plamen_broker_v2_tool_effect_plan *plan,
    const uint8_t *terminal, size_t terminal_size)
{
    const uint8_t *allowed, *observed;
    size_t allowed_size, observed_size;
    return origin_array_bounds(plan->payload, plan->payload_size,
            "allowed_origins", &allowed, &allowed_size)
        && origin_array_bounds(terminal, terminal_size,
            "observed_egress_origins", &observed, &observed_size)
        && origin_array_valid(allowed, allowed_size, NULL, 0U)
        && origin_array_valid(observed, observed_size, allowed, allowed_size);
}

static int
evidence_policy_valid(const struct plamen_broker_v2_tool_effect_plan *plan,
    const struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    int runtime_identity, execute, durable, js_method_terminal;
    js_method_terminal = plan != NULL
        && plan->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        && (plan->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE
            || plan->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY);
    if (evidence == NULL
        || evidence->version != PLAMEN_BROKER_V2_TOOL_EFFECT_EVIDENCE_VERSION
        || evidence->lane != plan->lane || evidence->method != plan->method
        || !constant_equal(evidence->authority_binding_sha256,
            plan->authority_binding_sha256, 32U)
        || !constant_equal(evidence->operation_nonce,
            plan->operation_nonce, 32U)
        || !constant_equal(evidence->request_sha256,
            plan->request_sha256, 32U)
        || !constant_equal(evidence->effects_context_sha256,
            plan->effects_context_sha256, 32U)
        || all_zero(evidence->effect_receipt_sha256)
        || evidence->effect_authenticated != 1U
        || evidence->effect_completed != 1U
        || evidence->terminal == NULL || evidence->terminal_size < 2U
        || evidence->terminal_size > PLAMEN_BROKER_V2_SPECIALIZED_PAYLOAD_MAX
        || (js_method_terminal
            ? (evidence->terminal[evidence->terminal_size - 1U] != '\n'
                || evidence->terminal[evidence->terminal_size - 2U] == '\n')
            : evidence->terminal[evidence->terminal_size - 1U] == '\n'))
        return 0;
    runtime_identity = plan->method
        == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_RUNTIME_IDENTITY
        || plan->method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_RUNTIME_IDENTITY
        || plan->method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_RUNTIME_IDENTITY;
    execute = plan->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE
        || plan->method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE
        || plan->method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE
        || plan->method == PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE
        || plan->method == PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE;
    durable = !runtime_identity;
    if (durable && (evidence->durable_operation != 1U
            || all_zero(evidence->durable_operation_sha256)))
        return 0;
    if (execute && (evidence->provider_authenticated != 1U
            || evidence->network_policy_enforced != 1U
            || evidence->population_zero != 1U
            || evidence->cleanup_complete != 1U
            || all_zero(evidence->lifecycle_receipt_sha256)
            || all_zero(evidence->network_policy_sha256)))
        return 0;
    if (plan->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE
        && (all_zero(evidence->observed_egress_sha256)
            || !contains_digest_field(evidence->terminal,
                evidence->terminal_size, "network_policy_sha256",
                evidence->network_policy_sha256)
            || !contains_digest_field(evidence->terminal,
                evidence->terminal_size, "observed_egress_sha256",
                evidence->observed_egress_sha256)
            || !js_egress_subset_valid(plan, evidence->terminal,
                evidence->terminal_size)))
        return 0;
    return method_terminal_schema_valid(plan->method,
        evidence->terminal, evidence->terminal_size);
}

static int
terminal_canonical_for_method(
    const struct plamen_broker_v2_tool_effect_plan *plan,
    const uint8_t *terminal, size_t terminal_size,
    const uint8_t terminal_sha256[32])
{
    struct plamen_broker_v2_specialized_response response;
    uint8_t *encoded;
    size_t encoded_size = 0U, capacity;
    int result;
    if (terminal_size > SIZE_MAX
            - PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE)
        return 0;
    capacity = terminal_size + PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE;
    encoded = malloc(capacity);
    if (encoded == NULL) return 0;
    memset(&response, 0, sizeof(response));
    response.lane = plan->lane;
    response.method = plan->method;
    response.disposition = method_disposition(plan->method);
    if (method_issues_capability(plan->method))
        memset(response.capability_id, 0x5a, sizeof(response.capability_id));
    memcpy(response.operation_nonce, plan->operation_nonce, 32U);
    memcpy(response.request_sha256, plan->request_sha256, 32U);
    memcpy(response.terminal_sha256, terminal_sha256, 32U);
    response.payload = terminal;
    response.payload_size = (uint32_t)terminal_size;
    result = plamen_broker_v2_specialized_response_encode(&response,
        encoded, capacity, &encoded_size) == PLAMEN_BROKER_V2_OK
        && encoded_size == capacity;
    plamen_broker_v2_secure_zero(encoded, capacity);
    free(encoded);
    return result;
}

static int
effect_plan_copy_terminal(
    const struct plamen_broker_v2_tool_effect_plan *plan,
    const struct plamen_broker_v2_tool_effect_evidence *evidence,
    uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32])
{
    extern int plamen_test_custody_failure_code;
    uint8_t observed_sha256[32];
    uint8_t *copy = NULL;
    int result = -1;
    memset(observed_sha256, 0, sizeof(observed_sha256));
    plamen_test_custody_failure_code = 0;
    if (!evidence_policy_valid(plan, evidence)) {
        plamen_test_custody_failure_code = 1; goto done;
    }
    if (plamen_broker_v2_sha256(evidence->terminal,
            evidence->terminal_size, observed_sha256) != PLAMEN_BROKER_V2_OK) {
        plamen_test_custody_failure_code = 2; goto done;
    }
    if (!terminal_canonical_for_method(plan, evidence->terminal,
            evidence->terminal_size, observed_sha256)) {
        plamen_test_custody_failure_code = 3; goto done;
    }
    copy = malloc(evidence->terminal_size);
    if (copy == NULL) goto done;
    memcpy(copy, evidence->terminal, evidence->terminal_size);
    *terminal = copy;
    *terminal_size = evidence->terminal_size;
    memcpy(terminal_sha256, observed_sha256, 32U);
    copy = NULL;
    result = 0;
done:
    if (copy != NULL) {
        plamen_broker_v2_secure_zero(copy, evidence->terminal_size);
        free(copy);
    }
    plamen_broker_v2_secure_zero(observed_sha256, sizeof(observed_sha256));
    return result;
}

int plamen_test_custody_failure_code;

int
plamen_broker_v2_tool_effect_plan_finalize(
    struct plamen_broker_v2_tool_effect_plan *plan,
    const struct plamen_broker_v2_tool_effect_evidence *evidence,
    uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32])
{
    int result = -1;
    if (terminal != NULL) *terminal = NULL;
    if (terminal_size != NULL) *terminal_size = 0U;
    if (terminal_sha256 != NULL) memset(terminal_sha256, 0, 32U);
    if (plan == NULL || terminal == NULL || terminal_size == NULL
        || terminal_sha256 == NULL || plan->magic != TOOL_EFFECT_PLAN_MAGIC
        || plan->consumed != 0U || plan->issued != 0U)
        return -1;
    plan->consumed = 1U;
    if (effect_plan_archive_root_stable(plan))
        result = effect_plan_copy_terminal(plan, evidence, terminal,
            terminal_size, terminal_sha256);
    effect_plan_clear(plan);
    return result;
}

int
plamen_broker_v2_tool_effect_plan_issue_lease(
    struct plamen_broker_v2_tool_effect_plan *plan,
    const struct plamen_broker_v2_tool_effect_evidence *evidence,
    uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32])
{
    int result;
    if (terminal != NULL) *terminal = NULL;
    if (terminal_size != NULL) *terminal_size = 0U;
    if (terminal_sha256 != NULL) memset(terminal_sha256, 0, 32U);
    if (plan == NULL || terminal == NULL || terminal_size == NULL
        || terminal_sha256 == NULL || plan->magic != TOOL_EFFECT_PLAN_MAGIC
        || plan->consumed != 0U || plan->issued != 0U
        || (plan->method != PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE
            && plan->method != PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE
            && plan->method != PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE))
        return -1;
    if (!effect_plan_archive_root_stable(plan)) {
        plan->consumed = 1U;
        effect_plan_clear(plan);
        return -1;
    }
    result = effect_plan_copy_terminal(plan, evidence, terminal,
        terminal_size, terminal_sha256);
    if (result == 0) {
        plan->issued = 1U;
        return 0;
    }
    plan->consumed = 1U;
    effect_plan_clear(plan);
    return -1;
}

static int
effect_plan_execute_from_lease(
    struct plamen_broker_v2_tool_effect_plan *lease,
    const struct plamen_broker_v2_tool_effect_plan_input *input,
    uint16_t prepare_method, uint16_t execute_method,
    struct plamen_broker_v2_tool_effect_plan **out)
{
    struct plamen_broker_v2_tool_effect_plan *execute = NULL;
    size_t index;
    int result = -1;
    if (out != NULL) *out = NULL;
    if (lease == NULL || input == NULL || out == NULL
        || lease->magic != TOOL_EFFECT_PLAN_MAGIC || lease->consumed != 0U
        || lease->issued != 1U || lease->method != prepare_method)
        return -1;
    if (!effect_plan_archive_root_stable(lease)) goto done;
    if (effect_plan_create(input, lease->lane, execute_method, &execute) != 0)
        goto done;
    if (!constant_equal(lease->authority_binding_sha256,
            execute->authority_binding_sha256, 32U)
        || !constant_equal(lease->effects_context_sha256,
            execute->effects_context_sha256, 32U)
        || lease->payload_size != execute->payload_size
        || (lease->payload_size != 0U
            && !constant_equal(lease->payload, execute->payload,
                lease->payload_size)))
        goto done;
    if (execute->fd_count != 0U) goto done;
    memcpy(execute->descriptors, lease->descriptors,
        lease->fd_count * sizeof(execute->descriptors[0]));
    for (index = 0; index < lease->fd_count; ++index) {
        execute->fds[index] = lease->fds[index];
        lease->fds[index] = -1;
    }
    execute->fd_count = lease->fd_count;
    memcpy(execute->archive_root_identity_sha256,
        lease->archive_root_identity_sha256, 32U);
    memcpy(execute->archive_manifest_sha256,
        lease->archive_manifest_sha256, 32U);
    memcpy(execute->archive_census_sha256,
        lease->archive_census_sha256, 32U);
    lease->fd_count = 0U;
    *out = execute;
    execute = NULL;
    result = 0;
done:
    /* Every authenticated continuation attempt burns the native lease. */
    lease->consumed = 1U;
    effect_plan_clear(lease);
    plamen_broker_v2_tool_effect_plan_destroy(execute);
    return result;
}

int
plamen_broker_v2_tool_effect_plan_js_execute_from_lease(
    struct plamen_broker_v2_tool_effect_plan *lease,
    const struct plamen_broker_v2_tool_effect_plan_input *input,
    struct plamen_broker_v2_tool_effect_plan **out)
{
    return effect_plan_execute_from_lease(lease, input,
        PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE,
        PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE, out);
}

int
plamen_broker_v2_tool_effect_plan_managed_evm_execute_from_lease(
    struct plamen_broker_v2_tool_effect_plan *lease,
    const struct plamen_broker_v2_tool_effect_plan_input *input,
    struct plamen_broker_v2_tool_effect_plan **out)
{
    return effect_plan_execute_from_lease(lease, input,
        PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE,
        PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE, out);
}

int
plamen_broker_v2_tool_effect_plan_snapshot_execute_from_lease(
    struct plamen_broker_v2_tool_effect_plan *lease,
    const struct plamen_broker_v2_tool_effect_plan_input *input,
    struct plamen_broker_v2_tool_effect_plan **out)
{
    return effect_plan_execute_from_lease(lease, input,
        PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE,
        PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE, out);
}

int
plamen_broker_v2_tool_effect_plan_fuzz_campaign_execute_from_lease(
    struct plamen_broker_v2_tool_effect_plan *lease,
    const struct plamen_broker_v2_tool_effect_plan_input *input,
    struct plamen_broker_v2_tool_effect_plan **out)
{
    return effect_plan_execute_from_lease(lease, input,
        PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE,
        PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE, out);
}

static int
effect_plan_execute_callback(
    struct plamen_broker_v2_tool_effect_plan *plan,
    void *context, plamen_broker_v2_tool_effect_execute_fn execute,
    plamen_broker_v2_tool_effect_dispose_fn dispose,
    uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32])
{
    struct plamen_broker_v2_tool_effect_plan_view view;
    struct plamen_broker_v2_tool_effect_evidence evidence;
    int callback_status, result;
    memset(&view, 0, sizeof(view));
    memset(&evidence, 0, sizeof(evidence));
    if (plan == NULL || context == NULL || execute == NULL || dispose == NULL
        || terminal == NULL || terminal_size == NULL || terminal_sha256 == NULL
        || plamen_broker_v2_tool_effect_plan_view(plan, &view) != 0)
        return -1;
    if (!effect_plan_archive_root_stable(plan)) {
        struct plamen_broker_v2_tool_effect_evidence incomplete;
        memset(&incomplete, 0, sizeof(incomplete));
        incomplete.version = PLAMEN_BROKER_V2_TOOL_EFFECT_EVIDENCE_VERSION;
        incomplete.lane = plan->lane;
        incomplete.method = plan->method;
        (void)plamen_broker_v2_tool_effect_plan_finalize(plan, &incomplete,
            terminal, terminal_size, terminal_sha256);
        return -1;
    }
    evidence.version = PLAMEN_BROKER_V2_TOOL_EFFECT_EVIDENCE_VERSION;
    evidence.lane = view.lane;
    evidence.method = view.method;
    memcpy(evidence.authority_binding_sha256,
        view.authority_binding_sha256, 32U);
    memcpy(evidence.operation_nonce, view.operation_nonce, 32U);
    memcpy(evidence.request_sha256, view.request_sha256, 32U);
    memcpy(evidence.effects_context_sha256,
        view.effects_context_sha256, 32U);
    callback_status = execute(context, &view, &evidence);
    if (callback_status != 0) {
        /* Finalize with incomplete evidence to consume/burn the one-shot plan. */
        result = plamen_broker_v2_tool_effect_plan_finalize(plan, &evidence,
            terminal, terminal_size, terminal_sha256);
        dispose(context, &evidence);
        return result == 0 ? -1 : callback_status;
    }
    result = plamen_broker_v2_tool_effect_plan_finalize(plan, &evidence,
        terminal, terminal_size, terminal_sha256);
    dispose(context, &evidence);
    return result;
}

int
plamen_broker_v2_tool_effect_plan_execute(
    struct plamen_broker_v2_tool_effect_plan *plan,
    const struct plamen_broker_v2_tool_effect_executor *executor,
    uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32])
{
    if (executor == NULL
        || executor->version != PLAMEN_BROKER_V2_TOOL_EFFECT_PLAN_VERSION)
        return -1;
    return effect_plan_execute_callback(plan, executor->context,
        executor->execute, executor->dispose, terminal, terminal_size,
        terminal_sha256);
}

static plamen_broker_v2_tool_effect_execute_fn
exact_executor_method(
    const struct plamen_broker_v2_tool_effect_exact_executor *executor,
    uint16_t method)
{
    switch (method) {
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE:
        return executor->js_authenticate;
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_RUNTIME_IDENTITY:
        return executor->js_runtime_identity;
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE:
        return executor->js_prepare;
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE:
        return executor->js_execute;
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY:
        return executor->js_replay;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_RUNTIME_IDENTITY:
        return executor->managed_evm_runtime_identity;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE:
        return executor->managed_evm_prepare;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE:
        return executor->managed_evm_execute;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PROJECT:
        return executor->managed_evm_project;
    case PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT:
        return executor->evm_projection_commit;
    case PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER:
        return executor->evm_projection_recover;
    case PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_PROJECT:
        return executor->evm_projection_project;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_RUNTIME_IDENTITY:
        return executor->snapshot_runtime_identity;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE:
        return executor->snapshot_acquire;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE:
        return executor->snapshot_prepare;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE:
        return executor->snapshot_execute;
    case PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE:
        return executor->fuzz_campaign_execute;
    case PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT:
        return executor->fuzz_service_admit;
    case PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE:
        return executor->fuzz_service_execute;
    default:
        return NULL;
    }
}

int
plamen_broker_v2_tool_effect_plan_execute_exact(
    struct plamen_broker_v2_tool_effect_plan *plan,
    const struct plamen_broker_v2_tool_effect_exact_executor *executor,
    uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32])
{
    plamen_broker_v2_tool_effect_execute_fn execute;
    if (plan == NULL || executor == NULL
        || executor->version
            != PLAMEN_BROKER_V2_TOOL_EFFECT_EXACT_EXECUTOR_VERSION
        || executor->context == NULL || executor->dispose == NULL
        || plan->magic != TOOL_EFFECT_PLAN_MAGIC || plan->consumed != 0U)
        return -1;
    execute = exact_executor_method(executor, plan->method);
    if (execute == NULL) {
        struct plamen_broker_v2_tool_effect_evidence incomplete;
        memset(&incomplete, 0, sizeof(incomplete));
        incomplete.version = PLAMEN_BROKER_V2_TOOL_EFFECT_EVIDENCE_VERSION;
        incomplete.lane = plan->lane;
        incomplete.method = plan->method;
        memcpy(incomplete.authority_binding_sha256,
            plan->authority_binding_sha256, 32U);
        memcpy(incomplete.operation_nonce, plan->operation_nonce, 32U);
        memcpy(incomplete.request_sha256, plan->request_sha256, 32U);
        memcpy(incomplete.effects_context_sha256,
            plan->effects_context_sha256, 32U);
        (void)plamen_broker_v2_tool_effect_plan_finalize(plan, &incomplete,
            terminal, terminal_size, terminal_sha256);
        executor->dispose(executor->context, &incomplete);
        return -1;
    }
    return effect_plan_execute_callback(plan, executor->context, execute,
        executor->dispose, terminal, terminal_size, terminal_sha256);
}

static int
zero_range(const uint8_t *value, size_t size)
{
    uint8_t aggregate = 0;
    size_t index;
    for (index = 0; index < size; ++index)
        aggregate |= value[index];
    return aggregate == 0;
}

static int
tool_id_valid(const char *value)
{
    size_t index, size;
    if (value == NULL || (size = strnlen(value,
            PLAMEN_BROKER_V2_TOOL_ID_MAX + 1U)) == 0
        || size > PLAMEN_BROKER_V2_TOOL_ID_MAX)
        return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (!((byte >= 'a' && byte <= 'z')
                || (byte >= '0' && byte <= '9') || byte == '-'))
            return 0;
    }
    return 1;
}

static int
run_id_valid(const char *value)
{
    size_t index, size;
    if (value == NULL || (size = strnlen(value,
            PLAMEN_BROKER_V2_TOOL_RUN_ID_MAX + 1U)) == 0U
        || size > PLAMEN_BROKER_V2_TOOL_RUN_ID_MAX
        || !((value[0] >= 'a' && value[0] <= 'z')
            || (value[0] >= '0' && value[0] <= '9')))
        return 0;
    for (index = 1U; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (!((byte >= 'a' && byte <= 'z')
                || (byte >= '0' && byte <= '9') || byte == '.'
                || byte == '_' || byte == '-'))
            return 0;
    }
    return 1;
}

static int
immutable_reference(const char *value)
{
    const char *marker;
    size_t index, size;
    if (value == NULL || (size = strlen(value)) < 75U || size > 511U
        || (marker = strstr(value, "@sha256:")) == NULL
        || marker == value || marker[8] == '\0' || strlen(marker + 8) != 64U)
        return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < 0x21 || byte > 0x7e || byte == '"' || byte == '\\')
            return 0;
    }
    for (index = 0; index < 64U; ++index)
        if (!((marker[8 + index] >= '0' && marker[8 + index] <= '9')
                || (marker[8 + index] >= 'a'
                    && marker[8 + index] <= 'f')))
            return 0;
    return strchr(marker + 8, '@') == NULL;
}

static void
hex32(const uint8_t digest[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32U; ++index) {
        output[index * 2U] = digits[digest[index] >> 4];
        output[index * 2U + 1U] = digits[digest[index] & 15U];
    }
    output[64] = '\0';
}

static int
append(struct json_writer *writer, const char *format, ...)
{
    va_list arguments;
    int amount;
    if (writer == NULL || writer->bytes == NULL
        || writer->size >= writer->capacity)
        return -1;
    va_start(arguments, format);
    amount = vsnprintf((char *)writer->bytes + writer->size,
        writer->capacity - writer->size, format, arguments);
    va_end(arguments);
    if (amount < 0 || (size_t)amount >= writer->capacity - writer->size)
        return -1;
    writer->size += (size_t)amount;
    return 0;
}

static int
capability_valid(
    const struct plamen_broker_v2_tool_custody_capability_input *input)
{
    return input != NULL
        && input->version == PLAMEN_BROKER_V2_TOOL_CUSTODY_VERSION
        && immutable_reference(input->runtime_image_reference)
        && !all_zero(input->image_closure_sha256)
        && !all_zero(input->provider_admission_sha256)
        && !all_zero(input->rosetta_authority_sha256)
        && !all_zero(input->network_isolation_authority_sha256)
        && !all_zero(input->custody_receipt_sha256)
        /* The currently frozen managed EVM closure is linux-x86_64. */
        && input->rosetta_required == 1;
}

int
plamen_broker_v2_tool_custody_render_apple_authority(
    const struct plamen_broker_v2_tool_custody_capability_input *input,
    uint8_t *output, size_t capacity, size_t *size, uint8_t digest[32])
{
    struct json_writer writer;
    char image[65], provider[65], rosetta[65], network[65], custody[65];
    if (output == NULL || size == NULL || digest == NULL
        || capacity > PLAMEN_BROKER_V2_TOOL_JSON_MAX
        || !capability_valid(input))
        return -1;
    hex32(input->image_closure_sha256, image);
    hex32(input->provider_admission_sha256, provider);
    hex32(input->rosetta_authority_sha256, rosetta);
    hex32(input->network_isolation_authority_sha256, network);
    hex32(input->custody_receipt_sha256, custody);
    writer.bytes = output; writer.capacity = capacity; writer.size = 0;
    if (append(&writer,
            "{\"architecture\":\"amd64\","
            "\"custody_receipt_sha256\":\"%s\","
            "\"image_closure_sha256\":\"%s\","
            "\"immutable_launch_authority\":"
            "\"PRIVATE_IMMUTABLE_PROJECTED_CLOSURE\","
            "\"network_isolation_authority_sha256\":\"%s\","
            "\"network_policy\":\"DENY_ALL\","
            "\"platform\":\"linux\","
            "\"population_zero_authority\":true,"
            "\"provider_admission_sha256\":\"%s\","
            "\"rootfs_readonly\":true,"
            "\"rosetta_authority_sha256\":\"%s\","
            "\"rosetta_required\":true,"
            "\"runtime_image_reference\":\"%s\","
            "\"schema\":\"plamen.apple-container-tool-custody.v1\"}",
            custody, image, network, provider, rosetta,
            input->runtime_image_reference) != 0
        || plamen_broker_v2_sha256(output, writer.size, digest) != 0)
        return -1;
    *size = writer.size;
    return 0;
}

int
plamen_broker_v2_tool_custody_render_snapshot_authority(
    const struct plamen_broker_v2_tool_custody_capability_input *input,
    uint8_t *output, size_t capacity, size_t *size, uint8_t digest[32])
{
    struct json_writer writer;
    uint8_t unsigned_json[PLAMEN_BROKER_V2_TOOL_JSON_MAX];
    char receipt[65];
    int amount;
    if (output == NULL || size == NULL || digest == NULL
        || capacity > PLAMEN_BROKER_V2_TOOL_JSON_MAX
        || !capability_valid(input))
        return -1;
    amount = snprintf((char *)unsigned_json, sizeof(unsigned_json),
        "{\"exhaustive_descendant_termination_authority\":true,"
        "\"immutable_launch_authority\":"
        "\"PRIVATE_IMMUTABLE_PROJECTED_CLOSURE\","
        "\"network_isolation_authority\":true,"
        "\"network_policy\":\"DENY_ALL\","
        "\"path_security\":\"POSIX_OWNER_MODE_NOFOLLOW\","
        "\"platform\":\"MACOS\","
        "\"population_zero_authority\":true,"
        "\"post_spawn_dynamic_identity_authority\":true,"
        "\"pre_execution_assignment\":true,"
        "\"provider_owns_tree\":true,"
        "\"schema\":\"plamen.snapshot-bound-tool-custody.v1\","
        "\"scratch_writes_only\":true,"
        "\"strategy\":\"APPLE_CONTAINER_VM_CGROUP_NATIVE_CUSTODY\","
        "\"target_read_only\":true,"
        "\"write_confinement_authority\":\"EXHAUSTIVE\"}");
    if (amount <= 0 || (size_t)amount >= sizeof(unsigned_json)
        || plamen_broker_v2_sha256(unsigned_json, (size_t)amount, digest) != 0)
        return -1;
    hex32(digest, receipt);
    writer.bytes = output; writer.capacity = capacity; writer.size = 0;
    /* receipt_sha256 sorts between provider_owns_tree and schema. */
    if (append(&writer,
        "{\"exhaustive_descendant_termination_authority\":true,"
        "\"immutable_launch_authority\":"
        "\"PRIVATE_IMMUTABLE_PROJECTED_CLOSURE\","
        "\"network_isolation_authority\":true,"
        "\"network_policy\":\"DENY_ALL\","
        "\"path_security\":\"POSIX_OWNER_MODE_NOFOLLOW\","
        "\"platform\":\"MACOS\","
        "\"population_zero_authority\":true,"
        "\"post_spawn_dynamic_identity_authority\":true,"
        "\"pre_execution_assignment\":true,"
        "\"provider_owns_tree\":true,"
        "\"receipt_sha256\":\"%s\","
        "\"schema\":\"plamen.snapshot-bound-tool-custody.v1\","
        "\"scratch_writes_only\":true,"
        "\"strategy\":\"APPLE_CONTAINER_VM_CGROUP_NATIVE_CUSTODY\","
        "\"target_read_only\":true,"
        "\"write_confinement_authority\":\"EXHAUSTIVE\"}", receipt) != 0)
        return -1;
    *size = writer.size;
    plamen_broker_v2_secure_zero(unsigned_json, sizeof(unsigned_json));
    return 0;
}

int
plamen_broker_v2_tool_custody_render_analysis_projection(
    const struct plamen_broker_v2_analysis_projection_custody *input,
    uint8_t *output, size_t capacity, size_t *size, uint8_t digest[32])
{
    struct json_writer writer;
    uint8_t unsigned_json[PLAMEN_BROKER_V2_TOOL_JSON_MAX];
    char source[65], copy[65], lock[65], dependency[65], modules[65];
    char workspace[65], custody[65], descriptor[65], mount[65];
    char lineage[65], materialization_request[65];
    char invocation[65], receipt[65];
    size_t full_size = 0;
    int amount, iteration;
    if (input == NULL || input->version != 1 || output == NULL || size == NULL
        || digest == NULL || capacity > PLAMEN_BROKER_V2_TOOL_JSON_MAX
        || input->source_copy_file_count == 0
        || input->source_copy_directory_count == 0
        || input->source_copy_bytes == 0
        || input->materialized_node_modules_file_count == 0
        || input->materialized_node_modules_directory_count == 0
        || input->materialized_node_modules_bytes == 0
        || input->materialization_lineage_byte_count == 0
        || input->analysis_workspace_file_count == 0
        || input->analysis_workspace_directory_count == 0
        || input->analysis_workspace_bytes == 0
        || all_zero(input->original_source_scope_sha256)
        || all_zero(input->source_copy_closure_sha256)
        || all_zero(input->js_lock_selection_sha256)
        || all_zero(input->dependency_materialization_receipt_sha256)
        || all_zero(input->materialized_node_modules_closure_sha256)
        || all_zero(input->materialization_lineage_sha256)
        || all_zero(input->native_materialization_request_sha256)
        || all_zero(input->analysis_workspace_closure_sha256)
        || all_zero(input->native_projection_custody_sha256)
        || all_zero(input->host_descriptor_identity_sha256)
        || all_zero(input->guest_mount_identity_sha256)
        || all_zero(input->invocation_sha256))
        return -1;
    hex32(input->original_source_scope_sha256, source);
    hex32(input->source_copy_closure_sha256, copy);
    hex32(input->js_lock_selection_sha256, lock);
    hex32(input->dependency_materialization_receipt_sha256, dependency);
    hex32(input->materialized_node_modules_closure_sha256, modules);
    hex32(input->analysis_workspace_closure_sha256, workspace);
    hex32(input->materialization_lineage_sha256, lineage);
    hex32(input->native_materialization_request_sha256,
        materialization_request);
    hex32(input->native_projection_custody_sha256, custody);
    hex32(input->host_descriptor_identity_sha256, descriptor);
    hex32(input->guest_mount_identity_sha256, mount);
    hex32(input->invocation_sha256, invocation);
#define PROJECTION_UNSIGNED \
    "{\"analysis_workspace_bytes\":%llu," \
    "\"analysis_workspace_closure_sha256\":\"%s\"," \
    "\"analysis_workspace_directory_count\":%llu," \
    "\"analysis_workspace_file_count\":%llu," \
    "\"component_kind\":\"evm_analysis_projection.v1\"," \
    "\"dependency_materialization_receipt_sha256\":\"%s\"," \
    "\"guest_mount_identity_sha256\":\"%s\"," \
    "\"guest_mount_path\":\"/workspace/project\"," \
    "\"host_descriptor_identity_sha256\":\"%s\"," \
    "\"invocation_sha256\":\"%s\"," \
    "\"js_lock_selection_sha256\":\"%s\"," \
    "\"materialization_lineage_byte_count\":%llu," \
    "\"materialization_lineage_sha256\":\"%s\"," \
    "\"materialized_node_modules_bytes\":%llu," \
    "\"materialized_node_modules_closure_sha256\":\"%s\"," \
    "\"materialized_node_modules_directory_count\":%llu," \
    "\"materialized_node_modules_file_count\":%llu," \
    "\"native_materialization_request_sha256\":\"%s\"," \
    "\"native_projection_custody_sha256\":\"%s\"," \
    "\"original_source_scope_sha256\":\"%s\"," \
    "\"project_read_only\":true," \
    "\"receipt_byte_count\":%llu," \
    "\"schema\":\"plamen.private-analysis-projection-custody.v1\"," \
    "\"source_copy_bytes\":%llu," \
    "\"source_copy_closure_sha256\":\"%s\"," \
    "\"source_copy_directory_count\":%llu," \
    "\"source_copy_file_count\":%llu," \
    "\"writable_mounts\":[\"/workspace/scratch\",\"/workspace/state\"]}"
    for (iteration = 0; iteration < 4; ++iteration) {
        amount = snprintf((char *)unsigned_json, sizeof(unsigned_json),
            PROJECTION_UNSIGNED,
            (unsigned long long)input->analysis_workspace_bytes, workspace,
            (unsigned long long)input->analysis_workspace_directory_count,
            (unsigned long long)input->analysis_workspace_file_count,
            dependency, mount, descriptor, invocation, lock,
            (unsigned long long)input->materialization_lineage_byte_count,
            lineage,
            (unsigned long long)input->materialized_node_modules_bytes, modules,
            (unsigned long long)input->materialized_node_modules_directory_count,
            (unsigned long long)input->materialized_node_modules_file_count,
            materialization_request, custody, source,
            (unsigned long long)full_size,
            (unsigned long long)input->source_copy_bytes, copy,
            (unsigned long long)input->source_copy_directory_count,
            (unsigned long long)input->source_copy_file_count);
        if (amount <= 0 || (size_t)amount >= sizeof(unsigned_json))
            return -1;
        /* The final field adds comma + key + quotes + 64 hex bytes. */
        if (full_size == (size_t)amount + 84U)
            break;
        full_size = (size_t)amount + 84U;
    }
    if (iteration == 4 || full_size > capacity
        || plamen_broker_v2_sha256(unsigned_json, (size_t)amount, digest) != 0)
        return -1;
    hex32(digest, receipt);
    writer.bytes = output; writer.capacity = capacity; writer.size = 0;
    /* receipt_sha256 sorts between receipt_byte_count and schema. */
    if (append(&writer,
        "{\"analysis_workspace_bytes\":%llu,"
        "\"analysis_workspace_closure_sha256\":\"%s\","
        "\"analysis_workspace_directory_count\":%llu,"
        "\"analysis_workspace_file_count\":%llu,"
        "\"component_kind\":\"evm_analysis_projection.v1\","
        "\"dependency_materialization_receipt_sha256\":\"%s\","
        "\"guest_mount_identity_sha256\":\"%s\","
        "\"guest_mount_path\":\"/workspace/project\","
        "\"host_descriptor_identity_sha256\":\"%s\","
        "\"invocation_sha256\":\"%s\","
        "\"js_lock_selection_sha256\":\"%s\","
        "\"materialization_lineage_byte_count\":%llu,"
        "\"materialization_lineage_sha256\":\"%s\","
        "\"materialized_node_modules_bytes\":%llu,"
        "\"materialized_node_modules_closure_sha256\":\"%s\","
        "\"materialized_node_modules_directory_count\":%llu,"
        "\"materialized_node_modules_file_count\":%llu,"
        "\"native_materialization_request_sha256\":\"%s\","
        "\"native_projection_custody_sha256\":\"%s\","
        "\"original_source_scope_sha256\":\"%s\","
        "\"project_read_only\":true,"
        "\"receipt_byte_count\":%llu,"
        "\"receipt_sha256\":\"%s\","
        "\"schema\":\"plamen.private-analysis-projection-custody.v1\","
        "\"source_copy_bytes\":%llu,"
        "\"source_copy_closure_sha256\":\"%s\","
        "\"source_copy_directory_count\":%llu,"
        "\"source_copy_file_count\":%llu,"
        "\"writable_mounts\":[\"/workspace/scratch\",\"/workspace/state\"]}",
        (unsigned long long)input->analysis_workspace_bytes, workspace,
        (unsigned long long)input->analysis_workspace_directory_count,
        (unsigned long long)input->analysis_workspace_file_count,
        dependency, mount, descriptor, invocation, lock,
        (unsigned long long)input->materialization_lineage_byte_count,
        lineage,
        (unsigned long long)input->materialized_node_modules_bytes, modules,
        (unsigned long long)input->materialized_node_modules_directory_count,
        (unsigned long long)input->materialized_node_modules_file_count,
        materialization_request, custody, source,
        (unsigned long long)full_size, receipt,
        (unsigned long long)input->source_copy_bytes, copy,
        (unsigned long long)input->source_copy_directory_count,
        (unsigned long long)input->source_copy_file_count) != 0
        || writer.size != full_size)
        return -1;
    *size = writer.size;
    plamen_broker_v2_secure_zero(unsigned_json, sizeof(unsigned_json));
    return 0;
#undef PROJECTION_UNSIGNED
}

static void store_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24); out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8); out[3] = (uint8_t)value;
}

static void store_u64(uint8_t *out, uint64_t value)
{
    store_u32(out, (uint32_t)(value >> 32)); store_u32(out + 4, (uint32_t)value);
}

static uint32_t load_u32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | in[3];
}

static uint64_t load_u64(const uint8_t *in)
{
    return ((uint64_t)load_u32(in) << 32) | load_u32(in + 4);
}

static int
binding_valid(const struct plamen_broker_v2_tool_execution_binding *binding)
{
    return binding != NULL && binding->version == 1
        && tool_id_valid(binding->tool_id)
        && run_id_valid(binding->run_id)
        && !all_zero(binding->request_sha256)
        && !all_zero(binding->custody_receipt_sha256)
        && !all_zero(binding->materialization_receipt_sha256)
        && !all_zero(binding->materialization_lineage_schema_sha256)
        && !all_zero(binding->snapshot_sha256)
        && !all_zero(binding->analysis_projection_sha256)
        && binding->analysis_projection_bytes != 0
        && !all_zero(binding->launch_object_sha256)
        && binding->launch_object_bytes != 0
        && !all_zero(binding->governance_sha256)
        && !all_zero(binding->version_lock_sha256)
        && !all_zero(binding->source_descriptor_identity_sha256)
        && !all_zero(binding->source_scope_sha256)
        && !all_zero(binding->argv_sha256)
        && !all_zero(binding->environment_sha256)
        && !all_zero(binding->cwd_sha256)
        && !all_zero(binding->mounts_sha256)
        && !all_zero(binding->native_runtime_identity_sha256)
        && !all_zero(binding->network_authority_sha256)
        && !all_zero(binding->allowed_path_manifest_sha256)
        && binding->timeout_ms != 0 && binding->memory_bytes != 0
        && binding->stdout_bound_bytes != 0
        && binding->stdout_bound_bytes <= TOOL_STREAM_OBSERVED_MAX
        && binding->stderr_bound_bytes != 0
        && binding->stderr_bound_bytes <= TOOL_STREAM_OBSERVED_MAX
        && binding->output_file_bound_bytes != 0;
}

static int
terminal_core_valid(const struct plamen_broker_v2_tool_guest_terminal *terminal)
{
    return terminal != NULL && terminal->version == 1
        && tool_id_valid(terminal->tool_id) && terminal->returncode == 0
        && terminal->stdout_retained_bytes <= terminal->stdout_observed_bytes
        && terminal->stderr_retained_bytes <= terminal->stderr_observed_bytes
        && terminal->stdout_observed_bytes <= TOOL_STREAM_OBSERVED_MAX
        && terminal->stderr_observed_bytes <= TOOL_STREAM_OBSERVED_MAX
        && terminal->stdout_retained_bytes <= TOOL_STREAM_RETAINED_MAX
        && terminal->stderr_retained_bytes <= TOOL_STREAM_RETAINED_MAX
        && !all_zero(terminal->post_spawn_dynamic_identity_sha256)
        && !all_zero(terminal->artifact_manifest_sha256)
        && terminal->artifact_count <= 65536U
        && terminal->output_limit_exceeded == 0U
        && terminal->network_denied == 1 && terminal->population_zero == 1
        && terminal->cleanup_complete == 1;
}

static int
terminal_matches(const struct plamen_broker_v2_tool_execution_binding *binding,
    const struct plamen_broker_v2_tool_guest_terminal *terminal)
{
    return binding_valid(binding) && terminal_core_valid(terminal)
        && strcmp(binding->tool_id, terminal->tool_id) == 0
        && constant_equal(binding->custody_receipt_sha256,
            terminal->custody_receipt_sha256, 32)
        && constant_equal(binding->materialization_receipt_sha256,
            terminal->materialization_receipt_sha256, 32)
        && constant_equal(binding->snapshot_sha256,
            terminal->snapshot_sha256, 32)
        && constant_equal(binding->launch_object_sha256,
            terminal->launch_object_sha256, 32)
        && binding->launch_object_bytes == terminal->launch_object_bytes
        && constant_equal(binding->argv_sha256, terminal->argv_sha256, 32)
        && constant_equal(binding->environment_sha256,
            terminal->environment_sha256, 32)
        && constant_equal(binding->cwd_sha256, terminal->cwd_sha256, 32)
        && constant_equal(binding->mounts_sha256, terminal->mounts_sha256, 32)
        && terminal->duration_ms <= binding->timeout_ms
        && terminal->peak_memory_bytes <= binding->memory_bytes
        && terminal->artifact_bytes <= binding->output_file_bound_bytes;
}

int
plamen_broker_v2_tool_guest_terminal_encode(
    const struct plamen_broker_v2_tool_execution_binding *binding,
    const struct plamen_broker_v2_tool_guest_terminal *terminal,
    const uint8_t key[32],
    uint8_t output[PLAMEN_BROKER_V2_TOOL_GUEST_TERMINAL_SIZE])
{
    static const uint8_t domain[] = "plamen.tool-guest-terminal.v1\0";
    uint8_t run_id_sha256[32];
    size_t tool_size;
    if (key == NULL || output == NULL || all_zero(key)
        || !terminal_matches(binding, terminal)
        || plamen_broker_v2_sha256(binding->run_id,
            strlen(binding->run_id), run_id_sha256) != 0)
        return -1;
    tool_size = strlen(binding->tool_id);
    memset(output, 0, PLAMEN_BROKER_V2_TOOL_GUEST_TERMINAL_SIZE);
    memcpy(output, "PLMTGT1\0", 8); store_u32(output + 8, 1);
    store_u32(output + 12, PLAMEN_BROKER_V2_TOOL_GUEST_TERMINAL_SIZE);
    store_u32(output + 16, (uint32_t)tool_size);
    memcpy(output + 24, binding->tool_id, tool_size);
    memcpy(output + 56, binding->custody_receipt_sha256, 32);
    memcpy(output + 88, binding->materialization_receipt_sha256, 32);
    memcpy(output + 120, binding->snapshot_sha256, 32);
    memcpy(output + 152, binding->launch_object_sha256, 32);
    store_u64(output + 184, binding->launch_object_bytes);
    memcpy(output + 192, terminal->post_spawn_dynamic_identity_sha256, 32);
    memcpy(output + 224, binding->argv_sha256, 32);
    memcpy(output + 256, binding->environment_sha256, 32);
    memcpy(output + 288, binding->cwd_sha256, 32);
    memcpy(output + 320, binding->mounts_sha256, 32);
    store_u32(output + 352, (uint32_t)terminal->returncode);
    output[356] = terminal->network_denied;
    output[357] = terminal->population_zero;
    output[358] = terminal->cleanup_complete;
    store_u64(output + 360, terminal->stdout_observed_bytes);
    store_u64(output + 368, terminal->stdout_retained_bytes);
    memcpy(output + 376, terminal->stdout_sha256, 32);
    store_u64(output + 408, terminal->stderr_observed_bytes);
    store_u64(output + 416, terminal->stderr_retained_bytes);
    memcpy(output + 424, terminal->stderr_sha256, 32);
    memcpy(output + 456, binding->request_sha256, 32);
    memcpy(output + 488, binding->materialization_lineage_schema_sha256, 32);
    memcpy(output + 520, binding->analysis_projection_sha256, 32);
    store_u64(output + 552, binding->analysis_projection_bytes);
    memcpy(output + 560, binding->governance_sha256, 32);
    memcpy(output + 592, binding->version_lock_sha256, 32);
    memcpy(output + 624, binding->source_descriptor_identity_sha256, 32);
    memcpy(output + 656, binding->source_scope_sha256, 32);
    memcpy(output + 688, binding->network_authority_sha256, 32);
    store_u64(output + 720, binding->timeout_ms);
    store_u64(output + 728, binding->memory_bytes);
    store_u64(output + 736, binding->stdout_bound_bytes);
    store_u64(output + 744, binding->stderr_bound_bytes);
    store_u64(output + 752, binding->output_file_bound_bytes);
    memcpy(output + 760, binding->allowed_path_manifest_sha256, 32);
    memcpy(output + 792, terminal->artifact_manifest_sha256, 32);
    store_u64(output + 824, terminal->artifact_count);
    store_u64(output + 832, terminal->artifact_bytes);
    memcpy(output + 840, run_id_sha256, 32);
    memcpy(output + 872, binding->native_runtime_identity_sha256, 32);
    store_u64(output + 904, terminal->duration_ms);
    store_u64(output + 912, terminal->peak_memory_bytes);
    output[920] = terminal->output_limit_exceeded;
    plamen_broker_v2_secure_zero(run_id_sha256, sizeof(run_id_sha256));
    return plamen_broker_v2_hmac_sha256(key, domain, sizeof(domain), output,
        GUEST_HMAC_OFFSET, output + GUEST_HMAC_OFFSET) == 0 ? 0 : -1;
}

int
plamen_broker_v2_tool_guest_terminal_decode(const uint8_t *input, size_t size,
    const uint8_t key[32],
    const struct plamen_broker_v2_tool_execution_binding *binding,
    struct plamen_broker_v2_tool_guest_terminal *terminal)
{
    static const uint8_t domain[] = "plamen.tool-guest-terminal.v1\0";
    uint8_t expected[32], run_id_sha256[32];
    uint32_t tool_size;
    if (input == NULL || key == NULL || terminal == NULL || all_zero(key)
        || !binding_valid(binding)
        || size != PLAMEN_BROKER_V2_TOOL_GUEST_TERMINAL_SIZE
        || memcmp(input, "PLMTGT1\0", 8) != 0 || load_u32(input + 8) != 1
        || load_u32(input + 12) != size
        || (tool_size = load_u32(input + 16)) == 0
        || tool_size > PLAMEN_BROKER_V2_TOOL_ID_MAX
        || !zero_range(input + 20, 4)
        || !zero_range(input + 24 + tool_size,
            PLAMEN_BROKER_V2_TOOL_ID_MAX - tool_size)
        || input[359] != 0 || !zero_range(input + 921, 71)
        || plamen_broker_v2_hmac_sha256(key, domain, sizeof(domain), input,
            GUEST_HMAC_OFFSET, expected) != 0
        || !constant_equal(expected, input + GUEST_HMAC_OFFSET, 32)
        || !constant_equal(input + 456, binding->request_sha256, 32)
        || !constant_equal(input + 488,
            binding->materialization_lineage_schema_sha256, 32)
        || !constant_equal(input + 520,
            binding->analysis_projection_sha256, 32)
        || load_u64(input + 552) != binding->analysis_projection_bytes
        || !constant_equal(input + 560, binding->governance_sha256, 32)
        || !constant_equal(input + 592, binding->version_lock_sha256, 32)
        || !constant_equal(input + 624,
            binding->source_descriptor_identity_sha256, 32)
        || !constant_equal(input + 656, binding->source_scope_sha256, 32)
        || !constant_equal(input + 688, binding->network_authority_sha256, 32)
        || load_u64(input + 720) != binding->timeout_ms
        || load_u64(input + 728) != binding->memory_bytes
        || load_u64(input + 736) != binding->stdout_bound_bytes
        || load_u64(input + 744) != binding->stderr_bound_bytes
        || load_u64(input + 752) != binding->output_file_bound_bytes
        || !constant_equal(input + 760,
            binding->allowed_path_manifest_sha256, 32)
        || plamen_broker_v2_sha256(binding->run_id,
            strlen(binding->run_id), run_id_sha256) != 0
        || !constant_equal(input + 840, run_id_sha256, 32)
        || !constant_equal(input + 872,
            binding->native_runtime_identity_sha256, 32))
        return -1;
    memset(terminal, 0, sizeof(*terminal)); terminal->version = 1;
    memcpy(terminal->tool_id, input + 24, tool_size);
    memcpy(terminal->custody_receipt_sha256, input + 56, 32);
    memcpy(terminal->materialization_receipt_sha256, input + 88, 32);
    memcpy(terminal->snapshot_sha256, input + 120, 32);
    memcpy(terminal->launch_object_sha256, input + 152, 32);
    terminal->launch_object_bytes = load_u64(input + 184);
    memcpy(terminal->post_spawn_dynamic_identity_sha256, input + 192, 32);
    memcpy(terminal->argv_sha256, input + 224, 32);
    memcpy(terminal->environment_sha256, input + 256, 32);
    memcpy(terminal->cwd_sha256, input + 288, 32);
    memcpy(terminal->mounts_sha256, input + 320, 32);
    terminal->returncode = (int32_t)load_u32(input + 352);
    terminal->network_denied = input[356];
    terminal->population_zero = input[357];
    terminal->cleanup_complete = input[358];
    terminal->stdout_observed_bytes = load_u64(input + 360);
    terminal->stdout_retained_bytes = load_u64(input + 368);
    memcpy(terminal->stdout_sha256, input + 376, 32);
    terminal->stderr_observed_bytes = load_u64(input + 408);
    terminal->stderr_retained_bytes = load_u64(input + 416);
    memcpy(terminal->stderr_sha256, input + 424, 32);
    memcpy(terminal->artifact_manifest_sha256, input + 792, 32);
    terminal->artifact_count = load_u64(input + 824);
    terminal->artifact_bytes = load_u64(input + 832);
    terminal->duration_ms = load_u64(input + 904);
    terminal->peak_memory_bytes = load_u64(input + 912);
    terminal->output_limit_exceeded = input[920];
    memcpy(terminal->record_hmac_sha256, input + GUEST_HMAC_OFFSET, 32);
    if (!terminal_matches(binding, terminal)
        || terminal->stdout_observed_bytes > binding->stdout_bound_bytes
        || terminal->stderr_observed_bytes > binding->stderr_bound_bytes
        || terminal->artifact_bytes > binding->output_file_bound_bytes) {
        plamen_broker_v2_secure_zero(terminal, sizeof(*terminal));
        plamen_broker_v2_secure_zero(run_id_sha256, sizeof(run_id_sha256));
        return -1;
    }
    plamen_broker_v2_secure_zero(run_id_sha256, sizeof(run_id_sha256));
    return 0;
}

static int
lifecycle_chain_valid(
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *started,
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *host,
    const struct plamen_broker_v2_apple_lifecycle_delete_receipt *deleted)
{
    return plamen_broker_v2_apple_lifecycle_create_receipt_validate(created) == 0
        && plamen_broker_v2_apple_lifecycle_start_receipt_validate(started) == 0
        && plamen_broker_v2_apple_lifecycle_terminal_receipt_validate(host) == 0
        && plamen_broker_v2_apple_lifecycle_delete_receipt_validate(deleted) == 0
        && strcmp(created->container_id, started->container_id) == 0
        && strcmp(created->container_id, host->container_id) == 0
        && strcmp(created->container_id, deleted->container_id) == 0
        && constant_equal(created->request_fingerprint_sha256,
            started->request_fingerprint_sha256, 32)
        && constant_equal(created->request_fingerprint_sha256,
            host->request_fingerprint_sha256, 32)
        && constant_equal(created->request_fingerprint_sha256,
            deleted->request_fingerprint_sha256, 32)
        && constant_equal(created->spec_sha256, started->spec_sha256, 32)
        && constant_equal(created->spec_sha256, host->spec_sha256, 32)
        && constant_equal(created->spec_sha256, deleted->spec_sha256, 32)
        && constant_equal(started->native_process_handle_sha256,
            host->native_process_handle_sha256, 32)
        && constant_equal(host->receipt_sha256,
            deleted->terminal_receipt_sha256, 32)
        && constant_equal(host->cleanup_sha256, deleted->cleanup_sha256, 32)
        && created->network_attachment_count == 0 && created->dns_disabled == 1
        && deleted->absent == 1;
}

static int
render_terminal_v3(
    const struct plamen_broker_v2_tool_execution_binding *binding,
    const struct plamen_broker_v2_tool_guest_terminal *terminal,
    uint8_t *output, size_t capacity, size_t *size, uint8_t digest[32])
{
    struct json_writer writer;
    char request[65], snapshot[65], source_descriptor[65], lineage[65];
    char governance[65], version_lock[65], runtime[65], argv[65];
    char environment[65], cwd[65], mounts[65], source_scope[65];
    char dynamic[65], stdout_digest[65], stderr_digest[65], output_tree[65];
    const char *exit_state, *truncation_debt;
    int stdout_truncated, stderr_truncated;
    if (output == NULL || size == NULL || digest == NULL
        || capacity > PLAMEN_BROKER_V2_TOOL_JSON_MAX
        || !terminal_matches(binding, terminal))
        return -1;
    stdout_truncated = terminal->stdout_observed_bytes
        != terminal->stdout_retained_bytes;
    stderr_truncated = terminal->stderr_observed_bytes
        != terminal->stderr_retained_bytes;
    exit_state = (stdout_truncated || stderr_truncated)
        ? "COMPLETED_WITH_TRUNCATION_DEBT" : "COMPLETED";
    if (stderr_truncated && stdout_truncated)
        truncation_debt = "{\"can_certify_clean\":false,"
            "\"findings_complete\":false,"
            "\"schema\":\"plamen.tool-output-truncation-debt.v1\","
            "\"streams\":[\"stderr\",\"stdout\"]}";
    else if (stderr_truncated)
        truncation_debt = "{\"can_certify_clean\":false,"
            "\"findings_complete\":false,"
            "\"schema\":\"plamen.tool-output-truncation-debt.v1\","
            "\"streams\":[\"stderr\"]}";
    else if (stdout_truncated)
        truncation_debt = "{\"can_certify_clean\":false,"
            "\"findings_complete\":false,"
            "\"schema\":\"plamen.tool-output-truncation-debt.v1\","
            "\"streams\":[\"stdout\"]}";
    else
        truncation_debt = "null";
    hex32(binding->request_sha256, request);
    hex32(binding->snapshot_sha256, snapshot);
    hex32(binding->source_descriptor_identity_sha256, source_descriptor);
    hex32(binding->materialization_lineage_schema_sha256, lineage);
    hex32(binding->governance_sha256, governance);
    hex32(binding->version_lock_sha256, version_lock);
    hex32(binding->native_runtime_identity_sha256, runtime);
    hex32(binding->argv_sha256, argv);
    hex32(binding->environment_sha256, environment);
    hex32(binding->cwd_sha256, cwd);
    hex32(binding->mounts_sha256, mounts);
    hex32(binding->source_scope_sha256, source_scope);
    hex32(terminal->post_spawn_dynamic_identity_sha256, dynamic);
    hex32(terminal->stdout_sha256, stdout_digest);
    hex32(terminal->stderr_sha256, stderr_digest);
    hex32(terminal->artifact_manifest_sha256, output_tree);
    writer.bytes = output; writer.capacity = capacity; writer.size = 0U;
    if (append(&writer,
        "{\"argv_sha256\":\"%s\","
        "\"audit_snapshot_sha256\":\"%s\","
        "\"cleanup_complete\":true,\"cwd_sha256\":\"%s\","
        "\"duration_ms\":%llu,\"egress_denied\":true,"
        "\"egress_policy\":\"DENY_ALL\","
        "\"environment_sha256\":\"%s\",\"exit_state\":\"%s\","
        "\"materialization_lineage_sha256\":\"%s\","
        "\"mounts_sha256\":\"%s\","
        "\"native_runtime_identity_sha256\":\"%s\","
        "\"output_bytes\":%llu,\"output_file_count\":%llu,"
        "\"output_limit_exceeded\":false,"
        "\"output_tree_sha256\":\"%s\",\"peak_memory_bytes\":%llu,"
        "\"population_zero\":true,"
        "\"post_spawn_dynamic_identity_sha256\":\"%s\","
        "\"request_sha256\":\"%s\",\"returncode\":0,"
        "\"run_id\":\"%s\","
        "\"schema\":\"plamen.snapshot-bound-tool-execution-terminal.v3\","
        "\"source_descriptor_sha256\":\"%s\","
        "\"source_scope_sha256\":\"%s\","
        "\"stderr_observed_bytes\":%llu,"
        "\"stderr_retained_bytes\":%llu,\"stderr_sha256\":\"%s\","
        "\"stdout_observed_bytes\":%llu,"
        "\"stdout_retained_bytes\":%llu,\"stdout_sha256\":\"%s\","
        "\"tool_id\":\"%s\","
        "\"toolchain_governance_sha256\":\"%s\","
        "\"toolchain_version_lock_sha256\":\"%s\","
        "\"truncation_debt\":%s}",
        argv, snapshot, cwd,
        (unsigned long long)terminal->duration_ms, environment, exit_state,
        lineage, mounts, runtime,
        (unsigned long long)terminal->artifact_bytes,
        (unsigned long long)terminal->artifact_count, output_tree,
        (unsigned long long)terminal->peak_memory_bytes, dynamic, request,
        binding->run_id, source_descriptor, source_scope,
        (unsigned long long)terminal->stderr_observed_bytes,
        (unsigned long long)terminal->stderr_retained_bytes, stderr_digest,
        (unsigned long long)terminal->stdout_observed_bytes,
        (unsigned long long)terminal->stdout_retained_bytes, stdout_digest,
        binding->tool_id, governance, version_lock, truncation_debt) != 0
        || plamen_broker_v2_sha256(output, writer.size, digest) != 0)
        return -1;
    *size = writer.size;
    return 0;
}

int
plamen_broker_v2_tool_custody_render_terminal(
    const struct plamen_broker_v2_tool_execution_binding *binding,
    const struct plamen_broker_v2_tool_guest_terminal *terminal,
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *started,
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *host,
    const struct plamen_broker_v2_apple_lifecycle_delete_receipt *deleted,
    uint8_t *output, size_t capacity, size_t *size, uint8_t digest[32])
{
    if (!lifecycle_chain_valid(created, started, host, deleted)
        || !terminal_matches(binding, terminal)
        || host->exit_code != terminal->returncode
        || host->end_monotonic_ms - host->start_monotonic_ms
            != terminal->duration_ms
        || host->stdout_observed_bytes != terminal->stdout_observed_bytes
        || host->stdout_retained_bytes != terminal->stdout_retained_bytes
        || host->stderr_observed_bytes != terminal->stderr_observed_bytes
        || host->stderr_retained_bytes != terminal->stderr_retained_bytes
        || !constant_equal(host->stdout_sha256, terminal->stdout_sha256, 32U)
        || !constant_equal(host->stderr_sha256, terminal->stderr_sha256, 32U))
        return -1;
    return render_terminal_v3(binding, terminal, output, capacity, size,
        digest);
}

#ifdef PLAMEN_BROKER_V2_TOOL_CUSTODY_TEST_ONLY
int
plamen_broker_v2_tool_custody_test_render_terminal_v3(
    const struct plamen_broker_v2_tool_execution_binding *binding,
    const struct plamen_broker_v2_tool_guest_terminal *terminal,
    uint8_t *output, size_t capacity, size_t *size, uint8_t digest[32])
{
    return render_terminal_v3(binding, terminal, output, capacity, size,
        digest);
}
#endif
