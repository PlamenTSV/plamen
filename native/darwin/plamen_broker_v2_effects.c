#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_effects.h"
#include "plamen_broker_v2_apple_container_lifecycle.h"
#include "plamen_broker_v2_artifact_export.h"
#include "plamen_broker_v2_process.h"
#include "plamen_broker_v2_process_custody_client.h"
#include "plamen_broker_v2_tool_custody.h"
#include "plamen_broker_v2_workspace_effects.h"
#include "plamen_broker_v2_specialized_runtime_effects_handoff.h"
#include "plamen_broker_v2_specialized_effect_store.h"
#include "plamen_broker_v2_specialized_apple_effect_execution.h"
#include "plamen_broker_v2_fuzz_campaign.h"

#include <errno.h>
#include <CommonCrypto/CommonDigest.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define EFFECTS_MAGIC UINT32_C(0x50465831)
#define STATE_FILE "journal-state-v1.bin"
#define STATE_MAGIC "PLMFXS1\0"
#define STATE_SIZE 224U
#define STATE_DIGEST_OFFSET 192U
#define REPLAY_MAGIC "PLMFXR1\0"
#define REPLAY_STATE_SIZE 84U
#define REPLAY_PREFIX_SIZE (188U + REPLAY_STATE_SIZE)
#define REPLAY_WIRE_OFFSET REPLAY_PREFIX_SIZE
#define PROVIDER_ADMISSION_FILE "provider-admission-v1.bin"
#define PROVIDER_ADMISSION_MAGIC "PLMPAD1\0"
#define PROVIDER_ADMISSION_SIZE 1024U
#define PROVIDER_ADMISSION_DIGEST_OFFSET 992U
#define PROVIDER_BINDING_FILE "provider-lifecycle-binding-v2.bin"
#define PROVIDER_BINDING_MAGIC "PLMPBL2\0"
#define PROVIDER_BINDING_SIZE 256U
#define PROVIDER_BINDING_DIGEST_OFFSET 224U
#define PROVIDER_EVIDENCE_MAGIC "PLMPEV1\0"
#define PROVIDER_EVIDENCE_SIZE 192U
#define PROVIDER_EVIDENCE_DIGEST_OFFSET 160U
#define PROVIDER_CREATED_EVIDENCE "provider-created-evidence-v1.bin"
#define PROVIDER_ADMISSION_EVIDENCE "provider-admission-evidence-v1.bin"
#define PROVIDER_START_EVIDENCE "provider-start-evidence-v1.bin"
#define PROVIDER_EXIT_EVIDENCE "provider-exit-evidence-v1.bin"
#define PROVIDER_EXTINCTION_EVIDENCE "provider-extinction-evidence-v1.bin"
#define PROVIDER_CENSUS_EVIDENCE "provider-census-evidence-v1.bin"
#define PROVIDER_EXPORT_PREPARED_EVIDENCE \
    "provider-export-prepared-evidence-v1.bin"
#define PROVIDER_EXPORT_EVIDENCE "provider-export-evidence-v1.bin"
#define PROVIDER_DELETE_EVIDENCE "provider-delete-evidence-v1.bin"
#define PLAMEN_APPLE_CLI_PATH "/usr/local/bin/container"
#define PROVIDER_CPU_COUNT 4U
#define PROVIDER_MEMORY_BYTES UINT64_C(4294967296)

struct effects_fd_snapshot {
    dev_t device;
    ino_t inode;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    nlink_t links;
    off_t size;
};

struct effects_buffer { uint8_t *data; size_t size; size_t capacity; };

static void effects_buffer_destroy(struct effects_buffer *buffer)
{
    if (buffer != NULL && buffer->data != NULL) {
        plamen_broker_v2_secure_zero(buffer->data, buffer->capacity);
        free(buffer->data);
    }
    if (buffer != NULL) memset(buffer, 0, sizeof(*buffer));
}

static int effects_buffer_write(struct effects_buffer *buffer,
    const void *bytes, size_t size)
{
    size_t capacity; uint8_t *value;
    if (buffer == NULL || (size != 0 && bytes == NULL)
        || size > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX - buffer->size)
        return -1;
    if (buffer->size + size > buffer->capacity) {
        capacity = buffer->capacity == 0 ? 1024U : buffer->capacity;
        while (capacity < buffer->size + size) {
            if (capacity > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX / 2U)
                capacity = PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX;
            else capacity *= 2U;
        }
        value = realloc(buffer->data, capacity);
        if (value == NULL) return -1;
        buffer->data = value; buffer->capacity = capacity;
    }
    if (size != 0) memcpy(buffer->data + buffer->size, bytes, size);
    buffer->size += size; return 0;
}

static int effects_buffer_format(struct effects_buffer *buffer,
    const char *format, ...)
{
    va_list first, second;
    char *value = NULL;
    int needed, written, result = -1;
    if (buffer == NULL || format == NULL) return -1;
    va_start(first, format); va_copy(second, first);
    needed = vsnprintf(NULL, 0, format, first);
    va_end(first);
    if (needed < 0
        || (size_t)needed > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX)
        goto done;
    value = malloc((size_t)needed + 1U);
    if (value == NULL) goto done;
    written = vsnprintf(value, (size_t)needed + 1U, format, second);
    if (written != needed
        || effects_buffer_write(buffer, value, (size_t)needed) != 0)
        goto done;
    result = 0;
done:
    va_end(second);
    if (value != NULL) {
        plamen_broker_v2_secure_zero(value,
            needed >= 0 ? (size_t)needed + 1U : 0U);
        free(value);
    }
    return result;
}

struct plamen_broker_v2_effects_context {
    uint32_t magic;
    struct plamen_broker_v2_operations_effects operations;
    struct plamen_broker_v2_service_registration registration;
    uint8_t *projection;
    size_t projection_size;
    uint8_t authority_binding[32];
    int state_parent_fd;
    int state_directory_fd;
    int generation_fd;
    int cancellation_fd;
    struct plamen_broker_v2_process_custody_client *custody_client;
    int authority_fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    struct effects_fd_snapshot
        authority_snapshots[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    struct effects_fd_snapshot state_parent_snapshot;
    struct effects_fd_snapshot state_directory_snapshot;
    struct effects_fd_snapshot generation_snapshot;
    struct effects_fd_snapshot cancellation_snapshot;
    struct plamen_broker_v2_commitment commitment;
    char backend[16];
    char docs_sha256[65];
    char target_identity_sha256[65];
    char backend_context_sha256[65];
    char credential_bundle_sha256[65];
    char egress_policy_sha256[65];
    char scope_sha256[65];
    char seccomp_sha256[65];
    char export_identity_sha256[65];
    char image_manifest_digest[72];
    char runtime_handle[72];
    char docs_handle[72];
    char image_handle[72];
    char target_handle[72];
    char backend_handle[72];
    char credential_handle[72];
    uint8_t current_checkpoint[32];
    uint8_t pending_ticket[32];
    uint64_t journal_sequence;
    uint64_t replay_nonce;
    uint16_t stage;
    uint16_t pending_operation;
    uint8_t complete;
    uint8_t effect_seen;
    uint8_t journal_present;
    pthread_mutex_t lock;
    uint8_t lock_initialized;
    struct plamen_broker_v2_process *process;
    struct plamen_broker_v2_workspace_effects_context *workspace;
    struct plamen_broker_v2_apple_lifecycle *provider_lifecycle;
    struct plamen_broker_v2_tool_effect_plan *js_prepare_lease;
    struct plamen_broker_v2_tool_effect_plan *managed_prepare_lease;
    struct plamen_broker_v2_tool_effect_plan *snapshot_prepare_lease;
    struct plamen_broker_v2_fuzz_service_session *fuzz_service_session;
    struct plamen_broker_v2_fuzz_service_continuation
        *fuzz_service_continuation;
    struct plamen_broker_v2_specialized_runtime_handoff
        *specialized_runtime;
    struct plamen_broker_v2_specialized_effect_store
        *active_specialized_store;
    uint8_t active_specialized_session_key[32];
    struct plamen_broker_v2_apple_container_admission_receipt
        provider_admission;
    uint8_t provider_admission_present;
    uint8_t provider_create_operation_key[32];
    uint8_t provider_spec_sha256[32];
    uint8_t provider_guest_spec_sha256[32];
    char provider_container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
};

static int effects_revalidate(void *, const uint8_t[32], const uint8_t[32],
    const uint8_t[32], uint16_t, uint16_t);
static uint64_t effects_monotonic_ms(void *);
static int effects_cancelled(void *);
static int effects_execute(void *,
    const struct plamen_broker_v2_operations_effect_request *,
    struct plamen_broker_v2_operations_effect_result *);
static void effects_dispose_result(void *,
    struct plamen_broker_v2_operations_effect_result *);
static int effects_replay_lookup(void *, const uint8_t[32],
    const uint8_t[32], uint8_t *, uint8_t *, size_t, size_t *,
    struct plamen_broker_v2_operations_replay_state *);
static int effects_replay_commit(void *, const uint8_t[32],
    const uint8_t[32], uint8_t, const uint8_t *, size_t,
    const struct plamen_broker_v2_operations_replay_state *);
static int provider_artifact_census(
    struct plamen_broker_v2_effects_context *,
    const struct plamen_broker_v2_operations_effect_request *,
    struct plamen_broker_v2_operations_effect_result *);
static int provider_artifact_export(
    struct plamen_broker_v2_effects_context *,
    const struct plamen_broker_v2_operations_effect_request *,
    struct plamen_broker_v2_operations_effect_result *);

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

static void
store_u16(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

static uint16_t
load_u16(const uint8_t *input)
{
    return (uint16_t)(((uint16_t)input[0] << 8) | input[1]);
}

static void
store_u32(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static uint32_t
load_u32(const uint8_t *input)
{
    return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16)
        | ((uint32_t)input[2] << 8) | input[3];
}

static void
store_u64(uint8_t *output, uint64_t value)
{
    size_t index;
    for (index = 0; index < 8; ++index)
        output[index] = (uint8_t)(value >> (56U - (unsigned int)index * 8U));
}

static uint64_t
load_u64(const uint8_t *input)
{
    uint64_t value = 0;
    size_t index;
    for (index = 0; index < 8; ++index)
        value = (value << 8) | input[index];
    return value;
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
format_alloc(uint8_t **output, size_t *output_size, const char *format, ...)
{
    va_list first, second;
    int needed, written;
    uint8_t *value;
    if (output == NULL || output_size == NULL || format == NULL)
        return -1;
    *output = NULL;
    *output_size = 0;
    va_start(first, format);
    va_copy(second, first);
    needed = vsnprintf(NULL, 0, format, first);
    va_end(first);
    if (needed < 0 || (size_t)needed > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX) {
        va_end(second);
        return -1;
    }
    value = malloc((size_t)needed + 1U);
    if (value == NULL) {
        va_end(second);
        return -1;
    }
    written = vsnprintf((char *)value, (size_t)needed + 1U, format, second);
    va_end(second);
    if (written != needed) {
        plamen_broker_v2_secure_zero(value, (size_t)needed + 1U);
        free(value);
        return -1;
    }
    *output = value;
    *output_size = (size_t)needed;
    return 0;
}

static int
snapshot_fd(int descriptor, struct effects_fd_snapshot *snapshot)
{
    struct stat information;
    if (descriptor < 0 || snapshot == NULL
        || fstat(descriptor, &information) != 0)
        return -1;
    snapshot->device = information.st_dev;
    snapshot->inode = information.st_ino;
    snapshot->mode = information.st_mode;
    snapshot->uid = information.st_uid;
    snapshot->gid = information.st_gid;
    snapshot->links = information.st_nlink;
    snapshot->size = information.st_size;
    return 0;
}

static int
snapshot_same(const struct effects_fd_snapshot *expected,
    const struct effects_fd_snapshot *actual)
{
    return expected->device == actual->device
        && expected->inode == actual->inode
        && expected->mode == actual->mode
        && expected->uid == actual->uid
        && expected->gid == actual->gid
        && expected->links == actual->links
        && expected->size == actual->size;
}

static int
duplicate_cloexec(int descriptor)
{
#ifdef F_DUPFD_CLOEXEC
    return fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
#else
    int duplicate = dup(descriptor);
    int flags;
    if (duplicate < 0)
        return -1;
    flags = fcntl(duplicate, F_GETFD);
    if (flags < 0 || fcntl(duplicate, F_SETFD, flags | FD_CLOEXEC) != 0) {
        (void)close(duplicate);
        return -1;
    }
    return duplicate;
#endif
}

static int
descriptor_shape_valid(size_t slot, const struct stat *information)
{
    if (slot == PLAMEN_BROKER_V2_RETAINED_TARGET
        || slot == PLAMEN_BROKER_V2_RETAINED_DOCS
        || slot == PLAMEN_BROKER_V2_RETAINED_EXPORT)
        return S_ISDIR(information->st_mode);
    if (slot == PLAMEN_BROKER_V2_RETAINED_PROVIDER
        || slot == PLAMEN_BROKER_V2_RETAINED_BACKEND)
        return S_ISREG(information->st_mode)
            && (information->st_mode & 0111) != 0;
    return S_ISREG(information->st_mode);
}

static int
validate_authority_array(
    const struct plamen_broker_v2_service_registration *registration,
    const int *descriptors, struct effects_fd_snapshot *snapshots)
{
    struct stat information[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    uint8_t identity[32];
    size_t index, prior;
    int result = -1;
    if (registration == NULL || descriptors == NULL || snapshots == NULL
        || !plamen_broker_v2_service_registration_descriptors_valid(
            registration))
        return -1;
    memset(information, 0, sizeof(information));
    memset(identity, 0, sizeof(identity));
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++index) {
        int present = (registration->authority_presence_mask
            & (uint16_t)(UINT16_C(1) << index)) != 0;
        int fd_flags, open_flags;
        if (!present) {
            if (descriptors[index] != -1)
                goto done;
            continue;
        }
        if (descriptors[index] < 0
            || (fd_flags = fcntl(descriptors[index], F_GETFD)) < 0
            || (fd_flags & FD_CLOEXEC) == 0
            || (open_flags = fcntl(descriptors[index], F_GETFL)) < 0
            || (open_flags & O_ACCMODE) != O_RDONLY
            || fstat(descriptors[index], &information[index]) != 0
            || !descriptor_shape_valid(index, &information[index])
            || plamen_broker_v2_fd_identity(descriptors[index], identity) != 0
            || !constant_equal(identity,
                registration->authority_descriptors[index].identity, 32)
            || snapshot_fd(descriptors[index], &snapshots[index]) != 0)
            goto done;
        for (prior = 0; prior < index; ++prior) {
            if ((registration->authority_presence_mask
                    & (uint16_t)(UINT16_C(1) << prior)) != 0
                && (descriptors[prior] == descriptors[index]
                    || (information[prior].st_dev == information[index].st_dev
                        && information[prior].st_ino
                            == information[index].st_ino)))
                goto done;
        }
    }
    result = 0;
done:
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    plamen_broker_v2_secure_zero(information, sizeof(information));
    return result;
}

static int
private_directory(int descriptor, struct effects_fd_snapshot *snapshot)
{
    struct stat information;
    int flags;
    if (descriptor < 0 || (flags = fcntl(descriptor, F_GETFD)) < 0
        || (flags & FD_CLOEXEC) == 0 || fstat(descriptor, &information) != 0
        || !S_ISDIR(information.st_mode) || information.st_uid != geteuid()
        || (information.st_mode & 0077) != 0)
        return -1;
    return snapshot_fd(descriptor, snapshot);
}

static int
connected_stream(int descriptor, struct effects_fd_snapshot *snapshot)
{
    struct sockaddr_storage peer;
    socklen_t peer_size = sizeof(peer), type_size = sizeof(int);
    int type = 0, flags;
    memset(&peer, 0, sizeof(peer));
    if (descriptor < 0 || (flags = fcntl(descriptor, F_GETFD)) < 0
        || (flags & FD_CLOEXEC) == 0
        || getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &type_size) != 0
        || type != SOCK_STREAM
        || getpeername(descriptor, (struct sockaddr *)&peer, &peer_size) != 0)
        return -1;
    return snapshot_fd(descriptor, snapshot);
}

static int
extract_projection_string(const uint8_t *projection, size_t projection_size,
    const char *key, char *output, size_t capacity)
{
    char pattern[160];
    size_t pattern_size, index, start = 0, found = 0, value_size;
    int amount;
    if (projection == NULL || key == NULL || output == NULL || capacity < 2)
        return -1;
    amount = snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    if (amount <= 0 || (size_t)amount >= sizeof(pattern))
        return -1;
    pattern_size = (size_t)amount;
    for (index = 0; index + pattern_size <= projection_size; ++index) {
        if (memcmp(projection + index, pattern, pattern_size) == 0) {
            if (++found != 1)
                return -1;
            start = index + pattern_size;
        }
    }
    if (found != 1 || start >= projection_size)
        return -1;
    index = start;
    while (index < projection_size && projection[index] != '"') {
        if (projection[index] < 0x20U || projection[index] > 0x7eU
            || projection[index] == '\\')
            return -1;
        ++index;
    }
    if (index >= projection_size)
        return -1;
    value_size = index - start;
    if (value_size == 0 || value_size >= capacity)
        return -1;
    memcpy(output, projection + start, value_size);
    output[value_size] = '\0';
    return 0;
}

static int
hex_string(const char *value)
{
    size_t index;
    if (value == NULL || strlen(value) != 64)
        return 0;
    for (index = 0; index < 64; ++index)
        if (!((value[index] >= '0' && value[index] <= '9')
            || (value[index] >= 'a' && value[index] <= 'f')))
            return 0;
    return 1;
}

static int
decode_hex32(const char *value, uint8_t output[32])
{
    size_t index;
    if (!hex_string(value) || output == NULL) return -1;
    for (index = 0; index < 32; ++index) {
        uint8_t high = (uint8_t)(value[index * 2U] <= '9'
            ? value[index * 2U] - '0' : value[index * 2U] - 'a' + 10);
        uint8_t low = (uint8_t)(value[index * 2U + 1U] <= '9'
            ? value[index * 2U + 1U] - '0'
            : value[index * 2U + 1U] - 'a' + 10);
        output[index] = (uint8_t)((high << 4) | low);
    }
    return all_zero(output) ? -1 : 0;
}

static int
make_handle(struct plamen_broker_v2_effects_context *context,
    const char *domain, const uint8_t identity[32], char output[72])
{
    uint8_t input[160], digest[32];
    char hex[65];
    size_t domain_size;
    if (context == NULL || domain == NULL || identity == NULL || output == NULL)
        return -1;
    domain_size = strlen(domain) + 1U;
    if (domain_size + 64U > sizeof(input))
        return -1;
    memcpy(input, domain, domain_size);
    memcpy(input + domain_size, context->registration.audit_request_fingerprint,
        32);
    memcpy(input + domain_size + 32U, identity, 32);
    if (plamen_broker_v2_sha256(input, domain_size + 64U, digest) != 0)
        return -1;
    encode_hex32(digest, hex);
    if (snprintf(output, 72, "opaque:%s", hex) != 71)
        return -1;
    plamen_broker_v2_secure_zero(input, sizeof(input));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    plamen_broker_v2_secure_zero(hex, sizeof(hex));
    return 0;
}

static int
load_projection_facts(struct plamen_broker_v2_effects_context *context)
{
    const uint8_t zero[32] = { 0 };
    const uint8_t *docs_identity = zero;
    if (extract_projection_string(context->projection, context->projection_size,
            "backend", context->backend, sizeof(context->backend)) != 0
        || (strcmp(context->backend, "codex") != 0
            && strcmp(context->backend, "claude") != 0)
        || extract_projection_string(context->projection,
            context->projection_size, "docs_sha256", context->docs_sha256,
            sizeof(context->docs_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "target_identity_sha256",
            context->target_identity_sha256,
            sizeof(context->target_identity_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "backend_context_sha256",
            context->backend_context_sha256,
            sizeof(context->backend_context_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "credential_bundle_sha256",
            context->credential_bundle_sha256,
            sizeof(context->credential_bundle_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "egress_policy_sha256",
            context->egress_policy_sha256,
            sizeof(context->egress_policy_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "scope_sha256", context->scope_sha256,
            sizeof(context->scope_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "seccomp_profile_sha256",
            context->seccomp_sha256, sizeof(context->seccomp_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "export_destination_identity_sha256",
            context->export_identity_sha256,
            sizeof(context->export_identity_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "image_manifest_digest",
            context->image_manifest_digest,
            sizeof(context->image_manifest_digest)) != 0
        || !hex_string(context->docs_sha256)
        || !hex_string(context->target_identity_sha256)
        || !hex_string(context->backend_context_sha256)
        || !hex_string(context->credential_bundle_sha256)
        || !hex_string(context->egress_policy_sha256)
        || !hex_string(context->scope_sha256)
        || !hex_string(context->seccomp_sha256)
        || !hex_string(context->export_identity_sha256)
        || strlen(context->image_manifest_digest) != 71
        || memcmp(context->image_manifest_digest, "sha256:", 7) != 0
        || !hex_string(context->image_manifest_digest + 7))
        return -1;
    if ((context->registration.authority_presence_mask
            & (uint16_t)(UINT16_C(1) << PLAMEN_BROKER_V2_RETAINED_DOCS)) != 0)
        docs_identity = context->registration.authority_descriptors[
            PLAMEN_BROKER_V2_RETAINED_DOCS].identity;
    return make_handle(context, "PLAMEN-EFFECTS-RUNTIME",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_RUNTIME_MANIFEST].identity,
            context->runtime_handle) == 0
        && make_handle(context, "PLAMEN-EFFECTS-DOCS", docs_identity,
            context->docs_handle) == 0
        && make_handle(context, "PLAMEN-EFFECTS-IMAGE",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_RUNTIME_MANIFEST].identity,
            context->image_handle) == 0
        && make_handle(context, "PLAMEN-EFFECTS-TARGET",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_TARGET].identity,
            context->target_handle) == 0
        && make_handle(context, "PLAMEN-EFFECTS-BACKEND",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_BACKEND_PROFILE].identity,
            context->backend_handle) == 0
        && make_handle(context, "PLAMEN-EFFECTS-CREDENTIAL",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_CREDENTIAL].identity,
            context->credential_handle) == 0 ? 0 : -1;
}

static int
full_sync(int descriptor)
{
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0)
        return 0;
#endif
    return fsync(descriptor);
}

static int
write_all(int descriptor, const uint8_t *data, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = write(descriptor, data + offset, size - offset);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0)
            return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int
pread_all(int descriptor, uint8_t *data, size_t size, off_t offset)
{
    size_t completed = 0;
    while (completed < size) {
        ssize_t amount = pread(descriptor, data + completed,
            size - completed, offset + (off_t)completed);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0)
            return -1;
        completed += (size_t)amount;
    }
    return 0;
}

static int
open_effects_directory(struct plamen_broker_v2_effects_context *context)
{
    char fingerprint[65], name[80];
    int descriptor = -1;
    encode_hex32(context->registration.audit_request_fingerprint, fingerprint);
    if (snprintf(name, sizeof(name), "effects-%s", fingerprint) != 72)
        return -1;
    if (mkdirat(context->state_parent_fd, name, 0700) != 0 && errno != EEXIST)
        return -1;
    descriptor = openat(context->state_parent_fd, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0
        || private_directory(descriptor,
            &context->state_directory_snapshot) != 0) {
        if (descriptor >= 0)
            (void)close(descriptor);
        return -1;
    }
    context->state_directory_fd = descriptor;
    return full_sync(context->state_parent_fd);
}

static void
encode_state(const struct plamen_broker_v2_effects_context *context,
    uint8_t bytes[STATE_SIZE])
{
    memset(bytes, 0, STATE_SIZE);
    memcpy(bytes, STATE_MAGIC, 8);
    store_u32(bytes + 8, PLAMEN_BROKER_V2_EFFECTS_VERSION);
    memcpy(bytes + 12, context->registration.audit_request_fingerprint, 32);
    memcpy(bytes + 44, context->registration.request_projection_sha256, 32);
    memcpy(bytes + 76, context->authority_binding, 32);
    store_u16(bytes + 108, context->stage);
    store_u16(bytes + 110, context->pending_operation);
    store_u64(bytes + 112, context->journal_sequence);
    bytes[120] = context->complete;
    bytes[121] = context->effect_seen;
    memcpy(bytes + 128, context->current_checkpoint, 32);
    memcpy(bytes + 160, context->pending_ticket, 32);
    (void)plamen_broker_v2_sha256(bytes, STATE_DIGEST_OFFSET,
        bytes + STATE_DIGEST_OFFSET);
}

static int
decode_state(struct plamen_broker_v2_effects_context *context,
    const uint8_t bytes[STATE_SIZE])
{
    uint8_t digest[32], zero[32] = { 0 };
    uint16_t stage, pending;
    uint64_t sequence;
    int result = -1;
    if (memcmp(bytes, STATE_MAGIC, 8) != 0
        || load_u32(bytes + 8) != PLAMEN_BROKER_V2_EFFECTS_VERSION
        || !constant_equal(bytes + 12,
            context->registration.audit_request_fingerprint, 32)
        || !constant_equal(bytes + 44,
            context->registration.request_projection_sha256, 32)
        || !constant_equal(bytes + 76, context->authority_binding, 32)
        || plamen_broker_v2_sha256(bytes, STATE_DIGEST_OFFSET, digest) != 0
        || !constant_equal(digest, bytes + STATE_DIGEST_OFFSET, 32))
        goto done;
    stage = load_u16(bytes + 108);
    pending = load_u16(bytes + 110);
    sequence = load_u64(bytes + 112);
    if (stage > PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED
        || pending > PLAMEN_BROKER_V2_OUTER_DELETE_GUEST
        || bytes[120] > 1 || bytes[121] > 1
        || (pending == 0
            ? !constant_equal(bytes + 160, zero, 32)
            : all_zero(bytes + 160))
        || all_zero(bytes + 128)
        || (bytes[120] && (stage != PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED
            || pending != 0)))
        goto done;
    context->stage = stage;
    context->pending_operation = pending;
    context->journal_sequence = sequence;
    context->complete = bytes[120];
    context->effect_seen = bytes[121];
    memcpy(context->current_checkpoint, bytes + 128, 32);
    memcpy(context->pending_ticket, bytes + 160, 32);
    context->journal_present = 1;
    result = 0;
done:
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return result;
}

static int
load_state(struct plamen_broker_v2_effects_context *context)
{
    struct stat information;
    uint8_t bytes[STATE_SIZE], extra;
    int descriptor, result = -1;
    descriptor = openat(context->state_directory_fd, STATE_FILE,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return errno == ENOENT ? 0 : -1;
    if (fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_uid != geteuid()
        || (information.st_mode & 0077) != 0
        || information.st_size != (off_t)STATE_SIZE
        || pread_all(descriptor, bytes, sizeof(bytes), 0) != 0
        || pread(descriptor, &extra, 1, (off_t)STATE_SIZE) != 0
        || decode_state(context, bytes) != 0)
        goto done;
    result = 1;
done:
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    (void)close(descriptor);
    return result;
}

static int
persist_state(struct plamen_broker_v2_effects_context *context)
{
    uint8_t bytes[STATE_SIZE], nonce[8];
    char temporary[64];
    int descriptor = -1, result = -1;
    ++context->replay_nonce;
    store_u64(nonce, context->replay_nonce);
    if (snprintf(temporary, sizeof(temporary), ".state-%02x%02x%02x%02x-"
            "%llu.tmp", nonce[0], nonce[1], nonce[2], nonce[3],
            (unsigned long long)context->replay_nonce) <= 0)
        return -1;
    encode_state(context, bytes);
    descriptor = openat(context->state_directory_fd, temporary,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0 || write_all(descriptor, bytes, sizeof(bytes)) != 0
        || full_sync(descriptor) != 0 || close(descriptor) != 0) {
        if (descriptor >= 0)
            (void)close(descriptor);
        descriptor = -1;
        goto done;
    }
    descriptor = -1;
    if (renameat(context->state_directory_fd, temporary,
            context->state_directory_fd, STATE_FILE) != 0
        || full_sync(context->state_directory_fd) != 0)
        goto done;
    context->journal_present = 1;
    result = 0;
done:
    if (descriptor >= 0)
        (void)close(descriptor);
    if (result != 0)
        (void)unlinkat(context->state_directory_fd, temporary, 0);
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    plamen_broker_v2_secure_zero(nonce, sizeof(nonce));
    return result;
}

static int
encode_provider_admission(
    const struct plamen_broker_v2_apple_container_admission_receipt *receipt,
    uint8_t bytes[PROVIDER_ADMISSION_SIZE])
{
    size_t reference_size;
    if (receipt == NULL
        || (reference_size = strlen(receipt->runtime_image_reference)) == 0
        || reference_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_REFERENCE_MAX)
        return -1;
    memset(bytes, 0, PROVIDER_ADMISSION_SIZE);
    memcpy(bytes, PROVIDER_ADMISSION_MAGIC, 8);
    store_u32(bytes + 8, PLAMEN_BROKER_V2_APPLE_CONTAINER_RECEIPT_VERSION);
    store_u32(bytes + 12, PROVIDER_ADMISSION_SIZE);
    memcpy(bytes + 16, receipt->request_fingerprint_sha256, 32);
    memcpy(bytes + 48, receipt->provider_provenance_sha256, 32);
    memcpy(bytes + 80, receipt->image_closure_sha256, 32);
    memcpy(bytes + 112, receipt->cli_sha256, 32);
    memcpy(bytes + 144, receipt->closure_sha256, 32);
    memcpy(bytes + 176, receipt->version_stdout_sha256, 32);
    memcpy(bytes + 208, receipt->status_stdout_sha256, 32);
    memcpy(bytes + 240, receipt->init_image_stdout_sha256, 32);
    memcpy(bytes + 272, receipt->runtime_image_stdout_sha256, 32);
    memcpy(bytes + 304, receipt->init_image_postcondition_sha256, 32);
    memcpy(bytes + 336, receipt->runtime_image_postcondition_sha256, 32);
    memcpy(bytes + 368, receipt->admission_sha256, 32);
    bytes[400] = receipt->command_count;
    bytes[401] = receipt->commands_read_only;
    bytes[402] = receipt->lifecycle_authority_granted;
    bytes[403] = receipt->mutable_identifier_accepted;
    bytes[404] = receipt->control_processes_reaped;
    bytes[405] = receipt->control_process_groups_extinct;
    store_u16(bytes + 406, (uint16_t)reference_size);
    memcpy(bytes + 408, receipt->runtime_image_reference, reference_size);
    return plamen_broker_v2_sha256(bytes,
        PROVIDER_ADMISSION_DIGEST_OFFSET,
        bytes + PROVIDER_ADMISSION_DIGEST_OFFSET);
}

static int
persist_provider_admission(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_apple_container_admission_receipt *receipt)
{
    struct stat information;
    uint8_t bytes[PROVIDER_ADMISSION_SIZE], existing[PROVIDER_ADMISSION_SIZE];
    int descriptor = -1, created = 0, result = -1;
    memset(bytes, 0, sizeof(bytes)); memset(existing, 0, sizeof(existing));
    if (encode_provider_admission(receipt, bytes) != 0) goto done;
    descriptor = openat(context->state_directory_fd, PROVIDER_ADMISSION_FILE,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor >= 0) {
        created = 1;
        if (write_all(descriptor, bytes, sizeof(bytes)) != 0
            || full_sync(descriptor) != 0 || close(descriptor) != 0) {
            if (descriptor >= 0) (void)close(descriptor);
            descriptor = -1; goto done;
        }
        descriptor = -1;
        if (full_sync(context->state_directory_fd) != 0) goto done;
        result = 0; goto done;
    }
    if (errno != EEXIST) goto done;
    descriptor = openat(context->state_directory_fd, PROVIDER_ADMISSION_FILE,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_uid != geteuid()
        || (information.st_mode & 0077) != 0
        || information.st_size != (off_t)sizeof(existing)
        || pread_all(descriptor, existing, sizeof(existing), 0) != 0
        || !constant_equal(bytes, existing, sizeof(bytes))) goto done;
    result = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (created && result != 0)
        (void)unlinkat(context->state_directory_fd, PROVIDER_ADMISSION_FILE, 0);
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    plamen_broker_v2_secure_zero(existing, sizeof(existing));
    return result;
}

static int
provider_binding_bytes(struct plamen_broker_v2_effects_context *context,
    const uint8_t create_operation_key[32], const char *container_id,
    const uint8_t spec_sha256[32], const uint8_t guest_spec_sha256[32],
    uint8_t bytes[PROVIDER_BINDING_SIZE])
{
    size_t id_size;
    if (context == NULL || create_operation_key == NULL || container_id == NULL
        || spec_sha256 == NULL || guest_spec_sha256 == NULL
        || all_zero(create_operation_key) || all_zero(spec_sha256)
        || all_zero(guest_spec_sha256)
        || (id_size = strlen(container_id)) == 0
        || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE) return -1;
    memset(bytes, 0, PROVIDER_BINDING_SIZE);
    memcpy(bytes, PROVIDER_BINDING_MAGIC, 8);
    store_u32(bytes + 8, PLAMEN_BROKER_V2_EFFECTS_VERSION);
    memcpy(bytes + 12, context->registration.audit_request_fingerprint, 32);
    memcpy(bytes + 44, context->authority_binding, 32);
    memcpy(bytes + 76, create_operation_key, 32);
    memcpy(bytes + 108, spec_sha256, 32);
    memcpy(bytes + 140, guest_spec_sha256, 32);
    bytes[172] = (uint8_t)id_size;
    memcpy(bytes + 173, container_id, id_size);
    return plamen_broker_v2_sha256(bytes, PROVIDER_BINDING_DIGEST_OFFSET,
        bytes + PROVIDER_BINDING_DIGEST_OFFSET);
}

static int
retain_provider_binding(struct plamen_broker_v2_effects_context *context,
    const uint8_t create_operation_key[32], const char *container_id,
    const uint8_t spec_sha256[32], const uint8_t guest_spec_sha256[32])
{
    struct stat information;
    uint8_t expected[PROVIDER_BINDING_SIZE], observed[PROVIDER_BINDING_SIZE];
    int descriptor = -1, result = -1;
    memset(expected, 0, sizeof(expected)); memset(observed, 0, sizeof(observed));
    if (provider_binding_bytes(context, create_operation_key, container_id,
            spec_sha256, guest_spec_sha256, expected) != 0) goto done;
    descriptor = openat(context->state_directory_fd, PROVIDER_BINDING_FILE,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor >= 0) {
        if (write_all(descriptor, expected, sizeof(expected)) != 0
            || full_sync(descriptor) != 0 || close(descriptor) != 0) {
            if (descriptor >= 0) (void)close(descriptor);
            descriptor = -1; goto done;
        }
        descriptor = -1;
        if (full_sync(context->state_directory_fd) != 0) goto done;
    } else {
        if (errno != EEXIST) goto done;
        descriptor = openat(context->state_directory_fd, PROVIDER_BINDING_FILE,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0 || fstat(descriptor, &information) != 0
            || !S_ISREG(information.st_mode) || information.st_nlink != 1
            || information.st_uid != geteuid()
            || (information.st_mode & 0077) != 0
            || information.st_size != (off_t)sizeof(observed)
            || pread_all(descriptor, observed, sizeof(observed), 0) != 0
            || !constant_equal(expected, observed, sizeof(expected))) goto done;
    }
    memcpy(context->provider_create_operation_key, create_operation_key, 32);
    memcpy(context->provider_spec_sha256, spec_sha256, 32);
    memcpy(context->provider_guest_spec_sha256, guest_spec_sha256, 32);
    memcpy(context->provider_container_id, container_id, strlen(container_id) + 1U);
    result = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    plamen_broker_v2_secure_zero(expected, sizeof(expected));
    plamen_broker_v2_secure_zero(observed, sizeof(observed));
    return result;
}

static int
load_provider_binding(struct plamen_broker_v2_effects_context *context)
{
    struct stat information;
    uint8_t bytes[PROVIDER_BINDING_SIZE], digest[32];
    uint8_t id_size;
    int descriptor = -1, result = -1;
    memset(bytes, 0, sizeof(bytes));
    descriptor = openat(context->state_directory_fd, PROVIDER_BINDING_FILE,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return errno == ENOENT ? 0 : -1;
    if (fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_uid != geteuid() || (information.st_mode & 0077) != 0
        || information.st_size != (off_t)sizeof(bytes)
        || pread_all(descriptor, bytes, sizeof(bytes), 0) != 0
        || memcmp(bytes, PROVIDER_BINDING_MAGIC, 8) != 0
        || load_u32(bytes + 8) != PLAMEN_BROKER_V2_EFFECTS_VERSION
        || !constant_equal(bytes + 12,
            context->registration.audit_request_fingerprint, 32)
        || !constant_equal(bytes + 44, context->authority_binding, 32)
        || all_zero(bytes + 76) || all_zero(bytes + 108)
        || all_zero(bytes + 140) || (id_size = bytes[172]) == 0
        || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE
        || bytes[173 + id_size] != 0
        || plamen_broker_v2_sha256(bytes, PROVIDER_BINDING_DIGEST_OFFSET,
            digest) != 0
        || !constant_equal(digest, bytes + PROVIDER_BINDING_DIGEST_OFFSET, 32))
        goto done;
    memcpy(context->provider_create_operation_key, bytes + 76, 32);
    memcpy(context->provider_spec_sha256, bytes + 108, 32);
    memcpy(context->provider_guest_spec_sha256, bytes + 140, 32);
    memcpy(context->provider_container_id, bytes + 173, id_size);
    context->provider_container_id[id_size] = '\0';
    if (plamen_broker_v2_apple_container_id_validate(
            context->provider_container_id) != 0) goto done;
    result = 1;
done:
    if (descriptor >= 0) (void)close(descriptor);
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return result;
}

static int
provider_evidence(struct plamen_broker_v2_effects_context *context,
    const char *name, uint32_t kind, const uint8_t commitment[32],
    const uint8_t auxiliary[32], int create, uint8_t observed_commitment[32],
    uint8_t observed_auxiliary[32])
{
    struct stat information;
    uint8_t expected[PROVIDER_EVIDENCE_SIZE], observed[PROVIDER_EVIDENCE_SIZE];
    int descriptor = -1, created = 0, result = -1;
    memset(expected, 0, sizeof(expected)); memset(observed, 0, sizeof(observed));
    if (observed_commitment != NULL) memset(observed_commitment, 0, 32);
    if (observed_auxiliary != NULL) memset(observed_auxiliary, 0, 32);
    if (context == NULL || name == NULL || kind == 0U
        || (create && (commitment == NULL || auxiliary == NULL
            || all_zero(commitment)))
        || (!create && (observed_commitment == NULL
            || observed_auxiliary == NULL))) goto done;
    if (create) {
        memcpy(expected, PROVIDER_EVIDENCE_MAGIC, 8);
        store_u32(expected + 8, PLAMEN_BROKER_V2_EFFECTS_VERSION);
        store_u32(expected + 12, kind);
        memcpy(expected + 16,
            context->registration.audit_request_fingerprint, 32);
        memcpy(expected + 48, context->authority_binding, 32);
        memcpy(expected + 80, commitment, 32);
        memcpy(expected + 112, auxiliary, 32);
        if (plamen_broker_v2_sha256(expected,
                PROVIDER_EVIDENCE_DIGEST_OFFSET,
                expected + PROVIDER_EVIDENCE_DIGEST_OFFSET) != 0) goto done;
        descriptor = openat(context->state_directory_fd, name,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (descriptor >= 0) {
            created = 1;
            if (write_all(descriptor, expected, sizeof(expected)) != 0
                || full_sync(descriptor) != 0 || close(descriptor) != 0) {
                if (descriptor >= 0) (void)close(descriptor);
                descriptor = -1; goto done;
            }
            descriptor = -1;
            if (full_sync(context->state_directory_fd) != 0) goto done;
        } else if (errno != EEXIST) goto done;
    }
    descriptor = openat(context->state_directory_fd, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_uid != geteuid() || (information.st_mode & 0077) != 0
        || information.st_size != (off_t)sizeof(observed)
        || pread_all(descriptor, observed, sizeof(observed), 0) != 0
        || memcmp(observed, PROVIDER_EVIDENCE_MAGIC, 8) != 0
        || load_u32(observed + 8) != PLAMEN_BROKER_V2_EFFECTS_VERSION
        || load_u32(observed + 12) != kind
        || !constant_equal(observed + 16,
            context->registration.audit_request_fingerprint, 32)
        || !constant_equal(observed + 48, context->authority_binding, 32)
        || all_zero(observed + 80)
        || plamen_broker_v2_sha256(observed,
            PROVIDER_EVIDENCE_DIGEST_OFFSET,
            expected + PROVIDER_EVIDENCE_DIGEST_OFFSET) != 0
        || !constant_equal(expected + PROVIDER_EVIDENCE_DIGEST_OFFSET,
            observed + PROVIDER_EVIDENCE_DIGEST_OFFSET, 32)
        || (create && !constant_equal(expected, observed, sizeof(observed))))
        goto done;
    if (!create) {
        memcpy(observed_commitment, observed + 80, 32);
        memcpy(observed_auxiliary, observed + 112, 32);
    }
    result = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (created && result != 0)
        (void)unlinkat(context->state_directory_fd, name, 0);
    plamen_broker_v2_secure_zero(expected, sizeof(expected));
    plamen_broker_v2_secure_zero(observed, sizeof(observed));
    return result;
}

static int
snapshot_same_custody(const struct effects_fd_snapshot *expected,
    const struct effects_fd_snapshot *actual)
{
    return expected->device == actual->device
        && expected->inode == actual->inode
        && expected->mode == actual->mode
        && expected->uid == actual->uid
        && expected->gid == actual->gid;
}

static int
internal_revalidate(struct plamen_broker_v2_effects_context *context)
{
    struct effects_fd_snapshot snapshot;
    uint8_t identity[32];
    size_t index;
    int loaded;
    if (context == NULL || context->magic != EFFECTS_MAGIC)
        return -1;
    memset(&snapshot, 0, sizeof(snapshot));
    memset(identity, 0, sizeof(identity));
    if (snapshot_fd(context->state_parent_fd, &snapshot) != 0
        || !snapshot_same_custody(&context->state_parent_snapshot, &snapshot)
        || snapshot_fd(context->state_directory_fd, &snapshot) != 0
        || !snapshot_same_custody(&context->state_directory_snapshot, &snapshot)
        || snapshot_fd(context->generation_fd, &snapshot) != 0
        || !snapshot_same_custody(&context->generation_snapshot, &snapshot)
        || snapshot_fd(context->cancellation_fd, &snapshot) != 0
        || !snapshot_same(&context->cancellation_snapshot, &snapshot))
        goto fail;
    if (plamen_broker_v2_specialized_runtime_handoff_revalidate(
            context->specialized_runtime) != 0)
        goto fail;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++index) {
        int present = (context->registration.authority_presence_mask
            & (uint16_t)(UINT16_C(1) << index)) != 0;
        int flags;
        if (!present) {
            if (context->authority_fds[index] != -1)
                goto fail;
            continue;
        }
        if (context->authority_fds[index] < 0
            || (flags = fcntl(context->authority_fds[index], F_GETFD)) < 0
            || (flags & FD_CLOEXEC) == 0
            || snapshot_fd(context->authority_fds[index], &snapshot) != 0
            || !snapshot_same(&context->authority_snapshots[index], &snapshot)
            || plamen_broker_v2_fd_identity(
                context->authority_fds[index], identity) != 0
            || !constant_equal(identity,
                context->registration.authority_descriptors[index].identity,
                32))
            goto fail;
    }
    loaded = load_state(context);
    if (loaded < 0 || (context->journal_present && loaded != 1)
        || plamen_broker_v2_workspace_effects_revalidate(
            context->workspace) != 0)
        goto fail;
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    plamen_broker_v2_secure_zero(&snapshot, sizeof(snapshot));
    return 0;
fail:
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    plamen_broker_v2_secure_zero(&snapshot, sizeof(snapshot));
    return -1;
}

static int
effects_revalidate(void *opaque, const uint8_t request_fingerprint[32],
    const uint8_t projection_sha256[32],
    const uint8_t authority_binding_sha256[32], uint16_t member,
    uint16_t method)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    int result = -1;
    if (context == NULL || request_fingerprint == NULL
        || projection_sha256 == NULL || authority_binding_sha256 == NULL
        || (member == 0 ? method != 0
            : (member > PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT
                || method == 0))
        || !constant_equal(request_fingerprint,
            context->registration.audit_request_fingerprint, 32)
        || !constant_equal(projection_sha256,
            context->registration.request_projection_sha256, 32)
        || !constant_equal(authority_binding_sha256,
            context->authority_binding, 32)
        || pthread_mutex_lock(&context->lock) != 0)
        return -1;
    result = internal_revalidate(context);
    (void)pthread_mutex_unlock(&context->lock);
    return result;
}

static uint64_t
effects_monotonic_ms(void *opaque)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    struct timespec now;
    if (context == NULL || context->magic != EFFECTS_MAGIC
        || clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0
        || (uint64_t)now.tv_sec > UINT64_MAX / UINT64_C(1000))
        return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000)
        + (uint64_t)now.tv_nsec / UINT64_C(1000000);
}

static int
effects_cancelled(void *opaque)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    struct pollfd item;
    uint8_t value;
    ssize_t amount;
    if (context == NULL || context->magic != EFFECTS_MAGIC
        || context->cancellation_fd < 0)
        return 1;
    memset(&item, 0, sizeof(item));
    item.fd = context->cancellation_fd;
    item.events = POLLIN;
    if (poll(&item, 1, 0) < 0)
        return errno == EINTR ? 0 : 1;
    if ((item.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        return 1;
    if ((item.revents & POLLIN) == 0)
        return 0;
    amount = recv(context->cancellation_fd, &value, 1,
        MSG_PEEK | MSG_DONTWAIT);
    if (amount > 0 || (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK
            || errno == EINTR)))
        return 0;
    return 1;
}

static int
set_result(struct plamen_broker_v2_operations_effect_result *result,
    uint8_t *wire, size_t wire_size, const uint8_t *semantic,
    size_t semantic_size, uint8_t effect_applied)
{
    if (result == NULL || wire == NULL || wire_size == 0 || semantic == NULL
        || semantic_size == 0
        || plamen_broker_v2_sha256(semantic, semantic_size,
            result->result_commitment_sha256) != 0)
        return -1;
    result->canonical_result = wire;
    result->canonical_result_size = wire_size;
    result->effect_applied = effect_applied;
    result->durability_proven = 1;
    return 0;
}

static int
make_runtime_result(struct plamen_broker_v2_effects_context *context,
    struct plamen_broker_v2_operations_effect_result *result)
{
    uint8_t *wire = NULL, *semantic = NULL;
    size_t wire_size = 0, semantic_size = 0;
    char runtime[65], image[65];
    int status = -1;
    encode_hex32(context->commitment.runtime_closure_sha256, runtime);
    encode_hex32(context->commitment.image_closure_sha256, image);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"AuthenticatedRuntimeImageLayout\",\"fields\":{"
            "\"authenticated\":true,\"docs_handle\":\"%s\","
            "\"docs_sha256\":\"%s\",\"driver_path\":"
            "\"/opt/plamen/scripts/plamen_driver.py\","
            "\"guest_architecture\":\"amd64\",\"guest_os\":\"linux\","
            "\"image_closure_sha256\":\"%s\",\"image_handle\":\"%s\","
            "\"image_manifest_digest\":\"%s\",\"immutable\":true,"
            "\"python_path\":\"/usr/bin/python3\","
            "\"runtime_handle\":\"%s\",\"runtime_layout_sha256\":\"%s\"}}",
            context->docs_handle, context->docs_sha256, image,
            context->image_handle, context->image_manifest_digest,
            context->runtime_handle, runtime) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"authenticated\":true,\"docs_handle\":\"%s\","
            "\"docs_sha256\":\"%s\",\"driver_path\":"
            "\"/opt/plamen/scripts/plamen_driver.py\","
            "\"guest_architecture\":\"amd64\",\"guest_os\":\"linux\","
            "\"image_closure_sha256\":\"%s\",\"image_handle\":\"%s\","
            "\"image_manifest_digest\":\"%s\",\"immutable\":true,"
            "\"python_path\":\"/usr/bin/python3\","
            "\"runtime_handle\":\"%s\",\"runtime_layout_sha256\":\"%s\"}}\n",
            context->docs_handle, context->docs_sha256, image,
            context->image_handle, context->image_manifest_digest,
            context->runtime_handle, runtime) != 0)
        goto done;
    status = set_result(result, wire, wire_size, semantic, semantic_size, 0);
    wire = NULL;
done:
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size);
        free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size);
        free(semantic);
    }
    plamen_broker_v2_secure_zero(runtime, sizeof(runtime));
    plamen_broker_v2_secure_zero(image, sizeof(image));
    return status;
}

static int
make_target_result(struct plamen_broker_v2_effects_context *context,
    int recensus, struct plamen_broker_v2_operations_effect_result *result)
{
    uint8_t *wire = NULL, *semantic = NULL;
    size_t wire_size = 0, semantic_size = 0;
    const char *type = recensus ? "TargetRecensus" : "TargetLease";
    int status = -1;
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"%s\",\"fields\":{%s%s"
            "\"content_sha256\":\"%s\",\"identity_sha256\":\"%s\","
            "\"readonly\":true,\"scratchpad_absent\":true,"
            "\"target_handle\":\"%s\"}}",
            type, recensus ? "" : "\"authenticated\":true,", "",
            context->target_identity_sha256,
            context->target_identity_sha256, context->target_handle) != 0
        || format_alloc(&semantic, &semantic_size,
            "{%s\"content_sha256\":\"%s\",\"identity_sha256\":\"%s\","
            "\"readonly\":true,\"scratchpad_absent\":true,"
            "\"target_handle\":\"%s\"}\n",
            recensus ? "" : "\"authenticated\":true,",
            context->target_identity_sha256,
            context->target_identity_sha256, context->target_handle) != 0)
        goto done;
    status = set_result(result, wire, wire_size, semantic, semantic_size, 0);
    wire = NULL;
done:
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size);
        free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size);
        free(semantic);
    }
    return status;
}

static int
make_backend_result(struct plamen_broker_v2_effects_context *context,
    struct plamen_broker_v2_operations_effect_result *result)
{
    uint8_t *wire = NULL, *semantic = NULL;
    size_t wire_size = 0, semantic_size = 0;
    char admission[65], credential_isolation[65], egress_admission[65];
    int status = -1;
    encode_hex32(context->commitment.backend_admission_sha256, admission);
    encode_hex32(context->commitment.credential_isolation_sha256,
        credential_isolation);
    encode_hex32(context->commitment.egress_admission_sha256,
        egress_admission);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"BackendContext\",\"fields\":{"
            "\"authenticated\":true,\"backend\":\"%s\","
            "\"backend_admission_sha256\":\"%s\","
            "\"context_handle\":\"%s\",\"context_sha256\":\"%s\","
            "\"credential_handle\":\"%s\","
            "\"credential_isolation_sha256\":\"%s\","
            "\"credential_sha256\":\"%s\","
            "\"egress_admission_sha256\":\"%s\","
            "\"egress_policy_sha256\":\"%s\","
            "\"inherited_environment\":{\"$tuple\":[]},"
            "\"network_mode\":\"NARROW_TRUSTED_PROXY_ONLY\"}}",
            context->backend, admission, context->backend_handle,
            context->backend_context_sha256, context->credential_handle,
            credential_isolation, context->credential_bundle_sha256,
            egress_admission, context->egress_policy_sha256) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"authenticated\":true,\"backend\":\"%s\","
            "\"backend_admission_sha256\":\"%s\","
            "\"context_handle\":\"%s\",\"context_sha256\":\"%s\","
            "\"credential_handle\":\"%s\","
            "\"credential_isolation_sha256\":\"%s\","
            "\"credential_sha256\":\"%s\","
            "\"egress_admission_sha256\":\"%s\","
            "\"egress_policy_sha256\":\"%s\","
            "\"inherited_environment\":[],"
            "\"network_mode\":\"NARROW_TRUSTED_PROXY_ONLY\"}\n",
            context->backend, admission, context->backend_handle,
            context->backend_context_sha256, context->credential_handle,
            credential_isolation, context->credential_bundle_sha256,
            egress_admission, context->egress_policy_sha256) != 0)
        goto done;
    status = set_result(result, wire, wire_size, semantic, semantic_size, 0);
    wire = NULL;
done:
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size);
        free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size);
        free(semantic);
    }
    plamen_broker_v2_secure_zero(admission, sizeof(admission));
    plamen_broker_v2_secure_zero(credential_isolation,
        sizeof(credential_isolation));
    plamen_broker_v2_secure_zero(egress_admission,
        sizeof(egress_admission));
    return status;
}

static int
make_provider_result(struct plamen_broker_v2_operations_effect_result *result)
{
    static const uint8_t semantic[] = "\"APPLE_CONTAINER\"\n";
    uint8_t *wire = NULL;
    size_t wire_size = 0;
    int status;
    if (format_alloc(&wire, &wire_size,
            "{\"$enum\":\"ProviderKind\",\"value\":\"APPLE_CONTAINER\"}")
            != 0)
        return -1;
    status = set_result(result, wire, wire_size, semantic,
        sizeof(semantic) - 1U, 0);
    if (status != 0) {
        plamen_broker_v2_secure_zero(wire, wire_size);
        free(wire);
    }
    return status;
}

static int
derive_provider_nonce(struct plamen_broker_v2_effects_context *context,
    const uint8_t create_operation_key[32], const char *domain,
    uint8_t output[32])
{
    uint8_t bytes[256];
    size_t domain_size;
    if (context == NULL || create_operation_key == NULL || domain == NULL
        || output == NULL || (domain_size = strlen(domain) + 1U) > 160U)
        return -1;
    memcpy(bytes, domain, domain_size);
    memcpy(bytes + domain_size,
        context->registration.audit_request_fingerprint, 32);
    memcpy(bytes + domain_size + 32U, create_operation_key, 32);
    memcpy(bytes + domain_size + 64U, context->authority_binding, 32);
    if (plamen_broker_v2_sha256(bytes, domain_size + 96U, output) != 0) {
        plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
        return -1;
    }
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    return all_zero(output) ? -1 : 0;
}

static int
build_provider_spec(struct plamen_broker_v2_effects_context *context,
    const uint8_t create_operation_key[32],
    struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_workspace_mount_view views[10],
    struct plamen_broker_v2_apple_lifecycle_commitments *commitments,
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE], int *stdin_fd)
{
    static const uint16_t purposes[10] = {
        PLAMEN_BROKER_V2_WORKSPACE_MERGED,
        PLAMEN_BROKER_V2_WORKSPACE_SCRATCH,
        PLAMEN_BROKER_V2_WORKSPACE_STATE,
        PLAMEN_BROKER_V2_WORKSPACE_CONTROL,
        PLAMEN_BROKER_V2_WORKSPACE_SECCOMP,
        PLAMEN_BROKER_V2_WORKSPACE_CREDENTIALS,
        PLAMEN_BROKER_V2_WORKSPACE_BACKEND,
        PLAMEN_BROKER_V2_WORKSPACE_RUNTIME,
        PLAMEN_BROKER_V2_WORKSPACE_DOCS,
        PLAMEN_BROKER_V2_WORKSPACE_SCOPE
    };
    static const char *const targets[10] = {
        "/workspace/project", "/workspace/scratch", "/workspace/state",
        "/workspace/control", "/run/plamen/seccomp",
        "/run/plamen/credentials", "/run/plamen/backend", "/opt/plamen",
        "/workspace/docs", "/workspace/scope"
    };
    static const char *const arguments[9] = {
        "-B", "/opt/plamen/scripts/plamen_driver.py",
        "/workspace/control/config.json", "--startup-intent",
        "start-new-run", "--unattended", "--no-sleep",
        "--startup-decision-receipt",
        "/workspace/control/startup-decision.json"
    };
    size_t index;
    uint8_t launch_policy[32];
    if (context == NULL || create_operation_key == NULL || spec == NULL
        || views == NULL || commitments == NULL || container_id == NULL
        || stdin_fd == NULL || all_zero(create_operation_key)
        || !context->provider_admission_present
        || plamen_broker_v2_apple_container_receipt_validate(
            &context->provider_admission) != 0
        || !constant_equal(context->provider_admission.request_fingerprint_sha256,
            context->registration.audit_request_fingerprint, 32)
        || !constant_equal(context->provider_admission.image_closure_sha256,
            context->commitment.image_closure_sha256, 32)
        || !constant_equal(context->provider_admission.provider_provenance_sha256,
            context->commitment.provider_provenance_sha256, 32)
        || decode_hex32(context->egress_policy_sha256, launch_policy) != 0
        || plamen_broker_v2_apple_container_derive_id(
            context->registration.audit_request_fingerprint,
            create_operation_key, container_id) != 0)
        return -1;
    memset(spec, 0, sizeof(*spec));
    memset(views, 0, sizeof(*views) * 10U);
    memset(commitments, 0, sizeof(*commitments));
    *stdin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (*stdin_fd < 0) return -1;
    for (index = 0; index < 10U; ++index) {
        if (plamen_broker_v2_workspace_effects_borrow_mount(
                context->workspace, purposes[index], &views[index]) != 0
            || views[index].version
                != PLAMEN_BROKER_V2_WORKSPACE_EFFECTS_VERSION
            || views[index].purpose != purposes[index]
            || views[index].read_only != (index == 1U || index == 2U ? 0U : 1U))
            goto fail;
        spec->mounts[index].source_fd = views[index].source_fd;
        spec->mounts[index].source_path = views[index].source_path;
        spec->mounts[index].target_path = targets[index];
        memcpy(spec->mounts[index].expected_identity_sha256,
            views[index].identity, 32);
        spec->mounts[index].readonly = views[index].read_only;
    }
    spec->version = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION;
    spec->cli_fd = context->authority_fds[PLAMEN_BROKER_V2_RETAINED_PROVIDER];
    spec->cli_path = PLAMEN_APPLE_CLI_PATH;
    spec->cwd_fd = views[0].source_fd;
    spec->stdin_fd = *stdin_fd;
    /* Lifecycle records are broker-private authority.  The guest-mounted state
     * directory is deliberately writable and therefore can never custody
     * CREATE/START/terminal recovery records. */
    spec->state_directory_fd = context->state_directory_fd;
    spec->admission = &context->provider_admission;
    spec->container_id = container_id;
    spec->runtime_image_reference =
        context->provider_admission.runtime_image_reference;
    spec->working_directory = "/workspace/project";
    spec->entrypoint = "/usr/bin/python3";
    spec->arguments = arguments;
    spec->argument_count = 9U;
    spec->cpus = PROVIDER_CPU_COUNT;
    spec->memory_bytes = PROVIDER_MEMORY_BYTES;
    spec->uid = 1000U; spec->gid = 1000U;
    spec->create_timeout_seconds = 120U;
    spec->driver_timeout_seconds = 86400U;
    spec->stop_grace_seconds = 10U;
    spec->rosetta_required = 1U;
    memcpy(spec->launch_policy_sha256, launch_policy, 32);
    memcpy(spec->create_operation_key, create_operation_key, 32);
    if (derive_provider_nonce(context, create_operation_key,
            "PLAMEN-APPLE-START-V1", spec->start_operation_nonce) != 0
        || derive_provider_nonce(context, create_operation_key,
            "PLAMEN-APPLE-WAIT-V1", spec->wait_operation_nonce) != 0
        || derive_provider_nonce(context, create_operation_key,
            "PLAMEN-APPLE-REVOKE-V1", spec->revoke_operation_nonce) != 0
        || plamen_broker_v2_apple_lifecycle_derive_commitments(
            spec, commitments) != 0)
        goto fail;
    memcpy(spec->spec_sha256, commitments->spec_sha256, 32);
    memcpy(spec->launch_request_sha256,
        commitments->launch_request_sha256, 32);
    memcpy(spec->driver_argv_sha256, commitments->driver_argv_sha256, 32);
    memcpy(spec->driver_environment_sha256,
        commitments->driver_environment_sha256, 32);
    memcpy(spec->driver_cwd_sha256, commitments->driver_cwd_sha256, 32);
    memcpy(spec->driver_stdin_sha256, commitments->driver_stdin_sha256, 32);
    memcpy(spec->pass_fd_roster_sha256,
        commitments->pass_fd_roster_sha256, 32);
    plamen_broker_v2_secure_zero(launch_policy, sizeof(launch_policy));
    return 0;
fail:
    (void)close(*stdin_fd); *stdin_fd = -1;
    plamen_broker_v2_secure_zero(launch_policy, sizeof(launch_policy));
    plamen_broker_v2_secure_zero(spec, sizeof(*spec));
    plamen_broker_v2_secure_zero(views, sizeof(*views) * 10U);
    plamen_broker_v2_secure_zero(commitments, sizeof(*commitments));
    plamen_broker_v2_secure_zero(container_id,
        PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE);
    return -1;
}

static size_t
json_object_end(const uint8_t *bytes, size_t size, size_t start)
{
    size_t index; unsigned int depth = 0; int quoted = 0, escaped = 0;
    if (bytes == NULL || start >= size || bytes[start] != '{') return 0;
    for (index = start; index < size; ++index) {
        uint8_t value = bytes[index];
        if (quoted) {
            if (escaped) escaped = 0;
            else if (value == '\\') escaped = 1;
            else if (value == '"') quoted = 0;
            continue;
        }
        if (value == '"') quoted = 1;
        else if (value == '{') ++depth;
        else if (value == '}' && --depth == 0) return index + 1U;
    }
    return 0;
}

static const uint8_t *
bounded_find(const uint8_t *bytes, size_t size, size_t start,
    const void *needle, size_t needle_size)
{
    size_t index;
    if (bytes == NULL || needle == NULL || needle_size == 0U
        || start > size || needle_size > size - start)
        return NULL;
    for (index = start; index <= size - needle_size; ++index) {
        if (memcmp(bytes + index, needle, needle_size) == 0)
            return bytes + index;
    }
    return NULL;
}

static int
recensus_semantic(const uint8_t *wire, size_t wire_size,
    uint8_t **semantic, size_t *semantic_size)
{
    static const char outer[] =
        "{\"$type\":\"LayoutRecensus\",\"fields\":";
    static const char components[] = "\"components\":{\"$tuple\":[";
    static const char component[] =
        "{\"$type\":\"LayoutComponent\",\"fields\":";
    struct effects_buffer output = { 0 };
    const uint8_t *marker;
    size_t cursor, object_end;
    int result = -1;
    if (semantic == NULL || semantic_size == NULL) return -1;
    *semantic = NULL; *semantic_size = 0;
    if (wire == NULL || wire_size <= sizeof(outer)
        || memcmp(wire, outer, sizeof(outer) - 1U) != 0
        || wire[wire_size - 1U] != '}' || wire[wire_size - 2U] != '}')
        return -1;
    cursor = sizeof(outer) - 1U;
    marker = bounded_find(wire, wire_size, cursor, components,
        sizeof(components) - 1U);
    if (marker == NULL || marker >= wire + wire_size
        || effects_buffer_write(&output, wire + cursor,
            (size_t)(marker - (wire + cursor))) != 0
        || effects_buffer_write(&output, "\"components\":[", 14U) != 0)
        goto done;
    cursor = (size_t)(marker - wire) + sizeof(components) - 1U;
    while (cursor < wire_size && wire[cursor] != ']') {
        if (output.size != 0 && output.data[output.size - 1U] == '}') {
            if (wire[cursor] != ','
                || effects_buffer_write(&output, ",", 1U) != 0) goto done;
            ++cursor;
        }
        if (cursor + sizeof(component) - 1U >= wire_size
            || memcmp(wire + cursor, component, sizeof(component) - 1U) != 0)
            goto done;
        cursor += sizeof(component) - 1U;
        object_end = json_object_end(wire, wire_size, cursor);
        if (object_end == 0 || object_end >= wire_size
            || wire[object_end] != '}'
            || effects_buffer_write(&output, wire + cursor,
                object_end - cursor) != 0) goto done;
        cursor = object_end + 1U;
    }
    if (cursor + 1U >= wire_size || wire[cursor] != ']'
        || wire[cursor + 1U] != '}'
        || effects_buffer_write(&output, "]", 1U) != 0) goto done;
    cursor += 2U;
    /* Copy through the fields object, excluding only the outer type wrapper. */
    if (cursor >= wire_size - 1U
        || effects_buffer_write(&output, wire + cursor,
            wire_size - 1U - cursor) != 0
        || effects_buffer_write(&output, "\n", 1U) != 0) goto done;
    *semantic = output.data; *semantic_size = output.size;
    output.data = NULL; output.size = output.capacity = 0; result = 0;
done:
    effects_buffer_destroy(&output);
    return result;
}

static int
provider_mount_payloads(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_workspace_mount_view views[10],
    uint8_t **wire, size_t *wire_size, uint8_t **semantic,
    size_t *semantic_size, uint8_t commitment[32])
{
    static const char *const purposes[10] = { "project-merged", "scratch",
        "state", "control", "seccomp", "credentials", "backend-context",
        "runtime", "docs", "scope" };
    static const char *const targets[10] = { "/workspace/project",
        "/workspace/scratch", "/workspace/state", "/workspace/control",
        "/run/plamen/seccomp", "/run/plamen/credentials",
        "/run/plamen/backend", "/opt/plamen", "/workspace/docs",
        "/workspace/scope" };
    static const char *const domains[10] = { "PLAMEN-WORKSPACE-MERGED",
        "PLAMEN-WORKSPACE-SCRATCH", "PLAMEN-WORKSPACE-STATE",
        "PLAMEN-WORKSPACE-CONTROL", "PLAMEN-WORKSPACE-SECCOMP", NULL,
        NULL, NULL, NULL, "PLAMEN-WORKSPACE-SCOPE" };
    struct effects_buffer typed = { 0 }, plain = { 0 };
    char handles[10][72]; uint8_t seccomp[32]; uint8_t *row = NULL;
    size_t row_size = 0, index; int result = -1;
    memset(handles, 0, sizeof(handles)); memset(seccomp, 0, sizeof(seccomp));
    if (wire == NULL || wire_size == NULL || semantic == NULL
        || semantic_size == NULL || commitment == NULL) return -1;
    *wire = NULL; *semantic = NULL; *wire_size = *semantic_size = 0;
    for (index = 0; index < 10U; ++index) {
        if (index == 5U) memcpy(handles[index], context->credential_handle, 72);
        else if (index == 6U) memcpy(handles[index], context->backend_handle, 72);
        else if (index == 7U) memcpy(handles[index], context->runtime_handle, 72);
        else if (index == 8U) memcpy(handles[index], context->docs_handle, 72);
        else if (index == 4U) {
            if (decode_hex32(context->seccomp_sha256, seccomp) != 0
                || make_handle(context, domains[index], seccomp,
                    handles[index]) != 0) goto done;
        } else if (make_handle(context, domains[index], views[index].identity,
                handles[index]) != 0) goto done;
    }
    if (effects_buffer_write(&typed, "{\"$tuple\":[", 11U) != 0
        || effects_buffer_write(&plain, "[", 1U) != 0) goto done;
    for (index = 0; index < 10U; ++index) {
        const char *mode = views[index].read_only ? "ro" : "rw";
        if (index != 0U && (effects_buffer_write(&typed, ",", 1U) != 0
            || effects_buffer_write(&plain, ",", 1U) != 0)) goto done;
        if (format_alloc(&row, &row_size,
                "{\"$type\":\"GuestMount\",\"fields\":{\"destination\":\"%s\",\"mode\":\"%s\",\"purpose\":\"%s\",\"source_handle\":\"%s\"}}",
                targets[index], mode, purposes[index], handles[index]) != 0
            || effects_buffer_write(&typed, row, row_size) != 0) goto done;
        plamen_broker_v2_secure_zero(row, row_size); free(row); row = NULL;
        if (format_alloc(&row, &row_size,
                "{\"destination\":\"%s\",\"mode\":\"%s\",\"purpose\":\"%s\",\"source_handle\":\"%s\"}",
                targets[index], mode, purposes[index], handles[index]) != 0
            || effects_buffer_write(&plain, row, row_size) != 0) goto done;
        plamen_broker_v2_secure_zero(row, row_size); free(row); row = NULL;
    }
    if (effects_buffer_write(&typed, "]}", 2U) != 0
        || effects_buffer_write(&plain, "]\n", 2U) != 0
        || plamen_broker_v2_sha256(plain.data, plain.size, commitment) != 0)
        goto done;
    *wire = typed.data; *wire_size = typed.size; typed.data = NULL;
    *semantic = plain.data; *semantic_size = plain.size;
    plain.data = NULL; result = 0;
done:
    if (row != NULL) { plamen_broker_v2_secure_zero(row, row_size); free(row); }
    effects_buffer_destroy(&typed); effects_buffer_destroy(&plain);
    plamen_broker_v2_secure_zero(handles, sizeof(handles));
    plamen_broker_v2_secure_zero(seccomp, sizeof(seccomp));
    return result;
}

static int
provider_create_stopped(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_apple_lifecycle_spec spec;
    struct plamen_broker_v2_workspace_mount_view views[10];
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    struct plamen_broker_v2_apple_lifecycle_create_receipt receipt;
    const uint8_t *pre_wire = NULL; size_t pre_wire_size = 0;
    uint8_t pre_commitment[32], guest_spec_commitment[32];
    uint8_t mount_commitment[32], provider_mounts[32];
    uint8_t *pre_semantic = NULL, *mount_wire = NULL, *mount_semantic = NULL;
    uint8_t *spec_wire = NULL, *spec_semantic = NULL, *wire = NULL;
    uint8_t *semantic = NULL;
    size_t pre_semantic_size = 0, mount_wire_size = 0, mount_semantic_size = 0;
    size_t spec_wire_size = 0, spec_semantic_size = 0, wire_size = 0;
    size_t semantic_size = 0;
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    char image_closure[65], provider[65], backend[65], credential[65], egress[65];
    char egress_admission[65], config[65], mount_hex[65], provider_mount_hex[65];
    struct plamen_broker_v2_operations_effect_result pre_capture, post_capture;
    int stdin_fd = -1, status = -1, lifecycle_status, mutation_started = 0;
    memset(&receipt, 0, sizeof(receipt));
    memset(&pre_capture, 0, sizeof(pre_capture));
    memset(&post_capture, 0, sizeof(post_capture));
    if (request->argument_count != 2 || request->arguments[1].is_receipt != 1
        || plamen_broker_v2_workspace_effects_capture_recensus(
            context->workspace, "PRE_CREATE", request->operation_key,
            &pre_capture) != 0
        || plamen_broker_v2_workspace_effects_borrow_recensus(
            context->workspace, "PRE_CREATE", &pre_wire, &pre_wire_size,
            pre_commitment) != 0
        || recensus_semantic(pre_wire, pre_wire_size, &pre_semantic,
            &pre_semantic_size) != 0)
        goto done;
    /* PRE_CREATE is authenticated separately; the complete spec comparison is
     * performed after the exact nested semantic value is assembled. */
    lifecycle_status = build_provider_spec(context, request->operation_key,
        &spec, views, &commitments, container_id, &stdin_fd);
    if (lifecycle_status != 0
        || provider_mount_payloads(context, views, &mount_wire,
            &mount_wire_size, &mount_semantic, &mount_semantic_size,
            mount_commitment) != 0) goto done;
    encode_hex32(context->commitment.image_closure_sha256, image_closure);
    encode_hex32(context->commitment.provider_provenance_sha256, provider);
    encode_hex32(context->commitment.backend_admission_sha256, backend);
    encode_hex32(context->commitment.credential_isolation_sha256, credential);
    encode_hex32(context->commitment.egress_admission_sha256, egress_admission);
    encode_hex32(context->commitment.config_sha256, config);
    encode_hex32(mount_commitment, mount_hex);
    memcpy(egress, context->egress_policy_sha256, 65);
    if (format_alloc(&spec_wire, &spec_wire_size,
            "{\"$type\":\"GuestCreateSpec\",\"fields\":{\"attempt_id\":\"%s\",\"backend_admission_sha256\":\"%s\",\"config_sha256\":\"%s\",\"create_stopped\":true,\"credential_isolation_sha256\":\"%s\",\"egress_admission_sha256\":\"%s\",\"egress_policy_sha256\":\"%s\",\"gid\":1000,\"guest_name\":\"%s\",\"image_closure_sha256\":\"%s\",\"image_handle\":\"%s\",\"image_manifest_digest\":\"%s\",\"inherited_environment\":{\"$tuple\":[]},\"initial_process_count\":0,\"mounts\":%.*s,\"network_mode\":\"NONE\",\"platform_architecture\":\"amd64\",\"platform_os\":\"linux\",\"precreate_recensus\":%.*s,\"provider_provenance_sha256\":\"%s\",\"rootfs_readonly\":true,\"uid\":1000}}",
            context->commitment.attempt_id, backend, config, credential,
            egress_admission, egress, container_id, image_closure,
            context->image_handle, context->image_manifest_digest,
            (int)mount_wire_size, mount_wire, (int)pre_wire_size, pre_wire,
            provider) != 0
        || format_alloc(&spec_semantic, &spec_semantic_size,
            "{\"attempt_id\":\"%s\",\"backend_admission_sha256\":\"%s\",\"config_sha256\":\"%s\",\"create_stopped\":true,\"credential_isolation_sha256\":\"%s\",\"egress_admission_sha256\":\"%s\",\"egress_policy_sha256\":\"%s\",\"gid\":1000,\"guest_name\":\"%s\",\"image_closure_sha256\":\"%s\",\"image_handle\":\"%s\",\"image_manifest_digest\":\"%s\",\"inherited_environment\":[],\"initial_process_count\":0,\"mounts\":%.*s,\"network_mode\":\"NONE\",\"platform_architecture\":\"amd64\",\"platform_os\":\"linux\",\"precreate_recensus\":%.*s,\"provider_provenance_sha256\":\"%s\",\"rootfs_readonly\":true,\"uid\":1000}\n",
            context->commitment.attempt_id, backend, config, credential,
            egress_admission, egress, container_id, image_closure,
            context->image_handle, context->image_manifest_digest,
            (int)(mount_semantic_size - 1U), mount_semantic,
            (int)(pre_semantic_size - 1U), pre_semantic, provider) != 0
        || plamen_broker_v2_sha256(spec_semantic, spec_semantic_size,
            guest_spec_commitment) != 0
        || !constant_equal(guest_spec_commitment,
            request->arguments[0].commitment_sha256, 32)
        || retain_provider_binding(context, request->operation_key,
            container_id, commitments.spec_sha256,
            guest_spec_commitment) != 0) goto done;
    lifecycle_status = plamen_broker_v2_apple_lifecycle_reopen_created(&spec,
        context->custody_client, context->authority_binding, &receipt,
        &context->provider_lifecycle);
    if (lifecycle_status == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED) {
        mutation_started = 1;
        lifecycle_status = plamen_broker_v2_apple_lifecycle_create(&spec,
            &receipt, &context->provider_lifecycle);
        if (lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
            || plamen_broker_v2_apple_lifecycle_bind_process_custody(
                context->provider_lifecycle, context->custody_client,
                context->authority_binding) != 0) goto done;
    } else if (lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) {
        mutation_started = 1;
        goto done;
    }
    mutation_started = 1;
    if (plamen_broker_v2_workspace_effects_capture_recensus(
            context->workspace, "POST_CREATE", request->operation_key,
            &post_capture) != 0
        || plamen_broker_v2_workspace_effects_provider_mounts_sha256(
            context->workspace, "POST_CREATE", provider_mounts) != 0)
        goto done;
    encode_hex32(provider_mounts, provider_mount_hex);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"GuestCreatedReceipt\",\"fields\":{\"attempt_id\":\"%s\",\"create_spec\":%.*s,\"guest_id\":\"%s\",\"mount_roster_sha256\":\"%s\",\"provider_kind\":{\"$enum\":\"ProviderKind\",\"value\":\"APPLE_CONTAINER\"},\"provider_mounts_sha256\":\"%s\",\"state\":\"CREATED_STOPPED\",\"workload_started\":false}}",
            context->commitment.attempt_id, (int)spec_wire_size, spec_wire,
            container_id, mount_hex, provider_mount_hex) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"attempt_id\":\"%s\",\"create_spec\":%.*s,\"guest_id\":\"%s\",\"mount_roster_sha256\":\"%s\",\"provider_kind\":\"APPLE_CONTAINER\",\"provider_mounts_sha256\":\"%s\",\"state\":\"CREATED_STOPPED\",\"workload_started\":false}\n",
            context->commitment.attempt_id, (int)(spec_semantic_size - 1U),
            spec_semantic, container_id, mount_hex, provider_mount_hex) != 0)
        goto done;
    if (set_result(result, wire, wire_size, semantic, semantic_size, 1) != 0)
        goto done;
    wire = NULL;
    if (provider_evidence(context, PROVIDER_CREATED_EVIDENCE, 1U,
            result->result_commitment_sha256, provider_mounts, 1,
            NULL, NULL) != 0) {
        effects_dispose_result(context, result);
        goto done;
    }
    status = 0;
done:
    if (stdin_fd >= 0) (void)close(stdin_fd);
#define RELEASE(value, count) do { if ((value) != NULL) { \
    plamen_broker_v2_secure_zero((value), (count)); free(value); } } while (0)
    RELEASE(pre_semantic, pre_semantic_size); RELEASE(mount_wire, mount_wire_size);
    RELEASE(mount_semantic, mount_semantic_size); RELEASE(spec_wire, spec_wire_size);
    RELEASE(spec_semantic, spec_semantic_size); RELEASE(wire, wire_size);
    RELEASE(semantic, semantic_size);
#undef RELEASE
    plamen_broker_v2_workspace_effects_dispose_result(&pre_capture);
    plamen_broker_v2_workspace_effects_dispose_result(&post_capture);
    plamen_broker_v2_secure_zero(provider_mounts, sizeof(provider_mounts));
    return status == 0 ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK
        : mutation_started ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS
        : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
}

static int
provider_reopen_created(struct plamen_broker_v2_effects_context *context,
    struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_workspace_mount_view views[10],
    struct plamen_broker_v2_apple_lifecycle_commitments *commitments,
    struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    int *stdin_fd)
{
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    int status;
    if (context == NULL || spec == NULL || views == NULL || commitments == NULL
        || created == NULL || stdin_fd == NULL
        || all_zero(context->provider_create_operation_key)
        || all_zero(context->provider_spec_sha256)
        || all_zero(context->provider_guest_spec_sha256)
        || context->provider_container_id[0] == '\0'
        || build_provider_spec(context, context->provider_create_operation_key,
            spec, views, commitments, container_id, stdin_fd) != 0
        || strcmp(container_id, context->provider_container_id) != 0
        || !constant_equal(commitments->spec_sha256,
            context->provider_spec_sha256, 32))
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    if (context->provider_lifecycle != NULL) {
        if (plamen_broker_v2_apple_lifecycle_detach(
                context->provider_lifecycle) != 0) {
            context->provider_lifecycle = NULL;
            return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
        }
        context->provider_lifecycle = NULL;
    }
    status = plamen_broker_v2_apple_lifecycle_reopen_created(spec,
        context->custody_client, context->authority_binding, created,
        &context->provider_lifecycle);
    plamen_broker_v2_secure_zero(container_id, sizeof(container_id));
    return status;
}

static int
provider_inspect_stopped(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_apple_lifecycle_spec spec;
    struct plamen_broker_v2_workspace_mount_view views[10];
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    struct plamen_broker_v2_apple_lifecycle_create_receipt created;
    uint8_t expected_created[32], provider_mounts[32];
    char native_spec[65], mount_roster[65], provider_mount_hex[65];
    uint8_t *wire = NULL, *semantic = NULL;
    size_t wire_size = 0, semantic_size = 0;
    int stdin_fd = -1, status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    memset(&spec, 0, sizeof(spec)); memset(views, 0, sizeof(views));
    memset(&commitments, 0, sizeof(commitments));
    memset(&created, 0, sizeof(created));
    if (request->argument_count != 1 || !request->arguments[0].is_receipt
        || provider_evidence(context, PROVIDER_CREATED_EVIDENCE, 1U,
            NULL, NULL, 0, expected_created, provider_mounts) != 0
        || !constant_equal(expected_created,
            request->arguments[0].commitment_sha256, 32)
        || provider_reopen_created(context, &spec, views, &commitments,
            &created, &stdin_fd) != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
        || plamen_broker_v2_workspace_effects_provider_mounts_sha256(
            context->workspace, "POST_CREATE", provider_mounts) != 0)
        goto done;
    encode_hex32(context->provider_guest_spec_sha256, native_spec);
    encode_hex32(commitments.mount_roster_sha256, mount_roster);
    encode_hex32(provider_mounts, provider_mount_hex);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"GuestObservation\",\"fields\":{\"guest_id\":\"%s\",\"mount_roster_sha256\":\"%s\",\"provider_kind\":{\"$enum\":\"ProviderKind\",\"value\":\"APPLE_CONTAINER\"},\"provider_mounts_sha256\":\"%s\",\"spec_sha256\":\"%s\",\"state\":\"CREATED_STOPPED\",\"workload_process_count\":0}}",
            context->provider_container_id, mount_roster,
            provider_mount_hex, native_spec) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"guest_id\":\"%s\",\"mount_roster_sha256\":\"%s\",\"provider_kind\":\"APPLE_CONTAINER\",\"provider_mounts_sha256\":\"%s\",\"spec_sha256\":\"%s\",\"state\":\"CREATED_STOPPED\",\"workload_process_count\":0}\n",
            context->provider_container_id, mount_roster,
            provider_mount_hex, native_spec) != 0
        || set_result(result, wire, wire_size, semantic, semantic_size, 0) != 0)
        goto done;
    wire = NULL; status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
done:
    if (stdin_fd >= 0) (void)close(stdin_fd);
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size); free(semantic);
    }
    plamen_broker_v2_secure_zero(expected_created, sizeof(expected_created));
    plamen_broker_v2_secure_zero(provider_mounts, sizeof(provider_mounts));
    return status;
}

static int
provider_launch_commitment(struct plamen_broker_v2_effects_context *context,
    const uint8_t admission_sha256[32], uint8_t commitment[32])
{
    char admission[65]; uint8_t *semantic = NULL; size_t semantic_size = 0;
    int result = -1;
    if (context == NULL || admission_sha256 == NULL || commitment == NULL
        || all_zero(admission_sha256)) return -1;
    encode_hex32(admission_sha256, admission);
    if (format_alloc(&semantic, &semantic_size,
            "{\"admission_sha256\":\"%s\",\"argv\":[\"/usr/bin/python3\",\"-B\",\"/opt/plamen/scripts/plamen_driver.py\",\"/workspace/control/config.json\",\"--startup-intent\",\"start-new-run\",\"--unattended\",\"--no-sleep\",\"--startup-decision-receipt\",\"/workspace/control/startup-decision.json\"],\"attempt_id\":\"%s\",\"cwd\":\"/workspace/project\",\"environment\":[],\"guest_id\":\"%s\",\"stdin\":\"DEVNULL\"}\n",
            admission, context->commitment.attempt_id,
            context->provider_container_id) != 0
        || plamen_broker_v2_sha256(semantic, semantic_size, commitment) != 0)
        goto done;
    result = 0;
done:
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size); free(semantic);
    }
    plamen_broker_v2_secure_zero(admission, sizeof(admission));
    return result;
}

static int
provider_start_driver(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_apple_lifecycle_spec spec;
    struct plamen_broker_v2_workspace_mount_view views[10];
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    struct plamen_broker_v2_apple_lifecycle_create_receipt created;
    struct plamen_broker_v2_apple_lifecycle_start_receipt started;
    uint8_t created_commitment[32], provider_mounts[32];
    uint8_t admission_commitment[32], admission_sha[32], launch_sha[32];
    char launch_hex[65], process_id[64];
    uint8_t *wire = NULL, *semantic = NULL;
    size_t wire_size = 0, semantic_size = 0;
    int stdin_fd = -1, lifecycle_status, mutation_started = 0;
    int status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    memset(&spec, 0, sizeof(spec)); memset(views, 0, sizeof(views));
    memset(&commitments, 0, sizeof(commitments));
    memset(&created, 0, sizeof(created)); memset(&started, 0, sizeof(started));
    if (request->argument_count != 4 || !request->arguments[0].is_receipt
        || !request->arguments[1].is_receipt
        || !request->arguments[3].is_receipt
        || provider_evidence(context, PROVIDER_CREATED_EVIDENCE, 1U,
            NULL, NULL, 0, created_commitment, provider_mounts) != 0
        || !constant_equal(created_commitment,
            request->arguments[0].commitment_sha256, 32)
        || provider_evidence(context, PROVIDER_ADMISSION_EVIDENCE, 2U,
            NULL, NULL, 0, admission_commitment, admission_sha) != 0
        || !constant_equal(admission_commitment,
            request->arguments[1].commitment_sha256, 32)
        || provider_launch_commitment(context, admission_sha, launch_sha) != 0
        || !constant_equal(launch_sha,
            request->arguments[2].commitment_sha256, 32)
        || build_provider_spec(context, context->provider_create_operation_key,
            &spec, views, &commitments, context->provider_container_id,
            &stdin_fd) != 0
        || !constant_equal(commitments.spec_sha256,
            context->provider_spec_sha256, 32)) goto done;
    if (context->provider_lifecycle != NULL) {
        if (plamen_broker_v2_apple_lifecycle_detach(
                context->provider_lifecycle) != 0) {
            context->provider_lifecycle = NULL; mutation_started = 1;
            goto done;
        }
        context->provider_lifecycle = NULL;
    }
    lifecycle_status = plamen_broker_v2_apple_lifecycle_reopen_started(&spec,
        context->custody_client, context->authority_binding, &created,
        &started, &context->provider_lifecycle);
    if (lifecycle_status == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED) {
        lifecycle_status = plamen_broker_v2_apple_lifecycle_reopen_created(&spec,
            context->custody_client, context->authority_binding, &created,
            &context->provider_lifecycle);
        if (lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) {
            mutation_started = lifecycle_status
                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
            goto done;
        }
        mutation_started = 1;
        lifecycle_status = plamen_broker_v2_apple_lifecycle_start(
            context->provider_lifecycle, &started);
    } else mutation_started = 1;
    if (lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
        || started.native_process_id <= 0
        || snprintf(process_id, sizeof(process_id), "native-%d",
            started.native_process_id) <= 0) goto done;
    encode_hex32(launch_sha, launch_hex);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"DriverStartReceipt\",\"fields\":{\"attempt_id\":\"%s\",\"driver_process_count\":1,\"driver_process_id\":\"%s\",\"guest_id\":\"%s\",\"launch_sha256\":\"%s\"}}",
            context->commitment.attempt_id, process_id,
            context->provider_container_id, launch_hex) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"attempt_id\":\"%s\",\"driver_process_count\":1,\"driver_process_id\":\"%s\",\"guest_id\":\"%s\",\"launch_sha256\":\"%s\"}\n",
            context->commitment.attempt_id, process_id,
            context->provider_container_id, launch_hex) != 0
        || set_result(result, wire, wire_size, semantic, semantic_size, 1) != 0)
        goto done;
    wire = NULL;
    if (provider_evidence(context, PROVIDER_START_EVIDENCE, 3U,
            result->result_commitment_sha256, launch_sha, 1,
            NULL, NULL) != 0) {
        effects_dispose_result(context, result); goto done;
    }
    status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
done:
    if (stdin_fd >= 0) (void)close(stdin_fd);
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size); free(semantic);
    }
    return status == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK ? status
        : mutation_started ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS
        : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
}

static int
provider_wait_driver(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_apple_lifecycle_spec spec;
    struct plamen_broker_v2_workspace_mount_view views[10];
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    struct plamen_broker_v2_apple_lifecycle_create_receipt created;
    struct plamen_broker_v2_apple_lifecycle_start_receipt started;
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt terminal;
    uint8_t created_commitment[32], provider_mounts[32];
    uint8_t start_commitment[32], launch_sha[32];
    char launch_hex[65], wait_hex[65];
    uint8_t *wire = NULL, *semantic = NULL;
    size_t wire_size = 0, semantic_size = 0;
    int stdin_fd = -1, lifecycle_status, mutation_started = 0;
    int status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    memset(&spec, 0, sizeof(spec)); memset(views, 0, sizeof(views));
    memset(&commitments, 0, sizeof(commitments));
    memset(&created, 0, sizeof(created)); memset(&started, 0, sizeof(started));
    memset(&terminal, 0, sizeof(terminal));
    if (request->argument_count != 3 || !request->arguments[0].is_receipt
        || !request->arguments[1].is_receipt || !request->arguments[2].is_receipt
        || provider_evidence(context, PROVIDER_CREATED_EVIDENCE, 1U,
            NULL, NULL, 0, created_commitment, provider_mounts) != 0
        || !constant_equal(created_commitment,
            request->arguments[0].commitment_sha256, 32)
        || provider_evidence(context, PROVIDER_START_EVIDENCE, 3U,
            NULL, NULL, 0, start_commitment, launch_sha) != 0
        || !constant_equal(start_commitment,
            request->arguments[1].commitment_sha256, 32)
        || build_provider_spec(context, context->provider_create_operation_key,
            &spec, views, &commitments, context->provider_container_id,
            &stdin_fd) != 0
        || !constant_equal(commitments.spec_sha256,
            context->provider_spec_sha256, 32)) goto done;
    if (context->provider_lifecycle != NULL) {
        if (plamen_broker_v2_apple_lifecycle_detach(
                context->provider_lifecycle) != 0) {
            context->provider_lifecycle = NULL; mutation_started = 1;
            goto done;
        }
        context->provider_lifecycle = NULL;
    }
    lifecycle_status = plamen_broker_v2_apple_lifecycle_reopen_terminal(&spec,
        context->custody_client, context->authority_binding, &created,
        &started, &terminal, &context->provider_lifecycle);
    if (lifecycle_status == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED) {
        lifecycle_status = plamen_broker_v2_apple_lifecycle_reopen_started(&spec,
            context->custody_client, context->authority_binding, &created,
            &started, &context->provider_lifecycle);
        if (lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) {
            mutation_started = lifecycle_status
                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
            goto done;
        }
        mutation_started = 1;
        lifecycle_status = plamen_broker_v2_apple_lifecycle_wait(
            context->provider_lifecycle, &terminal);
    } else mutation_started = 1;
    if (lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
        || terminal.exit_code < 0 || terminal.exit_code > 255) goto done;
    encode_hex32(launch_sha, launch_hex);
    encode_hex32(terminal.receipt_sha256, wait_hex);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"DriverExitReceipt\",\"fields\":{\"attempt_id\":\"%s\",\"exit_code\":%d,\"guest_id\":\"%s\",\"launch_sha256\":\"%s\",\"wait_sha256\":\"%s\"}}",
            context->commitment.attempt_id, terminal.exit_code,
            context->provider_container_id, launch_hex, wait_hex) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"attempt_id\":\"%s\",\"exit_code\":%d,\"guest_id\":\"%s\",\"launch_sha256\":\"%s\",\"wait_sha256\":\"%s\"}\n",
            context->commitment.attempt_id, terminal.exit_code,
            context->provider_container_id, launch_hex, wait_hex) != 0
        || set_result(result, wire, wire_size, semantic, semantic_size, 1) != 0)
        goto done;
    wire = NULL;
    if (provider_evidence(context, PROVIDER_EXIT_EVIDENCE, 4U,
            result->result_commitment_sha256, terminal.receipt_sha256, 1,
            NULL, NULL) != 0) {
        effects_dispose_result(context, result); goto done;
    }
    status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
done:
    if (stdin_fd >= 0) (void)close(stdin_fd);
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size); free(semantic);
    }
    plamen_broker_v2_apple_lifecycle_terminal_dispose(&terminal);
    return status == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK ? status
        : mutation_started ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS
        : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
}

static int
provider_extinguish(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_apple_lifecycle_spec spec;
    struct plamen_broker_v2_workspace_mount_view views[10];
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    struct plamen_broker_v2_apple_lifecycle_create_receipt created;
    struct plamen_broker_v2_apple_lifecycle_start_receipt started;
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt terminal;
    uint8_t created_commitment[32], provider_mounts[32];
    uint8_t exit_commitment[32], terminal_sha[32];
    char terminal_hex[65]; uint8_t *wire = NULL, *semantic = NULL;
    size_t wire_size = 0, semantic_size = 0;
    int stdin_fd = -1, lifecycle_status, mutation_started = 0;
    int status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    memset(&spec, 0, sizeof(spec)); memset(views, 0, sizeof(views));
    memset(&commitments, 0, sizeof(commitments));
    memset(&created, 0, sizeof(created)); memset(&started, 0, sizeof(started));
    memset(&terminal, 0, sizeof(terminal));
    if (request->argument_count != 4 || !request->arguments[1].is_receipt
        || !request->arguments[2].is_receipt || !request->arguments[3].is_receipt
        || provider_evidence(context, PROVIDER_CREATED_EVIDENCE, 1U,
            NULL, NULL, 0, created_commitment, provider_mounts) != 0
        || !constant_equal(created_commitment,
            request->arguments[1].commitment_sha256, 32)
        || provider_evidence(context, PROVIDER_EXIT_EVIDENCE, 4U,
            NULL, NULL, 0, exit_commitment, terminal_sha) != 0
        || !constant_equal(exit_commitment,
            request->arguments[2].commitment_sha256, 32)
        || build_provider_spec(context, context->provider_create_operation_key,
            &spec, views, &commitments, context->provider_container_id,
            &stdin_fd) != 0
        || !constant_equal(commitments.spec_sha256,
            context->provider_spec_sha256, 32)) goto done;
    if (context->provider_lifecycle != NULL) {
        if (plamen_broker_v2_apple_lifecycle_detach(
                context->provider_lifecycle) != 0) {
            context->provider_lifecycle = NULL; mutation_started = 1;
            goto done;
        }
        context->provider_lifecycle = NULL;
    }
    mutation_started = 1;
    lifecycle_status = plamen_broker_v2_apple_lifecycle_reopen_terminal(&spec,
        context->custody_client, context->authority_binding, &created,
        &started, &terminal, &context->provider_lifecycle);
    if (lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
        || !constant_equal(terminal.receipt_sha256, terminal_sha, 32)
        || terminal.terminal_durable != 1 || terminal.descendants_extinct != 1
        || terminal.guest_process_extinct != 1
        || terminal.backend_egress_revoked != 1) goto done;
    encode_hex32(terminal.receipt_sha256, terminal_hex);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"ExtinctionReceipt\",\"fields\":{\"attempt_id\":\"%s\",\"cgroup_populated\":0,\"exact_attempt\":true,\"guest_id\":\"%s\",\"process_count\":0,\"terminal_sha256\":\"%s\"}}",
            context->commitment.attempt_id, context->provider_container_id,
            terminal_hex) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"attempt_id\":\"%s\",\"cgroup_populated\":0,\"exact_attempt\":true,\"guest_id\":\"%s\",\"process_count\":0,\"terminal_sha256\":\"%s\"}\n",
            context->commitment.attempt_id, context->provider_container_id,
            terminal_hex) != 0
        || set_result(result, wire, wire_size, semantic, semantic_size, 1) != 0)
        goto done;
    wire = NULL;
    if (provider_evidence(context, PROVIDER_EXTINCTION_EVIDENCE, 5U,
            result->result_commitment_sha256, terminal.receipt_sha256, 1,
            NULL, NULL) != 0) {
        effects_dispose_result(context, result); goto done;
    }
    status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
done:
    if (stdin_fd >= 0) (void)close(stdin_fd);
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size); free(semantic);
    }
    plamen_broker_v2_apple_lifecycle_terminal_dispose(&terminal);
    return status == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK ? status
        : mutation_started ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS
        : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
}

static int
artifact_projection_roster_exact(
    const struct plamen_broker_v2_effects_context *context)
{
    static const char allowlist[] =
        "\"export_allowlist\":[\"project/AUDIT_REPORT.md\","
        "\"scratch/_plamen.log\",\"scratch/_v2_checkpoint.json\"]";
    static const char required[] =
        "\"required_artifacts\":[\"project/AUDIT_REPORT.md\","
        "\"scratch/_v2_checkpoint.json\"]";
    static const char failure[] =
        "\"failure_required_artifacts\":[\"scratch/_plamen.log\"]";
    static const char ceiling[] =
        "\"export_max_total_bytes\":2147483648";
    const char *fragments[] = { allowlist, required, failure, ceiling };
    size_t index;
    if (context == NULL || context->projection == NULL) return 0;
    for (index = 0; index < sizeof(fragments) / sizeof(fragments[0]); ++index) {
        size_t length = strlen(fragments[index]);
        const uint8_t *first = bounded_find(context->projection,
            context->projection_size, 0U, fragments[index], length);
        if (first == NULL || bounded_find(context->projection,
                context->projection_size,
                (size_t)(first - context->projection) + length,
                fragments[index], length) != NULL)
            return 0;
    }
    return 1;
}

static int
artifact_reopen_terminal(
    struct plamen_broker_v2_effects_context *context,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *terminal)
{
    struct plamen_broker_v2_apple_lifecycle_spec spec;
    struct plamen_broker_v2_workspace_mount_view views[10];
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    struct plamen_broker_v2_apple_lifecycle_create_receipt created;
    struct plamen_broker_v2_apple_lifecycle_start_receipt started;
    int stdin_fd = -1, status = -1;
    memset(&spec, 0, sizeof(spec)); memset(views, 0, sizeof(views));
    memset(&commitments, 0, sizeof(commitments));
    memset(&created, 0, sizeof(created)); memset(&started, 0, sizeof(started));
    memset(terminal, 0, sizeof(*terminal));
    if (build_provider_spec(context, context->provider_create_operation_key,
            &spec, views, &commitments, context->provider_container_id,
            &stdin_fd) != 0
        || !constant_equal(commitments.spec_sha256,
            context->provider_spec_sha256, 32)) goto done;
    if (context->provider_lifecycle != NULL) {
        if (plamen_broker_v2_apple_lifecycle_detach(
                context->provider_lifecycle) != 0) {
            context->provider_lifecycle = NULL; goto done;
        }
        context->provider_lifecycle = NULL;
    }
    if (plamen_broker_v2_apple_lifecycle_reopen_terminal(&spec,
            context->custody_client, context->authority_binding, &created,
            &started, terminal, &context->provider_lifecycle)
            != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK)
        goto done;
    status = 0;
done:
    if (stdin_fd >= 0) (void)close(stdin_fd);
    return status;
}

static int
artifact_session_prepare(
    struct plamen_broker_v2_effects_context *context,
    const uint8_t terminal_sha256[32], uint8_t driver_exit_code,
    struct plamen_broker_v2_artifact_session *session,
    struct plamen_broker_v2_artifact_spec specs[3],
    char census_handle[72], char destination_handle[72],
    uint8_t destination_identity[32], uint8_t source_content[32])
{
    const uint8_t *recensus = NULL;
    size_t recensus_size = 0;
    uint8_t recensus_commitment[32];
    char source_hex[65];
    int scratch_fd, target_fd;
    if (!artifact_projection_roster_exact(context)
        || decode_hex32(context->export_identity_sha256,
            destination_identity) != 0
        || plamen_broker_v2_workspace_effects_borrow_recensus(
            context->workspace, "PRE_CREATE", &recensus, &recensus_size,
            recensus_commitment) != 0
        || extract_projection_string(recensus, recensus_size,
            "target_content_sha256", source_hex, sizeof(source_hex)) != 0
        || decode_hex32(source_hex, source_content) != 0
        || make_handle(context, "PLAMEN-ARTIFACT-CENSUS-V1",
            terminal_sha256, census_handle) != 0
        || make_handle(context, "PLAMEN-WORKSPACE-EXPORT",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_EXPORT].identity,
            destination_handle) != 0)
        return -1;
    scratch_fd = plamen_broker_v2_workspace_effects_borrow_fd(
        context->workspace, PLAMEN_BROKER_V2_WORKSPACE_SCRATCH);
    target_fd = plamen_broker_v2_workspace_effects_borrow_fd(
        context->workspace, PLAMEN_BROKER_V2_WORKSPACE_TARGET);
    if (scratch_fd < 0 || target_fd < 0) return -1;
    memset(specs, 0, sizeof(*specs) * 3U);
    specs[0].parent_fd = scratch_fd;
    specs[0].physical_path = "AUDIT_REPORT.md";
    specs[0].logical_path = "project/AUDIT_REPORT.md";
    specs[0].required_on_success = 1U;
    specs[1].parent_fd = scratch_fd;
    specs[1].physical_path = "_plamen.log";
    specs[1].logical_path = "scratch/_plamen.log";
    specs[1].required_on_failure = 1U;
    specs[2].parent_fd = scratch_fd;
    specs[2].physical_path = "_v2_checkpoint.json";
    specs[2].logical_path = "scratch/_v2_checkpoint.json";
    specs[2].required_on_success = 1U;
    memset(session, 0, sizeof(*session));
    session->version = PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION;
    session->scratch_fd = scratch_fd; session->target_fd = target_fd;
    session->attempt_id = context->commitment.attempt_id;
    session->run_id = context->commitment.run_identity;
    session->census_handle = census_handle;
    session->destination_handle = destination_handle;
    session->terminal_sha256 = terminal_sha256;
    session->destination_identity_sha256 = destination_identity;
    session->source_content_sha256 = source_content;
    session->artifacts = specs; session->artifact_count = 3U;
    session->export_max_total_bytes = UINT64_C(2147483648);
    session->driver_exit_code = driver_exit_code;
    session->terminal_authenticated = 1U;
    session->extinction_proven = 1U;
    session->driver_terminal_proven = 1U;
    return 0;
}

static int
artifact_render_census(
    struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct effects_buffer wire = { 0 }, semantic = { 0 };
    char census_hex[65], terminal_hex[65], digest[65];
    size_t index;
    int status = -1;
    encode_hex32(census->census_sha256, census_hex);
    encode_hex32(session->terminal_sha256, terminal_hex);
    if (effects_buffer_format(&wire,
            "{\"$type\":\"ArtifactCensus\",\"fields\":{\"attempt_id\":\"%s\",\"census_handle\":\"%s\",\"census_sha256\":\"%s\",\"dispositions\":[",
            session->attempt_id, session->census_handle, census_hex) != 0
        || effects_buffer_format(&semantic,
            "{\"attempt_id\":\"%s\",\"census_handle\":\"%s\",\"census_sha256\":\"%s\",\"dispositions\":[",
            session->attempt_id, session->census_handle, census_hex) != 0)
        goto done;
    for (index = 0; index < census->disposition_count; ++index) {
        encode_hex32(census->dispositions[index].entry_sha256, digest);
        if (effects_buffer_format(&wire,
                "%s{\"$type\":\"ArtifactDisposition\",\"fields\":{\"entry_sha256\":\"%s\",\"relative_path\":\"%s\",\"status\":\"PRESENT\"}}",
                index == 0U ? "" : ",", digest,
                census->dispositions[index].relative_path) != 0
            || effects_buffer_format(&semantic,
                "%s{\"entry_sha256\":\"%s\",\"relative_path\":\"%s\",\"status\":\"PRESENT\"}",
                index == 0U ? "" : ",", digest,
                census->dispositions[index].relative_path) != 0)
            goto done;
    }
    if (effects_buffer_format(&wire,
            "],\"driver_exit_code\":%u,\"entries\":[",
            (unsigned int)session->driver_exit_code) != 0
        || effects_buffer_format(&semantic,
            "],\"driver_exit_code\":%u,\"entries\":[",
            (unsigned int)session->driver_exit_code) != 0)
        goto done;
    for (index = 0; index < census->entry_count; ++index) {
        encode_hex32(census->entries[index].sha256, digest);
        if (effects_buffer_format(&wire,
                "%s{\"$type\":\"ArtifactEntry\",\"fields\":{\"hardlink_count\":1,\"object_kind\":\"regular\",\"relative_path\":\"%s\",\"sha256\":\"%s\",\"size\":%llu,\"symlink\":false}}",
                index == 0U ? "" : ",",
                census->entries[index].relative_path, digest,
                (unsigned long long)census->entries[index].size) != 0
            || effects_buffer_format(&semantic,
                "%s{\"hardlink_count\":1,\"object_kind\":\"regular\",\"relative_path\":\"%s\",\"sha256\":\"%s\",\"size\":%llu,\"symlink\":false}",
                index == 0U ? "" : ",",
                census->entries[index].relative_path, digest,
                (unsigned long long)census->entries[index].size) != 0)
            goto done;
    }
    if (effects_buffer_format(&wire,
            "],\"exact\":true,\"immutable_lease\":true,\"run_id\":\"%s\",\"terminal_sha256\":\"%s\"}}",
            session->run_id, terminal_hex) != 0
        || effects_buffer_format(&semantic,
            "],\"exact\":true,\"immutable_lease\":true,\"run_id\":\"%s\",\"terminal_sha256\":\"%s\"}\n",
            session->run_id, terminal_hex) != 0
        || set_result(result, wire.data, wire.size, semantic.data,
            semantic.size, 1) != 0
        || !constant_equal(result->result_commitment_sha256,
            census->census_sha256, 32))
        goto done;
    wire.data = NULL; wire.size = wire.capacity = 0U; status = 0;
done:
    effects_buffer_destroy(&wire); effects_buffer_destroy(&semantic);
    plamen_broker_v2_secure_zero(census_hex, sizeof(census_hex));
    plamen_broker_v2_secure_zero(terminal_hex, sizeof(terminal_hex));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    if (status != 0) effects_dispose_result(context, result);
    return status;
}

static int
provider_artifact_census(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt terminal;
    struct plamen_broker_v2_artifact_session session;
    struct plamen_broker_v2_artifact_spec specs[3];
    struct plamen_broker_v2_artifact_census census;
    uint8_t layout[32], exit_receipt[32], terminal_sha[32];
    uint8_t extinction[32], extinction_terminal[32];
    uint8_t destination[32], source_content[32];
    char census_handle[72], destination_handle[72];
    int status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    memset(&terminal, 0, sizeof(terminal)); memset(&session, 0, sizeof(session));
    memset(specs, 0, sizeof(specs)); memset(&census, 0, sizeof(census));
    if (request->argument_count != 5U || !request->arguments[1].is_receipt
        || !request->arguments[2].is_receipt || !request->arguments[3].is_receipt
        || !request->arguments[4].is_receipt
        || plamen_broker_v2_workspace_effects_layout_commitment(
            context->workspace, layout) != 0
        || !constant_equal(layout,
            request->arguments[1].commitment_sha256, 32)
        || provider_evidence(context, PROVIDER_EXIT_EVIDENCE, 4U,
            NULL, NULL, 0, exit_receipt, terminal_sha) != 0
        || !constant_equal(exit_receipt,
            request->arguments[2].commitment_sha256, 32)
        || provider_evidence(context, PROVIDER_EXTINCTION_EVIDENCE, 5U,
            NULL, NULL, 0, extinction, extinction_terminal) != 0
        || !constant_equal(extinction,
            request->arguments[3].commitment_sha256, 32)
        || !constant_equal(terminal_sha, extinction_terminal, 32)
        || artifact_reopen_terminal(context, &terminal) != 0
        || !constant_equal(terminal.receipt_sha256, terminal_sha, 32)
        || terminal.exit_code < 0 || terminal.exit_code > 255
        || terminal.terminal_durable != 1U
        || terminal.descendants_extinct != 1U
        || terminal.guest_process_extinct != 1U
        || terminal.backend_egress_revoked != 1U
        || artifact_session_prepare(context, terminal_sha,
            (uint8_t)terminal.exit_code, &session, specs, census_handle,
            destination_handle, destination, source_content) != 0
        || plamen_broker_v2_artifact_census_report(&session, &census)
            != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || artifact_render_census(context, &session, &census, result) != 0)
        goto done;
    if (provider_evidence(context, PROVIDER_CENSUS_EVIDENCE, 6U,
            result->result_commitment_sha256, census.census_sha256, 1,
            NULL, NULL) != 0) {
        effects_dispose_result(context, result); goto done;
    }
    status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
done:
    plamen_broker_v2_artifact_census_dispose(&census);
    plamen_broker_v2_apple_lifecycle_terminal_dispose(&terminal);
    plamen_broker_v2_secure_zero(&session, sizeof(session));
    plamen_broker_v2_secure_zero(specs, sizeof(specs));
    plamen_broker_v2_secure_zero(destination, sizeof(destination));
    plamen_broker_v2_secure_zero(source_content, sizeof(source_content));
    return status;
}

static int
provider_artifact_export(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt terminal;
    struct plamen_broker_v2_artifact_session session;
    struct plamen_broker_v2_artifact_spec specs[3];
    struct plamen_broker_v2_artifact_census census;
    struct plamen_broker_v2_artifact_publication publication;
    struct plamen_broker_v2_artifact_export_receipt exported;
    struct stat prepared_status;
    uint8_t layout[32], census_commitment[32], census_sha[32];
    uint8_t exit_receipt[32], terminal_sha[32];
    uint8_t extinction[32], extinction_terminal[32];
    uint8_t destination[32], source_content[32];
    uint8_t prepared_census[32], prepared_report[32];
    char census_handle[72], destination_handle[72];
    char census_hex[65], destination_hex[65], manifest_hex[65], export_hex[65];
    uint8_t *wire = NULL, *semantic = NULL;
    size_t wire_size = 0, semantic_size = 0;
    int target_fd = -1, target_present = 0, prepared_present = 0;
    int mutation_started = 0;
    int status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    memset(&terminal, 0, sizeof(terminal)); memset(&session, 0, sizeof(session));
    memset(specs, 0, sizeof(specs)); memset(&census, 0, sizeof(census));
    memset(&publication, 0, sizeof(publication));
    memset(&exported, 0, sizeof(exported));
    if (request->argument_count != 4U || !request->arguments[1].is_receipt
        || !request->arguments[2].is_receipt || !request->arguments[3].is_receipt
        || plamen_broker_v2_workspace_effects_layout_commitment(
            context->workspace, layout) != 0
        || !constant_equal(layout,
            request->arguments[1].commitment_sha256, 32)
        || provider_evidence(context, PROVIDER_CENSUS_EVIDENCE, 6U,
            NULL, NULL, 0, census_commitment, census_sha) != 0
        || !constant_equal(census_commitment,
            request->arguments[2].commitment_sha256, 32)
        || provider_evidence(context, PROVIDER_EXIT_EVIDENCE, 4U,
            NULL, NULL, 0, exit_receipt, terminal_sha) != 0
        || provider_evidence(context, PROVIDER_EXTINCTION_EVIDENCE, 5U,
            NULL, NULL, 0, extinction, extinction_terminal) != 0
        || !constant_equal(terminal_sha, extinction_terminal, 32)
        || artifact_reopen_terminal(context, &terminal) != 0
        || !constant_equal(terminal.receipt_sha256, terminal_sha, 32)
        || terminal.exit_code != 0 || terminal.terminal_durable != 1U
        || terminal.descendants_extinct != 1U
        || terminal.guest_process_extinct != 1U
        || terminal.backend_egress_revoked != 1U
        || artifact_session_prepare(context, terminal_sha, 0U, &session,
            specs, census_handle, destination_handle, destination,
            source_content) != 0
        || plamen_broker_v2_artifact_census_report(&session, &census)
            != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || !constant_equal(census.census_sha256, census_sha, 32))
        goto done;
    prepared_present = fstatat(context->state_directory_fd,
        PROVIDER_EXPORT_PREPARED_EVIDENCE, &prepared_status,
        AT_SYMLINK_NOFOLLOW) == 0;
    if (!prepared_present && errno != ENOENT) goto done;
    if (prepared_present) {
        if (!S_ISREG(prepared_status.st_mode)
            || provider_evidence(context, PROVIDER_EXPORT_PREPARED_EVIDENCE,
                70U, NULL, NULL, 0, prepared_census, prepared_report) != 0
            || !constant_equal(prepared_census, census.census_sha256, 32)
            || !constant_equal(prepared_report, census.report_sha256, 32))
            goto done;
    } else {
        target_fd = openat(session.target_fd,
            PLAMEN_BROKER_V2_ARTIFACT_TARGET_REPORT,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (target_fd >= 0 || errno != ENOENT) goto done;
        if (provider_evidence(context, PROVIDER_EXPORT_PREPARED_EVIDENCE,
                70U, census.census_sha256, census.report_sha256, 1,
                NULL, NULL) != 0)
            goto done;
        prepared_present = 1;
    }
    target_fd = openat(session.target_fd,
        PLAMEN_BROKER_V2_ARTIFACT_TARGET_REPORT,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (target_fd >= 0) {
        target_present = 1;
        if (close(target_fd) != 0) { target_fd = -1; goto done; }
        target_fd = -1;
    } else if (errno != ENOENT) goto done;
    mutation_started = 1;
    if (target_present) {
        if (!prepared_present
            || plamen_broker_v2_artifact_reopen_publication(
                &session, &census, &exported)
                != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE)
            goto done;
    } else {
        publication.version = PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION;
        if (plamen_broker_v2_artifact_publish_report(&session, &census,
                &publication, &exported)
                != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE)
            goto done;
    }
    encode_hex32(exported.census_sha256, census_hex);
    encode_hex32(destination, destination_hex);
    encode_hex32(exported.manifest_sha256, manifest_hex);
    encode_hex32(exported.export_sha256, export_hex);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"ExportReceipt\",\"fields\":{\"attempt_id\":\"%s\",\"census_sha256\":\"%s\",\"complete\":true,\"destination_handle\":\"%s\",\"destination_identity_sha256\":\"%s\",\"export_sha256\":\"%s\",\"exported_bytes\":%llu,\"exported_count\":%llu,\"manifest_sha256\":\"%s\",\"run_id\":\"%s\"}}",
            context->commitment.attempt_id, census_hex, destination_handle,
            destination_hex, export_hex,
            (unsigned long long)exported.exported_bytes,
            (unsigned long long)exported.exported_count, manifest_hex,
            context->commitment.run_identity) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"attempt_id\":\"%s\",\"census_sha256\":\"%s\",\"complete\":true,\"destination_handle\":\"%s\",\"destination_identity_sha256\":\"%s\",\"export_sha256\":\"%s\",\"exported_bytes\":%llu,\"exported_count\":%llu,\"manifest_sha256\":\"%s\",\"run_id\":\"%s\"}\n",
            context->commitment.attempt_id, census_hex, destination_handle,
            destination_hex, export_hex,
            (unsigned long long)exported.exported_bytes,
            (unsigned long long)exported.exported_count, manifest_hex,
            context->commitment.run_identity) != 0
        || set_result(result, wire, wire_size, semantic, semantic_size, 1) != 0)
        goto done;
    wire = NULL;
    if (provider_evidence(context, PROVIDER_EXPORT_EVIDENCE, 7U,
            result->result_commitment_sha256, exported.export_sha256, 1,
            NULL, NULL) != 0) {
        effects_dispose_result(context, result); goto done;
    }
    status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
done:
    if (target_fd >= 0) (void)close(target_fd);
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size); free(semantic);
    }
    plamen_broker_v2_artifact_census_dispose(&census);
    plamen_broker_v2_apple_lifecycle_terminal_dispose(&terminal);
    plamen_broker_v2_secure_zero(&session, sizeof(session));
    plamen_broker_v2_secure_zero(specs, sizeof(specs));
    plamen_broker_v2_secure_zero(&exported, sizeof(exported));
    plamen_broker_v2_secure_zero(destination, sizeof(destination));
    plamen_broker_v2_secure_zero(source_content, sizeof(source_content));
    return status == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK ? status
        : mutation_started ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS
        : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
}

static int
provider_admit_stopped(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_operations_effect_request inspect_request;
    struct plamen_broker_v2_operations_effect_result inspection;
    const uint8_t *pre_wire = NULL, *post_wire = NULL;
    size_t pre_wire_size = 0, post_wire_size = 0;
    uint8_t pre_commitment[32], post_commitment[32], allowed_delta[32];
    uint8_t *pre_semantic = NULL, *post_semantic = NULL;
    size_t pre_semantic_size = 0, post_semantic_size = 0;
    uint8_t admission_sha[32];
    char admission_hex[65], delta_hex[65], spec_hex[65], handle[72];
    char post_hex[65]; uint8_t *proof = NULL, *wire = NULL, *semantic = NULL;
    size_t proof_size = 0, wire_size = 0, semantic_size = 0;
    int mutation_started = 0;
    int status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    memset(&inspect_request, 0, sizeof(inspect_request));
    memset(&inspection, 0, sizeof(inspection));
    if (request->argument_count != 5 || !request->arguments[1].is_receipt
        || !request->arguments[2].is_receipt || !request->arguments[3].is_receipt
        || !request->arguments[4].is_receipt)
        goto done;
    inspect_request = *request;
    inspect_request.method = PLAMEN_BROKER_V2_METHOD_PROVIDER_INSPECT_STOPPED;
    inspect_request.arguments = &request->arguments[1];
    inspect_request.argument_count = 1;
    if (provider_inspect_stopped(context, &inspect_request, &inspection)
            != PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK
        || !constant_equal(inspection.result_commitment_sha256,
            request->arguments[2].commitment_sha256, 32)
        || plamen_broker_v2_workspace_effects_borrow_recensus(
            context->workspace, "PRE_CREATE", &pre_wire, &pre_wire_size,
            pre_commitment) != 0
        || plamen_broker_v2_workspace_effects_borrow_recensus(
            context->workspace, "POST_CREATE", &post_wire, &post_wire_size,
            post_commitment) != 0
        || !constant_equal(post_commitment,
            request->arguments[3].commitment_sha256, 32)
        || plamen_broker_v2_workspace_effects_allowed_delta_sha256(
            context->workspace, allowed_delta) != 0
        || recensus_semantic(pre_wire, pre_wire_size, &pre_semantic,
            &pre_semantic_size) != 0
        || recensus_semantic(post_wire, post_wire_size, &post_semantic,
            &post_semantic_size) != 0)
        goto done;
    encode_hex32(post_commitment, post_hex);
    encode_hex32(context->provider_guest_spec_sha256, spec_hex);
    encode_hex32(allowed_delta, delta_hex);
    if (format_alloc(&proof, &proof_size,
            "{\"allowed_delta_sha256\":\"%s\",\"guest_id\":\"%s\",\"postcreate_recensus_sha256\":\"%s\",\"spec_sha256\":\"%s\"}\n",
            delta_hex, context->provider_container_id, post_hex, spec_hex) != 0
        || plamen_broker_v2_sha256(proof, proof_size, admission_sha) != 0
        || make_handle(context, "PLAMEN-GUEST-ADMISSION-V1", admission_sha,
            handle) != 0)
        goto done;
    encode_hex32(admission_sha, admission_hex);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"GuestAdmissionReceipt\",\"fields\":{\"admission_handle\":\"%s\",\"admission_sha256\":\"%s\",\"allowed_delta_sha256\":\"%s\",\"attempt_id\":\"%s\",\"guest_id\":\"%s\",\"postcreate_recensus\":%.*s,\"precreate_recensus\":%.*s,\"replay_consumed\":true,\"spec_sha256\":\"%s\",\"workload_nonexecuting\":true}}",
            handle, admission_hex, delta_hex, context->commitment.attempt_id,
            context->provider_container_id, (int)post_wire_size, post_wire,
            (int)pre_wire_size, pre_wire, spec_hex) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"admission_handle\":\"%s\",\"admission_sha256\":\"%s\",\"allowed_delta_sha256\":\"%s\",\"attempt_id\":\"%s\",\"guest_id\":\"%s\",\"postcreate_recensus\":%.*s,\"precreate_recensus\":%.*s,\"replay_consumed\":true,\"spec_sha256\":\"%s\",\"workload_nonexecuting\":true}\n",
            handle, admission_hex, delta_hex, context->commitment.attempt_id,
            context->provider_container_id,
            (int)(post_semantic_size - 1U), post_semantic,
            (int)(pre_semantic_size - 1U), pre_semantic, spec_hex) != 0
        || set_result(result, wire, wire_size, semantic, semantic_size, 1) != 0)
        goto done;
    wire = NULL; mutation_started = 1;
    if (provider_evidence(context, PROVIDER_ADMISSION_EVIDENCE, 2U,
            result->result_commitment_sha256, admission_sha, 1,
            NULL, NULL) != 0) {
        effects_dispose_result(context, result); goto done;
    }
    status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
done:
    effects_dispose_result(context, &inspection);
    if (proof != NULL) {
        plamen_broker_v2_secure_zero(proof, proof_size); free(proof);
    }
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size); free(semantic);
    }
    if (pre_semantic != NULL) {
        plamen_broker_v2_secure_zero(pre_semantic, pre_semantic_size);
        free(pre_semantic);
    }
    if (post_semantic != NULL) {
        plamen_broker_v2_secure_zero(post_semantic, post_semantic_size);
        free(post_semantic);
    }
    return status == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK ? status
        : mutation_started ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS
        : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
}

static int
provider_delete_guest(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_apple_lifecycle_spec spec;
    struct plamen_broker_v2_workspace_mount_view views[10];
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    struct plamen_broker_v2_apple_lifecycle_create_receipt created;
    struct plamen_broker_v2_apple_lifecycle_start_receipt started;
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt terminal;
    struct plamen_broker_v2_apple_lifecycle_delete_receipt deleted;
    uint8_t created_commitment[32], provider_mounts[32];
    uint8_t extinction_commitment[32], terminal_sha[32];
    uint8_t export_commitment[32], export_sha[32];
    char terminal_hex[65]; uint8_t *wire = NULL, *semantic = NULL;
    size_t wire_size = 0, semantic_size = 0;
    int stdin_fd = -1, lifecycle_status, mutation_started = 0;
    int status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    memset(&spec, 0, sizeof(spec)); memset(views, 0, sizeof(views));
    memset(&commitments, 0, sizeof(commitments));
    memset(&created, 0, sizeof(created)); memset(&started, 0, sizeof(started));
    memset(&terminal, 0, sizeof(terminal)); memset(&deleted, 0, sizeof(deleted));
    if (request->argument_count != 3 || !request->arguments[0].is_receipt
        || !request->arguments[1].is_receipt || !request->arguments[2].is_receipt
        || provider_evidence(context, PROVIDER_CREATED_EVIDENCE, 1U,
            NULL, NULL, 0, created_commitment, provider_mounts) != 0
        || !constant_equal(created_commitment,
            request->arguments[0].commitment_sha256, 32)
        || provider_evidence(context, PROVIDER_EXTINCTION_EVIDENCE, 5U,
            NULL, NULL, 0, extinction_commitment, terminal_sha) != 0
        || !constant_equal(extinction_commitment,
            request->arguments[1].commitment_sha256, 32)
        || provider_evidence(context, PROVIDER_EXPORT_EVIDENCE, 7U,
            NULL, NULL, 0, export_commitment, export_sha) != 0
        || build_provider_spec(context, context->provider_create_operation_key,
            &spec, views, &commitments, context->provider_container_id,
            &stdin_fd) != 0
        || !constant_equal(commitments.spec_sha256,
            context->provider_spec_sha256, 32)) goto done;
    if (context->provider_lifecycle != NULL) {
        if (plamen_broker_v2_apple_lifecycle_detach(
                context->provider_lifecycle) != 0) {
            context->provider_lifecycle = NULL; mutation_started = 1;
            goto done;
        }
        context->provider_lifecycle = NULL;
    }
    lifecycle_status = plamen_broker_v2_apple_lifecycle_reopen_deleted(&spec,
        context->custody_client, context->authority_binding, &created,
        &started, &terminal, &deleted, &context->provider_lifecycle);
    if (lifecycle_status == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED) {
        lifecycle_status = plamen_broker_v2_apple_lifecycle_reopen_terminal(
            &spec, context->custody_client, context->authority_binding,
            &created, &started, &terminal, &context->provider_lifecycle);
        if (lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
            || !constant_equal(terminal.receipt_sha256, terminal_sha, 32)) {
            mutation_started = lifecycle_status
                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
            goto done;
        }
        mutation_started = 1;
        lifecycle_status = plamen_broker_v2_apple_lifecycle_delete(
            context->provider_lifecycle, &terminal, &deleted);
    } else mutation_started = 1;
    if (lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
        || !constant_equal(deleted.terminal_receipt_sha256, terminal_sha, 32)
        || deleted.absent != 1) goto done;
    encode_hex32(terminal_sha, terminal_hex);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"DeleteReceipt\",\"fields\":{\"absent\":true,\"attempt_id\":\"%s\",\"guest_id\":\"%s\",\"provider_kind\":{\"$enum\":\"ProviderKind\",\"value\":\"APPLE_CONTAINER\"},\"terminal_sha256\":\"%s\"}}",
            context->commitment.attempt_id, context->provider_container_id,
            terminal_hex) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"absent\":true,\"attempt_id\":\"%s\",\"guest_id\":\"%s\",\"provider_kind\":\"APPLE_CONTAINER\",\"terminal_sha256\":\"%s\"}\n",
            context->commitment.attempt_id, context->provider_container_id,
            terminal_hex) != 0
        || set_result(result, wire, wire_size, semantic, semantic_size, 1) != 0)
        goto done;
    wire = NULL;
    if (provider_evidence(context, PROVIDER_DELETE_EVIDENCE, 8U,
            result->result_commitment_sha256, deleted.receipt_sha256, 1,
            NULL, NULL) != 0) {
        effects_dispose_result(context, result); goto done;
    }
    status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
done:
    if (stdin_fd >= 0) (void)close(stdin_fd);
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size); free(semantic);
    }
    plamen_broker_v2_apple_lifecycle_terminal_dispose(&terminal);
    return status == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK ? status
        : mutation_started ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS
        : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
}

static const char *
stage_name(uint16_t stage)
{
    static const char *names[] = {
        "EMPTY", "LAYOUT_READY", "CONFIG_READY", "GUEST_CREATED",
        "GUEST_ADMITTED", "DRIVER_STARTED", "DRIVER_EXITED", "EXTINCT",
        "CENSUSED", "EXPORTED", "DELETED"
    };
    return stage <= PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED
        ? names[stage] : NULL;
}

static const char *
operation_name(uint16_t operation)
{
    static const char *names[] = {
        NULL, "PREPARE_LAYOUT", "WRITE_CONFIG", "CREATE_GUEST",
        "ADMIT_GUEST", "START_DRIVER", "WAIT_DRIVER", "EXTINGUISH",
        "CENSUS_ARTIFACTS", "EXPORT_ARTIFACTS", "DELETE_GUEST"
    };
    return operation >= PLAMEN_BROKER_V2_OUTER_PREPARE_LAYOUT
        && operation <= PLAMEN_BROKER_V2_OUTER_DELETE_GUEST
        ? names[operation] : NULL;
}

static uint16_t
mutation_for_method(uint16_t method)
{
    switch (method) {
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_PREPARE_LAYOUT:
        return PLAMEN_BROKER_V2_OUTER_PREPARE_LAYOUT;
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_WRITE_GUEST_CONFIG:
        return PLAMEN_BROKER_V2_OUTER_WRITE_CONFIG;
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_CREATE_STOPPED:
        return PLAMEN_BROKER_V2_OUTER_CREATE_GUEST;
    case PLAMEN_BROKER_V2_METHOD_GUEST_ADMIT_STOPPED:
        return PLAMEN_BROKER_V2_OUTER_ADMIT_GUEST;
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_START_DRIVER:
        return PLAMEN_BROKER_V2_OUTER_START_DRIVER;
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_WAIT_DRIVER:
        return PLAMEN_BROKER_V2_OUTER_WAIT_DRIVER;
    case PLAMEN_BROKER_V2_METHOD_EXTINCTION_EXTINGUISH:
        return PLAMEN_BROKER_V2_OUTER_EXTINGUISH;
    case PLAMEN_BROKER_V2_METHOD_ARTIFACT_CENSUS:
        return PLAMEN_BROKER_V2_OUTER_CENSUS_ARTIFACTS;
    case PLAMEN_BROKER_V2_METHOD_EXPORT_EXPORT:
        return PLAMEN_BROKER_V2_OUTER_EXPORT_ARTIFACTS;
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_DELETE_GUEST:
        return PLAMEN_BROKER_V2_OUTER_DELETE_GUEST;
    default:
        return 0;
    }
}

static uint16_t
operation_value(const char *name, size_t size)
{
    uint16_t operation;
    for (operation = PLAMEN_BROKER_V2_OUTER_PREPARE_LAYOUT;
         operation <= PLAMEN_BROKER_V2_OUTER_DELETE_GUEST; ++operation) {
        const char *candidate = operation_name(operation);
        if (strlen(candidate) == size && memcmp(candidate, name, size) == 0)
            return operation;
    }
    return 0;
}

static int
make_checkpoint(struct plamen_broker_v2_effects_context *context,
    uint8_t **wire, size_t *wire_size, uint8_t **semantic,
    size_t *semantic_size)
{
    char fingerprint[65];
    const char *name = stage_name(context->stage);
    if (name == NULL || context->stage != PLAMEN_BROKER_V2_OPERATIONS_STAGE_EMPTY)
        return -1;
    encode_hex32(context->registration.audit_request_fingerprint, fingerprint);
    if (format_alloc(wire, wire_size,
            "{\"$type\":\"SupervisorCheckpoint\",\"fields\":{"
            "\"attempt_id\":\"%s\",\"receipts\":{\"$tuple\":[]},"
            "\"request_fingerprint_sha256\":\"%s\",\"run_id\":\"%s\","
            "\"stage\":{\"$enum\":\"SupervisorStage\",\"value\":\"%s\"}}}",
            context->commitment.attempt_id, fingerprint,
            context->commitment.run_identity, name) != 0
        || format_alloc(semantic, semantic_size,
            "{\"attempt_id\":\"%s\",\"receipts\":[],"
            "\"request_fingerprint_sha256\":\"%s\",\"run_id\":\"%s\","
            "\"stage\":\"%s\"}", context->commitment.attempt_id,
            fingerprint, context->commitment.run_identity, name) != 0) {
        if (*wire != NULL) {
            plamen_broker_v2_secure_zero(*wire, *wire_size);
            free(*wire);
            *wire = NULL;
            *wire_size = 0;
        }
        return -1;
    }
    return 0;
}

static int
semantic_digest_with_lf(const uint8_t *semantic, size_t semantic_size,
    uint8_t digest[32])
{
    uint8_t *bytes;
    int result;
    if (semantic == NULL || semantic_size > SIZE_MAX - 1U)
        return -1;
    bytes = malloc(semantic_size + 1U);
    if (bytes == NULL)
        return -1;
    memcpy(bytes, semantic, semantic_size);
    bytes[semantic_size] = '\n';
    result = plamen_broker_v2_sha256(bytes, semantic_size + 1U, digest);
    plamen_broker_v2_secure_zero(bytes, semantic_size + 1U);
    free(bytes);
    return result;
}

static int
journal_open_result(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    uint8_t *checkpoint_wire = NULL, *checkpoint_semantic = NULL;
    uint8_t *wire = NULL, *semantic = NULL;
    size_t checkpoint_wire_size = 0, checkpoint_semantic_size = 0;
    size_t wire_size = 0, semantic_size = 0;
    uint8_t initial[32];
    const char *status_name;
    int status = -1;
    if (context->stage != PLAMEN_BROKER_V2_OPERATIONS_STAGE_EMPTY
        || context->pending_operation != 0
        || make_checkpoint(context, &checkpoint_wire, &checkpoint_wire_size,
            &checkpoint_semantic, &checkpoint_semantic_size) != 0
        || semantic_digest_with_lf(checkpoint_semantic,
            checkpoint_semantic_size, initial) != 0)
        goto done;
    if (!context->journal_present) {
        if (!constant_equal(initial, request->current_checkpoint_sha256, 32))
            goto done;
        memcpy(context->current_checkpoint, initial, 32);
        if (persist_state(context) != 0)
            return PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS;
    } else if (!constant_equal(context->current_checkpoint,
            request->current_checkpoint_sha256, 32)) {
        goto done;
    }
    status_name = context->complete ? "COMPLETE" : "READY";
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"JournalOpenReceipt\",\"fields\":{"
            "\"checkpoint\":%.*s,\"pending\":null,"
            "\"status\":{\"$enum\":\"JournalOpenStatus\","
            "\"value\":\"%s\"}}}",
            (int)checkpoint_wire_size, checkpoint_wire, status_name) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"checkpoint\":%.*s,\"pending\":null,"
            "\"status\":\"%s\"}\n",
            (int)checkpoint_semantic_size, checkpoint_semantic,
            status_name) != 0
        || set_result(result, wire, wire_size, semantic, semantic_size, 0) != 0)
        goto done;
    wire = NULL;
    memcpy(result->durable_checkpoint_sha256, context->current_checkpoint, 32);
    result->durable_stage = context->stage;
    status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
done:
    if (checkpoint_wire != NULL) {
        plamen_broker_v2_secure_zero(checkpoint_wire, checkpoint_wire_size);
        free(checkpoint_wire);
    }
    if (checkpoint_semantic != NULL) {
        plamen_broker_v2_secure_zero(checkpoint_semantic,
            checkpoint_semantic_size);
        free(checkpoint_semantic);
    }
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size);
        free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size);
        free(semantic);
    }
    plamen_broker_v2_secure_zero(initial, sizeof(initial));
    return status == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK ? status
        : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
}

static int
journal_arm_result(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    uint8_t nonce_input[80], nonce[32];
    uint8_t *wire = NULL, *semantic = NULL;
    size_t wire_size = 0, semantic_size = 0;
    char fingerprint[65], checkpoint[65], nonce_hex[65];
    const char *name;
    uint16_t operation;
    uint64_t sequence;
    int status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    if (request->argument_count != 3 || request->arguments == NULL
        || request->arguments[1].scalar == NULL
        || request->arguments[2].scalar == NULL
        || context->pending_operation != 0 || !context->journal_present
        || request->stage != context->stage)
        return status;
    operation = operation_value(request->arguments[1].scalar,
        request->arguments[1].scalar_size);
    name = operation_name(operation);
    encode_hex32(context->current_checkpoint, checkpoint);
    if (name == NULL || operation != context->stage + 1U
        || request->arguments[2].scalar_size != 64
        || memcmp(request->arguments[2].scalar, checkpoint, 64) != 0
        || context->journal_sequence == UINT64_MAX)
        return status;
    sequence = context->journal_sequence + 1U;
    memset(nonce_input, 0, sizeof(nonce_input));
    memcpy(nonce_input, "PLAMEN-EFFECTS-TICKET\0", 22);
    memcpy(nonce_input + 22, request->operation_key, 32);
    store_u64(nonce_input + 54, sequence);
    if (plamen_broker_v2_sha256(nonce_input, 62, nonce) != 0)
        goto done;
    encode_hex32(context->registration.audit_request_fingerprint,
        fingerprint);
    encode_hex32(nonce, nonce_hex);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"MutationTicket\",\"fields\":{"
            "\"attempt_id\":\"%s\",\"authenticated\":true,"
            "\"before_checkpoint_sha256\":\"%s\",\"nonce\":\"%s\","
            "\"operation\":{\"$enum\":\"MutationOperation\","
            "\"value\":\"%s\"},\"request_fingerprint_sha256\":\"%s\","
            "\"sequence\":%llu}}",
            context->commitment.attempt_id, checkpoint, nonce_hex, name,
            fingerprint, (unsigned long long)sequence) != 0
        || format_alloc(&semantic, &semantic_size,
            "{\"attempt_id\":\"%s\",\"authenticated\":true,"
            "\"before_checkpoint_sha256\":\"%s\",\"nonce\":\"%s\","
            "\"operation\":\"%s\",\"request_fingerprint_sha256\":\"%s\","
            "\"sequence\":%llu}\n",
            context->commitment.attempt_id, checkpoint, nonce_hex, name,
            fingerprint, (unsigned long long)sequence) != 0
        || plamen_broker_v2_sha256(semantic, semantic_size,
            context->pending_ticket) != 0)
        goto done;
    context->journal_sequence = sequence;
    context->pending_operation = operation;
    context->effect_seen = 0;
    if (persist_state(context) != 0) {
        status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS;
        goto done;
    }
    if (set_result(result, wire, wire_size, semantic, semantic_size, 0) != 0) {
        status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS;
        goto done;
    }
    wire = NULL;
    status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
done:
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size);
        free(wire);
    }
    if (semantic != NULL) {
        plamen_broker_v2_secure_zero(semantic, semantic_size);
        free(semantic);
    }
    plamen_broker_v2_secure_zero(nonce_input, sizeof(nonce_input));
    plamen_broker_v2_secure_zero(nonce, sizeof(nonce));
    plamen_broker_v2_secure_zero(fingerprint, sizeof(fingerprint));
    plamen_broker_v2_secure_zero(checkpoint, sizeof(checkpoint));
    plamen_broker_v2_secure_zero(nonce_hex, sizeof(nonce_hex));
    return status;
}

static int
make_true_result(struct plamen_broker_v2_operations_effect_result *result,
    uint8_t effect_applied)
{
    static const uint8_t semantic[] = "true\n";
    uint8_t *wire = malloc(5);
    int status;
    if (wire == NULL)
        return -1;
    memcpy(wire, "true", 5);
    status = set_result(result, wire, 4, semantic, sizeof(semantic) - 1U,
        effect_applied);
    if (status != 0) {
        plamen_broker_v2_secure_zero(wire, 5);
        free(wire);
    }
    return status;
}

static int
journal_finish_result(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    char checkpoint[65];
    if (request->argument_count != 2 || request->arguments == NULL
        || request->arguments[1].scalar == NULL
        || context->stage != PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED
        || context->pending_operation != 0 || context->complete)
        return PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    encode_hex32(context->current_checkpoint, checkpoint);
    if (request->arguments[1].scalar_size != 64
        || memcmp(request->arguments[1].scalar, checkpoint, 64) != 0)
        return PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    context->complete = 1;
    if (persist_state(context) != 0)
        return PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS;
    return make_true_result(result, 0) == 0
        ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK
        : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS;
}

static int
journal_commit_result(struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    uint16_t next_stage;
    if (request->argument_count != 3 || request->arguments == NULL
        || request->arguments[1].is_receipt != 1
        || request->arguments[2].is_receipt != 1
        || context->pending_operation == 0 || !context->effect_seen
        || request->stage != context->stage
        || request->pending_operation != context->pending_operation
        || !constant_equal(request->arguments[1].commitment_sha256,
            context->pending_ticket, 32)
        || all_zero(request->arguments[2].commitment_sha256))
        return PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    next_stage = context->pending_operation;
    if (next_stage != context->stage + 1U)
        return PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    context->stage = next_stage;
    context->pending_operation = 0;
    context->effect_seen = 0;
    memcpy(context->current_checkpoint,
        request->arguments[2].commitment_sha256, 32);
    plamen_broker_v2_secure_zero(context->pending_ticket,
        sizeof(context->pending_ticket));
    if (persist_state(context) != 0)
        return PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS;
    return make_true_result(result, 0) == 0
        ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK
        : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS;
}

static int
effects_execute(void *opaque,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    uint64_t now;
    uint16_t mutation;
    int status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    if (result != NULL)
        memset(result, 0, sizeof(*result));
    if (context == NULL || request == NULL || result == NULL
        || request->version != PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION
        || !constant_equal(request->request_fingerprint_sha256,
            context->registration.audit_request_fingerprint, 32)
        || (now = effects_monotonic_ms(context)) == 0
        || request->monotonic_deadline_ms <= now
        || effects_cancelled(context) != 0
        || pthread_mutex_lock(&context->lock) != 0)
        return PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
    if (internal_revalidate(context) != 0)
        goto done;
    mutation = mutation_for_method(request->method);
    if (mutation != 0
        && (context->pending_operation != mutation
            || request->pending_operation != mutation
            || request->stage != context->stage
            || mutation != context->stage + 1U))
        goto done;
    {
        int workspace_status = plamen_broker_v2_workspace_effects_execute(
            context->workspace, request, result);
        if (workspace_status < 0) {
            status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
            goto done;
        }
        if (workspace_status > 0) {
            status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK;
            goto mutation_result;
        }
    }
    switch (request->method) {
    case PLAMEN_BROKER_V2_METHOD_RUNTIME_AUTHENTICATE:
        status = make_runtime_result(context, result) == 0
            ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK
            : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
        break;
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET:
        status = make_target_result(context, 0, result) == 0
            ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK
            : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
        break;
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_REVALIDATE_TARGET:
        status = make_target_result(context, 1, result) == 0
            ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK
            : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
        break;
    case PLAMEN_BROKER_V2_METHOD_BACKEND_AUTHENTICATE:
        status = make_backend_result(context, result) == 0
            ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK
            : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
        break;
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND:
        status = make_provider_result(result) == 0
            ? PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK
            : PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
        break;
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_CREATE_STOPPED:
        status = provider_create_stopped(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_INSPECT_STOPPED:
        status = provider_inspect_stopped(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_START_DRIVER:
        status = provider_start_driver(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_WAIT_DRIVER:
        status = provider_wait_driver(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_GUEST_ADMIT_STOPPED:
        status = provider_admit_stopped(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_EXTINCTION_EXTINGUISH:
        status = provider_extinguish(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_ARTIFACT_CENSUS:
        status = provider_artifact_census(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_EXPORT_EXPORT:
        status = provider_artifact_export(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_PROVIDER_DELETE_GUEST:
        status = provider_delete_guest(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_JOURNAL_OPEN:
        status = journal_open_result(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM:
        status = journal_arm_result(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_JOURNAL_FINISH:
        status = journal_finish_result(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_JOURNAL_COMMIT:
        status = journal_commit_result(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_JOURNAL_RESOLVE:
        /* Resolve is forbidden until native recovery supplies exact evidence. */
        status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
        break;
    default:
        status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED;
        break;
    }
mutation_result:
    if (mutation != 0 && status == PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK) {
        if (!result->effect_applied || !result->durability_proven) {
            status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS;
        } else {
            context->effect_seen = 1;
            if (persist_state(context) != 0)
                status = PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS;
        }
    }
done:
    (void)pthread_mutex_unlock(&context->lock);
    return status;
}

static void
effects_dispose_result(void *opaque,
    struct plamen_broker_v2_operations_effect_result *result)
{
    (void)opaque;
    if (result == NULL)
        return;
    if (result->canonical_result != NULL) {
        plamen_broker_v2_secure_zero((void *)result->canonical_result,
            result->canonical_result_size);
        free((void *)result->canonical_result);
    }
    plamen_broker_v2_secure_zero(result, sizeof(*result));
}

static int
replay_name(const uint8_t operation_key[32], char output[73])
{
    char hex[65];
    encode_hex32(operation_key, hex);
    return snprintf(output, 73, "rpc-%s.bin", hex) == 72 ? 0 : -1;
}

static void
encode_replay_state(
    const struct plamen_broker_v2_operations_replay_state *state,
    uint8_t output[REPLAY_STATE_SIZE])
{
    memset(output, 0, REPLAY_STATE_SIZE);
    store_u32(output, state->version);
    memcpy(output + 4, state->current_checkpoint_sha256, 32);
    memcpy(output + 36, state->pending_ticket_sha256, 32);
    store_u16(output + 68, state->stage);
    store_u16(output + 70, state->pending_operation);
    output[72] = state->journal_opened;
    output[73] = state->runtime_authenticated;
    output[74] = state->target_admitted;
    output[75] = state->backend_authenticated;
    output[76] = state->provider_known;
    output[77] = state->pending_effect_seen;
    output[78] = state->recovery_seen;
    output[79] = state->recovery_applied;
    output[80] = state->finished;
    output[81] = state->burned;
}

static void
decode_replay_state(const uint8_t input[REPLAY_STATE_SIZE],
    struct plamen_broker_v2_operations_replay_state *state)
{
    memset(state, 0, sizeof(*state));
    state->version = load_u32(input);
    memcpy(state->current_checkpoint_sha256, input + 4, 32);
    memcpy(state->pending_ticket_sha256, input + 36, 32);
    state->stage = load_u16(input + 68);
    state->pending_operation = load_u16(input + 70);
    state->journal_opened = input[72];
    state->runtime_authenticated = input[73];
    state->target_admitted = input[74];
    state->backend_authenticated = input[75];
    state->provider_known = input[76];
    state->pending_effect_seen = input[77];
    state->recovery_seen = input[78];
    state->recovery_applied = input[79];
    state->finished = input[80];
    state->burned = input[81];
}

static int
replay_state_valid(
    const struct plamen_broker_v2_operations_replay_state *state)
{
    const uint8_t flags[] = {
        state->journal_opened, state->runtime_authenticated,
        state->target_admitted, state->backend_authenticated,
        state->provider_known, state->pending_effect_seen,
        state->recovery_seen, state->recovery_applied, state->finished,
        state->burned
    };
    size_t index;
    if (state->version != PLAMEN_BROKER_V2_OPERATIONS_VERSION
        || state->stage > PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED
        || state->pending_operation
            > PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED)
        return 0;
    for (index = 0; index < sizeof(flags); ++index) {
        if (flags[index] > 1)
            return 0;
    }
    if ((state->pending_operation == 0)
        != all_zero(state->pending_ticket_sha256))
        return 0;
    return 1;
}

static int
read_replay_record(struct plamen_broker_v2_effects_context *context,
    const uint8_t operation_key[32], uint8_t request_sha256[32],
    uint8_t *kind, uint8_t **wire, size_t *wire_size,
    struct plamen_broker_v2_operations_replay_state *state)
{
    struct stat information;
    uint8_t prefix[REPLAY_PREFIX_SIZE], digest[32], extra;
    char name[73];
    uint8_t *value = NULL;
    uint32_t size;
    int descriptor = -1, result = -1;
    *wire = NULL;
    *wire_size = 0;
    if (replay_name(operation_key, name) != 0)
        return -1;
    descriptor = openat(context->state_directory_fd, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return errno == ENOENT ? 0 : -1;
    if (fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_uid != geteuid()
        || (information.st_mode & 0077) != 0
        || information.st_size < (off_t)REPLAY_PREFIX_SIZE
        || information.st_size
            > (off_t)(REPLAY_PREFIX_SIZE + PLAMEN_BROKER_V2_MAX_PAYLOAD)
        || pread_all(descriptor, prefix, sizeof(prefix), 0) != 0
        || memcmp(prefix, REPLAY_MAGIC, 8) != 0
        || load_u32(prefix + 8) != PLAMEN_BROKER_V2_EFFECTS_VERSION
        || !constant_equal(prefix + 12,
            context->registration.audit_request_fingerprint, 32)
        || !constant_equal(prefix + 44,
            context->registration.request_projection_sha256, 32)
        || !constant_equal(prefix + 76, context->authority_binding, 32))
        goto done;
    memcpy(request_sha256, prefix + 108, 32);
    size = load_u32(prefix + 140);
    *kind = prefix[144];
    if ((*kind != PLAMEN_BROKER_V2_OPERATIONS_RESPONSE
            && *kind != PLAMEN_BROKER_V2_OPERATIONS_ERROR)
        || size == 0 || size > PLAMEN_BROKER_V2_MAX_PAYLOAD
        || information.st_size != (off_t)(REPLAY_PREFIX_SIZE + size))
        goto done;
    decode_replay_state(prefix + 188, state);
    if (!replay_state_valid(state))
        goto done;
    value = malloc(size);
    if (value == NULL
        || pread_all(descriptor, value, size, REPLAY_WIRE_OFFSET) != 0
        || pread(descriptor, &extra, 1,
            (off_t)(REPLAY_WIRE_OFFSET + size)) != 0
        || plamen_broker_v2_sha256(value, size, digest) != 0
        || !constant_equal(digest, prefix + 156, 32))
        goto done;
    *wire = value;
    *wire_size = size;
    value = NULL;
    result = 1;
done:
    if (value != NULL) {
        plamen_broker_v2_secure_zero(value, size);
        free(value);
    }
    plamen_broker_v2_secure_zero(prefix, sizeof(prefix));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    if (descriptor >= 0)
        (void)close(descriptor);
    return result;
}

static int
effects_replay_lookup(void *opaque, const uint8_t operation_key[32],
    const uint8_t request_sha256[32], uint8_t *kind, uint8_t *wire,
    size_t wire_capacity, size_t *wire_size,
    struct plamen_broker_v2_operations_replay_state *state)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    uint8_t stored_request[32], stored_kind = 0, *stored_wire = NULL;
    size_t stored_size = 0;
    int status, result = -1;
    if (kind != NULL)
        *kind = 0;
    if (wire_size != NULL)
        *wire_size = 0;
    if (state != NULL)
        memset(state, 0, sizeof(*state));
    if (context == NULL || operation_key == NULL || request_sha256 == NULL
        || kind == NULL || wire == NULL || wire_size == NULL || state == NULL
        || wire_capacity == 0 || all_zero(operation_key)
        || all_zero(request_sha256)
        || pthread_mutex_lock(&context->lock) != 0)
        return -1;
    if (internal_revalidate(context) != 0)
        goto done;
    status = read_replay_record(context, operation_key, stored_request,
        &stored_kind, &stored_wire, &stored_size, state);
    if (status == 0) {
        result = PLAMEN_BROKER_V2_OPERATIONS_REPLAY_MISS;
        goto done;
    }
    if (status < 0)
        goto done;
    if (!constant_equal(stored_request, request_sha256, 32)) {
        result = PLAMEN_BROKER_V2_OPERATIONS_REPLAY_CONFLICT;
        goto done;
    }
    if (stored_size > wire_capacity)
        goto done;
    memcpy(wire, stored_wire, stored_size);
    *kind = stored_kind;
    *wire_size = stored_size;
    result = PLAMEN_BROKER_V2_OPERATIONS_REPLAY_FOUND;
done:
    if (stored_wire != NULL) {
        plamen_broker_v2_secure_zero(stored_wire, stored_size);
        free(stored_wire);
    }
    plamen_broker_v2_secure_zero(stored_request, sizeof(stored_request));
    (void)pthread_mutex_unlock(&context->lock);
    return result;
}

static int
existing_replay_matches(struct plamen_broker_v2_effects_context *context,
    const uint8_t operation_key[32], const uint8_t request_sha256[32],
    uint8_t kind, const uint8_t *wire, size_t wire_size,
    const struct plamen_broker_v2_operations_replay_state *state)
{
    uint8_t stored_request[32], stored_kind = 0, *stored_wire = NULL;
    uint8_t expected_state[REPLAY_STATE_SIZE], actual_state[REPLAY_STATE_SIZE];
    struct plamen_broker_v2_operations_replay_state stored_state;
    size_t stored_size = 0;
    int loaded, result = -1;
    memset(&stored_state, 0, sizeof(stored_state));
    loaded = read_replay_record(context, operation_key, stored_request,
        &stored_kind, &stored_wire, &stored_size, &stored_state);
    encode_replay_state(state, expected_state);
    encode_replay_state(&stored_state, actual_state);
    if (loaded == 1 && stored_kind == kind && stored_size == wire_size
        && constant_equal(stored_request, request_sha256, 32)
        && constant_equal(stored_wire, wire, wire_size)
        && constant_equal(expected_state, actual_state, REPLAY_STATE_SIZE))
        result = 0;
    if (stored_wire != NULL) {
        plamen_broker_v2_secure_zero(stored_wire, stored_size);
        free(stored_wire);
    }
    plamen_broker_v2_secure_zero(stored_request, sizeof(stored_request));
    plamen_broker_v2_secure_zero(&stored_state, sizeof(stored_state));
    plamen_broker_v2_secure_zero(expected_state, sizeof(expected_state));
    plamen_broker_v2_secure_zero(actual_state, sizeof(actual_state));
    return result;
}

static int
effects_replay_commit(void *opaque, const uint8_t operation_key[32],
    const uint8_t request_sha256[32], uint8_t kind, const uint8_t *wire,
    size_t wire_size,
    const struct plamen_broker_v2_operations_replay_state *state)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    uint8_t *record = NULL;
    char name[73], temporary[96];
    size_t record_size;
    int descriptor = -1, link_result, saved_errno, result = -1;
    if (context == NULL || operation_key == NULL || request_sha256 == NULL
        || wire == NULL || wire_size == 0 || state == NULL
        || wire_size > PLAMEN_BROKER_V2_MAX_PAYLOAD
        || (kind != PLAMEN_BROKER_V2_OPERATIONS_RESPONSE
            && kind != PLAMEN_BROKER_V2_OPERATIONS_ERROR)
        || !replay_state_valid(state)
        || all_zero(operation_key) || all_zero(request_sha256)
        || replay_name(operation_key, name) != 0
        || pthread_mutex_lock(&context->lock) != 0)
        return -1;
    if (internal_revalidate(context) != 0)
        goto done;
    if (existing_replay_matches(context, operation_key, request_sha256,
            kind, wire, wire_size, state) == 0) {
        result = 0;
        goto done;
    }
    if (wire_size > SIZE_MAX - REPLAY_PREFIX_SIZE)
        goto done;
    record_size = REPLAY_PREFIX_SIZE + wire_size;
    record = calloc(1, record_size);
    if (record == NULL)
        goto done;
    memcpy(record, REPLAY_MAGIC, 8);
    store_u32(record + 8, PLAMEN_BROKER_V2_EFFECTS_VERSION);
    memcpy(record + 12, context->registration.audit_request_fingerprint, 32);
    memcpy(record + 44, context->registration.request_projection_sha256, 32);
    memcpy(record + 76, context->authority_binding, 32);
    memcpy(record + 108, request_sha256, 32);
    store_u32(record + 140, (uint32_t)wire_size);
    record[144] = kind;
    if (plamen_broker_v2_sha256(wire, wire_size, record + 156) != 0)
        goto done;
    encode_replay_state(state, record + 188);
    memcpy(record + REPLAY_WIRE_OFFSET, wire, wire_size);
    ++context->replay_nonce;
    if (snprintf(temporary, sizeof(temporary), ".rpc-%llu-%ld.tmp",
            (unsigned long long)context->replay_nonce, (long)getpid()) <= 0)
        goto done;
    descriptor = openat(context->state_directory_fd, temporary,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0 || write_all(descriptor, record, record_size) != 0
        || full_sync(descriptor) != 0 || close(descriptor) != 0) {
        if (descriptor >= 0)
            (void)close(descriptor);
        descriptor = -1;
        goto cleanup_temp;
    }
    descriptor = -1;
    link_result = linkat(context->state_directory_fd, temporary,
        context->state_directory_fd, name, 0);
    saved_errno = errno;
    if (unlinkat(context->state_directory_fd, temporary, 0) != 0
        || full_sync(context->state_directory_fd) != 0)
        goto done;
    if (link_result == 0) {
        result = 0;
        goto done;
    }
    if (saved_errno == EEXIST
        && existing_replay_matches(context, operation_key, request_sha256,
            kind, wire, wire_size, state) == 0)
        result = 0;
    goto done;
cleanup_temp:
    (void)unlinkat(context->state_directory_fd, temporary, 0);
done:
    if (descriptor >= 0)
        (void)close(descriptor);
    if (record != NULL) {
        plamen_broker_v2_secure_zero(record, record_size);
        free(record);
    }
    (void)pthread_mutex_unlock(&context->lock);
    return result;
}

static void
destroy_context(struct plamen_broker_v2_effects_context *context)
{
    size_t index;
    if (context == NULL)
        return;
    if (context->provider_lifecycle != NULL) {
        (void)plamen_broker_v2_apple_lifecycle_detach(
            context->provider_lifecycle);
        context->provider_lifecycle = NULL;
    }
    if (context->workspace != NULL) {
        plamen_broker_v2_workspace_effects_destroy(context->workspace);
        context->workspace = NULL;
    }
    if (context->js_prepare_lease != NULL)
        plamen_broker_v2_tool_effect_plan_destroy(context->js_prepare_lease);
    if (context->managed_prepare_lease != NULL)
        plamen_broker_v2_tool_effect_plan_destroy(
            context->managed_prepare_lease);
    if (context->snapshot_prepare_lease != NULL)
        plamen_broker_v2_tool_effect_plan_destroy(
            context->snapshot_prepare_lease);
    plamen_broker_v2_fuzz_service_continuation_dispose(
        context->fuzz_service_continuation);
    context->fuzz_service_continuation = NULL;
    plamen_broker_v2_fuzz_service_session_dispose(
        context->fuzz_service_session);
    context->fuzz_service_session = NULL;
    plamen_broker_v2_specialized_runtime_handoff_destroy(
        context->specialized_runtime);
    context->specialized_runtime = NULL;
    if (context->process != NULL) {
        (void)plamen_broker_v2_process_extinguish(context->process, NULL);
        (void)plamen_broker_v2_process_close(context->process);
        context->process = NULL;
    }
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++index) {
        if (context->authority_fds[index] >= 0)
            (void)close(context->authority_fds[index]);
        context->authority_fds[index] = -1;
    }
    if (context->cancellation_fd >= 0)
        (void)close(context->cancellation_fd);
    if (context->generation_fd >= 0)
        (void)close(context->generation_fd);
    if (context->state_directory_fd >= 0)
        (void)close(context->state_directory_fd);
    if (context->state_parent_fd >= 0)
        (void)close(context->state_parent_fd);
    if (context->projection != NULL) {
        plamen_broker_v2_secure_zero(context->projection,
            context->projection_size);
        free(context->projection);
    }
    if (context->lock_initialized)
        (void)pthread_mutex_destroy(&context->lock);
    plamen_broker_v2_secure_zero(context, sizeof(*context));
    free(context);
}

int
plamen_broker_v2_effects_create(struct plamen_broker_v2_effects_open *open,
    struct plamen_broker_v2_effects_context **output)
{
    struct plamen_broker_v2_effects_context *context = NULL;
    struct plamen_broker_v2_commitment commitment;
    struct plamen_broker_v2_workspace_effects_open workspace_open;
    struct plamen_broker_v2_specialized_runtime_handoff_open runtime_open;
    struct effects_fd_snapshot snapshots[
        PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    size_t index;
    int loaded, result = -1;
    if (output != NULL)
        *output = NULL;
    memset(&commitment, 0, sizeof(commitment));
    memset(&workspace_open, 0, sizeof(workspace_open));
    memset(&runtime_open, 0, sizeof(runtime_open));
    memset(snapshots, 0, sizeof(snapshots));
    if (open == NULL || output == NULL
        || open->version != PLAMEN_BROKER_V2_EFFECTS_VERSION
        || open->registration == NULL || open->request_projection == NULL
        || open->request_projection_size == 0
        || open->request_projection_size > PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX
        || all_zero(open->authority_binding_sha256)
        || open->state_parent_fd < 0 || open->generation_fd < 0
        || open->runtime_manifest_fd < 0
        || open->runtime_manifest_member == NULL
        || open->image_member_receipt_fd < 0
        || open->specialized_runtime_auxiliary == NULL
        || open->custody_client == NULL || open->cancellation_fd < 0
        || open->authority_fds == NULL
        || open->authority_fd_count
            != PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT
        || open->request_projection_size
            != open->registration->request_projection_size
        || plamen_broker_v2_request_projection_validate_exact(
            open->request_projection, open->request_projection_size,
            open->registration->request_projection_sha256,
            open->registration->commitment,
            open->registration->commitment_size,
            open->registration->commitment_sha256, &commitment) != 0
        || !constant_equal(commitment.request_fingerprint,
            open->registration->audit_request_fingerprint, 32)
        || validate_authority_array(open->registration,
            open->authority_fds, snapshots) != 0)
        goto done;
    context = calloc(1, sizeof(*context));
    if (context == NULL)
        goto done;
    context->state_parent_fd = -1;
    context->state_directory_fd = -1;
    context->generation_fd = -1;
    context->cancellation_fd = -1;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++index)
        context->authority_fds[index] = -1;
    context->registration = *open->registration;
    context->custody_client = open->custody_client;
    context->commitment = commitment;
    memcpy(context->authority_binding, open->authority_binding_sha256, 32);
    memcpy(context->authority_snapshots, snapshots, sizeof(snapshots));
    context->projection = malloc(open->request_projection_size);
    if (context->projection == NULL)
        goto done;
    memcpy(context->projection, open->request_projection,
        open->request_projection_size);
    context->projection_size = open->request_projection_size;
    context->state_parent_fd = duplicate_cloexec(open->state_parent_fd);
    context->generation_fd = duplicate_cloexec(open->generation_fd);
    context->cancellation_fd = duplicate_cloexec(open->cancellation_fd);
    if (context->state_parent_fd < 0 || context->generation_fd < 0
        || context->cancellation_fd < 0
        || private_directory(context->state_parent_fd,
            &context->state_parent_snapshot) != 0
        || snapshot_fd(context->generation_fd,
            &context->generation_snapshot) != 0
        || connected_stream(context->cancellation_fd,
            &context->cancellation_snapshot) != 0
        || open_effects_directory(context) != 0
        || snapshot_fd(context->state_parent_fd,
            &context->state_parent_snapshot) != 0
        || load_projection_facts(context) != 0
        || pthread_mutex_init(&context->lock, NULL) != 0)
        goto done;
    context->lock_initialized = 1;
    context->magic = EFFECTS_MAGIC;
    runtime_open.version =
        PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_HANDOFF_VERSION;
    runtime_open.generation_fd = open->generation_fd;
    runtime_open.runtime_manifest_fd = open->runtime_manifest_fd;
    runtime_open.runtime_manifest_member = open->runtime_manifest_member;
    runtime_open.image_member_receipt_fd = open->image_member_receipt_fd;
    runtime_open.auxiliary = open->specialized_runtime_auxiliary;
    if (plamen_broker_v2_specialized_runtime_handoff_create(&runtime_open,
            &context->specialized_runtime) != 0)
        goto done;
    context->replay_nonce = effects_monotonic_ms(context) ^ (uint64_t)getpid();
    loaded = load_state(context);
    if (loaded < 0
        || (all_zero(context->registration.prior_audit_checkpoint_sha256)
            ? loaded != 0
            : (loaded != 1 || !constant_equal(context->current_checkpoint,
                context->registration.prior_audit_checkpoint_sha256, 32)))
        || load_provider_binding(context) < 0)
        goto done;
    workspace_open.version = PLAMEN_BROKER_V2_WORKSPACE_EFFECTS_VERSION;
    workspace_open.registration = open->registration;
    workspace_open.request_projection = open->request_projection;
    workspace_open.request_projection_size = open->request_projection_size;
    workspace_open.state_parent_fd = open->state_parent_fd;
    workspace_open.generation_fd = open->generation_fd;
    workspace_open.authority_fds = open->authority_fds;
    workspace_open.authority_fd_count = open->authority_fd_count;
    if (plamen_broker_v2_workspace_effects_create(&workspace_open,
            &context->workspace) != 0)
        goto done;
    context->operations.version =
        PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION;
    context->operations.context = context;
    context->operations.revalidate = effects_revalidate;
    context->operations.monotonic_ms = effects_monotonic_ms;
    context->operations.cancelled = effects_cancelled;
    context->operations.execute = effects_execute;
    context->operations.dispose_result = effects_dispose_result;
    context->operations.replay_lookup = effects_replay_lookup;
    context->operations.replay_commit = effects_replay_commit;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++index) {
        context->authority_fds[index] = open->authority_fds[index];
        open->authority_fds[index] = -1;
    }
    *output = context;
    context = NULL;
    result = 0;
done:
    if (context != NULL)
        destroy_context(context);
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    plamen_broker_v2_secure_zero(snapshots, sizeof(snapshots));
    return result;
}

const struct plamen_broker_v2_operations_effects *
plamen_broker_v2_effects_operations(
    struct plamen_broker_v2_effects_context *context)
{
    return context != NULL && context->magic == EFFECTS_MAGIC
        ? &context->operations : NULL;
}

static int
specialized_effects_context_sha256(
    const struct plamen_broker_v2_effects_context *context, uint8_t output[32])
{
    static const uint8_t domain[] = "PLAMEN-EFFECTS-CONTEXT-V2\0";
    uint8_t binding[sizeof(domain) + 32U * 8U + 2U];
    uint8_t specialized_runtime_sha256[32];
    size_t offset = 0;
    memset(specialized_runtime_sha256, 0,
        sizeof(specialized_runtime_sha256));
    if (context == NULL || output == NULL || context->magic != EFFECTS_MAGIC
        || plamen_broker_v2_specialized_runtime_handoff_authority_sha256(
            context->specialized_runtime, specialized_runtime_sha256) != 0)
        return -1;
#define APPEND(value, count) do { memcpy(binding + offset, (value), (count)); \
    offset += (count); } while (0)
    APPEND(domain, sizeof(domain));
    APPEND(context->registration.installed_closure_sha256, 32U);
    APPEND(context->registration.committed_audit_generation_sha256, 32U);
    APPEND(context->registration.audit_request_fingerprint, 32U);
    APPEND(context->registration.request_projection_sha256, 32U);
    APPEND(context->registration.commitment_sha256, 32U);
    APPEND(context->authority_binding, 32U);
    APPEND(specialized_runtime_sha256, 32U);
    if (context->provider_admission_present)
        APPEND(context->provider_admission.admission_sha256, 32U);
    else {
        static const uint8_t zero[32] = { 0 };
        APPEND(zero, 32U);
    }
    binding[offset++] = context->provider_admission_present;
    binding[offset++] = context->journal_present;
#undef APPEND
    if (offset != sizeof(binding)
        || plamen_broker_v2_sha256(binding, sizeof(binding), output) != 0) {
        plamen_broker_v2_secure_zero(binding, sizeof(binding));
        plamen_broker_v2_secure_zero(specialized_runtime_sha256,
            sizeof(specialized_runtime_sha256));
        return -1;
    }
    plamen_broker_v2_secure_zero(binding, sizeof(binding));
    plamen_broker_v2_secure_zero(specialized_runtime_sha256,
        sizeof(specialized_runtime_sha256));
    return all_zero(output) ? -1 : 0;
}

static int
specialized_worker_record_present(int directory_fd, const char *name)
{
    struct stat status;
    if (directory_fd < 0 || name == NULL) return -1;
    if (fstatat(directory_fd, name, &status, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT ? 0 : -1;
    return S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) ? 1 : -1;
}

static int
specialized_worker_directory_empty(int directory_fd)
{
    DIR *directory;
    struct dirent *entry;
    int duplicate, result = 1;
    if (directory_fd < 0
        || (duplicate = fcntl(directory_fd, F_DUPFD_CLOEXEC, 3)) < 0)
        return -1;
    directory = fdopendir(duplicate);
    if (directory == NULL) { (void)close(duplicate); return -1; }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0
            && strcmp(entry->d_name, "..") != 0) {
            result = 0; break;
        }
    }
    if (entry == NULL && errno != 0) result = -1;
    if (closedir(directory) != 0) result = -1;
    return result;
}

static int
specialized_worker_terminal_shape(const uint8_t *bytes, size_t size)
{
    size_t index;
    if (bytes == NULL || size < 2U
        || size > PLAMEN_BROKER_V2_APPLE_LIFECYCLE_RETAIN_MAX
        || bytes[0] != '{' || bytes[size - 1U] != '}') return -1;
    for (index = 0; index < size; ++index)
        if (bytes[index] == 0 || bytes[index] == '\n' || bytes[index] == '\r')
            return -1;
    return 0;
}

static int
specialized_worker_lifecycle_sha256(
    const struct plamen_broker_v2_specialized_worker_result *result,
    uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-SPECIALIZED-WORKER-LIFECYCLE-V1\0";
    CC_SHA256_CTX digest;
    if (result == NULL || output == NULL
        || plamen_broker_v2_apple_lifecycle_create_receipt_validate(
            &result->created) != 0
        || plamen_broker_v2_apple_lifecycle_start_receipt_validate(
            &result->started) != 0
        || plamen_broker_v2_apple_lifecycle_terminal_receipt_validate(
            &result->exited) != 0
        || plamen_broker_v2_apple_lifecycle_delete_receipt_validate(
            &result->deleted) != 0
        || CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, domain, sizeof(domain)) != 1
        || CC_SHA256_Update(&digest, result->created.receipt_sha256, 32) != 1
        || CC_SHA256_Update(&digest, result->started.receipt_sha256, 32) != 1
        || CC_SHA256_Update(&digest, result->exited.receipt_sha256, 32) != 1
        || CC_SHA256_Update(&digest, result->deleted.receipt_sha256, 32) != 1
        || CC_SHA256_Final(output, &digest) != 1)
        return -1;
    return all_zero(output) ? -1 : 0;
}

static int
specialized_worker_open_state(
    struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_specialized_worker_request *request,
    int *state_fd, int *existing)
{
    struct stat status;
    char nonce[65], record_name[96], directory_name[96];
    int amount, descriptor = -1, present;
    uint8_t record_sha256[32];
    if (state_fd != NULL) *state_fd = -1;
    if (existing != NULL) *existing = 0;
    if (context == NULL || request == NULL || state_fd == NULL
        || existing == NULL) return -1;
    encode_hex32(request->operation_key, nonce);
    amount = snprintf(record_name, sizeof(record_name),
        "worker-prepared-%04x-%s.bin", (unsigned int)request->method, nonce);
    if (amount <= 0 || (size_t)amount >= sizeof(record_name)) goto done;
    amount = snprintf(directory_name, sizeof(directory_name),
        "worker-%04x-%s", (unsigned int)request->method, nonce);
    if (amount <= 0 || (size_t)amount >= sizeof(directory_name)
        || provider_evidence(context, record_name, request->method,
            request->request_sha256, request->effects_context_sha256, 1,
            NULL, record_sha256) != 0)
        goto done;
    if (mkdirat(context->state_directory_fd, directory_name, 0700) != 0) {
        if (errno != EEXIST) goto done;
        *existing = 1;
    } else if (fsync(context->state_directory_fd) != 0) {
        goto done;
    }
    descriptor = openat(context->state_directory_fd, directory_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &status) != 0
        || !S_ISDIR(status.st_mode) || status.st_uid != geteuid()
        || (status.st_mode & (S_IRWXG | S_IRWXO)) != 0)
        goto done;
    present = specialized_worker_record_present(descriptor,
        "apple-create-prepared-v1.bin");
    if (present < 0) goto done;
    if (*existing && !present) {
        present = specialized_worker_directory_empty(descriptor);
        if (present != 1) goto done;
        *existing = 0;
    }
    *state_fd = descriptor; descriptor = -1;
    plamen_broker_v2_secure_zero(nonce, sizeof(nonce));
    plamen_broker_v2_secure_zero(record_name, sizeof(record_name));
    plamen_broker_v2_secure_zero(directory_name, sizeof(directory_name));
    plamen_broker_v2_secure_zero(record_sha256, sizeof(record_sha256));
    return 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    plamen_broker_v2_secure_zero(nonce, sizeof(nonce));
    plamen_broker_v2_secure_zero(record_name, sizeof(record_name));
    plamen_broker_v2_secure_zero(directory_name, sizeof(directory_name));
    plamen_broker_v2_secure_zero(record_sha256, sizeof(record_sha256));
    return -1;
}

void
plamen_broker_v2_effects_dispose_specialized_worker_result(
    struct plamen_broker_v2_specialized_worker_result *result)
{
    if (result == NULL) return;
    plamen_broker_v2_apple_lifecycle_terminal_dispose(&result->exited);
    plamen_broker_v2_secure_zero(result, sizeof(*result));
}

int
plamen_broker_v2_effects_run_specialized_worker_locked(
    struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_specialized_worker_request *request,
    struct plamen_broker_v2_specialized_worker_result *result)
{
    struct plamen_broker_v2_apple_lifecycle_spec spec;
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    struct plamen_broker_v2_apple_lifecycle *lifecycle = NULL;
    struct plamen_broker_v2_apple_lifecycle_create_receipt created;
    struct plamen_broker_v2_apple_lifecycle_start_receipt started;
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt exited;
    struct plamen_broker_v2_apple_lifecycle_delete_receipt deleted;
    uint8_t context_sha256[32], hmac[32];
    uint8_t cleanup_terminal = 0;
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    size_t index;
    int state_fd = -1, existing = 0, stage = 0, status = -1;
    static const uint8_t hmac_domain[] =
        "PLAMEN-SPECIALIZED-WORKER-TERMINAL-V1\0";
    if (result != NULL) memset(result, 0, sizeof(*result));
    memset(&spec, 0, sizeof(spec)); memset(&commitments, 0, sizeof(commitments));
    memset(&created, 0, sizeof(created)); memset(&started, 0, sizeof(started));
    memset(&exited, 0, sizeof(exited)); memset(&deleted, 0, sizeof(deleted));
    memset(context_sha256, 0, sizeof(context_sha256));
    memset(hmac, 0, sizeof(hmac)); memset(container_id, 0, sizeof(container_id));
    if (context == NULL || context->magic != EFFECTS_MAGIC || request == NULL
        || result == NULL
        || request->version != PLAMEN_BROKER_V2_SPECIALIZED_WORKER_VERSION
        || request->lane == 0 || request->method == 0
        || all_zero(request->operation_key) || all_zero(request->request_sha256)
        || all_zero(request->effects_context_sha256)
        || all_zero(request->launch_policy_sha256)
        || all_zero(request->terminal_hmac_key)
        || request->working_directory == NULL || request->entrypoint == NULL
        || request->arguments == NULL || request->argument_count == 0
        || request->argument_count >
            PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX
        || request->mounts == NULL || request->mount_count == 0
        || request->mount_count >
            PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX
        || request->stdin_fd < 0 || request->timeout_seconds == 0
        || request->timeout_seconds > 86400U
        || !context->provider_admission_present
        || plamen_broker_v2_apple_container_receipt_validate(
            &context->provider_admission) != 0
        || internal_revalidate(context) != 0
        || specialized_effects_context_sha256(context, context_sha256) != 0
        || !constant_equal(context_sha256,
            request->effects_context_sha256, 32)
        || specialized_worker_open_state(context, request,
            &state_fd, &existing) != 0)
        goto done;
    spec.version = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_DYNAMIC_VERSION;
    spec.cli_fd = context->authority_fds[PLAMEN_BROKER_V2_RETAINED_PROVIDER];
    spec.cli_path = PLAMEN_APPLE_CLI_PATH;
    spec.cwd_fd = context->generation_fd;
    spec.stdin_fd = request->stdin_fd;
    spec.state_directory_fd = state_fd;
    spec.admission = &context->provider_admission;
    if (plamen_broker_v2_apple_container_derive_id(
            context->registration.audit_request_fingerprint,
            request->operation_key, container_id) != 0) goto done;
    spec.container_id = container_id;
    spec.runtime_image_reference = context->provider_admission.runtime_image_reference;
    spec.working_directory = request->working_directory;
    spec.entrypoint = request->entrypoint;
    spec.arguments = request->arguments;
    spec.argument_count = request->argument_count;
    spec.cpus = request->cpus == 0 ? PROVIDER_CPU_COUNT : request->cpus;
    spec.memory_bytes = request->memory_bytes == 0
        ? PROVIDER_MEMORY_BYTES : request->memory_bytes;
    spec.uid = 1000U; spec.gid = 1000U;
    spec.create_timeout_seconds = 120U;
    spec.driver_timeout_seconds = request->timeout_seconds;
    spec.stop_grace_seconds = 10U;
    spec.rosetta_required = 0U;
    if (request->lane == PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM
        || (request->lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
            && request->method
                == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE
            && (strcmp(request->entrypoint,
                    "/usr/local/lib/plamen/toolchains/managed-evm/bin/slither")
                    == 0
                || strcmp(request->entrypoint,
                    "/usr/local/lib/plamen/toolchains/solc-amd64/solc")
                    == 0)))
        spec.rosetta_required = (uint8_t)(request->lane != 0U);
    memcpy(spec.launch_policy_sha256, request->launch_policy_sha256, 32);
    memcpy(spec.create_operation_key, request->operation_key, 32);
    if (derive_provider_nonce(context, request->operation_key,
            "PLAMEN-APPLE-WORKER-START-V1", spec.start_operation_nonce) != 0
        || derive_provider_nonce(context, request->operation_key,
            "PLAMEN-APPLE-WORKER-WAIT-V1", spec.wait_operation_nonce) != 0
        || derive_provider_nonce(context, request->operation_key,
            "PLAMEN-APPLE-WORKER-REVOKE-V1", spec.revoke_operation_nonce) != 0)
        goto done;
    spec.mount_count = request->mount_count; spec.dynamic_mounts = 1U;
    for (index = 0; index < request->mount_count; ++index)
        spec.mounts[index] = request->mounts[index];
    if (plamen_broker_v2_apple_lifecycle_derive_commitments(
            &spec, &commitments) != 0) goto done;
    memcpy(spec.spec_sha256, commitments.spec_sha256, 32);
    memcpy(spec.launch_request_sha256, commitments.launch_request_sha256, 32);
    memcpy(spec.driver_argv_sha256, commitments.driver_argv_sha256, 32);
    memcpy(spec.driver_environment_sha256,
        commitments.driver_environment_sha256, 32);
    memcpy(spec.driver_cwd_sha256, commitments.driver_cwd_sha256, 32);
    memcpy(spec.driver_stdin_sha256, commitments.driver_stdin_sha256, 32);
    memcpy(spec.pass_fd_roster_sha256, commitments.pass_fd_roster_sha256, 32);
    if (existing) {
        int present = specialized_worker_record_present(state_fd,
            "apple-deleted-v1.bin");
        if (present < 0) goto done;
        if (present) {
            if (plamen_broker_v2_apple_lifecycle_reopen_deleted(&spec,
                    context->custody_client, context->authority_binding,
                    &created, &started, &exited, &deleted, &lifecycle)
                    != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) goto done;
            stage = 4;
        } else {
            present = specialized_worker_record_present(state_fd,
                "apple-terminal-v1.bin");
            if (present < 0) goto done;
            if (present) {
                if (plamen_broker_v2_apple_lifecycle_reopen_terminal(&spec,
                        context->custody_client, context->authority_binding,
                        &created, &started, &exited, &lifecycle)
                        != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) goto done;
                stage = 3;
            } else {
                present = specialized_worker_record_present(state_fd,
                    "apple-start-prepared-v1.bin");
                if (present < 0) goto done;
                if (present) {
                    if (plamen_broker_v2_apple_lifecycle_reopen_started(&spec,
                            context->custody_client, context->authority_binding,
                            &created, &started, &lifecycle)
                            != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) goto done;
                    stage = 2;
                } else {
                    int reopen_status =
                        plamen_broker_v2_apple_lifecycle_reopen_created(
                            &spec, context->custody_client,
                            context->authority_binding, &created, &lifecycle);
                    if (reopen_status
                            == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED) {
                        if (plamen_broker_v2_apple_lifecycle_create(&spec,
                                &created, &lifecycle)
                                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
                            || plamen_broker_v2_apple_lifecycle_bind_process_custody(
                                lifecycle, context->custody_client,
                                context->authority_binding) != 0)
                            goto done;
                    } else if (reopen_status
                            != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK)
                        goto done;
                    stage = 1;
                }
            }
        }
    } else {
        if (plamen_broker_v2_apple_lifecycle_create(&spec, &created,
                &lifecycle) != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
            || plamen_broker_v2_apple_lifecycle_bind_process_custody(lifecycle,
                context->custody_client, context->authority_binding) != 0)
            goto done;
        stage = 1;
    }
    if (stage == 1) {
        if (plamen_broker_v2_apple_lifecycle_start(lifecycle, &started)
                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) goto done;
        stage = 2;
    }
    if (stage == 2) {
        if (plamen_broker_v2_apple_lifecycle_wait(lifecycle, &exited)
                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) goto done;
        stage = 3;
    }
    if (stage == 3) {
        if (plamen_broker_v2_apple_lifecycle_delete(lifecycle, &exited,
                &deleted) != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) goto done;
        stage = 4;
    }
    if (stage != 4 || exited.exit_code != 0 || exited.stderr_observed_bytes != 0
        || exited.stdout_truncated || exited.stderr_truncated
        || exited.stdout_observed_bytes != exited.stdout_retained_bytes
        || exited.descendants_extinct != 1 || exited.guest_process_extinct != 1
        || exited.backend_egress_revoked != 1
        || exited.stop_control_process_reaped != 1
        || exited.stop_control_process_group_extinct != 1
        || exited.guest_population_zero != 1
        || exited.container_vm_stopped != 1
        || deleted.absent != 1
        || specialized_worker_terminal_shape(exited.stdout_retained,
            exited.stdout_retained_bytes) != 0
        || plamen_broker_v2_sha256(exited.stdout_retained,
            exited.stdout_retained_bytes, result->guest_terminal_sha256) != 0
        || plamen_broker_v2_hmac_sha256(request->terminal_hmac_key,
            hmac_domain, sizeof(hmac_domain), exited.stdout_retained,
            exited.stdout_retained_bytes, hmac) != 0)
        goto done;
    result->version = PLAMEN_BROKER_V2_SPECIALIZED_WORKER_VERSION;
    result->created = created; result->started = started;
    result->exited = exited; memset(&exited, 0, sizeof(exited));
    result->deleted = deleted;
    memcpy(result->guest_terminal_hmac_sha256, hmac, 32);
    result->guest_terminal = result->exited.stdout_retained;
    result->guest_terminal_size = result->exited.stdout_retained_bytes;
    result->network_denied = 1U;
    result->population_zero = result->exited.descendants_extinct
        && result->exited.guest_process_extinct
        && result->exited.guest_population_zero
        && result->exited.container_vm_stopped;
    result->cleanup_complete = result->deleted.absent;
    if (specialized_worker_lifecycle_sha256(result,
            result->lifecycle_receipt_sha256) != 0) {
        plamen_broker_v2_effects_dispose_specialized_worker_result(result);
        goto done;
    }
    status = 0;
done:
    if (status != 0 && lifecycle != NULL && stage < 4) {
        struct plamen_broker_v2_apple_lifecycle_terminal_receipt cleanup_exit;
        struct plamen_broker_v2_apple_lifecycle_delete_receipt cleanup_delete;
        memset(&cleanup_exit, 0, sizeof(cleanup_exit));
        memset(&cleanup_delete, 0, sizeof(cleanup_delete));
        (void)plamen_broker_v2_apple_lifecycle_revoke_delete(lifecycle,
            &cleanup_exit, &cleanup_delete);
        plamen_broker_v2_apple_lifecycle_terminal_dispose(&cleanup_exit);
        cleanup_terminal = 1U;
    }
    if (lifecycle != NULL)
        (void)plamen_broker_v2_apple_lifecycle_close(lifecycle);
    if (state_fd >= 0) (void)close(state_fd);
    plamen_broker_v2_apple_lifecycle_terminal_dispose(&exited);
    if (status != 0 && result != NULL)
        plamen_broker_v2_effects_dispose_specialized_worker_result(result);
    plamen_broker_v2_secure_zero(&spec, sizeof(spec));
    plamen_broker_v2_secure_zero(&commitments, sizeof(commitments));
    plamen_broker_v2_secure_zero(&created, sizeof(created));
    plamen_broker_v2_secure_zero(&started, sizeof(started));
    plamen_broker_v2_secure_zero(&deleted, sizeof(deleted));
    plamen_broker_v2_secure_zero(context_sha256, sizeof(context_sha256));
    plamen_broker_v2_secure_zero(hmac, sizeof(hmac));
    plamen_broker_v2_secure_zero(container_id, sizeof(container_id));
    (void)cleanup_terminal;
    return status;
}

static int
specialized_contains_once(const uint8_t *bytes, size_t size,
    const char *fragment)
{
    const uint8_t *first;
    size_t fragment_size;
    if (bytes == NULL || fragment == NULL
        || (fragment_size = strlen(fragment)) == 0U)
        return 0;
    first = bounded_find(bytes, size, 0U, fragment, fragment_size);
    return first != NULL && bounded_find(bytes, size,
        (size_t)(first - bytes) + fragment_size, fragment, fragment_size)
        == NULL;
}

static int
specialized_hash_regular_fd(int descriptor, uint8_t output[32],
    uint64_t *byte_count)
{
    struct stat before, after;
    CC_SHA256_CTX digest;
    uint8_t buffer[65536];
    off_t offset = 0;
    ssize_t amount;
    int result = -1;
    if (output != NULL) memset(output, 0, 32);
    if (byte_count != NULL) *byte_count = 0;
    if (descriptor < 0 || output == NULL || byte_count == NULL
        || fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_nlink != 1 || before.st_size <= 0
        || before.st_size > (off_t)(512U * 1024U * 1024U)
        || (before.st_mode & 0022) != 0 || CC_SHA256_Init(&digest) != 1)
        goto done;
    while (offset < before.st_size) {
        size_t wanted = (size_t)(before.st_size - offset);
        if (wanted > sizeof(buffer)) wanted = sizeof(buffer);
        amount = pread(descriptor, buffer, wanted, offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0
            || CC_SHA256_Update(&digest, buffer, (CC_LONG)amount) != 1)
            goto done;
        offset += amount;
    }
    if (CC_SHA256_Final(output, &digest) != 1
        || fstat(descriptor, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_mode != after.st_mode || before.st_uid != after.st_uid
        || before.st_gid != after.st_gid || before.st_nlink != after.st_nlink
        || before.st_size != after.st_size
        || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
        || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
        || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec
        || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec)
        goto done;
    *byte_count = (uint64_t)before.st_size;
    result = 0;
done:
    plamen_broker_v2_secure_zero(buffer, sizeof(buffer));
    if (result != 0) memset(output, 0, 32);
    return result;
}

static int
specialized_json_safe_path(const char *path)
{
    size_t index, size;
    if (path == NULL || path[0] != '/'
        || (size = strlen(path)) == 0 || size >= PATH_MAX) return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)path[index];
        if (byte < 0x20 || byte > 0x7e || byte == '"' || byte == '\\')
            return 0;
    }
    return 1;
}

static int
specialized_extension_identity(
    struct plamen_broker_v2_effects_context *context, char path[PATH_MAX],
    uint8_t digest[32], uint64_t *byte_count)
{
    int library = -1, plamen = -1, extension = -1, result = -1;
    struct stat information;
    if (path != NULL) memset(path, 0, PATH_MAX);
    if (context == NULL || path == NULL || digest == NULL
        || byte_count == NULL || context->generation_fd < 0)
        return -1;
    library = openat(context->generation_fd, "lib",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (library >= 0)
        plamen = openat(library, "plamen",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (plamen >= 0)
        extension = openat(plamen,
            "_plamen_native_supervisor.cpython-312-darwin.so",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (extension < 0 || fstat(extension, &information) != 0
        || !S_ISREG(information.st_mode)
#ifdef F_GETPATH
        || fcntl(extension, F_GETPATH, path) != 0
#else
        || 1
#endif
        || path[0] != '/'
        || specialized_hash_regular_fd(extension, digest, byte_count) != 0)
        goto done;
    result = 0;
done:
    if (extension >= 0) (void)close(extension);
    if (plamen >= 0) (void)close(plamen);
    if (library >= 0) (void)close(library);
    if (result != 0) {
        memset(path, 0, PATH_MAX); memset(digest, 0, 32); *byte_count = 0;
    }
    return result;
}

static int
specialized_peer_identity_sha256(
    const struct plamen_broker_v2_effects_context *context, uint8_t output[32])
{
    uint8_t bytes[74];
    const struct plamen_broker_v2_peer_identity *peer;
    if (context == NULL || output == NULL) return -1;
    peer = &context->registration.launcher;
    memset(bytes, 0, sizeof(bytes));
    store_u64(bytes, peer->pid); store_u64(bytes + 8, peer->uid);
    store_u64(bytes + 16, peer->gid); store_u16(bytes + 24, peer->birth_kind);
    store_u64(bytes + 26, peer->birth_primary);
    store_u64(bytes + 34, peer->birth_secondary);
    memcpy(bytes + 42, peer->boot_id_sha256, 32);
    if (plamen_broker_v2_sha256(bytes, sizeof(bytes), output) != 0) {
        plamen_broker_v2_secure_zero(bytes, sizeof(bytes)); return -1;
    }
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    return all_zero(output) ? -1 : 0;
}

static int
specialized_evidence_begin(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    if (view == NULL || evidence == NULL
        || view->version != PLAMEN_BROKER_V2_TOOL_EFFECT_PLAN_VERSION)
        return -1;
    memset(evidence, 0, sizeof(*evidence));
    evidence->version = PLAMEN_BROKER_V2_TOOL_EFFECT_EVIDENCE_VERSION;
    evidence->lane = view->lane; evidence->method = view->method;
    memcpy(evidence->authority_binding_sha256,
        view->authority_binding_sha256, 32);
    memcpy(evidence->operation_nonce, view->operation_nonce, 32);
    memcpy(evidence->request_sha256, view->request_sha256, 32);
    memcpy(evidence->effects_context_sha256,
        view->effects_context_sha256, 32);
    return 0;
}

static int
specialized_durable_record(
    struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const uint8_t effect_receipt_sha256[32], uint8_t durable_sha256[32])
{
    uint8_t auxiliary_input[98], auxiliary[32], record[PROVIDER_EVIDENCE_SIZE];
    char nonce[65], name[96];
    int amount, result = -1;
    memset(auxiliary_input, 0, sizeof(auxiliary_input));
    memcpy(auxiliary_input, view->request_sha256, 32);
    memcpy(auxiliary_input + 32, view->operation_nonce, 32);
    memcpy(auxiliary_input + 64, view->effects_context_sha256, 32);
    store_u16(auxiliary_input + 96, view->method);
    encode_hex32(view->operation_nonce, nonce);
    amount = snprintf(name, sizeof(name), "specialized-%04x-%s.bin",
        (unsigned int)view->method, nonce);
    if (amount <= 0 || (size_t)amount >= sizeof(name)
        || plamen_broker_v2_sha256(auxiliary_input,
            sizeof(auxiliary_input), auxiliary) != 0
        || provider_evidence(context, name, (uint32_t)view->method,
            effect_receipt_sha256, auxiliary, 1, NULL, NULL) != 0)
        goto done;
    memset(record, 0, sizeof(record));
    memcpy(record, PROVIDER_EVIDENCE_MAGIC, 8);
    store_u32(record + 8, PLAMEN_BROKER_V2_EFFECTS_VERSION);
    store_u32(record + 12, (uint32_t)view->method);
    memcpy(record + 16, context->registration.audit_request_fingerprint, 32);
    memcpy(record + 48, context->authority_binding, 32);
    memcpy(record + 80, effect_receipt_sha256, 32);
    memcpy(record + 112, auxiliary, 32);
    if (plamen_broker_v2_sha256(record,
            PROVIDER_EVIDENCE_DIGEST_OFFSET, record + 160) != 0)
        goto done;
    memcpy(durable_sha256, record + 160, 32); result = 0;
done:
    plamen_broker_v2_secure_zero(auxiliary_input, sizeof(auxiliary_input));
    plamen_broker_v2_secure_zero(auxiliary, sizeof(auxiliary));
    plamen_broker_v2_secure_zero(record, sizeof(record));
    plamen_broker_v2_secure_zero(nonce, sizeof(nonce));
    return result;
}

static int
specialized_finish_terminal(
    struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence,
    uint8_t *terminal, size_t terminal_size, int durable)
{
    uint8_t effect_receipt_sha256[32];
    uint8_t durable_operation_sha256[32];
    int result = -1;
    memset(effect_receipt_sha256, 0, sizeof(effect_receipt_sha256));
    memset(durable_operation_sha256, 0,
        sizeof(durable_operation_sha256));
    if (terminal == NULL || terminal_size < 2U
        || specialized_evidence_begin(view, evidence) != 0
        || plamen_broker_v2_sha256(terminal, terminal_size,
            effect_receipt_sha256) != 0)
        goto done;
    if (durable) {
        if (specialized_durable_record(context, view,
                effect_receipt_sha256,
                durable_operation_sha256) != 0)
            goto done;
    }
    memcpy(evidence->effect_receipt_sha256,
        effect_receipt_sha256, 32);
    if (durable) {
        memcpy(evidence->durable_operation_sha256,
            durable_operation_sha256, 32);
        evidence->durable_operation = 1U;
    }
    evidence->terminal = terminal; evidence->terminal_size = terminal_size;
    evidence->effect_authenticated = 1U; evidence->effect_completed = 1U;
    result = 0;
done:
    plamen_broker_v2_secure_zero(effect_receipt_sha256,
        sizeof(effect_receipt_sha256));
    plamen_broker_v2_secure_zero(durable_operation_sha256,
        sizeof(durable_operation_sha256));
    if (result != 0)
        plamen_broker_v2_secure_zero(evidence, sizeof(*evidence));
    return result;
}

static int
specialized_runtime_identity(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence, int managed)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    char path[PATH_MAX], extension_hex[65], deployment_hex[65];
    char runtime_hex[65], peer_hex[65], custody_hex[65];
    uint8_t extension[32], peer[32], custody[32], custody_input[64];
    uint8_t authority_preimage[256], rosetta[32], network[32];
    uint8_t guest_authority[PLAMEN_BROKER_V2_TOOL_JSON_MAX], guest_digest[32];
    struct plamen_broker_v2_specialized_apple_runtime managed_runtime;
    struct plamen_broker_v2_tool_custody_capability_input guest_input;
    uint8_t *terminal = NULL;
    size_t terminal_size = 0, guest_size = 0, authority_size = 0;
    uint64_t bytes = 0;
    int status = -1;
    memset(path, 0, sizeof(path)); memset(extension, 0, sizeof(extension));
    memset(peer, 0, sizeof(peer)); memset(custody, 0, sizeof(custody));
    memset(custody_input, 0, sizeof(custody_input));
    memset(authority_preimage, 0, sizeof(authority_preimage));
    memset(rosetta, 0, sizeof(rosetta)); memset(network, 0, sizeof(network));
    memset(guest_authority, 0, sizeof(guest_authority));
    memset(guest_digest, 0, sizeof(guest_digest));
    memset(&managed_runtime, 0, sizeof(managed_runtime));
    memset(&guest_input, 0, sizeof(guest_input));
    if (context == NULL || view == NULL || evidence == NULL
        || specialized_extension_identity(context, path, extension, &bytes) != 0
        || !specialized_json_safe_path(path)
        || specialized_peer_identity_sha256(context, peer) != 0)
        goto done;
    memcpy(custody_input, context->authority_binding, 32);
    memcpy(custody_input + 32,
        context->registration.installed_closure_sha256, 32);
    if (plamen_broker_v2_sha256(custody_input,
            sizeof(custody_input), custody) != 0) goto done;
    encode_hex32(extension, extension_hex);
    encode_hex32(context->registration.committed_audit_generation_sha256,
        deployment_hex);
    encode_hex32(context->commitment.runtime_closure_sha256, runtime_hex);
    encode_hex32(peer, peer_hex); encode_hex32(custody, custody_hex);
    if (managed) {
        static const char rosetta_domain[] =
            "PLAMEN-MANAGED-EVM-ROSETTA-AUTHORITY-V1\0";
        static const char network_domain[] =
            "PLAMEN-MANAGED-EVM-NETWORK-AUTHORITY-V1\0";
        char managed_python_hex[65];
        if (!context->provider_admission_present
            || plamen_broker_v2_apple_container_receipt_validate(
                &context->provider_admission) != 0
            || context->specialized_runtime == NULL
            || plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
                context->specialized_runtime,
                PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM,
                "managed_python", &managed_runtime) != 0)
            goto done;
        memcpy(authority_preimage + authority_size, rosetta_domain,
            sizeof(rosetta_domain)); authority_size += sizeof(rosetta_domain);
        memcpy(authority_preimage + authority_size,
            context->provider_admission.admission_sha256, 32U);
        authority_size += 32U;
        memcpy(authority_preimage + authority_size,
            managed_runtime.runtime_manifest_sha256, 32U);
        authority_size += 32U;
        if (plamen_broker_v2_sha256(authority_preimage, authority_size,
                rosetta) != 0) goto done;
        authority_size = 0U;
        memcpy(authority_preimage + authority_size, network_domain,
            sizeof(network_domain)); authority_size += sizeof(network_domain);
        memcpy(authority_preimage + authority_size,
            context->provider_admission.admission_sha256, 32U);
        authority_size += 32U;
        memcpy(authority_preimage + authority_size,
            context->authority_binding, 32U); authority_size += 32U;
        if (plamen_broker_v2_sha256(authority_preimage, authority_size,
                network) != 0) goto done;
        guest_input.version = PLAMEN_BROKER_V2_TOOL_CUSTODY_VERSION;
        guest_input.runtime_image_reference =
            context->provider_admission.runtime_image_reference;
        memcpy(guest_input.image_closure_sha256,
            context->provider_admission.image_closure_sha256, 32U);
        memcpy(guest_input.provider_admission_sha256,
            context->provider_admission.admission_sha256, 32U);
        memcpy(guest_input.rosetta_authority_sha256, rosetta, 32U);
        memcpy(guest_input.network_isolation_authority_sha256, network, 32U);
        memcpy(guest_input.custody_receipt_sha256, custody, 32U);
        guest_input.rosetta_required = 1U;
        if (plamen_broker_v2_tool_custody_render_apple_authority(
                &guest_input, guest_authority, sizeof(guest_authority),
                &guest_size, guest_digest) != 0)
            goto done;
        encode_hex32(managed_runtime.tool_image_member_sha256,
            managed_python_hex);
        if (format_alloc(&terminal, &terminal_size,
                "{\"broker_peer_identity_sha256\":\"%s\",\"extension_byte_count\":%llu,\"extension_path\":\"%s\",\"extension_sha256\":\"%s\",\"guest_execution_authority\":%.*s,\"managed_python_sha256\":\"%s\",\"managed_python_size\":%llu,\"managed_toolchain_custody_sha256\":\"%s\",\"native_deployment_receipt_sha256\":\"%s\",\"native_interpreter_probe\":{\"base_prefix\":\"/usr/local/lib/plamen/python\",\"executable\":\"/usr/local/lib/plamen/python/bin/python3.12\",\"implementation\":\"CPython\",\"machine\":\"x86_64\",\"platlib\":\"/usr/local/lib/plamen/python/lib/python3.12/site-packages\",\"prefix\":\"/usr/local/lib/plamen/python\",\"purelib\":\"/usr/local/lib/plamen/python/lib/python3.12/site-packages\",\"sys_platform\":\"linux\",\"version\":\"3.12.12\",\"version_info\":[3,12,12]},\"platform\":\"MACOS\",\"runtime_closure_sha256\":\"%s\",\"schema\":\"plamen.managed-evm-toolchain-runtime-identity.v1\"}",
                peer_hex, (unsigned long long)bytes, path, extension_hex,
                (int)guest_size, guest_authority, managed_python_hex,
                (unsigned long long)managed_runtime.tool_image_member_size,
                custody_hex, deployment_hex, runtime_hex) != 0)
            goto done;
    } else if (format_alloc(&terminal, &terminal_size,
            "{\"broker_peer_identity_sha256\":\"%s\",\"extension_byte_count\":%llu,\"extension_path\":\"%s\",\"extension_sha256\":\"%s\",\"native_deployment_receipt_sha256\":\"%s\",\"platform\":\"MACOS\",\"runtime_closure_sha256\":\"%s\",\"schema\":\"plamen.darwin-tool-runtime-identity.v1\"}",
            peer_hex, (unsigned long long)bytes, path, extension_hex,
            deployment_hex, runtime_hex) != 0) goto done;
    if (specialized_finish_terminal(context, view, evidence,
            terminal, terminal_size, 0) != 0) goto done;
    terminal = NULL; status = 0;
done:
    if (terminal != NULL) {
        plamen_broker_v2_secure_zero(terminal, terminal_size); free(terminal);
    }
    plamen_broker_v2_secure_zero(path, sizeof(path));
    plamen_broker_v2_secure_zero(extension, sizeof(extension));
    plamen_broker_v2_secure_zero(peer, sizeof(peer));
    plamen_broker_v2_secure_zero(custody, sizeof(custody));
    plamen_broker_v2_secure_zero(custody_input, sizeof(custody_input));
    plamen_broker_v2_secure_zero(authority_preimage,
        sizeof(authority_preimage));
    plamen_broker_v2_secure_zero(rosetta, sizeof(rosetta));
    plamen_broker_v2_secure_zero(network, sizeof(network));
    plamen_broker_v2_secure_zero(guest_authority, sizeof(guest_authority));
    plamen_broker_v2_secure_zero(guest_digest, sizeof(guest_digest));
    plamen_broker_v2_secure_zero(&managed_runtime, sizeof(managed_runtime));
    plamen_broker_v2_secure_zero(&guest_input, sizeof(guest_input));
    return status;
}

static int
specialized_durable_capability(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence,
    const char *required_schema, const char *receipt_schema,
    int require_provider)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    uint8_t *terminal = NULL;
    size_t terminal_size = 0;
    char request_hex[65];
    int status = -1;
    if (context == NULL || view == NULL || evidence == NULL
        || required_schema == NULL || receipt_schema == NULL
        || (require_provider && (!context->provider_admission_present
            || plamen_broker_v2_apple_container_receipt_validate(
                &context->provider_admission) != 0))
        || !specialized_contains_once(view->payload, view->payload_size,
            required_schema))
        return -1;
    encode_hex32(view->request_sha256, request_hex);
    if (format_alloc(&terminal, &terminal_size,
            "{\"request_sha256\":\"%s\",\"schema\":\"%s\"}",
            request_hex, receipt_schema) != 0
        || specialized_finish_terminal(context, view, evidence,
            terminal, terminal_size, 1) != 0)
        goto done;
    terminal = NULL; status = 0;
done:
    if (terminal != NULL) {
        plamen_broker_v2_secure_zero(terminal, terminal_size); free(terminal);
    }
    plamen_broker_v2_secure_zero(request_hex, sizeof(request_hex));
    return status;
}

static int specialized_js_authenticate(void *context,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{ return specialized_durable_capability(context, view, evidence,
    "\"schema\":\"plamen.js-dependency-native-admission.v2\"",
    "plamen.js-dependency-materializer-session.v1", 0); }

/* JS identity additionally requires the installed bootstrap anchor and source
 * census, neither of which is present in the authenticated generation ABI. */
static int specialized_js_runtime_identity(void *context,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{ (void)context; (void)view; (void)evidence; return -1; }

static int specialized_js_prepare(void *context,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{ return specialized_durable_capability(context, view, evidence,
    "\"schema\":\"plamen.js-dependency-native-request.v2\"",
    "plamen.js-dependency-materializer-prepare.v1", 0); }

static int specialized_run_worker_adapter(void *opaque,
    const struct plamen_broker_v2_specialized_worker_request *request,
    struct plamen_broker_v2_specialized_worker_result *result)
{
    return plamen_broker_v2_effects_run_specialized_worker_locked(opaque,
        request, result);
}

static int specialized_js_execute(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    struct plamen_broker_v2_specialized_apple_effect_execution execution;
    if (context == NULL || context->magic != EFFECTS_MAGIC || view == NULL
        || evidence == NULL || context->active_specialized_store == NULL
        || context->specialized_runtime == NULL
        || all_zero(context->active_specialized_session_key))
        return -1;
    memset(&execution, 0, sizeof(execution));
    execution.version =
        PLAMEN_BROKER_V2_SPECIALIZED_APPLE_EFFECT_EXECUTION_VERSION;
    execution.store = context->active_specialized_store;
    execution.runtime_handoff = context->specialized_runtime;
    execution.view = view;
    execution.session_key = context->active_specialized_session_key;
    execution.native_effects_context = context;
    execution.run = specialized_run_worker_adapter;
    execution.dispose_result =
        plamen_broker_v2_effects_dispose_specialized_worker_result;
    execution.render_terminal =
        plamen_broker_v2_specialized_js_method_terminal_render;
    return plamen_broker_v2_specialized_apple_effect_execute_deny_all(
        &execution, evidence);
}

static int specialized_snapshot_execute(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    struct plamen_broker_v2_specialized_apple_effect_execution execution;
    if (context == NULL || context->magic != EFFECTS_MAGIC || view == NULL
        || evidence == NULL || context->active_specialized_store == NULL
        || context->specialized_runtime == NULL
        || all_zero(context->active_specialized_session_key)
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        || view->method != PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE)
        return -1;
    memset(&execution, 0, sizeof(execution));
    execution.version =
        PLAMEN_BROKER_V2_SPECIALIZED_APPLE_EFFECT_EXECUTION_VERSION;
    execution.store = context->active_specialized_store;
    execution.runtime_handoff = context->specialized_runtime;
    execution.view = view;
    execution.session_key = context->active_specialized_session_key;
    execution.native_effects_context = context;
    execution.run = specialized_run_worker_adapter;
    execution.dispose_result =
        plamen_broker_v2_effects_dispose_specialized_worker_result;
    execution.render_terminal =
        plamen_broker_v2_specialized_snapshot_method_terminal_render;
    return plamen_broker_v2_specialized_apple_effect_execute_deny_all(
        &execution, evidence);
}

static int specialized_projection_commit(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    struct plamen_broker_v2_specialized_apple_effect_execution execution;
    if (context == NULL || context->magic != EFFECTS_MAGIC || view == NULL
        || evidence == NULL || context->active_specialized_store == NULL
        || context->specialized_runtime == NULL
        || all_zero(context->active_specialized_session_key)
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
        || view->method != PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT)
        return -1;
    memset(&execution, 0, sizeof(execution));
    execution.version =
        PLAMEN_BROKER_V2_SPECIALIZED_APPLE_EFFECT_EXECUTION_VERSION;
    execution.store = context->active_specialized_store;
    execution.runtime_handoff = context->specialized_runtime;
    execution.view = view;
    execution.session_key = context->active_specialized_session_key;
    execution.native_effects_context = context;
    execution.run = specialized_run_worker_adapter;
    execution.dispose_result =
        plamen_broker_v2_effects_dispose_specialized_worker_result;
    /* Projection rendering is performed by the exact lane branch after the
     * authenticated worker observation is verified.  A non-null callback is
     * retained in the shared adapter ABI and is never invoked for this lane. */
    execution.render_terminal =
        plamen_broker_v2_specialized_snapshot_method_terminal_render;
    return plamen_broker_v2_specialized_apple_effect_execute_deny_all(
        &execution, evidence);
}

static int specialized_projection_project(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    uint8_t *terminal;
    if (context == NULL || context->magic != EFFECTS_MAGIC || view == NULL
        || evidence == NULL
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
        || view->method != PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_PROJECT
        || view->payload == NULL || view->payload_size < 2U
        || view->payload_size > PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_TERMINAL_MAX
        || view->payload[view->payload_size - 1U] == '\n'
        || !specialized_contains_once(view->payload, view->payload_size,
            "\"schema\":\"plamen.private-analysis-projection-custody.v1\""))
        return -1;
    terminal = malloc(view->payload_size);
    if (terminal == NULL) return -1;
    memcpy(terminal, view->payload, view->payload_size);
    if (specialized_finish_terminal(context, view, evidence,
            terminal, view->payload_size, 1) != 0) {
        plamen_broker_v2_secure_zero(terminal, view->payload_size);
        free(terminal);
        return -1;
    }
    return 0;
}

static int specialized_projection_recover(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    struct plamen_broker_v2_specialized_effect_completion completion;
    uint8_t *terminal = NULL;
    size_t terminal_size = 0U;
    int status = -1;
    memset(&completion, 0, sizeof(completion));
    if (context == NULL || context->magic != EFFECTS_MAGIC || view == NULL
        || evidence == NULL || context->active_specialized_store == NULL
        || plamen_broker_v2_specialized_apple_effect_recover_projection(
            context->active_specialized_store, view, &completion,
            &terminal, &terminal_size) != 0
        || specialized_finish_terminal(context, view, evidence,
            terminal, terminal_size, 1) != 0)
        goto done;
    terminal = NULL;
    terminal_size = 0U;
    status = 0;
done:
    if (terminal != NULL) {
        plamen_broker_v2_secure_zero(terminal, terminal_size);
        free(terminal);
    }
    plamen_broker_v2_secure_zero(&completion, sizeof(completion));
    return status;
}

static int specialized_fuzz_state_directory(
    struct plamen_broker_v2_effects_context *context, const char *container_id)
{
    char name[96]; struct stat status; int amount, descriptor = -1;
    if (context == NULL || container_id == NULL
        || strncmp(container_id, "plamen-", 7U) != 0)
        return -1;
    amount = snprintf(name, sizeof(name), "fuzz-%s", container_id + 7U);
    if (amount <= 0 || (size_t)amount >= sizeof(name)) return -1;
    if (mkdirat(context->state_directory_fd, name, 0700) != 0
        && errno != EEXIST) return -1;
    descriptor = openat(context->state_directory_fd, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &status) != 0
        || !S_ISDIR(status.st_mode) || status.st_uid != geteuid()
        || (status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        if (descriptor >= 0) (void)close(descriptor);
        return -1;
    }
    return descriptor;
}

static int specialized_fuzz_prepare(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    static const char *const targets[4] = {
        "/workspace/source", "/workspace/scratch",
        "/workspace/state", "/workspace/project"
    };
    static const uint16_t purposes[4] = {
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT
    };
    static const uint8_t readonly[4] = {1U, 0U, 0U, 1U};
    struct plamen_broker_v2_effects_context *context = opaque;
    struct plamen_broker_v2_fuzz_campaign_request_storage storage;
    struct plamen_broker_v2_fuzz_campaign_authority authority;
    struct plamen_broker_v2_specialized_apple_runtime runtime;
    struct plamen_broker_v2_apple_lifecycle_mount mounts[4];
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    char paths[4][PATH_MAX], guest[65], launch[65], mount[65], admission[65];
    char native_provider[65], native_spec[65], request_hex[65];
    char secure_preflight[65], secure_provider[65], secure_spec[65];
    uint8_t *terminal = NULL; size_t terminal_size = 0U, index;
    const char *member; int stdin_fd = -1, status = -1;
    memset(&storage, 0, sizeof(storage)); memset(&authority, 0, sizeof(authority));
    memset(&runtime, 0, sizeof(runtime)); memset(mounts, 0, sizeof(mounts));
    memset(&commitments, 0, sizeof(commitments)); memset(paths, 0, sizeof(paths));
    if (context == NULL || context->magic != EFFECTS_MAGIC || view == NULL
        || evidence == NULL || context->specialized_runtime == NULL
        || !context->provider_admission_present
        || plamen_broker_v2_apple_container_receipt_validate(
            &context->provider_admission) != 0
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        || view->method != PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE
        || view->fd_count != 4U || view->fds == NULL || view->descriptors == NULL
        || plamen_broker_v2_fuzz_campaign_request_decode(view, &storage) != 0
        || !constant_equal(storage.request.authority_sha256,
            context->registration.audit_request_fingerprint, 32U))
        goto done;
    member = storage.request.tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE
        ? "forge" : "medusa";
    if (plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
            context->specialized_runtime,
            PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
            member, &runtime) != 0) goto done;
    for (index = 0U; index < 4U; ++index) {
        struct stat descriptor;
        if (view->fds[index] < 0
            || view->descriptors[index].purpose != purposes[index]
            || view->descriptors[index].target != index + 1U
            || view->descriptors[index].access_mode
                != (readonly[index] ? PLAMEN_BROKER_V2_FD_READ
                                    : PLAMEN_BROKER_V2_FD_READ_WRITE)
            || fstat(view->fds[index], &descriptor) != 0
            || !S_ISDIR(descriptor.st_mode)
#ifdef F_GETPATH
            || fcntl(view->fds[index], F_GETPATH, paths[index]) != 0
#else
            || 1
#endif
            || paths[index][0] != '/' || !specialized_json_safe_path(paths[index]))
            goto done;
        mounts[index].source_fd = view->fds[index];
        mounts[index].source_path = paths[index];
        mounts[index].target_path = targets[index];
        memcpy(mounts[index].expected_identity_sha256,
            view->descriptors[index].identity, 32U);
        mounts[index].readonly = readonly[index];
    }
    storage.request.mounts = mounts; storage.request.mount_count = 4U;
    stdin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (stdin_fd < 0) goto done;
    authority.version = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_VERSION;
    authority.cli_fd = context->authority_fds[PLAMEN_BROKER_V2_RETAINED_PROVIDER];
    authority.cli_path = PLAMEN_APPLE_CLI_PATH;
    authority.cwd_fd = context->generation_fd; authority.stdin_fd = stdin_fd;
    authority.state_directory_fd = context->state_directory_fd;
    authority.admission = &context->provider_admission;
    authority.custody_client = context->custody_client;
    memcpy(authority.authority_binding_sha256, context->authority_binding, 32U);
    memcpy(authority.provider_preflight_sha256,
        storage.request.provider_preflight_sha256, 32U);
    if (storage.request.tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE)
        memcpy(authority.forge_executable_sha256,
            runtime.tool_image_member_sha256, 32U);
    else
        memcpy(authority.medusa_executable_sha256,
            runtime.tool_image_member_sha256, 32U);
    authority.runtime_image_reference =
        context->provider_admission.runtime_image_reference;
    authority.cpus = 2U; authority.memory_bytes = PROVIDER_MEMORY_BYTES;
    if (plamen_broker_v2_fuzz_campaign_prepare(
            &authority, &storage.request, &commitments) != 0) goto done;
    encode_hex32(storage.request.guest_executable_sha256, guest);
    encode_hex32(commitments.launch_request_sha256, launch);
    encode_hex32(commitments.mount_roster_sha256, mount);
    encode_hex32(context->provider_admission.admission_sha256, admission);
    encode_hex32(context->provider_admission.provider_provenance_sha256,
        native_provider);
    encode_hex32(commitments.spec_sha256, native_spec);
    encode_hex32(view->request_sha256, request_hex);
    encode_hex32(storage.request.provider_preflight_sha256, secure_preflight);
    encode_hex32(storage.request.provider_provenance_sha256, secure_provider);
    encode_hex32(storage.request.spec_sha256, secure_spec);
    if (format_alloc(&terminal, &terminal_size,
            "{\"guest_executable_sha256\":\"%s\",\"native_launch_request_sha256\":\"%s\",\"native_mount_roster_sha256\":\"%s\",\"native_provider_admission_sha256\":\"%s\",\"native_provider_provenance_sha256\":\"%s\",\"native_spec_sha256\":\"%s\",\"request_sha256\":\"%s\",\"schema\":\"plamen.apple-fuzz-campaign-native-prepare.v1\",\"secure_launcher_provider_preflight_sha256\":\"%s\",\"secure_launcher_provider_provenance_sha256\":\"%s\",\"secure_launcher_spec_sha256\":\"%s\"}",
            guest, launch, mount, admission, native_provider, native_spec,
            request_hex, secure_preflight, secure_provider, secure_spec) != 0
        || specialized_finish_terminal(context, view, evidence,
            terminal, terminal_size, 1) != 0) goto done;
    terminal = NULL; status = 0;
done:
    if (terminal != NULL) {
        plamen_broker_v2_secure_zero(terminal, terminal_size); free(terminal);
    }
    if (stdin_fd >= 0) (void)close(stdin_fd);
    plamen_broker_v2_secure_zero(&storage, sizeof(storage));
    plamen_broker_v2_secure_zero(&authority, sizeof(authority));
    plamen_broker_v2_secure_zero(&runtime, sizeof(runtime));
    plamen_broker_v2_secure_zero(mounts, sizeof(mounts));
    plamen_broker_v2_secure_zero(&commitments, sizeof(commitments));
    plamen_broker_v2_secure_zero(paths, sizeof(paths));
    plamen_broker_v2_secure_zero(guest, sizeof(guest));
    plamen_broker_v2_secure_zero(launch, sizeof(launch));
    plamen_broker_v2_secure_zero(mount, sizeof(mount));
    plamen_broker_v2_secure_zero(admission, sizeof(admission));
    plamen_broker_v2_secure_zero(native_provider, sizeof(native_provider));
    plamen_broker_v2_secure_zero(native_spec, sizeof(native_spec));
    plamen_broker_v2_secure_zero(request_hex, sizeof(request_hex));
    plamen_broker_v2_secure_zero(secure_preflight, sizeof(secure_preflight));
    plamen_broker_v2_secure_zero(secure_provider, sizeof(secure_provider));
    plamen_broker_v2_secure_zero(secure_spec, sizeof(secure_spec));
    if (status != 0) plamen_broker_v2_secure_zero(evidence, sizeof(*evidence));
    return status;
}

static int specialized_fuzz_campaign_execute(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    static const char *const targets[4] = {
        "/workspace/source", "/workspace/scratch",
        "/workspace/state", "/workspace/project"
    };
    static const uint16_t purposes[4] = {
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT
    };
    static const uint8_t readonly[4] = {1U, 0U, 0U, 1U};
    static const uint8_t network_domain[] =
        "PLAMEN-FUZZ-CAMPAIGN-NETWORK-NONE-V1\0";
    struct plamen_broker_v2_effects_context *context = opaque;
    struct plamen_broker_v2_fuzz_campaign_request_storage storage;
    struct plamen_broker_v2_fuzz_campaign_authority authority;
    struct plamen_broker_v2_fuzz_campaign_result result;
    struct plamen_broker_v2_specialized_apple_runtime runtime;
    struct plamen_broker_v2_apple_lifecycle_mount mounts[4];
    uint8_t network_preimage[sizeof(network_domain) + 64U], network_sha256[32];
    uint8_t *terminal = NULL; size_t terminal_size = 0U, index;
    int stdin_fd = -1, state_fd = -1, status = -1;
    char paths[4][PATH_MAX]; const char *member;
    memset(&storage, 0, sizeof(storage)); memset(&authority, 0, sizeof(authority));
    memset(&result, 0, sizeof(result)); memset(&runtime, 0, sizeof(runtime));
    memset(mounts, 0, sizeof(mounts)); memset(paths, 0, sizeof(paths));
    memset(network_preimage, 0, sizeof(network_preimage));
    memset(network_sha256, 0, sizeof(network_sha256));
    if (context == NULL || context->magic != EFFECTS_MAGIC || view == NULL
        || evidence == NULL || context->specialized_runtime == NULL
        || !context->provider_admission_present
        || plamen_broker_v2_apple_container_receipt_validate(
            &context->provider_admission) != 0
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        || view->method != PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE
        || view->fd_count != 4U || view->fds == NULL
        || view->descriptors == NULL
        || plamen_broker_v2_fuzz_campaign_request_decode(view, &storage) != 0
        || !constant_equal(storage.request.authority_sha256,
            context->registration.audit_request_fingerprint, 32U))
        goto done;
    member = storage.request.tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE
        ? "forge" : "medusa";
    if (plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
            context->specialized_runtime,
            PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
            member, &runtime) != 0)
        goto done;
    for (index = 0U; index < 4U; ++index) {
        struct stat descriptor;
        if (view->fds[index] < 0
            || view->descriptors[index].purpose != purposes[index]
            || view->descriptors[index].target != index + 1U
            || view->descriptors[index].access_mode
                != (readonly[index] ? PLAMEN_BROKER_V2_FD_READ
                                    : PLAMEN_BROKER_V2_FD_READ_WRITE)
            || fstat(view->fds[index], &descriptor) != 0
            || !S_ISDIR(descriptor.st_mode)
#ifdef F_GETPATH
            || fcntl(view->fds[index], F_GETPATH, paths[index]) != 0
#else
            || 1
#endif
            || paths[index][0] != '/' || !specialized_json_safe_path(paths[index]))
            goto done;
        mounts[index].source_fd = view->fds[index];
        mounts[index].source_path = paths[index];
        mounts[index].target_path = targets[index];
        memcpy(mounts[index].expected_identity_sha256,
            view->descriptors[index].identity, 32U);
        mounts[index].readonly = readonly[index];
    }
    storage.request.mounts = mounts; storage.request.mount_count = 4U;
    stdin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    state_fd = specialized_fuzz_state_directory(context,
        storage.request.container_id);
    if (stdin_fd < 0 || state_fd < 0) goto done;
    authority.version = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_VERSION;
    authority.cli_fd =
        context->authority_fds[PLAMEN_BROKER_V2_RETAINED_PROVIDER];
    authority.cli_path = PLAMEN_APPLE_CLI_PATH;
    authority.cwd_fd = context->generation_fd; authority.stdin_fd = stdin_fd;
    authority.state_directory_fd = state_fd;
    authority.admission = &context->provider_admission;
    authority.custody_client = context->custody_client;
    memcpy(authority.authority_binding_sha256,
        context->authority_binding, 32U);
    /* Compatible host preflight provenance and the native retained admission
     * are distinct authorities.  The request binds the former; spec
     * derivation consumes the latter through authority.admission. */
    memcpy(authority.provider_preflight_sha256,
        storage.request.provider_preflight_sha256, 32U);
    if (storage.request.tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE)
        memcpy(authority.forge_executable_sha256,
            runtime.tool_image_member_sha256, 32U);
    else
        memcpy(authority.medusa_executable_sha256,
            runtime.tool_image_member_sha256, 32U);
    authority.runtime_image_reference =
        context->provider_admission.runtime_image_reference;
    authority.cpus = 2U; authority.memory_bytes = PROVIDER_MEMORY_BYTES;
    memcpy(network_preimage, network_domain, sizeof(network_domain));
    memcpy(network_preimage + sizeof(network_domain),
        context->provider_admission.admission_sha256, 32U);
    if (plamen_broker_v2_fuzz_campaign_execute(&authority,
            &storage.request, &result) != 0)
        goto done;
    memcpy(network_preimage + sizeof(network_domain) + 32U,
        result.lifecycle_sha256, 32U);
    if (plamen_broker_v2_sha256(network_preimage,
            sizeof(network_preimage), network_sha256) != 0
        || plamen_broker_v2_fuzz_campaign_result_render(&storage.request,
            &authority, &result, &terminal, &terminal_size) != 0
        || specialized_finish_terminal(context, view, evidence,
            terminal, terminal_size, 1) != 0)
        goto done;
    terminal = NULL;
    memcpy(evidence->lifecycle_receipt_sha256,
        result.lifecycle_sha256, 32U);
    memcpy(evidence->network_policy_sha256, network_sha256, 32U);
    evidence->provider_authenticated = 1U;
    evidence->network_policy_enforced = 1U;
    evidence->population_zero = 1U; evidence->cleanup_complete = 1U;
    status = 0;
done:
    if (terminal != NULL) {
        plamen_broker_v2_secure_zero(terminal, terminal_size); free(terminal);
    }
    plamen_broker_v2_fuzz_campaign_result_dispose(&result);
    if (state_fd >= 0) (void)close(state_fd);
    if (stdin_fd >= 0) (void)close(stdin_fd);
    plamen_broker_v2_secure_zero(&storage, sizeof(storage));
    plamen_broker_v2_secure_zero(&authority, sizeof(authority));
    plamen_broker_v2_secure_zero(&runtime, sizeof(runtime));
    plamen_broker_v2_secure_zero(mounts, sizeof(mounts));
    plamen_broker_v2_secure_zero(paths, sizeof(paths));
    plamen_broker_v2_secure_zero(network_preimage, sizeof(network_preimage));
    plamen_broker_v2_secure_zero(network_sha256, sizeof(network_sha256));
    if (status != 0) plamen_broker_v2_secure_zero(evidence, sizeof(*evidence));
    return status;
}

static int specialized_fuzz_service_admit(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    static const char *const targets[4] = {
        "/workspace/source", "/workspace/scratch",
        "/workspace/state", "/workspace/project"
    };
    static const uint16_t purposes[4] = {
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT
    };
    static const uint8_t readonly[4] = {1U, 0U, 0U, 1U};
    struct plamen_broker_v2_effects_context *context = opaque;
    struct plamen_broker_v2_fuzz_service_admission_storage storage;
    struct plamen_broker_v2_fuzz_campaign_authority authority;
    struct plamen_broker_v2_fuzz_service_admission_receipt receipt;
    struct plamen_broker_v2_specialized_apple_runtime runtime;
    struct plamen_broker_v2_apple_lifecycle_mount mounts[4];
    uint8_t *terminal = NULL; size_t terminal_size = 0U, index;
    char paths[4][PATH_MAX]; const char *member; int stdin_fd = -1, status = -1;
    memset(&storage, 0, sizeof(storage)); memset(&authority, 0, sizeof(authority));
    memset(&receipt, 0, sizeof(receipt)); memset(&runtime, 0, sizeof(runtime));
    memset(mounts, 0, sizeof(mounts)); memset(paths, 0, sizeof(paths));
    if (context == NULL || context->magic != EFFECTS_MAGIC || view == NULL
        || evidence == NULL || context->specialized_runtime == NULL
        || !context->provider_admission_present
        || context->fuzz_service_session != NULL
        || context->fuzz_service_continuation != NULL
        || plamen_broker_v2_fuzz_service_admission_request_decode(
            view, &storage) != 0
        || view->fd_count != 4U || view->fds == NULL
        || view->descriptors == NULL) goto done;
    member = storage.request.tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE
        ? "forge" : "medusa";
    if (plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
            context->specialized_runtime,
            PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
            member, &runtime) != 0) goto done;
    for (index = 0U; index < 4U; ++index) {
        struct stat descriptor;
        if (view->fds[index] < 0
            || view->descriptors[index].purpose != purposes[index]
            || view->descriptors[index].target != index + 1U
            || view->descriptors[index].access_mode
                != (readonly[index] ? PLAMEN_BROKER_V2_FD_READ
                                    : PLAMEN_BROKER_V2_FD_READ_WRITE)
            || fstat(view->fds[index], &descriptor) != 0
            || !S_ISDIR(descriptor.st_mode)
#ifdef F_GETPATH
            || fcntl(view->fds[index], F_GETPATH, paths[index]) != 0
#else
            || 1
#endif
            || paths[index][0] != '/' || !specialized_json_safe_path(paths[index]))
            goto done;
        mounts[index].source_fd = view->fds[index];
        mounts[index].source_path = paths[index];
        mounts[index].target_path = targets[index];
        memcpy(mounts[index].expected_identity_sha256,
            view->descriptors[index].identity, 32U);
        mounts[index].readonly = readonly[index];
    }
    stdin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (stdin_fd < 0) goto done;
    authority.version = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_VERSION;
    authority.cli_fd = context->authority_fds[PLAMEN_BROKER_V2_RETAINED_PROVIDER];
    authority.cli_path = PLAMEN_APPLE_CLI_PATH;
    authority.cwd_fd = context->generation_fd; authority.stdin_fd = stdin_fd;
    authority.state_directory_fd = context->state_directory_fd;
    authority.admission = &context->provider_admission;
    authority.custody_client = context->custody_client;
    memcpy(authority.authority_binding_sha256,
        context->registration.audit_request_fingerprint, 32U);
    if (storage.request.tool == PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE)
        memcpy(authority.forge_executable_sha256,
            runtime.tool_image_member_sha256, 32U);
    else
        memcpy(authority.medusa_executable_sha256,
            runtime.tool_image_member_sha256, 32U);
    authority.runtime_image_reference =
        context->provider_admission.runtime_image_reference;
    authority.cpus = 2U; authority.memory_bytes = PROVIDER_MEMORY_BYTES;
    if (plamen_broker_v2_fuzz_service_acquire(&authority,
            &context->fuzz_service_session) != 0
        || plamen_broker_v2_fuzz_service_admit(
            context->fuzz_service_session, &storage.request, mounts, 4U,
            &receipt, &context->fuzz_service_continuation) != 0
        || plamen_broker_v2_fuzz_service_project_secure_receipt(
            context->fuzz_service_continuation,
            &terminal, &terminal_size) != 0
        || specialized_finish_terminal(context, view, evidence,
            terminal, terminal_size, 1) != 0) goto done;
    terminal = NULL; status = 0;
done:
    if (status != 0) {
        plamen_broker_v2_fuzz_service_continuation_dispose(
            context != NULL ? context->fuzz_service_continuation : NULL);
        if (context != NULL) context->fuzz_service_continuation = NULL;
        plamen_broker_v2_fuzz_service_session_dispose(
            context != NULL ? context->fuzz_service_session : NULL);
        if (context != NULL) context->fuzz_service_session = NULL;
    }
    if (terminal != NULL) {
        plamen_broker_v2_secure_zero(terminal, terminal_size); free(terminal);
    }
    if (stdin_fd >= 0) (void)close(stdin_fd);
    plamen_broker_v2_secure_zero(&storage, sizeof(storage));
    plamen_broker_v2_secure_zero(&authority, sizeof(authority));
    plamen_broker_v2_secure_zero(&receipt, sizeof(receipt));
    plamen_broker_v2_secure_zero(&runtime, sizeof(runtime));
    plamen_broker_v2_secure_zero(mounts, sizeof(mounts));
    plamen_broker_v2_secure_zero(paths, sizeof(paths));
    if (status != 0) plamen_broker_v2_secure_zero(evidence, sizeof(*evidence));
    return status;
}

static int specialized_fuzz_service_execute(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    static const uint8_t network_domain[] =
        "PLAMEN-FUZZ-SERVICE-NETWORK-NONE-V1\0";
    struct plamen_broker_v2_effects_context *context = opaque;
    struct plamen_broker_v2_fuzz_service_execute_request request;
    struct plamen_broker_v2_fuzz_service_terminal *native_terminal = NULL;
    uint8_t *terminal = NULL; size_t terminal_size = 0U;
    uint8_t network_preimage[sizeof(network_domain) + 32U], network_sha256[32];
    uint8_t lifecycle_sha256[32];
    int status = -1;
    memset(&request, 0, sizeof(request)); memset(network_preimage, 0,
        sizeof(network_preimage)); memset(network_sha256, 0, sizeof(network_sha256));
    memset(lifecycle_sha256, 0, sizeof(lifecycle_sha256));
    if (context == NULL || context->magic != EFFECTS_MAGIC || view == NULL
        || evidence == NULL || context->fuzz_service_session == NULL
        || context->fuzz_service_continuation == NULL
        || plamen_broker_v2_fuzz_service_execute_request_decode(
            view, &request) != 0
        || plamen_broker_v2_fuzz_service_execute(
            context->fuzz_service_session,
            context->fuzz_service_continuation,
            request.prepared_campaign_sha256, request.secure_receipt_sha256,
            &native_terminal) != 0
        || plamen_broker_v2_fuzz_service_project_terminal(native_terminal,
            &terminal, &terminal_size) != 0) goto done;
    memcpy(network_preimage, network_domain, sizeof(network_domain));
    if (plamen_broker_v2_sha256(terminal, terminal_size,
            lifecycle_sha256) != 0) goto done;
    memcpy(network_preimage + sizeof(network_domain),
        lifecycle_sha256, 32U);
    if (plamen_broker_v2_sha256(network_preimage,
            sizeof(network_preimage), network_sha256) != 0
        || specialized_finish_terminal(context, view, evidence,
            terminal, terminal_size, 1) != 0) goto done;
    terminal = NULL;
    memcpy(evidence->lifecycle_receipt_sha256, lifecycle_sha256, 32U);
    memcpy(evidence->network_policy_sha256, network_sha256, 32U);
    evidence->provider_authenticated = 1U;
    evidence->network_policy_enforced = 1U;
    evidence->population_zero = 1U; evidence->cleanup_complete = 1U;
    status = 0;
done:
    /* Success and failure both retire the one-shot native continuation. */
    if (context != NULL) {
        plamen_broker_v2_fuzz_service_continuation_dispose(
            context->fuzz_service_continuation);
        context->fuzz_service_continuation = NULL;
        plamen_broker_v2_fuzz_service_session_dispose(
            context->fuzz_service_session);
        context->fuzz_service_session = NULL;
    }
    plamen_broker_v2_fuzz_service_terminal_dispose(native_terminal);
    if (terminal != NULL) {
        plamen_broker_v2_secure_zero(terminal, terminal_size); free(terminal);
    }
    plamen_broker_v2_secure_zero(&request, sizeof(request));
    plamen_broker_v2_secure_zero(network_preimage, sizeof(network_preimage));
    plamen_broker_v2_secure_zero(network_sha256, sizeof(network_sha256));
    plamen_broker_v2_secure_zero(lifecycle_sha256, sizeof(lifecycle_sha256));
    if (status != 0) plamen_broker_v2_secure_zero(evidence, sizeof(*evidence));
    return status;
}

static int specialized_js_replay(void *opaque,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    struct plamen_broker_v2_effects_context *context = opaque;
    struct plamen_broker_v2_specialized_effect_completion completion;
    uint8_t *stored_terminal = NULL;
    size_t stored_terminal_size = 0U;
    int status = -1;
    memset(&completion, 0, sizeof(completion));
    if (context == NULL || context->magic != EFFECTS_MAGIC || view == NULL
        || evidence == NULL || context->active_specialized_store == NULL
        || context->specialized_runtime == NULL
        || all_zero(context->active_specialized_session_key)
        || plamen_broker_v2_specialized_apple_effect_replay_js(
            context->active_specialized_store, view, &completion,
            &stored_terminal, &stored_terminal_size) != 0
        || specialized_finish_terminal(context, view, evidence,
            stored_terminal, stored_terminal_size, 1) != 0)
        goto done;
    stored_terminal = NULL;
    status = 0;
done:
    if (stored_terminal != NULL) {
        plamen_broker_v2_secure_zero(stored_terminal, stored_terminal_size);
        free(stored_terminal);
    }
    plamen_broker_v2_secure_zero(&completion, sizeof(completion));
    return status;
}

static int specialized_managed_runtime_identity(void *context,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{ return specialized_runtime_identity(context, view, evidence, 1); }

static int specialized_managed_prepare(void *context,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{ return specialized_durable_capability(context, view, evidence,
    "\"schema\":\"plamen.managed-evm-python-native-plan.v1\"",
    "plamen.managed-evm-toolchain-prepare.v1", 0); }

static int specialized_snapshot_runtime_identity(void *context,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{ return specialized_runtime_identity(context, view, evidence, 0); }

static int specialized_snapshot_acquire(void *context,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{ return specialized_durable_capability(context, view, evidence, "{}",
    "plamen.snapshot-bound-tool-custody-acquisition.v1", 1); }

static int specialized_fuzz_prepare(void *,
    const struct plamen_broker_v2_tool_effect_plan_view *,
    struct plamen_broker_v2_tool_effect_evidence *);

static int specialized_snapshot_prepare(void *context,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    const char *schema =
        "\"schema\":\"plamen.snapshot-bound-tool-execution-request.v3\"";
    const char *domain = "plamen.snapshot-bound-tool-prepare.v1";
    if (view != NULL && specialized_contains_once(view->payload,
            view->payload_size,
            "\"schema\":\"plamen.apple-fuzz-campaign-native-request.v1\"")) {
        return specialized_fuzz_prepare(context, view, evidence);
    }
    return specialized_durable_capability(context, view, evidence,
        schema, domain, 1);
}

/* Method-exact unavailable callbacks document distinct missing production
 * engines.  The exact vtable prevents cross-lane fallback or generic success. */
#define SPECIALIZED_UNAVAILABLE(name) static int name(void *context, \
    const struct plamen_broker_v2_tool_effect_plan_view *view, \
    struct plamen_broker_v2_tool_effect_evidence *evidence) \
{ (void)context; (void)view; (void)evidence; return -1; }
SPECIALIZED_UNAVAILABLE(specialized_managed_execute)
SPECIALIZED_UNAVAILABLE(specialized_managed_project)
#undef SPECIALIZED_UNAVAILABLE

static void
specialized_effect_dispose(void *opaque,
    struct plamen_broker_v2_tool_effect_evidence *evidence)
{
    (void)opaque;
    if (evidence == NULL) return;
    if (evidence->terminal != NULL) {
        plamen_broker_v2_secure_zero((void *)evidence->terminal,
            evidence->terminal_size);
        free((void *)evidence->terminal);
    }
    plamen_broker_v2_secure_zero(evidence, sizeof(*evidence));
}

int
plamen_broker_v2_effects_dispatch_specialized(
    struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_specialized_request *request,
    const uint8_t *request_wire, size_t request_wire_size,
    const uint8_t request_sha256[32], const uint8_t session_key[32],
    int *fds, size_t fd_count,
    uint8_t **terminal, size_t *terminal_size)
{
    struct plamen_broker_v2_tool_effect_plan_input input;
    struct plamen_broker_v2_tool_effect_plan *plan = NULL;
    struct plamen_broker_v2_tool_effect_plan *issued = NULL;
    struct plamen_broker_v2_tool_effect_exact_executor executor;
    struct plamen_broker_v2_tool_effect_plan_view view;
    struct plamen_broker_v2_tool_effect_evidence evidence;
    struct plamen_broker_v2_tool_effect_plan **lease_slot = NULL;
    plamen_broker_v2_tool_effect_execute_fn prepare_callback = NULL;
    uint8_t terminal_sha256[32], runtime_authority_sha256[32];
    int status = -1, plan_status = -1;
    if (terminal != NULL) *terminal = NULL;
    if (terminal_size != NULL) *terminal_size = 0;
    memset(&input, 0, sizeof(input)); memset(&executor, 0, sizeof(executor));
    memset(&view, 0, sizeof(view)); memset(&evidence, 0, sizeof(evidence));
    memset(terminal_sha256, 0, sizeof(terminal_sha256));
    memset(runtime_authority_sha256, 0, sizeof(runtime_authority_sha256));
    if (context == NULL || request == NULL || request_wire == NULL
        || request_wire_size == 0U || request_sha256 == NULL
        || session_key == NULL || all_zero(session_key)
        || (fd_count != 0U && fds == NULL) || terminal == NULL
        || terminal_size == NULL || context->magic != EFFECTS_MAGIC
        || !constant_equal(request->authority_binding_sha256,
            context->authority_binding, 32)
        || pthread_mutex_lock(&context->lock) != 0)
        return -1;
    if (internal_revalidate(context) != 0
        || context->active_specialized_store != NULL
        || plamen_broker_v2_specialized_runtime_handoff_authority_sha256(
            context->specialized_runtime, runtime_authority_sha256) != 0
        || plamen_broker_v2_specialized_effect_store_open(
            context->state_directory_fd, session_key,
            runtime_authority_sha256, &context->active_specialized_store) != 0)
        goto done;
    memcpy(context->active_specialized_session_key, session_key, 32);
    input.version = PLAMEN_BROKER_V2_TOOL_EFFECT_PLAN_VERSION;
    input.request = request; input.request_wire = request_wire;
    input.request_wire_size = request_wire_size;
    memcpy(input.request_sha256, request_sha256, 32);
    input.fds = fds; input.fd_count = fd_count;
    if (specialized_effects_context_sha256(context,
            input.effects_context_sha256) != 0) goto done;
#define PLAN(method_name) plan_status = \
    plamen_broker_v2_tool_effect_plan_##method_name(&input, &plan)
    switch (request->method) {
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE:
        PLAN(js_authenticate); break;
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_RUNTIME_IDENTITY:
        PLAN(js_runtime_identity); break;
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE:
        PLAN(js_prepare); lease_slot = &context->js_prepare_lease;
        prepare_callback = specialized_js_prepare; break;
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE:
        issued = context->js_prepare_lease;
        context->js_prepare_lease = NULL;
        if (issued != NULL)
            plan_status = plamen_broker_v2_tool_effect_plan_js_execute_from_lease(
                issued, &input, &plan);
        break;
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY:
        PLAN(js_replay); break;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_RUNTIME_IDENTITY:
        PLAN(managed_evm_runtime_identity); break;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE:
        PLAN(managed_evm_prepare);
        lease_slot = &context->managed_prepare_lease;
        prepare_callback = specialized_managed_prepare; break;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE:
        issued = context->managed_prepare_lease;
        context->managed_prepare_lease = NULL;
        if (issued != NULL)
            plan_status =
                plamen_broker_v2_tool_effect_plan_managed_evm_execute_from_lease(
                    issued, &input, &plan);
        break;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PROJECT:
        PLAN(managed_evm_project); break;
    case PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT:
        PLAN(evm_projection_commit); break;
    case PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER:
        PLAN(evm_projection_recover); break;
    case PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_PROJECT:
        PLAN(evm_projection_project); break;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_RUNTIME_IDENTITY:
        PLAN(snapshot_runtime_identity); break;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE:
        PLAN(snapshot_acquire); break;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE:
        PLAN(snapshot_prepare); lease_slot = &context->snapshot_prepare_lease;
        prepare_callback = specialized_snapshot_prepare; break;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE:
        issued = context->snapshot_prepare_lease;
        context->snapshot_prepare_lease = NULL;
        if (issued != NULL)
            plan_status =
                plamen_broker_v2_tool_effect_plan_snapshot_execute_from_lease(
                    issued, &input, &plan);
        break;
    case PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE:
        issued = context->snapshot_prepare_lease;
        context->snapshot_prepare_lease = NULL;
        if (issued != NULL)
            plan_status =
                plamen_broker_v2_tool_effect_plan_fuzz_campaign_execute_from_lease(
                    issued, &input, &plan);
        break;
    case PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT:
        PLAN(fuzz_service_admit); break;
    case PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE:
        PLAN(fuzz_service_execute); break;
    default: break;
    }
#undef PLAN
    if (issued != NULL) {
        plamen_broker_v2_tool_effect_plan_destroy(issued); issued = NULL;
    }
    if (plan_status != 0 || plan == NULL) goto done;
    executor.version = PLAMEN_BROKER_V2_TOOL_EFFECT_EXACT_EXECUTOR_VERSION;
    executor.context = context;
    executor.js_authenticate = specialized_js_authenticate;
    executor.js_runtime_identity = specialized_js_runtime_identity;
    executor.js_prepare = specialized_js_prepare;
    executor.js_execute = specialized_js_execute;
    executor.js_replay = specialized_js_replay;
    executor.managed_evm_runtime_identity =
        specialized_managed_runtime_identity;
    executor.managed_evm_prepare = specialized_managed_prepare;
    executor.managed_evm_execute = specialized_managed_execute;
    executor.managed_evm_project = specialized_managed_project;
    executor.evm_projection_commit = specialized_projection_commit;
    executor.evm_projection_recover = specialized_projection_recover;
    executor.evm_projection_project = specialized_projection_project;
    executor.snapshot_runtime_identity = specialized_snapshot_runtime_identity;
    executor.snapshot_acquire = specialized_snapshot_acquire;
    executor.snapshot_prepare = specialized_snapshot_prepare;
    executor.snapshot_execute = specialized_snapshot_execute;
    executor.fuzz_campaign_execute = specialized_fuzz_campaign_execute;
    executor.fuzz_service_admit = specialized_fuzz_service_admit;
    executor.fuzz_service_execute = specialized_fuzz_service_execute;
    executor.dispose = specialized_effect_dispose;
    if (lease_slot != NULL) {
        if (*lease_slot != NULL || prepare_callback == NULL
            || plamen_broker_v2_tool_effect_plan_view(plan, &view) != 0
            || prepare_callback(context, &view, &evidence) != 0
            || plamen_broker_v2_tool_effect_plan_issue_lease(plan, &evidence,
                terminal, terminal_size, terminal_sha256) != 0) {
            specialized_effect_dispose(context, &evidence); goto done;
        }
        specialized_effect_dispose(context, &evidence);
        *lease_slot = plan; plan = NULL;
    } else if (plamen_broker_v2_tool_effect_plan_execute_exact(plan, &executor,
            terminal, terminal_size, terminal_sha256) != 0) goto done;
    status = 0;
done:
    plamen_broker_v2_specialized_effect_store_close(
        context->active_specialized_store);
    context->active_specialized_store = NULL;
    plamen_broker_v2_secure_zero(context->active_specialized_session_key,
        sizeof(context->active_specialized_session_key));
    if (issued != NULL) plamen_broker_v2_tool_effect_plan_destroy(issued);
    if (plan != NULL) plamen_broker_v2_tool_effect_plan_destroy(plan);
    plamen_broker_v2_secure_zero(&input, sizeof(input));
    plamen_broker_v2_secure_zero(&executor, sizeof(executor));
    plamen_broker_v2_secure_zero(&view, sizeof(view));
    plamen_broker_v2_secure_zero(&evidence, sizeof(evidence));
    plamen_broker_v2_secure_zero(terminal_sha256, sizeof(terminal_sha256));
    plamen_broker_v2_secure_zero(runtime_authority_sha256,
        sizeof(runtime_authority_sha256));
    (void)pthread_mutex_unlock(&context->lock);
    return status;
}

int
plamen_broker_v2_effects_retain_provider_admission(
    struct plamen_broker_v2_effects_context *context,
    const struct plamen_broker_v2_apple_container_admission_receipt *receipt)
{
    int result = -1;
    if (context == NULL || context->magic != EFFECTS_MAGIC || receipt == NULL
        || plamen_broker_v2_apple_container_receipt_validate(receipt) != 0
        || !constant_equal(receipt->request_fingerprint_sha256,
            context->registration.audit_request_fingerprint, 32)
        || pthread_mutex_lock(&context->lock) != 0)
        return -1;
    if (!context->provider_admission_present) {
        if (persist_provider_admission(context, receipt) == 0) {
            context->provider_admission = *receipt;
            context->provider_admission_present = 1;
            result = 0;
        }
    } else if (constant_equal(&context->provider_admission, receipt,
            sizeof(*receipt))) {
        result = 0;
    }
    (void)pthread_mutex_unlock(&context->lock);
    return result;
}

int
plamen_broker_v2_effects_copy_provider_admission(
    struct plamen_broker_v2_effects_context *context,
    struct plamen_broker_v2_apple_container_admission_receipt *receipt)
{
    int result = -1;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (context == NULL || context->magic != EFFECTS_MAGIC || receipt == NULL
        || pthread_mutex_lock(&context->lock) != 0)
        return -1;
    if (context->provider_admission_present) {
        *receipt = context->provider_admission;
        result = 0;
    }
    (void)pthread_mutex_unlock(&context->lock);
    return result;
}

void
plamen_broker_v2_effects_destroy(
    struct plamen_broker_v2_effects_context *context)
{
    destroy_context(context);
}
