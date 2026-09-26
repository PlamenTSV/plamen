#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_service_store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/random.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#error "Darwin broker service store requires O_CLOEXEC"
#endif
#ifndef O_NOFOLLOW
#error "Darwin broker service store requires O_NOFOLLOW"
#endif
#ifndef RENAME_EXCL
#error "Darwin broker service store requires renameatx_np(RENAME_EXCL)"
#endif

#define STORE_DIRECTORY "registrations-v2"
#define STORE_HEADER_SIZE 256U
#define STORE_TRAILER_SIZE 32U
#define STORE_REGISTRATION_UNUSED 1U
#define STORE_SESSION_PREPARED 2U
#define STORE_REGISTRATION_CONSUMED 3U
#define STORE_REQUEST_PROJECTION 4U
#define STORE_SPECIALIZED_SESSION 5U
#define STORE_SPECIALIZED_OPERATION 6U
#define STORE_REGISTRATION_RECORD_SIZE \
    (STORE_HEADER_SIZE + PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE \
        + STORE_TRAILER_SIZE)
#define STORE_SESSION_BUNDLE_MAX PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE
#define STORE_SESSION_PAYLOAD_SIZE \
    (PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE \
        + PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE + 32U + 4U \
        + STORE_SESSION_BUNDLE_MAX)
#define STORE_SESSION_RECORD_SIZE \
    (STORE_HEADER_SIZE + STORE_SESSION_PAYLOAD_SIZE \
        + STORE_TRAILER_SIZE)
#define STORE_MAX_RECORD_SIZE \
    (STORE_HEADER_SIZE + 4U \
        + PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE \
        + PLAMEN_BROKER_V2_MAX_FDS \
            * PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE \
        + PLAMEN_BROKER_V2_SPECIALIZED_PAYLOAD_MAX \
        + PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE \
        + PLAMEN_BROKER_V2_SPECIALIZED_PAYLOAD_MAX \
        + STORE_TRAILER_SIZE)
#define STORE_SPECIALIZED_SESSION_PAYLOAD_SIZE \
    (PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE \
        + PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE \
        + PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACK_SIZE + 32U)

static const uint8_t store_magic[8] = {
    'P', 'L', 'M', 'S', 'S', 'T', '2', '\0'
};
static const uint8_t checkpoint_domain[] =
    "plamen.broker-v2.registration.checkpoint.v2\0";
static const uint8_t session_domain[] =
    "plamen.broker-v2.session.binding.v2\0";
static const uint8_t burn_domain[] =
    "plamen.broker-v2.registration.burn.v2\0";
static const uint8_t specialized_authority_domain[] =
    "plamen.broker-v2.specialized.authority-binding.v1\0";

struct plamen_broker_v2_service_store {
    int directory_fd;
    int lock_fd;
    int poisoned;
};

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
static _Atomic int test_only_fail_after_prepare;

void
plamen_broker_v2_service_store_TEST_ONLY_fail_after_prepare_once(void)
{
    atomic_store_explicit(&test_only_fail_after_prepare, 1,
        memory_order_release);
}
#endif

static void
put_u16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void
put_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint16_t
get_u16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint32_t
get_u32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | in[3];
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
validate_projection(const uint8_t *projection, size_t projection_size,
    const struct plamen_broker_v2_service_registration *registration)
{
    struct plamen_broker_v2_commitment commitment;
    int result;
    memset(&commitment, 0, sizeof(commitment));
    result = plamen_broker_v2_request_projection_validate_exact(
        projection, projection_size, registration->request_projection_sha256,
        registration->commitment, registration->commitment_size,
        registration->commitment_sha256, &commitment);
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    return result;
}

static int
private_directory(int descriptor)
{
    struct stat information;
    return descriptor >= 0 && fstat(descriptor, &information) == 0
        && S_ISDIR(information.st_mode) && information.st_uid == geteuid()
        && (information.st_mode & 0777) == 0700;
}

static int
valid_lock(int descriptor)
{
    struct stat information;
    int flags = fcntl(descriptor, F_GETFL);
    return flags >= 0 && (flags & O_ACCMODE) == O_RDWR
        && fstat(descriptor, &information) == 0
        && S_ISREG(information.st_mode) && information.st_uid == geteuid()
        && information.st_nlink == 1 && (information.st_mode & 0777) == 0600;
}

static int
set_lock(int descriptor, short type)
{
    struct flock lock;
    int result;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = type;
    lock.l_whence = SEEK_SET;
    do {
        result = fcntl(descriptor,
            type == F_UNLCK ? F_SETLK : F_SETLKW, &lock);
    } while (result != 0 && errno == EINTR);
    return result == 0 ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_SYSTEM;
}

int
plamen_broker_v2_service_store_open(int parent_fd,
    struct plamen_broker_v2_service_store **out)
{
    struct plamen_broker_v2_service_store *store = NULL;
    int directory_fd = -1, lock_fd = -1;
    int created_directory = 0, created_lock = 0;

    if (out == NULL || !private_directory(parent_fd))
        return PLAMEN_BROKER_V2_INVALID;
    *out = NULL;
    if (mkdirat(parent_fd, STORE_DIRECTORY, 0700) == 0)
        created_directory = 1;
    else if (errno != EEXIST)
        return PLAMEN_BROKER_V2_SYSTEM;
    directory_fd = openat(parent_fd, STORE_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0 || !private_directory(directory_fd))
        goto invalid;
    if (created_directory && fsync(parent_fd) != 0)
        goto system;
    lock_fd = openat(directory_fd, ".lock",
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock_fd >= 0)
        created_lock = 1;
    else if (errno == EEXIST)
        lock_fd = openat(directory_fd, ".lock",
            O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (lock_fd < 0 || !valid_lock(lock_fd))
        goto invalid;
    if (created_lock && (fsync(lock_fd) != 0 || fsync(directory_fd) != 0))
        goto system;
    store = calloc(1, sizeof(*store));
    if (store == NULL)
        goto system;
    store->directory_fd = directory_fd;
    store->lock_fd = lock_fd;
    *out = store;
    return PLAMEN_BROKER_V2_OK;
invalid:
    if (lock_fd >= 0)
        close(lock_fd);
    if (directory_fd >= 0)
        close(directory_fd);
    return PLAMEN_BROKER_V2_INVALID;
system:
    if (lock_fd >= 0)
        close(lock_fd);
    if (directory_fd >= 0)
        close(directory_fd);
    free(store);
    return PLAMEN_BROKER_V2_SYSTEM;
}

void
plamen_broker_v2_service_store_close(
    struct plamen_broker_v2_service_store *store)
{
    if (store == NULL)
        return;
    if (store->lock_fd >= 0)
        close(store->lock_fd);
    if (store->directory_fd >= 0)
        close(store->directory_fd);
    plamen_broker_v2_secure_zero(store, sizeof(*store));
    free(store);
}

static int
digest_join(const uint8_t *domain, size_t domain_size,
    const uint8_t *first, size_t first_size, const uint8_t *second,
    size_t second_size, const uint8_t *third, size_t third_size,
    uint8_t out[32])
{
    uint8_t *canonical;
    size_t total;
    int result;
    if (domain == NULL || first == NULL || second == NULL || third == NULL
        || domain_size > SIZE_MAX - first_size
        || domain_size + first_size > SIZE_MAX - second_size
        || domain_size + first_size + second_size > SIZE_MAX - third_size)
        return PLAMEN_BROKER_V2_INVALID;
    total = domain_size + first_size + second_size + third_size;
    canonical = malloc(total);
    if (canonical == NULL)
        return PLAMEN_BROKER_V2_NOMEM;
    memcpy(canonical, domain, domain_size);
    memcpy(canonical + domain_size, first, first_size);
    memcpy(canonical + domain_size + first_size, second, second_size);
    memcpy(canonical + domain_size + first_size + second_size,
        third, third_size);
    result = plamen_broker_v2_sha256(canonical, total, out);
    plamen_broker_v2_secure_zero(canonical, total);
    free(canonical);
    return result;
}

static void
hex_digest(const uint8_t digest[32], char output[65])
{
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32; ++index) {
        output[index * 2] = alphabet[digest[index] >> 4];
        output[index * 2 + 1] = alphabet[digest[index] & 15];
    }
    output[64] = '\0';
}

static int
record_name(const uint8_t registration_sha256[32], uint16_t state,
    char output[96])
{
    char digest[65];
    const char *suffix;
    int count;
    hex_digest(registration_sha256, digest);
    if (state == STORE_REGISTRATION_UNUSED)
        suffix = ".unused";
    else if (state == STORE_SESSION_PREPARED)
        suffix = ".session-prepared";
    else if (state == STORE_REGISTRATION_CONSUMED)
        suffix = ".consumed";
    else if (state == STORE_REQUEST_PROJECTION)
        suffix = ".projection";
    else
        return PLAMEN_BROKER_V2_INVALID;
    count = snprintf(output, 96, "registration-%s%s", digest, suffix);
    return count > 0 && count < 96
        ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_INVALID;
}

static size_t
role_bundle_size(uint16_t role)
{
    if (role == PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR)
        return PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE;
    if (role == PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER)
        return PLAMEN_BROKER_V2_GUEST_AUTHORITY_BUNDLE_SIZE;
    return 0;
}

static int
encode_session_payload(
    const struct plamen_broker_v2_service_session_challenge *challenge,
    const struct plamen_broker_v2_service_session_open *session,
    const uint8_t key_sha256[32],
    const struct plamen_broker_v2_authority_bundle_binding *bundle,
    uint8_t payload[STORE_SESSION_PAYLOAD_SIZE])
{
    size_t bundle_size = 0, expected;
    const size_t open_offset =
        PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE;
    const size_t key_offset = open_offset
        + PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE;
    uint8_t *bundle_bytes = payload + key_offset + 36U;

    if (challenge == NULL || session == NULL || key_sha256 == NULL
        || bundle == NULL
        || all_zero(key_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    expected = role_bundle_size(session->initial_authority_role);
    if (expected == 0 || bundle->role != session->initial_authority_role)
        return PLAMEN_BROKER_V2_INVALID;
    memset(payload, 0, STORE_SESSION_PAYLOAD_SIZE);
    if (plamen_broker_v2_service_session_challenge_encode(
            challenge, payload) != 0
        || plamen_broker_v2_service_session_open_encode(
            session, payload + open_offset) != 0
        || plamen_broker_v2_authority_bundle_binding_encode(bundle,
            bundle_bytes, STORE_SESSION_BUNDLE_MAX, &bundle_size) != 0
        || bundle_size != expected)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(payload + key_offset, key_sha256, 32);
    put_u16(payload + key_offset + 32U,
        (uint16_t)bundle_size);
    return PLAMEN_BROKER_V2_OK;
}

static int
decode_session_payload(const uint8_t payload[STORE_SESSION_PAYLOAD_SIZE],
    struct plamen_broker_v2_service_session_challenge *challenge,
    struct plamen_broker_v2_service_session_open *session,
    uint8_t key_sha256[32],
    struct plamen_broker_v2_authority_bundle_binding *bundle)
{
    const size_t open_offset =
        PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE;
    const size_t key_offset = open_offset
        + PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE;
    const size_t bundle_offset = key_offset + 36U;
    size_t expected, index;
    uint16_t bundle_size;

    if (payload == NULL || challenge == NULL || session == NULL
        || key_sha256 == NULL || bundle == NULL
        || plamen_broker_v2_service_session_challenge_decode(payload,
            PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE, challenge) != 0
        || plamen_broker_v2_service_session_open_decode(payload + open_offset,
            PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE, session) != 0)
        return PLAMEN_BROKER_V2_CORRUPT;
    memcpy(key_sha256, payload + key_offset, 32);
    bundle_size = get_u16(payload + key_offset + 32U);
    expected = role_bundle_size(session->initial_authority_role);
    if (all_zero(key_sha256) || expected == 0 || bundle_size != expected
        || payload[key_offset + 34U] != 0
        || payload[key_offset + 35U] != 0
        || plamen_broker_v2_authority_bundle_binding_decode(
            payload + bundle_offset, bundle_size, bundle) != 0
        || bundle->role != session->initial_authority_role)
        return PLAMEN_BROKER_V2_CORRUPT;
    for (index = bundle_offset + bundle_size;
         index < STORE_SESSION_PAYLOAD_SIZE; ++index) {
        if (payload[index] != 0)
            return PLAMEN_BROKER_V2_CORRUPT;
    }
    return PLAMEN_BROKER_V2_OK;
}

static int
build_record(uint16_t state, const uint8_t registration_sha256[32],
    const uint8_t request_sha256[32],
    const uint8_t registration_checkpoint[32],
    const uint8_t session_binding[32], const uint8_t burn_checkpoint[32],
    const uint8_t authority_bundle[32], const uint8_t session_id[32],
    uint16_t role, uint16_t slot, const uint8_t *payload,
    uint32_t payload_size, uint8_t **record_out, size_t *record_size_out)
{
    uint8_t *record;
    size_t total = STORE_HEADER_SIZE + (size_t)payload_size
        + STORE_TRAILER_SIZE;
    int result;
    int payload_valid =
        (state == STORE_REGISTRATION_UNUSED
            && payload_size == PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE)
        || ((state == STORE_SESSION_PREPARED
                || state == STORE_REGISTRATION_CONSUMED)
            && payload_size == STORE_SESSION_PAYLOAD_SIZE);
    if (state == STORE_REQUEST_PROJECTION)
        payload_valid = payload_size > 0
            && payload_size <= PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX;
    if (record_out == NULL || record_size_out == NULL || payload == NULL
        || all_zero(registration_sha256) || all_zero(request_sha256)
        || all_zero(registration_checkpoint)
        || ((state == STORE_REGISTRATION_UNUSED
                || state == STORE_REQUEST_PROJECTION)
            && (!all_zero(session_binding) || !all_zero(burn_checkpoint)
                || all_zero(authority_bundle) || !all_zero(session_id)))
        || (state == STORE_SESSION_PREPARED
            && (all_zero(session_binding) || !all_zero(burn_checkpoint)
                || !all_zero(authority_bundle) || all_zero(session_id)))
        || (state == STORE_REGISTRATION_CONSUMED
            && (all_zero(session_binding) || all_zero(burn_checkpoint)
                || all_zero(authority_bundle) || all_zero(session_id)))
        || !payload_valid
        || slot != 0)
        return PLAMEN_BROKER_V2_INVALID;
    record = calloc(1, total);
    if (record == NULL)
        return PLAMEN_BROKER_V2_NOMEM;
    memcpy(record, store_magic, sizeof(store_magic));
    put_u16(record + 8, PLAMEN_BROKER_V2_SERVICE_STORE_VERSION);
    put_u16(record + 10, state);
    put_u32(record + 12, STORE_HEADER_SIZE);
    put_u32(record + 16, payload_size);
    memcpy(record + 24, registration_sha256, 32);
    memcpy(record + 56, request_sha256, 32);
    memcpy(record + 88, registration_checkpoint, 32);
    memcpy(record + 120, session_binding, 32);
    memcpy(record + 152, burn_checkpoint, 32);
    memcpy(record + 184, authority_bundle, 32);
    memcpy(record + 216, session_id, 32);
    put_u16(record + 248, role);
    put_u16(record + 250, slot);
    memcpy(record + STORE_HEADER_SIZE, payload, payload_size);
    result = plamen_broker_v2_sha256(record,
        STORE_HEADER_SIZE + payload_size,
        record + STORE_HEADER_SIZE + payload_size);
    if (result != PLAMEN_BROKER_V2_OK) {
        plamen_broker_v2_secure_zero(record, total);
        free(record);
        return result;
    }
    *record_out = record;
    *record_size_out = total;
    return PLAMEN_BROKER_V2_OK;
}

static int
specialized_name(const uint8_t session_id[32], const uint8_t *operation_nonce,
    char *output, size_t capacity)
{
    char session_hex[65], operation_hex[65];
    int amount;
    if (session_id == NULL || output == NULL || capacity == 0
        || all_zero(session_id))
        return PLAMEN_BROKER_V2_INVALID;
    hex_digest(session_id, session_hex);
    if (operation_nonce == NULL)
        amount = snprintf(output, capacity, "specialized-%s.session",
            session_hex);
    else {
        if (all_zero(operation_nonce))
            return PLAMEN_BROKER_V2_INVALID;
        hex_digest(operation_nonce, operation_hex);
        amount = snprintf(output, capacity, "specialized-%s-op-%s.record",
            session_hex, operation_hex);
    }
    return amount > 0 && (size_t)amount < capacity
        ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_INVALID;
}

static int
build_specialized_record(uint16_t state,
    const uint8_t registration_sha256[32], const uint8_t request_sha256[32],
    const uint8_t parent_binding_sha256[32],
    const uint8_t session_binding_sha256[32],
    const uint8_t key_or_terminal_sha256[32],
    const uint8_t authority_or_capability_sha256[32],
    const uint8_t session_id[32], uint16_t role, uint16_t slot,
    const uint8_t *payload, size_t payload_size, uint8_t **record_out,
    size_t *record_size_out)
{
    uint8_t *record;
    size_t total;
    int result;
    if (record_out == NULL || record_size_out == NULL || payload == NULL
        || payload_size == 0 || payload_size > UINT32_MAX
        || (state != STORE_SPECIALIZED_SESSION
            && state != STORE_SPECIALIZED_OPERATION)
        || all_zero(registration_sha256) || all_zero(request_sha256)
        || all_zero(parent_binding_sha256) || all_zero(session_binding_sha256)
        || all_zero(key_or_terminal_sha256) || all_zero(session_id)
        || role == 0 || slot == 0)
        return PLAMEN_BROKER_V2_INVALID;
    total = STORE_HEADER_SIZE + payload_size + STORE_TRAILER_SIZE;
    if (total > STORE_MAX_RECORD_SIZE)
        return PLAMEN_BROKER_V2_INVALID;
    record = calloc(1, total);
    if (record == NULL)
        return PLAMEN_BROKER_V2_NOMEM;
    memcpy(record, store_magic, sizeof(store_magic));
    put_u16(record + 8, PLAMEN_BROKER_V2_SERVICE_STORE_VERSION);
    put_u16(record + 10, state);
    put_u32(record + 12, STORE_HEADER_SIZE);
    put_u32(record + 16, (uint32_t)payload_size);
    memcpy(record + 24, registration_sha256, 32);
    memcpy(record + 56, request_sha256, 32);
    memcpy(record + 88, parent_binding_sha256, 32);
    memcpy(record + 120, session_binding_sha256, 32);
    memcpy(record + 152, key_or_terminal_sha256, 32);
    if (authority_or_capability_sha256 != NULL)
        memcpy(record + 184, authority_or_capability_sha256, 32);
    memcpy(record + 216, session_id, 32);
    put_u16(record + 248, role);
    put_u16(record + 250, slot);
    memcpy(record + STORE_HEADER_SIZE, payload, payload_size);
    result = plamen_broker_v2_sha256(record,
        STORE_HEADER_SIZE + payload_size,
        record + STORE_HEADER_SIZE + payload_size);
    if (result != PLAMEN_BROKER_V2_OK) {
        plamen_broker_v2_secure_zero(record, total);
        free(record);
        return result;
    }
    *record_out = record;
    *record_size_out = total;
    return PLAMEN_BROKER_V2_OK;
}

static int
read_exact(int descriptor, uint8_t *data, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = pread(descriptor, data + offset, size - offset,
            (off_t)offset);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0)
            return PLAMEN_BROKER_V2_CORRUPT;
        offset += (size_t)amount;
    }
    return pread(descriptor, data, 1, (off_t)size) == 0
        ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_CORRUPT;
}

static int
validate_record_bytes(const uint8_t *record, size_t total,
    uint16_t expected_state)
{
    uint8_t digest[32];
    uint32_t payload_size;
    if (record == NULL || total < STORE_HEADER_SIZE + STORE_TRAILER_SIZE)
        return PLAMEN_BROKER_V2_CORRUPT;
    payload_size = get_u32(record + 16);
    if (memcmp(record, store_magic, sizeof(store_magic)) != 0
        || get_u16(record + 8) != PLAMEN_BROKER_V2_SERVICE_STORE_VERSION
        || get_u16(record + 10) != expected_state
        || get_u32(record + 12) != STORE_HEADER_SIZE
        || get_u32(record + 20) != 0 || get_u32(record + 252) != 0
        || total != STORE_HEADER_SIZE + (size_t)payload_size
            + STORE_TRAILER_SIZE
        || plamen_broker_v2_sha256(record,
            STORE_HEADER_SIZE + payload_size, digest) != PLAMEN_BROKER_V2_OK
        || memcmp(digest, record + STORE_HEADER_SIZE + payload_size, 32) != 0)
        return PLAMEN_BROKER_V2_CORRUPT;
    return PLAMEN_BROKER_V2_OK;
}

static int
read_named_record(struct plamen_broker_v2_service_store *store,
    const char *name, uint16_t state, uint8_t **record, size_t *record_size)
{
    struct stat before, after;
    uint8_t *bytes = NULL;
    int descriptor = -1;
    int result = PLAMEN_BROKER_V2_CORRUPT;
    *record = NULL;
    *record_size = 0;
    descriptor = openat(store->directory_fd, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return errno == ENOENT
            ? PLAMEN_BROKER_V2_CONFLICT : PLAMEN_BROKER_V2_SYSTEM;
    if (fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_uid != geteuid() || before.st_nlink != 1
        || (before.st_mode & 0777) != 0400
        || before.st_size < (off_t)(STORE_HEADER_SIZE + STORE_TRAILER_SIZE)
        || before.st_size > (off_t)STORE_MAX_RECORD_SIZE)
        goto done;
    bytes = malloc((size_t)before.st_size);
    if (bytes == NULL) {
        result = PLAMEN_BROKER_V2_NOMEM;
        goto done;
    }
    if (read_exact(descriptor, bytes, (size_t)before.st_size) != 0
        || fstat(descriptor, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_size != after.st_size || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid || before.st_gid != after.st_gid
        || before.st_nlink != after.st_nlink
        || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
        || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
        || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec
        || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec
        || validate_record_bytes(bytes, (size_t)before.st_size, state) != 0)
        goto done;
    *record = bytes;
    *record_size = (size_t)before.st_size;
    bytes = NULL;
    result = PLAMEN_BROKER_V2_OK;
done:
    if (descriptor >= 0)
        close(descriptor);
    if (bytes != NULL) {
        plamen_broker_v2_secure_zero(bytes, (size_t)before.st_size);
        free(bytes);
    }
    if (result == PLAMEN_BROKER_V2_CORRUPT)
        store->poisoned = 1;
    return result;
}

static int
write_full(int descriptor, const uint8_t *data, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = write(descriptor, data + offset, size - offset);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0)
            return PLAMEN_BROKER_V2_SYSTEM;
        offset += (size_t)amount;
    }
    return PLAMEN_BROKER_V2_OK;
}

static int
publish_record(struct plamen_broker_v2_service_store *store,
    const char *name, uint16_t state, const uint8_t *expected,
    size_t expected_size)
{
    char pending[256];
    uint8_t *observed = NULL;
    size_t observed_size = 0;
    int descriptor = -1, result;
    struct stat information;

    if (snprintf(pending, sizeof(pending), "%s.pending", name)
            >= (int)sizeof(pending))
        return PLAMEN_BROKER_V2_INVALID;
    result = read_named_record(store, name, state, &observed, &observed_size);
    if (result == PLAMEN_BROKER_V2_OK) {
        result = observed_size == expected_size
                && memcmp(observed, expected, expected_size) == 0
            ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_CONFLICT;
        goto done;
    }
    if (result != PLAMEN_BROKER_V2_CONFLICT)
        goto done;
    result = read_named_record(store, pending, state, &observed, &observed_size);
    if (result == PLAMEN_BROKER_V2_OK) {
        if (observed_size != expected_size
            || memcmp(observed, expected, expected_size) != 0) {
            result = PLAMEN_BROKER_V2_CONFLICT;
            goto done;
        }
    } else if (result == PLAMEN_BROKER_V2_CONFLICT) {
        descriptor = openat(store->directory_fd, pending,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (descriptor < 0) {
            result = PLAMEN_BROKER_V2_SYSTEM;
            goto done;
        }
        if (write_full(descriptor, expected, expected_size) != 0
            || fchmod(descriptor, 0400) != 0 || fsync(descriptor) != 0
            || fstat(descriptor, &information) != 0
            || !S_ISREG(information.st_mode) || information.st_uid != geteuid()
            || information.st_nlink != 1
            || (information.st_mode & 0777) != 0400) {
            result = PLAMEN_BROKER_V2_SYSTEM;
            goto done;
        }
        if (close(descriptor) != 0) {
            descriptor = -1;
            result = PLAMEN_BROKER_V2_SYSTEM;
            goto done;
        }
        descriptor = -1;
        if (fsync(store->directory_fd) != 0) {
            result = PLAMEN_BROKER_V2_SYSTEM;
            goto done;
        }
    } else {
        goto done;
    }
    if (renameatx_np(store->directory_fd, pending,
            store->directory_fd, name, RENAME_EXCL) != 0) {
        if (errno != EEXIST) {
            result = PLAMEN_BROKER_V2_SYSTEM;
            goto done;
        }
        plamen_broker_v2_secure_zero(observed, observed_size);
        free(observed);
        observed = NULL;
        observed_size = 0;
        result = read_named_record(store, name, state, &observed, &observed_size);
        if (result != 0 || observed_size != expected_size
            || memcmp(observed, expected, expected_size) != 0) {
            result = PLAMEN_BROKER_V2_CONFLICT;
            goto done;
        }
    }
    if (fsync(store->directory_fd) != 0) {
        result = PLAMEN_BROKER_V2_SYSTEM;
        goto done;
    }
    result = PLAMEN_BROKER_V2_OK;
done:
    if (descriptor >= 0)
        close(descriptor);
    if (observed != NULL) {
        plamen_broker_v2_secure_zero(observed, observed_size);
        free(observed);
    }
    return result;
}

static int specialized_operation_decode_record(const uint8_t *, size_t,
    struct plamen_broker_v2_specialized_request *,
    struct plamen_broker_v2_specialized_response *, const uint8_t **,
    size_t *);

static int
specialized_attachment_name(const uint8_t session_id[32],
    const uint8_t operation_nonce[32], const uint8_t request_sha256[32],
    char *output, size_t capacity)
{
    char session_hex[65], operation_hex[65], request_hex[65];
    int amount;
    if (session_id == NULL || operation_nonce == NULL
        || request_sha256 == NULL || output == NULL || capacity == 0
        || all_zero(session_id) || all_zero(operation_nonce)
        || all_zero(request_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    hex_digest(session_id, session_hex);
    hex_digest(operation_nonce, operation_hex);
    hex_digest(request_sha256, request_hex);
    amount = snprintf(output, capacity,
        "specialized-%s-op-%s-request-%s.attachment",
        session_hex, operation_hex, request_hex);
    return amount > 0 && (size_t)amount < capacity
        ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_INVALID;
}

static int
same_file_snapshot(const struct stat *left, const struct stat *right)
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
open_specialized_attachment_locked(
    struct plamen_broker_v2_service_store *store, const char *name,
    const uint8_t expected_sha256[32], uint64_t expected_size,
    int *descriptor_out)
{
    struct stat before, after;
    uint8_t *bytes = NULL, observed_sha256[32];
    int descriptor = -1, flags, result = PLAMEN_BROKER_V2_CORRUPT;
    if (descriptor_out != NULL) *descriptor_out = -1;
    memset(observed_sha256, 0, sizeof(observed_sha256));
    if (store == NULL || name == NULL || expected_sha256 == NULL
        || descriptor_out == NULL || all_zero(expected_sha256)
        || expected_size == 0U
        || expected_size > PLAMEN_BROKER_V2_SPECIALIZED_ATTACHMENT_MAX_SIZE)
        return PLAMEN_BROKER_V2_INVALID;
    descriptor = openat(store->directory_fd, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return errno == ENOENT
            ? PLAMEN_BROKER_V2_CONFLICT : PLAMEN_BROKER_V2_SYSTEM;
    flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY
        || fcntl(descriptor, F_GETFD) < 0
        || (fcntl(descriptor, F_GETFD) & FD_CLOEXEC) == 0
        || fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_uid != geteuid() || before.st_nlink != 1
        || (before.st_mode & 0777) != 0400
        || before.st_size != (off_t)expected_size)
        goto done;
    bytes = malloc((size_t)expected_size);
    if (bytes == NULL) {
        result = PLAMEN_BROKER_V2_NOMEM;
        goto done;
    }
    if (read_exact(descriptor, bytes, (size_t)expected_size) != 0
        || plamen_broker_v2_sha256(bytes, (size_t)expected_size,
            observed_sha256) != PLAMEN_BROKER_V2_OK
        || memcmp(observed_sha256, expected_sha256, 32) != 0
        || fstat(descriptor, &after) != 0
        || !same_file_snapshot(&before, &after))
        goto done;
    *descriptor_out = descriptor;
    descriptor = -1;
    result = PLAMEN_BROKER_V2_OK;
done:
    if (descriptor >= 0) close(descriptor);
    if (bytes != NULL) {
        plamen_broker_v2_secure_zero(bytes, (size_t)expected_size);
        free(bytes);
    }
    plamen_broker_v2_secure_zero(observed_sha256,
        sizeof(observed_sha256));
    if (result == PLAMEN_BROKER_V2_CORRUPT)
        store->poisoned = 1;
    return result;
}

static int
publish_specialized_attachment_locked(
    struct plamen_broker_v2_service_store *store, const char *name,
    const uint8_t *bytes, size_t size, const uint8_t sha256[32],
    int *descriptor_out)
{
    char pending[256];
    struct stat information;
    int descriptor = -1, observed = -1, result;
    if (snprintf(pending, sizeof(pending), "%s.pending", name)
            >= (int)sizeof(pending))
        return PLAMEN_BROKER_V2_INVALID;
    result = open_specialized_attachment_locked(store, name, sha256,
        (uint64_t)size, &observed);
    if (result == PLAMEN_BROKER_V2_OK) {
        *descriptor_out = observed;
        return PLAMEN_BROKER_V2_OK;
    }
    if (result != PLAMEN_BROKER_V2_CONFLICT)
        return result;
    result = open_specialized_attachment_locked(store, pending, sha256,
        (uint64_t)size, &observed);
    if (result == PLAMEN_BROKER_V2_OK) {
        close(observed);
        observed = -1;
    } else if (result == PLAMEN_BROKER_V2_CONFLICT) {
        descriptor = openat(store->directory_fd, pending,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (descriptor < 0 || write_full(descriptor, bytes, size) != 0
            || fchmod(descriptor, 0400) != 0 || fsync(descriptor) != 0
            || fstat(descriptor, &information) != 0
            || !S_ISREG(information.st_mode)
            || information.st_uid != geteuid() || information.st_nlink != 1
            || (information.st_mode & 0777) != 0400) {
            if (descriptor >= 0) close(descriptor);
            return PLAMEN_BROKER_V2_SYSTEM;
        }
        if (close(descriptor) != 0) return PLAMEN_BROKER_V2_SYSTEM;
        descriptor = -1;
        if (fsync(store->directory_fd) != 0)
            return PLAMEN_BROKER_V2_SYSTEM;
    } else {
        return result;
    }
    if (renameatx_np(store->directory_fd, pending,
            store->directory_fd, name, RENAME_EXCL) != 0
        && errno != EEXIST)
        return PLAMEN_BROKER_V2_SYSTEM;
    if (fsync(store->directory_fd) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    return open_specialized_attachment_locked(store, name, sha256,
        (uint64_t)size, descriptor_out);
}

static int
stored_specialized_operation_matches_locked(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_specialized_session_ack *session,
    const struct plamen_broker_v2_specialized_request *request,
    const uint8_t request_sha256[32])
{
    struct plamen_broker_v2_specialized_request stored_request;
    struct plamen_broker_v2_specialized_response stored_response;
    uint8_t *record = NULL, *request_wire = NULL;
    const uint8_t *response_wire = NULL;
    size_t record_size = 0, request_wire_size, response_wire_size = 0;
    char name[160];
    int result;
    memset(&stored_request, 0, sizeof(stored_request));
    memset(&stored_response, 0, sizeof(stored_response));
    request_wire_size = PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE
        + (size_t)request->fd_count
            * PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE
        + request->payload_size;
    request_wire = malloc(request_wire_size);
    if (request_wire == NULL) return PLAMEN_BROKER_V2_NOMEM;
    if (specialized_name(session->specialized_session_id,
            request->operation_nonce, name, sizeof(name)) != 0
        || plamen_broker_v2_specialized_request_encode(request, request_wire,
            request_wire_size, &request_wire_size) != 0) {
        result = PLAMEN_BROKER_V2_INVALID;
        goto done;
    }
    result = read_named_record(store, name, STORE_SPECIALIZED_OPERATION,
        &record, &record_size);
    if (result != PLAMEN_BROKER_V2_OK) goto done;
    if (specialized_operation_decode_record(record, record_size,
            &stored_request, &stored_response, &response_wire,
            &response_wire_size) != PLAMEN_BROKER_V2_OK
        || memcmp(record + 56, request_sha256, 32) != 0
        || memcmp(record + 88, session->authority_binding_sha256, 32) != 0
        || memcmp(record + 216, session->specialized_session_id, 32) != 0
        || get_u32(record + STORE_HEADER_SIZE) != request_wire_size
        || memcmp(record + STORE_HEADER_SIZE + 4U,
            request_wire, request_wire_size) != 0) {
        store->poisoned = 1;
        result = PLAMEN_BROKER_V2_CORRUPT;
        goto done;
    }
    result = PLAMEN_BROKER_V2_OK;
done:
    if (request_wire != NULL) {
        plamen_broker_v2_secure_zero(request_wire, request_wire_size);
        free(request_wire);
    }
    if (record != NULL) {
        plamen_broker_v2_secure_zero(record, record_size);
        free(record);
    }
    plamen_broker_v2_secure_zero(&stored_request, sizeof(stored_request));
    plamen_broker_v2_secure_zero(&stored_response, sizeof(stored_response));
    return result;
}

int
plamen_broker_v2_service_store_specialized_attachment_prepare(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_specialized_session_ack *session,
    const struct plamen_broker_v2_specialized_request *request,
    const uint8_t request_sha256[32], const uint8_t *bytes, size_t size,
    struct plamen_broker_v2_specialized_attachment *attachment)
{
    char name[256];
    uint8_t sha256[32];
    int descriptor = -1, result;
    if (attachment != NULL) {
        memset(attachment, 0, sizeof(*attachment));
        attachment->descriptor = -1;
    }
    memset(sha256, 0, sizeof(sha256));
    if (store == NULL || session == NULL || request == NULL
        || request_sha256 == NULL || bytes == NULL || attachment == NULL
        || size == 0U
        || size > PLAMEN_BROKER_V2_SPECIALIZED_ATTACHMENT_MAX_SIZE
        || store->poisoned
        || specialized_attachment_name(session->specialized_session_id,
            request->operation_nonce, request_sha256, name, sizeof(name)) != 0
        || plamen_broker_v2_sha256(bytes, size, sha256) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    result = plamen_broker_v2_service_store_specialized_preflight(store,
        session, request, request_sha256);
    if (result != PLAMEN_BROKER_V2_OK) goto done;
    if (set_lock(store->lock_fd, F_WRLCK) != 0) {
        result = PLAMEN_BROKER_V2_SYSTEM;
        goto done;
    }
    result = publish_specialized_attachment_locked(store, name, bytes, size,
        sha256, &descriptor);
    if (set_lock(store->lock_fd, F_UNLCK) != 0
        && result == PLAMEN_BROKER_V2_OK)
        result = PLAMEN_BROKER_V2_SYSTEM;
    if (result == PLAMEN_BROKER_V2_OK) {
        attachment->version = PLAMEN_BROKER_V2_SPECIALIZED_ATTACHMENT_VERSION;
        attachment->size = (uint64_t)size;
        memcpy(attachment->sha256, sha256, 32);
        attachment->descriptor = descriptor;
        descriptor = -1;
    }
done:
    if (descriptor >= 0) close(descriptor);
    plamen_broker_v2_secure_zero(sha256, sizeof(sha256));
    return result;
}

int
plamen_broker_v2_service_store_specialized_attachment_reopen(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_specialized_session_ack *session,
    const struct plamen_broker_v2_specialized_request *request,
    const uint8_t request_sha256[32], const uint8_t expected_sha256[32],
    uint64_t expected_size,
    struct plamen_broker_v2_specialized_attachment *attachment)
{
    char name[256];
    int descriptor = -1, result;
    if (attachment != NULL) {
        memset(attachment, 0, sizeof(*attachment));
        attachment->descriptor = -1;
    }
    if (store == NULL || session == NULL || request == NULL
        || request_sha256 == NULL || expected_sha256 == NULL
        || attachment == NULL || all_zero(expected_sha256)
        || expected_size == 0U
        || expected_size > PLAMEN_BROKER_V2_SPECIALIZED_ATTACHMENT_MAX_SIZE
        || store->poisoned
        || specialized_attachment_name(session->specialized_session_id,
            request->operation_nonce, request_sha256, name, sizeof(name)) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    if (set_lock(store->lock_fd, F_RDLCK) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    result = stored_specialized_operation_matches_locked(store, session,
        request, request_sha256);
    if (result == PLAMEN_BROKER_V2_OK)
        result = open_specialized_attachment_locked(store, name,
            expected_sha256, expected_size, &descriptor);
    if (set_lock(store->lock_fd, F_UNLCK) != 0
        && result == PLAMEN_BROKER_V2_OK)
        result = PLAMEN_BROKER_V2_SYSTEM;
    if (result == PLAMEN_BROKER_V2_OK) {
        attachment->version = PLAMEN_BROKER_V2_SPECIALIZED_ATTACHMENT_VERSION;
        attachment->size = expected_size;
        memcpy(attachment->sha256, expected_sha256, 32);
        attachment->descriptor = descriptor;
        descriptor = -1;
    }
    if (descriptor >= 0) close(descriptor);
    return result;
}

void
plamen_broker_v2_service_store_specialized_attachment_dispose(
    struct plamen_broker_v2_specialized_attachment *attachment)
{
    if (attachment == NULL) return;
    if (attachment->descriptor >= 0) close(attachment->descriptor);
    plamen_broker_v2_secure_zero(attachment, sizeof(*attachment));
    attachment->descriptor = -1;
}

static int
record_exists(struct plamen_broker_v2_service_store *store,
    const uint8_t registration_sha256[32], uint16_t state)
{
    char name[96];
    struct stat information;
    if (record_name(registration_sha256, state, name) != 0)
        return -1;
    if (fstatat(store->directory_fd, name, &information,
            AT_SYMLINK_NOFOLLOW) == 0)
        return 1;
    return errno == ENOENT ? 0 : -1;
}

int
plamen_broker_v2_service_store_register(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_registration *registration,
    const uint8_t request_envelope_sha256[32],
    const uint8_t broker_closure_sha256[32],
    const uint8_t *request_projection,
    size_t request_projection_size,
    struct plamen_broker_v2_service_registration_ack *ack)
{
    uint8_t payload[PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE];
    uint8_t registration_sha256[32], checkpoint[32], zeros[32] = { 0 };
    uint8_t *record = NULL, *projection_record = NULL;
    size_t record_size = 0, projection_record_size = 0;
    char name[96], projection_name[96];
    int result, prepared_exists, consumed_exists;

    if (store == NULL || registration == NULL || request_envelope_sha256 == NULL
        || broker_closure_sha256 == NULL || ack == NULL || store->poisoned
        || request_projection == NULL || request_projection_size == 0
        || request_projection_size > PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX
        || all_zero(request_envelope_sha256) || all_zero(broker_closure_sha256))
        return store != NULL && store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    memset(ack, 0, sizeof(*ack));
    if (validate_projection(request_projection, request_projection_size,
            registration) != 0
        || request_projection_size != registration->request_projection_size
        || plamen_broker_v2_service_registration_encode(registration, payload) != 0
        || plamen_broker_v2_sha256(payload, sizeof(payload),
            registration_sha256) != 0
        || digest_join(checkpoint_domain, sizeof(checkpoint_domain),
            request_envelope_sha256, 32, registration_sha256, 32,
            broker_closure_sha256, 32, checkpoint) != 0
        || record_name(registration_sha256, STORE_REGISTRATION_UNUSED,
            name) != 0
        || record_name(registration_sha256, STORE_REQUEST_PROJECTION,
            projection_name) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    if (build_record(STORE_REQUEST_PROJECTION, registration_sha256,
            request_envelope_sha256, checkpoint, zeros, zeros,
            broker_closure_sha256, zeros,
            registration->initial_authority_role,
            registration->initial_interpreter_slot, request_projection,
            (uint32_t)request_projection_size, &projection_record,
            &projection_record_size) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    if (build_record(STORE_REGISTRATION_UNUSED, registration_sha256,
            request_envelope_sha256, checkpoint, zeros, zeros,
            broker_closure_sha256, zeros,
            registration->initial_authority_role,
            registration->initial_interpreter_slot, payload, sizeof(payload),
            &record, &record_size) != 0) {
        result = PLAMEN_BROKER_V2_INVALID;
        goto done;
    }
    if (set_lock(store->lock_fd, F_WRLCK) != 0) {
        result = PLAMEN_BROKER_V2_SYSTEM;
        goto done;
    }
    prepared_exists = record_exists(store, registration_sha256,
        STORE_SESSION_PREPARED);
    consumed_exists = record_exists(store, registration_sha256,
        STORE_REGISTRATION_CONSUMED);
    if (prepared_exists < 0 || consumed_exists < 0)
        result = PLAMEN_BROKER_V2_SYSTEM;
    else if (prepared_exists != 0 || consumed_exists != 0)
        result = PLAMEN_BROKER_V2_BURNED;
    else {
        result = publish_record(store, projection_name,
            STORE_REQUEST_PROJECTION, projection_record,
            projection_record_size);
        if (result == 0)
            result = publish_record(store, name, STORE_REGISTRATION_UNUSED,
                record, record_size);
    }
    if (set_lock(store->lock_fd, F_UNLCK) != 0 && result == 0)
        result = PLAMEN_BROKER_V2_SYSTEM;
    if (result != 0)
        goto done;
    memcpy(ack->request_envelope_sha256, request_envelope_sha256, 32);
    memcpy(ack->registration_sha256, registration_sha256, 32);
    memcpy(ack->registration_checkpoint_sha256, checkpoint, 32);
    memcpy(ack->broker_closure_sha256, broker_closure_sha256, 32);
    ack->suspended_child = registration->suspended_child;
    ack->initial_interpreter_slot = registration->initial_interpreter_slot;
    ack->initial_authority_role = registration->initial_authority_role;
    ack->issuance_state = 0;
    result = PLAMEN_BROKER_V2_OK;
done:
    if (record != NULL) {
        plamen_broker_v2_secure_zero(record, record_size);
        free(record);
    }
    if (projection_record != NULL) {
        plamen_broker_v2_secure_zero(projection_record,
            projection_record_size);
        free(projection_record);
    }
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
    return result;
}

static int
load_projection_locked(struct plamen_broker_v2_service_store *store,
    const uint8_t registration_sha256[32],
    const struct plamen_broker_v2_service_registration *registration,
    uint8_t **projection_out, size_t *projection_size_out)
{
    uint8_t *record = NULL, *projection = NULL;
    size_t record_size = 0, projection_size;
    char name[96];
    int result;

    *projection_out = NULL;
    *projection_size_out = 0;
    if (record_name(registration_sha256, STORE_REQUEST_PROJECTION, name) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    result = read_named_record(store, name, STORE_REQUEST_PROJECTION,
        &record, &record_size);
    if (result != 0)
        return result;
    projection_size = registration->request_projection_size;
    if (record_size != STORE_HEADER_SIZE + projection_size + STORE_TRAILER_SIZE
        || memcmp(record + 24, registration_sha256, 32) != 0
        || get_u32(record + 16) != projection_size
        || validate_projection(record + STORE_HEADER_SIZE, projection_size,
            registration) != 0) {
        store->poisoned = 1;
        result = PLAMEN_BROKER_V2_CORRUPT;
        goto done;
    }
    projection = malloc(projection_size);
    if (projection == NULL) {
        result = PLAMEN_BROKER_V2_NOMEM;
        goto done;
    }
    memcpy(projection, record + STORE_HEADER_SIZE, projection_size);
    *projection_out = projection;
    *projection_size_out = projection_size;
    projection = NULL;
    result = PLAMEN_BROKER_V2_OK;
done:
    if (projection != NULL) {
        plamen_broker_v2_secure_zero(projection, projection_size);
        free(projection);
    }
    if (record != NULL) {
        plamen_broker_v2_secure_zero(record, record_size);
        free(record);
    }
    return result;
}

static int
load_registration(struct plamen_broker_v2_service_store *store,
    const uint8_t registration_sha256[32],
    struct plamen_broker_v2_service_registration *registration,
    struct plamen_broker_v2_service_registration_ack *ack)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE];
    uint8_t observed_sha256[32];
    uint8_t *record = NULL, *projection = NULL;
    size_t record_size = 0, projection_size = 0;
    char name[96];
    int result;
    if (record_name(registration_sha256, STORE_REGISTRATION_UNUSED, name) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    result = read_named_record(store, name, STORE_REGISTRATION_UNUSED,
        &record, &record_size);
    if (result != 0)
        return result;
    if (record_size != STORE_REGISTRATION_RECORD_SIZE
        || memcmp(record + 24, registration_sha256, 32) != 0
        || plamen_broker_v2_service_registration_decode(
            record + STORE_HEADER_SIZE,
            PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE, registration) != 0
        || plamen_broker_v2_service_registration_encode(registration,
            canonical) != 0
        || plamen_broker_v2_sha256(canonical, sizeof(canonical),
            observed_sha256) != 0
        || memcmp(observed_sha256, registration_sha256, 32) != 0) {
        store->poisoned = 1;
        result = PLAMEN_BROKER_V2_CORRUPT;
    } else if (load_projection_locked(store, registration_sha256,
            registration, &projection, &projection_size) != 0) {
        result = store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_CONFLICT;
    } else {
        if (ack != NULL) {
            memset(ack, 0, sizeof(*ack));
            memcpy(ack->request_envelope_sha256, record + 56, 32);
            memcpy(ack->registration_sha256, registration_sha256, 32);
            memcpy(ack->registration_checkpoint_sha256, record + 88, 32);
            memcpy(ack->broker_closure_sha256, record + 184, 32);
            ack->suspended_child = registration->suspended_child;
            ack->initial_interpreter_slot =
                registration->initial_interpreter_slot;
            ack->initial_authority_role = registration->initial_authority_role;
        }
    }
    plamen_broker_v2_secure_zero(record, record_size);
    free(record);
    if (projection != NULL) {
        plamen_broker_v2_secure_zero(projection, projection_size);
        free(projection);
    }
    plamen_broker_v2_secure_zero(canonical, sizeof(canonical));
    return result;
}

int
plamen_broker_v2_service_store_copy_request_projection(
    struct plamen_broker_v2_service_store *store,
    const uint8_t registration_sha256[32], uint8_t **projection,
    size_t *projection_size)
{
    struct plamen_broker_v2_service_registration registration;
    int result;

    if (store == NULL || registration_sha256 == NULL || projection == NULL
        || projection_size == NULL || store->poisoned
        || all_zero(registration_sha256))
        return store != NULL && store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    *projection = NULL;
    *projection_size = 0;
    memset(&registration, 0, sizeof(registration));
    if (set_lock(store->lock_fd, F_RDLCK) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    result = load_registration(store, registration_sha256,
        &registration, NULL);
    if (result == 0)
        result = load_projection_locked(store, registration_sha256,
            &registration, projection, projection_size);
    if (set_lock(store->lock_fd, F_UNLCK) != 0 && result == 0)
        result = PLAMEN_BROKER_V2_SYSTEM;
    if (result != 0 && *projection != NULL) {
        plamen_broker_v2_secure_zero(*projection, *projection_size);
        free(*projection);
        *projection = NULL;
        *projection_size = 0;
    }
    plamen_broker_v2_secure_zero(&registration, sizeof(registration));
    return result;
}

int
plamen_broker_v2_service_store_copy_registration(
    struct plamen_broker_v2_service_store *store,
    const uint8_t registration_sha256[32],
    struct plamen_broker_v2_service_registration *registration)
{
    int result;
    if (store == NULL || registration_sha256 == NULL || registration == NULL
        || store->poisoned || all_zero(registration_sha256))
        return store != NULL && store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    memset(registration, 0, sizeof(*registration));
    if (set_lock(store->lock_fd, F_RDLCK) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    result = load_registration(store, registration_sha256,
        registration, NULL);
    if (set_lock(store->lock_fd, F_UNLCK) != 0 && result == 0)
        result = PLAMEN_BROKER_V2_SYSTEM;
    if (result != 0)
        plamen_broker_v2_secure_zero(registration, sizeof(*registration));
    return result;
}

static int
same_peer(const struct plamen_broker_v2_peer_identity *left,
    const struct plamen_broker_v2_peer_identity *right)
{
    return left->pid == right->pid && left->uid == right->uid
        && left->gid == right->gid && left->birth_kind == right->birth_kind
        && left->birth_primary == right->birth_primary
        && left->birth_secondary == right->birth_secondary
        && memcmp(left->boot_id_sha256, right->boot_id_sha256, 32) == 0;
}

static int
unused_name_digest(const char *name, uint8_t digest[32])
{
    static const char prefix[] = "registration-";
    static const char suffix[] = ".unused";
    size_t index;
    if (name == NULL
        || strlen(name) != sizeof(prefix) - 1 + 64 + sizeof(suffix) - 1
        || memcmp(name, prefix, sizeof(prefix) - 1) != 0
        || memcmp(name + sizeof(prefix) - 1 + 64,
            suffix, sizeof(suffix) - 1) != 0)
        return 0;
    for (index = 0; index < 32; ++index) {
        unsigned high, low;
        char a = name[sizeof(prefix) - 1 + index * 2];
        char b = name[sizeof(prefix) + index * 2];
        high = a >= '0' && a <= '9' ? (unsigned)(a - '0')
            : a >= 'a' && a <= 'f' ? (unsigned)(a - 'a' + 10) : 16U;
        low = b >= '0' && b <= '9' ? (unsigned)(b - '0')
            : b >= 'a' && b <= 'f' ? (unsigned)(b - 'a' + 10) : 16U;
        if (high > 15 || low > 15)
            return 0;
        digest[index] = (uint8_t)((high << 4) | low);
    }
    return 1;
}

int
plamen_broker_v2_service_store_lookup_unused(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_peer_identity *child,
    struct plamen_broker_v2_service_registration *registration,
    struct plamen_broker_v2_service_registration_ack *ack)
{
    struct plamen_broker_v2_service_registration candidate;
    struct plamen_broker_v2_service_registration_ack candidate_ack;
    struct dirent *entry;
    DIR *directory = NULL;
    uint8_t registration_sha256[32];
    int scan_fd = -1, matches = 0, result = PLAMEN_BROKER_V2_CONFLICT;

    if (store == NULL || child == NULL || registration == NULL || ack == NULL
        || store->poisoned)
        return store != NULL && store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    memset(registration, 0, sizeof(*registration));
    memset(ack, 0, sizeof(*ack));
    if (set_lock(store->lock_fd, F_WRLCK) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    scan_fd = openat(store->directory_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0 || (directory = fdopendir(scan_fd)) == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        result = PLAMEN_BROKER_V2_SYSTEM;
        goto unlock;
    }
    for (;;) {
        int prepared_exists, consumed_exists;
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            result = errno == 0
                ? (matches == 1
                    ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_CONFLICT)
                : PLAMEN_BROKER_V2_SYSTEM;
            break;
        }
        if (!unused_name_digest(entry->d_name, registration_sha256))
            continue;
        /*
         * The unused record is an immutable registration checkpoint, not an
         * ambient availability flag.  It intentionally remains on disk for
         * crash recovery after a session prepare/commit.  A lookup must
         * therefore consult the durable burn records before exposing it as an
         * unconsumed registration.
         */
        prepared_exists = record_exists(store, registration_sha256,
            STORE_SESSION_PREPARED);
        consumed_exists = record_exists(store, registration_sha256,
            STORE_REGISTRATION_CONSUMED);
        if (prepared_exists < 0 || consumed_exists < 0) {
            result = PLAMEN_BROKER_V2_SYSTEM;
            break;
        }
        if (prepared_exists != 0 || consumed_exists != 0)
            continue;
        memset(&candidate, 0, sizeof(candidate));
        memset(&candidate_ack, 0, sizeof(candidate_ack));
        result = load_registration(store, registration_sha256,
            &candidate, &candidate_ack);
        if (result != 0)
            break;
        if (same_peer(&candidate.suspended_child, child)) {
            if (++matches != 1) {
                result = PLAMEN_BROKER_V2_CORRUPT;
                store->poisoned = 1;
                break;
            }
            *registration = candidate;
            *ack = candidate_ack;
        }
    }
    closedir(directory);
unlock:
    if (set_lock(store->lock_fd, F_UNLCK) != 0 && result == 0)
        result = PLAMEN_BROKER_V2_SYSTEM;
    if (result != 0) {
        plamen_broker_v2_secure_zero(registration, sizeof(*registration));
        plamen_broker_v2_secure_zero(ack, sizeof(*ack));
    }
    return result;
}

int
plamen_broker_v2_service_store_consume(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_session_challenge *challenge,
    const struct plamen_broker_v2_service_session_open *session,
    const uint8_t request_envelope_sha256[32],
    const uint8_t member_capability_id
        [PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT][32],
    const uint8_t key_sha256[32],
    int allow_new_prepare,
    struct plamen_broker_v2_service_session_ack *ack,
    struct plamen_broker_v2_authority_bundle_binding *bundle_out)
{
    struct plamen_broker_v2_service_registration registration;
    struct plamen_broker_v2_service_registration_ack registered;
    struct plamen_broker_v2_authority_bundle_binding bundle;
    struct plamen_broker_v2_service_session_challenge prepared_challenge;
    uint8_t session_canonical[PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE];
    uint8_t challenge_canonical[
        PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE];
    uint8_t payload[STORE_SESSION_PAYLOAD_SIZE];
    uint8_t bundle_bytes[PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE];
    uint8_t registration_checkpoint[32], session_binding[32];
    uint8_t burn_checkpoint[32], authority_bundle_sha256[32], zeros[32] = { 0 };
    uint8_t prepared_key_sha256[32];
    uint8_t *prepared = NULL, *consumed = NULL;
    size_t prepared_size = 0, consumed_size = 0;
    size_t bundle_size = 0;
    char prepared_name[96], consumed_name[96];
    uint16_t member_count, index, prior;
    int result, prepared_exists;

    if (store == NULL || challenge == NULL || session == NULL
        || request_envelope_sha256 == NULL
        || member_capability_id == NULL || key_sha256 == NULL || ack == NULL
        || bundle_out == NULL || store->poisoned
        || all_zero(request_envelope_sha256) || all_zero(key_sha256)
        || !(allow_new_prepare == 0 || allow_new_prepare == 1))
        return store != NULL && store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    memset(ack, 0, sizeof(*ack));
    memset(bundle_out, 0, sizeof(*bundle_out));
    memset(&registration, 0, sizeof(registration));
    memset(&registered, 0, sizeof(registered));
    memset(&bundle, 0, sizeof(bundle));
    memset(&prepared_challenge, 0, sizeof(prepared_challenge));
    memset(bundle_bytes, 0, sizeof(bundle_bytes));
    if (plamen_broker_v2_service_session_challenge_encode(
            challenge, challenge_canonical) != 0
        || plamen_broker_v2_service_session_open_encode(
            session, session_canonical) != 0
        || !plamen_broker_v2_service_session_open_matches_challenge(
            challenge, session->challenge_envelope_sha256, session)
        || record_name(session->registration_sha256, STORE_SESSION_PREPARED,
            prepared_name) != 0
        || record_name(session->registration_sha256,
            STORE_REGISTRATION_CONSUMED, consumed_name) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    if (set_lock(store->lock_fd, F_WRLCK) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    result = load_registration(store, session->registration_sha256,
        &registration, &registered);
    if (result != 0)
        goto unlock;
    memcpy(registration_checkpoint,
        registered.registration_checkpoint_sha256, 32);
    if (!plamen_broker_v2_service_session_open_matches_registration(
            &registered, session)
        || memcmp(registration.committed_audit_generation_sha256,
            session->committed_audit_generation_sha256, 32) != 0) {
        result = PLAMEN_BROKER_V2_CONFLICT;
        goto unlock;
    }
    result = digest_join(session_domain, sizeof(session_domain),
        session_canonical, sizeof(session_canonical),
        request_envelope_sha256, 32,
        registration_checkpoint, 32, session_binding);
    if (result != 0)
        goto unlock;
    result = digest_join(burn_domain, sizeof(burn_domain),
        registration_checkpoint, 32, session_binding, 32,
        request_envelope_sha256, 32, burn_checkpoint);
    if (result != 0)
        goto unlock;
    prepared_exists = record_exists(store, session->registration_sha256,
        STORE_SESSION_PREPARED);
    if (prepared_exists < 0) {
        result = PLAMEN_BROKER_V2_SYSTEM;
        goto unlock;
    }
    if (prepared_exists == 1) {
        struct plamen_broker_v2_service_session_open prepared_session;
        memset(&prepared_session, 0, sizeof(prepared_session));
        result = read_named_record(store, prepared_name,
            STORE_SESSION_PREPARED, &prepared, &prepared_size);
        if (result != 0)
            goto unlock;
        if (prepared_size != STORE_SESSION_RECORD_SIZE
            || memcmp(prepared + 24, session->registration_sha256, 32) != 0
            || memcmp(prepared + 56, request_envelope_sha256, 32) != 0
            || memcmp(prepared + 88, registration_checkpoint, 32) != 0
            || memcmp(prepared + 120, session_binding, 32) != 0
            || !all_zero(prepared + 152) || !all_zero(prepared + 184)
            || memcmp(prepared + 216, session->session_id, 32) != 0
            || get_u16(prepared + 248) != session->initial_authority_role
            || get_u16(prepared + 250) != session->initial_interpreter_slot
            || decode_session_payload(prepared + STORE_HEADER_SIZE,
                &prepared_challenge, &prepared_session,
                prepared_key_sha256, &bundle) != 0
            || memcmp(prepared + STORE_HEADER_SIZE, challenge_canonical,
                sizeof(challenge_canonical)) != 0
            || memcmp(prepared + STORE_HEADER_SIZE
                    + sizeof(challenge_canonical), session_canonical,
                sizeof(session_canonical)) != 0
            || memcmp(prepared_key_sha256, key_sha256, 32) != 0
            || memcmp(bundle.registration_sha256,
                session->registration_sha256, 32) != 0
            || memcmp(bundle.issuance_checkpoint_sha256,
                burn_checkpoint, 32) != 0) {
            plamen_broker_v2_secure_zero(&prepared_session,
                sizeof(prepared_session));
            result = PLAMEN_BROKER_V2_CONFLICT;
            goto unlock;
        }
        plamen_broker_v2_secure_zero(&prepared_session,
            sizeof(prepared_session));
        memcpy(payload, prepared + STORE_HEADER_SIZE, sizeof(payload));
    } else {
        if (!allow_new_prepare) {
            result = PLAMEN_BROKER_V2_CONFLICT;
            goto unlock;
        }
        member_count = session->initial_authority_role
                == PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR
            ? PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT
            : PLAMEN_BROKER_V2_GUEST_AUTHORITY_MEMBER_COUNT;
        bundle.role = session->initial_authority_role;
        bundle.member_count = member_count;
        memcpy(bundle.registration_sha256, session->registration_sha256, 32);
        memcpy(bundle.issuance_checkpoint_sha256, burn_checkpoint, 32);
        for (index = 0; index < member_count; ++index) {
            if (all_zero(member_capability_id[index])) {
                result = PLAMEN_BROKER_V2_INVALID;
                goto unlock;
            }
            for (prior = 0; prior < index; ++prior) {
                if (memcmp(member_capability_id[index],
                        member_capability_id[prior], 32) == 0) {
                    result = PLAMEN_BROKER_V2_INVALID;
                    goto unlock;
                }
            }
            memcpy(bundle.member_sha256[index],
                member_capability_id[index], 32);
        }
        for (; index < PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT;
             ++index) {
            if (!all_zero(member_capability_id[index])) {
                result = PLAMEN_BROKER_V2_INVALID;
                goto unlock;
            }
        }
        result = encode_session_payload(challenge, session, key_sha256,
            &bundle, payload);
        if (result != 0)
            goto unlock;
    }
    result = plamen_broker_v2_authority_bundle_binding_encode(&bundle,
        bundle_bytes, sizeof(bundle_bytes), &bundle_size);
    if (result != 0
        || plamen_broker_v2_sha256(bundle_bytes, bundle_size,
            authority_bundle_sha256) != 0)
        goto unlock;
    if (prepared_exists == 0) {
        result = build_record(STORE_SESSION_PREPARED,
            session->registration_sha256, request_envelope_sha256,
            registration_checkpoint, session_binding, zeros, zeros,
            session->session_id, session->initial_authority_role,
            session->initial_interpreter_slot, payload, sizeof(payload),
            &prepared, &prepared_size);
        if (result != 0)
            goto unlock;
        result = publish_record(store, prepared_name, STORE_SESSION_PREPARED,
            prepared, prepared_size);
        if (result != 0)
            goto unlock;
#ifdef PLAMEN_BROKER_V2_TEST_ONLY
        if (atomic_exchange_explicit(&test_only_fail_after_prepare, 0,
                memory_order_acq_rel) != 0) {
            result = PLAMEN_BROKER_V2_SYSTEM;
            goto unlock;
        }
#endif
    }
    result = build_record(STORE_REGISTRATION_CONSUMED,
        session->registration_sha256, request_envelope_sha256,
        registration_checkpoint, session_binding, burn_checkpoint,
        authority_bundle_sha256, session->session_id,
        session->initial_authority_role, session->initial_interpreter_slot,
        payload, sizeof(payload), &consumed, &consumed_size);
    if (result != 0)
        goto unlock;
    result = publish_record(store, consumed_name,
        STORE_REGISTRATION_CONSUMED, consumed, consumed_size);
unlock:
    if (set_lock(store->lock_fd, F_UNLCK) != 0 && result == 0)
        result = PLAMEN_BROKER_V2_SYSTEM;
    if (result == 0) {
        memcpy(ack->registration_sha256, session->registration_sha256, 32);
        memcpy(ack->session_binding_sha256, session_binding, 32);
        memcpy(ack->registration_burn_checkpoint_sha256,
            burn_checkpoint, 32);
        memcpy(ack->authority_bundle_sha256, authority_bundle_sha256, 32);
        memcpy(ack->session_id, session->session_id, 32);
        ack->initial_authority_role = session->initial_authority_role;
        *bundle_out = bundle;
    }
    if (prepared != NULL) {
        plamen_broker_v2_secure_zero(prepared, prepared_size);
        free(prepared);
    }
    if (consumed != NULL) {
        plamen_broker_v2_secure_zero(consumed, consumed_size);
        free(consumed);
    }
    plamen_broker_v2_secure_zero(&registration, sizeof(registration));
    plamen_broker_v2_secure_zero(&bundle, sizeof(bundle));
    plamen_broker_v2_secure_zero(&prepared_challenge,
        sizeof(prepared_challenge));
    plamen_broker_v2_secure_zero(bundle_bytes, sizeof(bundle_bytes));
    plamen_broker_v2_secure_zero(session_canonical,
        sizeof(session_canonical));
    plamen_broker_v2_secure_zero(challenge_canonical,
        sizeof(challenge_canonical));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
    return result;
}

int
plamen_broker_v2_service_store_recover_consumed(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_session_open *session,
    const uint8_t request_envelope_sha256[32],
    const uint8_t key_sha256[32],
    struct plamen_broker_v2_service_consumed_session *recovered)
{
    struct plamen_broker_v2_service_session_challenge stored_challenge;
    struct plamen_broker_v2_service_session_open stored_session;
    struct plamen_broker_v2_authority_bundle_binding bundle;
    uint8_t expected_session[PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE];
    uint8_t stored_key_sha256[32], observed_bundle_sha256[32];
    uint8_t expected_session_binding[32], expected_burn_checkpoint[32];
    uint8_t *prepared = NULL, *consumed = NULL;
    size_t prepared_size = 0, consumed_size = 0, bundle_size = 0;
    char prepared_name[96], consumed_name[96];
    int result, consumed_exists;

    if (store == NULL || session == NULL || request_envelope_sha256 == NULL
        || key_sha256 == NULL || recovered == NULL || store->poisoned
        || all_zero(request_envelope_sha256) || all_zero(key_sha256))
        return store != NULL && store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    memset(recovered, 0, sizeof(*recovered));
    memset(&stored_challenge, 0, sizeof(stored_challenge));
    memset(&stored_session, 0, sizeof(stored_session));
    memset(&bundle, 0, sizeof(bundle));
    memset(stored_key_sha256, 0, sizeof(stored_key_sha256));
    if (plamen_broker_v2_service_session_open_encode(
            session, expected_session) != 0
        || record_name(session->registration_sha256, STORE_SESSION_PREPARED,
            prepared_name) != 0
        || record_name(session->registration_sha256,
            STORE_REGISTRATION_CONSUMED, consumed_name) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    /* Recovery may have to finish PREPARED -> CONSUMED. */
    if (set_lock(store->lock_fd, F_WRLCK) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    result = read_named_record(store, prepared_name, STORE_SESSION_PREPARED,
        &prepared, &prepared_size);
    if (result != 0)
        goto unlock;
    consumed_exists = record_exists(store, session->registration_sha256,
        STORE_REGISTRATION_CONSUMED);
    if (consumed_exists < 0) {
        result = PLAMEN_BROKER_V2_SYSTEM;
        goto unlock;
    }
    if (consumed_exists == 1) {
        result = read_named_record(store, consumed_name,
            STORE_REGISTRATION_CONSUMED, &consumed, &consumed_size);
        if (result != 0)
            goto unlock;
    }
    if (prepared_size != STORE_SESSION_RECORD_SIZE
        || memcmp(prepared + STORE_HEADER_SIZE
                + PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE,
            expected_session,
            sizeof(expected_session)) != 0
        || !all_zero(prepared + 152) || !all_zero(prepared + 184)
        || memcmp(prepared + 24, session->registration_sha256, 32) != 0
        || memcmp(prepared + 56, request_envelope_sha256, 32) != 0
        || memcmp(prepared + 216, session->session_id, 32) != 0
        || get_u16(prepared + 248) != session->initial_authority_role
        || get_u16(prepared + 250) != session->initial_interpreter_slot
        || decode_session_payload(prepared + STORE_HEADER_SIZE,
            &stored_challenge, &stored_session, stored_key_sha256,
            &bundle) != 0
        || !plamen_broker_v2_service_session_open_matches_challenge(
            &stored_challenge, session->challenge_envelope_sha256, session)
        || memcmp(stored_key_sha256, key_sha256, 32) != 0
        || memcmp(bundle.registration_sha256,
            session->registration_sha256, 32) != 0) {
        result = PLAMEN_BROKER_V2_CONFLICT;
        goto unlock;
    }
    result = digest_join(session_domain, sizeof(session_domain),
        expected_session, sizeof(expected_session), request_envelope_sha256,
        32, prepared + 88, 32, expected_session_binding);
    if (result != 0)
        goto unlock;
    result = digest_join(burn_domain, sizeof(burn_domain), prepared + 88, 32,
        expected_session_binding, 32, request_envelope_sha256, 32,
        expected_burn_checkpoint);
    if (result != 0)
        goto unlock;
    {
        uint8_t encoded[PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE];
        result = plamen_broker_v2_authority_bundle_binding_encode(&bundle,
            encoded, sizeof(encoded), &bundle_size);
        if (result == 0)
            result = plamen_broker_v2_sha256(encoded, bundle_size,
                observed_bundle_sha256);
        plamen_broker_v2_secure_zero(encoded, sizeof(encoded));
    }
    if (result != 0
        || memcmp(expected_session_binding, prepared + 120, 32) != 0
        || memcmp(bundle.issuance_checkpoint_sha256,
            expected_burn_checkpoint, 32) != 0) {
        result = PLAMEN_BROKER_V2_CORRUPT;
        store->poisoned = 1;
        goto unlock;
    }
    if (consumed_exists == 1) {
        if (consumed_size != STORE_SESSION_RECORD_SIZE
            || memcmp(prepared + STORE_HEADER_SIZE,
                consumed + STORE_HEADER_SIZE, STORE_SESSION_PAYLOAD_SIZE) != 0
            || memcmp(prepared + 24, consumed + 24, 128) != 0
            || memcmp(prepared + 216, consumed + 216, 36) != 0
            || memcmp(expected_burn_checkpoint, consumed + 152, 32) != 0
            || memcmp(observed_bundle_sha256, consumed + 184, 32) != 0) {
            result = PLAMEN_BROKER_V2_CORRUPT;
            store->poisoned = 1;
            goto unlock;
        }
    } else {
        result = build_record(STORE_REGISTRATION_CONSUMED,
            session->registration_sha256, request_envelope_sha256,
            prepared + 88, expected_session_binding,
            expected_burn_checkpoint, observed_bundle_sha256,
            session->session_id, session->initial_authority_role,
            session->initial_interpreter_slot,
            prepared + STORE_HEADER_SIZE, STORE_SESSION_PAYLOAD_SIZE,
            &consumed, &consumed_size);
        if (result != 0)
            goto unlock;
        result = publish_record(store, consumed_name,
            STORE_REGISTRATION_CONSUMED, consumed, consumed_size);
        if (result != 0)
            goto unlock;
    }
    recovered->session_challenge = stored_challenge;
    recovered->session_open = stored_session;
    recovered->authority_bundle = bundle;
    memcpy(recovered->key_sha256, stored_key_sha256, 32);
    memcpy(recovered->session_ack.registration_sha256,
        session->registration_sha256, 32);
    memcpy(recovered->session_ack.session_binding_sha256,
        expected_session_binding, 32);
    memcpy(recovered->session_ack.registration_burn_checkpoint_sha256,
        expected_burn_checkpoint, 32);
    memcpy(recovered->session_ack.authority_bundle_sha256,
        observed_bundle_sha256, 32);
    memcpy(recovered->session_ack.session_id, session->session_id, 32);
    recovered->session_ack.initial_authority_role =
        session->initial_authority_role;
    result = PLAMEN_BROKER_V2_OK;
unlock:
    if (set_lock(store->lock_fd, F_UNLCK) != 0 && result == 0)
        result = PLAMEN_BROKER_V2_SYSTEM;
    if (result != 0)
        plamen_broker_v2_secure_zero(recovered, sizeof(*recovered));
    if (prepared != NULL) {
        plamen_broker_v2_secure_zero(prepared, prepared_size);
        free(prepared);
    }
    if (consumed != NULL) {
        plamen_broker_v2_secure_zero(consumed, consumed_size);
        free(consumed);
    }
    plamen_broker_v2_secure_zero(&stored_session, sizeof(stored_session));
    plamen_broker_v2_secure_zero(&stored_challenge,
        sizeof(stored_challenge));
    plamen_broker_v2_secure_zero(&bundle, sizeof(bundle));
    plamen_broker_v2_secure_zero(expected_session, sizeof(expected_session));
    plamen_broker_v2_secure_zero(stored_key_sha256,
        sizeof(stored_key_sha256));
    plamen_broker_v2_secure_zero(observed_bundle_sha256,
        sizeof(observed_bundle_sha256));
    plamen_broker_v2_secure_zero(expected_session_binding,
        sizeof(expected_session_binding));
    plamen_broker_v2_secure_zero(expected_burn_checkpoint,
        sizeof(expected_burn_checkpoint));
    return result;
}

int
plamen_broker_v2_service_store_consume_specialized(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_session_ack *parent_ack,
    const struct plamen_broker_v2_service_specialized_session_challenge *challenge,
    const struct plamen_broker_v2_service_specialized_session_open *session,
    const uint8_t request_envelope_sha256[32],
    const uint8_t key[32], int allow_new,
    struct plamen_broker_v2_service_specialized_session_ack *ack)
{
    uint8_t lookup_bytes[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP_SIZE];
    uint8_t challenge_bytes[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE];
    uint8_t open_bytes[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE];
    uint8_t ack_bytes[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACK_SIZE];
    uint8_t payload[STORE_SPECIALIZED_SESSION_PAYLOAD_SIZE];
    uint8_t authority_binding[32], session_binding[32], key_sha256[32];
    uint8_t *parent = NULL, *record = NULL, *observed = NULL;
    size_t parent_size = 0, record_size = 0, observed_size = 0;
    char parent_name[96], name[96];
    int result;

    if (store == NULL || parent_ack == NULL || challenge == NULL
        || session == NULL || request_envelope_sha256 == NULL
        || key == NULL || ack == NULL || store->poisoned
        || all_zero(request_envelope_sha256) || all_zero(key)
        || !(allow_new == 0 || allow_new == 1))
        return store != NULL && store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    memset(ack, 0, sizeof(*ack));
    memset(payload, 0, sizeof(payload));
    if (plamen_broker_v2_service_specialized_session_lookup_encode(
            &challenge->lookup, lookup_bytes) != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_service_specialized_session_challenge_encode(
            challenge, challenge_bytes) != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_service_specialized_session_open_encode(
            session, open_bytes) != PLAMEN_BROKER_V2_OK
        || challenge->lookup.version != PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION
        || session->version != challenge->lookup.version
        || session->lane != challenge->lookup.lane
        || memcmp(session->parent_session_id,
            challenge->lookup.parent_session_id, 32) != 0
        || memcmp(session->specialized_session_id,
            challenge->lookup.specialized_session_id, 32) != 0
        || !same_peer(&session->extension_peer,
            &challenge->extension_peer)
        || record_name(parent_ack->registration_sha256,
            STORE_REGISTRATION_CONSUMED, parent_name) != PLAMEN_BROKER_V2_OK
        || specialized_name(session->specialized_session_id, NULL,
            name, sizeof(name)) != PLAMEN_BROKER_V2_OK)
        return PLAMEN_BROKER_V2_INVALID;
    result = digest_join(specialized_authority_domain,
        sizeof(specialized_authority_domain),
        parent_ack->authority_bundle_sha256, 32,
        lookup_bytes, sizeof(lookup_bytes),
        challenge->broker_closure_sha256, 32, authority_binding);
    if (result != PLAMEN_BROKER_V2_OK)
        return result;
    result = plamen_broker_v2_specialized_session_binding(key,
        session->parent_session_id, session->specialized_session_id,
        session->lane, authority_binding, session_binding);
    if (result != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_sha256(key, 32, key_sha256)
            != PLAMEN_BROKER_V2_OK)
        goto done;
    memcpy(ack->request_envelope_sha256, request_envelope_sha256, 32);
    ack->version = session->version;
    ack->lane = session->lane;
    memcpy(ack->parent_session_id, session->parent_session_id, 32);
    memcpy(ack->specialized_session_id,
        session->specialized_session_id, 32);
    memcpy(ack->authority_binding_sha256, authority_binding, 32);
    memcpy(ack->session_binding_sha256, session_binding, 32);
    if (plamen_broker_v2_service_specialized_session_ack_encode(
            ack, ack_bytes) != PLAMEN_BROKER_V2_OK) {
        result = PLAMEN_BROKER_V2_INVALID;
        goto done;
    }
    memcpy(payload, challenge_bytes, sizeof(challenge_bytes));
    memcpy(payload + sizeof(challenge_bytes), open_bytes, sizeof(open_bytes));
    memcpy(payload + sizeof(challenge_bytes) + sizeof(open_bytes),
        ack_bytes, sizeof(ack_bytes));
    memcpy(payload + sizeof(challenge_bytes) + sizeof(open_bytes)
        + sizeof(ack_bytes), key_sha256, 32);
    result = build_specialized_record(STORE_SPECIALIZED_SESSION,
        parent_ack->registration_sha256, request_envelope_sha256,
        parent_ack->session_binding_sha256, session_binding, key_sha256,
        authority_binding, session->specialized_session_id,
        session->lane, session->version, payload, sizeof(payload),
        &record, &record_size);
    if (result != PLAMEN_BROKER_V2_OK)
        goto done;
    if (set_lock(store->lock_fd, F_WRLCK) != PLAMEN_BROKER_V2_OK) {
        result = PLAMEN_BROKER_V2_SYSTEM;
        goto done;
    }
    result = read_named_record(store, parent_name,
        STORE_REGISTRATION_CONSUMED, &parent, &parent_size);
    if (result == PLAMEN_BROKER_V2_OK
        && (parent_size != STORE_SESSION_RECORD_SIZE
            || memcmp(parent + 24, parent_ack->registration_sha256, 32) != 0
            || memcmp(parent + 120, parent_ack->session_binding_sha256, 32) != 0
            || memcmp(parent + 184,
                parent_ack->authority_bundle_sha256, 32) != 0
            || memcmp(parent + 216, parent_ack->session_id, 32) != 0
            || memcmp(challenge->lookup.registration_sha256,
                parent_ack->registration_sha256, 32) != 0
            || memcmp(challenge->lookup.parent_session_id,
                parent_ack->session_id, 32) != 0
            || memcmp(challenge->lookup.authority_bundle_sha256,
                parent_ack->authority_bundle_sha256, 32) != 0)) {
        store->poisoned = 1;
        result = PLAMEN_BROKER_V2_CORRUPT;
    }
    if (result == PLAMEN_BROKER_V2_OK) {
        result = read_named_record(store, name, STORE_SPECIALIZED_SESSION,
            &observed, &observed_size);
        if (result == PLAMEN_BROKER_V2_OK) {
            result = observed_size == record_size
                    && memcmp(observed, record, record_size) == 0
                ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_CONFLICT;
        } else if (result == PLAMEN_BROKER_V2_CONFLICT && allow_new) {
            result = publish_record(store, name, STORE_SPECIALIZED_SESSION,
                record, record_size);
        }
    }
    if (set_lock(store->lock_fd, F_UNLCK) != PLAMEN_BROKER_V2_OK
        && result == PLAMEN_BROKER_V2_OK)
        result = PLAMEN_BROKER_V2_SYSTEM;
done:
    if (result != PLAMEN_BROKER_V2_OK)
        plamen_broker_v2_secure_zero(ack, sizeof(*ack));
    if (parent != NULL) {
        plamen_broker_v2_secure_zero(parent, parent_size);
        free(parent);
    }
    if (record != NULL) {
        plamen_broker_v2_secure_zero(record, record_size);
        free(record);
    }
    if (observed != NULL) {
        plamen_broker_v2_secure_zero(observed, observed_size);
        free(observed);
    }
    plamen_broker_v2_secure_zero(lookup_bytes, sizeof(lookup_bytes));
    plamen_broker_v2_secure_zero(challenge_bytes, sizeof(challenge_bytes));
    plamen_broker_v2_secure_zero(open_bytes, sizeof(open_bytes));
    plamen_broker_v2_secure_zero(ack_bytes, sizeof(ack_bytes));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
    plamen_broker_v2_secure_zero(authority_binding,
        sizeof(authority_binding));
    plamen_broker_v2_secure_zero(session_binding, sizeof(session_binding));
    plamen_broker_v2_secure_zero(key_sha256, sizeof(key_sha256));
    return result;
}

int
plamen_broker_v2_service_store_recover_specialized(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_specialized_session_open *session,
    const uint8_t request_envelope_sha256[32],
    const uint8_t key[32],
    struct plamen_broker_v2_service_consumed_specialized_session *recovered)
{
    uint8_t expected_open[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE];
    uint8_t *record = NULL;
    size_t record_size = 0;
    const uint8_t *payload;
    uint8_t key_sha256[32], expected_binding[32];
    char name[96];
    int result;
    if (store == NULL || session == NULL || request_envelope_sha256 == NULL
        || key == NULL || recovered == NULL || store->poisoned
        || all_zero(request_envelope_sha256) || all_zero(key)
        || plamen_broker_v2_service_specialized_session_open_encode(
            session, expected_open) != PLAMEN_BROKER_V2_OK
        || specialized_name(session->specialized_session_id, NULL,
            name, sizeof(name)) != PLAMEN_BROKER_V2_OK)
        return store != NULL && store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    memset(recovered, 0, sizeof(*recovered));
    if (plamen_broker_v2_sha256(key, 32, key_sha256)
            != PLAMEN_BROKER_V2_OK)
        return PLAMEN_BROKER_V2_INVALID;
    if (set_lock(store->lock_fd, F_RDLCK) != PLAMEN_BROKER_V2_OK)
        return PLAMEN_BROKER_V2_SYSTEM;
    result = read_named_record(store, name, STORE_SPECIALIZED_SESSION,
        &record, &record_size);
    if (result == PLAMEN_BROKER_V2_OK) {
        payload = record + STORE_HEADER_SIZE;
        if (record_size != STORE_HEADER_SIZE
                + STORE_SPECIALIZED_SESSION_PAYLOAD_SIZE + STORE_TRAILER_SIZE
            || memcmp(record + 56, request_envelope_sha256, 32) != 0
            || memcmp(record + 152, key_sha256, 32) != 0
            || memcmp(record + 216, session->specialized_session_id, 32) != 0
            || plamen_broker_v2_service_specialized_session_challenge_decode(
                payload,
                PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE,
                &recovered->challenge) != PLAMEN_BROKER_V2_OK
            || plamen_broker_v2_service_specialized_session_open_decode(
                payload
                    + PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE,
                PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE,
                &recovered->session_open) != PLAMEN_BROKER_V2_OK
            || plamen_broker_v2_service_specialized_session_ack_decode(
                payload
                    + PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE
                    + PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE,
                PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACK_SIZE,
                &recovered->session_ack) != PLAMEN_BROKER_V2_OK
            || memcmp(payload
                    + PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE
                    + PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE
                    + PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACK_SIZE,
                key_sha256, 32) != 0
            || memcmp(payload
                    + PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE,
                expected_open, sizeof(expected_open)) != 0
            || plamen_broker_v2_specialized_session_binding(key,
                recovered->session_ack.parent_session_id,
                recovered->session_ack.specialized_session_id,
                recovered->session_ack.lane,
                recovered->session_ack.authority_binding_sha256,
                expected_binding) != PLAMEN_BROKER_V2_OK
            || memcmp(expected_binding,
                recovered->session_ack.session_binding_sha256, 32) != 0) {
            store->poisoned = 1;
            result = PLAMEN_BROKER_V2_CORRUPT;
        } else {
            memcpy(recovered->key_sha256, key_sha256, 32);
        }
    }
    if (set_lock(store->lock_fd, F_UNLCK) != PLAMEN_BROKER_V2_OK
        && result == PLAMEN_BROKER_V2_OK)
        result = PLAMEN_BROKER_V2_SYSTEM;
    if (result != PLAMEN_BROKER_V2_OK)
        plamen_broker_v2_secure_zero(recovered, sizeof(*recovered));
    if (record != NULL) {
        plamen_broker_v2_secure_zero(record, record_size);
        free(record);
    }
    plamen_broker_v2_secure_zero(expected_open, sizeof(expected_open));
    plamen_broker_v2_secure_zero(key_sha256, sizeof(key_sha256));
    plamen_broker_v2_secure_zero(expected_binding,
        sizeof(expected_binding));
    return result;
}

static int
specialized_method_issues_capability(uint16_t method)
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
specialized_disposition(const struct plamen_broker_v2_specialized_request *request)
{
    if (request->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY)
        return PLAMEN_BROKER_V2_SPECIALIZED_REPLAYED;
    if (request->method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER
        || (request->flags & PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER) != 0)
        return PLAMEN_BROKER_V2_SPECIALIZED_RECOVERED;
    return specialized_method_issues_capability(request->method)
        ? PLAMEN_BROKER_V2_SPECIALIZED_ISSUED
        : PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED;
}

static int
specialized_predecessor_valid(uint16_t method, uint16_t predecessor)
{
    switch (method) {
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE:
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY:
        return predecessor ==
            PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE;
    case PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE:
        return predecessor == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE:
        return predecessor == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE;
    case PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PROJECT:
        return predecessor == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE;
    case PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_PROJECT:
        return predecessor == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
            || predecessor == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE:
        return predecessor == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE;
    case PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE:
    case PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE:
        return predecessor == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE;
    case PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE:
        return predecessor == PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT;
    default:
        return 0;
    }
}

static int
specialized_predecessor_one_shot(uint16_t predecessor)
{
    return predecessor == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE
        || predecessor == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE
        || predecessor == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE
        || predecessor == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE
        || predecessor == PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT;
}

static int
specialized_operation_decode_record(const uint8_t *record, size_t record_size,
    struct plamen_broker_v2_specialized_request *request,
    struct plamen_broker_v2_specialized_response *response,
    const uint8_t **response_wire, size_t *response_wire_size)
{
    uint32_t request_size;
    const uint8_t *payload;
    size_t payload_size;
    if (record == NULL || request == NULL || response == NULL
        || response_wire == NULL || response_wire_size == NULL
        || validate_record_bytes(record, record_size,
            STORE_SPECIALIZED_OPERATION) != PLAMEN_BROKER_V2_OK)
        return PLAMEN_BROKER_V2_CORRUPT;
    payload = record + STORE_HEADER_SIZE;
    payload_size = get_u32(record + 16);
    if (payload_size < 4U)
        return PLAMEN_BROKER_V2_CORRUPT;
    request_size = get_u32(payload);
    if ((size_t)request_size > payload_size - 4U)
        return PLAMEN_BROKER_V2_CORRUPT;
    *response_wire = payload + 4U + request_size;
    *response_wire_size = payload_size - 4U - request_size;
    if (plamen_broker_v2_specialized_request_decode_exact(payload + 4U,
            request_size, request) != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_specialized_response_decode_exact(*response_wire,
            *response_wire_size, response) != PLAMEN_BROKER_V2_OK)
        return PLAMEN_BROKER_V2_CORRUPT;
    return PLAMEN_BROKER_V2_OK;
}

static int
specialized_capability_authorized_locked(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_specialized_session_ack *session,
    const struct plamen_broker_v2_specialized_request *request)
{
    char session_hex[65], prefix[96];
    DIR *directory = NULL;
    struct dirent *entry;
    int scan_fd = -1, issuers = 0, consumers = 0, result = PLAMEN_BROKER_V2_CONFLICT;
    uint16_t predecessor = 0;

    if (all_zero(request->capability_id))
        return PLAMEN_BROKER_V2_OK;
    hex_digest(session->specialized_session_id, session_hex);
    if (snprintf(prefix, sizeof(prefix), "specialized-%s-op-", session_hex)
            >= (int)sizeof(prefix))
        return PLAMEN_BROKER_V2_INVALID;
    scan_fd = openat(store->directory_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0 || (directory = fdopendir(scan_fd)) == NULL) {
        if (scan_fd >= 0)
            close(scan_fd);
        return PLAMEN_BROKER_V2_SYSTEM;
    }
    for (;;) {
        uint8_t *record = NULL;
        size_t record_size = 0, response_wire_size = 0;
        const uint8_t *response_wire = NULL;
        struct plamen_broker_v2_specialized_request prior_request;
        struct plamen_broker_v2_specialized_response prior_response;
        size_t name_size;
        memset(&prior_request, 0, sizeof(prior_request));
        memset(&prior_response, 0, sizeof(prior_response));
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                result = PLAMEN_BROKER_V2_SYSTEM;
            break;
        }
        name_size = strlen(entry->d_name);
        if (strncmp(entry->d_name, prefix, strlen(prefix)) != 0
            || name_size != strlen(prefix) + 64U + sizeof(".record") - 1U)
            continue;
        result = read_named_record(store, entry->d_name,
            STORE_SPECIALIZED_OPERATION, &record, &record_size);
        if (result != PLAMEN_BROKER_V2_OK)
            break;
        if (specialized_operation_decode_record(record, record_size,
                &prior_request, &prior_response, &response_wire,
                &response_wire_size) != PLAMEN_BROKER_V2_OK
            || prior_request.lane != session->lane
            || memcmp(record + 216, session->specialized_session_id, 32) != 0
            || memcmp(record + 88, session->authority_binding_sha256, 32) != 0) {
            store->poisoned = 1;
            result = PLAMEN_BROKER_V2_CORRUPT;
        } else {
            if (memcmp(prior_response.capability_id,
                    request->capability_id, 32) == 0) {
                ++issuers;
                predecessor = prior_response.method;
            }
            if (memcmp(prior_request.capability_id,
                    request->capability_id, 32) == 0)
                ++consumers;
            result = PLAMEN_BROKER_V2_OK;
        }
        plamen_broker_v2_secure_zero(record, record_size);
        free(record);
        if (result != PLAMEN_BROKER_V2_OK)
            break;
    }
    closedir(directory);
    if (result == PLAMEN_BROKER_V2_OK
        && (issuers != 1 || !specialized_predecessor_valid(
                request->method, predecessor)
            || (specialized_predecessor_one_shot(predecessor)
                && consumers != 0)))
        result = PLAMEN_BROKER_V2_CONFLICT;
    return result;
}

int
plamen_broker_v2_service_store_specialized_preflight(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_specialized_session_ack *session,
    const struct plamen_broker_v2_specialized_request *request,
    const uint8_t request_sha256[32])
{
    uint8_t *request_wire = NULL, *session_record = NULL, *observed = NULL;
    uint8_t computed_request_sha256[32];
    size_t request_wire_size = 0, session_record_size = 0, observed_size = 0;
    char name[160], session_name[96];
    int result;

    memset(computed_request_sha256, 0, sizeof(computed_request_sha256));
    if (store == NULL || session == NULL || request == NULL
        || request_sha256 == NULL || store->poisoned
        || all_zero(request_sha256))
        return store != NULL && store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    request_wire_size = PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE
        + (size_t)request->fd_count
            * PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE
        + request->payload_size;
    request_wire = malloc(request_wire_size);
    if (request_wire == NULL)
        return PLAMEN_BROKER_V2_NOMEM;
    if (plamen_broker_v2_specialized_request_encode(request, request_wire,
            request_wire_size, &request_wire_size) != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_sha256(request_wire, request_wire_size,
            computed_request_sha256) != PLAMEN_BROKER_V2_OK
        || memcmp(computed_request_sha256, request_sha256, 32) != 0
        || memcmp(request->authority_binding_sha256,
            session->authority_binding_sha256, 32) != 0
        || request->lane != session->lane
        || specialized_name(session->specialized_session_id,
            request->operation_nonce, name, sizeof(name)) != PLAMEN_BROKER_V2_OK
        || specialized_name(session->specialized_session_id, NULL,
            session_name, sizeof(session_name)) != PLAMEN_BROKER_V2_OK) {
        result = PLAMEN_BROKER_V2_INVALID;
        goto done;
    }
    if (set_lock(store->lock_fd, F_WRLCK) != PLAMEN_BROKER_V2_OK) {
        result = PLAMEN_BROKER_V2_SYSTEM;
        goto done;
    }
    result = read_named_record(store, session_name,
        STORE_SPECIALIZED_SESSION, &session_record, &session_record_size);
    if (result == PLAMEN_BROKER_V2_OK
        && (memcmp(session_record + 120, session->session_binding_sha256, 32) != 0
            || memcmp(session_record + 184,
                session->authority_binding_sha256, 32) != 0
            || memcmp(session_record + 216,
                session->specialized_session_id, 32) != 0
            || get_u16(session_record + 248) != session->lane)) {
        store->poisoned = 1;
        result = PLAMEN_BROKER_V2_CORRUPT;
    }
    if (result != PLAMEN_BROKER_V2_OK)
        goto unlock;
    result = read_named_record(store, name, STORE_SPECIALIZED_OPERATION,
        &observed, &observed_size);
    if (result == PLAMEN_BROKER_V2_OK) {
        result = PLAMEN_BROKER_V2_CONFLICT;
        goto unlock;
    }
    if (result != PLAMEN_BROKER_V2_CONFLICT)
        goto unlock;
    result = specialized_capability_authorized_locked(store, session, request);
unlock:
    if (set_lock(store->lock_fd, F_UNLCK) != PLAMEN_BROKER_V2_OK
        && result == PLAMEN_BROKER_V2_OK)
        result = PLAMEN_BROKER_V2_SYSTEM;
done:
    if (request_wire != NULL) {
        plamen_broker_v2_secure_zero(request_wire, request_wire_size);
        free(request_wire);
    }
    if (session_record != NULL) {
        plamen_broker_v2_secure_zero(session_record, session_record_size);
        free(session_record);
    }
    if (observed != NULL) {
        plamen_broker_v2_secure_zero(observed, observed_size);
        free(observed);
    }
    plamen_broker_v2_secure_zero(computed_request_sha256,
        sizeof(computed_request_sha256));
    return result;
}

int
plamen_broker_v2_service_store_specialized_operation(
    struct plamen_broker_v2_service_store *store,
    const struct plamen_broker_v2_service_specialized_session_ack *session,
    const struct plamen_broker_v2_specialized_request *request,
    const uint8_t request_sha256[32], const uint8_t *terminal,
    size_t terminal_size, int allow_new,
    struct plamen_broker_v2_specialized_response *response,
    uint8_t **response_wire_out, size_t *response_wire_size_out)
{
    uint8_t *request_wire = NULL, *response_wire = NULL, *payload = NULL;
    uint8_t *record = NULL, *observed = NULL, *session_record = NULL;
    uint8_t terminal_sha256[32], computed_request_sha256[32];
    uint8_t issued_capability[32] = { 0 };
    size_t request_wire_size = 0, response_wire_size = 0, payload_size = 0;
    size_t record_size = 0, observed_size = 0, session_record_size = 0;
    const uint8_t *stored_response_wire = NULL;
    size_t stored_response_wire_size = 0;
    struct plamen_broker_v2_specialized_request stored_request;
    struct plamen_broker_v2_specialized_response stored_response;
    char name[160], session_name[96];
    int result;

    if (response != NULL)
        memset(response, 0, sizeof(*response));
    if (response_wire_out != NULL)
        *response_wire_out = NULL;
    if (response_wire_size_out != NULL)
        *response_wire_size_out = 0;
    memset(computed_request_sha256, 0, sizeof(computed_request_sha256));
    if (store == NULL || session == NULL || request == NULL
        || request_sha256 == NULL || response == NULL
        || response_wire_out == NULL || response_wire_size_out == NULL
        || store->poisoned || all_zero(request_sha256)
        || !(allow_new == 0 || allow_new == 1)
        || (allow_new && (terminal == NULL || terminal_size == 0)))
        return store != NULL && store->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    memset(&stored_request, 0, sizeof(stored_request));
    memset(&stored_response, 0, sizeof(stored_response));
    request_wire_size = PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE
        + (size_t)request->fd_count
            * PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE
        + request->payload_size;
    request_wire = malloc(request_wire_size);
    if (request_wire == NULL)
        return PLAMEN_BROKER_V2_NOMEM;
    if (plamen_broker_v2_specialized_request_encode(request, request_wire,
            request_wire_size, &request_wire_size) != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_sha256(request_wire, request_wire_size,
            computed_request_sha256) != PLAMEN_BROKER_V2_OK
        || memcmp(computed_request_sha256, request_sha256, 32) != 0
        || memcmp(request->authority_binding_sha256,
            session->authority_binding_sha256, 32) != 0
        || request->lane != session->lane
        || specialized_name(session->specialized_session_id,
            request->operation_nonce, name, sizeof(name)) != PLAMEN_BROKER_V2_OK
        || specialized_name(session->specialized_session_id, NULL,
            session_name, sizeof(session_name)) != PLAMEN_BROKER_V2_OK) {
        result = PLAMEN_BROKER_V2_INVALID;
        goto done;
    }
    if (set_lock(store->lock_fd, F_WRLCK) != PLAMEN_BROKER_V2_OK) {
        result = PLAMEN_BROKER_V2_SYSTEM;
        goto done;
    }
    result = read_named_record(store, session_name,
        STORE_SPECIALIZED_SESSION, &session_record, &session_record_size);
    if (result == PLAMEN_BROKER_V2_OK
        && (memcmp(session_record + 120, session->session_binding_sha256, 32) != 0
            || memcmp(session_record + 184,
                session->authority_binding_sha256, 32) != 0
            || memcmp(session_record + 216,
                session->specialized_session_id, 32) != 0
            || get_u16(session_record + 248) != session->lane)) {
        store->poisoned = 1;
        result = PLAMEN_BROKER_V2_CORRUPT;
    }
    if (result != PLAMEN_BROKER_V2_OK)
        goto unlock;
    result = read_named_record(store, name, STORE_SPECIALIZED_OPERATION,
        &observed, &observed_size);
    if (result == PLAMEN_BROKER_V2_OK) {
        if (specialized_operation_decode_record(observed, observed_size,
                &stored_request, &stored_response, &stored_response_wire,
                &stored_response_wire_size) != PLAMEN_BROKER_V2_OK
            || stored_response_wire_size == 0
            || stored_response.payload_size == 0
            || stored_response_wire_size > STORE_MAX_RECORD_SIZE) {
            store->poisoned = 1;
            result = PLAMEN_BROKER_V2_CORRUPT;
            goto unlock;
        }
        if (memcmp(observed + 56, request_sha256, 32) != 0
            || get_u32(observed + STORE_HEADER_SIZE) != request_wire_size
            || memcmp(observed + STORE_HEADER_SIZE + 4U,
                request_wire, request_wire_size) != 0
            || stored_request.lane != request->lane
            || stored_request.method != request->method
            || stored_request.flags != request->flags
            || stored_request.fd_count != request->fd_count) {
            result = PLAMEN_BROKER_V2_CONFLICT;
            goto unlock;
        }
        response_wire = malloc(stored_response_wire_size);
        if (response_wire == NULL) {
            result = PLAMEN_BROKER_V2_NOMEM;
            goto unlock;
        }
        memcpy(response_wire, stored_response_wire, stored_response_wire_size);
        response_wire_size = stored_response_wire_size;
        *response = stored_response;
        response->payload = response_wire
            + PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE;
        result = PLAMEN_BROKER_V2_OK;
        goto unlock;
    }
    if (result != PLAMEN_BROKER_V2_CONFLICT || !allow_new) {
        result = PLAMEN_BROKER_V2_CONFLICT;
        goto unlock;
    }
    result = specialized_capability_authorized_locked(store, session, request);
    if (result != PLAMEN_BROKER_V2_OK)
        goto unlock;
    if (plamen_broker_v2_sha256(terminal, terminal_size,
            terminal_sha256) != PLAMEN_BROKER_V2_OK) {
        result = PLAMEN_BROKER_V2_INVALID;
        goto unlock;
    }
    if (specialized_method_issues_capability(request->method)) {
        unsigned attempt;
        for (attempt = 0; attempt < 16U; ++attempt) {
            if (getentropy(issued_capability, sizeof(issued_capability)) != 0) {
                result = PLAMEN_BROKER_V2_SYSTEM;
                goto unlock;
            }
            if (!all_zero(issued_capability))
                break;
        }
        if (attempt == 16U) {
            result = PLAMEN_BROKER_V2_SYSTEM;
            goto unlock;
        }
    }
    response->lane = request->lane;
    response->method = request->method;
    response->disposition = specialized_disposition(request);
    response->status = 0;
    memcpy(response->capability_id, issued_capability, 32);
    memcpy(response->operation_nonce, request->operation_nonce, 32);
    memcpy(response->request_sha256, request_sha256, 32);
    memcpy(response->terminal_sha256, terminal_sha256, 32);
    response->payload_size = (uint32_t)terminal_size;
    response->payload = terminal;
    response_wire_size = PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE
        + terminal_size;
    response_wire = malloc(response_wire_size);
    if (response_wire == NULL) {
        result = PLAMEN_BROKER_V2_NOMEM;
        goto unlock;
    }
    if (plamen_broker_v2_specialized_response_encode(response, response_wire,
            response_wire_size, &response_wire_size) != PLAMEN_BROKER_V2_OK) {
        result = PLAMEN_BROKER_V2_INVALID;
        goto unlock;
    }
    payload_size = 4U + request_wire_size + response_wire_size;
    payload = malloc(payload_size);
    if (payload == NULL) {
        result = PLAMEN_BROKER_V2_NOMEM;
        goto unlock;
    }
    put_u32(payload, (uint32_t)request_wire_size);
    memcpy(payload + 4U, request_wire, request_wire_size);
    memcpy(payload + 4U + request_wire_size,
        response_wire, response_wire_size);
    result = build_specialized_record(STORE_SPECIALIZED_OPERATION,
        session_record + 24, request_sha256,
        session->authority_binding_sha256, terminal_sha256,
        terminal_sha256, issued_capability,
        session->specialized_session_id, request->method,
        response->disposition, payload, payload_size, &record, &record_size);
    if (result == PLAMEN_BROKER_V2_OK)
        result = publish_record(store, name, STORE_SPECIALIZED_OPERATION,
            record, record_size);
unlock:
    if (set_lock(store->lock_fd, F_UNLCK) != PLAMEN_BROKER_V2_OK
        && result == PLAMEN_BROKER_V2_OK)
        result = PLAMEN_BROKER_V2_SYSTEM;
done:
    if (result == PLAMEN_BROKER_V2_OK) {
        *response_wire_out = response_wire;
        *response_wire_size_out = response_wire_size;
        if (response->payload != NULL && response->payload != terminal)
            response->payload = response_wire
                + PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE;
        response_wire = NULL;
    } else {
        plamen_broker_v2_secure_zero(response, sizeof(*response));
    }
    if (request_wire != NULL) {
        plamen_broker_v2_secure_zero(request_wire, request_wire_size);
        free(request_wire);
    }
    if (response_wire != NULL) {
        plamen_broker_v2_secure_zero(response_wire, response_wire_size);
        free(response_wire);
    }
    if (payload != NULL) {
        plamen_broker_v2_secure_zero(payload, payload_size);
        free(payload);
    }
    if (record != NULL) {
        plamen_broker_v2_secure_zero(record, record_size);
        free(record);
    }
    if (observed != NULL) {
        plamen_broker_v2_secure_zero(observed, observed_size);
        free(observed);
    }
    if (session_record != NULL) {
        plamen_broker_v2_secure_zero(session_record, session_record_size);
        free(session_record);
    }
    plamen_broker_v2_secure_zero(&stored_request, sizeof(stored_request));
    plamen_broker_v2_secure_zero(&stored_response, sizeof(stored_response));
    plamen_broker_v2_secure_zero(terminal_sha256,
        sizeof(terminal_sha256));
    plamen_broker_v2_secure_zero(computed_request_sha256,
        sizeof(computed_request_sha256));
    plamen_broker_v2_secure_zero(issued_capability,
        sizeof(issued_capability));
    return result;
}
