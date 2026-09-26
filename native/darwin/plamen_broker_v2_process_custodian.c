#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_process_custodian.h"
#include "../include/plamen_broker_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define CUSTODY_DIRECTORY "process-custody-v1"
#define CUSTODY_MAX_OPERATIONS 64U
#define PREPARED_RECORD_SIZE 256U
#define STARTED_RECORD_SIZE 1024U
#define TERMINAL_RECORD_SIZE 1024U
#define CLOSED_RECORD_SIZE 304U
#define PREPARED_DIGEST_OFFSET 224U
#define STARTED_DIGEST_OFFSET 992U
#define TERMINAL_DIGEST_OFFSET 992U
#define CLOSED_DIGEST_OFFSET 272U
#define SPOOL_HEADER_SIZE 88U
#define SPOOL_TRAILER_SIZE 32U

_Static_assert(PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX
        == PLAMEN_BROKER_V2_SERVICE_MAX_FDS,
    "process custody and authenticated service FD ceilings must match");

enum custody_state {
    CUSTODY_UNUSED = 0,
    CUSTODY_START_PREPARED = 1,
    CUSTODY_PROCESS_PREPARED = 2,
    CUSTODY_START_EFFECT = 3,
    CUSTODY_STARTED_DURABLE = 4,
    CUSTODY_TERMINAL_PREPARED = 5,
    CUSTODY_TERMINAL_EFFECT = 6,
    CUSTODY_TERMINAL_DURABLE = 7,
    CUSTODY_FAILED_AMBIGUOUS = 8
};

struct plamen_broker_v2_process_custodian {
    int state_fd;
    dev_t state_device;
    ino_t state_inode;
};

struct custody_operation {
    uint8_t occupied;
    uint8_t state;
    dev_t state_device;
    ino_t state_inode;
    pthread_mutex_t lock;
    int claim_fd;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t prior_checkpoint_sha256[32];
    uint8_t claim_owner_sha256[32];
    uint8_t process_spec_sha256[32];
    uint8_t prepared_checkpoint_sha256[32];
    uint8_t terminal_operation_key[32];
    uint8_t terminal_request_sha256[32];
    uint8_t terminal_prior_checkpoint_sha256[32];
    uint8_t terminal_prepared_checkpoint_sha256[32];
    uint8_t terminal_kind;
    uint32_t stdout_retain_limit;
    uint32_t stderr_retain_limit;
    struct plamen_broker_v2_process *process;
    struct plamen_broker_v2_process_custodian_start_receipt started;
};

static struct custody_operation operations[CUSTODY_MAX_OPERATIONS];
static pthread_mutex_t operations_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
static uint32_t injected_fault;
static pthread_mutex_t fault_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

static int constant_equal(const void *left_value, const void *right_value,
    size_t size)
{
    const uint8_t *left = left_value, *right = right_value;
    uint8_t difference = 0; size_t index;
    for (index = 0; index < size; ++index) difference |= left[index] ^ right[index];
    return difference == 0;
}

static int all_zero(const uint8_t value[32])
{
    uint8_t aggregate = 0; size_t index;
    for (index = 0; index < 32; ++index) aggregate |= value[index];
    return aggregate == 0;
}

static int zero_bytes(const uint8_t *value, size_t size)
{
    uint8_t aggregate = 0; size_t index;
    for (index = 0; index < size; ++index) aggregate |= value[index];
    return aggregate == 0;
}

static void store_u32(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value >> 24); output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8); output[3] = (uint8_t)value;
}

static void store_u64(uint8_t *output, uint64_t value)
{
    store_u32(output, (uint32_t)(value >> 32));
    store_u32(output + 4, (uint32_t)value);
}

static uint32_t load_u32(const uint8_t *input)
{
    return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16)
        | ((uint32_t)input[2] << 8) | input[3];
}

static uint64_t load_u64(const uint8_t *input)
{
    return ((uint64_t)load_u32(input) << 32) | load_u32(input + 4);
}

static int sync_fd(int descriptor)
{
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0) return 0;
    if (errno != EINVAL && errno != ENOTTY && errno != ENOTSUP) return -1;
#endif
    return fsync(descriptor);
}

static int write_all(int descriptor, const uint8_t *bytes, size_t size)
{
    size_t offset = 0; ssize_t amount;
    while (offset < size) {
        amount = write(descriptor, bytes + offset, size - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int pread_all(int descriptor, uint8_t *bytes, size_t size)
{
    size_t offset = 0; ssize_t amount;
    while (offset < size) {
        amount = pread(descriptor, bytes + offset, size - offset, (off_t)offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int private_directory(int descriptor, struct stat *information)
{
    return descriptor >= 0 && fstat(descriptor, information) == 0
        && S_ISDIR(information->st_mode) && information->st_uid == geteuid()
        && (information->st_mode & 0077) == 0;
}

static void hex32(const uint8_t value[32], char output[65])
{
    static const char digits[] = "0123456789abcdef"; size_t index;
    for (index = 0; index < 32; ++index) {
        output[index * 2] = digits[value[index] >> 4];
        output[index * 2 + 1] = digits[value[index] & 15];
    }
    output[64] = '\0';
}

static int record_name(const uint8_t key[32], const char *suffix,
    char output[96])
{
    char encoded[65]; int amount;
    if (all_zero(key) || suffix == NULL) return -1;
    hex32(key, encoded);
    amount = snprintf(output, 96, "%s.%s", encoded, suffix);
    return amount > 0 && amount < 96 ? 0 : -1;
}

/* 0 created, 1 identical replay, -1 conflict/error. */
static int publish_exact(int directory, const char *name,
    const uint8_t *bytes, size_t size)
{
    struct stat information; uint8_t *existing = NULL;
    int descriptor = -1, created = 0, result = -1;
    descriptor = openat(directory, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor >= 0) {
        created = 1;
        if (write_all(descriptor, bytes, size) != 0 || sync_fd(descriptor) != 0)
            goto done;
        if (close(descriptor) != 0) { descriptor = -1; goto done; }
        descriptor = -1;
        if (sync_fd(directory) != 0) goto done;
        result = 0;
    } else {
        if (errno != EEXIST || (existing = malloc(size)) == NULL) goto done;
        descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0 || fstat(descriptor, &information) != 0
            || !S_ISREG(information.st_mode) || information.st_nlink != 1
            || information.st_uid != geteuid() || (information.st_mode & 0077) != 0
            || information.st_size != (off_t)size
            || pread_all(descriptor, existing, size) != 0
            || !constant_equal(existing, bytes, size)) goto done;
        result = 1;
    }
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (created && result < 0) (void)unlinkat(directory, name, 0);
    if (existing != NULL) {
        plamen_broker_v2_secure_zero(existing, size); free(existing);
    }
    return result;
}

/* 0 loaded, 1 absent, -1 malformed/error. */
static int read_exact(int directory, const char *name, uint8_t *bytes,
    size_t size)
{
    struct stat information; int descriptor, result = -1;
    descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return errno == ENOENT ? 1 : -1;
    if (fstat(descriptor, &information) == 0 && S_ISREG(information.st_mode)
        && information.st_nlink == 1 && information.st_uid == geteuid()
        && (information.st_mode & 0077) == 0
        && information.st_size == (off_t)size
        && pread_all(descriptor, bytes, size) == 0) result = 0;
    (void)close(descriptor); return result;
}

static int update_text(CC_SHA256_CTX *digest, const char *text)
{
    uint8_t size_bytes[4]; size_t size;
    if (text == NULL || (size = strlen(text)) > UINT32_MAX) return -1;
    store_u32(size_bytes, (uint32_t)size);
    return CC_SHA256_Update(digest, size_bytes, sizeof(size_bytes)) == 1
        && (size == 0 || CC_SHA256_Update(digest, text, (CC_LONG)size) == 1)
        ? 0 : -1;
}

static int update_fd_identity(CC_SHA256_CTX *digest, int descriptor)
{
    struct stat information; uint8_t bytes[48];
    if (descriptor < 0 || fstat(descriptor, &information) != 0) return -1;
    memset(bytes, 0, sizeof(bytes));
    store_u64(bytes, (uint64_t)information.st_dev);
    store_u64(bytes + 8, (uint64_t)information.st_ino);
    store_u64(bytes + 16, (uint64_t)information.st_size);
    store_u32(bytes + 24, (uint32_t)information.st_mode);
    store_u32(bytes + 28, (uint32_t)information.st_uid);
    store_u32(bytes + 32, (uint32_t)information.st_gid);
    return CC_SHA256_Update(digest, bytes, sizeof(bytes)) == 1 ? 0 : -1;
}

static int same_fd_identity(int left, int right)
{
    struct stat left_information, right_information;
    if (left < 0 || right < 0
        || fstat(left, &left_information) != 0
        || fstat(right, &right_information) != 0)
        return -1;
    return left_information.st_dev == right_information.st_dev
        && left_information.st_ino == right_information.st_ino
        && (left_information.st_mode & S_IFMT)
            == (right_information.st_mode & S_IFMT);
}

static int process_spec_digest(const struct plamen_broker_v2_process_spec *spec,
    uint8_t output[32])
{
    static const uint8_t domain[] = "plamen.native-process-custody.spec.v1";
    CC_SHA256_CTX digest; uint8_t number[8]; size_t index, prior;
    if (spec == NULL || spec->version != 1 || spec->argv == NULL
        || spec->argc == 0 || spec->argc > PLAMEN_BROKER_V2_PROCESS_ARGC_MAX
        || spec->environment_count > PLAMEN_BROKER_V2_PROCESS_ENVC_MAX
        || spec->fd_map_count > PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX
        || spec->expected_executable_sha256 == NULL
        || spec->expected_signing_identifier == NULL
        || spec->expected_team_identifier == NULL
        || (spec->environment_count != 0 && spec->environment == NULL)
        || (spec->fd_map_count != 0 && spec->fd_maps == NULL)) return -1;
    for (index = 0; index < spec->fd_map_count; ++index) {
        if (spec->fd_maps[index].source_fd < 0
            || spec->fd_maps[index].target_fd < 3
            || spec->fd_maps[index].target_fd >= 1024
            || same_fd_identity(spec->fd_maps[index].source_fd,
                spec->executable_fd) != 0
            || same_fd_identity(spec->fd_maps[index].source_fd,
                spec->cwd_fd) != 0
            || same_fd_identity(spec->fd_maps[index].source_fd,
                spec->stdin_fd) != 0)
            return -1;
        for (prior = 0; prior < index; ++prior) {
            if (spec->fd_maps[index].target_fd
                    == spec->fd_maps[prior].target_fd
                || same_fd_identity(spec->fd_maps[index].source_fd,
                    spec->fd_maps[prior].source_fd) != 0)
                return -1;
        }
    }
    if (CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, domain, sizeof(domain)) != 1
        || update_fd_identity(&digest, spec->executable_fd) != 0
        || update_fd_identity(&digest, spec->cwd_fd) != 0
        || update_fd_identity(&digest, spec->stdin_fd) != 0
        || update_text(&digest, spec->executable_path) != 0) return -1;
    store_u64(number, spec->argc);
    if (CC_SHA256_Update(&digest, number, 8) != 1) return -1;
    for (index = 0; index < spec->argc; ++index)
        if (update_text(&digest, spec->argv[index]) != 0) return -1;
    store_u32(number, spec->environment_policy);
    store_u32(number + 4, (uint32_t)spec->environment_count);
    if (CC_SHA256_Update(&digest, number, 8) != 1) return -1;
    for (index = 0; index < spec->environment_count; ++index)
        if (update_text(&digest, spec->environment[index]) != 0) return -1;
    store_u32(number, spec->timeout_seconds);
    store_u32(number + 4, spec->stdout_spool_limit);
    if (CC_SHA256_Update(&digest, number, 8) != 1) return -1;
    store_u32(number, spec->stderr_spool_limit);
    store_u32(number + 4, (uint32_t)spec->fd_map_count);
    if (CC_SHA256_Update(&digest, number, 8) != 1) return -1;
    for (index = 0; index < spec->fd_map_count; ++index) {
        store_u32(number, (uint32_t)spec->fd_maps[index].target_fd);
        store_u32(number + 4, 0);
        if (CC_SHA256_Update(&digest, number, 8) != 1
            || update_fd_identity(&digest, spec->fd_maps[index].source_fd) != 0)
            return -1;
    }
    if (CC_SHA256_Update(&digest, spec->expected_executable_sha256, 32) != 1
        || update_text(&digest, spec->expected_signing_identifier) != 0
        || update_text(&digest, spec->expected_team_identifier) != 0
        || CC_SHA256_Final(output, &digest) != 1) return -1;
    return 0;
}

static int encode_prepared(const uint8_t magic[8], uint32_t kind,
    const uint8_t operation_key[32], const uint8_t request[32],
    const uint8_t prior[32], const uint8_t claim[32],
    const uint8_t spec[32], uint8_t bytes[PREPARED_RECORD_SIZE])
{
    memset(bytes, 0, PREPARED_RECORD_SIZE); memcpy(bytes, magic, 8);
    store_u32(bytes + 8, 1); store_u32(bytes + 12, kind);
    store_u32(bytes + 16, PREPARED_RECORD_SIZE);
    memcpy(bytes + 24, operation_key, 32); memcpy(bytes + 56, request, 32);
    memcpy(bytes + 88, prior, 32); memcpy(bytes + 120, claim, 32);
    memcpy(bytes + 152, spec, 32);
    return plamen_broker_v2_sha256(bytes, PREPARED_DIGEST_OFFSET,
        bytes + PREPARED_DIGEST_OFFSET);
}

static int validate_prepared(const uint8_t bytes[PREPARED_RECORD_SIZE],
    const uint8_t operation_key[32], const uint8_t request[32],
    const uint8_t prior[32], const uint8_t claim[32])
{
    uint8_t digest[32];
    uint32_t kind = load_u32(bytes + 12);
    return ((kind == 1 && memcmp(bytes, "PLMPCP1\0", 8) == 0)
            || (kind == 3 && memcmp(bytes, "PLMPCW1\0", 8) == 0)
            || (kind == 4 && memcmp(bytes, "PLMPCR1\0", 8) == 0))
        && load_u32(bytes + 8) == 1
        && load_u32(bytes + 16) == PREPARED_RECORD_SIZE
        && zero_bytes(bytes + 20, 4) && zero_bytes(bytes + 184, 40)
        && plamen_broker_v2_sha256(bytes, PREPARED_DIGEST_OFFSET, digest) == 0
        && constant_equal(digest, bytes + PREPARED_DIGEST_OFFSET, 32)
        && constant_equal(bytes + 24, operation_key, 32)
        && constant_equal(bytes + 56, request, 32)
        && constant_equal(bytes + 88, prior, 32)
        && constant_equal(bytes + 120, claim, 32);
}

static int encode_started(
    const struct plamen_broker_v2_process_custodian_start_receipt *receipt,
    uint8_t bytes[STARTED_RECORD_SIZE])
{
    size_t signing_size = strnlen(receipt->identity.signing_identifier,
        PLAMEN_BROKER_V2_SIGNING_TEXT_MAX);
    size_t team_size = strnlen(receipt->identity.team_identifier,
        PLAMEN_BROKER_V2_SIGNING_TEXT_MAX);
    if (signing_size >= PLAMEN_BROKER_V2_SIGNING_TEXT_MAX
        || team_size >= PLAMEN_BROKER_V2_SIGNING_TEXT_MAX) return -1;
    memset(bytes, 0, STARTED_RECORD_SIZE); memcpy(bytes, "PLMPCS1\0", 8);
    store_u32(bytes + 8, 1); store_u32(bytes + 12, 2);
    store_u32(bytes + 16, STARTED_RECORD_SIZE);
    memcpy(bytes + 24, receipt->operation_key, 32);
    memcpy(bytes + 56, receipt->request_sha256, 32);
    memcpy(bytes + 88, receipt->prior_checkpoint_sha256, 32);
    memcpy(bytes + 120, receipt->claim_owner_sha256, 32);
    memcpy(bytes + 152, receipt->process_spec_sha256, 32);
    memcpy(bytes + 184, receipt->prepared_checkpoint_sha256, 32);
    store_u32(bytes + 216, (uint32_t)receipt->identity.child_pid);
    store_u32(bytes + 220, (uint32_t)receipt->identity.process_group_id);
    store_u64(bytes + 224, receipt->identity.child_birth_us);
    store_u64(bytes + 232, receipt->identity.executable_device);
    store_u64(bytes + 240, receipt->identity.executable_inode);
    memcpy(bytes + 248, receipt->identity.executable_sha256, 32);
    memcpy(bytes + 280, receipt->identity.executable_identity_sha256, 32);
    memcpy(bytes + 312, receipt->identity.native_process_handle_sha256, 32);
    memcpy(bytes + 344, receipt->identity.cdhash, 32);
    store_u32(bytes + 376, receipt->identity.cdhash_size);
    store_u32(bytes + 380, (uint32_t)signing_size);
    store_u32(bytes + 384, (uint32_t)team_size);
    memcpy(bytes + 388, receipt->identity.signing_identifier, signing_size);
    memcpy(bytes + 644, receipt->identity.team_identifier, team_size);
    return plamen_broker_v2_sha256(bytes, STARTED_DIGEST_OFFSET,
        bytes + STARTED_DIGEST_OFFSET);
}

static int decode_started(const uint8_t bytes[STARTED_RECORD_SIZE],
    struct plamen_broker_v2_process_custodian_start_receipt *receipt)
{
    uint8_t digest[32]; uint32_t signing_size, team_size;
    if (memcmp(bytes, "PLMPCS1\0", 8) != 0 || load_u32(bytes + 8) != 1
        || load_u32(bytes + 12) != 2
        || load_u32(bytes + 16) != STARTED_RECORD_SIZE
        || plamen_broker_v2_sha256(bytes, STARTED_DIGEST_OFFSET, digest) != 0
        || !constant_equal(digest, bytes + STARTED_DIGEST_OFFSET, 32)
        || !zero_bytes(bytes + 20, 4) || !zero_bytes(bytes + 900, 92)) return -1;
    signing_size = load_u32(bytes + 380); team_size = load_u32(bytes + 384);
    if (signing_size >= PLAMEN_BROKER_V2_SIGNING_TEXT_MAX
        || team_size >= PLAMEN_BROKER_V2_SIGNING_TEXT_MAX
        || !zero_bytes(bytes + 388 + signing_size,
            PLAMEN_BROKER_V2_SIGNING_TEXT_MAX - signing_size)
        || !zero_bytes(bytes + 644 + team_size,
            PLAMEN_BROKER_V2_SIGNING_TEXT_MAX - team_size)
        || load_u32(bytes + 216) == 0 || load_u32(bytes + 220) == 0
        || load_u64(bytes + 224) == 0 || load_u32(bytes + 376) > 32)
        return -1;
    memset(receipt, 0, sizeof(*receipt)); receipt->version = 1;
    receipt->status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK;
    memcpy(receipt->operation_key, bytes + 24, 32);
    memcpy(receipt->request_sha256, bytes + 56, 32);
    memcpy(receipt->prior_checkpoint_sha256, bytes + 88, 32);
    memcpy(receipt->claim_owner_sha256, bytes + 120, 32);
    memcpy(receipt->process_spec_sha256, bytes + 152, 32);
    memcpy(receipt->prepared_checkpoint_sha256, bytes + 184, 32);
    receipt->identity.version = 1;
    receipt->identity.child_pid = (int32_t)load_u32(bytes + 216);
    receipt->identity.process_group_id = (int32_t)load_u32(bytes + 220);
    receipt->identity.child_birth_us = load_u64(bytes + 224);
    receipt->identity.executable_device = load_u64(bytes + 232);
    receipt->identity.executable_inode = load_u64(bytes + 240);
    memcpy(receipt->identity.executable_sha256, bytes + 248, 32);
    memcpy(receipt->identity.executable_identity_sha256, bytes + 280, 32);
    memcpy(receipt->identity.native_process_handle_sha256, bytes + 312, 32);
    memcpy(receipt->identity.cdhash, bytes + 344, 32);
    receipt->identity.cdhash_size = load_u32(bytes + 376);
    memcpy(receipt->identity.signing_identifier, bytes + 388, signing_size);
    memcpy(receipt->identity.team_identifier, bytes + 644, team_size);
    memcpy(receipt->started_checkpoint_sha256,
        bytes + STARTED_DIGEST_OFFSET, 32);
    return 0;
}

static int matching_start_request(const struct custody_operation *operation,
    const struct plamen_broker_v2_process_custodian_start_request *request,
    const uint8_t spec_sha256[32])
{
    return constant_equal(operation->operation_key, request->operation_key, 32)
        && constant_equal(operation->request_sha256, request->request_sha256, 32)
        && constant_equal(operation->prior_checkpoint_sha256,
            request->prior_checkpoint_sha256, 32)
        && constant_equal(operation->claim_owner_sha256,
            request->claim_owner_sha256, 32)
        && constant_equal(operation->process_spec_sha256, spec_sha256, 32);
}

static struct custody_operation *find_operation(dev_t device, ino_t inode,
    const uint8_t operation_key[32])
{
    size_t index;
    for (index = 0; index < CUSTODY_MAX_OPERATIONS; ++index)
        if (operations[index].occupied
            && operations[index].state_device == device
            && operations[index].state_inode == inode
            && constant_equal(operations[index].operation_key,
                operation_key, 32)) return &operations[index];
    return NULL;
}

static int
closed_record_valid_for_operation(int directory,
    const struct custody_operation *operation)
{
    uint8_t closed[CLOSED_RECORD_SIZE], terminal[TERMINAL_RECORD_SIZE];
    uint8_t digest[32]; char name[96];
    if (record_name(operation->operation_key, "closed", name) != 0
        || read_exact(directory, name, closed, sizeof(closed)) != 0
        || memcmp(closed, "PLMPCC1\0", 8) != 0
        || load_u32(closed + 8) != 1 || load_u32(closed + 12) != 7
        || !constant_equal(closed + 16, operation->operation_key, 32)
        || !constant_equal(closed + 48, operation->request_sha256, 32)
        || !constant_equal(closed + 80,
            operation->prior_checkpoint_sha256, 32)
        || !constant_equal(closed + 112, operation->claim_owner_sha256, 32)
        || !constant_equal(closed + 144, operation->process_spec_sha256, 32)
        || !constant_equal(closed + 176,
            operation->started.started_checkpoint_sha256, 32)
        || !constant_equal(closed + 208,
            operation->terminal_operation_key, 32)
        || plamen_broker_v2_sha256(closed, CLOSED_DIGEST_OFFSET, digest) != 0
        || !constant_equal(digest, closed + CLOSED_DIGEST_OFFSET, 32)
        || record_name(operation->terminal_operation_key,
            "terminal", name) != 0
        || read_exact(directory, name, terminal, sizeof(terminal)) != 0
        || memcmp(terminal, "PLMPCT1\0", 8) != 0
        || !constant_equal(terminal + 24, operation->operation_key, 32)
        || !constant_equal(terminal + 56,
            operation->terminal_operation_key, 32)
        || plamen_broker_v2_sha256(terminal, TERMINAL_DIGEST_OFFSET,
            digest) != 0
        || !constant_equal(digest,
            terminal + TERMINAL_DIGEST_OFFSET, 32)
        || !constant_equal(terminal + TERMINAL_DIGEST_OFFSET,
            closed + 240, 32))
        return 0;
    return 1;
}

static struct custody_operation *allocate_operation(int directory,
    dev_t device, ino_t inode)
{
    size_t index;
    /*
     * A terminal operation remains replayable from its immutable records.
     * Reuse only a slot whose process and claim are gone and whose CLOSED
     * record was durably committed.  trylock is required: operations_lock
     * prevents new lookups, while trylock proves that no prior lookup still
     * owns the slot pointer.
     */
    for (index = 0; index < CUSTODY_MAX_OPERATIONS; ++index) {
        if (!operations[index].occupied
            || operations[index].state != CUSTODY_TERMINAL_DURABLE
            || operations[index].process != NULL
            || operations[index].claim_fd >= 0
            || pthread_mutex_trylock(&operations[index].lock) != 0)
            continue;
        if (!closed_record_valid_for_operation(directory, &operations[index])) {
            pthread_mutex_unlock(&operations[index].lock);
            continue;
        }
        pthread_mutex_unlock(&operations[index].lock);
        pthread_mutex_destroy(&operations[index].lock);
        memset(&operations[index], 0, sizeof(operations[index]));
        break;
    }
    for (index = 0; index < CUSTODY_MAX_OPERATIONS; ++index) {
        if (operations[index].occupied) continue;
        memset(&operations[index], 0, sizeof(operations[index]));
        operations[index].claim_fd = -1;
        if (pthread_mutex_init(&operations[index].lock, NULL) != 0)
            return NULL;
        operations[index].occupied = 1;
        operations[index].state_device = device;
        operations[index].state_inode = inode;
        return &operations[index];
    }
    return NULL;
}

/* 0 acquired, 1 owned by another broker process, -1 invalid/error. */
static int acquire_claim_fd(int directory, const uint8_t operation_key[32],
    int *claim_fd)
{
    struct stat information; char name[96]; int descriptor;
    *claim_fd = -1;
    if (record_name(operation_key, "claim", name) != 0) return -1;
    descriptor = openat(directory, name,
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_uid != geteuid() || (information.st_mode & 0077) != 0
        || information.st_size != 0) {
        if (descriptor >= 0) (void)close(descriptor);
        return -1;
    }
    if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        int busy = errno == EWOULDBLOCK || errno == EAGAIN;
        (void)close(descriptor); return busy ? 1 : -1;
    }
    *claim_fd = descriptor; return 0;
}

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
static int take_fault(uint32_t fault)
{
    int result = 0;
    pthread_mutex_lock(&fault_lock);
    if (injected_fault == fault) { injected_fault = 0; result = 1; }
    pthread_mutex_unlock(&fault_lock);
    return result;
}
#else
static int take_fault(uint32_t fault) { (void)fault; return 0; }
#endif

int
plamen_broker_v2_process_custodian_open(int state_parent_fd,
    struct plamen_broker_v2_process_custodian **output)
{
    struct plamen_broker_v2_process_custodian *custodian = NULL;
    struct stat information; int descriptor = -1;
    if (output == NULL) return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
    *output = NULL;
    if (!private_directory(state_parent_fd, &information))
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    if (mkdirat(state_parent_fd, CUSTODY_DIRECTORY, 0700) != 0 && errno != EEXIST)
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
    descriptor = openat(state_parent_fd, CUSTODY_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!private_directory(descriptor, &information) || sync_fd(state_parent_fd) != 0
        || (custodian = calloc(1, sizeof(*custodian))) == NULL) {
        if (descriptor >= 0) (void)close(descriptor);
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
    }
    custodian->state_fd = descriptor; custodian->state_device = information.st_dev;
    custodian->state_inode = information.st_ino; *output = custodian;
    return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK;
}

void
plamen_broker_v2_process_custodian_close(
    struct plamen_broker_v2_process_custodian *custodian)
{
    if (custodian == NULL) return;
    if (custodian->state_fd >= 0) (void)close(custodian->state_fd);
    memset(custodian, 0, sizeof(*custodian)); free(custodian);
}

static int start_record_state(
    struct plamen_broker_v2_process_custodian *custodian,
    const struct plamen_broker_v2_process_custodian_start_request *request,
    const uint8_t spec_sha256[32],
    struct plamen_broker_v2_process_custodian_start_receipt *receipt)
{
    uint8_t bytes[STARTED_RECORD_SIZE], closed[CLOSED_RECORD_SIZE];
    uint8_t terminal[TERMINAL_RECORD_SIZE], digest[32];
    char name[96]; int loaded;
    struct plamen_broker_v2_process_custodian_start_receipt decoded;
    if (record_name(request->operation_key, "started", name) != 0) return -1;
    loaded = read_exact(custodian->state_fd, name, bytes, sizeof(bytes));
    if (loaded == 1) {
        if (record_name(request->operation_key, "prepared", name) != 0) return -1;
        loaded = read_exact(custodian->state_fd, name, bytes, PREPARED_RECORD_SIZE);
        if (loaded == 1) return 0;
        return loaded == 0
            && validate_prepared(bytes, request->operation_key,
                request->request_sha256, request->prior_checkpoint_sha256,
                request->claim_owner_sha256)
            && constant_equal(bytes + 152, spec_sha256, 32) ? 1 : -1;
    }
    if (loaded != 0 || decode_started(bytes, &decoded) != 0
        || !constant_equal(decoded.operation_key, request->operation_key, 32)
        || !constant_equal(decoded.request_sha256, request->request_sha256, 32)
        || !constant_equal(decoded.prior_checkpoint_sha256,
            request->prior_checkpoint_sha256, 32)
        || !constant_equal(decoded.claim_owner_sha256,
            request->claim_owner_sha256, 32)
        || !constant_equal(decoded.process_spec_sha256, spec_sha256, 32)) return -1;
    if (record_name(request->operation_key, "closed", name) != 0)
        return -1;
    loaded = read_exact(custodian->state_fd, name, closed, sizeof(closed));
    if (loaded == 1)
        return 2;
    if (loaded != 0 || memcmp(closed, "PLMPCC1\0", 8) != 0
        || load_u32(closed + 8) != 1 || load_u32(closed + 12) != 7
        || !constant_equal(closed + 16, decoded.operation_key, 32)
        || !constant_equal(closed + 48, decoded.request_sha256, 32)
        || !constant_equal(closed + 80,
            decoded.prior_checkpoint_sha256, 32)
        || !constant_equal(closed + 112,
            decoded.claim_owner_sha256, 32)
        || !constant_equal(closed + 144, decoded.process_spec_sha256, 32)
        || !constant_equal(closed + 176,
            decoded.started_checkpoint_sha256, 32)
        || plamen_broker_v2_sha256(closed, CLOSED_DIGEST_OFFSET,
            digest) != 0
        || !constant_equal(digest, closed + CLOSED_DIGEST_OFFSET, 32)
        || record_name(closed + 208, "terminal", name) != 0
        || read_exact(custodian->state_fd, name, terminal,
            sizeof(terminal)) != 0
        || memcmp(terminal, "PLMPCT1\0", 8) != 0
        || !constant_equal(terminal + 24, request->operation_key, 32)
        || !constant_equal(terminal + 56, closed + 208, 32)
        || plamen_broker_v2_sha256(terminal, TERMINAL_DIGEST_OFFSET,
            digest) != 0
        || !constant_equal(digest,
            terminal + TERMINAL_DIGEST_OFFSET, 32)
        || !constant_equal(terminal + TERMINAL_DIGEST_OFFSET,
            closed + 240, 32))
        return -1;
    if (receipt != NULL) {
        *receipt = decoded;
        receipt->status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED;
    }
    return 3;
}

int
plamen_broker_v2_process_custodian_start(
    struct plamen_broker_v2_process_custodian *custodian,
    const struct plamen_broker_v2_process_custodian_start_request *request,
    struct plamen_broker_v2_process_custodian_start_receipt *receipt)
{
    static const uint8_t prepared_magic[8] = "PLMPCP1";
    struct custody_operation *operation;
    struct plamen_broker_v2_process_prepared_identity prepared_identity;
    uint8_t spec_sha256[32], prepared_bytes[PREPARED_RECORD_SIZE];
    uint8_t started_bytes[STARTED_RECORD_SIZE]; char name[96]; int published;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (custodian == NULL || request == NULL || receipt == NULL
        || request->version != 1
        || all_zero(request->operation_key) || all_zero(request->request_sha256)
        || all_zero(request->claim_owner_sha256)
        || process_spec_digest(request->process_spec, spec_sha256) != 0)
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    pthread_mutex_lock(&operations_lock);
    operation = find_operation(custodian->state_device, custodian->state_inode,
        request->operation_key);
    if (operation == NULL) {
        int claim_descriptor = -1;
        int claimed = acquire_claim_fd(custodian->state_fd,
            request->operation_key, &claim_descriptor);
        int durable;
        if (claimed != 0) {
            pthread_mutex_unlock(&operations_lock);
            return claimed > 0 ? PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_BUSY
                : PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
        }
        durable = start_record_state(custodian, request, spec_sha256, receipt);
        if (durable != 0) {
            (void)close(claim_descriptor);
            pthread_mutex_unlock(&operations_lock);
            if (durable == 3)
                return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED;
            return durable > 0
                ? PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS
                : PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
        }
        operation = allocate_operation(custodian->state_fd,
            custodian->state_device,
            custodian->state_inode);
        if (operation == NULL) {
            (void)close(claim_descriptor);
            pthread_mutex_unlock(&operations_lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
        }
        memcpy(operation->operation_key, request->operation_key, 32);
        memcpy(operation->request_sha256, request->request_sha256, 32);
        memcpy(operation->prior_checkpoint_sha256,
            request->prior_checkpoint_sha256, 32);
        memcpy(operation->claim_owner_sha256, request->claim_owner_sha256, 32);
        memcpy(operation->process_spec_sha256, spec_sha256, 32);
        operation->claim_fd = claim_descriptor;
        operation->stdout_retain_limit = request->process_spec->stdout_spool_limit;
        operation->stderr_retain_limit = request->process_spec->stderr_spool_limit;
    }
    pthread_mutex_lock(&operation->lock); pthread_mutex_unlock(&operations_lock);
    if (!matching_start_request(operation, request, spec_sha256)) {
        pthread_mutex_unlock(&operation->lock);
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    }
    if (operation->state >= CUSTODY_STARTED_DURABLE) {
        if (operation->state == CUSTODY_FAILED_AMBIGUOUS) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
        }
        *receipt = operation->started;
        pthread_mutex_unlock(&operation->lock);
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED;
    }
    if (operation->state == CUSTODY_UNUSED) {
        if (encode_prepared(prepared_magic, 1, request->operation_key,
                request->request_sha256, request->prior_checkpoint_sha256,
                request->claim_owner_sha256, spec_sha256, prepared_bytes) != 0
            || record_name(request->operation_key, "prepared", name) != 0
            || (published = publish_exact(custodian->state_fd, name,
                prepared_bytes, sizeof(prepared_bytes))) < 0) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
        }
        (void)published;
        memcpy(operation->prepared_checkpoint_sha256,
            prepared_bytes + PREPARED_DIGEST_OFFSET, 32);
        operation->state = CUSTODY_START_PREPARED;
        if (take_fault(PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_START_PREPARED)) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
        }
    }
    if (operation->state == CUSTODY_START_PREPARED) {
        memset(&prepared_identity, 0, sizeof(prepared_identity));
        if (plamen_broker_v2_process_prepare(request->process_spec,
                &prepared_identity, &operation->process) != 0) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
        }
        operation->state = CUSTODY_PROCESS_PREPARED;
        if (take_fault(PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_PROCESS_PREPARE)) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
        }
    }
    if (operation->state == CUSTODY_PROCESS_PREPARED) {
        memset(&operation->started, 0, sizeof(operation->started));
        if (plamen_broker_v2_process_start(operation->process,
                &operation->started.identity) != 0) {
            int extinguished = plamen_broker_v2_process_extinguish(
                operation->process, NULL);
            int closed = plamen_broker_v2_process_close(operation->process);
            if (closed == PLAMEN_BROKER_V2_PROCESS_OK)
                operation->process = NULL;
            operation->state = CUSTODY_FAILED_AMBIGUOUS;
            if (operation->process == NULL && operation->claim_fd >= 0) {
                (void)flock(operation->claim_fd, LOCK_UN);
                (void)close(operation->claim_fd); operation->claim_fd = -1;
            }
            (void)extinguished;
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
        }
        operation->started.version = 1;
        operation->started.status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK;
        memcpy(operation->started.operation_key, request->operation_key, 32);
        memcpy(operation->started.request_sha256, request->request_sha256, 32);
        memcpy(operation->started.prior_checkpoint_sha256,
            request->prior_checkpoint_sha256, 32);
        memcpy(operation->started.claim_owner_sha256,
            request->claim_owner_sha256, 32);
        memcpy(operation->started.process_spec_sha256, spec_sha256, 32);
        memcpy(operation->started.prepared_checkpoint_sha256,
            operation->prepared_checkpoint_sha256, 32);
        operation->state = CUSTODY_START_EFFECT;
        if (take_fault(PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_START_EFFECT)) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
        }
    }
    if (operation->state == CUSTODY_START_EFFECT) {
        if (encode_started(&operation->started, started_bytes) != 0
            || record_name(request->operation_key, "started", name) != 0
            || publish_exact(custodian->state_fd, name, started_bytes,
                sizeof(started_bytes)) < 0) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
        }
        memcpy(operation->started.started_checkpoint_sha256,
            started_bytes + STARTED_DIGEST_OFFSET, 32);
        operation->state = CUSTODY_STARTED_DURABLE;
        if (take_fault(PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_STARTED_DURABLE)) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
        }
    }
    *receipt = operation->started;
    pthread_mutex_unlock(&operation->lock);
    return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK;
}

int
plamen_broker_v2_process_custodian_recover_start(
    struct plamen_broker_v2_process_custodian *custodian,
    const struct plamen_broker_v2_process_custodian_start_request *request,
    struct plamen_broker_v2_process_custodian_start_receipt *receipt)
{
    return plamen_broker_v2_process_custodian_start(custodian, request, receipt);
}

int
plamen_broker_v2_process_custodian_adopt_start(
    struct plamen_broker_v2_process_custodian *custodian,
    const struct plamen_broker_v2_process_custodian_start_recovery_request *request,
    struct plamen_broker_v2_process_custodian_start_receipt *receipt)
{
    struct custody_operation *operation;
    uint8_t bytes[STARTED_RECORD_SIZE], closed[CLOSED_RECORD_SIZE];
    char name[96];
    struct plamen_broker_v2_process_custodian_start_receipt durable;
    struct custody_operation completed;

    if (receipt != NULL)
        memset(receipt, 0, sizeof(*receipt));
    if (custodian == NULL || request == NULL || receipt == NULL
        || request->version != 1 || all_zero(request->operation_key)
        || all_zero(request->request_sha256)
        || all_zero(request->claim_owner_sha256))
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;

    pthread_mutex_lock(&operations_lock);
    operation = find_operation(custodian->state_device, custodian->state_inode,
        request->operation_key);
    if (operation != NULL) {
        pthread_mutex_lock(&operation->lock);
        pthread_mutex_unlock(&operations_lock);
        if (!constant_equal(operation->request_sha256,
                request->request_sha256, 32)
            || !constant_equal(operation->prior_checkpoint_sha256,
                request->prior_checkpoint_sha256, 32)
            || !constant_equal(operation->claim_owner_sha256,
                request->claim_owner_sha256, 32)) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
        }
        if (operation->state >= CUSTODY_STARTED_DURABLE
            && operation->state != CUSTODY_FAILED_AMBIGUOUS) {
            *receipt = operation->started;
            receipt->status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED;
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED;
        }
        pthread_mutex_unlock(&operation->lock);
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
    }
    pthread_mutex_unlock(&operations_lock);

    if (record_name(request->operation_key, "started", name) != 0
        || read_exact(custodian->state_fd, name, bytes, sizeof(bytes)) != 0
        || decode_started(bytes, &durable) != 0)
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    if (!constant_equal(durable.operation_key, request->operation_key, 32)
        || !constant_equal(durable.request_sha256, request->request_sha256, 32)
        || !constant_equal(durable.prior_checkpoint_sha256,
            request->prior_checkpoint_sha256, 32)
        || !constant_equal(durable.claim_owner_sha256,
            request->claim_owner_sha256, 32))
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    if (record_name(request->operation_key, "closed", name) != 0
        || read_exact(custodian->state_fd, name, closed,
            sizeof(closed)) != 0)
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
    memset(&completed, 0, sizeof(completed));
    completed.state = CUSTODY_TERMINAL_DURABLE;
    completed.state_device = custodian->state_device;
    completed.state_inode = custodian->state_inode;
    memcpy(completed.operation_key, durable.operation_key, 32);
    memcpy(completed.request_sha256, durable.request_sha256, 32);
    memcpy(completed.prior_checkpoint_sha256,
        durable.prior_checkpoint_sha256, 32);
    memcpy(completed.claim_owner_sha256, durable.claim_owner_sha256, 32);
    memcpy(completed.process_spec_sha256, durable.process_spec_sha256, 32);
    completed.started = durable;
    memcpy(completed.terminal_operation_key, closed + 208, 32);
    if (!closed_record_valid_for_operation(custodian->state_fd, &completed))
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    *receipt = durable;
    receipt->status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED;
    return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED;
}

static int read_retained(struct plamen_broker_v2_process *process,
    uint32_t stream, uint64_t observed_size,
    const uint8_t observed_sha256[32], uint32_t limit,
    uint8_t **output, uint32_t *output_size, uint8_t output_sha256[32])
{
    CC_SHA256_CTX digest; uint8_t chunk_sha[32], computed_chunk_sha[32];
    uint8_t full_sha[32], eof = 0;
    uint64_t full_size = 0, offset = 0; uint32_t amount, maximum;
    size_t capacity = observed_size < limit ? (size_t)observed_size : limit;
    uint8_t *bytes = capacity == 0 ? NULL : malloc(capacity);
    uint8_t empty[1];
    if (capacity != 0 && bytes == NULL) return -1;
    while (!eof) {
        maximum = (uint32_t)(capacity - (size_t)offset);
        if (maximum > 262144U) maximum = 262144U;
        if (maximum == 0) break;
        if (plamen_broker_v2_process_read_output(process, stream, offset,
                maximum, bytes + offset, maximum, &amount, &eof, chunk_sha,
                full_sha, &full_size) != 0 || amount > maximum
            || CC_SHA256(bytes + offset, amount, computed_chunk_sha) == NULL
            || !constant_equal(chunk_sha, computed_chunk_sha, 32)
            || full_size != observed_size
            || !constant_equal(full_sha, observed_sha256, 32)) {
            free(bytes); return -1;
        }
        offset += amount;
    }
    if (capacity == 0) {
        if (CC_SHA256(empty, 0, output_sha256) == NULL) return -1;
    } else {
        if (offset != capacity || CC_SHA256_Init(&digest) != 1
            || CC_SHA256_Update(&digest, bytes, (CC_LONG)capacity) != 1
            || CC_SHA256_Final(output_sha256, &digest) != 1) {
            free(bytes); return -1;
        }
    }
    *output = bytes; *output_size = (uint32_t)capacity; return 0;
}

static int encode_spool(uint32_t stream, const uint8_t operation_key[32],
    const uint8_t *bytes, uint32_t size, const uint8_t sha256[32],
    uint8_t **record, size_t *record_size, uint8_t checkpoint[32])
{
    size_t total = SPOOL_HEADER_SIZE + size + SPOOL_TRAILER_SIZE;
    uint8_t *output = calloc(1, total);
    if (output == NULL || (size != 0 && bytes == NULL)) { free(output); return -1; }
    memcpy(output, "PLMPCO1\0", 8); store_u32(output + 8, 1);
    store_u32(output + 12, stream); store_u32(output + 16, (uint32_t)total);
    store_u32(output + 20, size); memcpy(output + 24, operation_key, 32);
    memcpy(output + 56, sha256, 32);
    if (size != 0) memcpy(output + SPOOL_HEADER_SIZE, bytes, size);
    if (plamen_broker_v2_sha256(output, total - 32, output + total - 32) != 0) {
        free(output); return -1;
    }
    memcpy(checkpoint, output + total - 32, 32); *record = output;
    *record_size = total; return 0;
}

static int publish_spool(int directory, const uint8_t operation_key[32],
    const char *suffix, uint32_t stream, const uint8_t *bytes, uint32_t size,
    const uint8_t sha256[32], uint8_t checkpoint[32])
{
    uint8_t *record = NULL; size_t record_size = 0; char name[96]; int result;
    if (record_name(operation_key, suffix, name) != 0
        || encode_spool(stream, operation_key, bytes, size, sha256,
            &record, &record_size, checkpoint) != 0) return -1;
    result = publish_exact(directory, name, record, record_size);
    plamen_broker_v2_secure_zero(record, record_size); free(record);
    return result < 0 ? -1 : 0;
}

static int encode_terminal(
    const struct plamen_broker_v2_process_custodian_terminal_receipt *receipt,
    uint8_t bytes[TERMINAL_RECORD_SIZE])
{
    memset(bytes, 0, TERMINAL_RECORD_SIZE); memcpy(bytes, "PLMPCT1\0", 8);
    store_u32(bytes + 8, 1); store_u32(bytes + 12, 3);
    store_u32(bytes + 16, TERMINAL_RECORD_SIZE);
    memcpy(bytes + 24, receipt->start_operation_key, 32);
    memcpy(bytes + 56, receipt->operation_key, 32);
    memcpy(bytes + 88, receipt->request_sha256, 32);
    memcpy(bytes + 120, receipt->prior_checkpoint_sha256, 32);
    memcpy(bytes + 152, receipt->claim_owner_sha256, 32);
    memcpy(bytes + 184, receipt->process_spec_sha256, 32);
    memcpy(bytes + 216, receipt->native_process_handle_sha256, 32);
    store_u32(bytes + 248, receipt->terminal.version);
    store_u32(bytes + 252, receipt->terminal.status);
    store_u32(bytes + 256, (uint32_t)receipt->terminal.exit_code);
    store_u32(bytes + 260, (uint32_t)receipt->terminal.signal_number);
    store_u32(bytes + 264, (uint32_t)receipt->terminal.child_pid);
    store_u32(bytes + 268, (uint32_t)receipt->terminal.process_group_id);
    store_u64(bytes + 272, receipt->terminal.child_birth_us);
    store_u64(bytes + 280, receipt->terminal.stdout_size);
    store_u64(bytes + 288, receipt->terminal.stderr_size);
    memcpy(bytes + 296, receipt->terminal.stdout_sha256, 32);
    memcpy(bytes + 328, receipt->terminal.stderr_sha256, 32);
    bytes[360] = receipt->terminal.stdout_overflow;
    bytes[361] = receipt->terminal.stderr_overflow;
    bytes[362] = receipt->terminal.child_reaped;
    bytes[363] = receipt->terminal.process_group_extinct;
    store_u32(bytes + 364, receipt->stdout_retained_size);
    store_u32(bytes + 368, receipt->stderr_retained_size);
    memcpy(bytes + 372, receipt->stdout_retained_sha256, 32);
    memcpy(bytes + 404, receipt->stderr_retained_sha256, 32);
    memcpy(bytes + 436, receipt->stdout_spool_checkpoint_sha256, 32);
    memcpy(bytes + 468, receipt->stderr_spool_checkpoint_sha256, 32);
    memcpy(bytes + 500, receipt->prepared_checkpoint_sha256, 32);
    return plamen_broker_v2_sha256(bytes, TERMINAL_DIGEST_OFFSET,
        bytes + TERMINAL_DIGEST_OFFSET);
}

static int
publish_closed(int directory, const struct custody_operation *operation,
    const struct plamen_broker_v2_process_custodian_terminal_receipt *receipt)
{
    uint8_t bytes[CLOSED_RECORD_SIZE]; char name[96];
    memset(bytes, 0, sizeof(bytes));
    memcpy(bytes, "PLMPCC1\0", 8);
    store_u32(bytes + 8, 1); store_u32(bytes + 12, 7);
    memcpy(bytes + 16, operation->operation_key, 32);
    memcpy(bytes + 48, operation->request_sha256, 32);
    memcpy(bytes + 80, operation->prior_checkpoint_sha256, 32);
    memcpy(bytes + 112, operation->claim_owner_sha256, 32);
    memcpy(bytes + 144, operation->process_spec_sha256, 32);
    memcpy(bytes + 176, operation->started.started_checkpoint_sha256, 32);
    memcpy(bytes + 208, receipt->operation_key, 32);
    memcpy(bytes + 240, receipt->terminal_checkpoint_sha256, 32);
    if (plamen_broker_v2_sha256(bytes, CLOSED_DIGEST_OFFSET,
            bytes + CLOSED_DIGEST_OFFSET) != 0
        || record_name(operation->operation_key, "closed", name) != 0
        || publish_exact(directory, name, bytes, sizeof(bytes)) < 0)
        return -1;
    return 0;
}

static int read_spool(int directory, const uint8_t operation_key[32],
    const char *suffix, uint32_t stream, uint32_t expected_size,
    const uint8_t expected_sha[32], const uint8_t expected_checkpoint[32],
    uint8_t **output)
{
    struct stat information; CC_SHA256_CTX digest;
    uint8_t *record = NULL, observed[32]; char name[96]; int descriptor = -1;
    size_t total = SPOOL_HEADER_SIZE + expected_size + SPOOL_TRAILER_SIZE;
    *output = NULL;
    if (record_name(operation_key, suffix, name) != 0
        || (record = malloc(total)) == NULL) goto fail;
    descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_uid != geteuid() || (information.st_mode & 0077) != 0
        || information.st_size != (off_t)total
        || pread_all(descriptor, record, total) != 0
        || memcmp(record, "PLMPCO1\0", 8) != 0 || load_u32(record + 8) != 1
        || load_u32(record + 12) != stream || load_u32(record + 16) != total
        || load_u32(record + 20) != expected_size
        || !constant_equal(record + 24, operation_key, 32)
        || !constant_equal(record + 56, expected_sha, 32)
        || plamen_broker_v2_sha256(record, total - 32, observed) != 0
        || !constant_equal(observed, record + total - 32, 32)
        || !constant_equal(observed, expected_checkpoint, 32)
        || CC_SHA256_Init(&digest) != 1
        || (expected_size != 0 && CC_SHA256_Update(&digest,
            record + SPOOL_HEADER_SIZE, expected_size) != 1)
        || CC_SHA256_Final(observed, &digest) != 1
        || !constant_equal(observed, expected_sha, 32)) goto fail;
    if (descriptor >= 0) (void)close(descriptor);
    if (expected_size != 0) {
        *output = malloc(expected_size);
        if (*output == NULL) goto fail;
        memcpy(*output, record + SPOOL_HEADER_SIZE, expected_size);
    }
    plamen_broker_v2_secure_zero(record, total); free(record); return 0;
fail:
    if (descriptor >= 0) (void)close(descriptor);
    if (record != NULL) { plamen_broker_v2_secure_zero(record, total); free(record); }
    free(*output); *output = NULL; return -1;
}

static int decode_terminal(int directory,
    const struct plamen_broker_v2_process_custodian_terminal_request *request,
    const uint8_t bytes[TERMINAL_RECORD_SIZE],
    struct plamen_broker_v2_process_custodian_terminal_receipt *receipt)
{
    uint8_t digest[32], started_bytes[STARTED_RECORD_SIZE]; char started_name[96];
    struct plamen_broker_v2_process_custodian_start_receipt started;
    if (memcmp(bytes, "PLMPCT1\0", 8) != 0 || load_u32(bytes + 8) != 1
        || load_u32(bytes + 12) != 3
        || load_u32(bytes + 16) != TERMINAL_RECORD_SIZE
        || plamen_broker_v2_sha256(bytes, TERMINAL_DIGEST_OFFSET, digest) != 0
        || !constant_equal(digest, bytes + TERMINAL_DIGEST_OFFSET, 32)
        || !constant_equal(bytes + 24, request->start_operation_key, 32)
        || !constant_equal(bytes + 56, request->operation_key, 32)
        || !constant_equal(bytes + 88, request->request_sha256, 32)
        || !constant_equal(bytes + 120, request->prior_checkpoint_sha256, 32)
        || !constant_equal(bytes + 152, request->claim_owner_sha256, 32)
        || !zero_bytes(bytes + 20, 4) || !zero_bytes(bytes + 532, 460))
        return -1;
    memset(receipt, 0, sizeof(*receipt)); receipt->version = 1;
    receipt->status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK;
    memcpy(receipt->start_operation_key, bytes + 24, 32);
    memcpy(receipt->operation_key, bytes + 56, 32);
    memcpy(receipt->request_sha256, bytes + 88, 32);
    memcpy(receipt->prior_checkpoint_sha256, bytes + 120, 32);
    memcpy(receipt->claim_owner_sha256, bytes + 152, 32);
    memcpy(receipt->process_spec_sha256, bytes + 184, 32);
    memcpy(receipt->native_process_handle_sha256, bytes + 216, 32);
    receipt->terminal.version = load_u32(bytes + 248);
    receipt->terminal.status = load_u32(bytes + 252);
    receipt->terminal.exit_code = (int32_t)load_u32(bytes + 256);
    receipt->terminal.signal_number = (int32_t)load_u32(bytes + 260);
    receipt->terminal.child_pid = (int32_t)load_u32(bytes + 264);
    receipt->terminal.process_group_id = (int32_t)load_u32(bytes + 268);
    receipt->terminal.child_birth_us = load_u64(bytes + 272);
    receipt->terminal.stdout_size = load_u64(bytes + 280);
    receipt->terminal.stderr_size = load_u64(bytes + 288);
    memcpy(receipt->terminal.stdout_sha256, bytes + 296, 32);
    memcpy(receipt->terminal.stderr_sha256, bytes + 328, 32);
    receipt->terminal.stdout_overflow = bytes[360];
    receipt->terminal.stderr_overflow = bytes[361];
    receipt->terminal.child_reaped = bytes[362];
    receipt->terminal.process_group_extinct = bytes[363];
    receipt->stdout_retained_size = load_u32(bytes + 364);
    receipt->stderr_retained_size = load_u32(bytes + 368);
    if (receipt->terminal.version != 1
        || (receipt->terminal.status != PLAMEN_BROKER_V2_PROCESS_OK
            && receipt->terminal.status != PLAMEN_BROKER_V2_PROCESS_TIMEOUT
            && receipt->terminal.status != PLAMEN_BROKER_V2_PROCESS_CANCELLED)
        || receipt->terminal.child_pid <= 0
        || receipt->terminal.process_group_id != receipt->terminal.child_pid
        || receipt->terminal.child_birth_us == 0
        || receipt->terminal.stdout_overflow != 0
        || receipt->terminal.stderr_overflow != 0
        || receipt->terminal.child_reaped != 1
        || receipt->terminal.process_group_extinct != 1
        || receipt->stdout_retained_size > PLAMEN_BROKER_V2_RETAIN_MAX
        || receipt->stderr_retained_size > PLAMEN_BROKER_V2_RETAIN_MAX
        || receipt->terminal.stdout_size > PLAMEN_BROKER_V2_OBSERVED_MAX
        || receipt->terminal.stderr_size > PLAMEN_BROKER_V2_OBSERVED_MAX
        || receipt->stdout_retained_size > receipt->terminal.stdout_size
        || receipt->stderr_retained_size > receipt->terminal.stderr_size)
        return -1;
    memcpy(receipt->stdout_retained_sha256, bytes + 372, 32);
    memcpy(receipt->stderr_retained_sha256, bytes + 404, 32);
    memcpy(receipt->stdout_spool_checkpoint_sha256, bytes + 436, 32);
    memcpy(receipt->stderr_spool_checkpoint_sha256, bytes + 468, 32);
    memcpy(receipt->prepared_checkpoint_sha256, bytes + 500, 32);
    memcpy(receipt->terminal_checkpoint_sha256,
        bytes + TERMINAL_DIGEST_OFFSET, 32);
    if (record_name(request->start_operation_key, "started", started_name) != 0
        || read_exact(directory, started_name, started_bytes,
            sizeof(started_bytes)) != 0
        || decode_started(started_bytes, &started) != 0
        || !constant_equal(started.operation_key,
            receipt->start_operation_key, 32)
        || !constant_equal(started.claim_owner_sha256,
            receipt->claim_owner_sha256, 32)
        || !constant_equal(started.process_spec_sha256,
            receipt->process_spec_sha256, 32)
        || !constant_equal(started.identity.native_process_handle_sha256,
            receipt->native_process_handle_sha256, 32)
        || !constant_equal(started.started_checkpoint_sha256,
            receipt->prior_checkpoint_sha256, 32))
        return -1;
    if (read_spool(directory, request->operation_key, "stdout", 1,
            receipt->stdout_retained_size, receipt->stdout_retained_sha256,
            receipt->stdout_spool_checkpoint_sha256,
            &receipt->stdout_retained) != 0
        || read_spool(directory, request->operation_key, "stderr", 2,
            receipt->stderr_retained_size, receipt->stderr_retained_sha256,
            receipt->stderr_spool_checkpoint_sha256,
            &receipt->stderr_retained) != 0) {
        plamen_broker_v2_process_custodian_terminal_dispose(receipt); return -1;
    }
    return 0;
}

static int terminal_request_matches(const struct custody_operation *operation,
    const struct plamen_broker_v2_process_custodian_terminal_request *request,
    uint8_t kind)
{
    return constant_equal(operation->operation_key,
            request->start_operation_key, 32)
        && constant_equal(operation->claim_owner_sha256,
            request->claim_owner_sha256, 32)
        && constant_equal(operation->started.started_checkpoint_sha256,
            request->prior_checkpoint_sha256, 32)
        && (operation->terminal_kind == 0
            || (operation->terminal_kind == kind
                && constant_equal(operation->terminal_operation_key,
                    request->operation_key, 32)
                && constant_equal(operation->terminal_request_sha256,
                    request->request_sha256, 32)
                && constant_equal(operation->terminal_prior_checkpoint_sha256,
                    request->prior_checkpoint_sha256, 32)));
}

static int durable_start_owned(
    struct plamen_broker_v2_process_custodian *custodian,
    const uint8_t operation_key[32], const uint8_t claim_owner[32])
{
    uint8_t bytes[STARTED_RECORD_SIZE]; char name[96];
    struct plamen_broker_v2_process_custodian_start_receipt receipt;
    if (record_name(operation_key, "started", name) != 0
        || read_exact(custodian->state_fd, name, bytes, sizeof(bytes)) != 0
        || decode_started(bytes, &receipt) != 0) return 0;
    return constant_equal(receipt.operation_key, operation_key, 32)
        && constant_equal(receipt.claim_owner_sha256, claim_owner, 32);
}

static int terminal_effect(
    struct plamen_broker_v2_process_custodian *custodian,
    const struct plamen_broker_v2_process_custodian_terminal_request *request,
    struct plamen_broker_v2_process_custodian_terminal_receipt *receipt,
    uint8_t kind)
{
    static const uint8_t wait_magic[8] = "PLMPCW1";
    static const uint8_t revoke_magic[8] = "PLMPCR1";
    struct custody_operation *operation; struct plamen_broker_v2_process_terminal terminal;
    uint8_t prepared[PREPARED_RECORD_SIZE], terminal_bytes[TERMINAL_RECORD_SIZE];
    char name[96]; int process_status;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (custodian == NULL || request == NULL || receipt == NULL
        || request->version != 1 || all_zero(request->start_operation_key)
        || all_zero(request->operation_key) || all_zero(request->request_sha256)
        || all_zero(request->claim_owner_sha256))
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    pthread_mutex_lock(&operations_lock);
    operation = find_operation(custodian->state_device, custodian->state_inode,
        request->start_operation_key);
    if (operation == NULL) {
        uint8_t durable_terminal[TERMINAL_RECORD_SIZE]; char terminal_name[96];
        int recovered, claim_fd = -1, claimed, terminal_presence;
        pthread_mutex_unlock(&operations_lock);
        if (record_name(request->operation_key, "terminal", terminal_name) != 0)
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
        terminal_presence = read_exact(custodian->state_fd, terminal_name,
            durable_terminal, sizeof(durable_terminal));
        if (terminal_presence < 0)
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
        if (terminal_presence == 0)
            return plamen_broker_v2_process_custodian_recover_terminal(custodian,
                request, receipt);
        claimed = acquire_claim_fd(custodian->state_fd,
            request->start_operation_key, &claim_fd);
        if (claimed > 0) return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_BUSY;
        if (claimed < 0) return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
        recovered = durable_start_owned(custodian,
            request->start_operation_key, request->claim_owner_sha256);
        if (claim_fd >= 0) (void)close(claim_fd);
        return recovered ? PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS
            : PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    }
    pthread_mutex_lock(&operation->lock); pthread_mutex_unlock(&operations_lock);
    if (!terminal_request_matches(operation, request, kind)) {
        pthread_mutex_unlock(&operation->lock);
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    }
    if (operation->state == CUSTODY_TERMINAL_DURABLE) {
        int recovered;
        if (operation->process != NULL) {
            if (plamen_broker_v2_process_close(operation->process) != 0) {
                pthread_mutex_unlock(&operation->lock);
                return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
            }
            operation->process = NULL;
        }
        recovered = plamen_broker_v2_process_custodian_recover_terminal(
            custodian, request, receipt);
        if (recovered != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED
            || publish_closed(custodian->state_fd, operation, receipt) != 0) {
            plamen_broker_v2_process_custodian_terminal_dispose(receipt);
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
        }
        if (operation->claim_fd >= 0) {
            (void)flock(operation->claim_fd, LOCK_UN);
            (void)close(operation->claim_fd); operation->claim_fd = -1;
        }
        pthread_mutex_unlock(&operation->lock);
        return recovered;
    }
    if (operation->state < CUSTODY_STARTED_DURABLE || operation->process == NULL) {
        pthread_mutex_unlock(&operation->lock);
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
    }
    if (operation->terminal_kind == 0) {
        operation->terminal_kind = kind;
        memcpy(operation->terminal_operation_key, request->operation_key, 32);
        memcpy(operation->terminal_request_sha256, request->request_sha256, 32);
        memcpy(operation->terminal_prior_checkpoint_sha256,
            request->prior_checkpoint_sha256, 32);
    }
    if (operation->state == CUSTODY_STARTED_DURABLE) {
        if (encode_prepared(kind == 1 ? wait_magic : revoke_magic, kind + 2,
                request->operation_key, request->request_sha256,
                request->prior_checkpoint_sha256, request->claim_owner_sha256,
                operation->process_spec_sha256, prepared) != 0
            || record_name(request->operation_key, "prepared", name) != 0
            || publish_exact(custodian->state_fd, name, prepared,
                sizeof(prepared)) < 0) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
        }
        memcpy(operation->terminal_prepared_checkpoint_sha256,
            prepared + PREPARED_DIGEST_OFFSET, 32);
        operation->state = CUSTODY_TERMINAL_PREPARED;
        if (take_fault(PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_TERMINAL_PREPARED)) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
        }
    }
    if (operation->state == CUSTODY_TERMINAL_PREPARED) {
        memset(&terminal, 0, sizeof(terminal));
        process_status = kind == 1
            ? plamen_broker_v2_process_wait(operation->process, &terminal)
            : plamen_broker_v2_process_extinguish(operation->process, &terminal);
        if (process_status == PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED
            || process_status == PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR
            || process_status == PLAMEN_BROKER_V2_PROCESS_OVERFLOW) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
        }
        operation->state = CUSTODY_TERMINAL_EFFECT;
        if (take_fault(PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_TERMINAL_EFFECT)) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
        }
    } else {
        memset(&terminal, 0, sizeof(terminal));
        process_status = plamen_broker_v2_process_wait(operation->process, &terminal);
        if (process_status == PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED
            || process_status == PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR
            || process_status == PLAMEN_BROKER_V2_PROCESS_OVERFLOW) {
            pthread_mutex_unlock(&operation->lock);
            return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
        }
    }
    memset(receipt, 0, sizeof(*receipt)); receipt->version = 1;
    receipt->status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK;
    memcpy(receipt->start_operation_key, request->start_operation_key, 32);
    memcpy(receipt->operation_key, request->operation_key, 32);
    memcpy(receipt->request_sha256, request->request_sha256, 32);
    memcpy(receipt->prior_checkpoint_sha256, request->prior_checkpoint_sha256, 32);
    memcpy(receipt->claim_owner_sha256, request->claim_owner_sha256, 32);
    memcpy(receipt->process_spec_sha256, operation->process_spec_sha256, 32);
    memcpy(receipt->native_process_handle_sha256,
        operation->started.identity.native_process_handle_sha256, 32);
    receipt->terminal = terminal;
    memcpy(receipt->prepared_checkpoint_sha256,
        operation->terminal_prepared_checkpoint_sha256, 32);
    if (read_retained(operation->process, PLAMEN_BROKER_V2_PROCESS_STREAM_STDOUT,
            terminal.stdout_size, terminal.stdout_sha256,
            operation->stdout_retain_limit,
            &receipt->stdout_retained, &receipt->stdout_retained_size,
            receipt->stdout_retained_sha256) != 0
        || read_retained(operation->process, PLAMEN_BROKER_V2_PROCESS_STREAM_STDERR,
            terminal.stderr_size, terminal.stderr_sha256,
            operation->stderr_retain_limit,
            &receipt->stderr_retained, &receipt->stderr_retained_size,
            receipt->stderr_retained_sha256) != 0
        || publish_spool(custodian->state_fd, request->operation_key, "stdout", 1,
            receipt->stdout_retained, receipt->stdout_retained_size,
            receipt->stdout_retained_sha256,
            receipt->stdout_spool_checkpoint_sha256) != 0) goto ambiguous;
    if (take_fault(PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_STDOUT_DURABLE))
        goto ambiguous;
    if (publish_spool(custodian->state_fd, request->operation_key, "stderr", 2,
            receipt->stderr_retained, receipt->stderr_retained_size,
            receipt->stderr_retained_sha256,
            receipt->stderr_spool_checkpoint_sha256) != 0) goto ambiguous;
    if (take_fault(PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_STDERR_DURABLE))
        goto ambiguous;
    if (encode_terminal(receipt, terminal_bytes) != 0
        || record_name(request->operation_key, "terminal", name) != 0
        || publish_exact(custodian->state_fd, name, terminal_bytes,
            sizeof(terminal_bytes)) < 0) goto ambiguous;
    memcpy(receipt->terminal_checkpoint_sha256,
        terminal_bytes + TERMINAL_DIGEST_OFFSET, 32);
    operation->state = CUSTODY_TERMINAL_DURABLE;
    if (plamen_broker_v2_process_close(operation->process) != 0) goto ambiguous;
    operation->process = NULL;
    if (publish_closed(custodian->state_fd, operation, receipt) != 0)
        goto ambiguous;
    if (operation->claim_fd >= 0) {
        (void)flock(operation->claim_fd, LOCK_UN);
        (void)close(operation->claim_fd); operation->claim_fd = -1;
    }
    if (take_fault(PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_TERMINAL_DURABLE)) {
        plamen_broker_v2_process_custodian_terminal_dispose(receipt);
        pthread_mutex_unlock(&operation->lock);
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
    }
    pthread_mutex_unlock(&operation->lock);
    return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK;
ambiguous:
    plamen_broker_v2_process_custodian_terminal_dispose(receipt);
    pthread_mutex_unlock(&operation->lock);
    return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
}

int
plamen_broker_v2_process_custodian_wait(
    struct plamen_broker_v2_process_custodian *custodian,
    const struct plamen_broker_v2_process_custodian_terminal_request *request,
    struct plamen_broker_v2_process_custodian_terminal_receipt *receipt)
{
    return terminal_effect(custodian, request, receipt, 1);
}

int
plamen_broker_v2_process_custodian_revoke(
    struct plamen_broker_v2_process_custodian *custodian,
    const struct plamen_broker_v2_process_custodian_terminal_request *request,
    struct plamen_broker_v2_process_custodian_terminal_receipt *receipt)
{
    return terminal_effect(custodian, request, receipt, 2);
}

int
plamen_broker_v2_process_custodian_recover_terminal(
    struct plamen_broker_v2_process_custodian *custodian,
    const struct plamen_broker_v2_process_custodian_terminal_request *request,
    struct plamen_broker_v2_process_custodian_terminal_receipt *receipt)
{
    uint8_t bytes[TERMINAL_RECORD_SIZE]; char name[96]; int loaded;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (custodian == NULL || request == NULL || receipt == NULL
        || request->version != 1 || all_zero(request->operation_key)
        || record_name(request->operation_key, "terminal", name) != 0)
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    loaded = read_exact(custodian->state_fd, name, bytes, sizeof(bytes));
    if (loaded == 0)
        return decode_terminal(custodian->state_fd, request, bytes, receipt) == 0
            ? PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED
            : PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    if (loaded < 0) return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    if (record_name(request->operation_key, "prepared", name) != 0)
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
    loaded = read_exact(custodian->state_fd, name, bytes, PREPARED_RECORD_SIZE);
    if (loaded == 0 && validate_prepared(bytes, request->operation_key,
            request->request_sha256, request->prior_checkpoint_sha256,
            request->claim_owner_sha256))
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
    return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
}

void
plamen_broker_v2_process_custodian_terminal_dispose(
    struct plamen_broker_v2_process_custodian_terminal_receipt *receipt)
{
    if (receipt == NULL) return;
    if (receipt->stdout_retained != NULL) {
        plamen_broker_v2_secure_zero(receipt->stdout_retained,
            receipt->stdout_retained_size); free(receipt->stdout_retained);
    }
    if (receipt->stderr_retained != NULL) {
        plamen_broker_v2_secure_zero(receipt->stderr_retained,
            receipt->stderr_retained_size); free(receipt->stderr_retained);
    }
    memset(receipt, 0, sizeof(*receipt));
}

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
void
plamen_broker_v2_process_custodian_TEST_ONLY_fail_once(uint32_t fault)
{
    pthread_mutex_lock(&fault_lock); injected_fault = fault;
    pthread_mutex_unlock(&fault_lock);
}

int
plamen_broker_v2_process_custodian_TEST_ONLY_forget_terminal_registry(void)
{
    size_t index; int result = 0;
    pthread_mutex_lock(&operations_lock);
    for (index = 0; index < CUSTODY_MAX_OPERATIONS; ++index) {
        if (!operations[index].occupied) continue;
        pthread_mutex_lock(&operations[index].lock);
        if (operations[index].process != NULL
            || operations[index].state != CUSTODY_TERMINAL_DURABLE) result = -1;
        pthread_mutex_unlock(&operations[index].lock);
        if (result != 0) break;
    }
    if (result == 0) {
        for (index = 0; index < CUSTODY_MAX_OPERATIONS; ++index) {
            if (!operations[index].occupied) continue;
            if (operations[index].claim_fd >= 0)
                (void)close(operations[index].claim_fd);
            pthread_mutex_destroy(&operations[index].lock);
            memset(&operations[index], 0, sizeof(operations[index]));
        }
    }
    pthread_mutex_unlock(&operations_lock); return result;
}
#endif
