#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_apple_container_lifecycle.h"
#include "plamen_broker_v2_process_custody_client.h"
#include "../include/plamen_broker_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define RECORD_SIZE 512U
#define TERMINAL_RECORD_SIZE 768U
#define TERMINAL_DIGEST_OFFSET 736U
#define RECORD_DIGEST_OFFSET 480U
#define IO_CHUNK 65536U
#define CREATE_RECORD "apple-create-v1.bin"
#define CREATE_PREPARED_RECORD "apple-create-prepared-v1.bin"
#define START_PREPARED_RECORD "apple-start-prepared-v1.bin"
#define START_INTENT_RECORD "apple-start-intent-v1.bin"
#define START_RECORD "apple-started-v1.bin"
#define WAIT_PREPARED_RECORD "apple-wait-prepared-v1.bin"
#define REVOKE_PREPARED_RECORD "apple-revoke-prepared-v1.bin"
#define TERMINAL_RECORD "apple-terminal-v1.bin"
#define STDOUT_RECORD "apple-stdout-v1.bin"
#define STDERR_RECORD "apple-stderr-v1.bin"
#define DELETE_RECORD "apple-deleted-v1.bin"
#define CREATE_RECEIPT_RECORD "apple-create-receipt-v1.bin"
#define START_RECEIPT_RECORD_V1 "apple-start-receipt-v1.bin"
#define START_RECEIPT_RECORD_V2 "apple-start-receipt-v2.bin"
#define CLI_IDENTIFIER "com.apple.container.cli"
#define APPLE_TEAM "UPBK2H6LZM"
#define INIT_REFERENCE \
    "ghcr.io/apple/containerization/vminit@sha256:" \
    "cde8a93f9861c664bf2b74b4e2893cf877680806f12e7e989eb9c51b2f2e93bf"
#define OCI_INDEX_MEDIA "application/vnd.oci.image.index.v1+json"
#define RUNTIME_HANDLER "container-runtime-linux"
#define LIFECYCLE_JSON_MAX (1024U * 1024U)
#define LIFECYCLE_TOKEN_MAX 2048U

static const char *const mount_targets[
    PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT] = {
    "/workspace/project", "/workspace/scratch", "/workspace/state",
    "/workspace/control", "/run/plamen/seccomp", "/run/plamen/credentials",
    "/run/plamen/backend", "/opt/plamen", "/workspace/docs",
    "/workspace/scope"
};
static const uint8_t mount_readonly[
    PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT] = {
    /*
     * /workspace/project is a single immutable private analysis projection:
     * source plus already-verified dependencies/materialized tools.  It is not
     * the user's tree and it is never an overlay target.  This avoids both
     * changing DODO and overlapping `/source` + `/source/node_modules` mounts.
     * Scratch and state alone are writable; all authority mounts are RO.
     */
    1, 0, 0, 1, 1, 1, 1, 1, 1, 1
};

struct finite_result {
    struct plamen_broker_v2_process_terminal terminal;
    uint8_t *stdout_bytes;
    uint8_t *stderr_bytes;
    uint32_t stdout_size;
    uint32_t stderr_size;
};

struct guest_extinction_evidence {
    uint8_t stop_argv_sha256[32];
    uint8_t stop_stdout_sha256[32];
    uint8_t stop_stderr_sha256[32];
    uint8_t stopped_observation_sha256[32];
    uint8_t guest_population_extinction_sha256[32];
    uint8_t stop_control_process_reaped;
    uint8_t stop_control_process_group_extinct;
    uint8_t guest_population_zero;
    uint8_t container_vm_stopped;
};

struct plamen_broker_v2_apple_lifecycle {
    uint32_t magic;
    int cli_fd, cwd_fd, stdin_fd, state_fd;
    char cli_path[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX];
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    char runtime_image_reference[PLAMEN_BROKER_V2_APPLE_CONTAINER_REFERENCE_MAX];
    char working_directory[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX];
    char entrypoint[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX];
    char arguments[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX]
        [PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX + 1U];
    size_t argument_count;
    uint32_t cpus, uid, gid;
    uint64_t memory_bytes;
    uint8_t rosetta_required;
    uint8_t cli_sha256[32];
    uint8_t request_fingerprint[32], provider_provenance[32], image_closure[32];
    uint8_t spec_sha256[32], launch_request_sha256[32];
    uint8_t launch_policy_sha256[32], driver_argv_sha256[32];
    uint8_t driver_environment_sha256[32], driver_cwd_sha256[32];
    uint8_t driver_stdin_sha256[32], pass_fd_roster_sha256[32];
    uint8_t start_operation_nonce[32], wait_operation_nonce[32];
    uint8_t revoke_operation_nonce[32];
    uint8_t create_receipt_sha256[32];
    uint8_t custody_claim_owner_sha256[32];
    size_t mount_count;
    uint8_t dynamic_mounts;
    int mount_fds[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX];
    char mount_source_paths[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX]
        [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX];
    char mount_target_paths[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX]
        [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX];
    uint8_t mount_readonly_flags[
        PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX];
    uint8_t mount_identities[
        PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX][32];
    uint8_t mount_roster_sha256[32];
    uint32_t driver_timeout_seconds, stop_grace_seconds;
    uint64_t start_monotonic_ms;
    struct plamen_broker_v2_process *driver;
    struct plamen_broker_v2_process_start_identity driver_identity;
    struct plamen_broker_v2_process_custody_client *custody_client;
    struct plamen_broker_v2_process_custodian_start_receipt custody_started;
    uint8_t terminal_receipt_sha256[32], terminal_cleanup_sha256[32];
    uint8_t created, started, terminal, deleted, known_absent;
};

static int container_absent(
    struct plamen_broker_v2_apple_lifecycle *context);

static int all_zero(const uint8_t value[32])
{
    uint8_t aggregate = 0; size_t index;
    for (index = 0; index < 32; ++index) aggregate |= value[index];
    return aggregate == 0;
}

static int bytes_all_zero(const uint8_t *value, size_t size)
{
    uint8_t aggregate = 0; size_t index;
    if (value == NULL) return 1;
    for (index = 0; index < size; ++index) aggregate |= value[index];
    return aggregate == 0;
}

static int constant_equal(const void *a_value, const void *b_value, size_t size)
{
    const uint8_t *a = a_value, *b = b_value; uint8_t difference = 0;
    size_t index;
    for (index = 0; index < size; ++index) difference |= a[index] ^ b[index];
    return difference == 0;
}

static uint32_t start_receipt_version(
    const struct plamen_broker_v2_apple_lifecycle *context)
{
    return context != NULL && context->dynamic_mounts
        ? PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
        : PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_VERSION;
}

static const char *start_receipt_record(
    const struct plamen_broker_v2_apple_lifecycle *context)
{
    return start_receipt_version(context)
            == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
        ? START_RECEIPT_RECORD_V2 : START_RECEIPT_RECORD_V1;
}

static const char *other_start_receipt_record(
    const struct plamen_broker_v2_apple_lifecycle *context)
{
    return start_receipt_version(context)
            == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
        ? START_RECEIPT_RECORD_V1 : START_RECEIPT_RECORD_V2;
}

static size_t
effective_mount_count(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec)
{
    if (spec == NULL) return 0;
    if (spec->version == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT;
    if (spec->version != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_DYNAMIC_VERSION
        || spec->dynamic_mounts != 1 || spec->mount_count == 0
        || spec->mount_count >
            PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX)
        return 0;
    return spec->mount_count;
}

static int
mount_targets_overlap(const char *left, const char *right)
{
    size_t left_size, right_size, smaller;
    if (left == NULL || right == NULL) return 1;
    left_size = strlen(left); right_size = strlen(right);
    smaller = left_size < right_size ? left_size : right_size;
    if (memcmp(left, right, smaller) != 0) return 0;
    if (left_size == right_size) return 1;
    return (left_size == smaller ? right[smaller] : left[smaller]) == '/';
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
        | ((uint32_t)input[2] << 8) | (uint32_t)input[3];
}

static uint64_t load_u64(const uint8_t *input)
{
    return ((uint64_t)load_u32(input) << 32) | load_u32(input + 4);
}

static int duplicate_fd(int source)
{
    return source >= 0 ? fcntl(source, F_DUPFD_CLOEXEC, 3) : -1;
}

static int safe_text(const char *value, size_t maximum, int absolute)
{
    size_t size, index, component = 0;
    if (value == NULL || (size = strlen(value)) == 0 || size >= maximum
        || (absolute && value[0] != '/')) return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < 0x20 || byte > 0x7e || byte == ',' || byte == '\n'
            || byte == '\r' || byte == '"' || byte == '\\') return 0;
        if (byte == '/') {
            if (index > component && (index - component == 1
                    && value[component] == '.')) return 0;
            if (index > component && (index - component == 2
                    && value[component] == '.' && value[component + 1] == '.'))
                return 0;
            component = index + 1U;
        }
    }
    if (size - component == 1 && value[component] == '.') return 0;
    if (size - component == 2 && value[component] == '.'
        && value[component + 1] == '.') return 0;
    return 1;
}

static uint64_t monotonic_ms(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0)
        return 0;
    return (uint64_t)value.tv_sec * UINT64_C(1000)
        + (uint64_t)value.tv_nsec / UINT64_C(1000000);
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

static int persist_fixed(int directory, const char *name,
    const uint8_t *bytes, size_t size)
{
    struct stat information;
    uint8_t *existing = NULL;
    int descriptor = -1, created = 0, result = -1;
    if (directory < 0 || name == NULL || bytes == NULL || size == 0
        || (existing = malloc(size)) == NULL)
        return -1;
    descriptor = openat(directory, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor >= 0) {
        created = 1;
        if (write_all(descriptor, bytes, size) != 0
            || sync_fd(descriptor) != 0)
            goto done;
        if (close(descriptor) != 0) {
            descriptor = -1;
            goto done;
        }
        descriptor = -1;
        if (sync_fd(directory) != 0)
            goto done;
    } else {
        if (errno != EEXIST)
            goto done;
        descriptor = openat(directory, name,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0 || fstat(descriptor, &information) != 0
            || !S_ISREG(information.st_mode) || information.st_nlink != 1
            || information.st_uid != geteuid()
            || (information.st_mode & 0077) != 0
            || information.st_size != (off_t)size
            || pread_all(descriptor, existing, size) != 0
            || !constant_equal(existing, bytes, size))
            goto done;
    }
    result = 0;
done:
    if (descriptor >= 0)
        (void)close(descriptor);
    if (created && result != 0)
        (void)unlinkat(directory, name, 0);
    plamen_broker_v2_secure_zero(existing, size);
    free(existing);
    return result;
}

static int read_fixed(int directory, const char *name, uint8_t *bytes,
    size_t size)
{
    struct stat information;
    int descriptor = -1, result = -1;
    if (directory < 0 || name == NULL || bytes == NULL || size == 0)
        return -1;
    descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_uid != geteuid() || (information.st_mode & 0077) != 0
        || information.st_size != (off_t)size
        || pread_all(descriptor, bytes, size) != 0)
        goto done;
    result = 0;
done:
    if (descriptor >= 0)
        (void)close(descriptor);
    return result;
}

static int fixed_record_present(int directory, const char *name)
{
    struct stat information;
    if (fstatat(directory, name, &information, AT_SYMLINK_NOFOLLOW) == 0)
        return S_ISREG(information.st_mode) ? 1 : -1;
    return errno == ENOENT ? 0 : -1;
}

static int persist_exact(int directory, const char *name, uint32_t kind,
    const char *container_id, const uint8_t request[32],
    const uint8_t spec[32], const uint8_t payload[32], uint8_t record_sha[32])
{
    struct stat information;
    uint8_t bytes[RECORD_SIZE], existing[RECORD_SIZE];
    size_t id_size;
    int descriptor = -1, created = 0, result = -1;
    if (directory < 0 || name == NULL || container_id == NULL
        || (id_size = strlen(container_id)) == 0
        || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE) return -1;
    memset(bytes, 0, sizeof(bytes)); memset(existing, 0, sizeof(existing));
    memcpy(bytes, "PLMACL3\0", 8); store_u32(bytes + 8, 1);
    store_u32(bytes + 12, kind); store_u32(bytes + 16, RECORD_SIZE);
    store_u32(bytes + 20, (uint32_t)id_size);
    memcpy(bytes + 24, request, 32); memcpy(bytes + 56, spec, 32);
    memcpy(bytes + 88, payload, 32); memcpy(bytes + 120, container_id, id_size);
    if (plamen_broker_v2_sha256(bytes, RECORD_DIGEST_OFFSET,
            bytes + RECORD_DIGEST_OFFSET) != 0) goto done;
    descriptor = openat(directory, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor >= 0) {
        created = 1;
        if (write_all(descriptor, bytes, sizeof(bytes)) != 0
            || sync_fd(descriptor) != 0) goto done;
        if (close(descriptor) != 0) { descriptor = -1; goto done; }
        descriptor = -1;
        if (sync_fd(directory) != 0) goto done;
    } else {
        if (errno != EEXIST) goto done;
        descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0 || fstat(descriptor, &information) != 0
            || !S_ISREG(information.st_mode) || information.st_nlink != 1
            || information.st_uid != geteuid() || (information.st_mode & 0077) != 0
            || information.st_size != RECORD_SIZE
            || pread_all(descriptor, existing, sizeof(existing)) != 0
            || !constant_equal(existing, bytes, sizeof(bytes))) goto done;
    }
    memcpy(record_sha, bytes + RECORD_DIGEST_OFFSET, 32); result = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (created && result != 0) (void)unlinkat(directory, name, 0);
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    plamen_broker_v2_secure_zero(existing, sizeof(existing));
    return result;
}

static int read_exact_record(int directory, const char *name, uint32_t kind,
    const char *container_id, const uint8_t request[32],
    const uint8_t spec[32], const uint8_t payload[32], uint8_t record_sha[32])
{
    uint8_t expected[RECORD_SIZE], observed[RECORD_SIZE];
    size_t id_size;
    int result = -1;
    if (directory < 0 || name == NULL || container_id == NULL
        || (id_size = strlen(container_id)) == 0
        || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE)
        return -1;
    memset(expected, 0, sizeof(expected));
    memset(observed, 0, sizeof(observed));
    memcpy(expected, "PLMACL3\0", 8);
    store_u32(expected + 8, 1);
    store_u32(expected + 12, kind);
    store_u32(expected + 16, RECORD_SIZE);
    store_u32(expected + 20, (uint32_t)id_size);
    memcpy(expected + 24, request, 32);
    memcpy(expected + 56, spec, 32);
    memcpy(expected + 88, payload, 32);
    memcpy(expected + 120, container_id, id_size);
    if (plamen_broker_v2_sha256(expected, RECORD_DIGEST_OFFSET,
            expected + RECORD_DIGEST_OFFSET) != 0
        || read_fixed(directory, name, observed, sizeof(observed)) != 0
        || !constant_equal(expected, observed, sizeof(expected)))
        goto done;
    memcpy(record_sha, expected + RECORD_DIGEST_OFFSET, 32);
    result = 0;
done:
    plamen_broker_v2_secure_zero(expected, sizeof(expected));
    plamen_broker_v2_secure_zero(observed, sizeof(observed));
    return result;
}

static int persist_stream(int directory, const char *name,
    const uint8_t *stream, uint32_t size, const uint8_t expected_sha[32])
{
    CC_SHA256_CTX digest;
    struct stat information;
    uint8_t header[16], observed[32], existing_header[16], existing_sha[32];
    uint8_t buffer[IO_CHUNK];
    size_t offset = 0;
    ssize_t amount;
    int descriptor = -1, created = 0, result = -1;
    memset(header, 0, sizeof(header)); memset(observed, 0, sizeof(observed));
    memcpy(header, "PLMASTR\0", 8); store_u32(header + 8, 1);
    store_u32(header + 12, size);
    if ((size != 0 && stream == NULL) || CC_SHA256_Init(&digest) != 1
        || (size != 0 && CC_SHA256_Update(&digest, stream, size) != 1)
        || CC_SHA256_Final(observed, &digest) != 1
        || !constant_equal(observed, expected_sha, 32)) return -1;
    descriptor = openat(directory, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor >= 0) {
        created = 1;
        if (write_all(descriptor, header, sizeof(header)) != 0
            || (size != 0 && write_all(descriptor, stream, size) != 0)
            || write_all(descriptor, observed, 32) != 0
            || sync_fd(descriptor) != 0) goto done;
        if (close(descriptor) != 0) { descriptor = -1; goto done; }
        descriptor = -1;
        if (sync_fd(directory) != 0) goto done;
    } else {
        if (errno != EEXIST) goto done;
        descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0 || fstat(descriptor, &information) != 0
            || !S_ISREG(information.st_mode) || information.st_nlink != 1
            || information.st_uid != geteuid() || (information.st_mode & 0077) != 0
            || information.st_size != (off_t)(sizeof(header) + size + 32U)
            || pread_all(descriptor, existing_header, sizeof(existing_header)) != 0
            || !constant_equal(header, existing_header, sizeof(header))) goto done;
        while (offset < size) {
            size_t want = size - offset > sizeof(buffer) ? sizeof(buffer)
                : size - offset;
            amount = pread(descriptor, buffer, want,
                (off_t)sizeof(header) + (off_t)offset);
            if (amount != (ssize_t)want
                || !constant_equal(buffer, stream + offset, want)) goto done;
            offset += want;
        }
        if (pread(descriptor, existing_sha, 32,
                (off_t)sizeof(header) + size) != 32
            || !constant_equal(existing_sha, observed, 32)) goto done;
    }
    result = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (created && result != 0) (void)unlinkat(directory, name, 0);
    plamen_broker_v2_secure_zero(buffer, sizeof(buffer));
    return result;
}

static int read_persisted_stream(int directory, const char *name,
    uint32_t expected_size, const uint8_t expected_sha[32], uint8_t **output)
{
    struct stat information;
    uint8_t header[16], digest[32], stored_digest[32], extra;
    uint8_t *bytes = NULL;
    int descriptor = -1, result = -1;
    if (output == NULL || expected_sha == NULL) return -1;
    *output = NULL;
    descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_uid != geteuid() || (information.st_mode & 0077) != 0
        || information.st_size != (off_t)(sizeof(header) + expected_size + 32U)
        || pread_all(descriptor, header, sizeof(header)) != 0
        || memcmp(header, "PLMASTR\0", 8) != 0 || load_u32(header + 8) != 1
        || load_u32(header + 12) != expected_size) goto done;
    if (expected_size != 0) {
        bytes = malloc(expected_size);
        if (bytes == NULL || pread(descriptor, bytes, expected_size,
                (off_t)sizeof(header)) != (ssize_t)expected_size) goto done;
    }
    if (pread(descriptor, stored_digest, 32,
            (off_t)sizeof(header) + expected_size) != 32
        || pread(descriptor, &extra, 1, information.st_size) != 0
        || plamen_broker_v2_sha256(bytes, expected_size, digest) != 0
        || !constant_equal(digest, expected_sha, 32)
        || !constant_equal(stored_digest, expected_sha, 32)) goto done;
    *output = bytes; bytes = NULL; result = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (bytes != NULL) {
        plamen_broker_v2_secure_zero(bytes, expected_size); free(bytes);
    }
    plamen_broker_v2_secure_zero(header, sizeof(header));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    plamen_broker_v2_secure_zero(stored_digest, sizeof(stored_digest));
    return result;
}

static int argv_digest(const char *const *argv, size_t argc, uint8_t output[32])
{
    CC_SHA256_CTX context; uint8_t length[4]; size_t index, size;
    static const uint8_t domain[] = "plamen.apple-container.argv.v1";
    if (argv == NULL || argc == 0 || argc > PLAMEN_BROKER_V2_PROCESS_ARGC_MAX
        || CC_SHA256_Init(&context) != 1
        || CC_SHA256_Update(&context, domain, sizeof(domain)) != 1) return -1;
    store_u32(length, (uint32_t)argc);
    if (CC_SHA256_Update(&context, length, sizeof(length)) != 1) return -1;
    for (index = 0; index < argc; ++index) {
        if (argv[index] == NULL || (size = strlen(argv[index])) == 0
            || size > PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX) return -1;
        store_u32(length, (uint32_t)size);
        if (CC_SHA256_Update(&context, length, sizeof(length)) != 1
            || CC_SHA256_Update(&context, argv[index], (CC_LONG)size) != 1)
            return -1;
    }
    return CC_SHA256_Final(output, &context) == 1 ? 0 : -1;
}

static int read_stream(struct plamen_broker_v2_process *process,
    uint32_t stream, uint64_t full_size, uint8_t **output,
    uint32_t *output_size, uint8_t retained_sha[32])
{
    CC_SHA256_CTX digest; uint64_t offset = 0, observed; uint32_t amount, want;
    uint8_t eof, chunk[32], full[32]; size_t retain;
    *output = NULL; *output_size = 0;
    retain = full_size > PLAMEN_BROKER_V2_APPLE_LIFECYCLE_RETAIN_MAX
        ? PLAMEN_BROKER_V2_APPLE_LIFECYCLE_RETAIN_MAX : (size_t)full_size;
    if (retain != 0 && (*output = malloc(retain)) == NULL) return -1;
    while (offset < retain) {
        want = (uint32_t)(retain - offset > IO_CHUNK ? IO_CHUNK : retain - offset);
        if (plamen_broker_v2_process_read_output(process, stream, offset, want,
                *output + offset, want, &amount, &eof, chunk, full, &observed) != 0
            || amount == 0 || observed != full_size) goto fail;
        offset += amount;
    }
    if (CC_SHA256_Init(&digest) != 1
        || (retain != 0 && CC_SHA256_Update(&digest, *output,
            (CC_LONG)retain) != 1)
        || CC_SHA256_Final(retained_sha, &digest) != 1) goto fail;
    *output_size = (uint32_t)retain; return 0;
fail:
    if (*output != NULL) { plamen_broker_v2_secure_zero(*output, retain); free(*output); }
    *output = NULL; return -1;
}

static void finite_dispose(struct finite_result *result)
{
    if (result == NULL) return;
    if (result->stdout_bytes != NULL) {
        plamen_broker_v2_secure_zero(result->stdout_bytes, result->stdout_size);
        free(result->stdout_bytes);
    }
    if (result->stderr_bytes != NULL) {
        plamen_broker_v2_secure_zero(result->stderr_bytes, result->stderr_size);
        free(result->stderr_bytes);
    }
    memset(result, 0, sizeof(*result));
}

static int run_finite(struct plamen_broker_v2_apple_lifecycle *context,
    const char *const *argv, size_t argc, uint32_t timeout,
    struct finite_result *result)
{
    struct plamen_broker_v2_process_spec spec;
    struct plamen_broker_v2_process_prepared_identity prepared;
    struct plamen_broker_v2_process_start_identity started;
    struct plamen_broker_v2_process *process = NULL;
    uint8_t retained[32]; int status = -1;
    memset(result, 0, sizeof(*result)); memset(&spec, 0, sizeof(spec));
    memset(&prepared, 0, sizeof(prepared)); memset(&started, 0, sizeof(started));
    spec.version = 1; spec.executable_fd = context->cli_fd;
    spec.executable_path = context->cli_path; spec.argv = argv; spec.argc = argc;
    spec.environment_policy = PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED;
    spec.cwd_fd = context->cwd_fd; spec.stdin_fd = context->stdin_fd;
    spec.timeout_seconds = timeout;
    spec.stdout_spool_limit = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_RETAIN_MAX;
    spec.stderr_spool_limit = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_RETAIN_MAX;
    spec.expected_executable_sha256 = context->cli_sha256;
    spec.expected_signing_identifier = CLI_IDENTIFIER;
    spec.expected_team_identifier = APPLE_TEAM;
    if (plamen_broker_v2_process_prepare(&spec, &prepared, &process) != 0
        || plamen_broker_v2_process_start(process, &started) != 0
        || plamen_broker_v2_process_wait(process, &result->terminal) != 0
        || result->terminal.status != PLAMEN_BROKER_V2_PROCESS_OK
        || result->terminal.exit_code != 0 || result->terminal.signal_number != 0
        || result->terminal.stdout_overflow || result->terminal.stderr_overflow
        || !result->terminal.child_reaped
        || !result->terminal.process_group_extinct
        || read_stream(process, PLAMEN_BROKER_V2_PROCESS_STREAM_STDOUT,
            result->terminal.stdout_size, &result->stdout_bytes,
            &result->stdout_size, retained) != 0
        || read_stream(process, PLAMEN_BROKER_V2_PROCESS_STREAM_STDERR,
            result->terminal.stderr_size, &result->stderr_bytes,
            &result->stderr_size, retained) != 0)
        goto done;
    status = 0;
done:
    if (process != NULL) {
        if (status != 0) (void)plamen_broker_v2_process_extinguish(process, NULL);
        if (plamen_broker_v2_process_close(process) != 0) status = -1;
    }
    if (status != 0) finite_dispose(result);
    return status;
}

static int mount_recensus(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    uint8_t roster_sha[32])
{
    CC_SHA256_CTX digest; struct stat descriptor, named; uint8_t identity[32];
    size_t index, other, count, source_size, target_size; uint8_t lengths[8];
    static const uint8_t domain[] = "plamen.apple-container.mount-roster.v1";
    count = effective_mount_count(spec);
    if (count == 0 || CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, domain, sizeof(domain)) != 1) return -1;
    for (index = 0; index < count; ++index) {
        const struct plamen_broker_v2_apple_lifecycle_mount *mount =
            &spec->mounts[index];
        if (mount->source_fd < 0
            || !safe_text(mount->source_path,
                PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX, 1)
            || !safe_text(mount->target_path,
                PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX, 1)
            || strcmp(mount->target_path, "/") == 0
            || mount->readonly > 1
            || (spec->version == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION
                && (strcmp(mount->target_path, mount_targets[index]) != 0
                    || mount->readonly != mount_readonly[index]))
            || fstat(mount->source_fd, &descriptor) != 0
            || lstat(mount->source_path, &named) != 0
            || !S_ISDIR(descriptor.st_mode)
            || S_ISLNK(named.st_mode) || descriptor.st_dev != named.st_dev
            || descriptor.st_ino != named.st_ino
            || plamen_broker_v2_fd_identity(mount->source_fd, identity) != 0
            || !constant_equal(identity, mount->expected_identity_sha256, 32))
            return -1;
        for (other = 0; other < index; ++other)
            if (mount_targets_overlap(mount->target_path,
                    spec->mounts[other].target_path))
                return -1;
        source_size = strlen(mount->source_path);
        target_size = strlen(mount->target_path);
        store_u32(lengths, (uint32_t)source_size);
        store_u32(lengths + 4, (uint32_t)target_size);
        if (CC_SHA256_Update(&digest, lengths, sizeof(lengths)) != 1
            || CC_SHA256_Update(&digest, mount->source_path,
                (CC_LONG)source_size) != 1
            || CC_SHA256_Update(&digest, mount->target_path,
                (CC_LONG)target_size) != 1
            || CC_SHA256_Update(&digest, &mount->readonly, 1) != 1
            || CC_SHA256_Update(&digest, identity, 32) != 1) return -1;
    }
    return CC_SHA256_Final(roster_sha, &digest) == 1 ? 0 : -1;
}

static int build_create_argv(
    const struct plamen_broker_v2_apple_lifecycle_spec *, const char **,
    size_t *, char [4][32],
    char [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX]
        [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX * 2U + 64U]);

static int validate_spec_shape(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    uint8_t mount_sha[32])
{
    char derived_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    size_t index, count;
    memset(derived_id, 0, sizeof(derived_id));
    count = effective_mount_count(spec);
    if (spec == NULL || count == 0
        || (spec->version != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION
            && spec->version !=
                PLAMEN_BROKER_V2_APPLE_LIFECYCLE_DYNAMIC_VERSION)
        || spec->cli_fd < 0 || spec->cwd_fd < 0 || spec->stdin_fd < 0
        || spec->state_directory_fd < 0 || spec->admission == NULL
        || plamen_broker_v2_apple_container_receipt_validate(spec->admission) != 0
        || plamen_broker_v2_apple_container_id_validate(spec->container_id) != 0
        || all_zero(spec->create_operation_key)
        || plamen_broker_v2_apple_container_derive_id(
            spec->admission->request_fingerprint_sha256,
            spec->create_operation_key, derived_id) != 0
        || strcmp(derived_id, spec->container_id) != 0
        || strcmp(spec->runtime_image_reference,
            spec->admission->runtime_image_reference) != 0
        || !safe_text(spec->cli_path, sizeof(((struct plamen_broker_v2_apple_lifecycle *)0)->cli_path), 1)
        || !safe_text(spec->working_directory,
            PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX, 1)
        || !safe_text(spec->entrypoint,
            PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX, 1)
        || spec->argument_count > PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX
        || spec->cpus == 0 || spec->cpus > 64 || spec->memory_bytes < 268435456
        || spec->uid == 0 || spec->gid == 0
        || spec->create_timeout_seconds == 0 || spec->create_timeout_seconds > 300
        || spec->driver_timeout_seconds == 0
        || spec->driver_timeout_seconds > PLAMEN_BROKER_V2_PROCESS_TIMEOUT_SECONDS_MAX
        || spec->stop_grace_seconds > 295 || spec->rosetta_required > 1
        || all_zero(spec->launch_policy_sha256)
        || all_zero(spec->start_operation_nonce) || all_zero(spec->wait_operation_nonce)
        || all_zero(spec->revoke_operation_nonce)
        || constant_equal(spec->start_operation_nonce, spec->wait_operation_nonce, 32)
        || constant_equal(spec->start_operation_nonce,
            spec->revoke_operation_nonce, 32)
        || constant_equal(spec->wait_operation_nonce,
            spec->revoke_operation_nonce, 32))
        return -1;
    for (index = 0; index < spec->argument_count; ++index)
        if (!safe_text(spec->arguments[index],
                PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX + 1U, 0)) return -1;
    return mount_recensus(spec, mount_sha);
}

static int digest_text_commitment(const uint8_t *domain, size_t domain_size,
    const char *value, uint8_t output[32])
{
    CC_SHA256_CTX digest; uint8_t length[4]; size_t size;
    if (domain == NULL || value == NULL || output == NULL
        || (size = strlen(value)) > UINT32_MAX
        || CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, domain, (CC_LONG)domain_size) != 1)
        return -1;
    store_u32(length, (uint32_t)size);
    return CC_SHA256_Update(&digest, length, sizeof(length)) == 1
        && (size == 0 || CC_SHA256_Update(&digest, value,
            (CC_LONG)size) == 1)
        && CC_SHA256_Final(output, &digest) == 1 ? 0 : -1;
}

static int digest_vector_commitment(const uint8_t *domain, size_t domain_size,
    const char *first, const char *const *remaining, size_t remaining_count,
    uint8_t output[32])
{
    CC_SHA256_CTX digest; uint8_t length[4]; size_t index, size;
    if (domain == NULL || output == NULL
        || (first == NULL && remaining_count != 0)
        || CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, domain, (CC_LONG)domain_size) != 1)
        return -1;
    store_u32(length, (uint32_t)(remaining_count + (first != NULL ? 1U : 0U)));
    if (CC_SHA256_Update(&digest, length, sizeof(length)) != 1) return -1;
    for (index = 0; index < remaining_count + (first != NULL ? 1U : 0U);
         ++index) {
        const char *value = index == 0 && first != NULL
            ? first : remaining[index - (first != NULL ? 1U : 0U)];
        if (value == NULL || (size = strlen(value)) > UINT32_MAX) return -1;
        store_u32(length, (uint32_t)size);
        if (CC_SHA256_Update(&digest, length, sizeof(length)) != 1
            || (size != 0 && CC_SHA256_Update(&digest, value,
                (CC_LONG)size) != 1)) return -1;
    }
    return CC_SHA256_Final(output, &digest) == 1 ? 0 : -1;
}

static int derive_commitments_with_mount(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    const uint8_t mount_sha[32],
    struct plamen_broker_v2_apple_lifecycle_commitments *output)
{
    static const uint8_t spec_domain[] =
        "plamen.apple-container.lifecycle-spec.v1";
    static const uint8_t launch_domain[] =
        "plamen.apple-container.driver-launch.v1";
    static const uint8_t argv_domain[] =
        "plamen.apple-container.guest-argv.v1";
    static const uint8_t environment_domain[] =
        "plamen.apple-container.closed-environment.v1";
    static const uint8_t cwd_domain[] =
        "plamen.apple-container.guest-cwd.v1";
    static const uint8_t pass_domain[] =
        "plamen.apple-container.empty-pass-fd-roster.v1";
    const char *create_argv[PLAMEN_BROKER_V2_PROCESS_ARGC_MAX];
    char numbers[4][32];
    char mounts[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX]
        [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX * 2U + 64U];
    CC_SHA256_CTX digest; uint8_t integer[8]; size_t create_argc = 0;
    memset(output, 0, sizeof(*output)); memset(create_argv, 0, sizeof(create_argv));
    memset(numbers, 0, sizeof(numbers)); memset(mounts, 0, sizeof(mounts));
    if (build_create_argv(spec, create_argv, &create_argc, numbers, mounts) != 0
        || argv_digest(create_argv, create_argc,
            output->create_argv_sha256) != 0
        || digest_vector_commitment(argv_domain, sizeof(argv_domain),
            spec->entrypoint, spec->arguments, spec->argument_count,
            output->driver_argv_sha256) != 0
        || digest_vector_commitment(environment_domain,
            sizeof(environment_domain), NULL, NULL, 0,
            output->driver_environment_sha256) != 0
        || digest_text_commitment(cwd_domain, sizeof(cwd_domain),
            spec->working_directory, output->driver_cwd_sha256) != 0
        || plamen_broker_v2_fd_identity(spec->stdin_fd,
            output->driver_stdin_sha256) != 0
        || digest_vector_commitment(pass_domain, sizeof(pass_domain),
            NULL, NULL, 0, output->pass_fd_roster_sha256) != 0)
        return -1;
    memcpy(output->mount_roster_sha256, mount_sha, 32);
    if (CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, spec_domain, sizeof(spec_domain)) != 1
        || CC_SHA256_Update(&digest, spec->admission->admission_sha256, 32) != 1
        || CC_SHA256_Update(&digest, output->create_argv_sha256, 32) != 1
        || CC_SHA256_Update(&digest, mount_sha, 32) != 1
        || CC_SHA256_Update(&digest, spec->admission->image_closure_sha256, 32) != 1
        || CC_SHA256_Final(output->spec_sha256, &digest) != 1)
        return -1;
    store_u32(integer, spec->driver_timeout_seconds);
    store_u32(integer + 4, spec->stop_grace_seconds);
    if (CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, launch_domain, sizeof(launch_domain)) != 1
        || CC_SHA256_Update(&digest, output->spec_sha256, 32) != 1
        || CC_SHA256_Update(&digest, spec->launch_policy_sha256, 32) != 1
        || CC_SHA256_Update(&digest, output->driver_argv_sha256, 32) != 1
        || CC_SHA256_Update(&digest,
            output->driver_environment_sha256, 32) != 1
        || CC_SHA256_Update(&digest, output->driver_cwd_sha256, 32) != 1
        || CC_SHA256_Update(&digest, output->driver_stdin_sha256, 32) != 1
        || CC_SHA256_Update(&digest, output->pass_fd_roster_sha256, 32) != 1
        || CC_SHA256_Update(&digest, mount_sha, 32) != 1
        || CC_SHA256_Update(&digest, spec->start_operation_nonce, 32) != 1
        || CC_SHA256_Update(&digest,
            spec->admission->request_fingerprint_sha256, 32) != 1
        || CC_SHA256_Update(&digest,
            spec->admission->provider_provenance_sha256, 32) != 1
        || CC_SHA256_Update(&digest, integer, sizeof(integer)) != 1
        || CC_SHA256_Update(&digest, &spec->rosetta_required, 1) != 1
        || CC_SHA256_Final(output->launch_request_sha256, &digest) != 1)
        return -1;
    return 0;
}

int
plamen_broker_v2_apple_lifecycle_derive_commitments(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_apple_lifecycle_commitments *output)
{
    uint8_t mount_sha[32];
    if (output == NULL || validate_spec_shape(spec, mount_sha) != 0
        || derive_commitments_with_mount(spec, mount_sha, output) != 0) {
        if (output != NULL) memset(output, 0, sizeof(*output));
        return -1;
    }
    return 0;
}

static int validate_spec(const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    uint8_t mount_sha[32])
{
    struct plamen_broker_v2_apple_lifecycle_commitments derived;
    if (validate_spec_shape(spec, mount_sha) != 0
        || derive_commitments_with_mount(spec, mount_sha, &derived) != 0
        || !constant_equal(spec->spec_sha256, derived.spec_sha256, 32)
        || !constant_equal(spec->launch_request_sha256,
            derived.launch_request_sha256, 32)
        || !constant_equal(spec->driver_argv_sha256,
            derived.driver_argv_sha256, 32)
        || !constant_equal(spec->driver_environment_sha256,
            derived.driver_environment_sha256, 32)
        || !constant_equal(spec->driver_cwd_sha256,
            derived.driver_cwd_sha256, 32)
        || !constant_equal(spec->driver_stdin_sha256,
            derived.driver_stdin_sha256, 32)
        || !constant_equal(spec->pass_fd_roster_sha256,
            derived.pass_fd_roster_sha256, 32)
        || !constant_equal(mount_sha, derived.mount_roster_sha256, 32))
        return -1;
    return 0;
}

static int copy_context(const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_apple_lifecycle *context)
{
    size_t index, count = effective_mount_count(spec);
    context->cli_fd = duplicate_fd(spec->cli_fd);
    context->cwd_fd = duplicate_fd(spec->cwd_fd);
    context->stdin_fd = duplicate_fd(spec->stdin_fd);
    context->state_fd = duplicate_fd(spec->state_directory_fd);
    if (context->cli_fd < 0 || context->cwd_fd < 0 || context->stdin_fd < 0
        || context->state_fd < 0) return -1;
    memcpy(context->cli_path, spec->cli_path, strlen(spec->cli_path) + 1U);
    memcpy(context->container_id, spec->container_id, strlen(spec->container_id) + 1U);
    memcpy(context->runtime_image_reference, spec->runtime_image_reference,
        strlen(spec->runtime_image_reference) + 1U);
    memcpy(context->working_directory, spec->working_directory,
        strlen(spec->working_directory) + 1U);
    memcpy(context->entrypoint, spec->entrypoint,
        strlen(spec->entrypoint) + 1U);
    context->argument_count = spec->argument_count;
    for (index = 0; index < spec->argument_count; ++index)
        memcpy(context->arguments[index], spec->arguments[index],
            strlen(spec->arguments[index]) + 1U);
    context->cpus = spec->cpus; context->memory_bytes = spec->memory_bytes;
    context->uid = spec->uid; context->gid = spec->gid;
    context->rosetta_required = spec->rosetta_required;
    memcpy(context->cli_sha256, spec->admission->cli_sha256, 32);
    memcpy(context->request_fingerprint,
        spec->admission->request_fingerprint_sha256, 32);
    memcpy(context->provider_provenance,
        spec->admission->provider_provenance_sha256, 32);
    memcpy(context->image_closure, spec->admission->image_closure_sha256, 32);
#define COPY32(field) memcpy(context->field, spec->field, 32)
    COPY32(spec_sha256); COPY32(launch_request_sha256);
    COPY32(launch_policy_sha256); COPY32(driver_argv_sha256);
    COPY32(driver_environment_sha256); COPY32(driver_cwd_sha256);
    COPY32(driver_stdin_sha256); COPY32(pass_fd_roster_sha256);
    COPY32(start_operation_nonce); COPY32(wait_operation_nonce);
    COPY32(revoke_operation_nonce);
#undef COPY32
    context->mount_count = count;
    context->dynamic_mounts = spec->version
        == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_DYNAMIC_VERSION;
    for (index = 0; index < count; ++index) {
        context->mount_fds[index] = duplicate_fd(spec->mounts[index].source_fd);
        if (context->mount_fds[index] < 0) return -1;
        memcpy(context->mount_source_paths[index],
            spec->mounts[index].source_path,
            strlen(spec->mounts[index].source_path) + 1U);
        memcpy(context->mount_target_paths[index],
            spec->mounts[index].target_path,
            strlen(spec->mounts[index].target_path) + 1U);
        context->mount_readonly_flags[index] = spec->mounts[index].readonly;
        memcpy(context->mount_identities[index],
            spec->mounts[index].expected_identity_sha256, 32);
    }
    context->driver_timeout_seconds = spec->driver_timeout_seconds;
    context->stop_grace_seconds = spec->stop_grace_seconds;
    return 0;
}

static void close_context(struct plamen_broker_v2_apple_lifecycle *context)
{
    size_t index;
    if (context == NULL) return;
    if (context->cli_fd >= 0) (void)close(context->cli_fd);
    if (context->cwd_fd >= 0) (void)close(context->cwd_fd);
    if (context->stdin_fd >= 0) (void)close(context->stdin_fd);
    if (context->state_fd >= 0) (void)close(context->state_fd);
    for (index = 0; index < PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX;
         ++index)
        if (context->mount_fds[index] >= 0)
            (void)close(context->mount_fds[index]);
    plamen_broker_v2_secure_zero(context, sizeof(*context)); free(context);
}

static int context_mount_recensus(
    struct plamen_broker_v2_apple_lifecycle *context, uint8_t roster_sha[32])
{
    struct plamen_broker_v2_apple_lifecycle_spec view;
    size_t index;
    memset(&view, 0, sizeof(view));
    view.version = context->dynamic_mounts
        ? PLAMEN_BROKER_V2_APPLE_LIFECYCLE_DYNAMIC_VERSION
        : PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION;
    view.mount_count = context->mount_count;
    view.dynamic_mounts = context->dynamic_mounts;
    for (index = 0; index < context->mount_count; ++index) {
        view.mounts[index].source_fd = context->mount_fds[index];
        view.mounts[index].source_path = context->mount_source_paths[index];
        view.mounts[index].target_path = context->mount_target_paths[index];
        memcpy(view.mounts[index].expected_identity_sha256,
            context->mount_identities[index], 32);
        view.mounts[index].readonly = context->mount_readonly_flags[index];
    }
    return mount_recensus(&view, roster_sha);
}

static int build_create_argv(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    const char **argv, size_t *argc, char numbers[4][32],
    char mounts[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX]
        [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX * 2U + 64U])
{
    size_t index, cursor = 0; int amount;
    amount = snprintf(numbers[0], 32, "%u", spec->cpus);
    if (amount <= 0 || amount >= 32) return -1;
    amount = snprintf(numbers[1], 32, "%llu",
        (unsigned long long)spec->memory_bytes);
    if (amount <= 0 || amount >= 32) return -1;
    amount = snprintf(numbers[2], 32, "%u", spec->uid);
    if (amount <= 0 || amount >= 32) return -1;
    amount = snprintf(numbers[3], 32, "%u", spec->gid);
    if (amount <= 0 || amount >= 32) return -1;
#define ADD(value) do { argv[cursor++] = (value); } while (0)
    ADD(spec->cli_path); ADD("create"); ADD("--name"); ADD(spec->container_id);
    /* Apple Container's Rosetta flag is the authority for an amd64 guest on
     * Apple Silicon.  Never claim arm64 while enabling translation. */
    ADD("--platform");
    ADD(spec->rosetta_required ? "linux/amd64" : "linux/arm64");
    ADD("--cpus"); ADD(numbers[0]);
    ADD("--memory"); ADD(numbers[1]); ADD("--uid"); ADD(numbers[2]);
    ADD("--gid"); ADD(numbers[3]); ADD("--workdir"); ADD(spec->working_directory);
    ADD("--entrypoint"); ADD(spec->entrypoint); ADD("--read-only"); ADD("--init");
    ADD("--cap-drop"); ADD("ALL"); ADD("--network"); ADD("none");
    ADD("--no-dns");
    ADD("--init-image"); ADD(INIT_REFERENCE);
    if (spec->rosetta_required) ADD("--rosetta");
    for (index = 0; index < effective_mount_count(spec); ++index) {
        amount = snprintf(mounts[index], sizeof(mounts[index]),
            "type=bind,source=%s,target=%s%s", spec->mounts[index].source_path,
            spec->mounts[index].target_path,
            spec->mounts[index].readonly ? ",readonly" : "");
        if (amount <= 0 || (size_t)amount >= sizeof(mounts[index])) return -1;
        ADD("--mount"); ADD(mounts[index]);
    }
    ADD(spec->runtime_image_reference);
    for (index = 0; index < spec->argument_count; ++index) ADD(spec->arguments[index]);
#undef ADD
    if (cursor > PLAMEN_BROKER_V2_PROCESS_ARGC_MAX) return -1;
    *argc = cursor; return 0;
}

enum lifecycle_token_type { LC_OBJECT = 1, LC_ARRAY = 2, LC_STRING = 3,
    LC_PRIMITIVE = 4 };
struct lifecycle_token { uint8_t type; int parent; size_t start, end; };
struct lifecycle_document {
    const uint8_t *bytes; size_t size;
    struct lifecycle_token tokens[LIFECYCLE_TOKEN_MAX]; size_t count;
};

static int lc_next(const struct lifecycle_document *, int, int);
static int lc_structure(const struct lifecycle_document *, int, unsigned int);

static int lc_add(struct lifecycle_document *document, uint8_t type,
    int parent, size_t start, size_t end, int *index)
{
    if (document->count >= LIFECYCLE_TOKEN_MAX) return -1;
    *index = (int)document->count++;
    document->tokens[*index].type = type;
    document->tokens[*index].parent = parent;
    document->tokens[*index].start = start;
    document->tokens[*index].end = end;
    return 0;
}

static size_t lc_raw_start(const struct lifecycle_token *token)
{ return token->type == LC_STRING ? token->start - 1U : token->start; }
static size_t lc_raw_end(const struct lifecycle_token *token)
{ return token->type == LC_STRING ? token->end + 1U : token->end; }

static int lc_gap(const struct lifecycle_document *document, size_t start,
    size_t end, int separator)
{
    while (start < end && isspace(document->bytes[start])) ++start;
    if (separator >= 0) {
        if (start >= end || document->bytes[start++] != (uint8_t)separator)
            return -1;
        while (start < end && isspace(document->bytes[start])) ++start;
    }
    return start == end ? 0 : -1;
}

static int lc_primitive_valid(const struct lifecycle_document *document,
    int index)
{
    const struct lifecycle_token *token = &document->tokens[index];
    size_t cursor = token->start; const uint8_t *bytes = document->bytes;
    if ((token->end - token->start == 4
            && (!memcmp(bytes + token->start, "true", 4)
                || !memcmp(bytes + token->start, "null", 4)))
        || (token->end - token->start == 5
            && !memcmp(bytes + token->start, "false", 5))) return 0;
    if (cursor < token->end && bytes[cursor] == '-') ++cursor;
    if (cursor >= token->end) return -1;
    if (bytes[cursor] == '0') ++cursor;
    else {
        if (bytes[cursor] < '1' || bytes[cursor] > '9') return -1;
        while (cursor < token->end && isdigit(bytes[cursor])) ++cursor;
    }
    if (cursor < token->end && bytes[cursor] == '.') {
        if (++cursor >= token->end || !isdigit(bytes[cursor])) return -1;
        while (cursor < token->end && isdigit(bytes[cursor])) ++cursor;
    }
    if (cursor < token->end
        && (bytes[cursor] == 'e' || bytes[cursor] == 'E')) {
        ++cursor;
        if (cursor < token->end
            && (bytes[cursor] == '+' || bytes[cursor] == '-')) ++cursor;
        if (cursor >= token->end || !isdigit(bytes[cursor])) return -1;
        while (cursor < token->end && isdigit(bytes[cursor])) ++cursor;
    }
    return cursor == token->end ? 0 : -1;
}

static int lc_structure(const struct lifecycle_document *document,
    int container, unsigned int depth)
{
    const struct lifecycle_token *parent, *item_token, *value_token;
    int item = -1, value, following; size_t previous;
    if (depth > 32 || container < 0
        || (size_t)container >= document->count) return -1;
    parent = &document->tokens[container];
    if (parent->type == LC_STRING) return 0;
    if (parent->type == LC_PRIMITIVE)
        return lc_primitive_valid(document, container);
    previous = parent->start + 1U;
    while ((item = lc_next(document, container, item)) >= 0) {
        item_token = &document->tokens[item];
        if (parent->type == LC_OBJECT) {
            if (item_token->type != LC_STRING
                || lc_gap(document, previous, lc_raw_start(item_token),
                    previous == parent->start + 1U ? -1 : ',') != 0
                || (value = lc_next(document, container, item)) < 0)
                return -1;
            value_token = &document->tokens[value];
            if (lc_gap(document, lc_raw_end(item_token),
                    lc_raw_start(value_token), ':') != 0
                || lc_structure(document, value, depth + 1U) != 0) return -1;
            previous = lc_raw_end(value_token); item = value;
        } else {
            if (lc_gap(document, previous, lc_raw_start(item_token),
                    previous == parent->start + 1U ? -1 : ',') != 0
                || lc_structure(document, item, depth + 1U) != 0) return -1;
            previous = lc_raw_end(item_token);
        }
    }
    following = parent->type == LC_OBJECT ? '}' : ']';
    return lc_gap(document, previous, parent->end - 1U, -1) == 0
        && document->bytes[parent->end - 1U] == following ? 0 : -1;
}

static int lc_parse(const uint8_t *bytes, size_t size,
    struct lifecycle_document *document)
{
    int stack[64], depth = 0, index, parent = -1; size_t cursor, start;
    uint8_t value;
    if (bytes == NULL || document == NULL || size == 0
        || size > LIFECYCLE_JSON_MAX) return -1;
    memset(document, 0, sizeof(*document));
    document->bytes = bytes; document->size = size;
    for (cursor = 0; cursor < size;) {
        value = bytes[cursor];
        if (value == ' ' || value == '\t' || value == '\r' || value == '\n')
            { ++cursor; continue; }
        if (value == '{' || value == '[') {
            if (depth >= 64 || lc_add(document,
                    value == '{' ? LC_OBJECT : LC_ARRAY, parent,
                    cursor, 0, &index) != 0) return -1;
            stack[depth++] = index; parent = index; ++cursor; continue;
        }
        if (value == '}' || value == ']') {
            if (depth <= 0 || document->tokens[stack[depth - 1]].type
                    != (value == '}' ? LC_OBJECT : LC_ARRAY)) return -1;
            document->tokens[stack[--depth]].end = cursor + 1U;
            parent = depth == 0 ? -1 : stack[depth - 1]; ++cursor; continue;
        }
        if (value == ',' || value == ':') { ++cursor; continue; }
        if (value == '"') {
            start = ++cursor;
            while (cursor < size && bytes[cursor] != '"') {
                /* Every accepted lifecycle value is constrained to printable
                 * ASCII without escapes, so alternate Unicode spellings and
                 * escaped path separators never acquire authority. */
                if (bytes[cursor] == '\\' || bytes[cursor] < 0x20
                    || bytes[cursor] > 0x7e) return -1;
                ++cursor;
            }
            if (cursor >= size || lc_add(document, LC_STRING, parent,
                    start, cursor, &index) != 0) return -1;
            ++cursor; continue;
        }
        start = cursor;
        while (cursor < size && bytes[cursor] != ',' && bytes[cursor] != ':'
            && bytes[cursor] != ']' && bytes[cursor] != '}'
            && bytes[cursor] != ' ' && bytes[cursor] != '\t'
            && bytes[cursor] != '\r' && bytes[cursor] != '\n') ++cursor;
        if (cursor == start || lc_add(document, LC_PRIMITIVE, parent,
                start, cursor, &index) != 0) return -1;
    }
    if (depth != 0 || document->count == 0
        || document->tokens[0].parent != -1) return -1;
    for (cursor = document->tokens[0].end; cursor < size; ++cursor)
        if (!isspace(bytes[cursor])) return -1;
    return document->tokens[0].end != 0
        && lc_structure(document, 0, 0) == 0 ? 0 : -1;
}

static int lc_next(const struct lifecycle_document *document, int parent,
    int after)
{
    size_t index;
    for (index = (size_t)(after + 1); index < document->count; ++index) {
        if (document->tokens[index].parent == parent) return (int)index;
        if (document->tokens[index].start >= document->tokens[parent].end) break;
    }
    return -1;
}

static int lc_text(const struct lifecycle_document *document, int index,
    const char *text)
{
    const struct lifecycle_token *token; size_t size = strlen(text);
    if (index < 0 || (size_t)index >= document->count) return 0;
    token = &document->tokens[index];
    return token->type == LC_STRING && token->end - token->start == size
        && memcmp(document->bytes + token->start, text, size) == 0;
}

static int lc_get(const struct lifecycle_document *document, int object,
    const char *key, int *value)
{
    int item = -1, following, found = -1;
    if (object < 0 || document->tokens[object].type != LC_OBJECT) return -1;
    while ((item = lc_next(document, object, item)) >= 0) {
        following = lc_next(document, object, item);
        if (following < 0 || document->tokens[item].type != LC_STRING) return -1;
        if (lc_text(document, item, key)) {
            if (found >= 0) return -1;
            found = following;
        }
        item = following;
    }
    if (found < 0) return -1;
    *value = found; return 0;
}

static int lc_keys(const struct lifecycle_document *document, int object,
    const char *const *allowed, size_t allowed_count, size_t minimum,
    size_t maximum)
{
    int item = -1, value, prior, prior_value, accepted; size_t count = 0, index;
    if (object < 0 || document->tokens[object].type != LC_OBJECT) return -1;
    while ((item = lc_next(document, object, item)) >= 0) {
        value = lc_next(document, object, item);
        if (value < 0 || document->tokens[item].type != LC_STRING) return -1;
        prior = -1;
        while ((prior = lc_next(document, object, prior)) >= 0 && prior < item) {
            prior_value = lc_next(document, object, prior);
            if (prior_value < 0) return -1;
            if (document->tokens[prior].type == LC_STRING
                && document->tokens[prior].end - document->tokens[prior].start
                    == document->tokens[item].end - document->tokens[item].start
                && memcmp(document->bytes + document->tokens[prior].start,
                    document->bytes + document->tokens[item].start,
                    document->tokens[item].end
                        - document->tokens[item].start) == 0) return -1;
            prior = prior_value;
        }
        accepted = 0;
        for (index = 0; index < allowed_count; ++index)
            if (lc_text(document, item, allowed[index])) { accepted = 1; break; }
        if (!accepted) return -1;
        ++count; item = value;
    }
    return count >= minimum && count <= maximum ? 0 : -1;
}

static int lc_empty(const struct lifecycle_document *document, int index,
    uint8_t type)
{
    return index >= 0 && document->tokens[index].type == type
        && lc_next(document, index, -1) < 0;
}

static int lc_primitive(const struct lifecycle_document *document, int index,
    const char *wanted)
{
    const struct lifecycle_token *token; size_t size = strlen(wanted);
    if (index < 0 || (size_t)index >= document->count) return 0;
    token = &document->tokens[index];
    return token->type == LC_PRIMITIVE && token->end - token->start == size
        && memcmp(document->bytes + token->start, wanted, size) == 0;
}

static int lc_u64(const struct lifecycle_document *document, int index,
    uint64_t *output)
{
    const struct lifecycle_token *token; uint64_t value = 0; size_t cursor;
    if (index < 0 || (size_t)index >= document->count
        || document->tokens[index].type != LC_PRIMITIVE) return -1;
    token = &document->tokens[index];
    if (token->start == token->end
        || (token->end - token->start > 1
            && document->bytes[token->start] == '0')) return -1;
    for (cursor = token->start; cursor < token->end; ++cursor) {
        uint8_t digit = document->bytes[cursor];
        if (digit < '0' || digit > '9'
            || value > (UINT64_MAX - (digit - '0')) / 10U) return -1;
        value = value * 10U + (digit - '0');
    }
    *output = value; return 0;
}

static int lc_string_array(const struct lifecycle_document *document,
    int array, const char *const *expected, size_t expected_count)
{
    int item = -1; size_t count = 0;
    if (array < 0 || document->tokens[array].type != LC_ARRAY) return -1;
    while ((item = lc_next(document, array, item)) >= 0) {
        if (count >= expected_count || !lc_text(document, item, expected[count]))
            return -1;
        ++count;
    }
    return count == expected_count ? 0 : -1;
}

static int lc_rfc3339(const struct lifecycle_document *document, int index)
{
    const struct lifecycle_token *token; size_t size, cursor;
    static const size_t separators[] = {4, 7, 10, 13, 16};
    static const uint8_t values[] = {'-', '-', 'T', ':', ':'};
    if (index < 0 || document->tokens[index].type != LC_STRING) return 0;
    token = &document->tokens[index]; size = token->end - token->start;
    if (size < 20 || size > 30 || document->bytes[token->end - 1U] != 'Z')
        return 0;
    for (cursor = 0; cursor < 5; ++cursor)
        if (document->bytes[token->start + separators[cursor]] != values[cursor])
            return 0;
    for (cursor = 0; cursor < 19; ++cursor) {
        if (cursor == 4 || cursor == 7 || cursor == 10 || cursor == 13
            || cursor == 16) continue;
        if (!isdigit(document->bytes[token->start + cursor])) return 0;
    }
    if (size == 20) return 1;
    if (document->bytes[token->start + 19] != '.' || size < 22) return 0;
    for (cursor = 20; cursor + 1U < size; ++cursor)
        if (!isdigit(document->bytes[token->start + cursor])) return 0;
    return 1;
}

static int lc_optional_null(const struct lifecycle_document *document,
    int object, const char *key)
{
    int value;
    return lc_get(document, object, key, &value) != 0
        || lc_primitive(document, value, "null");
}

static int lc_mounts(const struct lifecycle_document *document, int array,
    const struct plamen_broker_v2_apple_lifecycle_spec *spec)
{
    static const char *const mount_keys[] = {
        "type", "source", "destination", "options"
    };
    static const char *const type_keys[] = {"virtiofs"};
    const char *readonly_option[1] = {"ro"};
    uint8_t seen[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX] = {0};
    int mount = -1, type, source, destination, options, child;
    size_t count = 0, expected, index; int matched;
    expected = effective_mount_count(spec);
    if (expected == 0 || array < 0
        || document->tokens[array].type != LC_ARRAY) return -1;
    while ((mount = lc_next(document, array, mount)) >= 0) {
        if (count >= expected
            || lc_keys(document, mount, mount_keys, 4, 4, 4) != 0
            || lc_get(document, mount, "type", &type) != 0
            || lc_get(document, mount, "source", &source) != 0
            || lc_get(document, mount, "destination", &destination) != 0
            || lc_get(document, mount, "options", &options) != 0) return -1;
        if (!lc_text(document, type, "virtiofs")) {
            if (lc_keys(document, type, type_keys, 1, 1, 1) != 0
                || lc_get(document, type, "virtiofs", &child) != 0
                || !lc_empty(document, child, LC_OBJECT)) return -1;
        }
        matched = -1;
        for (index = 0; index < expected; ++index) {
            if (!seen[index]
                && lc_text(document, source, spec->mounts[index].source_path)
                && lc_text(document, destination,
                    spec->mounts[index].target_path)) {
                matched = (int)index; break;
            }
        }
        if (matched < 0
            || (spec->mounts[matched].readonly
                ? lc_string_array(document, options, readonly_option, 1) != 0
                : !lc_empty(document, options, LC_ARRAY))) return -1;
        seen[matched] = 1; ++count;
    }
    if (count != expected) return -1;
    for (index = 0; index < expected; ++index) if (!seen[index]) return -1;
    return 0;
}

static int validate_inspect_document(const uint8_t *bytes, size_t size,
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    const char *state, uint8_t observation[32])
{
    static const char *const root_keys[] = {"id", "configuration", "status"};
    static const char *const config_keys[] = {
        "id", "image", "mounts", "publishedPorts", "publishedSockets",
        "labels", "sysctls", "networks", "rosetta", "initProcess",
        "platform", "resources", "runtimeHandler", "virtualization", "ssh",
        "readOnly", "useInit", "capAdd", "capDrop", "creationDate", "dns",
        "shmSize", "stopSignal", "maskedPaths", "readonlyPaths"
    };
    static const char *const image_keys[] = {"reference", "descriptor"};
    static const char *const descriptor_keys[] = {"digest", "mediaType", "size"};
    static const char *const platform_keys[] = {"os", "architecture"};
    static const char *const resource_keys[] = {
        "cpus", "memoryInBytes", "cpuOverhead", "storage"
    };
    static const char *const process_keys[] = {
        "executable", "arguments", "environment", "workingDirectory",
        "terminal", "user", "supplementalGroups", "rlimits"
    };
    static const char *const user_keys[] = {"id"};
    static const char *const user_id_keys[] = {"uid", "gid"};
    static const char *const status_keys[] = {"state", "networks", "startedDate"};
    static const char *const cap_drop[] = {"ALL"};
    struct lifecycle_document document;
    int resource, config, status, image, descriptor, platform_value, resources;
    int process, user, user_id, value, array, item; uint64_t number;
    const char *digest;
    if (bytes == NULL || spec == NULL || state == NULL || observation == NULL
        || (strcmp(state, "stopped") != 0 && strcmp(state, "running") != 0)
        || (digest = strchr(spec->runtime_image_reference, '@')) == NULL
        || lc_parse(bytes, size, &document) != 0
        || document.tokens[0].type != LC_ARRAY
        || (resource = lc_next(&document, 0, -1)) < 0
        || lc_next(&document, 0, resource) >= 0
        || lc_keys(&document, resource, root_keys, 3, 3, 3) != 0
        || lc_get(&document, resource, "id", &value) != 0
        || !lc_text(&document, value, spec->container_id)
        || lc_get(&document, resource, "configuration", &config) != 0
        || lc_keys(&document, config, config_keys, 25, 20, 25) != 0
        || lc_get(&document, config, "id", &value) != 0
        || !lc_text(&document, value, spec->container_id)
        || lc_get(&document, config, "image", &image) != 0
        || lc_keys(&document, image, image_keys, 2, 2, 2) != 0
        || lc_get(&document, image, "reference", &value) != 0
        || !lc_text(&document, value, spec->runtime_image_reference)
        || lc_get(&document, image, "descriptor", &descriptor) != 0
        || lc_keys(&document, descriptor, descriptor_keys, 3, 3, 3) != 0
        || lc_get(&document, descriptor, "digest", &value) != 0
        || !lc_text(&document, value, digest + 1U)
        || lc_get(&document, descriptor, "mediaType", &value) != 0
        || !lc_text(&document, value, OCI_INDEX_MEDIA)
        || lc_get(&document, descriptor, "size", &value) != 0
        || lc_u64(&document, value, &number) != 0 || number == 0
        || lc_get(&document, config, "labels", &value) != 0
        || !lc_empty(&document, value, LC_OBJECT)
        || lc_get(&document, config, "platform", &platform_value) != 0
        || lc_keys(&document, platform_value, platform_keys, 2, 2, 2) != 0
        || lc_get(&document, platform_value, "os", &value) != 0
        || !lc_text(&document, value, "linux")
        || lc_get(&document, platform_value, "architecture", &value) != 0
        || !lc_text(&document, value,
            spec->rosetta_required ? "amd64" : "arm64")) return -1;

#define REQUIRE_EMPTY(key, type) do { \
    if (lc_get(&document, config, (key), &value) != 0 \
        || !lc_empty(&document, value, (type))) return -1; \
} while (0)
    REQUIRE_EMPTY("publishedPorts", LC_ARRAY);
    REQUIRE_EMPTY("publishedSockets", LC_ARRAY);
    REQUIRE_EMPTY("sysctls", LC_OBJECT);
    REQUIRE_EMPTY("networks", LC_ARRAY);
    REQUIRE_EMPTY("capAdd", LC_ARRAY);
#undef REQUIRE_EMPTY
    if (lc_get(&document, config, "capDrop", &array) != 0
        || lc_string_array(&document, array, cap_drop, 1) != 0
        || lc_get(&document, config, "rosetta", &value) != 0
        || !lc_primitive(&document, value,
            spec->rosetta_required ? "true" : "false")
        || lc_get(&document, config, "virtualization", &value) != 0
        || !lc_primitive(&document, value, "false")
        || lc_get(&document, config, "ssh", &value) != 0
        || !lc_primitive(&document, value, "false")
        || lc_get(&document, config, "readOnly", &value) != 0
        || !lc_primitive(&document, value, "true")
        /* Apple 1.3.1 exposes only useInit in container inspect.  The exact
         * immutable init-image reference is independently bound by the
         * admitted init-image postcondition and the recomputed create argv. */
        || lc_get(&document, config, "useInit", &value) != 0
        || !lc_primitive(&document, value, "true")
        || !lc_optional_null(&document, config, "dns")
        || !lc_optional_null(&document, config, "shmSize")
        || !lc_optional_null(&document, config, "stopSignal")
        || !lc_optional_null(&document, config, "maskedPaths")
        || !lc_optional_null(&document, config, "readonlyPaths")
        || lc_get(&document, config, "runtimeHandler", &value) != 0
        || !lc_text(&document, value, RUNTIME_HANDLER)
        || lc_get(&document, config, "creationDate", &value) != 0
        || !lc_rfc3339(&document, value)
        || lc_get(&document, config, "resources", &resources) != 0
        || lc_keys(&document, resources, resource_keys, 4, 3, 4) != 0
        || lc_get(&document, resources, "cpus", &value) != 0
        || lc_u64(&document, value, &number) != 0 || number != spec->cpus
        || lc_get(&document, resources, "memoryInBytes", &value) != 0
        || lc_u64(&document, value, &number) != 0 || number != spec->memory_bytes
        || lc_get(&document, resources, "cpuOverhead", &value) != 0
        || lc_u64(&document, value, &number) != 0 || number != 1
        || !lc_optional_null(&document, resources, "storage")
        || lc_get(&document, config, "initProcess", &process) != 0
        || lc_keys(&document, process, process_keys, 8, 8, 8) != 0
        || lc_get(&document, process, "executable", &value) != 0
        || !lc_text(&document, value, spec->entrypoint)
        || lc_get(&document, process, "arguments", &array) != 0
        || lc_string_array(&document, array, spec->arguments,
            spec->argument_count) != 0
        || lc_get(&document, process, "environment", &value) != 0
        || !lc_empty(&document, value, LC_ARRAY)
        || lc_get(&document, process, "workingDirectory", &value) != 0
        || !lc_text(&document, value, spec->working_directory)
        || lc_get(&document, process, "terminal", &value) != 0
        || !lc_primitive(&document, value, "false")
        || lc_get(&document, process, "supplementalGroups", &value) != 0
        || !lc_empty(&document, value, LC_ARRAY)
        || lc_get(&document, process, "rlimits", &value) != 0
        || !lc_empty(&document, value, LC_ARRAY)
        || lc_get(&document, process, "user", &user) != 0
        || lc_keys(&document, user, user_keys, 1, 1, 1) != 0
        || lc_get(&document, user, "id", &user_id) != 0
        || lc_keys(&document, user_id, user_id_keys, 2, 2, 2) != 0
        || lc_get(&document, user_id, "uid", &value) != 0
        || lc_u64(&document, value, &number) != 0 || number != spec->uid
        || lc_get(&document, user_id, "gid", &value) != 0
        || lc_u64(&document, value, &number) != 0 || number != spec->gid
        || lc_get(&document, config, "mounts", &array) != 0
        || lc_mounts(&document, array, spec) != 0
        || lc_get(&document, resource, "status", &status) != 0
        || lc_keys(&document, status, status_keys, 3, 2, 3) != 0
        || lc_get(&document, status, "state", &value) != 0
        || !lc_text(&document, value, state)
        || lc_get(&document, status, "networks", &value) != 0
        || !lc_empty(&document, value, LC_ARRAY)) return -1;
    if (lc_get(&document, status, "startedDate", &item) == 0
        && !lc_primitive(&document, item, "null")
        && !lc_rfc3339(&document, item)) return -1;
    return plamen_broker_v2_sha256(bytes, size, observation);
}

static int exact_stdout_id(const struct finite_result *result, const char *id)
{
    size_t size = result->stdout_size, id_size = strlen(id);
    if (result->stderr_size != 0 || size != id_size + 1U)
        return 0;
    return memcmp(result->stdout_bytes, id, id_size) == 0
        && result->stdout_bytes[id_size] == '\n';
}

static int inspect_state(struct plamen_broker_v2_apple_lifecycle *context,
    const char *state, uint8_t observation[32])
{
    const char *argv[3] = { context->cli_path, "inspect", context->container_id };
    const char *arguments[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX];
    struct plamen_broker_v2_apple_lifecycle_spec view;
    struct finite_result result; size_t index; int status = -1;
    memset(&view, 0, sizeof(view)); memset(arguments, 0, sizeof(arguments));
    view.version = context->dynamic_mounts
        ? PLAMEN_BROKER_V2_APPLE_LIFECYCLE_DYNAMIC_VERSION
        : PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION;
    view.container_id = context->container_id;
    view.runtime_image_reference = context->runtime_image_reference;
    view.working_directory = context->working_directory;
    view.entrypoint = context->entrypoint;
    view.argument_count = context->argument_count;
    view.arguments = arguments; view.cpus = context->cpus;
    view.memory_bytes = context->memory_bytes; view.uid = context->uid;
    view.gid = context->gid; view.rosetta_required = context->rosetta_required;
    view.mount_count = context->mount_count;
    view.dynamic_mounts = context->dynamic_mounts;
    for (index = 0; index < context->argument_count; ++index)
        arguments[index] = context->arguments[index];
    for (index = 0; index < context->mount_count; ++index) {
        view.mounts[index].source_path = context->mount_source_paths[index];
        view.mounts[index].target_path = context->mount_target_paths[index];
        view.mounts[index].readonly = context->mount_readonly_flags[index];
    }
    if (run_finite(context, argv, 3, 30, &result) == 0
        && result.stderr_size == 0
        && validate_inspect_document(result.stdout_bytes, result.stdout_size,
            &view, state, observation) == 0)
        status = 0;
    finite_dispose(&result); return status;
}

/*
 * Apple Container's attached start command reports the init-process exit, but
 * that host process is not the per-container VM.  The provider's documented
 * stop transaction is the native boundary which kills any remaining guest
 * processes, tears down relays/mounts, syncs the guest, and stops that VM.
 * A successful exact-ID response is therefore mandatory after wait.  The
 * subsequent exact stopped-state parse is a separate provider observation;
 * neither the CLI process group nor `inspect` can establish this proof alone.
 */
static int
stop_and_prove_guest_extinction(
    struct plamen_broker_v2_apple_lifecycle *context, int force,
    struct guest_extinction_evidence *output)
{
    struct guest_extinction_evidence evidence;
    struct finite_result control;
    CC_SHA256_CTX digest;
    char grace[16];
    const char *argv[5];
    size_t argc;
    uint32_t timeout;
    int status = -1;
    static const uint8_t domain[] =
        "plamen.apple-container.guest-population-extinction.v2";
    memset(&evidence, 0, sizeof(evidence));
    memset(&control, 0, sizeof(control));
    if (context == NULL || output == NULL || (force != 0 && force != 1))
        return -1;
    argv[0] = context->cli_path;
    argv[1] = "stop";
    if (force) {
        argv[2] = "--signal";
        argv[3] = "KILL";
        argv[4] = context->container_id;
        argc = 5U;
        timeout = 30U;
    } else {
        if (snprintf(grace, sizeof(grace), "%u", context->stop_grace_seconds)
                <= 0)
            goto done;
        argv[2] = "--time";
        argv[3] = grace;
        argv[4] = context->container_id;
        argc = 5U;
        timeout = context->stop_grace_seconds + 5U;
    }
    if (argv_digest(argv, argc, evidence.stop_argv_sha256) != 0
        || run_finite(context, argv, argc, timeout, &control) != 0
        || !exact_stdout_id(&control, context->container_id)
        || control.terminal.child_reaped != 1
        || control.terminal.process_group_extinct != 1
        || inspect_state(context, "stopped",
            evidence.stopped_observation_sha256) != 0)
        goto done;
    memcpy(evidence.stop_stdout_sha256,
        control.terminal.stdout_sha256, 32);
    memcpy(evidence.stop_stderr_sha256,
        control.terminal.stderr_sha256, 32);
    evidence.stop_control_process_reaped = 1U;
    evidence.stop_control_process_group_extinct = 1U;
    evidence.guest_population_zero = 1U;
    evidence.container_vm_stopped = 1U;
    if (CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, domain, sizeof(domain)) != 1
        || CC_SHA256_Update(&digest, context->container_id,
            (CC_LONG)strlen(context->container_id)) != 1
        || CC_SHA256_Update(&digest, evidence.stop_argv_sha256, 32) != 1
        || CC_SHA256_Update(&digest, evidence.stop_stdout_sha256, 32) != 1
        || CC_SHA256_Update(&digest, evidence.stop_stderr_sha256, 32) != 1
        || CC_SHA256_Update(&digest,
            evidence.stopped_observation_sha256, 32) != 1
        || CC_SHA256_Update(&digest,
            context->provider_provenance, 32) != 1
        || CC_SHA256_Update(&digest, context->image_closure, 32) != 1
        || CC_SHA256_Final(
            evidence.guest_population_extinction_sha256, &digest) != 1
        || all_zero(evidence.guest_population_extinction_sha256))
        goto done;
    *output = evidence;
    status = 0;
done:
    finite_dispose(&control);
    plamen_broker_v2_secure_zero(&evidence, sizeof(evidence));
    plamen_broker_v2_secure_zero(grace, sizeof(grace));
    return status;
}

static void create_receipt_digest(
    struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt)
{
    (void)plamen_broker_v2_sha256(receipt,
        offsetof(struct plamen_broker_v2_apple_lifecycle_create_receipt,
            receipt_sha256), receipt->receipt_sha256);
}

static int encode_create_receipt(
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt,
    uint8_t bytes[RECORD_SIZE])
{
    size_t id_size;
    if (receipt == NULL
        || (id_size = strlen(receipt->container_id)) == 0
        || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE)
        return -1;
    memset(bytes, 0, RECORD_SIZE);
    memcpy(bytes, "PLMACR1\0", 8);
    store_u32(bytes + 8, receipt->version);
    store_u32(bytes + 12, receipt->status);
    store_u32(bytes + 16, (uint32_t)id_size);
    memcpy(bytes + 20, receipt->container_id, id_size);
    memcpy(bytes + 64, receipt->request_fingerprint_sha256, 32);
    memcpy(bytes + 96, receipt->provider_provenance_sha256, 32);
    memcpy(bytes + 128, receipt->image_closure_sha256, 32);
    memcpy(bytes + 160, receipt->spec_sha256, 32);
    memcpy(bytes + 192, receipt->mount_roster_sha256, 32);
    memcpy(bytes + 224, receipt->create_argv_sha256, 32);
    memcpy(bytes + 256, receipt->create_stdout_sha256, 32);
    memcpy(bytes + 288, receipt->create_stderr_sha256, 32);
    memcpy(bytes + 320, receipt->stopped_observation_sha256, 32);
    bytes[352] = receipt->rootfs_readonly;
    bytes[353] = receipt->use_init;
    bytes[354] = receipt->network_attachment_count;
    bytes[355] = receipt->dns_disabled;
    bytes[356] = receipt->control_process_reaped;
    bytes[357] = receipt->control_process_group_extinct;
    memcpy(bytes + 384, receipt->receipt_sha256, 32);
    return plamen_broker_v2_sha256(bytes, RECORD_DIGEST_OFFSET,
        bytes + RECORD_DIGEST_OFFSET);
}

static int decode_create_receipt(const uint8_t bytes[RECORD_SIZE],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt)
{
    uint8_t canonical[RECORD_SIZE], digest[32];
    uint32_t id_size;
    if (bytes == NULL || receipt == NULL
        || memcmp(bytes, "PLMACR1\0", 8) != 0
        || (id_size = load_u32(bytes + 16)) == 0
        || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE
        || plamen_broker_v2_sha256(bytes, RECORD_DIGEST_OFFSET, digest) != 0
        || !constant_equal(digest, bytes + RECORD_DIGEST_OFFSET, 32))
        return -1;
    memset(receipt, 0, sizeof(*receipt));
    receipt->version = load_u32(bytes + 8);
    receipt->status = load_u32(bytes + 12);
    memcpy(receipt->container_id, bytes + 20, id_size);
    memcpy(receipt->request_fingerprint_sha256, bytes + 64, 32);
    memcpy(receipt->provider_provenance_sha256, bytes + 96, 32);
    memcpy(receipt->image_closure_sha256, bytes + 128, 32);
    memcpy(receipt->spec_sha256, bytes + 160, 32);
    memcpy(receipt->mount_roster_sha256, bytes + 192, 32);
    memcpy(receipt->create_argv_sha256, bytes + 224, 32);
    memcpy(receipt->create_stdout_sha256, bytes + 256, 32);
    memcpy(receipt->create_stderr_sha256, bytes + 288, 32);
    memcpy(receipt->stopped_observation_sha256, bytes + 320, 32);
    receipt->rootfs_readonly = bytes[352];
    receipt->use_init = bytes[353];
    receipt->network_attachment_count = bytes[354];
    receipt->dns_disabled = bytes[355];
    receipt->control_process_reaped = bytes[356];
    receipt->control_process_group_extinct = bytes[357];
    memcpy(receipt->receipt_sha256, bytes + 384, 32);
    if (plamen_broker_v2_apple_lifecycle_create_receipt_validate(receipt) != 0
        || encode_create_receipt(receipt, canonical) != 0
        || !constant_equal(canonical, bytes, RECORD_SIZE)) {
        memset(receipt, 0, sizeof(*receipt));
        return -1;
    }
    return 0;
}

int
plamen_broker_v2_apple_lifecycle_create_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt)
{
    struct plamen_broker_v2_apple_lifecycle_create_receipt copy;
    if (receipt == NULL
        || receipt->version != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION
        || receipt->status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
        || plamen_broker_v2_apple_container_id_validate(receipt->container_id)
            != 0
        || receipt->rootfs_readonly != 1 || receipt->use_init != 1
        || receipt->network_attachment_count != 0
        || receipt->dns_disabled != 1
        || receipt->control_process_reaped != 1
        || receipt->control_process_group_extinct != 1)
        return -1;
    copy = *receipt;
    memset(copy.receipt_sha256, 0, sizeof(copy.receipt_sha256));
    create_receipt_digest(&copy);
    return constant_equal(copy.receipt_sha256, receipt->receipt_sha256, 32)
        ? 0 : -1;
}

int
plamen_broker_v2_apple_lifecycle_create(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt,
    struct plamen_broker_v2_apple_lifecycle **output)
{
    const char *argv[PLAMEN_BROKER_V2_PROCESS_ARGC_MAX]; size_t argc = 0;
    char numbers[4][32];
    char mounts[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX]
        [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX * 2U + 64U];
    struct plamen_broker_v2_apple_lifecycle *context = NULL;
    struct finite_result result; uint8_t mount_before[32], mount_after[32];
    uint8_t argv_sha[32], record_sha[32], receipt_bytes[RECORD_SIZE];
    int status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (output != NULL) *output = NULL;
    memset(argv, 0, sizeof(argv)); memset(numbers, 0, sizeof(numbers));
    memset(mounts, 0, sizeof(mounts)); memset(&result, 0, sizeof(result));
    if (receipt == NULL || output == NULL || validate_spec(spec, mount_before) != 0
        || build_create_argv(spec, argv, &argc, numbers, mounts) != 0
        || argv_digest(argv, argc, argv_sha) != 0
        || (context = calloc(1, sizeof(*context))) == NULL) goto done;
    context->cli_fd = context->cwd_fd = context->stdin_fd = context->state_fd = -1;
    {
        size_t index;
        for (index = 0;
             index < PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX; ++index)
            context->mount_fds[index] = -1;
    }
    if (copy_context(spec, context) != 0) goto done;
    memcpy(context->mount_roster_sha256, mount_before, 32);
    if (persist_exact(context->state_fd, CREATE_PREPARED_RECORD, 0,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, argv_sha, record_sha) != 0)
        { status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS; goto done; }
    context->magic = UINT32_C(0x504c4333); context->created = 1;
    if (run_finite(context, argv, argc, spec->create_timeout_seconds, &result) != 0
        || !exact_stdout_id(&result, spec->container_id)
        || context_mount_recensus(context, mount_after) != 0
        || !constant_equal(mount_before, mount_after, 32)
        || inspect_state(context, "stopped", receipt->stopped_observation_sha256) != 0)
        { status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS; goto done; }
    receipt->version = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION;
    receipt->status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
    memcpy(receipt->container_id, spec->container_id, strlen(spec->container_id) + 1U);
    memcpy(receipt->request_fingerprint_sha256, context->request_fingerprint, 32);
    memcpy(receipt->provider_provenance_sha256, context->provider_provenance, 32);
    memcpy(receipt->image_closure_sha256, context->image_closure, 32);
    memcpy(receipt->spec_sha256, context->spec_sha256, 32);
    memcpy(receipt->mount_roster_sha256, mount_before, 32);
    memcpy(receipt->create_argv_sha256, argv_sha, 32);
    memcpy(receipt->create_stdout_sha256, result.terminal.stdout_sha256, 32);
    memcpy(receipt->create_stderr_sha256, result.terminal.stderr_sha256, 32);
    receipt->rootfs_readonly = 1; receipt->use_init = 1;
    receipt->network_attachment_count = 0; receipt->dns_disabled = 1;
    receipt->control_process_reaped = 1; receipt->control_process_group_extinct = 1;
    create_receipt_digest(receipt);
    if (encode_create_receipt(receipt, receipt_bytes) != 0
        || persist_fixed(context->state_fd, CREATE_RECEIPT_RECORD,
            receipt_bytes, sizeof(receipt_bytes)) != 0
        || persist_exact(context->state_fd, CREATE_RECORD, 1,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, receipt->receipt_sha256, record_sha) != 0)
        { status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS; goto done; }
    memcpy(context->create_receipt_sha256, receipt->receipt_sha256, 32);
    *output = context; context = NULL; status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
done:
    finite_dispose(&result);
    if (context != NULL && status == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS
        && context->magic == UINT32_C(0x504c4333)) {
        *output = context; context = NULL;
    }
    if (context != NULL) close_context(context);
    plamen_broker_v2_secure_zero(argv, sizeof(argv));
    plamen_broker_v2_secure_zero(numbers, sizeof(numbers));
    plamen_broker_v2_secure_zero(mounts, sizeof(mounts));
    plamen_broker_v2_secure_zero(receipt_bytes, sizeof(receipt_bytes));
    if (status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK && receipt != NULL)
        memset(receipt, 0, sizeof(*receipt));
    return status;
}

int
plamen_broker_v2_apple_lifecycle_bind_process_custody(
    struct plamen_broker_v2_apple_lifecycle *context,
    struct plamen_broker_v2_process_custody_client *client,
    const uint8_t claim_owner_sha256[32])
{
    if (context == NULL || context->magic != UINT32_C(0x504c4333)
        || client == NULL || claim_owner_sha256 == NULL
        || all_zero(claim_owner_sha256) || context->started
        || context->terminal || context->deleted)
        return -1;
    if (context->custody_client != NULL
        && (context->custody_client != client
            || !constant_equal(context->custody_claim_owner_sha256,
                claim_owner_sha256, 32)))
        return -1;
    context->custody_client = client;
    memcpy(context->custody_claim_owner_sha256, claim_owner_sha256, 32);
    return 0;
}

static int start_receipt_digest(
    struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    CC_SHA256_CTX digest;
    uint8_t encoded[8];
    size_t legacy_size = offsetof(
        struct plamen_broker_v2_apple_lifecycle_start_receipt,
        receipt_sha256);
    if (receipt == NULL) return -1;
    if (receipt->version
            == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_VERSION)
        return plamen_broker_v2_sha256(receipt, legacy_size,
            receipt->receipt_sha256);
    if (receipt->version
            != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION)
        return -1;
    store_u32(encoded, receipt->post_spawn_dynamic_identity_kind);
    store_u32(encoded + 4, receipt->post_spawn_dynamic_identity_size);
    return CC_SHA256_Init(&digest) == 1
        && CC_SHA256_Update(&digest, receipt, (CC_LONG)legacy_size) == 1
        && CC_SHA256_Update(&digest, encoded, sizeof(encoded)) == 1
        && CC_SHA256_Update(&digest,
            receipt->post_spawn_dynamic_identity_sha256, 32) == 1
        && CC_SHA256_Final(receipt->receipt_sha256, &digest) == 1 ? 0 : -1;
}

static int project_start_dynamic_identity(
    const struct plamen_broker_v2_process_start_identity *identity,
    uint32_t *kind, uint32_t *size, uint8_t sha256[32])
{
    uint32_t observed_size;
    if (identity == NULL || kind == NULL || size == NULL || sha256 == NULL
        || identity->version != 1
        || ((observed_size = identity->cdhash_size) != 20
            && observed_size != 32)
        || bytes_all_zero(identity->cdhash, observed_size)
        || (observed_size < sizeof(identity->cdhash)
            && !bytes_all_zero(identity->cdhash + observed_size,
                sizeof(identity->cdhash) - observed_size))
        || plamen_broker_v2_sha256(identity->cdhash, observed_size,
            sha256) != 0)
        return -1;
    *kind =
        PLAMEN_BROKER_V2_APPLE_DYNAMIC_IDENTITY_APPLE_CODEDIRECTORY_CDHASH;
    *size = observed_size;
    return 0;
}

static int bind_start_dynamic_identity(
    struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt,
    const struct plamen_broker_v2_process_start_identity *identity)
{
    if (receipt == NULL
        || receipt->version
            != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
        || identity == NULL
        || receipt->native_process_id != identity->child_pid
        || !constant_equal(receipt->native_process_handle_sha256,
            identity->native_process_handle_sha256, 32))
        return -1;
    return project_start_dynamic_identity(identity,
        &receipt->post_spawn_dynamic_identity_kind,
        &receipt->post_spawn_dynamic_identity_size,
        receipt->post_spawn_dynamic_identity_sha256);
}

static int start_dynamic_identity_matches(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt,
    const struct plamen_broker_v2_process_start_identity *identity)
{
    uint8_t sha256[32]; uint32_t kind = 0, size = 0;
    return receipt != NULL
        && plamen_broker_v2_apple_lifecycle_start_receipt_dynamic_identity_validate(
            receipt) == 0
        && project_start_dynamic_identity(identity, &kind, &size, sha256) == 0
        && receipt->native_process_id == identity->child_pid
        && constant_equal(receipt->native_process_handle_sha256,
            identity->native_process_handle_sha256, 32)
        && receipt->post_spawn_dynamic_identity_kind == kind
        && receipt->post_spawn_dynamic_identity_size == size
        && constant_equal(receipt->post_spawn_dynamic_identity_sha256,
            sha256, 32) ? 0 : -1;
}

static int encode_start_receipt(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt,
    uint8_t bytes[RECORD_SIZE])
{
    size_t id_size;
    if (receipt == NULL
        || (id_size = strlen(receipt->container_id)) == 0
        || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE)
        return -1;
    if (receipt->version
            != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_VERSION
        && receipt->version
            != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION)
        return -1;
    memset(bytes, 0, RECORD_SIZE);
    memcpy(bytes, receipt->version
            == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
        ? "PLMASR2\0" : "PLMASR1\0", 8);
    store_u32(bytes + 8, receipt->version);
    store_u32(bytes + 12, receipt->status);
    store_u32(bytes + 16, (uint32_t)id_size);
    memcpy(bytes + 20, receipt->container_id, id_size);
    memcpy(bytes + 64, receipt->request_fingerprint_sha256, 32);
    memcpy(bytes + 96, receipt->spec_sha256, 32);
    memcpy(bytes + 128, receipt->launch_request_sha256, 32);
    memcpy(bytes + 160, receipt->start_operation_nonce, 32);
    memcpy(bytes + 192, receipt->start_argv_sha256, 32);
    memcpy(bytes + 224, receipt->native_process_handle_sha256, 32);
    store_u32(bytes + 256, (uint32_t)receipt->native_process_id);
    store_u64(bytes + 264, receipt->start_monotonic_ms);
    memcpy(bytes + 272, receipt->prepared_record_sha256, 32);
    memcpy(bytes + 304, receipt->custody_process_spec_sha256, 32);
    memcpy(bytes + 336, receipt->custody_prepared_checkpoint_sha256, 32);
    memcpy(bytes + 368, receipt->custody_started_checkpoint_sha256, 32);
    memcpy(bytes + 400, receipt->receipt_sha256, 32);
    if (receipt->version
            == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION) {
        store_u32(bytes + 432, receipt->post_spawn_dynamic_identity_kind);
        store_u32(bytes + 436, receipt->post_spawn_dynamic_identity_size);
        memcpy(bytes + 440,
            receipt->post_spawn_dynamic_identity_sha256, 32);
    }
    return plamen_broker_v2_sha256(bytes, RECORD_DIGEST_OFFSET,
        bytes + RECORD_DIGEST_OFFSET);
}

static int decode_start_receipt(const uint8_t bytes[RECORD_SIZE],
    struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    uint8_t canonical[RECORD_SIZE], digest[32];
    uint32_t id_size;
    uint32_t version;
    if (bytes == NULL || receipt == NULL
        || ((memcmp(bytes, "PLMASR1\0", 8) != 0
                || load_u32(bytes + 8)
                    != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_VERSION)
            && (memcmp(bytes, "PLMASR2\0", 8) != 0
                || load_u32(bytes + 8)
                    != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION))
        || (id_size = load_u32(bytes + 16)) == 0
        || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE
        || plamen_broker_v2_sha256(bytes, RECORD_DIGEST_OFFSET, digest) != 0
        || !constant_equal(digest, bytes + RECORD_DIGEST_OFFSET, 32))
        return -1;
    memset(receipt, 0, sizeof(*receipt));
    version = load_u32(bytes + 8);
    receipt->version = version;
    receipt->status = load_u32(bytes + 12);
    memcpy(receipt->container_id, bytes + 20, id_size);
    memcpy(receipt->request_fingerprint_sha256, bytes + 64, 32);
    memcpy(receipt->spec_sha256, bytes + 96, 32);
    memcpy(receipt->launch_request_sha256, bytes + 128, 32);
    memcpy(receipt->start_operation_nonce, bytes + 160, 32);
    memcpy(receipt->start_argv_sha256, bytes + 192, 32);
    memcpy(receipt->native_process_handle_sha256, bytes + 224, 32);
    receipt->native_process_id = (int32_t)load_u32(bytes + 256);
    receipt->start_monotonic_ms = load_u64(bytes + 264);
    memcpy(receipt->prepared_record_sha256, bytes + 272, 32);
    memcpy(receipt->custody_process_spec_sha256, bytes + 304, 32);
    memcpy(receipt->custody_prepared_checkpoint_sha256, bytes + 336, 32);
    memcpy(receipt->custody_started_checkpoint_sha256, bytes + 368, 32);
    memcpy(receipt->receipt_sha256, bytes + 400, 32);
    if (version
            == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION) {
        receipt->post_spawn_dynamic_identity_kind = load_u32(bytes + 432);
        receipt->post_spawn_dynamic_identity_size = load_u32(bytes + 436);
        memcpy(receipt->post_spawn_dynamic_identity_sha256,
            bytes + 440, 32);
    }
    if (plamen_broker_v2_apple_lifecycle_start_receipt_validate(receipt) != 0
        || encode_start_receipt(receipt, canonical) != 0
        || !constant_equal(canonical, bytes, RECORD_SIZE)) {
        memset(receipt, 0, sizeof(*receipt));
        return -1;
    }
    return 0;
}

int
plamen_broker_v2_apple_lifecycle_start_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    struct plamen_broker_v2_apple_lifecycle_start_receipt copy;
    if (receipt == NULL
        || (receipt->version
                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_VERSION
            && receipt->version
                != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION)
        || receipt->status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
        || plamen_broker_v2_apple_container_id_validate(receipt->container_id)
            != 0
        || receipt->native_process_id <= 0
        || receipt->start_monotonic_ms == 0
        || all_zero(receipt->native_process_handle_sha256)
        || all_zero(receipt->prepared_record_sha256)
        || all_zero(receipt->custody_process_spec_sha256)
        || all_zero(receipt->custody_prepared_checkpoint_sha256)
        || all_zero(receipt->custody_started_checkpoint_sha256)
        || (receipt->version
                == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_VERSION
            && (receipt->post_spawn_dynamic_identity_kind
                    != PLAMEN_BROKER_V2_APPLE_DYNAMIC_IDENTITY_NONE
                || receipt->post_spawn_dynamic_identity_size != 0
                || !all_zero(
                    receipt->post_spawn_dynamic_identity_sha256)))
        || (receipt->version
                == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
            && (receipt->post_spawn_dynamic_identity_kind
                    != PLAMEN_BROKER_V2_APPLE_DYNAMIC_IDENTITY_APPLE_CODEDIRECTORY_CDHASH
                || (receipt->post_spawn_dynamic_identity_size != 20
                    && receipt->post_spawn_dynamic_identity_size != 32)
                || all_zero(
                    receipt->post_spawn_dynamic_identity_sha256))))
        return -1;
    copy = *receipt;
    memset(copy.receipt_sha256, 0, sizeof(copy.receipt_sha256));
    if (start_receipt_digest(&copy) != 0) return -1;
    return constant_equal(copy.receipt_sha256, receipt->receipt_sha256, 32)
        ? 0 : -1;
}

int
plamen_broker_v2_apple_lifecycle_start_receipt_dynamic_identity_validate(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    return receipt != NULL
        && receipt->version
            == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
        && plamen_broker_v2_apple_lifecycle_start_receipt_validate(receipt) == 0
        ? 0 : -1;
}

static int derive_start_prepared_payload(
    const struct plamen_broker_v2_apple_lifecycle *context,
    const uint8_t argv_sha[32], uint8_t payload[32])
{
    CC_SHA256_CTX digest;
    static const uint8_t domain[] =
        "plamen.apple-container.start-prepared.v1";
    return context != NULL && argv_sha != NULL && payload != NULL
        && CC_SHA256_Init(&digest) == 1
        && CC_SHA256_Update(&digest, domain, sizeof(domain)) == 1
        && CC_SHA256_Update(&digest,
            context->launch_request_sha256, 32) == 1
        && CC_SHA256_Update(&digest,
            context->start_operation_nonce, 32) == 1
        && CC_SHA256_Update(&digest, argv_sha, 32) == 1
        && CC_SHA256_Final(payload, &digest) == 1 ? 0 : -1;
}

static int encode_start_intent(
    const struct plamen_broker_v2_apple_lifecycle *context,
    const uint8_t argv_sha[32], uint64_t start_monotonic_ms,
    uint8_t bytes[RECORD_SIZE])
{
    size_t id_size;
    if (context == NULL || argv_sha == NULL || bytes == NULL
        || start_monotonic_ms == 0
        || (id_size = strlen(context->container_id)) == 0
        || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE)
        return -1;
    memset(bytes, 0, RECORD_SIZE);
    memcpy(bytes, "PLMASI1\0", 8);
    store_u32(bytes + 8, 1);
    store_u32(bytes + 12, (uint32_t)id_size);
    store_u64(bytes + 16, start_monotonic_ms);
    memcpy(bytes + 24, context->container_id, id_size);
    memcpy(bytes + 64, context->request_fingerprint, 32);
    memcpy(bytes + 96, context->spec_sha256, 32);
    memcpy(bytes + 128, context->launch_request_sha256, 32);
    memcpy(bytes + 160, context->start_operation_nonce, 32);
    memcpy(bytes + 192, argv_sha, 32);
    memcpy(bytes + 224, context->create_receipt_sha256, 32);
    memcpy(bytes + 256, context->custody_claim_owner_sha256, 32);
    return plamen_broker_v2_sha256(bytes, RECORD_DIGEST_OFFSET,
        bytes + RECORD_DIGEST_OFFSET);
}

static int read_start_intent(
    const struct plamen_broker_v2_apple_lifecycle *context,
    const uint8_t argv_sha[32], uint64_t *start_monotonic_ms)
{
    uint8_t bytes[RECORD_SIZE], expected[RECORD_SIZE];
    uint64_t value;
    int result = -1;
    memset(bytes, 0, sizeof(bytes));
    memset(expected, 0, sizeof(expected));
    if (start_monotonic_ms == NULL
        || read_fixed(context->state_fd, START_INTENT_RECORD,
            bytes, sizeof(bytes)) != 0
        || (value = load_u64(bytes + 16)) == 0
        || encode_start_intent(context, argv_sha, value, expected) != 0
        || !constant_equal(bytes, expected, sizeof(bytes)))
        goto done;
    *start_monotonic_ms = value;
    result = 0;
done:
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    plamen_broker_v2_secure_zero(expected, sizeof(expected));
    return result;
}

int
plamen_broker_v2_apple_lifecycle_start(
    struct plamen_broker_v2_apple_lifecycle *context,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    struct plamen_broker_v2_process_spec spec;
    struct plamen_broker_v2_process_custodian_start_request custody_request;
    struct plamen_broker_v2_process_custodian_start_receipt custody_receipt;
    const char *argv[4]; uint8_t argv_sha[32], prepared_sha[32], payload[32];
    uint8_t receipt_bytes[RECORD_SIZE], intent_bytes[RECORD_SIZE];
    uint32_t daemon_status = UINT32_MAX;
    int result = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    int receipt_present, other_receipt_present;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (context == NULL || context->magic != UINT32_C(0x504c4333)
        || receipt == NULL || !context->created || context->started
        || context->terminal || context->deleted
        || context->custody_client == NULL
        || all_zero(context->custody_claim_owner_sha256)
        || all_zero(context->create_receipt_sha256)) return result;
    receipt_present = fixed_record_present(context->state_fd,
        start_receipt_record(context));
    other_receipt_present = fixed_record_present(context->state_fd,
        other_start_receipt_record(context));
    if (receipt_present != 0 || other_receipt_present != 0)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    if (context_mount_recensus(context, prepared_sha) != 0
        || !constant_equal(prepared_sha, context->mount_roster_sha256, 32))
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    argv[0] = context->cli_path; argv[1] = "start"; argv[2] = "--attach";
    argv[3] = context->container_id;
    memset(&spec, 0, sizeof(spec));
    memset(&custody_request, 0, sizeof(custody_request));
    memset(&custody_receipt, 0, sizeof(custody_receipt));
    if (argv_digest(argv, 4, argv_sha) != 0) return result;
    if (derive_start_prepared_payload(context, argv_sha, payload) != 0
        || persist_exact(context->state_fd, START_PREPARED_RECORD, 2,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, payload, prepared_sha) != 0)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    context->start_monotonic_ms = monotonic_ms();
    if (context->start_monotonic_ms == 0
        || encode_start_intent(context, argv_sha,
            context->start_monotonic_ms, intent_bytes) != 0
        || persist_fixed(context->state_fd, START_INTENT_RECORD,
            intent_bytes, sizeof(intent_bytes)) != 0)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    spec.version = 1; spec.executable_fd = context->cli_fd;
    spec.executable_path = context->cli_path; spec.argv = argv; spec.argc = 4;
    spec.environment_policy = PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED;
    spec.cwd_fd = context->cwd_fd; spec.stdin_fd = context->stdin_fd;
    spec.timeout_seconds = context->driver_timeout_seconds;
    spec.stdout_spool_limit = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_RETAIN_MAX;
    spec.stderr_spool_limit = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_RETAIN_MAX;
    spec.expected_executable_sha256 = context->cli_sha256;
    spec.expected_signing_identifier = CLI_IDENTIFIER;
    spec.expected_team_identifier = APPLE_TEAM;
    custody_request.version = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_VERSION;
    memcpy(custody_request.operation_key, context->start_operation_nonce, 32);
    memcpy(custody_request.request_sha256,
        context->launch_request_sha256, 32);
    memcpy(custody_request.prior_checkpoint_sha256,
        context->create_receipt_sha256, 32);
    memcpy(custody_request.claim_owner_sha256,
        context->custody_claim_owner_sha256, 32);
    custody_request.process_spec = &spec;
    if (plamen_broker_v2_process_custody_client_start(context->custody_client,
            &custody_request, &custody_receipt, &daemon_status)
            != PLAMEN_BROKER_V2_CUSTODY_CLIENT_OK
        || (daemon_status != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK
            && daemon_status != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED)
        || !constant_equal(custody_receipt.operation_key,
            custody_request.operation_key, 32)
        || !constant_equal(custody_receipt.request_sha256,
            custody_request.request_sha256, 32)
        || !constant_equal(custody_receipt.prior_checkpoint_sha256,
            custody_request.prior_checkpoint_sha256, 32)
        || !constant_equal(custody_receipt.claim_owner_sha256,
            custody_request.claim_owner_sha256, 32)) {
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    }
    context->started = 1;
    receipt->version = start_receipt_version(context);
    receipt->status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
    memcpy(receipt->container_id, context->container_id,
        strlen(context->container_id) + 1U);
    memcpy(receipt->request_fingerprint_sha256, context->request_fingerprint, 32);
    memcpy(receipt->spec_sha256, context->spec_sha256, 32);
    memcpy(receipt->launch_request_sha256, context->launch_request_sha256, 32);
    memcpy(receipt->start_operation_nonce, context->start_operation_nonce, 32);
    memcpy(receipt->start_argv_sha256, argv_sha, 32);
    memcpy(receipt->native_process_handle_sha256,
        custody_receipt.identity.native_process_handle_sha256, 32);
    receipt->native_process_id = custody_receipt.identity.child_pid;
    receipt->start_monotonic_ms = context->start_monotonic_ms;
    memcpy(receipt->prepared_record_sha256, prepared_sha, 32);
    memcpy(receipt->custody_process_spec_sha256,
        custody_receipt.process_spec_sha256, 32);
    memcpy(receipt->custody_prepared_checkpoint_sha256,
        custody_receipt.prepared_checkpoint_sha256, 32);
    memcpy(receipt->custody_started_checkpoint_sha256,
        custody_receipt.started_checkpoint_sha256, 32);
    if ((receipt->version
                == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
            && bind_start_dynamic_identity(receipt,
                &custody_receipt.identity) != 0)
        || start_receipt_digest(receipt) != 0
        || encode_start_receipt(receipt, receipt_bytes) != 0
        || persist_fixed(context->state_fd, start_receipt_record(context),
            receipt_bytes, sizeof(receipt_bytes)) != 0
        || persist_exact(context->state_fd, START_RECORD, 3,
            context->container_id,
            context->request_fingerprint, context->spec_sha256,
            receipt->receipt_sha256, payload) != 0)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    context->driver_identity = custody_receipt.identity;
    context->custody_started = custody_receipt;
    plamen_broker_v2_secure_zero(receipt_bytes, sizeof(receipt_bytes));
    plamen_broker_v2_secure_zero(intent_bytes, sizeof(intent_bytes));
    return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

static int reopen_create_records(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_process_custody_client *client,
    const uint8_t claim_owner_sha256[32], int require_terminal_record,
    struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt,
    struct plamen_broker_v2_apple_lifecycle **output)
{
    const char *argv[PLAMEN_BROKER_V2_PROCESS_ARGC_MAX];
    char numbers[4][32];
    char mounts[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX]
        [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX * 2U + 64U];
    struct plamen_broker_v2_apple_lifecycle *context = NULL;
    uint8_t receipt_bytes[RECORD_SIZE], mount_sha[32], observed_mount[32];
    uint8_t argv_sha[32], record_sha[32];
    size_t argc = 0, index;
    int status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    int receipt_present;
    if (receipt != NULL)
        memset(receipt, 0, sizeof(*receipt));
    if (output != NULL)
        *output = NULL;
    memset(argv, 0, sizeof(argv));
    memset(numbers, 0, sizeof(numbers));
    memset(mounts, 0, sizeof(mounts));
    memset(receipt_bytes, 0, sizeof(receipt_bytes));
    if (spec == NULL || client == NULL || claim_owner_sha256 == NULL
        || all_zero(claim_owner_sha256) || receipt == NULL || output == NULL
        || validate_spec(spec, mount_sha) != 0
        || build_create_argv(spec, argv, &argc, numbers, mounts) != 0
        || argv_digest(argv, argc, argv_sha) != 0
        || (context = calloc(1, sizeof(*context))) == NULL)
        goto done;
    context->cli_fd = context->cwd_fd = context->stdin_fd = context->state_fd = -1;
    for (index = 0;
         index < PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX; ++index)
        context->mount_fds[index] = -1;
    if (copy_context(spec, context) != 0
        || (receipt_present = fixed_record_present(context->state_fd,
            CREATE_RECEIPT_RECORD)) < 0
        || (require_terminal_record && !receipt_present)
        || (receipt_present
            && (read_fixed(context->state_fd, CREATE_RECEIPT_RECORD,
                    receipt_bytes, sizeof(receipt_bytes)) != 0
                || decode_create_receipt(receipt_bytes, receipt) != 0
                || strcmp(receipt->container_id, context->container_id) != 0
                || !constant_equal(receipt->request_fingerprint_sha256,
                    context->request_fingerprint, 32)
                || !constant_equal(receipt->provider_provenance_sha256,
                    context->provider_provenance, 32)
                || !constant_equal(receipt->image_closure_sha256,
                    context->image_closure, 32)
                || !constant_equal(receipt->spec_sha256,
                    context->spec_sha256, 32)
                || !constant_equal(receipt->mount_roster_sha256,
                    mount_sha, 32)
                || !constant_equal(receipt->create_argv_sha256,
                    argv_sha, 32)))
        || read_exact_record(context->state_fd, CREATE_PREPARED_RECORD, 0,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, argv_sha, record_sha) != 0
        || (require_terminal_record && receipt_present
            && read_exact_record(context->state_fd, CREATE_RECORD, 1,
                context->container_id, context->request_fingerprint,
                context->spec_sha256, receipt->receipt_sha256,
                record_sha) != 0)
        || context_mount_recensus(context, observed_mount) != 0
        || !constant_equal(observed_mount, mount_sha, 32))
        goto done;
    context->magic = UINT32_C(0x504c4333);
    context->created = 1;
    memcpy(context->mount_roster_sha256, mount_sha, 32);
    if (receipt_present)
        memcpy(context->create_receipt_sha256, receipt->receipt_sha256, 32);
    context->custody_client = client;
    memcpy(context->custody_claim_owner_sha256, claim_owner_sha256, 32);
    *output = context;
    context = NULL;
    status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
done:
    if (context != NULL)
        close_context(context);
    if (status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK && receipt != NULL)
        memset(receipt, 0, sizeof(*receipt));
    plamen_broker_v2_secure_zero(receipt_bytes, sizeof(receipt_bytes));
    plamen_broker_v2_secure_zero(argv, sizeof(argv));
    plamen_broker_v2_secure_zero(numbers, sizeof(numbers));
    plamen_broker_v2_secure_zero(mounts, sizeof(mounts));
    return status;
}

int
plamen_broker_v2_apple_lifecycle_reopen_created(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_process_custody_client *client,
    const uint8_t claim_owner_sha256[32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt,
    struct plamen_broker_v2_apple_lifecycle **output)
{
    struct plamen_broker_v2_apple_lifecycle *context = NULL;
    uint8_t observation[32], record_sha[32], receipt_bytes[RECORD_SIZE];
    char stdout_bytes[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE + 1U];
    int amount;
    int status = reopen_create_records(spec, client, claim_owner_sha256, 0,
        receipt, &context);
    if (status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK)
        return status;
    if (inspect_state(context, "stopped", observation) != 0) {
        int absence = container_absent(context);
        close_context(context);
        memset(receipt, 0, sizeof(*receipt));
        /* PREPARE may be durable before the CREATE mutation.  Exact list
         * evidence that this derived ID is absent permits the caller to
         * replay CREATE; an unknown or differently configured live object
         * remains ambiguous and can never be overwritten. */
        return absence == 0
            ? PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED
            : PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    }
    if (receipt->version == 0) {
        memset(receipt, 0, sizeof(*receipt));
        receipt->version = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION;
        receipt->status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
        memcpy(receipt->container_id, context->container_id,
            strlen(context->container_id) + 1U);
        memcpy(receipt->request_fingerprint_sha256,
            context->request_fingerprint, 32);
        memcpy(receipt->provider_provenance_sha256,
            context->provider_provenance, 32);
        memcpy(receipt->image_closure_sha256, context->image_closure, 32);
        memcpy(receipt->spec_sha256, context->spec_sha256, 32);
        memcpy(receipt->mount_roster_sha256,
            context->mount_roster_sha256, 32);
        {
            const char *argv[PLAMEN_BROKER_V2_PROCESS_ARGC_MAX];
            const char *arguments[
                PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX];
            char numbers[4][32];
            char mounts[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX]
                [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX * 2U + 64U];
            struct plamen_broker_v2_apple_lifecycle_spec view;
            size_t argc = 0, index;
            memset(&view, 0, sizeof(view));
            memset(arguments, 0, sizeof(arguments));
            view.version = context->dynamic_mounts
                ? PLAMEN_BROKER_V2_APPLE_LIFECYCLE_DYNAMIC_VERSION
                : PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION;
            view.cli_path = context->cli_path;
            view.container_id = context->container_id;
            view.runtime_image_reference = context->runtime_image_reference;
            view.working_directory = context->working_directory;
            view.entrypoint = context->entrypoint;
            view.arguments = arguments;
            view.argument_count = context->argument_count;
            view.cpus = context->cpus;
            view.memory_bytes = context->memory_bytes;
            view.uid = context->uid;
            view.gid = context->gid;
            view.rosetta_required = context->rosetta_required;
            view.mount_count = context->mount_count;
            view.dynamic_mounts = context->dynamic_mounts;
            for (index = 0; index < context->argument_count; ++index)
                arguments[index] = context->arguments[index];
            for (index = 0;
                 index < context->mount_count; ++index) {
                view.mounts[index].source_path =
                    context->mount_source_paths[index];
                view.mounts[index].target_path =
                    context->mount_target_paths[index];
                view.mounts[index].readonly =
                    context->mount_readonly_flags[index];
            }
            if (build_create_argv(&view, argv, &argc, numbers, mounts) != 0
                || argv_digest(argv, argc,
                    receipt->create_argv_sha256) != 0) {
                close_context(context);
                memset(receipt, 0, sizeof(*receipt));
                return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_INTERNAL_ERROR;
            }
        }
        amount = snprintf(stdout_bytes, sizeof(stdout_bytes), "%s\n",
            context->container_id);
        if (amount <= 0 || (size_t)amount >= sizeof(stdout_bytes)
            || plamen_broker_v2_sha256(stdout_bytes, (size_t)amount,
                receipt->create_stdout_sha256) != 0
            || plamen_broker_v2_sha256(NULL, 0,
                receipt->create_stderr_sha256) != 0) {
            close_context(context);
            memset(receipt, 0, sizeof(*receipt));
            return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_INTERNAL_ERROR;
        }
        memcpy(receipt->stopped_observation_sha256, observation, 32);
        receipt->rootfs_readonly = 1;
        receipt->use_init = 1;
        receipt->dns_disabled = 1;
        receipt->control_process_reaped = 1;
        receipt->control_process_group_extinct = 1;
        create_receipt_digest(receipt);
        if (encode_create_receipt(receipt, receipt_bytes) != 0
            || persist_fixed(context->state_fd, CREATE_RECEIPT_RECORD,
                receipt_bytes, sizeof(receipt_bytes)) != 0) {
            close_context(context);
            memset(receipt, 0, sizeof(*receipt));
            return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
        }
        memcpy(context->create_receipt_sha256,
            receipt->receipt_sha256, 32);
    } else if (!constant_equal(observation,
            receipt->stopped_observation_sha256, 32)) {
        close_context(context);
        memset(receipt, 0, sizeof(*receipt));
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    }
    if (persist_exact(context->state_fd, CREATE_RECORD, 1,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, receipt->receipt_sha256, record_sha) != 0) {
        close_context(context);
        memset(receipt, 0, sizeof(*receipt));
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    }
    *output = context;
    return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

int
plamen_broker_v2_apple_lifecycle_reopen_started(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_process_custody_client *client,
    const uint8_t claim_owner_sha256[32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *started,
    struct plamen_broker_v2_apple_lifecycle **output)
{
    struct plamen_broker_v2_apple_lifecycle *context = NULL;
    struct plamen_broker_v2_process_custodian_start_recovery_request request;
    struct plamen_broker_v2_process_custodian_start_receipt adopted;
    const char *argv[4];
    uint8_t receipt_bytes[RECORD_SIZE], argv_sha[32], payload[32];
    uint8_t prepared_sha[32], record_sha[32], observation[32];
    uint64_t start_monotonic_ms = 0;
    uint32_t daemon_status = UINT32_MAX;
    int status, receipt_present, other_receipt_present;
    if (started != NULL)
        memset(started, 0, sizeof(*started));
    if (output != NULL)
        *output = NULL;
    memset(&request, 0, sizeof(request));
    memset(&adopted, 0, sizeof(adopted));
    memset(receipt_bytes, 0, sizeof(receipt_bytes));
    status = reopen_create_records(spec, client, claim_owner_sha256, 1,
        created, &context);
    if (status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK)
        return status;
    argv[0] = context->cli_path;
    argv[1] = "start";
    argv[2] = "--attach";
    argv[3] = context->container_id;
    if (started == NULL || output == NULL
        || argv_digest(argv, 4, argv_sha) != 0
        || derive_start_prepared_payload(context, argv_sha, payload) != 0
        || read_exact_record(context->state_fd, START_PREPARED_RECORD, 2,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, payload, prepared_sha) != 0
        || read_start_intent(context, argv_sha, &start_monotonic_ms) != 0
        || (receipt_present = fixed_record_present(context->state_fd,
            start_receipt_record(context))) < 0)
        goto rejected;
    other_receipt_present = fixed_record_present(context->state_fd,
        other_start_receipt_record(context));
    if (other_receipt_present != 0)
        goto ambiguous;
    if (receipt_present
        && (read_fixed(context->state_fd, start_receipt_record(context),
                receipt_bytes, sizeof(receipt_bytes)) != 0
            || decode_start_receipt(receipt_bytes, started) != 0))
        goto rejected;
    request.version = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_VERSION;
    memcpy(request.operation_key, context->start_operation_nonce, 32);
    memcpy(request.request_sha256, context->launch_request_sha256, 32);
    memcpy(request.prior_checkpoint_sha256,
        context->create_receipt_sha256, 32);
    memcpy(request.claim_owner_sha256,
        context->custody_claim_owner_sha256, 32);
    if (plamen_broker_v2_process_custody_client_adopt(client, &request,
            &adopted, &daemon_status) != PLAMEN_BROKER_V2_CUSTODY_CLIENT_OK
        || daemon_status != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED
        || !constant_equal(adopted.operation_key, request.operation_key, 32)
        || !constant_equal(adopted.request_sha256, request.request_sha256, 32)
        || !constant_equal(adopted.prior_checkpoint_sha256,
            request.prior_checkpoint_sha256, 32)
        || !constant_equal(adopted.claim_owner_sha256,
            request.claim_owner_sha256, 32))
        goto ambiguous;
    if (!receipt_present) {
        started->version = start_receipt_version(context);
        started->status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
        memcpy(started->container_id, context->container_id,
            strlen(context->container_id) + 1U);
        memcpy(started->request_fingerprint_sha256,
            context->request_fingerprint, 32);
        memcpy(started->spec_sha256, context->spec_sha256, 32);
        memcpy(started->launch_request_sha256,
            context->launch_request_sha256, 32);
        memcpy(started->start_operation_nonce,
            context->start_operation_nonce, 32);
        memcpy(started->start_argv_sha256, argv_sha, 32);
        memcpy(started->native_process_handle_sha256,
            adopted.identity.native_process_handle_sha256, 32);
        started->native_process_id = adopted.identity.child_pid;
        started->start_monotonic_ms = start_monotonic_ms;
        memcpy(started->prepared_record_sha256, prepared_sha, 32);
        memcpy(started->custody_process_spec_sha256,
            adopted.process_spec_sha256, 32);
        memcpy(started->custody_prepared_checkpoint_sha256,
            adopted.prepared_checkpoint_sha256, 32);
        memcpy(started->custody_started_checkpoint_sha256,
            adopted.started_checkpoint_sha256, 32);
        if ((started->version
                    == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
                && bind_start_dynamic_identity(started,
                    &adopted.identity) != 0)
            || start_receipt_digest(started) != 0
            || encode_start_receipt(started, receipt_bytes) != 0
            || persist_fixed(context->state_fd, start_receipt_record(context),
                receipt_bytes, sizeof(receipt_bytes)) != 0)
            goto ambiguous;
    }
    if (strcmp(started->container_id, context->container_id) != 0
        || !constant_equal(started->request_fingerprint_sha256,
            context->request_fingerprint, 32)
        || !constant_equal(started->spec_sha256, context->spec_sha256, 32)
        || !constant_equal(started->launch_request_sha256,
            context->launch_request_sha256, 32)
        || !constant_equal(started->start_operation_nonce,
            context->start_operation_nonce, 32)
        || !constant_equal(started->start_argv_sha256, argv_sha, 32)
        || !constant_equal(started->prepared_record_sha256,
            prepared_sha, 32)
        || started->start_monotonic_ms != start_monotonic_ms
        || !constant_equal(adopted.process_spec_sha256,
            started->custody_process_spec_sha256, 32)
        || !constant_equal(adopted.prepared_checkpoint_sha256,
            started->custody_prepared_checkpoint_sha256, 32)
        || !constant_equal(adopted.started_checkpoint_sha256,
            started->custody_started_checkpoint_sha256, 32)
        || !constant_equal(adopted.identity.native_process_handle_sha256,
            started->native_process_handle_sha256, 32)
        || adopted.identity.child_pid != started->native_process_id
        || (started->version
                == PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION
            && start_dynamic_identity_matches(started,
                &adopted.identity) != 0)
        || persist_exact(context->state_fd, START_RECORD, 3,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, started->receipt_sha256, record_sha) != 0)
        goto ambiguous;
    if (inspect_state(context, "running", observation) != 0
        && inspect_state(context, "stopped", observation) != 0)
        goto ambiguous;
    context->custody_started = adopted;
    context->driver_identity = adopted.identity;
    context->start_monotonic_ms = started->start_monotonic_ms;
    context->started = 1;
    *output = context;
    plamen_broker_v2_secure_zero(receipt_bytes, sizeof(receipt_bytes));
    return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
rejected:
    status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    goto fail;
ambiguous:
    status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
fail:
    close_context(context);
    if (created != NULL)
        memset(created, 0, sizeof(*created));
    if (started != NULL)
        memset(started, 0, sizeof(*started));
    plamen_broker_v2_secure_zero(receipt_bytes, sizeof(receipt_bytes));
    return status;
}

static int encode_terminal(
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt,
    uint8_t bytes[TERMINAL_RECORD_SIZE])
{
    size_t id_size = strlen(receipt->container_id);
    if (id_size == 0 || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE)
        return -1;
    memset(bytes, 0, TERMINAL_RECORD_SIZE); memcpy(bytes, "PLMATER\0", 8);
    store_u32(bytes + 8, receipt->version); store_u32(bytes + 12, receipt->status);
    store_u32(bytes + 16, (uint32_t)id_size); memcpy(bytes + 20, receipt->container_id, id_size);
    memcpy(bytes + 64, receipt->request_fingerprint_sha256, 32);
    memcpy(bytes + 96, receipt->spec_sha256, 32);
    memcpy(bytes + 128, receipt->launch_request_sha256, 32);
    memcpy(bytes + 160, receipt->start_operation_nonce, 32);
    memcpy(bytes + 192, receipt->wait_operation_nonce, 32);
    memcpy(bytes + 224, receipt->revoke_operation_nonce, 32);
    memcpy(bytes + 256, receipt->native_process_handle_sha256, 32);
    store_u32(bytes + 288, (uint32_t)receipt->native_process_id);
    store_u32(bytes + 292, (uint32_t)receipt->exit_code);
    store_u64(bytes + 296, receipt->start_monotonic_ms);
    store_u64(bytes + 304, receipt->end_monotonic_ms);
    store_u64(bytes + 312, receipt->stdout_observed_bytes);
    store_u64(bytes + 320, receipt->stderr_observed_bytes);
    store_u32(bytes + 328, receipt->stdout_retained_bytes);
    store_u32(bytes + 332, receipt->stderr_retained_bytes);
    memcpy(bytes + 336, receipt->stdout_sha256, 32);
    memcpy(bytes + 368, receipt->stderr_sha256, 32);
    memcpy(bytes + 400, receipt->stdout_retained_sha256, 32);
    memcpy(bytes + 432, receipt->stderr_retained_sha256, 32);
    memcpy(bytes + 464, receipt->native_process_extinction_sha256, 32);
    memcpy(bytes + 496, receipt->cleanup_sha256, 32);
    bytes[528] = receipt->descendants_extinct;
    bytes[529] = receipt->guest_process_extinct;
    bytes[530] = receipt->backend_egress_revoked;
    bytes[531] = receipt->stdout_truncated; bytes[532] = receipt->stderr_truncated;
    bytes[533] = receipt->terminal_durable; bytes[534] = receipt->deleted;
    memcpy(bytes + 544, receipt->stop_argv_sha256, 32);
    memcpy(bytes + 576, receipt->stop_stdout_sha256, 32);
    memcpy(bytes + 608, receipt->stop_stderr_sha256, 32);
    memcpy(bytes + 640, receipt->stopped_observation_sha256, 32);
    memcpy(bytes + 672, receipt->guest_population_extinction_sha256, 32);
    bytes[704] = receipt->stop_control_process_reaped;
    bytes[705] = receipt->stop_control_process_group_extinct;
    bytes[706] = receipt->guest_population_zero;
    bytes[707] = receipt->container_vm_stopped;
    if (plamen_broker_v2_sha256(bytes, TERMINAL_DIGEST_OFFSET,
            receipt->receipt_sha256) != 0) return -1;
    memcpy(bytes + TERMINAL_DIGEST_OFFSET, receipt->receipt_sha256, 32);
    return 0;
}

static int decode_terminal(const uint8_t bytes[TERMINAL_RECORD_SIZE],
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    uint8_t canonical[TERMINAL_RECORD_SIZE];
    uint32_t id_size;
    if (bytes == NULL || receipt == NULL
        || memcmp(bytes, "PLMATER\0", 8) != 0
        || (id_size = load_u32(bytes + 16)) == 0
        || id_size >= PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE) return -1;
    memset(receipt, 0, sizeof(*receipt));
    receipt->version = load_u32(bytes + 8);
    receipt->status = load_u32(bytes + 12);
    memcpy(receipt->container_id, bytes + 20, id_size);
    memcpy(receipt->request_fingerprint_sha256, bytes + 64, 32);
    memcpy(receipt->spec_sha256, bytes + 96, 32);
    memcpy(receipt->launch_request_sha256, bytes + 128, 32);
    memcpy(receipt->start_operation_nonce, bytes + 160, 32);
    memcpy(receipt->wait_operation_nonce, bytes + 192, 32);
    memcpy(receipt->revoke_operation_nonce, bytes + 224, 32);
    memcpy(receipt->native_process_handle_sha256, bytes + 256, 32);
    receipt->native_process_id = (int32_t)load_u32(bytes + 288);
    receipt->exit_code = (int32_t)load_u32(bytes + 292);
    receipt->start_monotonic_ms = load_u64(bytes + 296);
    receipt->end_monotonic_ms = load_u64(bytes + 304);
    receipt->stdout_observed_bytes = load_u64(bytes + 312);
    receipt->stderr_observed_bytes = load_u64(bytes + 320);
    receipt->stdout_retained_bytes = load_u32(bytes + 328);
    receipt->stderr_retained_bytes = load_u32(bytes + 332);
    memcpy(receipt->stdout_sha256, bytes + 336, 32);
    memcpy(receipt->stderr_sha256, bytes + 368, 32);
    memcpy(receipt->stdout_retained_sha256, bytes + 400, 32);
    memcpy(receipt->stderr_retained_sha256, bytes + 432, 32);
    memcpy(receipt->native_process_extinction_sha256, bytes + 464, 32);
    memcpy(receipt->cleanup_sha256, bytes + 496, 32);
    receipt->descendants_extinct = bytes[528];
    receipt->guest_process_extinct = bytes[529];
    receipt->backend_egress_revoked = bytes[530];
    receipt->stdout_truncated = bytes[531];
    receipt->stderr_truncated = bytes[532];
    receipt->terminal_durable = bytes[533];
    receipt->deleted = bytes[534];
    memcpy(receipt->stop_argv_sha256, bytes + 544, 32);
    memcpy(receipt->stop_stdout_sha256, bytes + 576, 32);
    memcpy(receipt->stop_stderr_sha256, bytes + 608, 32);
    memcpy(receipt->stopped_observation_sha256, bytes + 640, 32);
    memcpy(receipt->guest_population_extinction_sha256, bytes + 672, 32);
    receipt->stop_control_process_reaped = bytes[704];
    receipt->stop_control_process_group_extinct = bytes[705];
    receipt->guest_population_zero = bytes[706];
    receipt->container_vm_stopped = bytes[707];
    memcpy(receipt->receipt_sha256, bytes + TERMINAL_DIGEST_OFFSET, 32);
    if (plamen_broker_v2_apple_lifecycle_terminal_receipt_validate(receipt) != 0
        || encode_terminal(receipt, canonical) != 0
        || !constant_equal(canonical, bytes, sizeof(canonical))) {
        memset(receipt, 0, sizeof(*receipt));
        plamen_broker_v2_secure_zero(canonical, sizeof(canonical));
        return -1;
    }
    plamen_broker_v2_secure_zero(canonical, sizeof(canonical));
    return 0;
}

static int
reopen_terminal_state(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_process_custody_client *client,
    const uint8_t claim_owner_sha256[32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *started,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *terminal,
    struct plamen_broker_v2_apple_lifecycle **output, int allow_absent)
{
    struct plamen_broker_v2_apple_lifecycle *context = NULL;
    uint8_t bytes[TERMINAL_RECORD_SIZE], observation[32];
    int status;
    if (terminal != NULL) memset(terminal, 0, sizeof(*terminal));
    if (output != NULL) *output = NULL;
    memset(bytes, 0, sizeof(bytes));
    status = plamen_broker_v2_apple_lifecycle_reopen_started(spec, client,
        claim_owner_sha256, created, started, &context);
    if (status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) return status;
    if (terminal == NULL || output == NULL
        || read_fixed(context->state_fd, TERMINAL_RECORD, bytes,
            sizeof(bytes)) != 0
        || decode_terminal(bytes, terminal) != 0
        || strcmp(terminal->container_id, context->container_id) != 0
        || !constant_equal(terminal->request_fingerprint_sha256,
            context->request_fingerprint, 32)
        || !constant_equal(terminal->spec_sha256, context->spec_sha256, 32)
        || !constant_equal(terminal->launch_request_sha256,
            context->launch_request_sha256, 32)
        || !constant_equal(terminal->start_operation_nonce,
            context->start_operation_nonce, 32)
        || !constant_equal(terminal->wait_operation_nonce,
            context->wait_operation_nonce, 32)
        || !constant_equal(terminal->revoke_operation_nonce,
            context->revoke_operation_nonce, 32)
        || !constant_equal(terminal->native_process_handle_sha256,
            started->native_process_handle_sha256, 32)
        || terminal->native_process_id != started->native_process_id
        || terminal->start_monotonic_ms != started->start_monotonic_ms
        || read_persisted_stream(context->state_fd, STDOUT_RECORD,
            terminal->stdout_retained_bytes,
            terminal->stdout_retained_sha256,
            &terminal->stdout_retained) != 0
        || read_persisted_stream(context->state_fd, STDERR_RECORD,
            terminal->stderr_retained_bytes,
            terminal->stderr_retained_sha256,
            &terminal->stderr_retained) != 0
        || (allow_absent ? container_absent(context)
            : inspect_state(context, "stopped", observation)) != 0) {
        plamen_broker_v2_apple_lifecycle_terminal_dispose(terminal);
        close_context(context);
        if (created != NULL) memset(created, 0, sizeof(*created));
        if (started != NULL) memset(started, 0, sizeof(*started));
        plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    }
    memcpy(context->terminal_receipt_sha256, terminal->receipt_sha256, 32);
    memcpy(context->terminal_cleanup_sha256, terminal->cleanup_sha256, 32);
    context->terminal = 1;
    *output = context;
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    plamen_broker_v2_secure_zero(observation, sizeof(observation));
    return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

int
plamen_broker_v2_apple_lifecycle_reopen_terminal(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_process_custody_client *client,
    const uint8_t claim_owner_sha256[32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *started,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *terminal,
    struct plamen_broker_v2_apple_lifecycle **output)
{
    return reopen_terminal_state(spec, client, claim_owner_sha256, created,
        started, terminal, output, 0);
}

static void terminal_digest(
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    uint8_t bytes[TERMINAL_RECORD_SIZE];
    if (encode_terminal(receipt, bytes) != 0)
        memset(receipt->receipt_sha256, 0, 32);
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
}

int
plamen_broker_v2_apple_lifecycle_terminal_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt copy;
    if (receipt == NULL
        || receipt->version
            != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_TERMINAL_RECEIPT_VERSION
        || (receipt->status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
            && receipt->status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REVOKED)
        || plamen_broker_v2_apple_container_id_validate(receipt->container_id)
            != 0
        || receipt->native_process_id <= 0 || receipt->exit_code < 0
        || receipt->start_monotonic_ms == 0
        || receipt->end_monotonic_ms < receipt->start_monotonic_ms
        || receipt->stdout_retained_bytes > receipt->stdout_observed_bytes
        || receipt->stderr_retained_bytes > receipt->stderr_observed_bytes
        || receipt->terminal_durable != 1
        || receipt->descendants_extinct != 1
        || receipt->guest_process_extinct != 1
        || receipt->backend_egress_revoked != 1
        || receipt->stop_control_process_reaped != 1
        || receipt->stop_control_process_group_extinct != 1
        || receipt->guest_population_zero != 1
        || receipt->container_vm_stopped != 1
        || all_zero(receipt->native_process_handle_sha256)
        || all_zero(receipt->native_process_extinction_sha256)
        || all_zero(receipt->cleanup_sha256)
        || all_zero(receipt->stop_argv_sha256)
        || all_zero(receipt->stop_stdout_sha256)
        || all_zero(receipt->stop_stderr_sha256)
        || all_zero(receipt->stopped_observation_sha256)
        || all_zero(receipt->guest_population_extinction_sha256))
        return -1;
    copy = *receipt;
    memset(copy.receipt_sha256, 0, sizeof(copy.receipt_sha256));
    terminal_digest(&copy);
    return constant_equal(copy.receipt_sha256, receipt->receipt_sha256, 32)
        ? 0 : -1;
}

static int persist_terminal_record(int directory,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    struct stat information;
    uint8_t bytes[TERMINAL_RECORD_SIZE], existing[TERMINAL_RECORD_SIZE];
    int descriptor = -1, created = 0, result = -1;
    memset(bytes, 0, sizeof(bytes)); memset(existing, 0, sizeof(existing));
    if (directory < 0 || encode_terminal(receipt, bytes) != 0) goto done;
    descriptor = openat(directory, TERMINAL_RECORD,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor >= 0) {
        created = 1;
        if (write_all(descriptor, bytes, sizeof(bytes)) != 0
            || sync_fd(descriptor) != 0) goto done;
        if (close(descriptor) != 0) { descriptor = -1; goto done; }
        descriptor = -1;
        if (sync_fd(directory) != 0) goto done;
    } else {
        if (errno != EEXIST) goto done;
        descriptor = openat(directory, TERMINAL_RECORD,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0 || fstat(descriptor, &information) != 0
            || !S_ISREG(information.st_mode) || information.st_nlink != 1
            || information.st_uid != geteuid()
            || (information.st_mode & 0077) != 0
            || information.st_size != TERMINAL_RECORD_SIZE
            || pread_all(descriptor, existing, sizeof(existing)) != 0
            || !constant_equal(existing, bytes, sizeof(bytes))) goto done;
    }
    result = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (created && result != 0)
        (void)unlinkat(directory, TERMINAL_RECORD, 0);
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    plamen_broker_v2_secure_zero(existing, sizeof(existing));
    return result;
}

static int persist_terminal(struct plamen_broker_v2_apple_lifecycle *context,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    terminal_digest(receipt);
    if (all_zero(receipt->receipt_sha256)) return -1;
    if (persist_stream(context->state_fd, STDOUT_RECORD,
            receipt->stdout_retained, receipt->stdout_retained_bytes,
            receipt->stdout_retained_sha256) != 0
        || persist_stream(context->state_fd, STDERR_RECORD,
            receipt->stderr_retained, receipt->stderr_retained_bytes,
            receipt->stderr_retained_sha256) != 0)
        return -1;
    return persist_terminal_record(context->state_fd, receipt);
}

static int collect_terminal(struct plamen_broker_v2_apple_lifecycle *context,
    struct plamen_broker_v2_process_custodian_terminal_receipt *custody,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt,
    uint32_t lifecycle_status,
    const struct guest_extinction_evidence *guest_extinction)
{
    struct plamen_broker_v2_process_terminal *terminal = &custody->terminal;
    CC_SHA256_CTX digest;
    static const uint8_t extinction_domain[] = "plamen.apple-container.extinction.v1";
    static const uint8_t cleanup_domain[] = "plamen.apple-container.cleanup.v1";
    memset(receipt, 0, sizeof(*receipt));
    if ((lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
            && lifecycle_status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REVOKED)
        || terminal->status != PLAMEN_BROKER_V2_PROCESS_OK
        || terminal->exit_code < 0 || terminal->exit_code > 255
        || terminal->stdout_overflow || terminal->stderr_overflow
        || !terminal->child_reaped || !terminal->process_group_extinct
        || terminal->stdout_size > PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OBSERVED_MAX
        || terminal->stderr_size > PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OBSERVED_MAX
        || !constant_equal(custody->start_operation_key,
            context->start_operation_nonce, 32)
        || !constant_equal(custody->claim_owner_sha256,
            context->custody_claim_owner_sha256, 32)
        || !constant_equal(custody->native_process_handle_sha256,
            context->driver_identity.native_process_handle_sha256, 32)
        || custody->stdout_retained_size
            > PLAMEN_BROKER_V2_APPLE_LIFECYCLE_RETAIN_MAX
        || custody->stderr_retained_size
            > PLAMEN_BROKER_V2_APPLE_LIFECYCLE_RETAIN_MAX
        || guest_extinction == NULL
        || guest_extinction->stop_control_process_reaped != 1U
        || guest_extinction->stop_control_process_group_extinct != 1U
        || guest_extinction->guest_population_zero != 1U
        || guest_extinction->container_vm_stopped != 1U
        || all_zero(guest_extinction->stop_argv_sha256)
        || all_zero(guest_extinction->stop_stdout_sha256)
        || all_zero(guest_extinction->stop_stderr_sha256)
        || all_zero(guest_extinction->stopped_observation_sha256)
        || all_zero(guest_extinction->guest_population_extinction_sha256))
        return -1;
    receipt->version =
        PLAMEN_BROKER_V2_APPLE_LIFECYCLE_TERMINAL_RECEIPT_VERSION;
    receipt->status = lifecycle_status;
    memcpy(receipt->container_id, context->container_id,
        strlen(context->container_id) + 1U);
    memcpy(receipt->request_fingerprint_sha256, context->request_fingerprint, 32);
    memcpy(receipt->spec_sha256, context->spec_sha256, 32);
    memcpy(receipt->launch_request_sha256, context->launch_request_sha256, 32);
    memcpy(receipt->start_operation_nonce, context->start_operation_nonce, 32);
    memcpy(receipt->wait_operation_nonce, context->wait_operation_nonce, 32);
    memcpy(receipt->revoke_operation_nonce,
        context->revoke_operation_nonce, 32);
    memcpy(receipt->native_process_handle_sha256,
        context->driver_identity.native_process_handle_sha256, 32);
    receipt->native_process_id = terminal->child_pid;
    receipt->exit_code = terminal->exit_code;
    receipt->start_monotonic_ms = context->start_monotonic_ms;
    receipt->end_monotonic_ms = monotonic_ms();
    receipt->stdout_observed_bytes = terminal->stdout_size;
    receipt->stderr_observed_bytes = terminal->stderr_size;
    memcpy(receipt->stdout_sha256, terminal->stdout_sha256, 32);
    memcpy(receipt->stderr_sha256, terminal->stderr_sha256, 32);
    receipt->stdout_retained = custody->stdout_retained;
    receipt->stderr_retained = custody->stderr_retained;
    custody->stdout_retained = NULL;
    custody->stderr_retained = NULL;
    receipt->stdout_retained_bytes = custody->stdout_retained_size;
    receipt->stderr_retained_bytes = custody->stderr_retained_size;
    memcpy(receipt->stdout_retained_sha256,
        custody->stdout_retained_sha256, 32);
    memcpy(receipt->stderr_retained_sha256,
        custody->stderr_retained_sha256, 32);
    receipt->stdout_truncated = terminal->stdout_size != receipt->stdout_retained_bytes;
    receipt->stderr_truncated = terminal->stderr_size != receipt->stderr_retained_bytes;
    memcpy(receipt->stop_argv_sha256,
        guest_extinction->stop_argv_sha256, 32);
    memcpy(receipt->stop_stdout_sha256,
        guest_extinction->stop_stdout_sha256, 32);
    memcpy(receipt->stop_stderr_sha256,
        guest_extinction->stop_stderr_sha256, 32);
    memcpy(receipt->stopped_observation_sha256,
        guest_extinction->stopped_observation_sha256, 32);
    memcpy(receipt->guest_population_extinction_sha256,
        guest_extinction->guest_population_extinction_sha256, 32);
    receipt->stop_control_process_reaped = 1U;
    receipt->stop_control_process_group_extinct = 1U;
    receipt->guest_population_zero = 1U;
    receipt->container_vm_stopped = 1U;
    receipt->descendants_extinct = 1; receipt->guest_process_extinct = 1;
    receipt->backend_egress_revoked = 1;
    if (CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, extinction_domain,
            sizeof(extinction_domain)) != 1
        || CC_SHA256_Update(&digest, context->container_id,
            (CC_LONG)strlen(context->container_id)) != 1
        || CC_SHA256_Update(&digest, context->driver_identity.native_process_handle_sha256, 32) != 1
        || CC_SHA256_Update(&digest,
            receipt->guest_population_extinction_sha256, 32) != 1
        || CC_SHA256_Final(receipt->native_process_extinction_sha256, &digest) != 1
        || CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, cleanup_domain, sizeof(cleanup_domain)) != 1
        || CC_SHA256_Update(&digest, receipt->native_process_extinction_sha256, 32) != 1
        || CC_SHA256_Update(&digest, context->image_closure, 32) != 1
        || CC_SHA256_Final(receipt->cleanup_sha256, &digest) != 1) return -1;
    receipt->terminal_durable = 1;
    if (persist_terminal(context, receipt) != 0) {
        receipt->terminal_durable = 0; return -1;
    }
    memcpy(context->terminal_receipt_sha256, receipt->receipt_sha256, 32);
    memcpy(context->terminal_cleanup_sha256, receipt->cleanup_sha256, 32);
    context->terminal = 1;
    return 0;
}

int
plamen_broker_v2_apple_lifecycle_wait(
    struct plamen_broker_v2_apple_lifecycle *context,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    struct plamen_broker_v2_process_custodian_terminal_request request;
    struct plamen_broker_v2_process_custodian_terminal_receipt terminal;
    struct guest_extinction_evidence guest_extinction;
    uint8_t prepared[32], payload[32];
    uint32_t daemon_status = UINT32_MAX;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (context == NULL || context->magic != UINT32_C(0x504c4333)
        || receipt == NULL || !context->started || context->terminal
        || context->deleted || context->custody_client == NULL)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    if (plamen_broker_v2_sha256(context->wait_operation_nonce, 32, payload) != 0
        || persist_exact(context->state_fd, WAIT_PREPARED_RECORD, 4,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, payload, prepared) != 0)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    memset(&request, 0, sizeof(request));
    memset(&terminal, 0, sizeof(terminal));
    memset(&guest_extinction, 0, sizeof(guest_extinction));
    request.version = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_VERSION;
    memcpy(request.start_operation_key, context->start_operation_nonce, 32);
    memcpy(request.operation_key, context->wait_operation_nonce, 32);
    memcpy(request.request_sha256, payload, 32);
    memcpy(request.prior_checkpoint_sha256,
        context->custody_started.started_checkpoint_sha256, 32);
    memcpy(request.claim_owner_sha256,
        context->custody_claim_owner_sha256, 32);
    if (plamen_broker_v2_process_custody_client_wait(context->custody_client,
            &request, &terminal, &daemon_status)
            != PLAMEN_BROKER_V2_CUSTODY_CLIENT_OK
        || (daemon_status != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK
            && daemon_status != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED)
        || !constant_equal(terminal.operation_key,
            request.operation_key, 32)
        || !constant_equal(terminal.request_sha256,
            request.request_sha256, 32)
        || !constant_equal(terminal.prior_checkpoint_sha256,
            request.prior_checkpoint_sha256, 32)
        || stop_and_prove_guest_extinction(
            context, 0, &guest_extinction) != 0
        || collect_terminal(context, &terminal, receipt,
            PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK,
            &guest_extinction) != 0) {
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal);
        plamen_broker_v2_apple_lifecycle_terminal_dispose(receipt);
        plamen_broker_v2_secure_zero(
            &guest_extinction, sizeof(guest_extinction));
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    }
    plamen_broker_v2_process_custodian_terminal_dispose(&terminal);
    plamen_broker_v2_secure_zero(
        &guest_extinction, sizeof(guest_extinction));
    return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

static int list_id_valid(const uint8_t *bytes, size_t size)
{
    size_t index;
    if (bytes == NULL || size == 0 || size > 128
        || !((bytes[0] >= 'A' && bytes[0] <= 'Z')
            || (bytes[0] >= 'a' && bytes[0] <= 'z')
            || (bytes[0] >= '0' && bytes[0] <= '9'))
        || !((bytes[size - 1U] >= 'A' && bytes[size - 1U] <= 'Z')
            || (bytes[size - 1U] >= 'a' && bytes[size - 1U] <= 'z')
            || (bytes[size - 1U] >= '0' && bytes[size - 1U] <= '9')))
        return 0;
    for (index = 0; index < size; ++index) {
        uint8_t value = bytes[index];
        if (!((value >= 'A' && value <= 'Z')
                || (value >= 'a' && value <= 'z')
                || (value >= '0' && value <= '9'))
            && value != '_' && value != '.' && value != '-')
            return 0;
        if (value == '.' && index + 1U < size && bytes[index + 1U] == '.')
            return 0;
    }
    return 1;
}

static int list_proves_absent(const uint8_t *bytes, size_t size,
    const char *container_id)
{
    static const char *const root_keys[] = {
        "status", "networks", "configuration"
    };
    struct lifecycle_document document;
    int item = -1, prior = -1, configuration, id, prior_configuration;
    int prior_id, status, networks;
    size_t id_size, value_size, prior_size;
    const struct lifecycle_token *value, *prior_value;
    if (container_id == NULL || bytes == NULL || size == 0
        || size > LIFECYCLE_JSON_MAX) return -1;
    id_size = strlen(container_id);
    if (lc_parse(bytes, size, &document) != 0
        || document.tokens[0].type != LC_ARRAY) return -1;
    while ((item = lc_next(&document, 0, item)) >= 0) {
        if (document.tokens[item].type != LC_OBJECT
            || lc_keys(&document, item, root_keys, 3, 3, 3) != 0
            || lc_get(&document, item, "status", &status) != 0
            || document.tokens[status].type != LC_STRING
            || lc_get(&document, item, "networks", &networks) != 0
            || document.tokens[networks].type != LC_ARRAY
            || lc_get(&document, item, "configuration", &configuration) != 0
            || document.tokens[configuration].type != LC_OBJECT
            || lc_get(&document, configuration, "id", &id) != 0)
            return -1;
        value = &document.tokens[id];
        value_size = value->end - value->start;
        if (value->type != LC_STRING
            || !list_id_valid(document.bytes + value->start, value_size)
            || (value_size == id_size
                && memcmp(document.bytes + value->start,
                    container_id, id_size) == 0)) return -1;
        /* A duplicate identifier makes the provider census non-canonical. */
        prior = -1;
        while ((prior = lc_next(&document, 0, prior)) >= 0 && prior < item) {
            if (lc_get(&document, prior, "configuration",
                    &prior_configuration) != 0
                || lc_get(&document, prior_configuration, "id",
                    &prior_id) != 0) return -1;
            prior_value = &document.tokens[prior_id];
            prior_size = prior_value->end - prior_value->start;
            if (prior_value->type != LC_STRING) return -1;
            if (prior_size == value_size
                && memcmp(document.bytes + prior_value->start,
                    document.bytes + value->start, value_size) == 0)
                return -1;
        }
    }
    return 0;
}

static int container_absent(struct plamen_broker_v2_apple_lifecycle *context)
{
    const char *argv[5] = {
        context->cli_path, "list", "--all", "--format", "json"
    };
    struct finite_result result; int status = -1;
    if (run_finite(context, argv, 5, 30, &result) != 0 || result.stderr_size != 0)
        goto done;
    if (list_proves_absent(result.stdout_bytes, result.stdout_size,
            context->container_id) == 0) status = 0;
done:
    finite_dispose(&result); return status;
}

int
plamen_broker_v2_apple_lifecycle_revoke_delete(
    struct plamen_broker_v2_apple_lifecycle *context,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt,
    struct plamen_broker_v2_apple_lifecycle_delete_receipt *deleted)
{
    struct plamen_broker_v2_process_custodian_terminal_request request;
    struct plamen_broker_v2_process_custodian_terminal_receipt terminal;
    struct guest_extinction_evidence guest_extinction;
    CC_SHA256_CTX revoke_digest;
    uint8_t observation[32], revoke_payload[32], revoke_record[32];
    uint32_t daemon_status = UINT32_MAX;
    uint8_t started_marker;
    static const uint8_t revoke_domain[] =
        "plamen.apple-container.revoke-prepared.v1";
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (deleted != NULL) memset(deleted, 0, sizeof(*deleted));
    memset(&guest_extinction, 0, sizeof(guest_extinction));
    if (context == NULL || context->magic != UINT32_C(0x504c4333)
        || receipt == NULL || deleted == NULL || !context->created
        || context->terminal || context->deleted)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    started_marker = context->started;
    if (CC_SHA256_Init(&revoke_digest) != 1
        || CC_SHA256_Update(&revoke_digest, revoke_domain,
            sizeof(revoke_domain)) != 1
        || CC_SHA256_Update(&revoke_digest,
            context->launch_request_sha256, 32) != 1
        || CC_SHA256_Update(&revoke_digest,
            context->start_operation_nonce, 32) != 1
        || CC_SHA256_Update(&revoke_digest,
            context->wait_operation_nonce, 32) != 1
        || CC_SHA256_Update(&revoke_digest,
            context->revoke_operation_nonce, 32) != 1
        || CC_SHA256_Update(&revoke_digest,
            context->driver_identity.native_process_handle_sha256, 32) != 1
        || CC_SHA256_Update(&revoke_digest, &started_marker, 1) != 1
        || CC_SHA256_Final(revoke_payload, &revoke_digest) != 1
        || persist_exact(context->state_fd, REVOKE_PREPARED_RECORD, 5,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, revoke_payload, revoke_record) != 0)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    if (context->started && !context->terminal) {
        if (stop_and_prove_guest_extinction(
                context, 0, &guest_extinction) != 0
            && stop_and_prove_guest_extinction(
                context, 1, &guest_extinction) != 0)
            return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
        memset(&request, 0, sizeof(request));
        memset(&terminal, 0, sizeof(terminal));
        request.version = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_VERSION;
        memcpy(request.start_operation_key,
            context->start_operation_nonce, 32);
        memcpy(request.operation_key, context->revoke_operation_nonce, 32);
        memcpy(request.request_sha256, revoke_payload, 32);
        memcpy(request.prior_checkpoint_sha256,
            context->custody_started.started_checkpoint_sha256, 32);
        memcpy(request.claim_owner_sha256,
            context->custody_claim_owner_sha256, 32);
        if (plamen_broker_v2_process_custody_client_revoke(
                context->custody_client, &request, &terminal,
                &daemon_status) != PLAMEN_BROKER_V2_CUSTODY_CLIENT_OK
            || (daemon_status != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK
                && daemon_status
                    != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED)
            || !constant_equal(terminal.operation_key,
                request.operation_key, 32)
            || !constant_equal(terminal.request_sha256,
                request.request_sha256, 32)
            || !constant_equal(terminal.prior_checkpoint_sha256,
                request.prior_checkpoint_sha256, 32)
            || collect_terminal(context, &terminal, receipt,
                PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REVOKED,
                &guest_extinction) != 0) {
            plamen_broker_v2_process_custodian_terminal_dispose(&terminal);
            plamen_broker_v2_apple_lifecycle_terminal_dispose(receipt);
            return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
        }
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal);
    } else {
        CC_SHA256_CTX digest;
        static const uint8_t extinction_domain[] =
            "plamen.apple-container.prestart-extinction.v1";
        static const uint8_t cleanup_domain[] =
            "plamen.apple-container.cleanup.v1";
        memset(observation, 0, sizeof(observation));
        if (container_absent(context) == 0) {
            static const uint8_t absent_domain[] =
                "plamen.apple-container.prestart-absent.v1";
            context->known_absent = 1;
            if (plamen_broker_v2_sha256(absent_domain,
                    sizeof(absent_domain), observation) != 0)
                return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_INTERNAL_ERROR;
        } else if (inspect_state(context, "stopped", observation) != 0) {
            return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
        }
        receipt->version = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION;
        receipt->status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REVOKED;
        memcpy(receipt->container_id, context->container_id,
            strlen(context->container_id) + 1U);
        memcpy(receipt->request_fingerprint_sha256,
            context->request_fingerprint, 32);
        memcpy(receipt->spec_sha256, context->spec_sha256, 32);
        memcpy(receipt->launch_request_sha256,
            context->launch_request_sha256, 32);
        memcpy(receipt->start_operation_nonce,
            context->start_operation_nonce, 32);
        memcpy(receipt->wait_operation_nonce, context->wait_operation_nonce, 32);
        memcpy(receipt->revoke_operation_nonce,
            context->revoke_operation_nonce, 32);
        CC_SHA256(NULL, 0, receipt->stdout_sha256);
        CC_SHA256(NULL, 0, receipt->stderr_sha256);
        CC_SHA256(NULL, 0, receipt->stdout_retained_sha256);
        CC_SHA256(NULL, 0, receipt->stderr_retained_sha256);
        receipt->start_monotonic_ms = monotonic_ms();
        receipt->end_monotonic_ms = receipt->start_monotonic_ms;
        receipt->descendants_extinct = 1; receipt->guest_process_extinct = 1;
        receipt->backend_egress_revoked = 1; receipt->terminal_durable = 1;
        if (CC_SHA256_Init(&digest) != 1
            || CC_SHA256_Update(&digest, extinction_domain,
                sizeof(extinction_domain)) != 1
            || CC_SHA256_Update(&digest, context->container_id,
                (CC_LONG)strlen(context->container_id)) != 1
            || CC_SHA256_Update(&digest, observation, 32) != 1
            || CC_SHA256_Final(receipt->native_process_extinction_sha256,
                &digest) != 1
            || CC_SHA256_Init(&digest) != 1
            || CC_SHA256_Update(&digest, cleanup_domain,
                sizeof(cleanup_domain)) != 1
            || CC_SHA256_Update(&digest,
                receipt->native_process_extinction_sha256, 32) != 1
            || CC_SHA256_Update(&digest, context->image_closure, 32) != 1
            || CC_SHA256_Final(receipt->cleanup_sha256, &digest) != 1
            || persist_terminal(context, receipt) != 0)
            return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
        memcpy(context->terminal_receipt_sha256, receipt->receipt_sha256, 32);
        memcpy(context->terminal_cleanup_sha256, receipt->cleanup_sha256, 32);
        context->terminal = 1;
    }
    return plamen_broker_v2_apple_lifecycle_delete(context, receipt, deleted);
}

int
plamen_broker_v2_apple_lifecycle_delete(
    struct plamen_broker_v2_apple_lifecycle *context,
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *terminal,
    struct plamen_broker_v2_apple_lifecycle_delete_receipt *receipt)
{
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt copy;
    struct finite_result control;
    CC_SHA256_CTX digest;
    const char *remove[3];
    uint8_t record[32], payload[32];
    static const uint8_t absence_domain[] = "plamen.apple-container.absent.v1";
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (context == NULL || context->magic != UINT32_C(0x504c4333)
        || terminal == NULL || receipt == NULL || !context->terminal
        || context->deleted || terminal->terminal_durable != 1
        || terminal->descendants_extinct != 1
        || terminal->guest_process_extinct != 1
        || terminal->backend_egress_revoked != 1
        || strcmp(terminal->container_id, context->container_id) != 0
        || !constant_equal(terminal->cleanup_sha256,
            context->terminal_cleanup_sha256, 32))
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    copy = *terminal; memset(copy.receipt_sha256, 0, 32);
    terminal_digest(&copy);
    if (!constant_equal(copy.receipt_sha256,
            context->terminal_receipt_sha256, 32)
        || !constant_equal(terminal->receipt_sha256,
            context->terminal_receipt_sha256, 32))
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    if (!context->known_absent) {
        /* Reconcile the exact guest immediately before destructive mutation.
         * inspect_state also proves both configuration and live attachments
         * have empty network rosters. */
        if (inspect_state(context, "stopped", record) != 0)
            return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
        remove[0] = context->cli_path; remove[1] = "delete";
        remove[2] = context->container_id;
        if (run_finite(context, remove, 3, 30, &control) != 0
            || control.stderr_size != 0
            || !exact_stdout_id(&control, context->container_id)) {
            finite_dispose(&control);
            return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
        }
        finite_dispose(&control);
    }
    if (container_absent(context) != 0)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    receipt->version = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION;
    receipt->status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
    memcpy(receipt->container_id, context->container_id,
        strlen(context->container_id) + 1U);
    memcpy(receipt->request_fingerprint_sha256, context->request_fingerprint, 32);
    memcpy(receipt->spec_sha256, context->spec_sha256, 32);
    memcpy(receipt->terminal_receipt_sha256,
        context->terminal_receipt_sha256, 32);
    memcpy(receipt->cleanup_sha256, context->terminal_cleanup_sha256, 32);
    receipt->descendants_extinct = 1; receipt->guest_process_extinct = 1;
    receipt->backend_egress_revoked = 1; receipt->absent = 1;
    if (CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, absence_domain, sizeof(absence_domain)) != 1
        || CC_SHA256_Update(&digest, context->container_id,
            (CC_LONG)strlen(context->container_id)) != 1
        || CC_SHA256_Update(&digest, context->terminal_receipt_sha256, 32) != 1
        || CC_SHA256_Final(receipt->absence_sha256, &digest) != 1
        || plamen_broker_v2_sha256(receipt,
            offsetof(struct plamen_broker_v2_apple_lifecycle_delete_receipt,
                receipt_sha256), receipt->receipt_sha256) != 0
        || plamen_broker_v2_sha256(receipt->receipt_sha256, 32, payload) != 0
        || persist_exact(context->state_fd, DELETE_RECORD, 6,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, payload, record) != 0)
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    context->deleted = 1;
    return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

int
plamen_broker_v2_apple_lifecycle_reopen_deleted(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    struct plamen_broker_v2_process_custody_client *client,
    const uint8_t claim_owner_sha256[32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *created,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *started,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *terminal,
    struct plamen_broker_v2_apple_lifecycle_delete_receipt *deleted,
    struct plamen_broker_v2_apple_lifecycle **output)
{
    struct plamen_broker_v2_apple_lifecycle *context = NULL;
    CC_SHA256_CTX digest;
    uint8_t record[32], payload[32];
    int status;
    static const uint8_t absence_domain[] =
        "plamen.apple-container.absent.v1";
    if (deleted != NULL) memset(deleted, 0, sizeof(*deleted));
    if (output != NULL) *output = NULL;
    if (deleted == NULL || output == NULL) {
        if (created != NULL) memset(created, 0, sizeof(*created));
        if (started != NULL) memset(started, 0, sizeof(*started));
        if (terminal != NULL)
            plamen_broker_v2_apple_lifecycle_terminal_dispose(terminal);
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED;
    }
    status = reopen_terminal_state(spec, client, claim_owner_sha256, created,
        started, terminal, &context, 1);
    if (status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK) return status;
    deleted->version = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION;
    deleted->status = PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
    memcpy(deleted->container_id, context->container_id,
        strlen(context->container_id) + 1U);
    memcpy(deleted->request_fingerprint_sha256,
        context->request_fingerprint, 32);
    memcpy(deleted->spec_sha256, context->spec_sha256, 32);
    memcpy(deleted->terminal_receipt_sha256,
        context->terminal_receipt_sha256, 32);
    memcpy(deleted->cleanup_sha256, context->terminal_cleanup_sha256, 32);
    deleted->descendants_extinct = 1;
    deleted->guest_process_extinct = 1;
    deleted->backend_egress_revoked = 1;
    deleted->absent = 1;
    if (CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, absence_domain,
            sizeof(absence_domain)) != 1
        || CC_SHA256_Update(&digest, context->container_id,
            (CC_LONG)strlen(context->container_id)) != 1
        || CC_SHA256_Update(&digest,
            context->terminal_receipt_sha256, 32) != 1
        || CC_SHA256_Final(deleted->absence_sha256, &digest) != 1
        || plamen_broker_v2_sha256(deleted,
            offsetof(struct plamen_broker_v2_apple_lifecycle_delete_receipt,
                receipt_sha256), deleted->receipt_sha256) != 0
        || plamen_broker_v2_sha256(deleted->receipt_sha256, 32, payload) != 0
        || read_exact_record(context->state_fd, DELETE_RECORD, 6,
            context->container_id, context->request_fingerprint,
            context->spec_sha256, payload, record) != 0
        || plamen_broker_v2_apple_lifecycle_delete_receipt_validate(deleted)
            != 0) {
        plamen_broker_v2_apple_lifecycle_terminal_dispose(terminal);
        close_context(context);
        if (created != NULL) memset(created, 0, sizeof(*created));
        if (started != NULL) memset(started, 0, sizeof(*started));
        memset(deleted, 0, sizeof(*deleted));
        plamen_broker_v2_secure_zero(record, sizeof(record));
        plamen_broker_v2_secure_zero(payload, sizeof(payload));
        return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS;
    }
    context->known_absent = 1;
    context->deleted = 1;
    *output = context;
    plamen_broker_v2_secure_zero(record, sizeof(record));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
    return PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK;
}

int
plamen_broker_v2_apple_lifecycle_delete_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_delete_receipt *receipt)
{
    struct plamen_broker_v2_apple_lifecycle_delete_receipt copy;
    uint8_t digest[32];
    if (receipt == NULL
        || receipt->version != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION
        || receipt->status != PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK
        || plamen_broker_v2_apple_container_id_validate(receipt->container_id)
            != 0
        || receipt->absent != 1 || all_zero(receipt->absence_sha256)
        || all_zero(receipt->terminal_receipt_sha256)
        || all_zero(receipt->cleanup_sha256))
        return -1;
    copy = *receipt;
    memset(copy.receipt_sha256, 0, sizeof(copy.receipt_sha256));
    if (plamen_broker_v2_sha256(&copy,
            offsetof(struct plamen_broker_v2_apple_lifecycle_delete_receipt,
                receipt_sha256), digest) != 0)
        return -1;
    return constant_equal(digest, receipt->receipt_sha256, 32) ? 0 : -1;
}

void
plamen_broker_v2_apple_lifecycle_terminal_dispose(
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    if (receipt == NULL) return;
    if (receipt->stdout_retained != NULL) {
        plamen_broker_v2_secure_zero(receipt->stdout_retained,
            receipt->stdout_retained_bytes); free(receipt->stdout_retained);
    }
    if (receipt->stderr_retained != NULL) {
        plamen_broker_v2_secure_zero(receipt->stderr_retained,
            receipt->stderr_retained_bytes); free(receipt->stderr_retained);
    }
    memset(receipt, 0, sizeof(*receipt));
}

int
plamen_broker_v2_apple_lifecycle_close(
    struct plamen_broker_v2_apple_lifecycle *context)
{
    if (context == NULL || context->magic != UINT32_C(0x504c4333)
        || context->driver != NULL || !context->deleted) return -1;
    close_context(context); return 0;
}

int
plamen_broker_v2_apple_lifecycle_detach(
    struct plamen_broker_v2_apple_lifecycle *context)
{
    if (context == NULL || context->magic != UINT32_C(0x504c4333)
        || context->driver != NULL || context->custody_client == NULL)
        return -1;
    close_context(context);
    return 0;
}

#ifdef PLAMEN_BROKER_V2_APPLE_CONTAINER_TEST_ONLY
int
plamen_broker_v2_apple_lifecycle_test_create_argv(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    char *output, size_t capacity)
{
    const char *argv[PLAMEN_BROKER_V2_PROCESS_ARGC_MAX]; size_t argc = 0, index, used = 0;
    char numbers[4][32];
    char mounts[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX]
        [PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX * 2U + 64U];
    int amount;
    if (spec == NULL || output == NULL || capacity == 0
        || build_create_argv(spec, argv, &argc, numbers, mounts) != 0) return -1;
    for (index = 0; index < argc; ++index) {
        amount = snprintf(output + used, capacity - used, "%s%s",
            index == 0 ? "" : "\n", argv[index]);
        if (amount < 0 || (size_t)amount >= capacity - used) return -1;
        used += (size_t)amount;
    }
    return 0;
}

int
plamen_broker_v2_apple_lifecycle_test_validate_spec(
    const struct plamen_broker_v2_apple_lifecycle_spec *spec)
{
    uint8_t mount_sha[32];
    return validate_spec(spec, mount_sha);
}

int
plamen_broker_v2_apple_lifecycle_test_validate_inspect(const uint8_t *bytes,
    size_t size, const struct plamen_broker_v2_apple_lifecycle_spec *spec,
    const char *state, uint8_t observation[32])
{
    return validate_inspect_document(bytes, size, spec, state, observation);
}

int
plamen_broker_v2_apple_lifecycle_test_exact_id_output(const uint8_t *bytes,
    size_t size, const char *container_id)
{
    struct finite_result result;
    memset(&result, 0, sizeof(result));
    result.stdout_bytes = (uint8_t *)bytes; result.stdout_size = (uint32_t)size;
    return size <= UINT32_MAX && exact_stdout_id(&result, container_id) ? 0 : -1;
}

int
plamen_broker_v2_apple_lifecycle_test_list_proves_absent(
    const uint8_t *bytes, size_t size, const char *container_id)
{
    return list_proves_absent(bytes, size, container_id);
}

int
plamen_broker_v2_apple_lifecycle_test_encode_create_receipt(
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt,
    uint8_t bytes[RECORD_SIZE])
{
    return encode_create_receipt(receipt, bytes);
}

int
plamen_broker_v2_apple_lifecycle_test_decode_create_receipt(
    const uint8_t bytes[RECORD_SIZE],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *receipt)
{
    return decode_create_receipt(bytes, receipt);
}

int
plamen_broker_v2_apple_lifecycle_test_encode_start_receipt(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt,
    uint8_t bytes[RECORD_SIZE])
{
    return encode_start_receipt(receipt, bytes);
}

int
plamen_broker_v2_apple_lifecycle_test_decode_start_receipt(
    const uint8_t bytes[RECORD_SIZE],
    struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt)
{
    return decode_start_receipt(bytes, receipt);
}

int
plamen_broker_v2_apple_lifecycle_test_encode_terminal_receipt(
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt,
    uint8_t bytes[TERMINAL_RECORD_SIZE])
{
    return encode_terminal(receipt, bytes);
}

int
plamen_broker_v2_apple_lifecycle_test_decode_terminal_receipt(
    const uint8_t bytes[TERMINAL_RECORD_SIZE],
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *receipt)
{
    return decode_terminal(bytes, receipt);
}

int
plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity(
    struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt,
    const struct plamen_broker_v2_process_start_identity *identity)
{
    if (bind_start_dynamic_identity(receipt, identity) != 0
        || start_receipt_digest(receipt) != 0)
        return -1;
    return plamen_broker_v2_apple_lifecycle_start_receipt_validate(receipt);
}

int
plamen_broker_v2_apple_lifecycle_test_start_dynamic_identity_matches(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *receipt,
    const struct plamen_broker_v2_process_start_identity *identity)
{
    return start_dynamic_identity_matches(receipt, identity);
}
#endif
