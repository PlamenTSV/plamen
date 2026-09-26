#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_specialized_effect_store.h"
#include "plamen_broker_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef RENAME_EXCL
#error "specialized effect store requires renameatx_np(RENAME_EXCL)"
#endif

#define STORE_MAGIC UINT32_C(0x504c4553)
#define PREPARED_SIZE 256U
#define INDEX_SIZE 256U
#define TERMINAL_HEADER_SIZE 384U
#define TERMINAL_TRAILER_SIZE 32U

static const uint8_t prepared_magic[8] = {
    'P', 'L', 'M', 'S', 'W', 'P', '1', '\0'
};
static const uint8_t index_magic[8] = {
    'P', 'L', 'M', 'S', 'W', 'I', '1', '\0'
};
static const uint8_t terminal_magic[8] = {
    'P', 'L', 'M', 'S', 'W', 'T', '1', '\0'
};
static const uint8_t key_domain[] =
    "PLAMEN-SPECIALIZED-WORKER-TERMINAL-KEY-V1\0";
static const uint8_t method_terminal_domain[] =
    "PLAMEN-SPECIALIZED-METHOD-TERMINAL-V1\0";

struct plamen_broker_v2_specialized_effect_store {
    uint32_t magic;
    int directory_fd;
    uint8_t session_key[32];
    uint8_t runtime_authority_sha256[32];
};

static void put16(uint8_t *out, uint16_t value)
{ out[0] = (uint8_t)(value >> 8); out[1] = (uint8_t)value; }

static void put32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24); out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8); out[3] = (uint8_t)value;
}

static void put64(uint8_t *out, uint64_t value)
{
    size_t index;
    for (index = 0; index < 8U; ++index) {
        out[7U - index] = (uint8_t)value; value >>= 8;
    }
}

static uint16_t get16(const uint8_t *in)
{ return (uint16_t)(((uint16_t)in[0] << 8) | in[1]); }

static uint32_t get32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | in[3];
}

static uint64_t get64(const uint8_t *in)
{
    uint64_t value = 0; size_t index;
    for (index = 0; index < 8U; ++index) value = (value << 8) | in[index];
    return value;
}

static int zero32(const uint8_t value[32])
{
    uint8_t aggregate = 0; size_t index;
    for (index = 0; index < 32U; ++index) aggregate |= value[index];
    return aggregate == 0;
}

static int equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0; size_t index;
    for (index = 0; index < size; ++index) difference |= left[index] ^ right[index];
    return difference == 0;
}

static int hash(const uint8_t *bytes, size_t size, uint8_t output[32])
{
    return bytes != NULL && output != NULL && size <= UINT32_MAX
        && CC_SHA256(bytes, (CC_LONG)size, output) != NULL ? 0 : -1;
}

static void hex32(const uint8_t value[32], char output[65])
{
    static const char alphabet[] = "0123456789abcdef"; size_t index;
    for (index = 0; index < 32U; ++index) {
        output[index * 2U] = alphabet[value[index] >> 4];
        output[index * 2U + 1U] = alphabet[value[index] & 15U];
    }
    output[64] = '\0';
}

static int private_directory(int descriptor)
{
    struct stat information; int flags;
    return descriptor >= 0 && fstat(descriptor, &information) == 0
        && S_ISDIR(information.st_mode) && information.st_uid == geteuid()
        && (information.st_mode & 0077) == 0
        && (flags = fcntl(descriptor, F_GETFD)) >= 0
        && (flags & FD_CLOEXEC) != 0;
}

static int exact_file(int descriptor, size_t expected_size)
{
    struct stat information; int flags;
    return descriptor >= 0 && fstat(descriptor, &information) == 0
        && S_ISREG(information.st_mode) && information.st_nlink == 1
        && information.st_uid == geteuid()
        && (information.st_mode & 0777) == 0400
        && information.st_size == (off_t)expected_size
        && (flags = fcntl(descriptor, F_GETFL)) >= 0
        && (flags & O_ACCMODE) == O_RDONLY;
}

static int read_all(int descriptor, uint8_t *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = pread(descriptor, bytes + offset, size - offset,
            (off_t)offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int write_all(int descriptor, const uint8_t *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = write(descriptor, bytes + offset, size - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int read_named(int directory, const char *name, size_t exact_size,
    uint8_t **output)
{
    uint8_t *bytes = NULL; int descriptor = -1, result = -1;
    if (output != NULL) *output = NULL;
    if (directory < 0 || name == NULL || output == NULL || exact_size == 0)
        return -1;
    descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    bytes = malloc(exact_size);
    if (descriptor < 0 || bytes == NULL || !exact_file(descriptor, exact_size)
        || read_all(descriptor, bytes, exact_size) != 0)
        goto done;
    *output = bytes; bytes = NULL; result = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (bytes != NULL) { memset(bytes, 0, exact_size); free(bytes); }
    return result;
}

static int publish_exact(int directory, const char *final_name,
    const uint8_t *bytes, size_t size)
{
    uint8_t nonce[16]; char nonce_hex[33], temporary[128];
    size_t index;
    int descriptor = -1, amount, result = -1, saved_errno = 0;
    static const char alphabet[] = "0123456789abcdef";
    if (directory < 0 || final_name == NULL || bytes == NULL || size == 0
        || getentropy(nonce, sizeof(nonce)) != 0)
        return -1;
    for (index = 0; index < sizeof(nonce); ++index) {
        nonce_hex[index * 2U] = alphabet[nonce[index] >> 4];
        nonce_hex[index * 2U + 1U] = alphabet[nonce[index] & 15U];
    }
    nonce_hex[32] = '\0';
    amount = snprintf(temporary, sizeof(temporary), ".pending-%s", nonce_hex);
    if (amount <= 0 || (size_t)amount >= sizeof(temporary)) goto done;
    descriptor = openat(directory, temporary,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0 || write_all(descriptor, bytes, size) != 0
        || fsync(descriptor) != 0 || fchmod(descriptor, 0400) != 0
        || fsync(descriptor) != 0 || close(descriptor) != 0)
        goto done;
    descriptor = -1;
    if (renameatx_np(directory, temporary, directory, final_name,
            RENAME_EXCL) != 0 || fsync(directory) != 0)
        goto done;
    result = 0;
done:
    saved_errno = errno;
    if (descriptor >= 0) (void)close(descriptor);
    if (result != 0 && temporary[0] != '\0')
        (void)unlinkat(directory, temporary, 0);
    memset(nonce, 0, sizeof(nonce)); memset(nonce_hex, 0, sizeof(nonce_hex));
    memset(temporary, 0, sizeof(temporary));
    if (result != 0) errno = saved_errno;
    return result;
}

static int publish_or_match(int directory, const char *name,
    const uint8_t *bytes, size_t size)
{
    uint8_t *existing = NULL; int result;
    result = publish_exact(directory, name, bytes, size);
    if (result == 0) return 0;
    if (errno != EEXIST || read_named(directory, name, size, &existing) != 0)
        return -1;
    result = equal(existing, bytes, size) ? 0 : -1;
    memset(existing, 0, size); free(existing); return result;
}

static int prepared_name(const uint8_t key[32], char output[96])
{
    char hex[65]; int amount; hex32(key, hex);
    amount = snprintf(output, 96, "prepared-%s.bin", hex);
    memset(hex, 0, sizeof(hex)); return amount == 77 ? 0 : -1;
}

static int index_name(const uint8_t key[32], char output[96])
{
    char hex[65]; int amount; hex32(key, hex);
    amount = snprintf(output, 96, "completed-%s.bin", hex);
    memset(hex, 0, sizeof(hex)); return amount == 78 ? 0 : -1;
}

static int terminal_name(const uint8_t key[32], char output[96])
{
    char hex[65]; int amount; hex32(key, hex);
    amount = snprintf(output, 96, "terminal-%s.bin", hex);
    memset(hex, 0, sizeof(hex)); return amount == 77 ? 0 : -1;
}

static int worker_request_name(const uint8_t key[32], char output[96])
{
    char hex[65]; int amount; hex32(key, hex);
    amount = snprintf(output, 96, "worker-request-%s.json", hex);
    memset(hex, 0, sizeof(hex)); return amount == 84 ? 0 : -1;
}

int
plamen_broker_v2_specialized_effect_store_stage_worker_request(
    struct plamen_broker_v2_specialized_effect_store *store,
    const uint8_t operation_key[32], const uint8_t *request,
    size_t request_size, int *request_fd, uint8_t request_bytes_sha256[32])
{
    char name[96]; uint8_t *observed = NULL, digest[32];
    int descriptor = -1, result = -1;
    if (request_fd != NULL) *request_fd = -1;
    if (request_bytes_sha256 != NULL)
        memset(request_bytes_sha256, 0, 32);
    memset(name, 0, sizeof(name)); memset(digest, 0, sizeof(digest));
    if (store == NULL || store->magic != STORE_MAGIC || operation_key == NULL
        || zero32(operation_key) || request == NULL || request_size < 2U
        || request_size > 1048576U || request_fd == NULL
        || request_bytes_sha256 == NULL
        || hash(request, request_size, digest) != 0
        || worker_request_name(operation_key, name) != 0
        || publish_or_match(store->directory_fd, name, request,
            request_size) != 0)
        goto done;
    descriptor = openat(store->directory_fd, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    observed = malloc(request_size);
    if (descriptor < 0 || observed == NULL
        || !exact_file(descriptor, request_size)
        || read_all(descriptor, observed, request_size) != 0
        || !equal(observed, request, request_size)
        || lseek(descriptor, 0, SEEK_SET) != 0)
        goto done;
    memcpy(request_bytes_sha256, digest, 32);
    *request_fd = descriptor; descriptor = -1; result = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (observed != NULL) {
        memset(observed, 0, request_size); free(observed);
    }
    memset(name, 0, sizeof(name)); memset(digest, 0, sizeof(digest));
    return result;
}

int
plamen_broker_v2_specialized_effect_store_open(int directory_fd,
    const uint8_t session_key[32], const uint8_t runtime_authority_sha256[32],
    struct plamen_broker_v2_specialized_effect_store **output)
{
    struct plamen_broker_v2_specialized_effect_store *store;
    int duplicate;
    if (output != NULL) *output = NULL;
    if (output == NULL || session_key == NULL
        || runtime_authority_sha256 == NULL || zero32(session_key)
        || zero32(runtime_authority_sha256) || !private_directory(directory_fd)
        || (duplicate = fcntl(directory_fd, F_DUPFD_CLOEXEC, 3)) < 0)
        return -1;
    store = calloc(1, sizeof(*store));
    if (store == NULL) { (void)close(duplicate); return -1; }
    store->magic = STORE_MAGIC; store->directory_fd = duplicate;
    memcpy(store->session_key, session_key, 32);
    memcpy(store->runtime_authority_sha256, runtime_authority_sha256, 32);
    *output = store; return 0;
}

int
plamen_broker_v2_specialized_effect_store_prepare(
    struct plamen_broker_v2_specialized_effect_store *store, uint16_t lane,
    uint16_t method, const uint8_t operation_key[32],
    const uint8_t request_sha256[32], uint8_t terminal_hmac_key[32],
    int *created)
{
    uint8_t record[PREPARED_SIZE], preimage[100], digest[32];
    uint8_t *existing = NULL; char name[96]; int result = -1;
    if (terminal_hmac_key != NULL) memset(terminal_hmac_key, 0, 32);
    if (created != NULL) *created = 0;
    memset(record, 0, sizeof(record)); memset(preimage, 0, sizeof(preimage));
    memset(digest, 0, sizeof(digest)); memset(name, 0, sizeof(name));
    if (store == NULL || store->magic != STORE_MAGIC || lane == 0 || method == 0
        || operation_key == NULL || request_sha256 == NULL
        || terminal_hmac_key == NULL || created == NULL || zero32(operation_key)
        || zero32(request_sha256) || prepared_name(operation_key, name) != 0)
        goto done;
    memcpy(preimage, operation_key, 32); memcpy(preimage + 32, request_sha256, 32);
    memcpy(preimage + 64, store->runtime_authority_sha256, 32);
    put16(preimage + 96, lane); put16(preimage + 98, method);
    if (plamen_broker_v2_hmac_sha256(store->session_key, key_domain,
            sizeof(key_domain), preimage, sizeof(preimage), terminal_hmac_key)
            != 0 || zero32(terminal_hmac_key))
        goto done;
    memcpy(record, prepared_magic, 8); put32(record + 8, 1U);
    put32(record + 12, PREPARED_SIZE); put16(record + 16, lane);
    put16(record + 18, method); memcpy(record + 24, operation_key, 32);
    memcpy(record + 56, request_sha256, 32);
    memcpy(record + 88, store->runtime_authority_sha256, 32);
    memcpy(record + 120, terminal_hmac_key, 32);
    if (hash(terminal_hmac_key, 32, record + 152) != 0
        || hash(store->session_key, 32, record + 184) != 0
        || hash(record, 224, record + 224) != 0)
        goto done;
    if (publish_exact(store->directory_fd, name, record, sizeof(record)) == 0) {
        *created = 1; result = 0; goto done;
    }
    if (errno != EEXIST
        || read_named(store->directory_fd, name, sizeof(record), &existing) != 0
        || hash(existing, 224, digest) != 0
        || !equal(existing, record, 120)
        || !equal(digest, existing + 224, 32)
        || zero32(existing + 120)
        || hash(existing + 120, 32, digest) != 0
        || !equal(digest, existing + 152, 32))
        goto done;
    memcpy(terminal_hmac_key, existing + 120, 32); result = 0;
done:
    if (existing != NULL) { memset(existing, 0, PREPARED_SIZE); free(existing); }
    memset(record, 0, sizeof(record)); memset(preimage, 0, sizeof(preimage));
    memset(digest, 0, sizeof(digest)); memset(name, 0, sizeof(name));
    if (result != 0) {
        memset(terminal_hmac_key, 0, 32); *created = 0;
    }
    return result;
}

static int
completion_terminal_hmac_valid(
    struct plamen_broker_v2_specialized_effect_store *store,
    const struct plamen_broker_v2_specialized_effect_completion *completion,
    const uint8_t *terminal, size_t terminal_size)
{
    uint8_t *prepared = NULL; uint8_t digest[32], expected[32]; char name[96];
    int valid = 0;
    memset(digest, 0, sizeof(digest)); memset(expected, 0, sizeof(expected));
    memset(name, 0, sizeof(name));
    if (store == NULL || store->magic != STORE_MAGIC || completion == NULL
        || terminal == NULL || terminal_size == 0U
        || prepared_name(completion->operation_key, name) != 0
        || read_named(store->directory_fd, name, PREPARED_SIZE, &prepared) != 0
        || memcmp(prepared, prepared_magic, sizeof(prepared_magic)) != 0
        || get32(prepared + 8) != 1U || get32(prepared + 12) != PREPARED_SIZE
        || get16(prepared + 16) != completion->lane
        || get16(prepared + 18) != completion->method
        || !equal(prepared + 24, completion->operation_key, 32)
        || !equal(prepared + 56, completion->request_sha256, 32)
        || !equal(prepared + 88, completion->runtime_authority_sha256, 32)
        || zero32(prepared + 120)
        || hash(prepared, 224, digest) != 0
        || !equal(digest, prepared + 224, 32)
        || plamen_broker_v2_hmac_sha256(prepared + 120,
            method_terminal_domain, sizeof(method_terminal_domain), terminal,
            terminal_size, expected) != 0
        || !equal(expected, completion->terminal_hmac_sha256, 32))
        goto done;
    valid = 1;
done:
    if (prepared != NULL) { memset(prepared, 0, PREPARED_SIZE); free(prepared); }
    memset(digest, 0, sizeof(digest)); memset(expected, 0, sizeof(expected));
    memset(name, 0, sizeof(name)); return valid;
}

static int encode_terminal_header(
    const struct plamen_broker_v2_specialized_effect_completion *completion,
    size_t terminal_size, uint8_t header[TERMINAL_HEADER_SIZE])
{
    memset(header, 0, TERMINAL_HEADER_SIZE);
    if (completion == NULL || completion->version != 1U
        || completion->lane == 0 || completion->method == 0
        || zero32(completion->operation_key) || zero32(completion->request_sha256)
        || zero32(completion->runtime_authority_sha256)
        || zero32(completion->worker_request_sha256)
        || zero32(completion->lifecycle_receipt_sha256)
        || zero32(completion->terminal_sha256)
        || zero32(completion->terminal_hmac_sha256)
        || completion->provider_authenticated != 1U
        || completion->population_zero != 1U || completion->cleanup_complete != 1U
        || completion->network_policy_enforced > 1U
        || terminal_size == 0
        || terminal_size > PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_TERMINAL_MAX)
        return -1;
    memcpy(header, terminal_magic, 8); put32(header + 8, 1U);
    put32(header + 12, TERMINAL_HEADER_SIZE); put16(header + 16, completion->lane);
    put16(header + 18, completion->method); put32(header + 20, completion->flags);
    memcpy(header + 24, completion->operation_key, 32);
    memcpy(header + 56, completion->request_sha256, 32);
    memcpy(header + 88, completion->runtime_authority_sha256, 32);
    memcpy(header + 120, completion->worker_request_sha256, 32);
    memcpy(header + 152, completion->lifecycle_receipt_sha256, 32);
    memcpy(header + 184, completion->terminal_sha256, 32);
    memcpy(header + 216, completion->terminal_hmac_sha256, 32);
    memcpy(header + 248, completion->network_policy_sha256, 32);
    memcpy(header + 280, completion->observed_egress_sha256, 32);
    put64(header + 312, (uint64_t)terminal_size);
    header[320] = completion->provider_authenticated;
    header[321] = completion->network_policy_enforced;
    header[322] = completion->population_zero;
    header[323] = completion->cleanup_complete;
    return hash(header, 352, header + 352);
}

static int completion_equal(
    const struct plamen_broker_v2_specialized_effect_completion *left,
    const struct plamen_broker_v2_specialized_effect_completion *right)
{
    return left != NULL && right != NULL
        && left->version == right->version && left->lane == right->lane
        && left->method == right->method && left->flags == right->flags
        && equal(left->operation_key, right->operation_key, 32)
        && equal(left->request_sha256, right->request_sha256, 32)
        && equal(left->runtime_authority_sha256,
            right->runtime_authority_sha256, 32)
        && equal(left->worker_request_sha256,
            right->worker_request_sha256, 32)
        && equal(left->lifecycle_receipt_sha256,
            right->lifecycle_receipt_sha256, 32)
        && equal(left->terminal_sha256, right->terminal_sha256, 32)
        && equal(left->terminal_hmac_sha256,
            right->terminal_hmac_sha256, 32)
        && equal(left->network_policy_sha256,
            right->network_policy_sha256, 32)
        && equal(left->observed_egress_sha256,
            right->observed_egress_sha256, 32)
        && left->provider_authenticated == right->provider_authenticated
        && left->network_policy_enforced == right->network_policy_enforced
        && left->population_zero == right->population_zero
        && left->cleanup_complete == right->cleanup_complete;
}

static int decode_terminal_record(const uint8_t *record, size_t size,
    const uint8_t expected_authority[32],
    struct plamen_broker_v2_specialized_effect_completion *completion,
    uint8_t **terminal, size_t *terminal_size)
{
    uint8_t digest[32]; size_t payload_size; int result = -1;
    if (terminal != NULL) *terminal = NULL;
    if (terminal_size != NULL) *terminal_size = 0;
    memset(digest, 0, sizeof(digest));
    if (record == NULL || expected_authority == NULL || completion == NULL
        || terminal == NULL || terminal_size == NULL
        || size < TERMINAL_HEADER_SIZE + TERMINAL_TRAILER_SIZE
        || memcmp(record, terminal_magic, 8) != 0 || get32(record + 8) != 1U
        || get32(record + 12) != TERMINAL_HEADER_SIZE
        || (payload_size = (size_t)get64(record + 312)) == 0
        || payload_size > PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_TERMINAL_MAX
        || size != TERMINAL_HEADER_SIZE + payload_size + TERMINAL_TRAILER_SIZE
        || hash(record, 352, digest) != 0 || !equal(digest, record + 352, 32)
        || hash(record, TERMINAL_HEADER_SIZE + payload_size, digest) != 0
        || !equal(digest, record + TERMINAL_HEADER_SIZE + payload_size, 32)
        || hash(record + TERMINAL_HEADER_SIZE, payload_size, digest) != 0
        || !equal(digest, record + 184, 32)
        || !equal(record + 88, expected_authority, 32)
        || record[320] != 1U || record[321] > 1U
        || record[322] != 1U || record[323] != 1U)
        goto done;
    memset(completion, 0, sizeof(*completion)); completion->version = 1U;
    completion->lane = get16(record + 16); completion->method = get16(record + 18);
    completion->flags = get32(record + 20);
    memcpy(completion->operation_key, record + 24, 32);
    memcpy(completion->request_sha256, record + 56, 32);
    memcpy(completion->runtime_authority_sha256, record + 88, 32);
    memcpy(completion->worker_request_sha256, record + 120, 32);
    memcpy(completion->lifecycle_receipt_sha256, record + 152, 32);
    memcpy(completion->terminal_sha256, record + 184, 32);
    memcpy(completion->terminal_hmac_sha256, record + 216, 32);
    memcpy(completion->network_policy_sha256, record + 248, 32);
    memcpy(completion->observed_egress_sha256, record + 280, 32);
    completion->provider_authenticated = record[320];
    completion->network_policy_enforced = record[321];
    completion->population_zero = record[322];
    completion->cleanup_complete = record[323];
    *terminal = malloc(payload_size);
    if (*terminal == NULL) goto done;
    memcpy(*terminal, record + TERMINAL_HEADER_SIZE, payload_size);
    *terminal_size = payload_size; result = 0;
done:
    if (result != 0) {
        if (terminal != NULL && *terminal != NULL) {
            memset(*terminal, 0, payload_size); free(*terminal); *terminal = NULL;
        }
        if (terminal_size != NULL) *terminal_size = 0;
        if (completion != NULL) memset(completion, 0, sizeof(*completion));
    }
    memset(digest, 0, sizeof(digest)); return result;
}

int
plamen_broker_v2_specialized_effect_store_commit(
    struct plamen_broker_v2_specialized_effect_store *store,
    const struct plamen_broker_v2_specialized_effect_completion *completion,
    const uint8_t *terminal, size_t terminal_size)
{
    uint8_t header[TERMINAL_HEADER_SIZE], *record = NULL, *prepared = NULL;
    uint8_t index[INDEX_SIZE], digest[32];
    char terminal_file[96], prepared_file[96], index_file[96];
    struct plamen_broker_v2_specialized_effect_completion existing_completion;
    uint8_t *existing_terminal = NULL;
    size_t record_size, existing_terminal_size = 0;
    struct stat existing_index;
    int result = -1;
    memset(header, 0, sizeof(header)); memset(index, 0, sizeof(index));
    memset(digest, 0, sizeof(digest)); memset(terminal_file, 0, sizeof(terminal_file));
    memset(prepared_file, 0, sizeof(prepared_file)); memset(index_file, 0, sizeof(index_file));
    memset(&existing_completion, 0, sizeof(existing_completion));
    if (store == NULL || store->magic != STORE_MAGIC || completion == NULL
        || terminal == NULL || terminal_size == 0
        || !equal(completion->runtime_authority_sha256,
            store->runtime_authority_sha256, 32)
        || hash(terminal, terminal_size, digest) != 0
        || !equal(digest, completion->terminal_sha256, 32)
        || !completion_terminal_hmac_valid(store, completion,
            terminal, terminal_size)
        || encode_terminal_header(completion, terminal_size, header) != 0
        || prepared_name(completion->operation_key, prepared_file) != 0
        || index_name(completion->operation_key, index_file) != 0
        || terminal_name(completion->terminal_sha256, terminal_file) != 0
        )
        goto done;
    if (fstatat(store->directory_fd, index_file, &existing_index,
            AT_SYMLINK_NOFOLLOW) == 0) {
        if (plamen_broker_v2_specialized_effect_store_lookup_operation(store,
                completion->operation_key, completion->request_sha256,
                &existing_completion, &existing_terminal,
                &existing_terminal_size) != 0
            || !completion_equal(&existing_completion, completion)
            || existing_terminal_size != terminal_size
            || !equal(existing_terminal, terminal, terminal_size))
            goto done;
        result = 0; goto done;
    }
    if (errno != ENOENT
        || read_named(store->directory_fd, prepared_file, PREPARED_SIZE,
            &prepared) != 0
        || memcmp(prepared, prepared_magic, 8) != 0
        || get32(prepared + 8) != 1U || get32(prepared + 12) != PREPARED_SIZE
        || get16(prepared + 16) != completion->lane
        || get16(prepared + 18) != completion->method
        || !equal(prepared + 24, completion->operation_key, 32)
        || !equal(prepared + 56, completion->request_sha256, 32)
        || !equal(prepared + 88, completion->runtime_authority_sha256, 32)
        || hash(prepared, 224, digest) != 0 || !equal(digest, prepared + 224, 32))
        goto done;
    record_size = TERMINAL_HEADER_SIZE + terminal_size + TERMINAL_TRAILER_SIZE;
    record = malloc(record_size);
    if (record == NULL) goto done;
    memcpy(record, header, TERMINAL_HEADER_SIZE);
    memcpy(record + TERMINAL_HEADER_SIZE, terminal, terminal_size);
    if (hash(record, TERMINAL_HEADER_SIZE + terminal_size,
            record + TERMINAL_HEADER_SIZE + terminal_size) != 0
        || publish_or_match(store->directory_fd, terminal_file,
            record, record_size) != 0)
        goto done;
    memcpy(index, index_magic, 8); put32(index + 8, 1U);
    put32(index + 12, INDEX_SIZE); put16(index + 16, completion->lane);
    put16(index + 18, completion->method); put32(index + 20, completion->flags);
    memcpy(index + 24, completion->operation_key, 32);
    memcpy(index + 56, completion->request_sha256, 32);
    memcpy(index + 88, completion->runtime_authority_sha256, 32);
    memcpy(index + 120, completion->terminal_sha256, 32);
    memcpy(index + 152, completion->worker_request_sha256, 32);
    memcpy(index + 184, completion->lifecycle_receipt_sha256, 32);
    if (hash(index, 224, index + 224) != 0
        || publish_or_match(store->directory_fd, index_file,
            index, sizeof(index)) != 0)
        goto done;
    result = 0;
done:
    if (record != NULL) { memset(record, 0, record_size); free(record); }
    if (prepared != NULL) { memset(prepared, 0, PREPARED_SIZE); free(prepared); }
    if (existing_terminal != NULL) {
        memset(existing_terminal, 0, existing_terminal_size);
        free(existing_terminal);
    }
    memset(header, 0, sizeof(header)); memset(index, 0, sizeof(index));
    memset(digest, 0, sizeof(digest)); memset(terminal_file, 0, sizeof(terminal_file));
    memset(prepared_file, 0, sizeof(prepared_file)); memset(index_file, 0, sizeof(index_file));
    memset(&existing_completion, 0, sizeof(existing_completion));
    return result;
}

int
plamen_broker_v2_specialized_effect_store_lookup_terminal(
    struct plamen_broker_v2_specialized_effect_store *store,
    const uint8_t terminal_sha256[32],
    struct plamen_broker_v2_specialized_effect_completion *completion,
    uint8_t **terminal, size_t *terminal_size)
{
    uint8_t *record = NULL; struct stat info; char name[96]; int fd = -1, result = -1;
    if (terminal != NULL) *terminal = NULL; if (terminal_size != NULL) *terminal_size = 0;
    memset(name, 0, sizeof(name));
    if (store == NULL || store->magic != STORE_MAGIC || terminal_sha256 == NULL
        || zero32(terminal_sha256) || completion == NULL || terminal == NULL
        || terminal_size == NULL || terminal_name(terminal_sha256, name) != 0)
        return -1;
    if (fstatat(store->directory_fd, name, &info, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT)
            return PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_NOT_FOUND;
        return PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_INVALID;
    }
    fd = openat(store->directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &info) != 0 || info.st_size <= 0
        || (uint64_t)info.st_size > TERMINAL_HEADER_SIZE
            + PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_TERMINAL_MAX
            + TERMINAL_TRAILER_SIZE
        || !exact_file(fd, (size_t)info.st_size))
        goto done;
    record = malloc((size_t)info.st_size);
    if (record == NULL || read_all(fd, record, (size_t)info.st_size) != 0
        || decode_terminal_record(record, (size_t)info.st_size,
            store->runtime_authority_sha256, completion, terminal,
            terminal_size) != 0
        || !equal(completion->terminal_sha256, terminal_sha256, 32)
        || !completion_terminal_hmac_valid(store, completion,
            *terminal, *terminal_size))
        goto done;
    result = 0;
done:
    if (fd >= 0) (void)close(fd);
    if (record != NULL) { memset(record, 0, (size_t)info.st_size); free(record); }
    memset(name, 0, sizeof(name)); return result;
}

int
plamen_broker_v2_specialized_effect_store_lookup_operation(
    struct plamen_broker_v2_specialized_effect_store *store,
    const uint8_t operation_key[32], const uint8_t request_sha256[32],
    struct plamen_broker_v2_specialized_effect_completion *completion,
    uint8_t **terminal, size_t *terminal_size)
{
    uint8_t *index = NULL, digest[32]; char name[96]; struct stat information;
    int result = -1;
    if (terminal != NULL) *terminal = NULL; if (terminal_size != NULL) *terminal_size = 0;
    memset(digest, 0, sizeof(digest)); memset(name, 0, sizeof(name));
    if (store == NULL || store->magic != STORE_MAGIC || operation_key == NULL
        || request_sha256 == NULL || completion == NULL || terminal == NULL
        || terminal_size == NULL || zero32(operation_key) || zero32(request_sha256)
        || index_name(operation_key, name) != 0)
        return PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_INVALID;
    if (fstatat(store->directory_fd, name, &information,
            AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT)
            return PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_NOT_FOUND;
        return PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_INVALID;
    }
    if (read_named(store->directory_fd, name, INDEX_SIZE, &index) != 0
        || memcmp(index, index_magic, 8) != 0 || get32(index + 8) != 1U
        || get32(index + 12) != INDEX_SIZE
        || !equal(index + 24, operation_key, 32)
        || !equal(index + 56, request_sha256, 32)
        || !equal(index + 88, store->runtime_authority_sha256, 32)
        || hash(index, 224, digest) != 0 || !equal(digest, index + 224, 32)
        || plamen_broker_v2_specialized_effect_store_lookup_terminal(store,
            index + 120, completion, terminal, terminal_size) != 0
        || !equal(completion->operation_key, operation_key, 32)
        || !equal(completion->request_sha256, request_sha256, 32)
        || completion->lane != get16(index + 16)
        || completion->method != get16(index + 18)
        || completion->flags != get32(index + 20)
        || !equal(completion->worker_request_sha256, index + 152, 32)
        || !equal(completion->lifecycle_receipt_sha256, index + 184, 32))
        goto done;
    result = 0;
done:
    if (result != 0 && terminal != NULL && *terminal != NULL) {
        memset(*terminal, 0, *terminal_size); free(*terminal); *terminal = NULL;
        *terminal_size = 0;
    }
    if (index != NULL) { memset(index, 0, INDEX_SIZE); free(index); }
    memset(digest, 0, sizeof(digest)); memset(name, 0, sizeof(name));
    if (result != 0 && completion != NULL) memset(completion, 0, sizeof(*completion));
    return result;
}

void
plamen_broker_v2_specialized_effect_store_close(
    struct plamen_broker_v2_specialized_effect_store *store)
{
    if (store == NULL) return;
    if (store->directory_fd >= 0) (void)close(store->directory_fd);
    memset(store, 0, sizeof(*store)); free(store);
}
