#include "plamen_native_backend_receipt_signer_v1.h"
#include "plamen_native_operation4_helper_v1.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SIGNED_GROWTH_MAX 1024U
#define SOURCE_MANIFEST_MAX (64U * 1024U * 1024U)
#define PAYLOAD_MAX (8ULL * 1024ULL * 1024ULL * 1024ULL)

extern int32_t plamen_native_backend_crypto_create_v1(void **context,
    uint8_t *public_output, intptr_t public_capacity);
extern int32_t plamen_native_backend_crypto_sign_receipt_v1(void *context,
    uint16_t role, const uint8_t *unsigned_bytes, intptr_t unsigned_size,
    const uint8_t payload_sha256[32], uint64_t payload_size,
    const uint8_t manifest_sha256[32], uint64_t manifest_size,
    const uint8_t policy_sha256[32], uint8_t *output,
    intptr_t output_capacity, intptr_t *output_size,
    char *resolved_version, intptr_t resolved_version_capacity);
extern void plamen_native_backend_crypto_dispose_v1(void *context);

struct retained_identity_v1 {
    dev_t device;
    ino_t inode;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    nlink_t links;
    off_t size;
    struct timespec mtime;
    struct timespec ctime;
    uint8_t sha256[32];
};

struct plamen_native_backend_receipt_signer_v1 {
    uid_t owner_uid;
    void *crypto_context;
    int public_key_fd;
    struct retained_identity_v1 public_key_identity;
    uint8_t public_key_sha256[32];
    uint8_t issued_mask;
    pthread_mutex_t lock;
    int lock_ready;
};

static const uint8_t footer_magic[8] = {
    'P','L','M','O','P','4','R','1'
};
static const char backend_schema[] =
    "plamen.native-backend-latest-acquisition-receipt.v1";

static void store16(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)(value >> 8U);
    output[1] = (uint8_t)value;
}

static void store64(uint8_t *output, uint64_t value)
{
    size_t index;
    for (index = 0U; index < 8U; ++index)
        output[index] = (uint8_t)(value >> (56U - 8U * index));
}

static int constant_equal(const uint8_t *left, const uint8_t *right,
    size_t size)
{
    uint8_t difference = 0U;
    size_t index;
    for (index = 0U; index < size; ++index)
        difference |= (uint8_t)(left[index] ^ right[index]);
    return difference == 0U;
}

static int all_zero(const uint8_t *value, size_t size)
{
    uint8_t aggregate = 0U;
    size_t index;
    for (index = 0U; index < size; ++index) aggregate |= value[index];
    return aggregate == 0U;
}

static int duplicate_cloexec(int descriptor)
{
    if (descriptor < 3) { errno = EBADF; return -1; }
    return fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
}

static int sha256_fd(int descriptor, uint64_t size, uint8_t output[32])
{
    CC_SHA256_CTX context;
    uint8_t buffer[1024U * 1024U];
    uint64_t offset = 0U;
    int result = -1;
    if (CC_SHA256_Init(&context) != 1) goto done;
    while (offset < size) {
        size_t wanted = size - offset > sizeof(buffer)
            ? sizeof(buffer) : (size_t)(size - offset);
        ssize_t amount = pread(descriptor, buffer, wanted, (off_t)offset);
        if (amount != (ssize_t)wanted
                || CC_SHA256_Update(&context, buffer, (CC_LONG)wanted) != 1)
            goto done;
        offset += wanted;
    }
    if (CC_SHA256_Final(output, &context) != 1) goto done;
    result = 0;
done:
    memset(buffer, 0, sizeof(buffer));
    memset(&context, 0, sizeof(context));
    if (result != 0) memset(output, 0, 32U);
    return result;
}

static int identity_from_fd(int descriptor, uid_t owner, int access,
    uint64_t maximum, int require_nonempty,
    struct retained_identity_v1 *identity)
{
    struct stat before, after;
    int flags, descriptor_flags;
    if (identity == NULL) return -1;
    memset(identity, 0, sizeof(*identity));
    if (descriptor < 3 || (flags = fcntl(descriptor, F_GETFL)) < 0
            || (descriptor_flags = fcntl(descriptor, F_GETFD)) < 0
            || (flags & O_ACCMODE) != access
            || (descriptor_flags & FD_CLOEXEC) == 0
            || fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode)
            || before.st_uid != owner || before.st_nlink != 1
            || (before.st_mode & 0022U) != 0U || before.st_size < 0
            || (uint64_t)before.st_size > maximum
            || (require_nonempty && before.st_size == 0)) return -1;
    identity->device = before.st_dev; identity->inode = before.st_ino;
    identity->mode = before.st_mode; identity->uid = before.st_uid;
    identity->gid = before.st_gid; identity->links = before.st_nlink;
    identity->size = before.st_size; identity->mtime = before.st_mtimespec;
    identity->ctime = before.st_ctimespec;
    if (sha256_fd(descriptor, (uint64_t)before.st_size,
            identity->sha256) != 0 || fstat(descriptor, &after) != 0
            || before.st_dev != after.st_dev || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode || before.st_uid != after.st_uid
            || before.st_gid != after.st_gid || before.st_nlink != after.st_nlink
            || before.st_size != after.st_size
            || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
            || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
            || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec
            || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec) {
        memset(identity, 0, sizeof(*identity)); return -1;
    }
    return 0;
}

static int same_identity(const struct retained_identity_v1 *left,
    const struct retained_identity_v1 *right)
{
    return left->device == right->device && left->inode == right->inode
        && left->mode == right->mode && left->uid == right->uid
        && left->gid == right->gid && left->links == right->links
        && left->size == right->size
        && left->mtime.tv_sec == right->mtime.tv_sec
        && left->mtime.tv_nsec == right->mtime.tv_nsec
        && left->ctime.tv_sec == right->ctime.tv_sec
        && left->ctime.tv_nsec == right->ctime.tv_nsec
        && constant_equal(left->sha256, right->sha256, 32U);
}

static int same_vnode(const struct retained_identity_v1 *left,
    const struct retained_identity_v1 *right)
{
    return left->device == right->device && left->inode == right->inode;
}

static int writable_handle_count_exact(int descriptor, unsigned int expected)
{
    struct stat target, candidate;
    int limit, current;
    unsigned int count = 0U;
    if (fstat(descriptor, &target) != 0
            || (limit = getdtablesize()) <= 0) return -1;
    for (current = 0; current < limit; ++current) {
        int flags;
        if (fstat(current, &candidate) != 0
                || candidate.st_dev != target.st_dev
                || candidate.st_ino != target.st_ino) continue;
        flags = fcntl(current, F_GETFL);
        if (flags >= 0 && (flags & O_ACCMODE) != O_RDONLY) ++count;
    }
    return count == expected ? 0 : -1;
}

static int write_all_at(int descriptor, const uint8_t *bytes, size_t size,
    off_t offset)
{
    size_t consumed = 0U;
    while (consumed < size) {
        ssize_t amount = pwrite(descriptor, bytes + consumed,
            size - consumed, offset + (off_t)consumed);
        if (amount <= 0) return -1;
        consumed += (size_t)amount;
    }
    return 0;
}

static int read_all(int descriptor, uint64_t size, uint8_t *output)
{
    uint64_t offset = 0U;
    while (offset < size) {
        size_t wanted = size - offset > 1024U * 1024U
            ? 1024U * 1024U : (size_t)(size - offset);
        ssize_t amount = pread(descriptor, output + offset, wanted,
            (off_t)offset);
        if (amount != (ssize_t)wanted) return -1;
        offset += wanted;
    }
    return 0;
}

static int policy_row_for_role(uint16_t role,
    const struct plamen_native_operation4_policy_row_v1 **row)
{
    const struct plamen_native_operation4_fixed_policy_v1 *policy =
        &plamen_native_operation4_generated_policy_v1;
    const struct plamen_native_operation4_policy_row_v1 *candidate;
    if (row == NULL || (role != PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1
            && role != PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1)
            || policy->version != 1U
            || policy->role_count !=
                PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT
            || all_zero(policy->roster_sha256, 32U)) return -1;
    candidate = &policy->rows[role];
    if (candidate->role != role
            || candidate->identity_mode !=
                PLAMEN_NATIVE_OPERATION4_LATEST_BACKEND_RECEIPT_V1
            || candidate->receipt_validator !=
                PLAMEN_NATIVE_OPERATION4_BACKEND_RECEIPT_V1
            || candidate->reserved != 0U
            || candidate->payload_size != 0U
            || candidate->source_manifest_size != 0U
            || candidate->semantic_receipt_size != 0U
            || !all_zero(candidate->payload_sha256, 32U)
            || !all_zero(candidate->source_manifest_sha256, 32U)
            || !all_zero(candidate->semantic_receipt_sha256, 32U)
            || all_zero(candidate->policy_sha256, 32U)
            || strnlen(candidate->receipt_schema,
                sizeof(candidate->receipt_schema)) != strlen(backend_schema)
            || memcmp(candidate->receipt_schema, backend_schema,
                strlen(backend_schema)) != 0) return -1;
    *row = candidate;
    return 0;
}

static int publish_public_key(int writer, int reader, uid_t owner,
    const uint8_t public_key[32], struct retained_identity_v1 *identity)
{
    struct retained_identity_v1 writer_identity, reader_identity;
    int result = -1;
    if (identity_from_fd(writer, owner, O_RDWR, 32U, 0,
            &writer_identity) != 0
            || identity_from_fd(reader, owner, O_RDONLY, 32U, 0,
                &reader_identity) != 0
            || writer_identity.size != 0 || reader_identity.size != 0
            || !same_vnode(&writer_identity, &reader_identity)
            || writable_handle_count_exact(writer, 1U) != 0
            || ftruncate(writer, 0) != 0 || fchmod(writer, 0600U) != 0
            || write_all_at(writer, public_key, 32U, 0) != 0
            || fsync(writer) != 0 || fchmod(writer, 0400U) != 0
            || fsync(writer) != 0) goto done;
    if (close(writer) != 0) { writer = -1; goto done; }
    writer = -1;
    if (identity_from_fd(reader, owner, O_RDONLY, 32U, 1, identity) != 0
            || identity->size != 32U
            || (identity->mode & 07777U) != 0400U
            || writable_handle_count_exact(reader, 0U) != 0) goto done;
    result = 0;
done:
    if (writer >= 0) close(writer);
    return result;
}

int plamen_native_backend_receipt_signer_create_v1(uid_t owner_uid,
    int public_key_writer_fd, int public_key_reader_fd,
    struct plamen_native_backend_receipt_signer_v1 **output)
{
    struct plamen_native_backend_receipt_signer_v1 *signer = NULL;
    uint8_t public_key[32];
    int writer = public_key_writer_fd;
    int result = -1;
    memset(public_key, 0, sizeof(public_key));
    if (output != NULL) *output = NULL;
    if (output == NULL || owner_uid != getuid()) goto done;
    signer = calloc(1U, sizeof(*signer));
    if (signer == NULL) goto done;
    signer->public_key_fd = -1; signer->owner_uid = owner_uid;
    if (pthread_mutex_init(&signer->lock, NULL) != 0) goto done;
    signer->lock_ready = 1;
    if (plamen_native_backend_crypto_create_v1(&signer->crypto_context,
            public_key, (intptr_t)sizeof(public_key)) != 0
            || signer->crypto_context == NULL) goto done;
    {
        int publish_status = publish_public_key(writer, public_key_reader_fd,
            owner_uid, public_key, &signer->public_key_identity);
        writer = -1;
        if (publish_status != 0) goto done;
    }
    signer->public_key_fd = duplicate_cloexec(public_key_reader_fd);
    if (signer->public_key_fd < 0
            || identity_from_fd(signer->public_key_fd, owner_uid, O_RDONLY,
                32U, 1, &signer->public_key_identity) != 0) goto done;
    memcpy(signer->public_key_sha256,
        signer->public_key_identity.sha256, 32U);
    *output = signer; signer = NULL; result = 0;
done:
    if (writer >= 0) close(writer);
    memset(public_key, 0, sizeof(public_key));
    plamen_native_backend_receipt_signer_dispose_v1(signer);
    return result;
}

static void render_footer(uint8_t footer[512], uint16_t role,
    uint64_t payload_size, const uint8_t payload_sha256[32],
    uint64_t manifest_size, const uint8_t manifest_sha256[32],
    uint64_t semantic_size, const uint8_t semantic_sha256[32],
    const uint8_t policy_sha256[32], const char *version)
{
    memset(footer, 0, 512U); memcpy(footer, footer_magic, 8U);
    store16(footer + 8U, 1U); store16(footer + 10U, 512U);
    store16(footer + 12U, role);
    store16(footer + 14U,
        PLAMEN_NATIVE_OPERATION4_LATEST_BACKEND_RECEIPT_V1);
    store16(footer + 16U, PLAMEN_NATIVE_OPERATION4_BACKEND_RECEIPT_V1);
    store64(footer + 20U, payload_size);
    store64(footer + 28U, manifest_size);
    store64(footer + 36U, semantic_size);
    memcpy(footer + 44U, policy_sha256, 32U);
    memcpy(footer + 76U, payload_sha256, 32U);
    memcpy(footer + 108U, manifest_sha256, 32U);
    memcpy(footer + 140U, semantic_sha256, 32U);
    memcpy(footer + 172U, backend_schema, strlen(backend_schema));
    memcpy(footer + 268U, version, strlen(version));
    (void)CC_SHA256(footer, 480U, footer + 480U);
}

int plamen_native_backend_receipt_sign_v1(
    struct plamen_native_backend_receipt_signer_v1 *signer,
    uint16_t role, int unsigned_receipt_fd, int payload_fd,
    int source_manifest_fd, int semantic_writer_fd, int semantic_reader_fd,
    struct plamen_native_backend_signed_projection_v1 *projection)
{
    const struct plamen_native_operation4_policy_row_v1 *policy = NULL;
    struct retained_identity_v1 public_after, unsigned_before, unsigned_after;
    struct retained_identity_v1 payload_before, payload_after;
    struct retained_identity_v1 manifest_before, manifest_after;
    struct retained_identity_v1 writer_identity, reader_identity, final_identity;
    uint8_t *unsigned_bytes = NULL, *signed_bytes = NULL;
    uint8_t footer[512], semantic_sha256[32];
    char version[128];
    intptr_t signed_size = 0;
    size_t capacity = 0U;
    int writer = semantic_writer_fd;
    int locked = 0;
    int result = -1;
    if (projection != NULL) {
        memset(projection, 0, sizeof(*projection));
        projection->verifier_public_key_fd = -1;
        projection->semantic_receipt_fd = -1;
    }
    memset(footer, 0, sizeof(footer));
    memset(semantic_sha256, 0, sizeof(semantic_sha256));
    memset(version, 0, sizeof(version));
    if (signer == NULL || projection == NULL || signer->crypto_context == NULL)
        goto done;
    if (pthread_mutex_lock(&signer->lock) != 0) goto done;
    locked = 1;
    if (policy_row_for_role(role, &policy) != 0
            || (signer->issued_mask & (uint8_t)(1U << (role - 5U))) != 0U
            || identity_from_fd(signer->public_key_fd, signer->owner_uid,
                O_RDONLY, 32U, 1, &public_after) != 0
            || !same_identity(&public_after, &signer->public_key_identity)
            || identity_from_fd(unsigned_receipt_fd, signer->owner_uid,
                O_RDONLY, PLAMEN_NATIVE_BACKEND_RECEIPT_SIGNER_V1_MAX_UNSIGNED_SIZE,
                1, &unsigned_before) != 0
            || identity_from_fd(payload_fd, signer->owner_uid, O_RDONLY,
                PAYLOAD_MAX, 1, &payload_before) != 0
            || identity_from_fd(source_manifest_fd, signer->owner_uid,
                O_RDONLY, SOURCE_MANIFEST_MAX, 1, &manifest_before) != 0
            || identity_from_fd(writer, signer->owner_uid, O_RDWR,
                PLAMEN_NATIVE_OPERATION4_PRODUCER_RECEIPT_MAX, 0,
                &writer_identity) != 0
            || identity_from_fd(semantic_reader_fd, signer->owner_uid,
                O_RDONLY, PLAMEN_NATIVE_OPERATION4_PRODUCER_RECEIPT_MAX, 0,
                &reader_identity) != 0
            || writer_identity.size != 0 || reader_identity.size != 0
            || !same_vnode(&writer_identity, &reader_identity)
            || writable_handle_count_exact(writer, 1U) != 0) goto done;
    if ((uint64_t)unsigned_before.size > SIZE_MAX - SIGNED_GROWTH_MAX
            || (capacity = (size_t)unsigned_before.size
                + SIGNED_GROWTH_MAX) > INT_MAX) goto done;
    unsigned_bytes = malloc((size_t)unsigned_before.size);
    signed_bytes = malloc(capacity);
    if (unsigned_bytes == NULL || signed_bytes == NULL
            || read_all(unsigned_receipt_fd, (uint64_t)unsigned_before.size,
                unsigned_bytes) != 0
            || plamen_native_backend_crypto_sign_receipt_v1(
                signer->crypto_context, role, unsigned_bytes,
                (intptr_t)unsigned_before.size, payload_before.sha256,
                (uint64_t)payload_before.size, manifest_before.sha256,
                (uint64_t)manifest_before.size, policy->policy_sha256,
                signed_bytes, (intptr_t)capacity, &signed_size, version,
                (intptr_t)sizeof(version)) != 0
            || signed_size <= 0 || (size_t)signed_size > capacity
            || strnlen(version, sizeof(version)) == 0U
            || strnlen(version, sizeof(version)) == sizeof(version)
            || CC_SHA256(signed_bytes, (CC_LONG)signed_size,
                semantic_sha256) == NULL
            || identity_from_fd(unsigned_receipt_fd, signer->owner_uid,
                O_RDONLY, PLAMEN_NATIVE_BACKEND_RECEIPT_SIGNER_V1_MAX_UNSIGNED_SIZE,
                1, &unsigned_after) != 0
            || !same_identity(&unsigned_before, &unsigned_after)
            || identity_from_fd(payload_fd, signer->owner_uid, O_RDONLY,
                PAYLOAD_MAX, 1, &payload_after) != 0
            || !same_identity(&payload_before, &payload_after)
            || identity_from_fd(source_manifest_fd, signer->owner_uid,
                O_RDONLY, SOURCE_MANIFEST_MAX, 1, &manifest_after) != 0
            || !same_identity(&manifest_before, &manifest_after)) goto done;
    render_footer(footer, role, (uint64_t)payload_before.size,
        payload_before.sha256, (uint64_t)manifest_before.size,
        manifest_before.sha256, (uint64_t)signed_size, semantic_sha256,
        policy->policy_sha256, version);
    if (ftruncate(writer, 0) != 0 || fchmod(writer, 0600U) != 0
            || write_all_at(writer, signed_bytes, (size_t)signed_size, 0) != 0
            || write_all_at(writer, footer, sizeof(footer),
                (off_t)signed_size) != 0 || fsync(writer) != 0
            || fchmod(writer, 0400U) != 0 || fsync(writer) != 0) goto done;
    close(writer); writer = -1;
    if (identity_from_fd(semantic_reader_fd, signer->owner_uid, O_RDONLY,
            PLAMEN_NATIVE_OPERATION4_PRODUCER_RECEIPT_MAX, 1,
            &final_identity) != 0
            || final_identity.size != signed_size + (off_t)sizeof(footer)
            || (final_identity.mode & 07777U) != 0400U
            || writable_handle_count_exact(semantic_reader_fd, 0U) != 0)
        goto done;
    projection->verifier_public_key_fd = duplicate_cloexec(
        signer->public_key_fd);
    projection->semantic_receipt_fd = duplicate_cloexec(semantic_reader_fd);
    if (projection->verifier_public_key_fd < 0
            || projection->semantic_receipt_fd < 0) goto done;
    projection->role = role;
    projection->semantic_receipt_size = (uint64_t)final_identity.size;
    memcpy(projection->verifier_public_key_sha256,
        signer->public_key_sha256, 32U);
    memcpy(projection->semantic_receipt_sha256,
        final_identity.sha256, 32U);
    memcpy(projection->payload_sha256, payload_before.sha256, 32U);
    projection->payload_size = (uint64_t)payload_before.size;
    memcpy(projection->source_manifest_sha256,
        manifest_before.sha256, 32U);
    projection->source_manifest_size = (uint64_t)manifest_before.size;
    memcpy(projection->policy_sha256, policy->policy_sha256, 32U);
    signer->issued_mask |= (uint8_t)(1U << (role - 5U));
    result = 0;
done:
    if (writer >= 0) close(writer);
    if (result != 0)
        plamen_native_backend_signed_projection_dispose_v1(projection);
    if (unsigned_bytes != NULL) {
        memset(unsigned_bytes, 0, (size_t)unsigned_before.size);
        free(unsigned_bytes);
    }
    if (signed_bytes != NULL) { memset(signed_bytes, 0, capacity); free(signed_bytes); }
    memset(footer, 0, sizeof(footer));
    memset(semantic_sha256, 0, sizeof(semantic_sha256));
    memset(version, 0, sizeof(version));
    if (locked) (void)pthread_mutex_unlock(&signer->lock);
    return result;
}

void plamen_native_backend_signed_projection_dispose_v1(
    struct plamen_native_backend_signed_projection_v1 *projection)
{
    if (projection == NULL) return;
    if (projection->verifier_public_key_fd >= 0)
        close(projection->verifier_public_key_fd);
    if (projection->semantic_receipt_fd >= 0)
        close(projection->semantic_receipt_fd);
    memset(projection, 0, sizeof(*projection));
    projection->verifier_public_key_fd = -1;
    projection->semantic_receipt_fd = -1;
}

void plamen_native_backend_receipt_signer_dispose_v1(
    struct plamen_native_backend_receipt_signer_v1 *signer)
{
    if (signer == NULL) return;
    if (signer->public_key_fd >= 0) close(signer->public_key_fd);
    if (signer->crypto_context != NULL)
        plamen_native_backend_crypto_dispose_v1(signer->crypto_context);
    if (signer->lock_ready) (void)pthread_mutex_destroy(&signer->lock);
    memset(signer, 0, sizeof(*signer));
    free(signer);
}
