#define _DARWIN_C_SOURCE 1

#include "plamen_native_fixed_role_acquisition_v1.h"
#include "plamen_native_operation4_helper_v1.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define POLICY_MAX_SIZE (128ULL * 1024ULL)
#define COPY_BLOCK_SIZE (1024U * 1024U)

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

static const uint16_t fixed_roles[
    PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT] = {
    PLAMEN_SOURCE_BOOTSTRAP_BASE_ROOTFS_V1,
    PLAMEN_SOURCE_BOOTSTRAP_DEBIAN_PACKAGE_STATE_V1,
    PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_GUEST_V1,
    PLAMEN_SOURCE_BOOTSTRAP_CPYTHON_V1,
    PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_PACKAGE_V1,
    PLAMEN_SOURCE_BOOTSTRAP_FOUNDRY_V1,
    PLAMEN_SOURCE_BOOTSTRAP_AMD64_COMPAT_V1
};

static const char *const role_names[
    PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT] = {
    "base_rootfs", "debian_package_state", "plamen_guest", "cpython",
    "plamen_package", "codex", "claude", "foundry", "medusa",
    "solc_amd64", "amd64_compat"
};

static const uint8_t footer_magic[8] = {
    'P', 'L', 'M', 'O', 'P', '4', 'R', '1'
};

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

static int nonzero(const uint8_t *value, size_t size)
{
    uint8_t aggregate = 0U;
    size_t index;
    for (index = 0U; index < size; ++index) aggregate |= value[index];
    return aggregate != 0U;
}

static int sha256_fd(int descriptor, uint64_t size, uint8_t output[32])
{
    CC_SHA256_CTX context;
    uint8_t buffer[COPY_BLOCK_SIZE];
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
    uint64_t maximum, int require_nonempty, struct retained_identity_v1 *identity)
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
            || (require_nonempty && before.st_size == 0)
            || sha256_fd(descriptor, (uint64_t)before.st_size,
                identity->sha256) != 0
            || fstat(descriptor, &after) != 0
            || before.st_dev != after.st_dev || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode || before.st_uid != after.st_uid
            || before.st_gid != after.st_gid || before.st_nlink != after.st_nlink
            || before.st_size != after.st_size
            || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
            || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
            || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec
            || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec) {
        memset(identity, 0, sizeof(*identity));
        errno = EINVAL;
        return -1;
    }
    identity->device = before.st_dev;
    identity->inode = before.st_ino;
    identity->mode = before.st_mode;
    identity->uid = before.st_uid;
    identity->gid = before.st_gid;
    identity->links = before.st_nlink;
    identity->size = before.st_size;
    identity->mtime = before.st_mtimespec;
    identity->ctime = before.st_ctimespec;
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

static int private_root(int descriptor, uid_t owner)
{
    struct stat info;
    int flags, descriptor_flags;
    return descriptor >= 3
        && (flags = fcntl(descriptor, F_GETFL)) >= 0
        && (descriptor_flags = fcntl(descriptor, F_GETFD)) >= 0
        && (flags & O_ACCMODE) == O_RDONLY
        && (descriptor_flags & FD_CLOEXEC) != 0
        && fstat(descriptor, &info) == 0 && S_ISDIR(info.st_mode)
        && info.st_uid == owner && info.st_nlink >= 1
        && (info.st_mode & 0077U) == 0U;
}

static int open_authority_directory(int root, uid_t owner)
{
    const char *parts[3] = {"share", "plamen", "native-source-authority-v1"};
    int current = fcntl(root, F_DUPFD_CLOEXEC, 3), next = -1;
    struct stat info;
    size_t index;
    if (current < 0) return -1;
    for (index = 0U; index < 3U; ++index) {
        if (mkdirat(current, parts[index], 0700) != 0 && errno != EEXIST)
            goto fail;
        next = openat(current, parts[index],
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 || fstat(next, &info) != 0 || !S_ISDIR(info.st_mode)
                || info.st_uid != owner || info.st_nlink < 1
                || (info.st_mode & 0077U) != 0U) goto fail;
        close(current);
        current = next;
        next = -1;
    }
    return current;
fail:
    if (next >= 0) close(next);
    close(current);
    return -1;
}

static int expected_mode(uint16_t role)
{
    return role == PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_GUEST_V1
            || role == PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_PACKAGE_V1
        ? PLAMEN_NATIVE_OPERATION4_FROZEN_SOURCE_PROJECTION_V1
        : PLAMEN_NATIVE_OPERATION4_STATIC_PAYLOAD_V1;
}

static int expected_validator(uint16_t role)
{
    switch (role) {
    case PLAMEN_SOURCE_BOOTSTRAP_BASE_ROOTFS_V1:
    case PLAMEN_SOURCE_BOOTSTRAP_DEBIAN_PACKAGE_STATE_V1:
        return PLAMEN_NATIVE_OPERATION4_DEBIAN_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_GUEST_V1:
    case PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_PACKAGE_V1:
        return PLAMEN_NATIVE_OPERATION4_PLAMEN_SOURCE_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_CPYTHON_V1:
        return PLAMEN_NATIVE_OPERATION4_CPYTHON_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_FOUNDRY_V1:
        return PLAMEN_NATIVE_OPERATION4_FOUNDRY_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_AMD64_COMPAT_V1:
        return PLAMEN_NATIVE_OPERATION4_AMD64_COMPAT_RECEIPT_V1;
    default:
        return 0;
    }
}

static int exact_ascii_field(const char *value, size_t capacity)
{
    size_t index;
    int ended = 0;
    if (capacity == 0U || value[0] == '\0') return 0;
    for (index = 0U; index < capacity; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (ended) {
            if (byte != 0U) return 0;
        } else if (byte == 0U) {
            ended = 1;
        } else if (byte < 0x21U || byte > 0x7eU) {
            return 0;
        }
    }
    return ended;
}

static int validate_row(uint16_t role,
    const struct plamen_native_operation4_policy_row_v1 **output)
{
    const struct plamen_native_operation4_fixed_policy_v1 *fixed =
        &plamen_native_operation4_generated_policy_v1;
    const struct plamen_native_operation4_policy_row_v1 *row;
    if (output == NULL || role >= fixed->role_count || fixed->version != 1U
            || fixed->role_count
                != PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT
            || !nonzero(fixed->roster_sha256, 32U)) return -1;
    row = &fixed->rows[role];
    if (row->role != role || row->reserved != 0U
            || row->identity_mode != expected_mode(role)
            || row->receipt_validator != expected_validator(role)
            || row->payload_size == 0U || row->source_manifest_size == 0U
            || row->semantic_receipt_size == 0U
            || row->semantic_receipt_size
                > PLAMEN_NATIVE_OPERATION4_PRODUCER_RECEIPT_MAX
                    - PLAMEN_NATIVE_OPERATION4_PRODUCER_FOOTER_V1_SIZE
            || !nonzero(row->policy_sha256, 32U)
            || !nonzero(row->payload_sha256, 32U)
            || !nonzero(row->source_manifest_sha256, 32U)
            || !nonzero(row->semantic_receipt_sha256, 32U)
            || !exact_ascii_field(row->receipt_schema,
                sizeof(row->receipt_schema))) return -1;
    *output = row;
    return 0;
}

static void render_footer(
    const struct plamen_native_operation4_policy_row_v1 *row,
    uint8_t footer[PLAMEN_NATIVE_OPERATION4_PRODUCER_FOOTER_V1_SIZE])
{
    size_t schema_size = strlen(row->receipt_schema);
    memset(footer, 0, PLAMEN_NATIVE_OPERATION4_PRODUCER_FOOTER_V1_SIZE);
    memcpy(footer, footer_magic, sizeof(footer_magic));
    store16(footer + 8U, 1U);
    store16(footer + 10U,
        PLAMEN_NATIVE_OPERATION4_PRODUCER_FOOTER_V1_SIZE);
    store16(footer + 12U, row->role);
    store16(footer + 14U, row->identity_mode);
    store16(footer + 16U, row->receipt_validator);
    store64(footer + 20U, row->payload_size);
    store64(footer + 28U, row->source_manifest_size);
    store64(footer + 36U, row->semantic_receipt_size);
    memcpy(footer + 44U, row->policy_sha256, 32U);
    memcpy(footer + 76U, row->payload_sha256, 32U);
    memcpy(footer + 108U, row->source_manifest_sha256, 32U);
    memcpy(footer + 140U, row->semantic_receipt_sha256, 32U);
    memcpy(footer + 172U, row->receipt_schema, schema_size);
    (void)CC_SHA256(footer, 480U, footer + 480U);
}

static int write_all(int descriptor, const uint8_t *bytes, size_t size)
{
    size_t consumed = 0U;
    while (consumed < size) {
        ssize_t amount = write(descriptor, bytes + consumed, size - consumed);
        if (amount <= 0) return -1;
        consumed += (size_t)amount;
    }
    return 0;
}

static int copy_exact(int source, uint64_t size, int destination,
    CC_SHA256_CTX *receipt_hash)
{
    uint8_t buffer[COPY_BLOCK_SIZE];
    uint64_t offset = 0U;
    int result = -1;
    while (offset < size) {
        size_t wanted = size - offset > sizeof(buffer)
            ? sizeof(buffer) : (size_t)(size - offset);
        ssize_t amount = pread(source, buffer, wanted, (off_t)offset);
        if (amount != (ssize_t)wanted || write_all(destination, buffer, wanted) != 0
                || (receipt_hash != NULL
                    && CC_SHA256_Update(receipt_hash, buffer,
                        (CC_LONG)wanted) != 1)) goto done;
        offset += wanted;
    }
    result = 0;
done:
    memset(buffer, 0, sizeof(buffer));
    return result;
}

static int make_leaf(int directory, const char *name)
{
    return openat(directory, name,
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
}

static int publish_leaf(int directory, const char *name, int *writer,
    uid_t owner, uint64_t size, const uint8_t digest[32], int *reader,
    struct retained_identity_v1 *published)
{
    struct retained_identity_v1 before, after;
    int result = -1;
    if (writer == NULL || *writer < 0 || reader == NULL || published == NULL
            || fsync(*writer) != 0 || fchmod(*writer, 0400U) != 0
            || fsync(*writer) != 0
            || identity_from_fd(*writer, owner, O_RDWR, size, 1, &before) != 0
            || (uint64_t)before.size != size
            || !constant_equal(before.sha256, digest, 32U)) return -1;
    if (close(*writer) != 0) { *writer = -1; return -1; }
    *writer = -1;
    *reader = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (*reader < 0
            || identity_from_fd(*reader, owner, O_RDONLY, size, 1, &after) != 0
            || (uint64_t)after.size != size || (after.mode & 07777U) != 0400U
            || !constant_equal(after.sha256, digest, 32U)
            || !same_identity(&before, &after)) goto done;
    *published = after;
    result = 0;
done:
    if (result != 0 && *reader >= 0) {
        close(*reader);
        *reader = -1;
    }
    return result;
}

static void leaf_names(uint16_t role, char payload[64], char producer[64],
    char manifest[64])
{
    (void)snprintf(payload, 64U, "%02u-%s.payload", role, role_names[role]);
    (void)snprintf(producer, 64U, "%02u-%s.producer-receipt", role,
        role_names[role]);
    (void)snprintf(manifest, 64U, "%02u-%s.source-manifest", role,
        role_names[role]);
}

static void projection_reset(struct plamen_native_fixed_role_projection_v1 *value)
{
    size_t index;
    memset(value, 0, sizeof(*value));
    for (index = 0U;
            index < PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT;
            ++index) {
        value->roles[index].role = fixed_roles[index];
        value->roles[index].payload_fd = -1;
        value->roles[index].producer_receipt_fd = -1;
        value->roles[index].source_manifest_fd = -1;
    }
}

int plamen_native_fixed_role_acquisition_issue_v1(uid_t owner, int root_fd,
    const struct plamen_native_fixed_role_input_v1 inputs[
        PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT],
    struct plamen_native_fixed_role_projection_v1 *projection)
{
    enum { INPUTS_PER_ROLE = 4, OUTPUTS_PER_ROLE = 3 };
    struct retained_identity_v1 before[
        PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT * INPUTS_PER_ROLE];
    struct retained_identity_v1 after[
        PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT * INPUTS_PER_ROLE];
    const struct plamen_native_operation4_policy_row_v1 *rows[
        PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT];
    int writers[
        PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT * OUTPUTS_PER_ROLE];
    int directory = -1;
    size_t index, inner, created = 0U;
    int result = -1;
    uint8_t footer[PLAMEN_NATIVE_OPERATION4_PRODUCER_FOOTER_V1_SIZE];
    char names[
        PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT * OUTPUTS_PER_ROLE][64];
    if (projection == NULL) { errno = EINVAL; return -1; }
    projection_reset(projection);
    memset(before, 0, sizeof(before));
    memset(after, 0, sizeof(after));
    memset(rows, 0, sizeof(rows));
    memset(writers, 0xff, sizeof(writers));
    memset(footer, 0, sizeof(footer));
    memset(names, 0, sizeof(names));
    if (inputs == NULL || owner != getuid() || !private_root(root_fd, owner))
        goto done;

    for (index = 0U;
            index < PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT;
            ++index) {
        const struct plamen_native_fixed_role_input_v1 *input = &inputs[index];
        const int descriptors[INPUTS_PER_ROLE] = {
            input->payload_fd, input->semantic_receipt_fd,
            input->source_manifest_fd, input->reviewed_policy_fd
        };
        uint64_t maxima[INPUTS_PER_ROLE];
        const uint8_t *digests[INPUTS_PER_ROLE];
        if (input->role != fixed_roles[index] || input->reserved != 0U
                || validate_row(input->role, &rows[index]) != 0) goto done;
        maxima[0] = rows[index]->payload_size;
        maxima[1] = rows[index]->semantic_receipt_size;
        maxima[2] = rows[index]->source_manifest_size;
        maxima[3] = POLICY_MAX_SIZE;
        digests[0] = rows[index]->payload_sha256;
        digests[1] = rows[index]->semantic_receipt_sha256;
        digests[2] = rows[index]->source_manifest_sha256;
        digests[3] = rows[index]->policy_sha256;
        for (inner = 0U; inner < INPUTS_PER_ROLE; ++inner) {
            struct retained_identity_v1 *identity =
                &before[index * INPUTS_PER_ROLE + inner];
            size_t prior;
            if (identity_from_fd(descriptors[inner], owner, O_RDONLY,
                    maxima[inner], 1, identity) != 0
                    || (inner < 3U
                        && (uint64_t)identity->size != maxima[inner])
                    || !constant_equal(identity->sha256, digests[inner], 32U))
                goto done;
            for (prior = 0U; prior < index * INPUTS_PER_ROLE + inner; ++prior)
                if (same_vnode(identity, &before[prior])) {
                    errno = EINVAL;
                    goto done;
                }
        }
        leaf_names(input->role, names[index * 3U], names[index * 3U + 1U],
            names[index * 3U + 2U]);
    }

    directory = open_authority_directory(root_fd, owner);
    if (directory < 0) goto done;
    for (index = 0U;
            index < PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT * 3U;
            ++index) {
        writers[index] = make_leaf(directory, names[index]);
        if (writers[index] < 0) goto done;
        created = index + 1U;
    }

    for (index = 0U;
            index < PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT;
            ++index) {
        const struct plamen_native_fixed_role_input_v1 *input = &inputs[index];
        const struct plamen_native_operation4_policy_row_v1 *row = rows[index];
        struct plamen_native_fixed_role_projection_row_v1 *output =
            &projection->roles[index];
        struct retained_identity_v1 ignored;
        CC_SHA256_CTX receipt_hash;
        uint8_t receipt_digest[32];
        if (copy_exact(input->payload_fd, row->payload_size,
                writers[index * 3U], NULL) != 0
                || CC_SHA256_Init(&receipt_hash) != 1
                || copy_exact(input->semantic_receipt_fd,
                    row->semantic_receipt_size, writers[index * 3U + 1U],
                    &receipt_hash) != 0) {
            memset(&receipt_hash, 0, sizeof(receipt_hash));
            goto done;
        }
        render_footer(row, footer);
        if (write_all(writers[index * 3U + 1U], footer, sizeof(footer)) != 0
                || CC_SHA256_Update(&receipt_hash, footer,
                    (CC_LONG)sizeof(footer)) != 1
                || CC_SHA256_Final(receipt_digest, &receipt_hash) != 1
                || copy_exact(input->source_manifest_fd,
                    row->source_manifest_size, writers[index * 3U + 2U],
                    NULL) != 0) {
            memset(&receipt_hash, 0, sizeof(receipt_hash));
            memset(receipt_digest, 0, sizeof(receipt_digest));
            goto done;
        }
        memset(&receipt_hash, 0, sizeof(receipt_hash));
        if (publish_leaf(directory, names[index * 3U], &writers[index * 3U],
                owner, row->payload_size, row->payload_sha256,
                &output->payload_fd, &ignored) != 0
                || publish_leaf(directory, names[index * 3U + 1U],
                    &writers[index * 3U + 1U], owner,
                    row->semantic_receipt_size + sizeof(footer), receipt_digest,
                    &output->producer_receipt_fd, &ignored) != 0
                || publish_leaf(directory, names[index * 3U + 2U],
                    &writers[index * 3U + 2U], owner,
                    row->source_manifest_size, row->source_manifest_sha256,
                    &output->source_manifest_fd, &ignored) != 0) {
            memset(receipt_digest, 0, sizeof(receipt_digest));
            goto done;
        }
        output->payload_size = row->payload_size;
        output->producer_receipt_size =
            row->semantic_receipt_size + sizeof(footer);
        output->source_manifest_size = row->source_manifest_size;
        memcpy(output->policy_sha256, row->policy_sha256, 32U);
        memcpy(output->payload_sha256, row->payload_sha256, 32U);
        memcpy(output->producer_receipt_sha256, receipt_digest, 32U);
        memcpy(output->source_manifest_sha256,
            row->source_manifest_sha256, 32U);
        memset(receipt_digest, 0, sizeof(receipt_digest));
    }
    if (fsync(directory) != 0) goto done;

    for (index = 0U;
            index < PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT;
            ++index) {
        const struct plamen_native_fixed_role_input_v1 *input = &inputs[index];
        const int descriptors[INPUTS_PER_ROLE] = {
            input->payload_fd, input->semantic_receipt_fd,
            input->source_manifest_fd, input->reviewed_policy_fd
        };
        uint64_t maxima[INPUTS_PER_ROLE] = {
            rows[index]->payload_size, rows[index]->semantic_receipt_size,
            rows[index]->source_manifest_size, POLICY_MAX_SIZE
        };
        for (inner = 0U; inner < INPUTS_PER_ROLE; ++inner) {
            size_t offset = index * INPUTS_PER_ROLE + inner;
            if (identity_from_fd(descriptors[inner], owner, O_RDONLY,
                    maxima[inner], 1, &after[offset]) != 0
                    || !same_identity(&before[offset], &after[offset]))
                goto done;
        }
    }
    result = 0;
done:
    if (result != 0) {
        plamen_native_fixed_role_projection_dispose_v1(projection);
        if (directory >= 0) {
            for (index = 0U; index < created; ++index)
                (void)unlinkat(directory, names[index], 0);
            (void)fsync(directory);
        }
    }
    for (index = 0U;
            index < PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT * 3U;
            ++index)
        if (writers[index] >= 0) close(writers[index]);
    if (directory >= 0) close(directory);
    memset(before, 0, sizeof(before));
    memset(after, 0, sizeof(after));
    memset(rows, 0, sizeof(rows));
    memset(footer, 0, sizeof(footer));
    memset(names, 0, sizeof(names));
    return result;
}

void plamen_native_fixed_role_projection_dispose_v1(
    struct plamen_native_fixed_role_projection_v1 *projection)
{
    size_t index;
    if (projection == NULL) return;
    for (index = 0U;
            index < PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT;
            ++index) {
        if (projection->roles[index].payload_fd >= 0)
            close(projection->roles[index].payload_fd);
        if (projection->roles[index].producer_receipt_fd >= 0)
            close(projection->roles[index].producer_receipt_fd);
        if (projection->roles[index].source_manifest_fd >= 0)
            close(projection->roles[index].source_manifest_fd);
    }
    projection_reset(projection);
}
