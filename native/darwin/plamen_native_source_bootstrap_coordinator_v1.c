#define _DARWIN_C_SOURCE 1

#include "plamen_native_source_bootstrap_coordinator_v1.h"

#include <CommonCrypto/CommonDigest.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc_info.h>
#endif
#ifdef PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_MAIN
#include "plamen_native_operation4_helper_v1.h"
#include "plamen_native_backend_receipt_signer_v1.h"
#include "plamen_native_evm_static_acquisition_v1.h"
#include "plamen_native_fixed_role_acquisition_v1.h"
#endif
#ifdef PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_TESTING
#include <stdio.h>
#define TEST_FAIL(label) do { fprintf(stderr, "coordinator:%s:%zu\n", \
    (label), index); goto done; } while (0)
#else
#define TEST_FAIL(label) do { goto done; } while (0)
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define RECEIPT_ROWS_OFFSET 512U
#define RECEIPT_OUTPUTS_OFFSET \
    (RECEIPT_ROWS_OFFSET + PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT \
        * PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROW_SIZE)
#define RECEIPT_TRAILER_OFFSET \
    (PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE - 32U)
#define SOURCE_MAX_BYTES (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define PRODUCER_RECEIPT_MAX_BYTES (1024ULL * 1024ULL)
#define SOURCE_MANIFEST_MAX_BYTES (1024ULL * 1024ULL)
#define COMPOSITION_MANIFEST_MAX_BYTES (4ULL * 1024ULL * 1024ULL)
#define OPERATION_RECEIPT_MAX_BYTES (4ULL * 1024ULL * 1024ULL)

static const uint8_t receipt_magic[8] = {
    'P', 'L', 'M', 'S', 'B', 'C', '1', 0
};
static const uint8_t acquisition_domain[] =
    "PLAMEN_NATIVE_RUNTIME_ACQUISITION_ROSTER_V1";
static const uint8_t output_domain[] =
    "PLAMEN_NATIVE_RUNTIME_OPERATION4_OUTPUT_ROSTER_V1";
static const uint8_t installed_authority_domain[] =
    "PLAMEN-NATIVE-INSTALLED-SOURCE-AUTHORITY-ROSTER-V1";
static const char *const source_roles[
    PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT] = {
    "base_rootfs", "debian_package_state", "plamen_guest", "cpython",
    "plamen_package", "codex", "claude", "foundry", "medusa",
    "solc_amd64", "amd64_compat"
};
static const char *const installed_member_paths[
    PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT] = {
    "share/plamen/native-source-authority-v1/00-base_rootfs.payload",
    "share/plamen/native-source-authority-v1/00-base_rootfs.producer-receipt",
    "share/plamen/native-source-authority-v1/00-base_rootfs.source-manifest",
    "share/plamen/native-source-authority-v1/01-debian_package_state.payload",
    "share/plamen/native-source-authority-v1/01-debian_package_state.producer-receipt",
    "share/plamen/native-source-authority-v1/01-debian_package_state.source-manifest",
    "share/plamen/native-source-authority-v1/02-plamen_guest.payload",
    "share/plamen/native-source-authority-v1/02-plamen_guest.producer-receipt",
    "share/plamen/native-source-authority-v1/02-plamen_guest.source-manifest",
    "share/plamen/native-source-authority-v1/03-cpython.payload",
    "share/plamen/native-source-authority-v1/03-cpython.producer-receipt",
    "share/plamen/native-source-authority-v1/03-cpython.source-manifest",
    "share/plamen/native-source-authority-v1/04-plamen_package.payload",
    "share/plamen/native-source-authority-v1/04-plamen_package.producer-receipt",
    "share/plamen/native-source-authority-v1/04-plamen_package.source-manifest",
    "share/plamen/native-source-authority-v1/05-codex.payload",
    "share/plamen/native-source-authority-v1/05-codex.producer-receipt",
    "share/plamen/native-source-authority-v1/05-codex.source-manifest",
    "share/plamen/native-source-authority-v1/06-claude.payload",
    "share/plamen/native-source-authority-v1/06-claude.producer-receipt",
    "share/plamen/native-source-authority-v1/06-claude.source-manifest",
    "share/plamen/native-source-authority-v1/07-foundry.payload",
    "share/plamen/native-source-authority-v1/07-foundry.producer-receipt",
    "share/plamen/native-source-authority-v1/07-foundry.source-manifest",
    "share/plamen/native-source-authority-v1/08-medusa.payload",
    "share/plamen/native-source-authority-v1/08-medusa.producer-receipt",
    "share/plamen/native-source-authority-v1/08-medusa.source-manifest",
    "share/plamen/native-source-authority-v1/09-solc_amd64.payload",
    "share/plamen/native-source-authority-v1/09-solc_amd64.producer-receipt",
    "share/plamen/native-source-authority-v1/09-solc_amd64.source-manifest",
    "share/plamen/native-source-authority-v1/10-amd64_compat.payload",
    "share/plamen/native-source-authority-v1/10-amd64_compat.producer-receipt",
    "share/plamen/native-source-authority-v1/10-amd64_compat.source-manifest"
};
struct plamen_source_bootstrap_authority_v1 {
    uid_t owner_uid;
    int producer_verifier_key_fd;
    int composition_manifest_fd;
    int payload_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT];
    int producer_receipt_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT];
    int source_manifest_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT];
    int output_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT];
    int operation4_terminal_receipt_fd;
    int coordinator_receipt_fd;
    struct plamen_source_bootstrap_receipt_v1 receipt;
};

struct plamen_source_bootstrap_installed_authority_v1 {
    uid_t owner_uid;
    int coordinator_receipt_fd;
    struct plamen_source_bootstrap_installed_binding_v1 binding;
    struct plamen_source_bootstrap_receipt_v1 receipt;
};

struct inode_key { uint64_t device; uint64_t inode; };

static int writable_handle_count_exact(int fd, unsigned int expected);

static void store16(uint8_t *out, uint16_t value)
{ out[0] = (uint8_t)(value >> 8U); out[1] = (uint8_t)value; }

static void store32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24U); out[1] = (uint8_t)(value >> 16U);
    out[2] = (uint8_t)(value >> 8U); out[3] = (uint8_t)value;
}

static void store64(uint8_t *out, uint64_t value)
{
    size_t index;
    for (index = 0U; index < 8U; ++index) {
        out[7U - index] = (uint8_t)value; value >>= 8U;
    }
}

static uint16_t load16(const uint8_t *in)
{ return (uint16_t)(((uint16_t)in[0] << 8U) | in[1]); }

static uint32_t load32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24U) | ((uint32_t)in[1] << 16U)
        | ((uint32_t)in[2] << 8U) | in[3];
}

static uint64_t load64(const uint8_t *in)
{ return ((uint64_t)load32(in) << 32U) | load32(in + 4U); }

static int all_zero(const uint8_t *value, size_t size)
{
    uint8_t aggregate = 0U; size_t index;
    if (value == NULL) return 1;
    for (index = 0U; index < size; ++index) aggregate |= value[index];
    return aggregate == 0U;
}

static int constant_equal(const uint8_t *left, const uint8_t *right,
    size_t size)
{
    uint8_t difference = 0U; size_t index;
    for (index = 0U; index < size; ++index)
        difference |= left[index] ^ right[index];
    return difference == 0U;
}

static int duplicate_cloexec(int fd)
{
#ifdef F_DUPFD_CLOEXEC
    return fcntl(fd, F_DUPFD_CLOEXEC, 3);
#else
    int copy = fcntl(fd, F_DUPFD, 3);
    if (copy >= 0 && fcntl(copy, F_SETFD, FD_CLOEXEC) != 0) {
        int saved = errno; close(copy); errno = saved; return -1;
    }
    return copy;
#endif
}

static int sha256_fd(int fd, uint64_t size, uint8_t output[32])
{
    CC_SHA256_CTX digest;
    uint8_t buffer[1024U * 1024U];
    uint64_t offset = 0U;
    int result = -1;
    if (CC_SHA256_Init(&digest) != 1) goto done;
    while (offset < size) {
        size_t wanted = (size - offset) > sizeof(buffer)
            ? sizeof(buffer) : (size_t)(size - offset);
        ssize_t amount = pread(fd, buffer, wanted, (off_t)offset);
        if (amount <= 0 || (size_t)amount != wanted
                || CC_SHA256_Update(&digest, buffer, (CC_LONG)wanted) != 1)
            goto done;
        offset += wanted;
    }
    if (CC_SHA256_Final(output, &digest) != 1) goto done;
    result = 0;
done:
    memset(buffer, 0, sizeof(buffer));
    memset(&digest, 0, sizeof(digest));
    if (result != 0 && output != NULL) memset(output, 0, 32U);
    return result;
}

static int identity_from_fd(int fd, uid_t owner, uint64_t maximum,
    int expected_access, int require_link, int require_nonempty,
    struct plamen_source_bootstrap_fd_identity_v1 *identity)
{
    struct stat before, after;
    int status, descriptor_flags;
    if (identity == NULL) return -1;
    memset(identity, 0, sizeof(*identity));
    if (fd < 3 || (status = fcntl(fd, F_GETFL)) < 0
            || (descriptor_flags = fcntl(fd, F_GETFD)) < 0
            || (status & O_ACCMODE) != expected_access
            || (descriptor_flags & FD_CLOEXEC) == 0
            || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
            || before.st_uid != owner || (before.st_mode & 0022U) != 0U
            || (require_link && before.st_nlink != 1)
            || before.st_size < 0 || (uint64_t)before.st_size > maximum
            || (require_nonempty && before.st_size == 0))
        return -1;
    identity->device = (uint64_t)before.st_dev;
    identity->inode = (uint64_t)before.st_ino;
    identity->mode = (uint32_t)before.st_mode;
    identity->uid = (uint32_t)before.st_uid;
    identity->gid = (uint32_t)before.st_gid;
    identity->links = (uint32_t)before.st_nlink;
    identity->size = (uint64_t)before.st_size;
    identity->mtime_seconds = (int64_t)before.st_mtimespec.tv_sec;
    identity->mtime_nanoseconds = (uint32_t)before.st_mtimespec.tv_nsec;
    identity->ctime_seconds = (int64_t)before.st_ctimespec.tv_sec;
    identity->ctime_nanoseconds = (uint32_t)before.st_ctimespec.tv_nsec;
    if (sha256_fd(fd, identity->size, identity->sha256) != 0
            || fstat(fd, &after) != 0
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

static int same_identity(
    const struct plamen_source_bootstrap_fd_identity_v1 *left,
    const struct plamen_source_bootstrap_fd_identity_v1 *right)
{
    return left->device == right->device && left->inode == right->inode
        && left->mode == right->mode && left->uid == right->uid
        && left->gid == right->gid && left->links == right->links
        && left->size == right->size
        && left->mtime_seconds == right->mtime_seconds
        && left->mtime_nanoseconds == right->mtime_nanoseconds
        && left->ctime_seconds == right->ctime_seconds
        && left->ctime_nanoseconds == right->ctime_nanoseconds
        && constant_equal(left->sha256, right->sha256, 32U);
}

static void encode_identity(uint8_t output[96],
    const struct plamen_source_bootstrap_fd_identity_v1 *identity)
{
    memset(output, 0, 96U);
    store64(output, identity->device); store64(output + 8U, identity->inode);
    store32(output + 16U, identity->mode); store32(output + 20U, identity->uid);
    store32(output + 24U, identity->gid); store32(output + 28U, identity->links);
    store64(output + 32U, identity->size);
    store64(output + 40U, (uint64_t)identity->mtime_seconds);
    store32(output + 48U, identity->mtime_nanoseconds);
    store64(output + 52U, (uint64_t)identity->ctime_seconds);
    store32(output + 60U, identity->ctime_nanoseconds);
    memcpy(output + 64U, identity->sha256, 32U);
}

const char *plamen_source_bootstrap_installed_member_relative_path_v1(
    uint16_t role, uint16_t kind)
{
    size_t index;
    if (role >= PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT
            || kind > PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_SOURCE_MANIFEST_V1)
        return NULL;
    index = (size_t)role * 3U + kind;
    return installed_member_paths[index];
}

int plamen_source_bootstrap_installed_authority_roster_sha256_v1(
    const struct plamen_source_bootstrap_receipt_v1 *receipt,
    uint8_t output[32])
{
    CC_SHA256_CTX digest;
    uint8_t scalar[8], identity[96];
    size_t member;
    if (receipt == NULL || output == NULL
            || CC_SHA256_Init(&digest) != 1
            || CC_SHA256_Update(&digest, installed_authority_domain,
                (CC_LONG)sizeof(installed_authority_domain)) != 1)
        return -1;
    memset(scalar, 0, sizeof(scalar));
    store16(scalar, PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT);
    if (CC_SHA256_Update(&digest, scalar, 2U) != 1) return -1;
    for (member = 0U;
            member < PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT;
            ++member) {
        uint16_t role = (uint16_t)(member / 3U);
        uint16_t kind = (uint16_t)(member % 3U);
        const char *path = installed_member_paths[member];
        size_t path_size = strlen(path);
        const struct plamen_source_bootstrap_fd_identity_v1 *source =
            kind == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PAYLOAD_V1
                ? &receipt->rows[role].payload
                : kind == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PRODUCER_RECEIPT_V1
                    ? &receipt->rows[role].producer_receipt
                    : &receipt->rows[role].source_manifest;
        if (path_size == 0U || path_size > UINT16_MAX
                || source->device == 0U || source->inode == 0U
                || source->links != 1U || source->size == 0U
                || all_zero(source->sha256, 32U)) return -1;
        memset(scalar, 0, sizeof(scalar));
        store16(scalar, (uint16_t)member);
        store16(scalar + 2U, role);
        store16(scalar + 4U, kind);
        store16(scalar + 6U, (uint16_t)path_size);
        encode_identity(identity, source);
        if (CC_SHA256_Update(&digest, scalar, sizeof(scalar)) != 1
                || CC_SHA256_Update(&digest, path,
                    (CC_LONG)path_size) != 1
                || CC_SHA256_Update(&digest, identity,
                    (CC_LONG)sizeof(identity)) != 1) {
            memset(identity, 0, sizeof(identity)); return -1;
        }
    }
    memset(identity, 0, sizeof(identity));
    memset(scalar, 0, sizeof(scalar));
    return CC_SHA256_Final(output, &digest) == 1 ? 0 : -1;
}

static int secure_directory_at(int parent_fd, const char *name, uid_t owner_uid)
{
    struct stat state;
    int descriptor = openat(parent_fd, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &state) != 0
            || !S_ISDIR(state.st_mode) || state.st_uid != owner_uid
            || (state.st_mode & 0022U) != 0U
            || (fcntl(descriptor, F_GETFD) & FD_CLOEXEC) == 0) {
        int saved = errno;
        if (descriptor >= 0) close(descriptor);
        errno = saved; return -1;
    }
    return descriptor;
}

static int same_directory_state(const struct stat *left,
    const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino
        && left->st_mode == right->st_mode && left->st_uid == right->st_uid
        && left->st_gid == right->st_gid && left->st_nlink == right->st_nlink
        && left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec
        && left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec
        && left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec
        && left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
}

int plamen_source_bootstrap_staged_authority_validate_v1(
    int generation_root_fd, int coordinator_receipt_fd, uid_t owner_uid,
    uint8_t output[32])
{
    struct plamen_source_bootstrap_receipt_v1 receipt;
    struct plamen_source_bootstrap_fd_identity_v1 supplied_receipt_identity;
    struct plamen_source_bootstrap_fd_identity_v1 named_receipt_identity;
    struct stat root_before, root_after, authority_before, authority_after;
    uint64_t seen = 0U;
    int share_fd = -1, plamen_fd = -1, authority_fd = -1;
    int named_receipt_fd = -1, enumeration_fd = -1;
    int member_fds[PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT];
    DIR *directory = NULL;
    size_t member;
    int result = -1;
    if (output != NULL) memset(output, 0, 32U);
    memset(&receipt, 0, sizeof(receipt));
    for (member = 0U;
            member < PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT;
            ++member) member_fds[member] = -1;
    if (generation_root_fd < 3 || coordinator_receipt_fd < 3 || output == NULL
            || fstat(generation_root_fd, &root_before) != 0
            || !S_ISDIR(root_before.st_mode) || root_before.st_uid != owner_uid
            || (root_before.st_mode & 0022U) != 0U
            || (fcntl(generation_root_fd, F_GETFD) & FD_CLOEXEC) == 0
            || (fcntl(generation_root_fd, F_GETFL) & O_ACCMODE) != O_RDONLY)
        goto done;
    share_fd = secure_directory_at(generation_root_fd, "share", owner_uid);
    if (share_fd < 0) goto done;
    plamen_fd = secure_directory_at(share_fd, "plamen", owner_uid);
    if (plamen_fd < 0) goto done;
    authority_fd = secure_directory_at(plamen_fd,
        "native-source-authority-v1", owner_uid);
    if (authority_fd < 0 || fstat(authority_fd, &authority_before) != 0)
        goto done;
    named_receipt_fd = openat(plamen_fd,
        "native-source-bootstrap-coordinator-receipt-v1.bin",
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (named_receipt_fd < 0
            || identity_from_fd(coordinator_receipt_fd, owner_uid,
                PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE,
                O_RDONLY, 1, 1, &supplied_receipt_identity) != 0
            || identity_from_fd(named_receipt_fd, owner_uid,
                PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE,
                O_RDONLY, 1, 1, &named_receipt_identity) != 0
            || supplied_receipt_identity.size
                != PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE
            || !same_identity(&supplied_receipt_identity,
                &named_receipt_identity)
            || writable_handle_count_exact(coordinator_receipt_fd, 0U) != 0
            || plamen_source_bootstrap_receipt_read_fd_v1(
                coordinator_receipt_fd, owner_uid, &receipt) != 0)
        goto done;
    enumeration_fd = duplicate_cloexec(authority_fd);
    if (enumeration_fd < 0 || (directory = fdopendir(enumeration_fd)) == NULL)
        goto done;
    enumeration_fd = -1;
    for (;;) {
        struct dirent *entry;
        size_t matched;
        errno = 0; entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) goto done;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0
                || strcmp(entry->d_name, "..") == 0) continue;
        for (matched = 0U;
                matched < PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT;
                ++matched) {
            const char *slash = strrchr(installed_member_paths[matched], '/');
            if (slash != NULL && strcmp(entry->d_name, slash + 1U) == 0)
                break;
        }
        if (matched == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT
                || (seen & (UINT64_C(1) << matched)) != 0U) goto done;
        seen |= UINT64_C(1) << matched;
    }
    if (seen != ((UINT64_C(1)
            << PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT) - 1U))
        goto done;
    for (member = 0U;
            member < PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT;
            ++member) {
        struct plamen_source_bootstrap_fd_identity_v1 observed;
        uint16_t role = (uint16_t)(member / 3U);
        uint16_t kind = (uint16_t)(member % 3U);
        const struct plamen_source_bootstrap_fd_identity_v1 *expected =
            kind == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PAYLOAD_V1
                ? &receipt.rows[role].payload
                : kind == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PRODUCER_RECEIPT_V1
                    ? &receipt.rows[role].producer_receipt
                    : &receipt.rows[role].source_manifest;
        const char *slash = strrchr(installed_member_paths[member], '/');
        if (slash == NULL) goto done;
        member_fds[member] = openat(authority_fd, slash + 1U,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (member_fds[member] < 0
                || identity_from_fd(member_fds[member], owner_uid,
                    kind == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PAYLOAD_V1
                        ? SOURCE_MAX_BYTES
                        : kind
                            == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PRODUCER_RECEIPT_V1
                            ? PRODUCER_RECEIPT_MAX_BYTES
                            : SOURCE_MANIFEST_MAX_BYTES,
                    O_RDONLY, 1, 1, &observed) != 0
                || !same_identity(&observed, expected)
                || writable_handle_count_exact(member_fds[member], 0U) != 0)
            goto done;
    }
    /* Rehash every still-retained leaf before returning the commitment. */
    for (member = 0U;
            member < PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT;
            ++member) {
        struct plamen_source_bootstrap_fd_identity_v1 observed;
        uint16_t role = (uint16_t)(member / 3U);
        uint16_t kind = (uint16_t)(member % 3U);
        const struct plamen_source_bootstrap_fd_identity_v1 *expected =
            kind == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PAYLOAD_V1
                ? &receipt.rows[role].payload
                : kind == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PRODUCER_RECEIPT_V1
                    ? &receipt.rows[role].producer_receipt
                    : &receipt.rows[role].source_manifest;
        if (identity_from_fd(member_fds[member], owner_uid,
                kind == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PAYLOAD_V1
                    ? SOURCE_MAX_BYTES
                    : kind
                        == PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PRODUCER_RECEIPT_V1
                        ? PRODUCER_RECEIPT_MAX_BYTES
                        : SOURCE_MANIFEST_MAX_BYTES,
                O_RDONLY, 1, 1, &observed) != 0
                || !same_identity(&observed, expected)
                || writable_handle_count_exact(member_fds[member], 0U) != 0)
            goto done;
    }
    if (fstat(authority_fd, &authority_after) != 0
            || fstat(generation_root_fd, &root_after) != 0
            || !same_directory_state(&authority_before, &authority_after)
            || !same_directory_state(&root_before, &root_after)
            || plamen_source_bootstrap_installed_authority_roster_sha256_v1(
                &receipt, output) != 0)
        goto done;
    result = 0;
done:
    for (member = 0U;
            member < PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT;
            ++member)
        if (member_fds[member] >= 0) close(member_fds[member]);
    if (directory != NULL) closedir(directory);
    else if (enumeration_fd >= 0) close(enumeration_fd);
    if (named_receipt_fd >= 0) close(named_receipt_fd);
    if (authority_fd >= 0) close(authority_fd);
    if (plamen_fd >= 0) close(plamen_fd);
    if (share_fd >= 0) close(share_fd);
    memset(&receipt, 0, sizeof(receipt));
    memset(&supplied_receipt_identity, 0, sizeof(supplied_receipt_identity));
    memset(&named_receipt_identity, 0, sizeof(named_receipt_identity));
    if (result != 0 && output != NULL) memset(output, 0, 32U);
    return result;
}

static int decode_identity_links(const uint8_t input[96], uint32_t links,
    struct plamen_source_bootstrap_fd_identity_v1 *identity)
{
    memset(identity, 0, sizeof(*identity));
    identity->device = load64(input); identity->inode = load64(input + 8U);
    identity->mode = load32(input + 16U); identity->uid = load32(input + 20U);
    identity->gid = load32(input + 24U); identity->links = load32(input + 28U);
    identity->size = load64(input + 32U);
    identity->mtime_seconds = (int64_t)load64(input + 40U);
    identity->mtime_nanoseconds = load32(input + 48U);
    identity->ctime_seconds = (int64_t)load64(input + 52U);
    identity->ctime_nanoseconds = load32(input + 60U);
    memcpy(identity->sha256, input + 64U, 32U);
    return identity->device != 0U && identity->inode != 0U
        && identity->links == links && identity->size != 0U
        && identity->mtime_nanoseconds < 1000000000U
        && identity->ctime_nanoseconds < 1000000000U
        && !all_zero(identity->sha256, 32U) && (identity->mode & 0022U) == 0U
        && S_ISREG((mode_t)identity->mode) ? 0 : -1;
}

static int decode_identity(const uint8_t input[96],
    struct plamen_source_bootstrap_fd_identity_v1 *identity)
{ return decode_identity_links(input, 1U, identity); }

static int compare_expected(
    const struct plamen_source_bootstrap_input_v1 *expected,
    const struct plamen_source_bootstrap_fd_identity_v1 *payload,
    const struct plamen_source_bootstrap_fd_identity_v1 *producer,
    const struct plamen_source_bootstrap_fd_identity_v1 *manifest)
{
    int producer_exact = expected->expected_producer_receipt_size != 0U
        || !all_zero(expected->expected_producer_receipt_sha256, 32U);
    if (expected->reserved != 0U || all_zero(expected->policy_sha256, 32U))
        return 0;
    if (expected->identity_mode
            == PLAMEN_SOURCE_BOOTSTRAP_LATEST_BACKEND_RECEIPT_V1)
        return expected->expected_payload_size == 0U
            && expected->expected_producer_receipt_size == 0U
            && expected->expected_source_manifest_size == 0U
            && all_zero(expected->expected_payload_sha256, 32U)
            && all_zero(expected->expected_producer_receipt_sha256, 32U)
            && all_zero(expected->expected_source_manifest_sha256, 32U);
    if (expected->identity_mode != PLAMEN_SOURCE_BOOTSTRAP_STATIC_PAYLOAD_V1
            && expected->identity_mode
                != PLAMEN_SOURCE_BOOTSTRAP_FROZEN_SOURCE_PROJECTION_V1)
        return 0;
    return expected->expected_payload_size == payload->size
        && expected->expected_source_manifest_size == manifest->size
        && constant_equal(expected->expected_payload_sha256,
            payload->sha256, 32U)
        && constant_equal(expected->expected_source_manifest_sha256,
            manifest->sha256, 32U)
        && (!producer_exact
            || (expected->expected_producer_receipt_size == producer->size
                && constant_equal(expected->expected_producer_receipt_sha256,
                    producer->sha256, 32U)));
}

static int key_add(struct inode_key *keys, size_t *count, size_t capacity,
    const struct plamen_source_bootstrap_fd_identity_v1 *identity)
{
    size_t index;
    for (index = 0U; index < *count; ++index)
        if (keys[index].device == identity->device
                && keys[index].inode == identity->inode) return -1;
    if (*count >= capacity) return -1;
    keys[*count].device = identity->device;
    keys[*count].inode = identity->inode;
    ++*count;
    return 0;
}

/* Standalone coordinator custody: reject any undisclosed writable alias. */
static int writable_handle_count_exact(int fd, unsigned int expected)
{
    struct stat target, candidate; int limit, current; unsigned int count = 0U;
    if (fstat(fd, &target) != 0 || (limit = getdtablesize()) <= 0) return -1;
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

/*
 * Output stores arrive already unlinked.  Census all same-UID processes so an
 * alias retained outside the coordinator cannot survive from helper hash to
 * coordinator seal.  With no directory entry, a successful census is also a
 * closed capability set: a later pathname open is impossible.
 */
static int private_store_aliases_exact(int fd, uid_t owner,
    unsigned int total_expected, unsigned int writable_expected)
{
#if defined(__APPLE__)
    struct stat target, after; pid_t *pids = NULL; int bytes, listed;
    unsigned int total = 0U, writable = 0U; size_t pid_index;
    if (fstat(fd, &target) != 0 || target.st_uid != owner
            || target.st_nlink != 0) return -1;
    bytes = proc_listpids(PROC_UID_ONLY, (uint32_t)owner, NULL, 0);
    if (bytes <= 0 || bytes > INT_MAX - (int)(64U * sizeof(pid_t))) return -1;
    bytes += (int)(64U * sizeof(pid_t));
    pids = calloc(1U, (size_t)bytes);
    if (pids == NULL) return -1;
    listed = proc_listpids(PROC_UID_ONLY, (uint32_t)owner, pids, bytes);
    if (listed <= 0 || listed >= bytes
            || (size_t)listed % sizeof(pid_t) != 0U) goto fail;
    for (pid_index = 0U; pid_index < (size_t)listed / sizeof(pid_t);
            ++pid_index) {
        struct proc_bsdinfo bsd; struct proc_fdinfo *fds = NULL;
        int fd_bytes, fd_listed; size_t fd_index;
        if (pids[pid_index] <= 0) continue;
        memset(&bsd, 0, sizeof(bsd));
        if (proc_pidinfo(pids[pid_index], PROC_PIDTBSDINFO, 0, &bsd,
                (int)sizeof(bsd)) != (int)sizeof(bsd)) continue;
        if (bsd.pbi_uid != owner) continue;
        fd_bytes = proc_pidinfo(pids[pid_index], PROC_PIDLISTFDS, 0, NULL, 0);
        if (fd_bytes <= 0) {
            if (bsd.pbi_nfiles != 0U) goto fail;
            continue;
        }
        if (fd_bytes > INT_MAX - (int)(32U * sizeof(struct proc_fdinfo)))
            goto fail;
        fd_bytes += (int)(32U * sizeof(struct proc_fdinfo));
        fds = calloc(1U, (size_t)fd_bytes);
        if (fds == NULL) goto fail;
        fd_listed = proc_pidinfo(pids[pid_index], PROC_PIDLISTFDS, 0, fds,
            fd_bytes);
        if (fd_listed < 0 || fd_listed >= fd_bytes
                || (size_t)fd_listed % sizeof(*fds) != 0U) {
            free(fds); goto fail;
        }
        for (fd_index = 0U;
                fd_index < (size_t)fd_listed / sizeof(*fds); ++fd_index) {
            struct vnode_fdinfowithpath vnode; int amount;
            if (fds[fd_index].proc_fdtype != PROX_FDTYPE_VNODE) continue;
            memset(&vnode, 0, sizeof(vnode));
            amount = proc_pidfdinfo(pids[pid_index], fds[fd_index].proc_fd,
                PROC_PIDFDVNODEPATHINFO, &vnode, (int)sizeof(vnode));
            if (amount != (int)sizeof(vnode)) continue;
            if ((dev_t)vnode.pvip.vip_vi.vi_stat.vst_dev == target.st_dev
                    && (ino_t)vnode.pvip.vip_vi.vi_stat.vst_ino
                        == target.st_ino) {
                ++total;
                if ((vnode.pfi.fi_openflags & FWRITE) != 0U)
                    ++writable;
            }
        }
        free(fds);
    }
    free(pids);
    if (fstat(fd, &after) != 0 || after.st_dev != target.st_dev
            || after.st_ino != target.st_ino || after.st_nlink != 0)
        return -1;
    if (total != total_expected || writable != writable_expected) {
#ifdef PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_TESTING
        fprintf(stderr, "private-store aliases total=%u/%u writable=%u/%u\n",
            total, total_expected, writable, writable_expected);
#endif
        return -1;
    }
    return 0;
fail:
    free(pids); return -1;
#else
    (void)fd; (void)owner; (void)total_expected; (void)writable_expected;
    return -1;
#endif
}

static int hash_acquisition_roster(
    const struct plamen_source_bootstrap_receipt_v1 *receipt,
    uint8_t output[32])
{
    CC_SHA256_CTX digest; uint8_t count[2], identity[96]; size_t index;
    if (CC_SHA256_Init(&digest) != 1
            || CC_SHA256_Update(&digest, acquisition_domain,
                (CC_LONG)sizeof(acquisition_domain)) != 1) return -1;
    store16(count, PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT);
    if (CC_SHA256_Update(&digest, count, sizeof(count)) != 1) return -1;
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;
            ++index) {
        uint8_t ordinal[2], role_size[2]; size_t length = strlen(source_roles[index]);
        store16(ordinal, (uint16_t)index); store16(role_size, (uint16_t)length);
        if (CC_SHA256_Update(&digest, ordinal, 2U) != 1
                || CC_SHA256_Update(&digest, role_size, 2U) != 1
                || CC_SHA256_Update(&digest, source_roles[index],
                    (CC_LONG)length) != 1) return -1;
        encode_identity(identity, &receipt->rows[index].payload);
        if (CC_SHA256_Update(&digest, identity, 96U) != 1) return -1;
        encode_identity(identity, &receipt->rows[index].producer_receipt);
        if (CC_SHA256_Update(&digest, identity, 96U) != 1
                || CC_SHA256_Update(&digest, receipt->rows[index].policy_sha256,
                    32U) != 1) return -1;
    }
    memset(identity, 0, sizeof(identity));
    return CC_SHA256_Final(output, &digest) == 1 ? 0 : -1;
}

static int hash_output_roster(
    const struct plamen_source_bootstrap_receipt_v1 *receipt,
    uint8_t output[32])
{
    CC_SHA256_CTX digest; uint8_t count[2], encoded[96]; size_t index;
    if (CC_SHA256_Init(&digest) != 1
            || CC_SHA256_Update(&digest, output_domain,
                (CC_LONG)sizeof(output_domain)) != 1) return -1;
    store16(count, PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT);
    if (CC_SHA256_Update(&digest, count, 2U) != 1) return -1;
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) {
        uint8_t ordinal[2]; store16(ordinal, (uint16_t)index);
        encode_identity(encoded, &receipt->outputs[index]);
        if (CC_SHA256_Update(&digest, ordinal, 2U) != 1
                || CC_SHA256_Update(&digest, encoded, 96U) != 1) return -1;
    }
    memset(encoded, 0, sizeof(encoded));
    return CC_SHA256_Final(output, &digest) == 1 ? 0 : -1;
}

static int encode_receipt(const struct plamen_source_bootstrap_receipt_v1 *receipt,
    uint8_t bytes[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE])
{
    size_t index;
    memset(bytes, 0, PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE);
    memcpy(bytes, receipt_magic, 8U);
    store16(bytes + 8U, PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_VERSION);
    store16(bytes + 10U, PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_HEADER_SIZE);
    store16(bytes + 12U, PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROW_SIZE);
    store16(bytes + 14U, PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT);
    store16(bytes + 16U, PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_ROW_SIZE);
    store16(bytes + 18U, PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT);
    store32(bytes + 24U, PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE);
    memcpy(bytes + 32U, receipt->acquisition_roster_sha256, 32U);
    encode_identity(bytes + 64U, &receipt->composition_manifest);
    memcpy(bytes + 160U, receipt->operation4_executable_sha256, 32U);
    encode_identity(bytes + 192U, &receipt->operation4_terminal_receipt);
    memcpy(bytes + 288U, receipt->output_roster_sha256, 32U);
    encode_identity(bytes + 320U, &receipt->producer_verifier_key);
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;
            ++index) {
        const struct plamen_source_bootstrap_receipt_row_v1 *source =
            &receipt->rows[index];
        uint8_t *row = bytes + RECEIPT_ROWS_OFFSET
            + index * PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROW_SIZE;
        size_t role_size = strlen(source_roles[index]);
        store16(row, (uint16_t)index); store16(row + 2U, (uint16_t)role_size);
        encode_identity(row + 8U, &source->payload);
        encode_identity(row + 104U, &source->producer_receipt);
        memcpy(row + 200U, source->policy_sha256, 32U);
        encode_identity(row + 232U, &source->source_manifest);
        memcpy(row + 328U, source_roles[index], role_size);
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) {
        uint8_t *row = bytes + RECEIPT_OUTPUTS_OFFSET
            + index * PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_ROW_SIZE;
        store16(row, (uint16_t)index);
        encode_identity(row + 8U, &receipt->outputs[index]);
    }
    return CC_SHA256(bytes, (CC_LONG)RECEIPT_TRAILER_OFFSET,
        bytes + RECEIPT_TRAILER_OFFSET) == bytes + RECEIPT_TRAILER_OFFSET
        ? 0 : -1;
}

int plamen_source_bootstrap_receipt_decode_exact_v1(const uint8_t *bytes,
    size_t size, struct plamen_source_bootstrap_receipt_v1 *receipt)
{
    uint8_t prefix_sha[32], roster[32], outputs[32], full[32]; size_t index;
    if (bytes == NULL || receipt == NULL
            || size != PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE
            || !constant_equal(bytes, receipt_magic, 8U)
            || load16(bytes + 8U) != PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_VERSION
            || load16(bytes + 10U) != PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_HEADER_SIZE
            || load16(bytes + 12U) != PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROW_SIZE
            || load16(bytes + 14U) != PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT
            || load16(bytes + 16U) != PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_ROW_SIZE
            || load16(bytes + 18U) != PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT
            || load32(bytes + 20U) != 0U
            || load32(bytes + 24U) != PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE
            || load32(bytes + 28U) != 0U
            || !all_zero(bytes + 416U, RECEIPT_ROWS_OFFSET - 416U)
            || !all_zero(bytes + RECEIPT_OUTPUTS_OFFSET
                + PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT
                    * PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_ROW_SIZE,
                RECEIPT_TRAILER_OFFSET - (RECEIPT_OUTPUTS_OFFSET
                + PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT
                    * PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_ROW_SIZE))
            || CC_SHA256(bytes, (CC_LONG)RECEIPT_TRAILER_OFFSET, prefix_sha) == NULL
            || !constant_equal(prefix_sha, bytes + RECEIPT_TRAILER_OFFSET, 32U))
        return -1;
    memset(receipt, 0, sizeof(*receipt));
    memcpy(receipt->acquisition_roster_sha256, bytes + 32U, 32U);
    if (decode_identity(bytes + 64U, &receipt->composition_manifest) != 0
            || all_zero(bytes + 160U, 32U)
            || decode_identity(bytes + 192U,
                &receipt->operation4_terminal_receipt) != 0
            || decode_identity(bytes + 320U,
                &receipt->producer_verifier_key) != 0
            || receipt->producer_verifier_key.size != 32U
            || (receipt->producer_verifier_key.mode & 07777U) != 0400U)
        return -1;
    memcpy(receipt->operation4_executable_sha256, bytes + 160U, 32U);
    memcpy(receipt->output_roster_sha256, bytes + 288U, 32U);
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;
            ++index) {
        const uint8_t *row = bytes + RECEIPT_ROWS_OFFSET
            + index * PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROW_SIZE;
        size_t role_size = strlen(source_roles[index]);
        struct plamen_source_bootstrap_receipt_row_v1 *target = &receipt->rows[index];
        if (load16(row) != index || load16(row + 2U) != role_size
                || load32(row + 4U) != 0U
                || decode_identity(row + 8U, &target->payload) != 0
                || decode_identity(row + 104U, &target->producer_receipt) != 0
                || all_zero(row + 200U, 32U)
                || decode_identity(row + 232U, &target->source_manifest) != 0
                || !constant_equal(row + 328U,
                    (const uint8_t *)source_roles[index], role_size)
                || !all_zero(row + 328U + role_size, 32U - role_size)
                || !all_zero(row + 360U, 24U)) return -1;
        target->ordinal = (uint16_t)index;
        memcpy(target->role, source_roles[index], role_size);
        memcpy(target->policy_sha256, row + 200U, 32U);
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) {
        const uint8_t *row = bytes + RECEIPT_OUTPUTS_OFFSET
            + index * PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_ROW_SIZE;
        if (load16(row) != index || !all_zero(row + 2U, 6U)
                || decode_identity_links(row + 8U, 0U,
                    &receipt->outputs[index]) != 0
                || !all_zero(row + 104U, 24U)) return -1;
    }
    if (hash_acquisition_roster(receipt, roster) != 0
            || hash_output_roster(receipt, outputs) != 0
            || !constant_equal(roster, receipt->acquisition_roster_sha256, 32U)
            || !constant_equal(outputs, receipt->output_roster_sha256, 32U)
            || CC_SHA256(bytes, (CC_LONG)size, full) == NULL) return -1;
    memcpy(receipt->receipt_sha256, full, 32U);
    return 0;
}

int plamen_source_bootstrap_receipt_read_fd_v1(int fd, uid_t owner,
    struct plamen_source_bootstrap_receipt_v1 *receipt)
{
    uint8_t bytes[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE];
    struct stat before, after; int flags, descriptor_flags;
    size_t offset = 0U; int result = -1;
    if (fd < 3 || receipt == NULL || (flags = fcntl(fd, F_GETFL)) < 0
            || (flags & O_ACCMODE) != O_RDONLY
            || (descriptor_flags = fcntl(fd, F_GETFD)) < 0
            || (descriptor_flags & FD_CLOEXEC) == 0
            || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
            || before.st_uid != owner || before.st_nlink != 1
            || (before.st_mode & 07777U) != 0400U
            || before.st_size != (off_t)sizeof(bytes)) goto done;
    while (offset < sizeof(bytes)) {
        ssize_t amount = pread(fd, bytes + offset, sizeof(bytes) - offset,
            (off_t)offset);
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    if (fstat(fd, &after) != 0 || before.st_dev != after.st_dev
            || before.st_ino != after.st_ino || before.st_mode != after.st_mode
            || before.st_uid != after.st_uid || before.st_gid != after.st_gid
            || before.st_nlink != after.st_nlink || before.st_size != after.st_size
            || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
            || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
            || plamen_source_bootstrap_receipt_decode_exact_v1(bytes,
                sizeof(bytes), receipt) != 0) goto done;
    result = 0;
done:
    memset(bytes, 0, sizeof(bytes)); return result;
}

static int write_receipt(int writer, int reader, uid_t owner,
    const uint8_t bytes[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE])
{
    struct stat output, read_state, final_state;
    int wf, rf, writer_descriptor_flags, reader_descriptor_flags;
    size_t offset = 0U;
    if ((wf = fcntl(writer, F_GETFL)) < 0 || (rf = fcntl(reader, F_GETFL)) < 0
            || (wf & O_ACCMODE) != O_RDWR || (rf & O_ACCMODE) != O_RDONLY
            || (writer_descriptor_flags = fcntl(writer, F_GETFD)) < 0
            || (reader_descriptor_flags = fcntl(reader, F_GETFD)) < 0
            || (writer_descriptor_flags & FD_CLOEXEC) == 0
            || (reader_descriptor_flags & FD_CLOEXEC) == 0
            || fstat(writer, &output) != 0 || fstat(reader, &read_state) != 0
            || !S_ISREG(output.st_mode) || output.st_uid != owner
            || output.st_nlink != 1 || output.st_size != 0
            || (output.st_mode & 07777U) != 0600U
            || output.st_dev != read_state.st_dev || output.st_ino != read_state.st_ino)
        return -1;
    while (offset < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE) {
        ssize_t amount = pwrite(writer, bytes + offset,
            PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE - offset,
            (off_t)offset);
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    if (fsync(writer) != 0 || fchmod(writer, 0400U) != 0 || fsync(writer) != 0
            || fstat(reader, &final_state) != 0
            || final_state.st_dev != output.st_dev
            || final_state.st_ino != output.st_ino
            || final_state.st_uid != owner || final_state.st_nlink != 1
            || (final_state.st_mode & 07777U) != 0400U
            || final_state.st_size !=
                PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE)
        return -1;
    return 0;
}

void plamen_source_bootstrap_authority_dispose_v1(
    struct plamen_source_bootstrap_authority_v1 *authority)
{
    size_t index;
    if (authority == NULL) return;
    if (authority->composition_manifest_fd >= 0)
        close(authority->composition_manifest_fd);
    if (authority->producer_verifier_key_fd >= 0)
        close(authority->producer_verifier_key_fd);
    if (authority->operation4_terminal_receipt_fd >= 0)
        close(authority->operation4_terminal_receipt_fd);
    if (authority->coordinator_receipt_fd >= 0)
        close(authority->coordinator_receipt_fd);
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;
            ++index) {
        if (authority->payload_fds[index] >= 0) close(authority->payload_fds[index]);
        if (authority->producer_receipt_fds[index] >= 0)
            close(authority->producer_receipt_fds[index]);
        if (authority->source_manifest_fds[index] >= 0)
            close(authority->source_manifest_fds[index]);
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index)
        if (authority->output_fds[index] >= 0) close(authority->output_fds[index]);
    memset(authority, 0, sizeof(*authority)); free(authority);
}

static struct plamen_source_bootstrap_authority_v1 *authority_new(void)
{
    struct plamen_source_bootstrap_authority_v1 *value = calloc(1U, sizeof(*value));
    size_t index;
    if (value == NULL) return NULL;
    value->producer_verifier_key_fd = -1;
    value->composition_manifest_fd = -1;
    value->operation4_terminal_receipt_fd = -1;
    value->coordinator_receipt_fd = -1;
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;
            ++index) value->payload_fds[index] = value->producer_receipt_fds[index]
                = value->source_manifest_fds[index] = -1;
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) value->output_fds[index] = -1;
    return value;
}

int plamen_source_bootstrap_coordinator_issue_v1(
    struct plamen_source_bootstrap_issue_request_v1 *request,
    struct plamen_source_bootstrap_authority_v1 **authority_output,
    struct plamen_source_bootstrap_receipt_v1 *receipt_output)
{
    enum { KEY_CAPACITY = 1 + 3 * PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT
        + PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT
        + PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT + 3 };
    struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt;
    struct plamen_source_bootstrap_fd_identity_v1 identity, after;
    struct inode_key keys[KEY_CAPACITY]; size_t key_count = 0U, index;
    int output_writers[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT];
    int scratch[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT];
    int operation_terminal = -1, receipt_writer = -1; uint8_t bytes[8192];
    uint8_t verifier_key[32];
    int result = -1;
    memset(&receipt, 0, sizeof(receipt)); memset(keys, 0, sizeof(keys));
    memset(bytes, 0, sizeof(bytes)); memset(verifier_key, 0, sizeof(verifier_key));
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) output_writers[index] = -1;
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT;
            ++index) scratch[index] = -1;
    if (authority_output != NULL) *authority_output = NULL;
    if (receipt_output != NULL) memset(receipt_output, 0, sizeof(*receipt_output));
    if (request == NULL || authority_output == NULL || receipt_output == NULL
            || request->owner_uid != getuid())
        TEST_FAIL("request-null");
    /* Transfer every writable descriptor before any fallible admission. */
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) {
        output_writers[index] = request->output_writer_fds[index];
        request->output_writer_fds[index] = -1;
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT;
            ++index) {
        scratch[index] = request->scratch_fds[index];
        request->scratch_fds[index] = -1;
    }
    receipt_writer = request->receipt_writer_fd;
    request->receipt_writer_fd = -1;
    if (request->policy_authority.authenticate_source == NULL
            || request->policy_authority.authenticate_operation4 == NULL
            || request->operation4.invoke == NULL
            || request->operation4.rejoin_terminal_outputs == NULL
            || all_zero(request->operation4.executable_sha256, 32U)
            || request->policy_authority.authenticate_operation4(
                request->policy_authority.context,
                request->operation4.executable_sha256) != 0)
        TEST_FAIL("request");
    authority = authority_new();
    if (authority == NULL) goto done;
    authority->owner_uid = request->owner_uid;
    authority->producer_verifier_key_fd = duplicate_cloexec(
        request->producer_verifier_key_fd);
    if (authority->producer_verifier_key_fd < 0
            || identity_from_fd(authority->producer_verifier_key_fd,
                request->owner_uid, 32U, O_RDONLY, 1, 1,
                &receipt.producer_verifier_key) != 0
            || receipt.producer_verifier_key.size != 32U
            || (receipt.producer_verifier_key.mode & 07777U) != 0400U
            || pread(authority->producer_verifier_key_fd, verifier_key,
                sizeof(verifier_key), 0) != (ssize_t)sizeof(verifier_key)
            || all_zero(verifier_key, sizeof(verifier_key))
            || writable_handle_count_exact(
                authority->producer_verifier_key_fd, 0U) != 0
            || key_add(keys, &key_count, KEY_CAPACITY,
                &receipt.producer_verifier_key) != 0)
        TEST_FAIL("producer-verifier-key");
    authority->composition_manifest_fd = duplicate_cloexec(
        request->composition_manifest_fd);
    if (authority->composition_manifest_fd < 0
            || identity_from_fd(authority->composition_manifest_fd,
                request->owner_uid, COMPOSITION_MANIFEST_MAX_BYTES, O_RDONLY,
                1, 1, &receipt.composition_manifest) != 0
            || writable_handle_count_exact(authority->composition_manifest_fd,
                0U) != 0
            || key_add(keys, &key_count, KEY_CAPACITY,
                &receipt.composition_manifest) != 0) TEST_FAIL("composition");
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;
            ++index) {
        struct plamen_source_bootstrap_receipt_row_v1 *row = &receipt.rows[index];
        const struct plamen_source_bootstrap_input_v1 *input = &request->inputs[index];
        authority->payload_fds[index] = duplicate_cloexec(input->payload_fd);
        authority->producer_receipt_fds[index] = duplicate_cloexec(
            input->producer_receipt_fd);
        authority->source_manifest_fds[index] = duplicate_cloexec(
            input->source_manifest_fd);
        if (authority->payload_fds[index] < 0
                || authority->producer_receipt_fds[index] < 0
                || authority->source_manifest_fds[index] < 0
                || identity_from_fd(authority->payload_fds[index],
                    request->owner_uid, SOURCE_MAX_BYTES, O_RDONLY, 1, 1,
                    &row->payload) != 0
                || identity_from_fd(authority->producer_receipt_fds[index],
                    request->owner_uid, PRODUCER_RECEIPT_MAX_BYTES, O_RDONLY,
                    1, 1, &row->producer_receipt) != 0
                || identity_from_fd(authority->source_manifest_fds[index],
                    request->owner_uid, SOURCE_MANIFEST_MAX_BYTES, O_RDONLY,
                    1, 1, &row->source_manifest) != 0
                || writable_handle_count_exact(authority->payload_fds[index],
                    0U) != 0
                || writable_handle_count_exact(
                    authority->producer_receipt_fds[index], 0U) != 0
                || writable_handle_count_exact(
                    authority->source_manifest_fds[index], 0U) != 0
                || !compare_expected(input, &row->payload,
                    &row->producer_receipt, &row->source_manifest)
                || key_add(keys, &key_count, KEY_CAPACITY, &row->payload) != 0
                || key_add(keys, &key_count, KEY_CAPACITY,
                    &row->producer_receipt) != 0
                || key_add(keys, &key_count, KEY_CAPACITY,
                    &row->source_manifest) != 0
                || request->policy_authority.authenticate_source(
                    request->policy_authority.context, (uint16_t)index,
                    authority->producer_receipt_fds[index], input,
                    &row->payload, &row->producer_receipt,
                    &row->source_manifest) != 0) TEST_FAIL("source");
        row->ordinal = (uint16_t)index;
        memcpy(row->role, source_roles[index], strlen(source_roles[index]));
        memcpy(row->policy_sha256, input->policy_sha256, 32U);
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) {
        struct plamen_source_bootstrap_fd_identity_v1 reader_identity;
        authority->output_fds[index] = duplicate_cloexec(
            request->output_reader_fds[index]);
        if (authority->output_fds[index] < 0 || output_writers[index] < 3
                || identity_from_fd(output_writers[index], request->owner_uid,
                    SOURCE_MAX_BYTES, O_RDWR, 0, 0, &identity) != 0
                || identity_from_fd(authority->output_fds[index], request->owner_uid,
                    SOURCE_MAX_BYTES, O_RDONLY, 0, 0, &reader_identity) != 0
                || identity.size != 0U
                || reader_identity.size != 0U
                || identity.links != 0U || reader_identity.links != 0U
                || identity.device != reader_identity.device
                || identity.inode != reader_identity.inode
                || writable_handle_count_exact(output_writers[index], 1U) != 0
                || private_store_aliases_exact(output_writers[index],
                    request->owner_uid, 3U, 1U) != 0
                || key_add(keys, &key_count, KEY_CAPACITY, &identity) != 0)
            TEST_FAIL("output-admission");
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT;
            ++index) {
        if (scratch[index] < 0
                || identity_from_fd(scratch[index], request->owner_uid,
                    SOURCE_MAX_BYTES, O_RDWR, 0, 0, &identity) != 0
                || identity.size != 0U || identity.links != 0U
                || writable_handle_count_exact(scratch[index], 1U) != 0
                || key_add(keys, &key_count, KEY_CAPACITY, &identity) != 0)
            TEST_FAIL("scratch-admission");
    }
    {
        struct plamen_source_bootstrap_fd_identity_v1 receipt_reader_identity;
        authority->coordinator_receipt_fd = duplicate_cloexec(
            request->receipt_reader_fd);
        if (receipt_writer < 3 || authority->coordinator_receipt_fd < 0
                || identity_from_fd(receipt_writer, request->owner_uid,
                    PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE,
                    O_RDWR, 1, 0, &identity) != 0
                || identity_from_fd(authority->coordinator_receipt_fd,
                    request->owner_uid,
                    PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE,
                    O_RDONLY, 1, 0, &receipt_reader_identity) != 0
                || identity.size != 0U || receipt_reader_identity.size != 0U
                || identity.device != receipt_reader_identity.device
                || identity.inode != receipt_reader_identity.inode
                || writable_handle_count_exact(receipt_writer, 1U) != 0
                || key_add(keys, &key_count, KEY_CAPACITY, &identity) != 0)
            TEST_FAIL("receipt-admission");
    }
    if (request->operation4.invoke(request->operation4.context,
            authority->composition_manifest_fd, authority->payload_fds,
            authority->source_manifest_fds, output_writers, scratch,
            &operation_terminal) != 0 || operation_terminal < 3)
        TEST_FAIL("operation4");
    authority->operation4_terminal_receipt_fd = duplicate_cloexec(operation_terminal);
    if (authority->operation4_terminal_receipt_fd < 0)
        TEST_FAIL("terminal-duplicate");
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) {
        if (fsync(output_writers[index]) != 0
                || fchmod(output_writers[index], 0400U) != 0
                || fsync(output_writers[index]) != 0)
            TEST_FAIL("output-seal");
        close(output_writers[index]); output_writers[index] = -1;
    }
    if (identity_from_fd(authority->operation4_terminal_receipt_fd,
                request->owner_uid, OPERATION_RECEIPT_MAX_BYTES, O_RDONLY, 1, 1,
                &receipt.operation4_terminal_receipt) != 0
            || (receipt.operation4_terminal_receipt.mode & 07777U) != 0400U
            || writable_handle_count_exact(
                authority->operation4_terminal_receipt_fd, 0U) != 0
            || key_add(keys, &key_count, KEY_CAPACITY,
                &receipt.operation4_terminal_receipt) != 0)
        TEST_FAIL("terminal");
    /* Rejoin and rehash every acquisition input after the transform. */
    if (identity_from_fd(authority->producer_verifier_key_fd,
            request->owner_uid, 32U, O_RDONLY, 1, 1, &after) != 0
            || !same_identity(&after, &receipt.producer_verifier_key))
        TEST_FAIL("producer-verifier-key-rejoin");
    if (identity_from_fd(authority->composition_manifest_fd, request->owner_uid,
            COMPOSITION_MANIFEST_MAX_BYTES, O_RDONLY, 1, 1, &after) != 0
            || !same_identity(&after, &receipt.composition_manifest))
        TEST_FAIL("composition-rejoin");
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;
            ++index) {
        if (identity_from_fd(authority->payload_fds[index], request->owner_uid,
                SOURCE_MAX_BYTES, O_RDONLY, 1, 1, &after) != 0
                || !same_identity(&after, &receipt.rows[index].payload)
                || identity_from_fd(authority->producer_receipt_fds[index],
                    request->owner_uid, PRODUCER_RECEIPT_MAX_BYTES, O_RDONLY,
                    1, 1, &after) != 0
                || !same_identity(&after, &receipt.rows[index].producer_receipt)
                || identity_from_fd(authority->source_manifest_fds[index],
                    request->owner_uid, SOURCE_MANIFEST_MAX_BYTES, O_RDONLY,
                    1, 1, &after) != 0
                || !same_identity(&after, &receipt.rows[index].source_manifest))
            TEST_FAIL("source-rejoin");
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index)
        if (identity_from_fd(authority->output_fds[index], request->owner_uid,
                SOURCE_MAX_BYTES, O_RDONLY, 0, 1, &receipt.outputs[index]) != 0
                || receipt.outputs[index].links != 0U
                || (receipt.outputs[index].mode & 07777U) != 0400U
                || private_store_aliases_exact(authority->output_fds[index],
                    request->owner_uid, 2U, 0U) != 0)
            TEST_FAIL("output-census");
    if (request->operation4.rejoin_terminal_outputs(
            request->operation4.context,
            authority->operation4_terminal_receipt_fd, receipt.outputs) != 0)
        TEST_FAIL("output-terminal-rejoin");
    memcpy(receipt.operation4_executable_sha256,
        request->operation4.executable_sha256, 32U);
    if (hash_acquisition_roster(&receipt, receipt.acquisition_roster_sha256) != 0
            || hash_output_roster(&receipt, receipt.output_roster_sha256) != 0
            || encode_receipt(&receipt, bytes) != 0) TEST_FAIL("encode");
    if (receipt_writer < 0 || authority->coordinator_receipt_fd < 0
            || write_receipt(receipt_writer, authority->coordinator_receipt_fd,
                request->owner_uid, bytes) != 0
            || plamen_source_bootstrap_receipt_read_fd_v1(
                authority->coordinator_receipt_fd, request->owner_uid,
                &authority->receipt) != 0) TEST_FAIL("publish-read");
    receipt = authority->receipt;
    *receipt_output = receipt;
    *authority_output = authority;
    authority = NULL; result = 0;
done:
    if (operation_terminal >= 0) close(operation_terminal);
    if (receipt_writer >= 0) close(receipt_writer);
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) if (output_writers[index] >= 0) close(output_writers[index]);
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT;
            ++index) if (scratch[index] >= 0) close(scratch[index]);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    memset(&receipt, 0, sizeof(receipt)); memset(&identity, 0, sizeof(identity));
    memset(&after, 0, sizeof(after)); memset(keys, 0, sizeof(keys));
    memset(bytes, 0, sizeof(bytes)); memset(verifier_key, 0, sizeof(verifier_key));
    return result;
}

int plamen_source_bootstrap_authority_project_role_v1(
    const struct plamen_source_bootstrap_authority_v1 *authority,
    uint16_t role, struct plamen_source_bootstrap_projection_v1 *projection)
{
    struct plamen_source_bootstrap_fd_identity_v1 observed;
    if (projection != NULL) {
        memset(projection, 0, sizeof(*projection));
        projection->payload_fd = projection->producer_receipt_fd =
            projection->source_manifest_fd = projection->coordinator_receipt_fd = -1;
    }
    if (authority == NULL || projection == NULL
            || role >= PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT)
        return -1;
    if (identity_from_fd(authority->payload_fds[role], authority->owner_uid,
            SOURCE_MAX_BYTES, O_RDONLY, 1, 1, &observed) != 0
            || !same_identity(&observed, &authority->receipt.rows[role].payload)
            || identity_from_fd(authority->producer_receipt_fds[role],
                authority->owner_uid, PRODUCER_RECEIPT_MAX_BYTES, O_RDONLY,
                1, 1, &observed) != 0
            || !same_identity(&observed,
                &authority->receipt.rows[role].producer_receipt)
            || identity_from_fd(authority->source_manifest_fds[role],
                authority->owner_uid, SOURCE_MANIFEST_MAX_BYTES, O_RDONLY,
                1, 1, &observed) != 0
            || !same_identity(&observed,
                &authority->receipt.rows[role].source_manifest)) return -1;
    projection->payload_fd = duplicate_cloexec(authority->payload_fds[role]);
    projection->producer_receipt_fd = duplicate_cloexec(
        authority->producer_receipt_fds[role]);
    projection->source_manifest_fd = duplicate_cloexec(
        authority->source_manifest_fds[role]);
    projection->coordinator_receipt_fd = duplicate_cloexec(
        authority->coordinator_receipt_fd);
    if (projection->payload_fd < 0 || projection->producer_receipt_fd < 0
            || projection->source_manifest_fd < 0
            || projection->coordinator_receipt_fd < 0) {
        plamen_source_bootstrap_projection_dispose_v1(projection); return -1;
    }
    projection->ordinal = role;
    memcpy(projection->role, source_roles[role], strlen(source_roles[role]));
    projection->payload = authority->receipt.rows[role].payload;
    projection->producer_receipt = authority->receipt.rows[role].producer_receipt;
    projection->source_manifest = authority->receipt.rows[role].source_manifest;
    memcpy(projection->policy_sha256,
        authority->receipt.rows[role].policy_sha256, 32U);
    memcpy(projection->producer_verifier_key_sha256,
        authority->receipt.producer_verifier_key.sha256, 32U);
    memcpy(projection->acquisition_roster_sha256,
        authority->receipt.acquisition_roster_sha256, 32U);
    memcpy(projection->coordinator_receipt_sha256,
        authority->receipt.receipt_sha256, 32U);
    return 0;
}

void plamen_source_bootstrap_projection_dispose_v1(
    struct plamen_source_bootstrap_projection_v1 *projection)
{
    if (projection == NULL) return;
    if (projection->payload_fd >= 0) close(projection->payload_fd);
    if (projection->producer_receipt_fd >= 0) close(projection->producer_receipt_fd);
    if (projection->source_manifest_fd >= 0) close(projection->source_manifest_fd);
    if (projection->coordinator_receipt_fd >= 0) close(projection->coordinator_receipt_fd);
    memset(projection, 0, sizeof(*projection));
    projection->payload_fd = projection->producer_receipt_fd =
        projection->source_manifest_fd = projection->coordinator_receipt_fd = -1;
}

void plamen_source_bootstrap_installed_authority_dispose_v1(
    struct plamen_source_bootstrap_installed_authority_v1 *authority)
{
    if (authority == NULL) return;
    if (authority->coordinator_receipt_fd >= 0)
        close(authority->coordinator_receipt_fd);
    memset(authority, 0, sizeof(*authority));
    free(authority);
}

int plamen_source_bootstrap_installed_readmit_v1(int receipt_fd,
    uid_t owner_uid,
    const struct plamen_source_bootstrap_installed_binding_v1 *binding,
    struct plamen_source_bootstrap_installed_authority_v1 **authority_output)
{
    struct plamen_source_bootstrap_installed_authority_v1 *authority = NULL;
    uint8_t installed_roster[32];
    memset(installed_roster, 0, sizeof(installed_roster));
    if (authority_output != NULL) *authority_output = NULL;
    if (receipt_fd < 3 || binding == NULL || authority_output == NULL
            || binding->receipt_size !=
                PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE
            || all_zero(binding->receipt_sha256, 32U)
            || all_zero(binding->acquisition_roster_sha256, 32U)
            || all_zero(binding->producer_verifier_key_sha256, 32U)
            || all_zero(binding->installed_authority_roster_sha256, 32U)
            || all_zero(binding->coordinator_member_identity_sha256, 32U)
            || all_zero(binding->coordinator_code_identity_sha256, 32U))
        return -1;
    authority = calloc(1U, sizeof(*authority));
    if (authority == NULL) return -1;
    authority->owner_uid = owner_uid;
    authority->coordinator_receipt_fd = duplicate_cloexec(receipt_fd);
    if (authority->coordinator_receipt_fd < 0
            || plamen_source_bootstrap_receipt_read_fd_v1(
                authority->coordinator_receipt_fd, owner_uid,
                &authority->receipt) != 0
            || !constant_equal(authority->receipt.receipt_sha256,
                binding->receipt_sha256, 32U)
            || !constant_equal(authority->receipt.acquisition_roster_sha256,
                binding->acquisition_roster_sha256, 32U)
            || !constant_equal(authority->receipt.producer_verifier_key.sha256,
                binding->producer_verifier_key_sha256, 32U)
            || plamen_source_bootstrap_installed_authority_roster_sha256_v1(
                &authority->receipt, installed_roster) != 0
            || !constant_equal(installed_roster,
                binding->installed_authority_roster_sha256, 32U)) {
        memset(installed_roster, 0, sizeof(installed_roster));
        plamen_source_bootstrap_installed_authority_dispose_v1(authority);
        return -1;
    }
    memset(installed_roster, 0, sizeof(installed_roster));
    authority->binding = *binding;
    *authority_output = authority;
    return 0;
}

int plamen_source_bootstrap_installed_project_role_v1(
    const struct plamen_source_bootstrap_installed_authority_v1 *authority,
    uint16_t role,
    int installed_payload_fd,
    int installed_producer_receipt_fd,
    int installed_source_manifest_fd,
    struct plamen_source_bootstrap_installed_projection_v1 *projection)
{
    struct plamen_source_bootstrap_receipt_v1 observed;
    struct plamen_source_bootstrap_fd_identity_v1 payload_identity;
    struct plamen_source_bootstrap_fd_identity_v1 producer_identity;
    struct plamen_source_bootstrap_fd_identity_v1 manifest_identity;
    if (projection != NULL) {
        memset(projection, 0, sizeof(*projection));
        projection->payload_fd = -1;
        projection->producer_receipt_fd = -1;
        projection->source_manifest_fd = -1;
        projection->coordinator_receipt_fd = -1;
    }
    if (authority == NULL || projection == NULL
            || role >= PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT
            || plamen_source_bootstrap_receipt_read_fd_v1(
                authority->coordinator_receipt_fd, authority->owner_uid,
                &observed) != 0
            || !constant_equal(observed.receipt_sha256,
                authority->binding.receipt_sha256, 32U)
            || !constant_equal(observed.acquisition_roster_sha256,
                authority->binding.acquisition_roster_sha256, 32U)
            || identity_from_fd(installed_payload_fd, authority->owner_uid,
                SOURCE_MAX_BYTES, O_RDONLY, 1, 1, &payload_identity) != 0
            || !same_identity(&payload_identity, &observed.rows[role].payload)
            || writable_handle_count_exact(installed_payload_fd, 0U) != 0
            || identity_from_fd(installed_producer_receipt_fd,
                authority->owner_uid, PRODUCER_RECEIPT_MAX_BYTES, O_RDONLY,
                1, 1, &producer_identity) != 0
            || !same_identity(&producer_identity,
                &observed.rows[role].producer_receipt)
            || writable_handle_count_exact(installed_producer_receipt_fd,
                0U) != 0
            || identity_from_fd(installed_source_manifest_fd,
                authority->owner_uid, SOURCE_MANIFEST_MAX_BYTES, O_RDONLY,
                1, 1, &manifest_identity) != 0
            || !same_identity(&manifest_identity,
                &observed.rows[role].source_manifest)
            || writable_handle_count_exact(installed_source_manifest_fd,
                0U) != 0)
        return -1;
    projection->payload_fd = duplicate_cloexec(installed_payload_fd);
    projection->producer_receipt_fd = duplicate_cloexec(
        installed_producer_receipt_fd);
    projection->source_manifest_fd = duplicate_cloexec(
        installed_source_manifest_fd);
    projection->coordinator_receipt_fd = duplicate_cloexec(
        authority->coordinator_receipt_fd);
    if (projection->payload_fd < 0 || projection->producer_receipt_fd < 0
            || projection->source_manifest_fd < 0
            || projection->coordinator_receipt_fd < 0) {
        plamen_source_bootstrap_installed_projection_dispose_v1(projection);
        return -1;
    }
    projection->ordinal = role;
    memcpy(projection->role, source_roles[role], strlen(source_roles[role]));
    projection->row = observed.rows[role];
    memcpy(projection->coordinator_receipt_sha256,
        authority->binding.receipt_sha256, 32U);
    memcpy(projection->acquisition_roster_sha256,
        authority->binding.acquisition_roster_sha256, 32U);
    memcpy(projection->producer_verifier_key_sha256,
        authority->binding.producer_verifier_key_sha256, 32U);
    memcpy(projection->installed_authority_roster_sha256,
        authority->binding.installed_authority_roster_sha256, 32U);
    memcpy(projection->coordinator_member_identity_sha256,
        authority->binding.coordinator_member_identity_sha256, 32U);
    memcpy(projection->coordinator_code_identity_sha256,
        authority->binding.coordinator_code_identity_sha256, 32U);
    memset(&observed, 0, sizeof(observed));
    return 0;
}

void plamen_source_bootstrap_installed_projection_dispose_v1(
    struct plamen_source_bootstrap_installed_projection_v1 *projection)
{
    if (projection == NULL) return;
    if (projection->payload_fd >= 0) close(projection->payload_fd);
    if (projection->producer_receipt_fd >= 0)
        close(projection->producer_receipt_fd);
    if (projection->source_manifest_fd >= 0)
        close(projection->source_manifest_fd);
    if (projection->coordinator_receipt_fd >= 0)
        close(projection->coordinator_receipt_fd);
    memset(projection, 0, sizeof(*projection));
    projection->payload_fd = -1;
    projection->producer_receipt_fd = -1;
    projection->source_manifest_fd = -1;
    projection->coordinator_receipt_fd = -1;
}

#ifdef PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_MAIN
static int parse_inherited_fd_v1(const char *value)
{
    char *end = NULL; long number;
    if (value == NULL || value[0] == '\0') return -1;
    errno = 0; number = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || number < 3L
            || number > 1048576L || fcntl((int)number, F_GETFD) < 0
            || fcntl((int)number, F_SETFD, FD_CLOEXEC) != 0)
        return -1;
    return (int)number;
}

static void source_bootstrap_cli_diagnostic_v1(void)
{
    static const char message[] = "Plamen native source bootstrap denied.\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1U);
}

/*
 * Setup-only fixed signer command.  Acquisition workers prepare canonical
 * unsigned observations without authority; this signed native executable
 * signs Codex and Claude together under one ephemeral install-generation key.
 * ABI: public (writer,reader), then for roles 5 and 6
 * (unsigned,payload,source-manifest,semantic-writer,semantic-reader).
 */
static int sign_backends_cli_v1(int argc, char **argv)
{
    struct plamen_native_backend_receipt_signer_v1 *signer = NULL;
    struct plamen_native_backend_signed_projection_v1 projections[2];
    int descriptors[12];
    size_t index;
    int result = -1;
    memset(projections, 0, sizeof(projections));
    for (index = 0U; index < 2U; ++index) {
        projections[index].verifier_public_key_fd = -1;
        projections[index].semantic_receipt_fd = -1;
    }
    for (index = 0U; index < 12U; ++index) descriptors[index] = -1;
    if (argc != 14 || strcmp(argv[1], "sign-backends-v1") != 0)
        goto done;
    for (index = 0U; index < 12U; ++index) {
        descriptors[index] = parse_inherited_fd_v1(argv[index + 2U]);
        if (descriptors[index] < 0) goto done;
    }
    if (plamen_native_backend_receipt_signer_create_v1(getuid(),
            descriptors[0], descriptors[1], &signer) != 0) {
        descriptors[0] = -1; goto done;
    }
    descriptors[0] = -1;
    if (plamen_native_backend_receipt_sign_v1(signer,
            PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1, descriptors[2], descriptors[3],
            descriptors[4], descriptors[5], descriptors[6],
            &projections[0]) != 0) {
        descriptors[5] = -1; goto done;
    }
    descriptors[5] = -1;
    if (plamen_native_backend_receipt_sign_v1(signer,
            PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1, descriptors[7], descriptors[8],
            descriptors[9], descriptors[10], descriptors[11],
            &projections[1]) != 0) {
        descriptors[10] = -1; goto done;
    }
    descriptors[10] = -1;
    result = 0;
done:
    for (index = 0U; index < 12U; ++index)
        if (descriptors[index] >= 0) close(descriptors[index]);
    for (index = 0U; index < 2U; ++index)
        plamen_native_backend_signed_projection_dispose_v1(
            &projections[index]);
    plamen_native_backend_receipt_signer_dispose_v1(signer);
    return result;
}

/*
 * Setup-only static EVM producer.  The caller supplies only the retained
 * private generation root and the four reviewed upstream evidence objects:
 * Medusa archive, Medusa Sigstore bundle, solc provider index, solc binary.
 * The native producer authenticates those exact descriptors and creates the
 * six role-8/role-9 leaves below the retained root.  No path or digest is
 * caller-selectable.
 */
static int sign_evm_static_cli_v1(int argc, char **argv)
{
    struct plamen_native_evm_static_projection_v1 projection;
    int descriptors[5] = {-1, -1, -1, -1, -1};
    size_t index;
    int result = -1;
    memset(&projection, 0, sizeof(projection));
    for (index = 0U; index <
            PLAMEN_NATIVE_EVM_STATIC_ACQUISITION_V1_ROLE_COUNT; ++index) {
        projection.roles[index].payload_fd = -1;
        projection.roles[index].producer_receipt_fd = -1;
        projection.roles[index].source_manifest_fd = -1;
    }
    if (argc != 7 || strcmp(argv[1], "sign-evm-static-v1") != 0)
        goto done;
    for (index = 0U; index < 5U; ++index) {
        descriptors[index] = parse_inherited_fd_v1(argv[index + 2U]);
        if (descriptors[index] < 0) goto done;
    }
    if (plamen_native_evm_static_acquisition_issue_v1(getuid(),
            descriptors[0], descriptors[1], descriptors[2], descriptors[3],
            descriptors[4], &projection) != 0)
        goto done;
    result = 0;
done:
    plamen_native_evm_static_projection_dispose_v1(&projection);
    for (index = 0U; index < 5U; ++index)
        if (descriptors[index] >= 0) close(descriptors[index]);
    return result;
}

/*
 * Setup-only producer for fixed roles 0-4, 7 and 10.  ABI:
 *
 *   1: sign-fixed-roles-v1
 *   2: retained private staged-generation root
 *   3..30: seven ordered
 *      (payload, semantic receipt, source manifest, reviewed policy) tuples
 *
 * No digest, role, policy, path, mode or schema is caller selectable.
 */
static int sign_fixed_roles_cli_v1(int argc, char **argv)
{
    struct plamen_native_fixed_role_input_v1 inputs[
        PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT];
    struct plamen_native_fixed_role_projection_v1 projection;
    static const uint16_t roles[
        PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT] = {
        PLAMEN_SOURCE_BOOTSTRAP_BASE_ROOTFS_V1,
        PLAMEN_SOURCE_BOOTSTRAP_DEBIAN_PACKAGE_STATE_V1,
        PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_GUEST_V1,
        PLAMEN_SOURCE_BOOTSTRAP_CPYTHON_V1,
        PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_PACKAGE_V1,
        PLAMEN_SOURCE_BOOTSTRAP_FOUNDRY_V1,
        PLAMEN_SOURCE_BOOTSTRAP_AMD64_COMPAT_V1
    };
    int descriptors[1U
        + PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT * 4U];
    size_t index, offset;
    int result = -1;
    memset(inputs, 0, sizeof(inputs));
    memset(&projection, 0, sizeof(projection));
    for (index = 0U; index < sizeof(descriptors) / sizeof(descriptors[0]);
            ++index) descriptors[index] = -1;
    for (index = 0U;
            index < PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT;
            ++index) {
        projection.roles[index].payload_fd = -1;
        projection.roles[index].producer_receipt_fd = -1;
        projection.roles[index].source_manifest_fd = -1;
    }
    if (argc != 31 || strcmp(argv[1], "sign-fixed-roles-v1") != 0)
        goto done;
    for (index = 0U; index < sizeof(descriptors) / sizeof(descriptors[0]);
            ++index) {
        descriptors[index] = parse_inherited_fd_v1(argv[index + 2U]);
        if (descriptors[index] < 0) goto done;
    }
    for (index = 0U;
            index < PLAMEN_NATIVE_FIXED_ROLE_ACQUISITION_V1_ROLE_COUNT;
            ++index) {
        offset = 1U + index * 4U;
        inputs[index].role = roles[index];
        inputs[index].payload_fd = descriptors[offset];
        inputs[index].semantic_receipt_fd = descriptors[offset + 1U];
        inputs[index].source_manifest_fd = descriptors[offset + 2U];
        inputs[index].reviewed_policy_fd = descriptors[offset + 3U];
    }
    if (plamen_native_fixed_role_acquisition_issue_v1(getuid(),
            descriptors[0], inputs, &projection) != 0) goto done;
    result = 0;
done:
    plamen_native_fixed_role_projection_dispose_v1(&projection);
    for (index = 0U; index < sizeof(descriptors) / sizeof(descriptors[0]);
            ++index)
        if (descriptors[index] >= 0) close(descriptors[index]);
    memset(inputs, 0, sizeof(inputs));
    return result;
}

/*
 * Fixed inherited-descriptor ABI.  No path, policy, digest, schema, command,
 * executable, environment value, or callback is caller-selectable:
 *
 *   1: issue-v1
 *   2..4: authenticated runtime-root, managed-Python, transform member
 *   5: install-generation Ed25519 producer-verifier public key
 *   6: composition manifest
 *   7..39: 11 (payload, producer receipt, source manifest) triples
 *   40..49: 5 already-unlinked private-store (output writer, reader) pairs
 *   50..73: 24 scratch writers
 *   74..75: coordinator receipt writer/reader
 *   76..77: already-unlinked private grouped-operation writer/reader
 *   78..79: already-unlinked private operation-terminal writer/reader
 */
int main(int argc, char **argv)
{
    struct plamen_source_bootstrap_issue_request_v1 request;
    struct plamen_source_bootstrap_receipt_v1 receipt;
    struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_native_operation4_context_v1 *operation = NULL;
    int runtime_root_fd, python_fd, transform_fd;
    int grouped_writer_fd, grouped_reader_fd;
    int terminal_writer_fd, terminal_reader_fd;
    size_t index; int result = 1;
    memset(&request, 0, sizeof(request)); memset(&receipt, 0, sizeof(receipt));
    if (argc > 1 && strcmp(argv[1], "sign-backends-v1") == 0) {
        result = sign_backends_cli_v1(argc, argv) == 0 ? 0 : 1;
        goto done;
    }
    if (argc > 1 && strcmp(argv[1], "sign-evm-static-v1") == 0) {
        result = sign_evm_static_cli_v1(argc, argv) == 0 ? 0 : 1;
        goto done;
    }
    if (argc > 1 && strcmp(argv[1], "sign-fixed-roles-v1") == 0) {
        result = sign_fixed_roles_cli_v1(argc, argv) == 0 ? 0 : 1;
        goto done;
    }
    if (argc != 80 || strcmp(argv[1], "issue-v1") != 0) goto done;
    runtime_root_fd = parse_inherited_fd_v1(argv[2]);
    python_fd = parse_inherited_fd_v1(argv[3]);
    transform_fd = parse_inherited_fd_v1(argv[4]);
    request.producer_verifier_key_fd = parse_inherited_fd_v1(argv[5]);
    request.composition_manifest_fd = parse_inherited_fd_v1(argv[6]);
    grouped_writer_fd = parse_inherited_fd_v1(argv[76]);
    grouped_reader_fd = parse_inherited_fd_v1(argv[77]);
    terminal_writer_fd = parse_inherited_fd_v1(argv[78]);
    terminal_reader_fd = parse_inherited_fd_v1(argv[79]);
    if (runtime_root_fd < 0 || python_fd < 0 || transform_fd < 0
            || request.producer_verifier_key_fd < 0
            || request.composition_manifest_fd < 0 || grouped_writer_fd < 0
            || grouped_reader_fd < 0 || terminal_writer_fd < 0
            || terminal_reader_fd < 0
            || plamen_native_operation4_context_create_fixed_v1(getuid(),
                runtime_root_fd, python_fd, transform_fd,
                request.producer_verifier_key_fd,
                grouped_writer_fd, grouped_reader_fd,
                terminal_writer_fd, terminal_reader_fd, &operation) != 0)
        goto done;
    /* The context owns duplicates; eliminate caller-known writable aliases. */
    close(runtime_root_fd); close(python_fd); close(transform_fd);
    close(grouped_writer_fd); close(grouped_reader_fd);
    close(terminal_writer_fd); close(terminal_reader_fd);
    if (plamen_native_operation4_policy_fill_fixed_v1(operation,
            request.inputs) != 0) goto done;
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;
            ++index) {
        request.inputs[index].payload_fd = parse_inherited_fd_v1(
            argv[7U + index * 3U]);
        request.inputs[index].producer_receipt_fd = parse_inherited_fd_v1(
            argv[8U + index * 3U]);
        request.inputs[index].source_manifest_fd = parse_inherited_fd_v1(
            argv[9U + index * 3U]);
        if (request.inputs[index].payload_fd < 0
                || request.inputs[index].producer_receipt_fd < 0
                || request.inputs[index].source_manifest_fd < 0) goto done;
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) {
        request.output_writer_fds[index] = parse_inherited_fd_v1(
            argv[40U + index * 2U]);
        request.output_reader_fds[index] = parse_inherited_fd_v1(
            argv[41U + index * 2U]);
        if (request.output_writer_fds[index] < 0
                || request.output_reader_fds[index] < 0) goto done;
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT;
            ++index) {
        request.scratch_fds[index] = parse_inherited_fd_v1(argv[50U + index]);
        if (request.scratch_fds[index] < 0) goto done;
    }
    request.receipt_writer_fd = parse_inherited_fd_v1(argv[74]);
    request.receipt_reader_fd = parse_inherited_fd_v1(argv[75]);
    if (request.receipt_writer_fd < 0 || request.receipt_reader_fd < 0
            || plamen_native_operation4_executable_sha256_fixed_v1(operation,
                request.operation4.executable_sha256) != 0) goto done;
    request.owner_uid = getuid();
    request.policy_authority.context = operation;
    request.policy_authority.authenticate_source =
        plamen_native_operation4_authenticate_source_fixed_v1;
    request.policy_authority.authenticate_operation4 =
        plamen_native_operation4_authenticate_executable_fixed_v1;
    request.operation4.context = operation;
    request.operation4.invoke = plamen_native_operation4_invoke_fixed_v1;
    request.operation4.rejoin_terminal_outputs =
        plamen_native_operation4_rejoin_terminal_outputs_fixed_v1;
    if (plamen_source_bootstrap_coordinator_issue_v1(
            &request, &authority, &receipt) != 0) goto done;
    result = 0;
done:
    plamen_source_bootstrap_authority_dispose_v1(authority);
    plamen_native_operation4_context_dispose_v1(operation);
    memset(&request, 0, sizeof(request)); memset(&receipt, 0, sizeof(receipt));
    if (result != 0) source_bootstrap_cli_diagnostic_v1();
    return result;
}
#endif
