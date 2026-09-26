#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_specialized_runtime_authority.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ROLE8_MAX_SIZE \
    (PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE \
        + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE \
        + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_TRAILER_SIZE \
        + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES \
            * PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE)

static const uint8_t authority_domain[] =
    "PLAMEN-BROKER-V2-SPECIALIZED-RUNTIME-AUTHORITY-V1\0";
static const char fixed_init_reference[] = "/usr/local/libexec/plamen-guest";

static int
all_zero(const uint8_t *value, size_t size)
{
    uint8_t aggregate = 0;
    size_t index;
    for (index = 0; index < size; ++index) aggregate |= value[index];
    return aggregate == 0;
}

static int
constant_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < size; ++index) difference |= left[index] ^ right[index];
    return difference == 0;
}

static int
same_stat(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino
        && left->st_mode == right->st_mode && left->st_uid == right->st_uid
        && left->st_gid == right->st_gid && left->st_nlink == right->st_nlink
        && left->st_size == right->st_size
        && left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec
        && left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec
        && left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec
        && left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
}

static int
read_fd_exact(int descriptor, size_t maximum, uint8_t **bytes_out,
    size_t *size_out, uint8_t sha256[32], struct stat *identity_out)
{
    CC_SHA256_CTX digest;
    struct stat before, after;
    uint8_t *bytes = NULL;
    size_t offset = 0, size;
    int flags, status = -1;
    if (bytes_out != NULL) *bytes_out = NULL;
    if (size_out != NULL) *size_out = 0;
    if (sha256 != NULL) memset(sha256, 0, 32);
    if (descriptor < 0 || bytes_out == NULL || size_out == NULL
        || sha256 == NULL || identity_out == NULL
        || (flags = fcntl(descriptor, F_GETFL)) < 0
        || (flags & O_ACCMODE) != O_RDONLY
        || fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_nlink != 1 || before.st_size <= 0
        || (uint64_t)before.st_size > maximum)
        return -1;
    size = (size_t)before.st_size;
    bytes = malloc(size);
    if (bytes == NULL || CC_SHA256_Init(&digest) != 1) goto done;
    while (offset < size) {
        ssize_t amount = pread(descriptor, bytes + offset,
            size - offset, (off_t)offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0 || CC_SHA256_Update(&digest, bytes + offset,
                (CC_LONG)amount) != 1) goto done;
        offset += (size_t)amount;
    }
    if (CC_SHA256_Final(sha256, &digest) != 1
        || fstat(descriptor, &after) != 0 || !same_stat(&before, &after))
        goto done;
    *bytes_out = bytes; bytes = NULL; *size_out = size;
    *identity_out = after; status = 0;
done:
    if (bytes != NULL) {
        memset(bytes, 0, size); free(bytes);
    }
    if (status != 0) memset(sha256, 0, 32);
    return status;
}

static int
hash_policy_fd(int generation_fd, uint8_t output[32])
{
    uint8_t *bytes = NULL, digest[32];
    size_t size = 0;
    struct stat root, policy_dir_info, policy_info;
    int policy_dir = -1, policy = -1, result = -1;
    memset(digest, 0, sizeof(digest));
    if (generation_fd < 0 || output == NULL
        || fstat(generation_fd, &root) != 0 || !S_ISDIR(root.st_mode)
        || (policy_dir = openat(generation_fd, "verification_policy",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || fstat(policy_dir, &policy_dir_info) != 0
        || !S_ISDIR(policy_dir_info.st_mode)
        || policy_dir_info.st_uid != root.st_uid
        || (policy = openat(policy_dir, "native_runtime_bindings.v2.json",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || read_fd_exact(policy, 64U * 1024U * 1024U, &bytes, &size,
            digest, &policy_info) != 0
        || policy_info.st_uid != root.st_uid
        || (policy_info.st_mode & 0022) != 0)
        goto done;
    memcpy(output, digest, 32); result = 0;
done:
    if (bytes != NULL) { memset(bytes, 0, size); free(bytes); }
    if (policy >= 0) (void)close(policy);
    if (policy_dir >= 0) (void)close(policy_dir);
    memset(digest, 0, sizeof(digest));
    if (result != 0) memset(output, 0, 32);
    return result;
}

static int
auxiliary_matches(const struct stat *identity, const uint8_t sha256[32],
    const struct plamen_install_receipt_specialized_authority *auxiliary,
    const uint8_t role8_sha256[32],
    const struct plamen_runtime_package_bindings_v2 *bindings)
{
    return identity != NULL && sha256 != NULL && auxiliary != NULL
        && bindings != NULL && bindings->specialized_present == 1U
        && strcmp(auxiliary->relative_path,
            PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_RECEIPT_PATH) == 0
        && bindings->specialized_member_receipt_path_size
            == sizeof(PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_RECEIPT_PATH) - 1U
        && memcmp(auxiliary->relative_path,
            bindings->specialized_member_receipt_path,
            bindings->specialized_member_receipt_path_size) == 0
        && constant_equal(auxiliary->runtime_package_manifest_sha256,
            role8_sha256, 32)
        && constant_equal(auxiliary->sha256, sha256, 32)
        && auxiliary->size == (uint64_t)identity->st_size
        && auxiliary->device == (uint64_t)identity->st_dev
        && auxiliary->inode == (uint64_t)identity->st_ino
        && auxiliary->mode == (uint32_t)(identity->st_mode & 07777)
        && auxiliary->uid == (uint32_t)identity->st_uid
        && auxiliary->gid == (uint32_t)identity->st_gid
        && auxiliary->size == PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE
        && auxiliary->mode == 0400U && identity->st_nlink == 1;
}

static int
authority_digest(
    const struct plamen_broker_v2_specialized_runtime_authority *authority,
    uint8_t output[32])
{
    CC_SHA256_CTX digest;
    size_t reference_size, init_size;
    uint8_t architecture[2];
    if (authority != NULL) {
        architecture[0] = (uint8_t)(authority->target_arch >> 8);
        architecture[1] = (uint8_t)authority->target_arch;
    } else {
        architecture[0] = architecture[1] = 0;
    }
    if (authority == NULL || output == NULL
        || (reference_size = strlen(authority->oci_image_reference)) == 0
        || (init_size = strlen(authority->oci_init_reference)) == 0
        || CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, authority_domain,
            sizeof(authority_domain)) != 1
        || CC_SHA256_Update(&digest, architecture,
            sizeof(architecture)) != 1
        || CC_SHA256_Update(&digest, authority->oci_image_reference,
            (CC_LONG)reference_size) != 1
        || CC_SHA256_Update(&digest, authority->oci_init_reference,
            (CC_LONG)init_size) != 1
        || CC_SHA256_Update(&digest, authority->runtime_manifest_sha256,
            32) != 1
        || CC_SHA256_Update(&digest, authority->runtime_manifest_tree_sha256,
            32) != 1
        || CC_SHA256_Update(&digest, authority->image_member_receipt_sha256,
            32) != 1
        || CC_SHA256_Update(&digest, authority->member_roster_sha256, 32) != 1
        || CC_SHA256_Update(&digest, authority->frozen_policy_sha256, 32) != 1
        || CC_SHA256_Update(&digest, authority->frozen_policy_bytes_sha256,
            32) != 1
        || CC_SHA256_Update(&digest, authority->runtime_digests,
            sizeof(authority->runtime_digests)) != 1
        || CC_SHA256_Final(output, &digest) != 1)
        return -1;
    return all_zero(output, 32) ? -1 : 0;
}

int
plamen_broker_v2_specialized_runtime_authority_load(
    const struct plamen_broker_v2_specialized_runtime_authority_open *open,
    struct plamen_broker_v2_specialized_runtime_authority *output)
{
    struct plamen_runtime_package_manifest_result_v2 manifest_result;
    struct plamen_runtime_package_bindings_v2 bindings;
    struct plamen_image_member_receipt_v2_expected member_expected;
    struct stat role8_identity, member_identity;
    uint8_t *role8_bytes = NULL, *member_bytes = NULL;
    uint8_t role8_sha256[32], member_sha256[32], policy_bytes_sha256[32];
    size_t role8_size = 0, member_size = 0;
    int status = -1;
    if (output != NULL) memset(output, 0, sizeof(*output));
    memset(&manifest_result, 0, sizeof(manifest_result));
    memset(&bindings, 0, sizeof(bindings));
    memset(&member_expected, 0, sizeof(member_expected));
    memset(&role8_identity, 0, sizeof(role8_identity));
    memset(&member_identity, 0, sizeof(member_identity));
    memset(role8_sha256, 0, sizeof(role8_sha256));
    memset(member_sha256, 0, sizeof(member_sha256));
    memset(policy_bytes_sha256, 0, sizeof(policy_bytes_sha256));
    if (open == NULL || output == NULL
        || open->version !=
            PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_AUTHORITY_VERSION
        || open->generation_fd < 0 || open->runtime_manifest_fd < 0
        || open->runtime_manifest_member == NULL
        || open->runtime_manifest_member->role !=
            PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST
        || open->image_member_receipt_fd < 0 || open->auxiliary == NULL
        || open->runtime_manifest_fd == open->image_member_receipt_fd
        || plamen_install_receipt_member_revalidate(
            open->runtime_manifest_fd,
            open->runtime_manifest_member) != 0
        || plamen_runtime_package_manifest_revalidate_v2(
            open->generation_fd, open->runtime_manifest_fd,
            open->runtime_manifest_member->uid, &manifest_result) != 0
        || read_fd_exact(open->runtime_manifest_fd, ROLE8_MAX_SIZE,
            &role8_bytes, &role8_size, role8_sha256, &role8_identity) != 0
        || !constant_equal(role8_sha256,
            open->runtime_manifest_member->sha256, 32)
        || plamen_runtime_package_manifest_decode_bindings_exact_v2(
            role8_bytes, role8_size, &manifest_result, &bindings) != 0
        || bindings.specialized_present != 1U
        || bindings.target_arch !=
            PLAMEN_RUNTIME_PACKAGE_TARGET_ARCH_ARM64_V2
        || bindings.oci_init_reference_size != sizeof(fixed_init_reference) - 1U
        || memcmp(bindings.oci_init_reference, fixed_init_reference,
            sizeof(fixed_init_reference) - 1U) != 0
        || hash_policy_fd(open->generation_fd, policy_bytes_sha256) != 0
        || !constant_equal(policy_bytes_sha256,
            bindings.specialized_policy_bytes_sha256, 32)
        || read_fd_exact(open->image_member_receipt_fd,
            PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE, &member_bytes, &member_size,
            member_sha256, &member_identity) != 0
        || member_size != PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE
        || !auxiliary_matches(&member_identity, member_sha256,
            open->auxiliary, role8_sha256, &bindings))
        goto done;
    memcpy(member_expected.oci_manifest_sha256,
        bindings.digests[PLAMEN_RUNTIME_PACKAGE_IMAGE_MANIFEST_V2], 32);
    memcpy(member_expected.runtime_package_manifest_sha256, role8_sha256, 32);
    memcpy(member_expected.image_closure_sha256,
        bindings.digests[PLAMEN_RUNTIME_PACKAGE_IMAGE_CLOSURE_V2], 32);
    memcpy(member_expected.closure_census_sha256,
        bindings.digests[PLAMEN_RUNTIME_PACKAGE_CLOSURE_CENSUS_V2], 32);
    memcpy(member_expected.materialization_receipt_sha256,
        bindings.digests[PLAMEN_RUNTIME_PACKAGE_MATERIALIZATION_RECEIPT_V2], 32);
    memcpy(member_expected.roster_sha256,
        bindings.specialized_roster_sha256, 32);
    memcpy(member_expected.policy_sha256,
        bindings.specialized_policy_self_sha256, 32);
    if (plamen_image_member_receipt_v2_validate(member_bytes, member_size,
            &member_expected, &output->image_members) != 0
        || bindings.oci_image_reference_size == 0
        || bindings.oci_image_reference_size
            >= sizeof(output->oci_image_reference)
        || bindings.oci_init_reference_size == 0
        || bindings.oci_init_reference_size
            >= sizeof(output->oci_init_reference))
        goto done;
    output->version =
        PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_AUTHORITY_VERSION;
    output->target_arch = bindings.target_arch;
    memcpy(output->oci_image_reference, bindings.oci_image_reference,
        bindings.oci_image_reference_size);
    memcpy(output->oci_init_reference, bindings.oci_init_reference,
        bindings.oci_init_reference_size);
    memcpy(output->runtime_manifest_sha256, role8_sha256, 32);
    memcpy(output->runtime_manifest_tree_sha256,
        manifest_result.tree_sha256, 32);
    memcpy(output->image_member_receipt_sha256, member_sha256, 32);
    memcpy(output->member_roster_sha256,
        bindings.specialized_roster_sha256, 32);
    memcpy(output->frozen_policy_sha256,
        bindings.specialized_policy_self_sha256, 32);
    memcpy(output->frozen_policy_bytes_sha256,
        bindings.specialized_policy_bytes_sha256, 32);
    memcpy(output->runtime_digests, bindings.digests,
        sizeof(output->runtime_digests));
    if (authority_digest(output, output->authority_sha256) != 0) goto done;
    status = 0;
done:
    if (role8_bytes != NULL) {
        memset(role8_bytes, 0, role8_size); free(role8_bytes);
    }
    if (member_bytes != NULL) {
        memset(member_bytes, 0, member_size); free(member_bytes);
    }
    memset(&manifest_result, 0, sizeof(manifest_result));
    memset(&bindings, 0, sizeof(bindings));
    memset(&member_expected, 0, sizeof(member_expected));
    memset(&role8_identity, 0, sizeof(role8_identity));
    memset(&member_identity, 0, sizeof(member_identity));
    memset(role8_sha256, 0, sizeof(role8_sha256));
    memset(member_sha256, 0, sizeof(member_sha256));
    memset(policy_bytes_sha256, 0, sizeof(policy_bytes_sha256));
    if (status != 0) memset(output, 0, sizeof(*output));
    return status;
}
