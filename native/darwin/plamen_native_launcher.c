#include "../include/plamen_broker_v2.h"
#include "plamen_broker_v2_install_receipt.h"
#include "plamen_native_deployment_receipt_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/random.h>
#include <unistd.h>
#include <xpc/xpc.h>

#ifndef POSIX_SPAWN_CLOEXEC_DEFAULT
#define POSIX_SPAWN_CLOEXEC_DEFAULT 0x4000
#endif

#define PLAMEN_LAUNCHER_HARDSTOP 78
#define PLAMEN_LAUNCHER_XPC_TIMEOUT_NS (UINT64_C(5) * NSEC_PER_SEC)
#define PLAMEN_LAUNCHER_SUFFIX "/bin/plamen-native-launcher"
#define PLAMEN_LAUNCHER_CONFIG_MAX (UINT32_C(256) * UINT32_C(1024))
#define PLAMEN_LAUNCHER_CODEX_PROFILE_RELATIVE \
    "lib/plamen/runtime/profiles/codex-v2.bin"
#define PLAMEN_LAUNCHER_CODEX_PROFILE_MANIFEST_PATH \
    "profiles/codex-v2.bin"
#define PLAMEN_LAUNCHER_CLAUDE_PROFILE_RELATIVE \
    "lib/plamen/runtime/profiles/claude-v2.bin"
#define PLAMEN_LAUNCHER_CLAUDE_PROFILE_MANIFEST_PATH \
    "profiles/claude-v2.bin"
#define PLAMEN_LAUNCHER_EXTERNAL_PROFILE_SIZE 2048U
#define PLAMEN_LAUNCHER_EXTERNAL_PROFILE_HASHED_SIZE 2016U
#define PLAMEN_LAUNCHER_RUNTIME_MANIFEST_HEADER_SIZE 256U
#define PLAMEN_LAUNCHER_RUNTIME_MANIFEST_BINDING_SIZE 2048U
#define PLAMEN_LAUNCHER_RUNTIME_MANIFEST_ROW_SIZE 640U
#define PLAMEN_LAUNCHER_GENERATED_MAX 4096U
#define PLAMEN_LAUNCHER_CLAUDE_CREDENTIAL_MAX \
    (UINT32_C(1024) * UINT32_C(1024))
#define PLAMEN_LAUNCHER_CREDENTIAL_MAX \
    (UINT32_C(16) * UINT32_C(1024) * UINT32_C(1024))
#define PLAMEN_LAUNCHER_AUTHORITY_DIRECTORY "launcher-authority-v2"
#define PLAMEN_LAUNCHER_PROVIDER_PATH "/usr/local/bin/container"
#define PLAMEN_LAUNCHER_CLAUDE_KEYCHAIN_SERVICE "Claude Code-credentials"
static const uint8_t plamen_launcher_backend_acquisition_policy_sha256[32] = {
    0x20, 0xe6, 0xdc, 0xb3, 0xdb, 0x56, 0x22, 0x5d,
    0x56, 0x15, 0xe5, 0x8c, 0x5b, 0xf5, 0x6f, 0xf1,
    0xbc, 0x58, 0x54, 0xcf, 0x55, 0x0a, 0xbf, 0x41,
    0xaf, 0xc8, 0x0e, 0x4e, 0xfb, 0x7c, 0xee, 0x61
};

/*
 * This object must eventually arrive from a native installer/launch authority.
 * It is intentionally private and has no argv, environment, file, Python,
 * callback, token-table, or public constructor path.
 */
struct plamen_launcher_authority {
    struct plamen_install_receipt receipt;
    uint8_t installed_closure_sha256[32];
    uint8_t committed_audit_generation_sha256[32];
    uint8_t audit_request_fingerprint[32];
    uint8_t prior_audit_checkpoint_sha256[32];
    uint8_t python_executable_sha256[32];
    uint8_t python_entrypoint_sha256[32];
    uint8_t python_argv_sha256[32];
    uint8_t python_environment_sha256[32];
    uint8_t broker_closure_sha256[32];
    uint8_t installation_receipt_sha256[32];
    uint8_t request_projection_sha256[32];
    uint8_t commitment_sha256[32];
    uint16_t commitment_size;
    uint8_t commitment[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    uint8_t *request_projection;
    size_t request_projection_size;
    uint16_t authority_presence_mask;
    int authority_fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    uint8_t authority_identities
        [PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT][32];
    char python_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char entrypoint_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char config_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    uint16_t startup_intent;
    int generation_fd;
    int receipt_fd;
    int config_fd;
    int member_fds[PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT];
    char python_code_requirement[512];
    char broker_code_requirement[512];
};

struct plamen_launcher_code_identity {
    uint8_t cdhash[32];
    uint32_t cdhash_size;
    char identifier[256];
    char team[256];
};

struct plamen_launcher_external_profile {
    uint8_t provider_sha256[32];
    uint8_t backend_sha256[32];
    uint8_t provider_cdhash[32];
    uint8_t backend_cdhash[32];
    uint8_t backend_acquisition_policy_sha256[32];
    uint16_t provider_cdhash_size;
    uint16_t backend_cdhash_size;
    char provider_identifier[129];
    char provider_team[129];
    char provider_version[129];
    char backend_identifier[129];
    char backend_team[129];
    char backend_version[129];
    char backend_release[257];
    char backend_selector[33];
    char provider_selector[33];
};

static int dynamic_code_identity(pid_t, const char *,
    struct plamen_launcher_code_identity *);
static int static_code_identity(const char *, const char *,
    struct plamen_launcher_code_identity *);

static char *const closed_environment[] = { NULL };

static int
constant_equal(const void *left_value, const void *right_value, size_t size)
{
    const uint8_t *left = left_value;
    const uint8_t *right = right_value;
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < size; index++)
        difference |= left[index] ^ right[index];
    return difference == 0;
}

static int
all_zero(const uint8_t value[32])
{
    uint8_t zero[32] = { 0 };
    return constant_equal(value, zero, sizeof(zero));
}

static int
same_peer(const struct plamen_broker_v2_peer_identity *left,
    const struct plamen_broker_v2_peer_identity *right)
{
    return left->pid == right->pid && left->uid == right->uid
        && left->gid == right->gid && left->birth_kind == right->birth_kind
        && left->birth_primary == right->birth_primary
        && left->birth_secondary == right->birth_secondary
        && constant_equal(left->boot_id_sha256, right->boot_id_sha256, 32);
}

static int
same_vnode(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino
        && (left->st_mode & S_IFMT) == (right->st_mode & S_IFMT)
        && left->st_uid == right->st_uid && left->st_gid == right->st_gid;
}

static int
sha256_fd(int descriptor, uint8_t output[32])
{
    CC_SHA256_CTX context;
    struct stat before, after;
    uint8_t buffer[65536];
    off_t offset = 0;

    if (fstat(descriptor, &before) < 0 || !S_ISREG(before.st_mode)
        || before.st_size < 0 || CC_SHA256_Init(&context) != 1)
        return -1;
    while (offset < before.st_size) {
        size_t wanted = sizeof(buffer);
        ssize_t amount;
        if ((off_t)wanted > before.st_size - offset)
            wanted = (size_t)(before.st_size - offset);
        do {
            amount = pread(descriptor, buffer, wanted, offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0
            || CC_SHA256_Update(&context, buffer, (CC_LONG)amount) != 1)
            return -1;
        offset += amount;
    }
    if (fstat(descriptor, &after) < 0 || !same_vnode(&before, &after)
        || before.st_size != after.st_size
        || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
        || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
        || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec
        || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec
        || CC_SHA256_Final(output, &context) != 1)
        return -1;
    return 0;
}

static int
sha256_bytes(const void *bytes, size_t size, uint8_t output[32])
{
    return CC_SHA256(bytes, (CC_LONG)size, output) == output ? 0 : -1;
}

static int
peer_identity(pid_t pid, struct plamen_broker_v2_peer_identity *identity)
{
    struct proc_bsdinfo information;
    int amount;
    memset(&information, 0, sizeof(information));
    memset(identity, 0, sizeof(*identity));
    amount = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &information,
        (int)sizeof(information));
    if (amount != (int)sizeof(information)
        || information.pbi_pid != (uint32_t)pid
        || information.pbi_start_tvsec == 0)
        return -1;
    identity->pid = (uint64_t)pid;
    identity->uid = information.pbi_uid;
    identity->gid = information.pbi_gid;
    identity->birth_kind = PLAMEN_BROKER_V2_BIRTH_DARWIN_EPOCH;
    identity->birth_primary = information.pbi_start_tvsec;
    identity->birth_secondary =
        (uint64_t)information.pbi_start_tvusec * UINT64_C(1000);
    return identity->birth_secondary < UINT64_C(1000000000) ? 0 : -1;
}

static int
digest_fixed_invocation(const struct plamen_launcher_authority *authority,
    uint8_t argv_digest[32], uint8_t environment_digest[32])
{
    return authority == NULL ? -1
        : plamen_install_receipt_python_invocation_digests(
            &authority->receipt, argv_digest, environment_digest);
}

static int
same_vnode_exact(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino
        && left->st_mode == right->st_mode && left->st_uid == right->st_uid
        && left->st_gid == right->st_gid && left->st_nlink == right->st_nlink
        && left->st_size == right->st_size;
}

static int
read_receipt_exact(int fd, uint8_t output[PLAMEN_INSTALL_RECEIPT_SIZE])
{
    struct stat before, after;
    size_t offset = 0;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size != PLAMEN_INSTALL_RECEIPT_SIZE
        || before.st_nlink != 1 || before.st_uid != geteuid()
        || (before.st_mode & 0777) != 0400)
        return -1;
    while (offset < PLAMEN_INSTALL_RECEIPT_SIZE) {
        ssize_t amount;
        do {
            amount = pread(fd, output + offset,
                PLAMEN_INSTALL_RECEIPT_SIZE - offset, (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            return -1;
        offset += (size_t)amount;
    }
    return pread(fd, output, 1, PLAMEN_INSTALL_RECEIPT_SIZE) == 0
        && fstat(fd, &after) == 0 && same_vnode_exact(&before, &after)
        ? 0 : -1;
}

static int
open_relative_file(int root_fd, const char *relative, int *output)
{
    char copy[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char *part, *slash;
    int current = -1, next = -1, result = -1;

    *output = -1;
    if (root_fd < 0 || relative == NULL || relative[0] == '\0'
        || relative[0] == '/' || strlen(relative) >= sizeof(copy))
        return -1;
    memcpy(copy, relative, strlen(relative) + 1);
    current = openat(root_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0)
        goto done;
    part = copy;
    while ((slash = strchr(part, '/')) != NULL) {
        *slash = '\0';
        if (part[0] == '\0' || strcmp(part, ".") == 0
            || strcmp(part, "..") == 0)
            goto done;
        next = openat(current, part,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0)
            goto done;
        close(current);
        current = next;
        part = slash + 1;
    }
    if (part[0] == '\0' || strcmp(part, ".") == 0
        || strcmp(part, "..") == 0)
        goto done;
    next = openat(current, part, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (next < 0)
        goto done;
    *output = next;
    next = -1;
    result = 0;
done:
    if (next >= 0)
        close(next);
    if (current >= 0)
        close(current);
    memset(copy, 0, sizeof(copy));
    return result;
}

static int
open_install_root_from_generation(int generation_fd, int *root_fd)
{
    struct stat generations_info, root_info;
    int generations_fd = -1, candidate = -1, result = -1;

    *root_fd = -1;
    generations_fd = openat(generation_fd, "..",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (generations_fd < 0 || fstat(generations_fd, &generations_info) != 0
        || !S_ISDIR(generations_info.st_mode)
        || generations_info.st_uid != geteuid()
        || (generations_info.st_mode & 0022) != 0)
        goto done;
    candidate = openat(generations_fd, "..",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (candidate < 0 || fstat(candidate, &root_info) != 0
        || !S_ISDIR(root_info.st_mode) || root_info.st_uid != geteuid()
        || (root_info.st_mode & 0777) != 0700)
        goto done;
    *root_fd = candidate;
    candidate = -1;
    result = 0;
done:
    if (candidate >= 0)
        close(candidate);
    if (generations_fd >= 0)
        close(generations_fd);
    return result;
}

static int
canonical_absolute_path(const char *path)
{
    size_t size;
    if (path == NULL || path[0] != '/')
        return 0;
    size = strlen(path);
    return size > 1 && size <= PLAMEN_INSTALL_RECEIPT_PATH_MAX
        && path[size - 1] != '/' && strstr(path, "//") == NULL
        && strstr(path, "/./") == NULL && strstr(path, "/../") == NULL
        && strcmp(path + (size > 2 ? size - 2 : 0), "/.") != 0
        && strcmp(path + (size > 3 ? size - 3 : 0), "/..") != 0;
}

static int
open_absolute_file(const char *path, size_t maximum_size, int *output)
{
    char copy[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char *part, *slash;
    struct stat information;
    int current = -1, next = -1, result = -1;

    *output = -1;
    if (!canonical_absolute_path(path))
        return -1;
    memcpy(copy, path + 1, strlen(path));
    current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0)
        goto done;
    part = copy;
    while ((slash = strchr(part, '/')) != NULL) {
        *slash = '\0';
        next = openat(current, part,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0)
            goto done;
        close(current);
        current = next;
        part = slash + 1;
    }
    next = openat(current, part, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (next < 0 || fstat(next, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink == 0
        || information.st_size <= 0
        || (uint64_t)information.st_size > maximum_size)
        goto done;
    *output = next;
    next = -1;
    result = 0;
done:
    if (next >= 0)
        close(next);
    if (current >= 0)
        close(current);
    memset(copy, 0, sizeof(copy));
    return result;
}

static int
open_absolute_directory(const char *path, int *output)
{
    char copy[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char *part, *slash;
    int current = -1, next = -1, result = -1;

    *output = -1;
    if (!canonical_absolute_path(path))
        return -1;
    memcpy(copy, path + 1, strlen(path));
    current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0)
        goto done;
    part = copy;
    for (;;) {
        slash = strchr(part, '/');
        if (slash != NULL)
            *slash = '\0';
        if (part[0] == '\0' || strcmp(part, ".") == 0
            || strcmp(part, "..") == 0)
            goto done;
        next = openat(current, part,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0)
            goto done;
        close(current);
        current = next;
        next = -1;
        if (slash == NULL)
            break;
        part = slash + 1;
    }
    *output = current;
    current = -1;
    result = 0;
done:
    if (next >= 0)
        close(next);
    if (current >= 0)
        close(current);
    memset(copy, 0, sizeof(copy));
    return result;
}

static int
hex_matches_basename(const char *path, const uint8_t digest[32])
{
    static const char alphabet[] = "0123456789abcdef";
    const char *basename = strrchr(path, '/');
    size_t index;
    if (basename == NULL || strlen(++basename) != 64)
        return 0;
    for (index = 0; index < 32; ++index) {
        if (basename[index * 2] != alphabet[digest[index] >> 4]
            || basename[index * 2 + 1] != alphabet[digest[index] & 15])
            return 0;
    }
    return 1;
}

static void
hex_bytes(const uint8_t *bytes, size_t size, char *output)
{
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < size; ++index) {
        output[index * 2] = alphabet[bytes[index] >> 4];
        output[index * 2 + 1] = alphabet[bytes[index] & 15];
    }
    output[size * 2] = '\0';
}

static uint16_t
load_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t
load_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16)
        | ((uint32_t)bytes[2] << 8) | bytes[3];
}

static uint64_t
load_be64(const uint8_t *bytes)
{
    uint64_t value = 0;
    size_t index;
    for (index = 0; index < 8; ++index)
        value = (value << 8) | bytes[index];
    return value;
}

static int
zero_region(const uint8_t *bytes, size_t size)
{
    uint8_t aggregate = 0;
    size_t index;
    for (index = 0; index < size; ++index)
        aggregate |= bytes[index];
    return aggregate == 0;
}

static int
copy_profile_text(const uint8_t *slot, size_t slot_size, uint16_t size,
    char *output, size_t output_size, int component)
{
    size_t index;
    if (size == 0 || size >= output_size || size > slot_size
        || !zero_region(slot + size, slot_size - size))
        return -1;
    for (index = 0; index < size; ++index) {
        if (slot[index] < 0x20 || slot[index] > 0x7e
            || slot[index] == '\\' || slot[index] == '\n'
            || slot[index] == '\r' || slot[index] == '\t'
            || (component && slot[index] == '/'))
            return -1;
    }
    memcpy(output, slot, size);
    output[size] = '\0';
    return 0;
}

static int
read_external_profile(int profile_fd,
    struct plamen_launcher_external_profile *profile,
    uint8_t profile_sha256[32])
{
    static const uint8_t magic[8] = {
        'P', 'L', 'M', 'B', 'P', 'F', '2', 0
    };
    uint8_t bytes[PLAMEN_LAUNCHER_EXTERNAL_PROFILE_SIZE], trailer[32];
    char expected_release[257];
    struct stat before, after;
    size_t offset = 0;
    ssize_t amount;
    int result = -1;

    memset(profile, 0, sizeof(*profile));
    if (fstat(profile_fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_uid != geteuid() || before.st_nlink != 1
        || (before.st_mode & 07777) != 0400
        || before.st_size != PLAMEN_LAUNCHER_EXTERNAL_PROFILE_SIZE
        || (fcntl(profile_fd, F_GETFL) & O_ACCMODE) != O_RDONLY)
        goto done;
    while (offset < sizeof(bytes)) {
        do {
            amount = pread(profile_fd, bytes + offset,
                sizeof(bytes) - offset, (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            goto done;
        offset += (size_t)amount;
    }
    if (pread(profile_fd, trailer, 1, sizeof(bytes)) != 0
        || fstat(profile_fd, &after) != 0 || !same_vnode_exact(&before, &after)
        || memcmp(bytes, magic, sizeof(magic)) != 0
        || load_be16(bytes + 8) != 2
        || load_be16(bytes + 10) != 256
        || load_be32(bytes + 12) != sizeof(bytes)
        || load_be32(bytes + 16) != 1
        || !zero_region(bytes + 20, 12)
        || !constant_equal(bytes + 182,
            plamen_launcher_backend_acquisition_policy_sha256, 32)
        || !zero_region(bytes + 214, 42)
        || !zero_region(bytes + 1344,
            PLAMEN_LAUNCHER_EXTERNAL_PROFILE_HASHED_SIZE - 1344)
        || sha256_bytes(bytes, PLAMEN_LAUNCHER_EXTERNAL_PROFILE_HASHED_SIZE,
            trailer) != 0
        || !constant_equal(trailer,
            bytes + PLAMEN_LAUNCHER_EXTERNAL_PROFILE_HASHED_SIZE, 32)
        || sha256_bytes(bytes, sizeof(bytes), profile_sha256) != 0)
        goto done;
    memcpy(profile->provider_sha256, bytes + 32, 32);
    memcpy(profile->backend_sha256, bytes + 64, 32);
    memcpy(profile->provider_cdhash, bytes + 96, 32);
    memcpy(profile->backend_cdhash, bytes + 128, 32);
    memcpy(profile->backend_acquisition_policy_sha256, bytes + 182, 32);
    profile->provider_cdhash_size = load_be16(bytes + 160);
    profile->backend_cdhash_size = load_be16(bytes + 162);
    if ((profile->provider_cdhash_size != 20
            && profile->provider_cdhash_size != 32)
        || (profile->backend_cdhash_size != 20
            && profile->backend_cdhash_size != 32)
        || !zero_region(profile->provider_cdhash
            + profile->provider_cdhash_size,
            32 - profile->provider_cdhash_size)
        || !zero_region(profile->backend_cdhash
            + profile->backend_cdhash_size,
            32 - profile->backend_cdhash_size)
        || all_zero(profile->provider_sha256)
        || all_zero(profile->backend_sha256)
        || copy_profile_text(bytes + 256, 128, load_be16(bytes + 164),
            profile->provider_identifier,
            sizeof(profile->provider_identifier), 0) != 0
        || copy_profile_text(bytes + 384, 128, load_be16(bytes + 166),
            profile->provider_team, sizeof(profile->provider_team), 0) != 0
        || copy_profile_text(bytes + 512, 128, load_be16(bytes + 168),
            profile->provider_version, sizeof(profile->provider_version), 0) != 0
        || copy_profile_text(bytes + 640, 128, load_be16(bytes + 170),
            profile->backend_identifier, sizeof(profile->backend_identifier), 0)
            != 0
        || copy_profile_text(bytes + 768, 128, load_be16(bytes + 172),
            profile->backend_team, sizeof(profile->backend_team), 0) != 0
        || copy_profile_text(bytes + 896, 128, load_be16(bytes + 174),
            profile->backend_version, sizeof(profile->backend_version), 0) != 0
        || copy_profile_text(bytes + 1024, 256, load_be16(bytes + 176),
            profile->backend_release, sizeof(profile->backend_release), 1) != 0
        || copy_profile_text(bytes + 1280, 32, load_be16(bytes + 178),
            profile->backend_selector, sizeof(profile->backend_selector), 1) != 0
        || copy_profile_text(bytes + 1312, 32, load_be16(bytes + 180),
            profile->provider_selector, sizeof(profile->provider_selector), 1)
            != 0
        || strcmp(profile->provider_identifier, "com.apple.container.cli") != 0
        || strcmp(profile->provider_team, "UPBK2H6LZM") != 0
        || strncmp(profile->provider_version, "container CLI version ", 22) != 0
        || strcmp(profile->provider_selector, "apple-container-v2") != 0
        || !(
            (strcmp(profile->backend_identifier, "codex") == 0
                && strcmp(profile->backend_team, "2DC432GLL2") == 0
                && strncmp(profile->backend_version, "codex-cli ", 10) == 0
                && strcmp(profile->backend_selector, "codex") == 0
                && snprintf(expected_release, sizeof(expected_release),
                    "%s-aarch64-apple-darwin",
                    profile->backend_version + 10)
                    < (int)sizeof(expected_release)
                && strcmp(profile->backend_release, expected_release) == 0)
            ||
            (strcmp(profile->backend_identifier,
                    "com.anthropic.claude-code") == 0
                && strcmp(profile->backend_team, "Q6L2SF6YDW") == 0
                && strcmp(profile->backend_selector, "claude") == 0
                && snprintf(expected_release, sizeof(expected_release),
                    "%s (Claude Code)", profile->backend_release)
                    < (int)sizeof(expected_release)
                && strcmp(profile->backend_version, expected_release) == 0)
        ))
        goto done;
    result = 0;
done:
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    plamen_broker_v2_secure_zero(trailer, sizeof(trailer));
    plamen_broker_v2_secure_zero(expected_release,
        sizeof(expected_release));
    if (result != 0) {
        plamen_broker_v2_secure_zero(profile, sizeof(*profile));
        plamen_broker_v2_secure_zero(profile_sha256, 32);
    }
    return result;
}

static int
runtime_manifest_binds_profile(int manifest_fd, int profile_fd,
    const struct plamen_launcher_external_profile *profile,
    const uint8_t profile_sha256[32])
{
    static const uint8_t magic[8] = {
        'P', 'L', 'M', 'R', 'P', 'M', '2', 0
    };
    const char *path;
    uint8_t header[PLAMEN_LAUNCHER_RUNTIME_MANIFEST_HEADER_SIZE];
    uint8_t row[PLAMEN_LAUNCHER_RUNTIME_MANIFEST_ROW_SIZE];
    struct stat manifest_info, profile_info;
    uint32_t count, index;
    uint64_t expected_size;
    int matches = 0;

    if (profile == NULL)
        return -1;
    if (strcmp(profile->backend_selector, "codex") == 0)
        path = PLAMEN_LAUNCHER_CODEX_PROFILE_MANIFEST_PATH;
    else if (strcmp(profile->backend_selector, "claude") == 0)
        path = PLAMEN_LAUNCHER_CLAUDE_PROFILE_MANIFEST_PATH;
    else
        return -1;
    if (fstat(manifest_fd, &manifest_info) != 0
        || fstat(profile_fd, &profile_info) != 0
        || !S_ISREG(manifest_info.st_mode) || !S_ISREG(profile_info.st_mode)
        || profile_info.st_nlink != 1 || profile_info.st_uid != geteuid()
        || (profile_info.st_mode & 07777) != 0400
        || pread(manifest_fd, header, sizeof(header), 0) != sizeof(header)
        || memcmp(header, magic, sizeof(magic)) != 0
        || load_be16(header + 8) != 2
        || load_be16(header + 10) != sizeof(header)
        || load_be32(header + 16) != sizeof(row))
        return -1;
    count = load_be32(header + 20);
    expected_size = (uint64_t)sizeof(header)
        + PLAMEN_LAUNCHER_RUNTIME_MANIFEST_BINDING_SIZE
        + (uint64_t)count * sizeof(row) + 32;
    if (count == 0 || expected_size != (uint64_t)manifest_info.st_size
        || expected_size > UINT32_MAX)
        return -1;
    for (index = 0; index < count; ++index) {
        off_t offset = (off_t)(sizeof(header)
            + PLAMEN_LAUNCHER_RUNTIME_MANIFEST_BINDING_SIZE
            + (uint64_t)index * sizeof(row));
        uint16_t path_size;
        if (pread(manifest_fd, row, sizeof(row), offset) != sizeof(row))
            return -1;
        path_size = load_be16(row + 2);
        if (path_size == strlen(path)
            && memcmp(row + 56, path, path_size) == 0) {
            if (matches != 0 || load_be16(row) != 2
                || load_be32(row + 4) != 0400
                || load_be64(row + 8) != (uint64_t)profile_info.st_size
                || load_be32(row + 16) != 1
                || !constant_equal(row + 24, profile_sha256, 32)
                || !zero_region(row + 56 + path_size, 512 - path_size))
                return -1;
            matches = 1;
        }
    }
    return matches == 1 ? 0 : -1;
}

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
int
plamen_native_launcher_TEST_ONLY_profile_validate(int profile_fd,
    int runtime_manifest_fd)
{
    struct plamen_launcher_external_profile profile;
    uint8_t profile_sha256[32];
    int status;
    memset(&profile, 0, sizeof(profile));
    memset(profile_sha256, 0, sizeof(profile_sha256));
    status = read_external_profile(profile_fd, &profile, profile_sha256);
    if (status == 0)
        status = runtime_manifest_binds_profile(runtime_manifest_fd,
            profile_fd, &profile, profile_sha256);
    plamen_broker_v2_secure_zero(&profile, sizeof(profile));
    plamen_broker_v2_secure_zero(profile_sha256, sizeof(profile_sha256));
    return status;
}
#endif

static int
durable_sync(int descriptor)
{
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0)
        return 0;
#endif
    return fsync(descriptor);
}

static int
open_private_directory_at(int parent_fd, const char *name, int *output)
{
    struct stat information;
    int descriptor;
    *output = -1;
    if (mkdirat(parent_fd, name, 0700) != 0 && errno != EEXIST)
        return -1;
    descriptor = openat(parent_fd, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !S_ISDIR(information.st_mode) || information.st_uid != geteuid()
        || (information.st_mode & 07777) != 0700) {
        if (descriptor >= 0)
            close(descriptor);
        return -1;
    }
    *output = descriptor;
    return 0;
}

static int
create_generated_authority(int install_root_fd, const char *kind,
    const uint8_t *bytes, size_t size, int *output)
{
    uint8_t digest[32], observed[32];
    char digest_hex[65], name[96];
    struct stat created_info, retained_info;
    int state_fd = -1, directory_fd = -1, writable = -1, retained = -1;
    size_t offset = 0;
    ssize_t amount;
    int published = 0, status = -1;

    *output = -1;
    memset(name, 0, sizeof(name));
    if (kind == NULL || bytes == NULL || size == 0
        || size > PLAMEN_LAUNCHER_GENERATED_MAX
        || strchr(kind, '/') != NULL || sha256_bytes(bytes, size, digest) != 0)
        goto done;
    hex_bytes(digest, sizeof(digest), digest_hex);
    if (snprintf(name, sizeof(name), "%s-%s.bin", kind, digest_hex)
            >= (int)sizeof(name)
        || open_private_directory_at(install_root_fd,
            "service-state-v2", &state_fd) != 0
        || open_private_directory_at(state_fd,
            PLAMEN_LAUNCHER_AUTHORITY_DIRECTORY, &directory_fd) != 0)
        goto done;
    writable = openat(directory_fd, name,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (writable < 0)
        goto done;
    while (offset < size) {
        do {
            amount = pwrite(writable, bytes + offset, size - offset,
                (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            goto done;
        offset += (size_t)amount;
    }
    if (ftruncate(writable, (off_t)size) != 0
        || fchmod(writable, 0400) != 0 || durable_sync(writable) != 0
        || fstat(writable, &created_info) != 0
        || !S_ISREG(created_info.st_mode) || created_info.st_uid != geteuid()
        || created_info.st_nlink != 1 || created_info.st_size != (off_t)size
        || (created_info.st_mode & 07777) != 0400)
        goto done;
    close(writable);
    writable = -1;
    retained = openat(directory_fd, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (retained < 0 || fstat(retained, &retained_info) != 0
        || !same_vnode_exact(&created_info, &retained_info)
        || (fcntl(retained, F_GETFL) & O_ACCMODE) != O_RDONLY
        || sha256_fd(retained, observed) != 0
        || !constant_equal(observed, digest, 32)
        || durable_sync(directory_fd) != 0 || durable_sync(state_fd) != 0
        || durable_sync(install_root_fd) != 0)
        goto done;
    published = 1;
    *output = retained;
    retained = -1;
    status = 0;
done:
    if (retained >= 0)
        close(retained);
    if (writable >= 0)
        close(writable);
    if (!published && directory_fd >= 0 && name[0] != '\0')
        (void)unlinkat(directory_fd, name, 0);
    if (directory_fd >= 0)
        close(directory_fd);
    if (state_fd >= 0)
        close(state_fd);
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    plamen_broker_v2_secure_zero(observed, sizeof(observed));
    plamen_broker_v2_secure_zero(digest_hex, sizeof(digest_hex));
    plamen_broker_v2_secure_zero(name, sizeof(name));
    return status;
}

static int
copy_claude_keychain_credential(const char *account, uint8_t **output,
    size_t *output_size)
{
    const void *keys[5], *values[5];
    CFStringRef service = NULL, account_value = NULL;
    CFDictionaryRef query = NULL;
    CFTypeRef result = NULL;
    CFDataRef data;
    CFIndex size = 0;
    uint8_t *bytes = NULL;
    int status = -1;

    *output = NULL;
    *output_size = 0;
    if (account == NULL || account[0] == '\0'
        || strlen(account) > 1024U)
        goto done;
    service = CFStringCreateWithCString(kCFAllocatorDefault,
        PLAMEN_LAUNCHER_CLAUDE_KEYCHAIN_SERVICE, kCFStringEncodingUTF8);
    account_value = CFStringCreateWithCString(kCFAllocatorDefault,
        account, kCFStringEncodingUTF8);
    if (service == NULL || account_value == NULL)
        goto done;
    keys[0] = kSecClass;
    values[0] = kSecClassGenericPassword;
    keys[1] = kSecAttrService;
    values[1] = service;
    keys[2] = kSecAttrAccount;
    values[2] = account_value;
    keys[3] = kSecReturnData;
    values[3] = kCFBooleanTrue;
    keys[4] = kSecUseAuthenticationUI;
    values[4] = kSecUseAuthenticationUISkip;
    query = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 5,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (query == NULL || SecItemCopyMatching(query, &result) != errSecSuccess
        || result == NULL || CFGetTypeID(result) != CFDataGetTypeID())
        goto done;
    data = (CFDataRef)result;
    size = CFDataGetLength(data);
    if (size <= 0 || (uint64_t)size > PLAMEN_LAUNCHER_CLAUDE_CREDENTIAL_MAX)
        goto done;
    bytes = malloc((size_t)size);
    if (bytes == NULL)
        goto done;
    CFDataGetBytes(data, CFRangeMake(0, size), bytes);
    if (memchr(bytes, '\0', (size_t)size) != NULL
        || bytes[0] != '{' || bytes[(size_t)size - 1U] != '}')
        goto done;
    *output = bytes;
    *output_size = (size_t)size;
    bytes = NULL;
    status = 0;
done:
    if (bytes != NULL) {
        plamen_broker_v2_secure_zero(bytes,
            size > 0 ? (size_t)size : 0U);
        free(bytes);
    }
    if (result != NULL) CFRelease(result);
    if (query != NULL) CFRelease(query);
    if (account_value != NULL) CFRelease(account_value);
    if (service != NULL) CFRelease(service);
    return status;
}

static int
copy_retained_credential_bytes(int descriptor, uint8_t **output,
    size_t *output_size)
{
    struct stat before, after;
    uint8_t *bytes = NULL;
    size_t size, offset = 0;
    ssize_t amount;
    int status = -1;

    *output = NULL;
    *output_size = 0;
    if (descriptor < 0 || fstat(descriptor, &before) != 0
        || !S_ISREG(before.st_mode) || before.st_uid != geteuid()
        || before.st_nlink != 1 || (before.st_mode & 0077) != 0
        || before.st_size <= 0
        || (uint64_t)before.st_size > PLAMEN_LAUNCHER_CREDENTIAL_MAX
        || (fcntl(descriptor, F_GETFL) & O_ACCMODE) != O_RDONLY)
        goto done;
    size = (size_t)before.st_size;
    bytes = malloc(size);
    if (bytes == NULL)
        goto done;
    while (offset < size) {
        do {
            amount = pread(descriptor, bytes + offset, size - offset,
                (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            goto done;
        offset += (size_t)amount;
    }
    if (fstat(descriptor, &after) != 0 || !same_vnode_exact(&before, &after))
        goto done;
    *output = bytes;
    *output_size = size;
    bytes = NULL;
    status = 0;
done:
    if (bytes != NULL) {
        plamen_broker_v2_secure_zero(bytes,
            before.st_size > 0 ? (size_t)before.st_size : 0U);
        free(bytes);
    }
    return status;
}

static int
create_unlinked_credential_authority(int install_root_fd,
    const uint8_t *bytes, size_t size, int *output)
{
    uint8_t nonce[32], expected[32], observed[32];
    char nonce_hex[65], name[96];
    struct stat writable_info, retained_info;
    int state_fd = -1, directory_fd = -1, writable = -1, retained = -1;
    size_t offset = 0;
    ssize_t amount;
    int linked = 0, status = -1;

    *output = -1;
    memset(nonce, 0, sizeof(nonce));
    memset(expected, 0, sizeof(expected));
    memset(observed, 0, sizeof(observed));
    memset(nonce_hex, 0, sizeof(nonce_hex));
    memset(name, 0, sizeof(name));
    if (bytes == NULL || size == 0 || size > PLAMEN_LAUNCHER_CREDENTIAL_MAX
        || sha256_bytes(bytes, size, expected) != 0
        || getentropy(nonce, sizeof(nonce)) != 0)
        goto done;
    hex_bytes(nonce, sizeof(nonce), nonce_hex);
    if (snprintf(name, sizeof(name), "credential-%s.tmp", nonce_hex)
            >= (int)sizeof(name)
        || open_private_directory_at(install_root_fd,
            "service-state-v2", &state_fd) != 0
        || open_private_directory_at(state_fd,
            PLAMEN_LAUNCHER_AUTHORITY_DIRECTORY, &directory_fd) != 0)
        goto done;
    writable = openat(directory_fd, name,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (writable < 0)
        goto done;
    linked = 1;
    /* Open the read-only custody descriptor and remove the empty name before
     * copying any secret byte.  A crash can therefore leave at most an empty
     * 0600 name, never a recoverable named credential file. */
    retained = openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (retained < 0 || unlinkat(directory_fd, name, 0) != 0)
        goto done;
    linked = 0;
    if (durable_sync(directory_fd) != 0)
        goto done;
    while (offset < size) {
        do {
            amount = pwrite(writable, bytes + offset, size - offset,
                (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            goto done;
        offset += (size_t)amount;
    }
    if (ftruncate(writable, (off_t)size) != 0
        || fchmod(writable, 0600) != 0
        || fstat(writable, &writable_info) != 0
        || !S_ISREG(writable_info.st_mode)
        || writable_info.st_uid != geteuid() || writable_info.st_nlink != 0
        || writable_info.st_size != (off_t)size
        || (writable_info.st_mode & 07777) != 0600)
        goto done;
    if (fstat(writable, &writable_info) != 0
        || fstat(retained, &retained_info) != 0
        || !same_vnode_exact(&writable_info, &retained_info)
        || retained_info.st_nlink != 0
        || (retained_info.st_mode & 07777) != 0600
        || (fcntl(retained, F_GETFL) & O_ACCMODE) != O_RDONLY
        || sha256_fd(retained, observed) != 0
        || !constant_equal(observed, expected, sizeof(expected)))
        goto done;
    *output = retained;
    retained = -1;
    status = 0;
done:
    if (linked && directory_fd >= 0 && name[0] != '\0')
        (void)unlinkat(directory_fd, name, 0);
    if (retained >= 0) close(retained);
    if (writable >= 0) close(writable);
    if (directory_fd >= 0) close(directory_fd);
    if (state_fd >= 0) close(state_fd);
    plamen_broker_v2_secure_zero(nonce, sizeof(nonce));
    plamen_broker_v2_secure_zero(expected, sizeof(expected));
    plamen_broker_v2_secure_zero(observed, sizeof(observed));
    plamen_broker_v2_secure_zero(nonce_hex, sizeof(nonce_hex));
    plamen_broker_v2_secure_zero(name, sizeof(name));
    return status;
}

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
int
plamen_native_launcher_TEST_ONLY_create_unlinked_credential(
    int install_root_fd, const uint8_t *bytes, size_t size, int *output)
{
    return create_unlinked_credential_authority(
        install_root_fd, bytes, size, output);
}
#endif

static int
admit_external_executable(const char *path, uid_t expected_owner,
    const uint8_t expected_sha256[32], const uint8_t expected_cdhash[32],
    uint16_t expected_cdhash_size, const char *expected_identifier,
    const char *expected_team, int *output)
{
    struct stat before, after;
    struct plamen_launcher_code_identity identity;
    uint8_t digest[32];
    char cdhash_hex[65], requirement[768];
    int descriptor = -1, status = -1;

    *output = -1;
    if ((expected_cdhash_size != 20 && expected_cdhash_size != 32)
        || expected_identifier == NULL || expected_identifier[0] == '\0'
        || expected_team == NULL || expected_team[0] == '\0'
        || open_absolute_file(path, UINT32_C(512) * 1024 * 1024,
            &descriptor) != 0
        || fstat(descriptor, &before) != 0 || before.st_uid != expected_owner
        || before.st_nlink != 1 || (before.st_mode & 0111) == 0
        || (before.st_mode & 0022) != 0
        || sha256_fd(descriptor, digest) != 0
        || !constant_equal(digest, expected_sha256, 32))
        goto done;
    hex_bytes(expected_cdhash, expected_cdhash_size, cdhash_hex);
    if (snprintf(requirement, sizeof(requirement),
            "anchor apple generic and identifier \"%s\" and "
            "certificate leaf[subject.OU] = \"%s\" and cdhash H\"%s\"",
            expected_identifier, expected_team, cdhash_hex)
            >= (int)sizeof(requirement)
        || static_code_identity(path, requirement, &identity) != 0
        || identity.cdhash_size != expected_cdhash_size
        || !constant_equal(identity.cdhash, expected_cdhash,
            expected_cdhash_size)
        || strcmp(identity.identifier, expected_identifier) != 0
        || strcmp(identity.team, expected_team) != 0
        || fstat(descriptor, &after) != 0 || !same_vnode_exact(&before, &after)
        || sha256_fd(descriptor, digest) != 0
        || !constant_equal(digest, expected_sha256, 32))
        goto done;
    *output = descriptor;
    descriptor = -1;
    status = 0;
done:
    if (descriptor >= 0)
        close(descriptor);
    plamen_broker_v2_secure_zero(&identity, sizeof(identity));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    plamen_broker_v2_secure_zero(cdhash_hex, sizeof(cdhash_hex));
    plamen_broker_v2_secure_zero(requirement, sizeof(requirement));
    return status;
}

static int
resolve_backend_executable(const char *home,
    const struct plamen_launcher_external_profile *profile, int *output)
{
    char releases[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char expected[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    int status = -1;

    *output = -1;
    if (profile == NULL || (
            strcmp(profile->backend_selector, "codex") != 0
            && strcmp(profile->backend_selector, "claude") != 0))
        goto done;
    if (snprintf(releases, sizeof(releases),
            "%s/.local/share/plamen/backends/%s/releases", home,
            profile->backend_selector) >= (int)sizeof(releases)
        || (strcmp(profile->backend_selector, "codex") == 0
            ? snprintf(expected, sizeof(expected), "%s/%s/bin/codex",
                releases, profile->backend_release)
        : snprintf(expected, sizeof(expected), "%s/%s/claude", releases,
                profile->backend_release)) >= (int)sizeof(expected)
        || admit_external_executable(expected, geteuid(),
            profile->backend_sha256, profile->backend_cdhash,
            profile->backend_cdhash_size, profile->backend_identifier,
            profile->backend_team, output) != 0)
        goto done;
    status = 0;
done:
    plamen_broker_v2_secure_zero(releases, sizeof(releases));
    plamen_broker_v2_secure_zero(expected, sizeof(expected));
    return status;
}

static int
collect_request_authority(struct plamen_launcher_authority *authority,
    int install_root_fd, const char *home, const char *account)
{
    struct plamen_broker_v2_projection_discovery discovery;
    struct plamen_broker_v2_projection_builder_inputs input;
    struct plamen_broker_v2_projection_builder_result built;
    struct plamen_broker_v2_commitment commitment;
    struct plamen_launcher_external_profile profile;
    struct stat credential_info;
    uint8_t profile_sha[32], nonce[32], config_sha[32], policy_sha[32];
    uint8_t *policy = NULL, *admission = NULL, *credential_bytes = NULL;
    char config_hex[65], nonce_hex[65], profile_hex[65];
    char provider_hex[65], backend_hex[65], policy_hex[65];
    char credential_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    const char *profile_relative = NULL;
    int sources[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    int profile_fd = -1, named_credential_fd = -1;
    size_t policy_size = 0, admission_size = 0, credential_size = 0, index;
    int amount, status = -1;

    memset(&discovery, 0, sizeof(discovery));
    memset(&input, 0, sizeof(input));
    memset(&built, 0, sizeof(built));
    memset(&commitment, 0, sizeof(commitment));
    memset(&profile, 0, sizeof(profile));
    memset(sources, -1, sizeof(sources));
    memset(config_hex, 0, sizeof(config_hex));
    memset(nonce_hex, 0, sizeof(nonce_hex));
    memset(profile_hex, 0, sizeof(profile_hex));
    memset(provider_hex, 0, sizeof(provider_hex));
    memset(backend_hex, 0, sizeof(backend_hex));
    memset(policy_hex, 0, sizeof(policy_hex));
    memset(credential_path, 0, sizeof(credential_path));
    if (authority == NULL || install_root_fd < 0 || home == NULL
        || account == NULL || account[0] == '\0'
        || authority->config_fd < 0
        || authority->startup_intent != PLAMEN_BROKER_V2_STARTUP_START_NEW_RUN)
        goto done;
    if (plamen_broker_v2_projection_discover_config(authority->startup_intent,
            authority->config_path, authority->config_fd, &discovery) != 0
        || (strcmp(discovery.backend, "codex") != 0
            && strcmp(discovery.backend, "claude") != 0)
        || strcmp(discovery.provider_selector, "apple-container-v2") != 0
        || strcmp(discovery.backend_profile_selector, discovery.backend) != 0
        || strcmp(discovery.credential_selector, discovery.backend) != 0
        || strcmp(discovery.egress_selector, "verified-egress-v2") != 0
        || ((profile_relative = strcmp(discovery.backend, "codex") == 0
                ? PLAMEN_LAUNCHER_CODEX_PROFILE_RELATIVE
                : PLAMEN_LAUNCHER_CLAUDE_PROFILE_RELATIVE) == NULL)
        || open_relative_file(authority->generation_fd, profile_relative,
            &profile_fd) != 0
        || read_external_profile(profile_fd, &profile, profile_sha) != 0
        || strcmp(profile.backend_selector, discovery.backend) != 0
        || runtime_manifest_binds_profile(
            authority->member_fds[
                PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST - 1],
            profile_fd, &profile, profile_sha) != 0
        || open_absolute_directory(discovery.project_root, &sources[1]) != 0
        || open_absolute_directory(discovery.scratchpad, &sources[4]) != 0)
        goto done;
    if (discovery.has_docs
        && open_absolute_directory(discovery.docs_path, &sources[2]) != 0
        && open_absolute_file(discovery.docs_path,
            UINT32_C(512) * 1024 * 1024, &sources[2]) != 0)
        goto done;
    if (discovery.has_scope
        && open_absolute_file(discovery.scope_file,
            UINT32_C(512) * 1024 * 1024, &sources[3]) != 0)
        goto done;
    if (admit_external_executable(PLAMEN_LAUNCHER_PROVIDER_PATH, 0,
            profile.provider_sha256, profile.provider_cdhash,
            profile.provider_cdhash_size, profile.provider_identifier,
            profile.provider_team, &sources[7]) != 0
        || resolve_backend_executable(home, &profile, &sources[8]) != 0
        || (strcmp(discovery.backend, "codex") == 0
            ? (snprintf(credential_path, sizeof(credential_path),
                    "%s/.codex/auth.json", home) >= (int)sizeof(credential_path)
                || open_absolute_file(credential_path,
                    PLAMEN_LAUNCHER_CREDENTIAL_MAX,
                    &named_credential_fd) != 0
                || copy_retained_credential_bytes(named_credential_fd,
                    &credential_bytes, &credential_size) != 0
                || create_unlinked_credential_authority(install_root_fd,
                    credential_bytes, credential_size, &sources[10]) != 0)
            : (copy_claude_keychain_credential(account, &credential_bytes,
                    &credential_size) != 0
                || create_unlinked_credential_authority(install_root_fd,
                    credential_bytes, credential_size, &sources[10]) != 0))
        || fstat(sources[10], &credential_info) != 0
        || credential_info.st_uid != geteuid()
        || credential_info.st_nlink != 0
        || (credential_info.st_mode & 0077) != 0
        || sha256_fd(authority->config_fd, config_sha) != 0
        || getentropy(nonce, sizeof(nonce)) != 0)
        goto done;
    plamen_broker_v2_secure_zero(credential_bytes, credential_size);
    free(credential_bytes);
    credential_bytes = NULL;
    credential_size = 0;
    sources[0] = authority->config_fd;
    sources[5] = authority->member_fds[PLAMEN_INSTALL_MEMBER_SCHEMA - 1];
    sources[6] = authority->member_fds[
        PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST - 1];
    sources[9] = profile_fd;
    hex_bytes(config_sha, 32, config_hex);
    hex_bytes(nonce, 32, nonce_hex);
    hex_bytes(profile_sha, 32, profile_hex);
    hex_bytes(profile.provider_sha256, 32, provider_hex);
    hex_bytes(profile.backend_sha256, 32, backend_hex);
    policy = malloc(PLAMEN_LAUNCHER_GENERATED_MAX);
    admission = malloc(PLAMEN_LAUNCHER_GENERATED_MAX);
    if (policy == NULL || admission == NULL)
        goto done;
    amount = snprintf((char *)policy, PLAMEN_LAUNCHER_GENERATED_MAX,
        "{\"backend\":\"%s\",\"config_sha256\":\"%s\","
        "\"network_mode\":\"NARROW_TRUSTED_PROXY_ONLY\","
        "\"nonce\":\"%s\",\"profile_sha256\":\"%s\","
        "\"schema\":\"plamen.egress-policy.v2\"}\n",
        discovery.backend, config_hex, nonce_hex, profile_hex);
    if (amount <= 0
        || (unsigned)amount >= PLAMEN_LAUNCHER_GENERATED_MAX)
        goto done;
    policy_size = (size_t)amount;
    if (sha256_bytes(policy, policy_size, policy_sha) != 0)
        goto done;
    hex_bytes(policy_sha, 32, policy_hex);
    amount = snprintf((char *)admission, PLAMEN_LAUNCHER_GENERATED_MAX,
        "{\"backend_sha256\":\"%s\",\"policy_sha256\":\"%s\","
        "\"provider_sha256\":\"%s\","
        "\"schema\":\"plamen.egress-admission.v2\"}\n",
        backend_hex, policy_hex, provider_hex);
    if (amount <= 0
        || (unsigned)amount >= PLAMEN_LAUNCHER_GENERATED_MAX)
        goto done;
    admission_size = (size_t)amount;
    if (create_generated_authority(install_root_fd, "egress-policy",
            policy, policy_size, &sources[11]) != 0
        || create_generated_authority(install_root_fd, "egress-admission",
            admission, admission_size, &sources[12]) != 0)
        goto done;
    input.startup_intent = authority->startup_intent;
    input.config_path = authority->config_path;
    input.config_fd = sources[0];
    input.discovery = &discovery;
    input.target_root_fd = sources[1];
    input.docs_root_fd = sources[2];
    input.scope_fd = sources[3];
    input.export_root_fd = sources[4];
    input.role5_schema_fd = sources[5];
    input.runtime_manifest_fd = sources[6];
    input.provider_executable_fd = sources[7];
    input.backend_executable_fd = sources[8];
    input.backend_profile_fd = sources[9];
    input.credential_source_fd = sources[10];
    input.egress_policy_fd = sources[11];
    input.egress_admission_fd = sources[12];
    input.resume_checkpoint_fd = -1;
    memcpy(input.expected_role5_schema_sha256,
        authority->receipt.members[PLAMEN_INSTALL_MEMBER_SCHEMA - 1].sha256,
        32);
    memcpy(input.expected_runtime_manifest_sha256,
        authority->receipt.members[
            PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST - 1].sha256, 32);
    if (plamen_broker_v2_projection_build_from_retained(&input, &built) != 0
        || plamen_broker_v2_projection_builder_revalidate(&built) != 0
        || built.commitment_size > sizeof(authority->commitment)
        || built.commitment_size > UINT16_MAX
        || plamen_broker_v2_decode_commitment_exact(built.commitment,
            built.commitment_size, &commitment) != 0)
        goto done;
    authority->request_projection = built.request_projection;
    authority->request_projection_size = built.request_projection_size;
    built.request_projection = NULL;
    built.request_projection_size = 0;
    authority->commitment_size = (uint16_t)built.commitment_size;
    memcpy(authority->commitment, built.commitment, built.commitment_size);
    memcpy(authority->request_projection_sha256,
        built.request_projection_sha256, 32);
    memcpy(authority->commitment_sha256, built.commitment_sha256, 32);
    memcpy(authority->audit_request_fingerprint,
        commitment.request_fingerprint, 32);
    memcpy(authority->committed_audit_generation_sha256,
        authority->receipt.generation_id_sha256, 32);
    authority->authority_presence_mask = built.retained_presence_mask;
    for (index = 0;
         index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index) {
        authority->authority_fds[index] = built.retained_fds[index];
        built.retained_fds[index] = -1;
        memcpy(authority->authority_identities[index],
            built.retained_identities[index], 32);
    }
    status = 0;
done:
    if (credential_bytes != NULL) {
        plamen_broker_v2_secure_zero(credential_bytes, credential_size);
        free(credential_bytes);
    }
    for (index = 0;
         index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index) {
        if (index == 0 || index == 5 || index == 6 || index == 9)
            continue;
        if (sources[index] >= 0)
            close(sources[index]);
    }
    if (profile_fd >= 0)
        close(profile_fd);
    if (named_credential_fd >= 0)
        close(named_credential_fd);
    plamen_broker_v2_projection_builder_result_destroy(&built);
    plamen_broker_v2_projection_discovery_destroy(&discovery);
    if (policy != NULL) {
        plamen_broker_v2_secure_zero(policy, PLAMEN_LAUNCHER_GENERATED_MAX);
        free(policy);
    }
    if (admission != NULL) {
        plamen_broker_v2_secure_zero(admission,
            PLAMEN_LAUNCHER_GENERATED_MAX);
        free(admission);
    }
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    plamen_broker_v2_secure_zero(&profile, sizeof(profile));
    plamen_broker_v2_secure_zero(profile_sha, sizeof(profile_sha));
    plamen_broker_v2_secure_zero(nonce, sizeof(nonce));
    plamen_broker_v2_secure_zero(config_sha, sizeof(config_sha));
    plamen_broker_v2_secure_zero(policy_sha, sizeof(policy_sha));
    plamen_broker_v2_secure_zero(config_hex, sizeof(config_hex));
    plamen_broker_v2_secure_zero(nonce_hex, sizeof(nonce_hex));
    plamen_broker_v2_secure_zero(profile_hex, sizeof(profile_hex));
    plamen_broker_v2_secure_zero(provider_hex, sizeof(provider_hex));
    plamen_broker_v2_secure_zero(backend_hex, sizeof(backend_hex));
    plamen_broker_v2_secure_zero(policy_hex, sizeof(policy_hex));
    plamen_broker_v2_secure_zero(credential_path, sizeof(credential_path));
    return status;
}

static void
close_authority(struct plamen_launcher_authority *authority)
{
    size_t index;
    if (authority->request_projection != NULL) {
        plamen_broker_v2_secure_zero(authority->request_projection,
            authority->request_projection_size);
        free(authority->request_projection);
    }
    if (authority->config_fd >= 0)
        close(authority->config_fd);
    if (authority->receipt_fd >= 0)
        close(authority->receipt_fd);
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        if (authority->member_fds[index] >= 0)
            close(authority->member_fds[index]);
    }
    for (index = 0;
         index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index) {
        if (authority->authority_fds[index] >= 0)
            close(authority->authority_fds[index]);
    }
    if (authority->generation_fd >= 0)
        close(authority->generation_fd);
    plamen_broker_v2_secure_zero(authority, sizeof(*authority));
}

static int
admit_authority(struct plamen_launcher_authority *authority,
    const char *command, const char *config_path)
{
    struct passwd password, *password_result = NULL;
    struct stat self_info, member_info, install_root_info, ancestry_root_info;
    struct plamen_launcher_code_identity static_identity, dynamic_identity;
    uint8_t receipt_bytes[PLAMEN_INSTALL_RECEIPT_SIZE];
    uint8_t projection_schema_sha256[32];
    char password_buffer[4096];
    char self_path[PROC_PIDPATHINFO_MAXSIZE];
    char generation_path[PROC_PIDPATHINFO_MAXSIZE];
    char install_root_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char stable_self_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char expected_generation_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char generation_self_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char generation_digest_hex[65];
    char cdhash_hex[PLAMEN_INSTALL_RECEIPT_CDHASH_MAX * 2 + 1];
    char launcher_requirement[512];
    size_t index;
    int self_fd = -1, install_root_fd = -1, ancestry_root_fd = -1;
    int deployment_receipt_fd = -1;
    int generations_fd = -1;
    int readiness_only = command != NULL
        && strcmp(command, "readiness") == 0;
    int result = PLAMEN_LAUNCHER_HARDSTOP;

    /*
     * Fail closed until the installed receipt, generation, signed launcher,
     * retained request closure, and native projection composer have all been
     * admitted below.  The initialized hard-stop value is deliberately kept
     * through every incomplete or ambiguous branch.
     */
    memset(authority, 0, sizeof(*authority));
    authority->generation_fd = -1;
    authority->receipt_fd = -1;
    authority->config_fd = -1;
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; ++index)
        authority->member_fds[index] = -1;
    for (index = 0;
         index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index)
        authority->authority_fds[index] = -1;
    if (command == NULL
        || !(readiness_only
            || strcmp(command, "start-config") == 0
            || strcmp(command, "resume") == 0)
        || (readiness_only ? config_path != NULL
            : (config_path == NULL || !canonical_absolute_path(config_path))))
        return 64;
    if (!readiness_only) {
        authority->startup_intent = strcmp(command, "resume") == 0
            ? PLAMEN_BROKER_V2_STARTUP_RESUME_EXISTING
            : PLAMEN_BROKER_V2_STARTUP_START_NEW_RUN;
        memcpy(authority->config_path, config_path, strlen(config_path) + 1);
    }
    memset(self_path, 0, sizeof(self_path));
    if (proc_pidpath(getpid(), self_path, sizeof(self_path)) <= 0
        || getpwuid_r(getuid(), &password, password_buffer,
            sizeof(password_buffer), &password_result) != 0
        || password_result == NULL || password.pw_uid != getuid()
        || password.pw_dir == NULL || password.pw_name == NULL
        || password.pw_name[0] == '\0' || strlen(password.pw_name) > 1024U
        || snprintf(install_root_path, sizeof(install_root_path),
            "%s/.local/share/plamen", password.pw_dir)
            >= (int)sizeof(install_root_path)
        || snprintf(stable_self_path, sizeof(stable_self_path),
            "%s/bin/plamen-native-launcher", install_root_path)
            >= (int)sizeof(stable_self_path)
        || open_absolute_directory(install_root_path, &install_root_fd) != 0
        || fstat(install_root_fd, &install_root_info) != 0
        || !S_ISDIR(install_root_info.st_mode)
        || install_root_info.st_uid != geteuid()
        || (install_root_info.st_mode & 0777) != 0700
        || open_relative_file(install_root_fd,
            PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH, &authority->receipt_fd) != 0
        || read_receipt_exact(authority->receipt_fd, receipt_bytes) != 0
        || plamen_install_receipt_decode_exact(receipt_bytes,
            sizeof(receipt_bytes), &authority->receipt) != 0
        || (!readiness_only
            && (open_relative_file(install_root_fd,
                    PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_RELATIVE,
                    &deployment_receipt_fd) != 0
                || plamen_native_darwin_deployment_receipt_validate_v2(
                    deployment_receipt_fd, &authority->receipt) != 0)))
        goto done;
    hex_bytes(authority->receipt.generation_id_sha256, 32,
        generation_digest_hex);
    if (snprintf(expected_generation_path, sizeof(expected_generation_path),
            "%s/generations/%s", install_root_path, generation_digest_hex)
            >= (int)sizeof(expected_generation_path)
        || snprintf(generation_self_path, sizeof(generation_self_path),
            "%s%s", expected_generation_path, PLAMEN_LAUNCHER_SUFFIX)
            >= (int)sizeof(generation_self_path)
        || strcmp(authority->receipt.generation_path,
            expected_generation_path) != 0
        || !hex_matches_basename(authority->receipt.generation_path,
            authority->receipt.generation_id_sha256))
        goto done;
    memcpy(generation_path, expected_generation_path,
        strlen(expected_generation_path) + 1);
    generations_fd = openat(install_root_fd, "generations",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    authority->generation_fd = generations_fd < 0 ? -1
        : openat(generations_fd, generation_digest_hex,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (authority->generation_fd < 0
        || open_install_root_from_generation(authority->generation_fd,
            &ancestry_root_fd) != 0
        || fstat(ancestry_root_fd, &ancestry_root_info) != 0
        || !same_vnode_exact(&install_root_info, &ancestry_root_info)
        || !(strcmp(self_path, stable_self_path) == 0
            || strcmp(self_path, generation_self_path) == 0))
        goto done;
    self_fd = open(self_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (self_fd < 0
        || CC_SHA256(receipt_bytes, sizeof(receipt_bytes),
            authority->installation_receipt_sha256)
            != authority->installation_receipt_sha256
        || CC_SHA256(PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA,
            (CC_LONG)strlen(PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA),
            projection_schema_sha256) != projection_schema_sha256
        || !constant_equal(projection_schema_sha256,
            authority->receipt.projection_schema_sha256, 32)
        || !constant_equal(authority->receipt.protocol_schema_sha256,
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_SHARED_ABI - 1]
                .sha256, 32))
        goto done;
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        if (plamen_install_receipt_open_member(authority->generation_fd,
                &authority->receipt.members[index],
                &authority->member_fds[index]) != 0)
            goto done;
    }
    if (fstat(self_fd, &self_info) != 0
        || fstat(authority->member_fds[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1],
            &member_info) != 0 || !same_vnode_exact(&self_info, &member_info)
        || (!readiness_only
            && (snprintf(authority->python_path,
                    sizeof(authority->python_path), "%s/%s", generation_path,
                    authority->receipt.members[
                        PLAMEN_INSTALL_MEMBER_PYTHON - 1].relative_path)
                    >= (int)sizeof(authority->python_path)
                || snprintf(authority->entrypoint_path,
                    sizeof(authority->entrypoint_path), "%s/%s", generation_path,
                    authority->receipt.members[
                        PLAMEN_INSTALL_MEMBER_OUTER_ENTRYPOINT - 1].relative_path)
                    >= (int)sizeof(authority->entrypoint_path)
                || open_absolute_file(config_path, PLAMEN_LAUNCHER_CONFIG_MAX,
                    &authority->config_fd) != 0)))
        goto done;
    hex_bytes(authority->receipt.members[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1]
            .cdhash,
        authority->receipt.members[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1]
            .cdhash_size, cdhash_hex);
    if (snprintf(launcher_requirement, sizeof(launcher_requirement),
            "identifier \"%s\" and cdhash H\"%s\"",
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1]
                .signing_identifier, cdhash_hex)
            >= (int)sizeof(launcher_requirement)
        || static_code_identity(self_path, launcher_requirement,
            &static_identity) != 0
        || dynamic_code_identity(getpid(), launcher_requirement,
            &dynamic_identity) != 0
        || static_identity.cdhash_size
            != authority->receipt.members[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1]
                .cdhash_size
        || dynamic_identity.cdhash_size != static_identity.cdhash_size
        || !constant_equal(static_identity.cdhash,
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1]
                .cdhash, static_identity.cdhash_size)
        || !constant_equal(dynamic_identity.cdhash, static_identity.cdhash,
            static_identity.cdhash_size)
        || strcmp(static_identity.identifier,
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1]
                .signing_identifier) != 0
        || strcmp(dynamic_identity.identifier, static_identity.identifier) != 0
        || strcmp(static_identity.team,
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1]
                .team_identifier) != 0
        || strcmp(dynamic_identity.team, static_identity.team) != 0)
        goto done;
    memcpy(authority->installed_closure_sha256,
        authority->receipt.generation_id_sha256, 32);
    memcpy(authority->broker_closure_sha256,
        authority->receipt.members[PLAMEN_INSTALL_MEMBER_SERVICE - 1].sha256, 32);
    memcpy(authority->python_executable_sha256,
        authority->receipt.members[PLAMEN_INSTALL_MEMBER_PYTHON - 1].sha256, 32);
    memcpy(authority->python_entrypoint_sha256,
        authority->receipt.members[PLAMEN_INSTALL_MEMBER_OUTER_ENTRYPOINT - 1]
            .sha256, 32);
    hex_bytes(authority->receipt.members[PLAMEN_INSTALL_MEMBER_SERVICE - 1]
            .cdhash,
        authority->receipt.members[PLAMEN_INSTALL_MEMBER_SERVICE - 1]
            .cdhash_size, cdhash_hex);
    if (snprintf(authority->broker_code_requirement,
            sizeof(authority->broker_code_requirement),
            "identifier \"%s\" and cdhash H\"%s\"",
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_SERVICE - 1]
                .signing_identifier, cdhash_hex)
            >= (int)sizeof(authority->broker_code_requirement))
        goto done;
    if (readiness_only) {
        result = 0;
        goto done;
    }
    hex_bytes(authority->receipt.members[PLAMEN_INSTALL_MEMBER_PYTHON - 1]
            .cdhash,
        authority->receipt.members[PLAMEN_INSTALL_MEMBER_PYTHON - 1]
            .cdhash_size, cdhash_hex);
    if (snprintf(authority->python_code_requirement,
            sizeof(authority->python_code_requirement),
            "identifier \"%s\" and cdhash H\"%s\"",
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_PYTHON - 1]
                .signing_identifier, cdhash_hex)
            >= (int)sizeof(authority->python_code_requirement)
        || digest_fixed_invocation(authority,
            authority->python_argv_sha256,
            authority->python_environment_sha256) != 0)
        goto done;
    if (collect_request_authority(authority, install_root_fd,
            password.pw_dir, password.pw_name) != 0)
        goto done;
    result = 0;
done:
    if (deployment_receipt_fd >= 0)
        close(deployment_receipt_fd);
    if (generations_fd >= 0)
        close(generations_fd);
    if (ancestry_root_fd >= 0)
        close(ancestry_root_fd);
    if (install_root_fd >= 0)
        close(install_root_fd);
    if (self_fd >= 0)
        close(self_fd);
    plamen_broker_v2_secure_zero(receipt_bytes, sizeof(receipt_bytes));
    plamen_broker_v2_secure_zero(cdhash_hex, sizeof(cdhash_hex));
    plamen_broker_v2_secure_zero(launcher_requirement,
        sizeof(launcher_requirement));
    return result;
}

static int
open_admitted_file(const char *path, const uint8_t expected_sha256[32], int *out)
{
    uint8_t digest[32];
    struct stat information;
    int descriptor;

    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) < 0
        || !S_ISREG(information.st_mode) || information.st_nlink == 0
        || sha256_fd(descriptor, digest) < 0
        || !constant_equal(digest, expected_sha256, sizeof(digest))) {
        if (descriptor >= 0)
            close(descriptor);
        return -1;
    }
    *out = descriptor;
    return 0;
}

static int
copy_cf_string(CFTypeRef value, char output[256])
{
    if (value == NULL) {
        output[0] = '\0';
        return 0;
    }
    return CFGetTypeID(value) == CFStringGetTypeID()
        && CFStringGetCString((CFStringRef)value, output, 256,
            kCFStringEncodingUTF8) ? 0 : -1;
}

static int
copy_signing_fields(CFDictionaryRef information,
    struct plamen_launcher_code_identity *identity)
{
    CFTypeRef unique;
    CFIndex size;
    memset(identity, 0, sizeof(*identity));
    if (information == NULL
        || CFGetTypeID(information) != CFDictionaryGetTypeID()
        || copy_cf_string(CFDictionaryGetValue(information,
                kSecCodeInfoIdentifier), identity->identifier) < 0
        || copy_cf_string(CFDictionaryGetValue(information,
                kSecCodeInfoTeamIdentifier), identity->team) < 0)
        return -1;
    unique = CFDictionaryGetValue(information, kSecCodeInfoUnique);
    if (unique == NULL || CFGetTypeID(unique) != CFDataGetTypeID())
        return -1;
    size = CFDataGetLength((CFDataRef)unique);
    if (size <= 0 || size > (CFIndex)sizeof(identity->cdhash))
        return -1;
    CFDataGetBytes((CFDataRef)unique, CFRangeMake(0, size),
        identity->cdhash);
    identity->cdhash_size = (uint32_t)size;
    return 0;
}

static int
dynamic_code_identity(pid_t child, const char *requirement_text,
    struct plamen_launcher_code_identity *identity)
{
    CFNumberRef pid_number = NULL;
    CFDictionaryRef attributes = NULL;
    CFStringRef requirement_string = NULL;
    SecRequirementRef requirement = NULL;
    SecCodeRef guest = NULL;
    CFDictionaryRef information = NULL;
    const void *keys[1] = { kSecGuestAttributePid };
    const void *values[1];
    int32_t exact_pid = child;
    int result = -1;

    if (requirement_text == NULL || requirement_text[0] == '\0')
        return -1;
    pid_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type,
        &exact_pid);
    requirement_string = CFStringCreateWithCString(kCFAllocatorDefault,
        requirement_text, kCFStringEncodingUTF8);
    if (pid_number == NULL || requirement_string == NULL)
        goto done;
    values[0] = pid_number;
    attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (attributes == NULL
        || SecRequirementCreateWithString(requirement_string,
            kSecCSDefaultFlags, &requirement) != errSecSuccess
        || SecCodeCopyGuestWithAttributes(NULL, attributes,
            kSecCSDefaultFlags, &guest) != errSecSuccess
        || SecCodeCheckValidity(guest, kSecCSStrictValidate,
            requirement) != errSecSuccess
        || SecCodeCopySigningInformation(guest, kSecCSSigningInformation,
            &information) != errSecSuccess
        || copy_signing_fields(information, identity) < 0)
        goto done;
    result = 0;
done:
    if (information != NULL)
        CFRelease(information);
    if (guest != NULL)
        CFRelease(guest);
    if (requirement != NULL)
        CFRelease(requirement);
    if (attributes != NULL)
        CFRelease(attributes);
    if (requirement_string != NULL)
        CFRelease(requirement_string);
    if (pid_number != NULL)
        CFRelease(pid_number);
    return result;
}

static int
static_code_identity(const char *path, const char *requirement_text,
    struct plamen_launcher_code_identity *identity)
{
    CFURLRef url = NULL;
    CFStringRef requirement_string = NULL;
    SecRequirementRef requirement = NULL;
    SecStaticCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    int result = -1;

    url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
        (const UInt8 *)path, (CFIndex)strlen(path), false);
    requirement_string = CFStringCreateWithCString(kCFAllocatorDefault,
        requirement_text, kCFStringEncodingUTF8);
    if (url == NULL || requirement_string == NULL
        || SecRequirementCreateWithString(requirement_string,
            kSecCSDefaultFlags, &requirement) != errSecSuccess
        || SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags,
            &code) != errSecSuccess
        || SecStaticCodeCheckValidity(code, kSecCSStrictValidate,
            requirement) != errSecSuccess
        || SecCodeCopySigningInformation(code, kSecCSSigningInformation,
            &information) != errSecSuccess
        || copy_signing_fields(information, identity) < 0)
        goto done;
    result = 0;
done:
    if (information != NULL)
        CFRelease(information);
    if (code != NULL)
        CFRelease(code);
    if (requirement != NULL)
        CFRelease(requirement);
    if (requirement_string != NULL)
        CFRelease(requirement_string);
    if (url != NULL)
        CFRelease(url);
    return result;
}

static int
attest_suspended_python(pid_t child, int retained_python,
    const struct plamen_launcher_authority *authority,
    const struct plamen_broker_v2_peer_identity *expected_peer)
{
    struct plamen_broker_v2_peer_identity observed_peer;
    struct plamen_launcher_code_identity dynamic_identity, static_identity;
    struct stat retained_info, path_info;
    uint8_t retained_digest[32], path_digest[32];
    char path[PROC_PIDPATHINFO_MAXSIZE];
    int path_fd = -1;
    int amount;
    int result = -1;

    memset(path, 0, sizeof(path));
    amount = proc_pidpath(child, path, sizeof(path));
    if (amount <= 0 || (size_t)amount >= sizeof(path)
        || strcmp(path, authority->python_path) != 0
        || peer_identity(child, &observed_peer) < 0
        || !same_peer(&observed_peer, expected_peer) || getpgid(child) != child)
        goto done;
    path_fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (path_fd < 0 || fstat(path_fd, &path_info) < 0
        || fstat(retained_python, &retained_info) < 0
        || !same_vnode(&path_info, &retained_info)
        || sha256_fd(path_fd, path_digest) < 0
        || sha256_fd(retained_python, retained_digest) < 0
        || !constant_equal(path_digest,
            authority->python_executable_sha256, 32)
        || !constant_equal(retained_digest,
            authority->python_executable_sha256, 32)
        || dynamic_code_identity(child, authority->python_code_requirement,
            &dynamic_identity) < 0
        || static_code_identity(path, authority->python_code_requirement,
            &static_identity) < 0
        || dynamic_identity.cdhash_size != static_identity.cdhash_size
        || !constant_equal(dynamic_identity.cdhash, static_identity.cdhash,
            dynamic_identity.cdhash_size)
        || strcmp(dynamic_identity.identifier, static_identity.identifier) != 0
        || strcmp(dynamic_identity.team, static_identity.team) != 0
        || peer_identity(child, &observed_peer) < 0
        || !same_peer(&observed_peer, expected_peer))
        goto done;
    result = 0;
done:
    if (path_fd >= 0)
        close(path_fd);
    return result;
}

static int
xpc_dictionary_has_exact_envelope(xpc_object_t dictionary)
{
    __block size_t count = 0;
    __block int valid = 1;
    if (xpc_get_type(dictionary) != XPC_TYPE_DICTIONARY)
        return 0;
    xpc_dictionary_apply(dictionary, ^bool(const char *key, xpc_object_t value) {
        count++;
        if (strcmp(key, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE) != 0
            || xpc_get_type(value) != XPC_TYPE_DATA)
            valid = 0;
        return true;
    });
    return valid && count == 1;
}

static int
send_service_envelope(const uint8_t *envelope, size_t envelope_size,
    const uint8_t *projection, size_t projection_size,
    const int authority_fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT],
    uint16_t authority_presence_mask,
    const char *broker_requirement, uint8_t **reply_bytes,
    size_t *reply_size, struct plamen_broker_v2_peer_identity *service_peer)
{
    xpc_connection_t connection = NULL;
    xpc_object_t message = NULL;
    dispatch_semaphore_t semaphore = NULL;
    __block xpc_object_t reply = NULL;
    int status = -1;

    if (broker_requirement == NULL || broker_requirement[0] == '\0')
        return -1;
    connection = xpc_connection_create_mach_service(
        PLAMEN_BROKER_V2_DARWIN_SERVICE_NAME, NULL, 0);
    if (connection == NULL
        || xpc_connection_set_peer_code_signing_requirement(connection,
            broker_requirement) != 0)
        goto done;
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    xpc_connection_activate(connection);
    message = xpc_dictionary_create(NULL, NULL, 0);
    semaphore = dispatch_semaphore_create(0);
    if (message == NULL || semaphore == NULL)
        goto done;
    xpc_dictionary_set_data(message, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE,
        envelope, envelope_size);
    if (projection != NULL)
        xpc_dictionary_set_data(message,
            PLAMEN_BROKER_V2_XPC_KEY_REQUEST_PROJECTION,
            projection, projection_size);
    for (size_t slot = 0;
         slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++slot) {
        char key[16];
        uint16_t bit = (uint16_t)(UINT16_C(1) << slot);
        int amount;
        if ((authority_presence_mask & bit) == 0)
            continue;
        if (authority_fds == NULL || authority_fds[slot] < 0)
            goto done;
        amount = snprintf(key, sizeof(key), "%s%02zu",
            PLAMEN_BROKER_V2_XPC_KEY_AUTHORITY_PREFIX, slot);
        if (amount <= 0 || amount >= (int)sizeof(key))
            goto done;
        xpc_dictionary_set_fd(message, key, authority_fds[slot]);
    }
    xpc_connection_send_message_with_reply(connection, message,
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        ^(xpc_object_t response) {
            reply = xpc_retain(response);
            dispatch_semaphore_signal(semaphore);
        });
    if (dispatch_semaphore_wait(semaphore,
            dispatch_time(DISPATCH_TIME_NOW,
                PLAMEN_LAUNCHER_XPC_TIMEOUT_NS)) != 0) {
        xpc_connection_cancel(connection);
        goto done;
    }
    if (!xpc_dictionary_has_exact_envelope(reply))
        goto done;
    if (service_peer != NULL
        && peer_identity(xpc_connection_get_pid(connection), service_peer) != 0)
        goto done;
    {
        const void *data;
        size_t size = 0;
        data = xpc_dictionary_get_data(reply,
            PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE, &size);
        if (data == NULL || size == 0
            || size > PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE
                + PLAMEN_BROKER_V2_SERVICE_MAX_PAYLOAD)
            goto done;
        *reply_bytes = malloc(size);
        if (*reply_bytes == NULL)
            goto done;
        memcpy(*reply_bytes, data, size);
        *reply_size = size;
    }
    status = 0;
done:
    if (reply != NULL)
        xpc_release(reply);
    if (message != NULL)
        xpc_release(message);
    if (connection != NULL) {
        xpc_connection_cancel(connection);
        xpc_release(connection);
    }
    return status;
}

static int
service_readiness(const struct plamen_launcher_authority *authority)
{
    struct plamen_broker_v2_service_readiness readiness;
    struct plamen_broker_v2_service_ready ready;
    struct plamen_broker_v2_service_envelope_view reply_view;
    struct plamen_broker_v2_peer_identity actual_service_peer;
    uint8_t payload[PLAMEN_BROKER_V2_SERVICE_READINESS_SIZE];
    uint8_t transaction_nonce[32], invocation_nonce[32];
    uint8_t request_envelope_sha256[32];
    uint8_t *envelope = NULL, *reply = NULL;
    size_t envelope_size = 0, reply_size = 0;
    int status = -1;

    memset(&readiness, 0, sizeof(readiness));
    memset(&ready, 0, sizeof(ready));
    memset(&reply_view, 0, sizeof(reply_view));
    memset(&actual_service_peer, 0, sizeof(actual_service_peer));
    memcpy(readiness.installed_closure_sha256,
        authority->installed_closure_sha256, 32);
    memcpy(readiness.broker_closure_sha256,
        authority->broker_closure_sha256, 32);
    memcpy(readiness.installation_receipt_sha256,
        authority->installation_receipt_sha256, 32);
    if (getentropy(transaction_nonce, sizeof(transaction_nonce)) != 0
        || getentropy(invocation_nonce, sizeof(invocation_nonce)) != 0
        || plamen_broker_v2_service_readiness_encode(
            &readiness, payload) != 0
        || plamen_broker_v2_service_envelope_build(
            PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER,
            PLAMEN_BROKER_V2_SERVICE_READINESS,
            transaction_nonce, invocation_nonce, payload, sizeof(payload), 0,
            &envelope, &envelope_size) != 0
        || plamen_broker_v2_sha256(envelope, envelope_size,
            request_envelope_sha256) != 0
        || send_service_envelope(envelope, envelope_size, NULL, 0, NULL, 0,
            authority->broker_code_requirement, &reply, &reply_size,
            &actual_service_peer) != 0
        || plamen_broker_v2_service_envelope_accept(
            PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER, reply, reply_size, 0,
            &reply_view) != 0
        || reply_view.type != PLAMEN_BROKER_V2_SERVICE_READY
        || !constant_equal(reply_view.transaction_nonce,
            transaction_nonce, 32)
        || !constant_equal(reply_view.invocation_nonce,
            invocation_nonce, 32)
        || plamen_broker_v2_service_ready_decode(reply_view.payload,
            reply_view.payload_size, &ready) != 0
        || !plamen_broker_v2_service_ready_matches_readiness(
            &readiness, request_envelope_sha256, &ready)
        || !same_peer(&actual_service_peer, &ready.service_peer))
        goto done;
    status = 0;
done:
    if (envelope != NULL) {
        plamen_broker_v2_secure_zero(envelope, envelope_size);
        free(envelope);
    }
    if (reply != NULL) {
        plamen_broker_v2_secure_zero(reply, reply_size);
        free(reply);
    }
    plamen_broker_v2_secure_zero(&readiness, sizeof(readiness));
    plamen_broker_v2_secure_zero(&ready, sizeof(ready));
    plamen_broker_v2_secure_zero(transaction_nonce,
        sizeof(transaction_nonce));
    plamen_broker_v2_secure_zero(invocation_nonce,
        sizeof(invocation_nonce));
    return status;
}

static int
register_suspended_child(
    const struct plamen_launcher_authority *authority,
    const struct plamen_broker_v2_peer_identity *launcher_peer,
    const struct plamen_broker_v2_peer_identity *child_peer)
{
    struct plamen_broker_v2_service_registration registration;
    struct plamen_broker_v2_service_registration_ack acknowledgement;
    struct plamen_broker_v2_service_envelope_view reply_view;
    uint8_t payload[PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE];
    uint8_t transaction_nonce[32], invocation_nonce[32];
    uint8_t payload_digest[32], request_envelope_digest[32];
    uint8_t *envelope = NULL, *reply = NULL;
    size_t envelope_size = 0, reply_size = 0;
    uint16_t registration_fd_count = 0;
    uint16_t message_type;
    int status = -1;

    memset(&registration, 0, sizeof(registration));
    memset(&acknowledgement, 0, sizeof(acknowledgement));
    memset(&reply_view, 0, sizeof(reply_view));
    memcpy(registration.installed_closure_sha256,
        authority->installed_closure_sha256, 32);
    memcpy(registration.committed_audit_generation_sha256,
        authority->committed_audit_generation_sha256, 32);
    memcpy(registration.audit_request_fingerprint,
        authority->audit_request_fingerprint, 32);
    memcpy(registration.request_projection_sha256,
        authority->request_projection_sha256, 32);
    registration.request_projection_size =
        (uint32_t)authority->request_projection_size;
    memcpy(registration.commitment_sha256,
        authority->commitment_sha256, 32);
    registration.commitment_size = authority->commitment_size;
    memcpy(registration.commitment, authority->commitment,
        authority->commitment_size);
    memcpy(registration.python_entrypoint_sha256,
        authority->python_entrypoint_sha256, 32);
    memcpy(registration.python_argv_sha256,
        authority->python_argv_sha256, 32);
    memcpy(registration.python_environment_sha256,
        authority->python_environment_sha256, 32);
    registration.launcher = *launcher_peer;
    registration.suspended_child = *child_peer;
    memcpy(registration.prior_audit_checkpoint_sha256,
        authority->prior_audit_checkpoint_sha256, 32);
    registration.initial_interpreter_slot = 0;
    registration.initial_authority_role =
        PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    registration.authority_presence_mask =
        authority->authority_presence_mask;
    for (size_t slot = 0;
         slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++slot) {
        uint16_t bit = (uint16_t)(UINT16_C(1) << slot);
        if ((registration.authority_presence_mask & bit) == 0)
            continue;
        registration.authority_descriptors[slot].purpose =
            (uint16_t)(PLAMEN_BROKER_V2_FD_AUTHORITY_CONFIG + slot);
        registration.authority_descriptors[slot].target =
            (uint16_t)(slot + 1U);
        registration.authority_descriptors[slot].access_mode =
            PLAMEN_BROKER_V2_FD_READ;
        memcpy(registration.authority_descriptors[slot].identity,
            authority->authority_identities[slot], 32);
    }
    message_type = all_zero(authority->prior_audit_checkpoint_sha256)
        ? PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
        : PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY;
    if (getentropy(transaction_nonce, sizeof(transaction_nonce)) < 0
        || getentropy(invocation_nonce, sizeof(invocation_nonce)) < 0
        || plamen_broker_v2_service_registration_fd_count(&registration,
            &registration_fd_count) != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_service_registration_encode(&registration,
            payload) != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_sha256(payload, sizeof(payload),
            payload_digest) != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_service_envelope_build(
            PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER,
            message_type, transaction_nonce, invocation_nonce, payload,
            sizeof(payload), registration_fd_count,
            &envelope, &envelope_size) != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_sha256(envelope, envelope_size,
            request_envelope_digest) != PLAMEN_BROKER_V2_OK
        || send_service_envelope(envelope, envelope_size,
            authority->request_projection, authority->request_projection_size,
            authority->authority_fds, authority->authority_presence_mask,
            authority->broker_code_requirement, &reply, &reply_size, NULL) < 0
        || plamen_broker_v2_service_envelope_accept(
            PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER, reply, reply_size, 0,
            &reply_view) != PLAMEN_BROKER_V2_OK
        || reply_view.type !=
            PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACCEPTED
        || !constant_equal(reply_view.transaction_nonce,
            transaction_nonce, 32)
        || !constant_equal(reply_view.invocation_nonce,
            invocation_nonce, 32)
        || plamen_broker_v2_service_registration_ack_decode(
            reply_view.payload, reply_view.payload_size,
            &acknowledgement) != PLAMEN_BROKER_V2_OK
        || !constant_equal(acknowledgement.request_envelope_sha256,
            request_envelope_digest, 32)
        || !constant_equal(acknowledgement.registration_sha256,
            payload_digest, 32)
        || !constant_equal(acknowledgement.broker_closure_sha256,
            authority->broker_closure_sha256, 32)
        || !same_peer(&acknowledgement.suspended_child, child_peer)
        || acknowledgement.initial_interpreter_slot != 0
        || acknowledgement.initial_authority_role !=
            PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR
        || acknowledgement.issuance_state != 0)
        goto done;
    status = 0;
done:
    if (envelope != NULL) {
        plamen_broker_v2_secure_zero(envelope, envelope_size);
        free(envelope);
    }
    if (reply != NULL) {
        plamen_broker_v2_secure_zero(reply, reply_size);
        free(reply);
    }
    plamen_broker_v2_secure_zero(transaction_nonce,
        sizeof(transaction_nonce));
    plamen_broker_v2_secure_zero(invocation_nonce,
        sizeof(invocation_nonce));
    plamen_broker_v2_secure_zero(&registration, sizeof(registration));
    plamen_broker_v2_secure_zero(&acknowledgement,
        sizeof(acknowledgement));
    return status;
}

static int
kill_and_reap(pid_t child)
{
    int wait_status;
    pid_t waited;
    if (child <= 0)
        return -1;
    if (kill(-child, SIGKILL) < 0 && errno != ESRCH)
        (void)kill(child, SIGKILL);
    do {
        waited = waitpid(child, &wait_status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child ? 0 : -1;
}

static int
spawn_register_and_resume(const struct plamen_launcher_authority *authority)
{
    posix_spawnattr_t attributes;
    sigset_t empty, defaults;
    short flags = POSIX_SPAWN_START_SUSPENDED
        | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP
        | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
    struct plamen_broker_v2_peer_identity launcher_peer, child_peer;
    uint8_t argv_digest[32], environment_digest[32];
    int python_fd = -1, entrypoint_fd = -1;
    int attributes_ready = 0;
    pid_t child = -1;
    int wait_status;
    int waited;
    int result = PLAMEN_LAUNCHER_HARDSTOP;
    char *const child_argv[] = {
        (char *)authority->python_path,
        "-I",
        "-B",
        (char *)authority->entrypoint_path,
        NULL
    };

    if (all_zero(authority->installed_closure_sha256)
        || all_zero(authority->committed_audit_generation_sha256)
        || all_zero(authority->audit_request_fingerprint)
        || all_zero(authority->broker_closure_sha256)
        || authority->python_code_requirement[0] == '\0'
        || authority->broker_code_requirement[0] == '\0'
        || digest_fixed_invocation(authority,
            argv_digest, environment_digest) < 0
        || !constant_equal(argv_digest, authority->python_argv_sha256, 32)
        || !constant_equal(environment_digest,
            authority->python_environment_sha256, 32)
        || peer_identity(getpid(), &launcher_peer) < 0
        || open_admitted_file(authority->python_path,
            authority->python_executable_sha256, &python_fd) < 0
        || open_admitted_file(authority->entrypoint_path,
            authority->python_entrypoint_sha256, &entrypoint_fd) < 0)
        goto done;
    if (posix_spawnattr_init(&attributes) != 0)
        goto done;
    attributes_ready = 1;
    sigemptyset(&empty);
    sigfillset(&defaults);
    sigdelset(&defaults, SIGKILL);
    sigdelset(&defaults, SIGSTOP);
    if (posix_spawnattr_setflags(&attributes, flags) != 0
        || posix_spawnattr_setpgroup(&attributes, 0) != 0
        || posix_spawnattr_setsigmask(&attributes, &empty) != 0
        || posix_spawnattr_setsigdefault(&attributes, &defaults) != 0
        || posix_spawn(&child, authority->python_path, NULL, &attributes,
            child_argv, closed_environment) != 0)
        goto done;
    /* PID custody starts immediately; every later error kills and reaps. */
    if (peer_identity(child, &child_peer) < 0
        || attest_suspended_python(child, python_fd, authority,
            &child_peer) < 0
        || register_suspended_child(authority, &launcher_peer,
            &child_peer) < 0
        || kill(child, SIGCONT) < 0) {
        (void)kill_and_reap(child);
        child = -1;
        goto done;
    }
    do {
        waited = waitpid(child, &wait_status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child)
        result = PLAMEN_LAUNCHER_HARDSTOP;
    else if (WIFEXITED(wait_status))
        result = WEXITSTATUS(wait_status);
    else if (WIFSIGNALED(wait_status))
        result = 128 + WTERMSIG(wait_status);
    else
        result = PLAMEN_LAUNCHER_HARDSTOP;
done:
    if (attributes_ready)
        posix_spawnattr_destroy(&attributes);
    if (python_fd >= 0)
        close(python_fd);
    if (entrypoint_fd >= 0)
        close(entrypoint_fd);
    return result;
}

int
main(int argc, char **argv)
{
    struct plamen_launcher_authority authority;
    int status;
    /* The caller selects only one typed intent and one untrusted config path. */
    if (!((argc == 2 && strcmp(argv[1], "readiness") == 0)
            || (argc == 3
                && (strcmp(argv[1], "start-config") == 0
                    || strcmp(argv[1], "resume") == 0)
                && canonical_absolute_path(argv[2]))))
        return 64;
    status = admit_authority(&authority, argv[1], argc == 3 ? argv[2] : NULL);
    if (status != 0) {
        close_authority(&authority);
        fputs("PLAMEN_NATIVE_LAUNCHER_HARDSTOP_NATIVE_AUDIT_AUTHORITY_REQUIRED\n",
            stderr);
        return PLAMEN_LAUNCHER_HARDSTOP;
    }
    status = service_readiness(&authority);
    if (status == 0 && argc == 3)
        status = spawn_register_and_resume(&authority);
    close_authority(&authority);
    return status;
}
