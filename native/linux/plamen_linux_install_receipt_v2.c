#define _GNU_SOURCE 1

#include "plamen_linux_install_receipt_v2.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <openssl/evp.h>
#endif

#define RECEIPT_HEADER_SIZE 1024U
#define RECEIPT_MEMBER_SIZE 1024U
#define RECEIPT_MEMBERS_OFFSET 1024U
#define RECEIPT_RESERVED_OFFSET 5120U
#define RECEIPT_SOCKET_OFFSET 512U
#define RECEIPT_SOABI_OFFSET 768U
#define RECEIPT_IMPLEMENTATION_OFFSET 896U
#define MEMBER_PATH_OFFSET 184U
#define MEMBER_INTERP_OFFSET 440U

static const uint8_t receipt_magic[8] = {
    'P', 'L', 'N', 'L', 'I', 'R', '2', '\0'
};
static const uint32_t member_modes[
    PLAMEN_LINUX_INSTALL_RECEIPT_V2_MEMBER_COUNT] = {
    0500U, 0400U, 0500U, 0500U
};

static uint16_t
load_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t
load_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t
load_u64(const uint8_t *p)
{
    return ((uint64_t)load_u32(p) << 32) | load_u32(p + 4);
}

static void
store_u16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void
store_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static void
store_u64(uint8_t *p, uint64_t value)
{
    store_u32(p, (uint32_t)(value >> 32));
    store_u32(p + 4, (uint32_t)value);
}

static int
all_zero(const uint8_t *p, size_t size)
{
    uint8_t aggregate = 0;
    size_t index;
    for (index = 0; index < size; ++index)
        aggregate |= p[index];
    return aggregate == 0;
}

static int
digest_present(const uint8_t digest[32])
{
    return !all_zero(digest, 32);
}

static int
string_slot_valid(const char *value, size_t maximum, int absolute)
{
    size_t index, size;
    if (value == NULL)
        return 0;
    size = strnlen(value, maximum + 1U);
    if (size == 0 || size > maximum || (absolute && value[0] != '/')
        || (!absolute && value[0] == '/'))
        return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < 0x21 || byte > 0x7e || byte == '\\')
            return 0;
    }
    return value[size - 1] != '/'
        && strcmp(value, ".") != 0 && strcmp(value, "..") != 0
        && strncmp(value, "./", 2) != 0 && strncmp(value, "../", 3) != 0
        && strstr(value, "//") == NULL && strstr(value, "/./") == NULL
        && strstr(value, "/../") == NULL
        && !(size >= 2 && strcmp(value + size - 2, "/.") == 0)
        && !(size >= 3 && strcmp(value + size - 3, "/..") == 0);
}

static int
identifier_valid(const char *value, size_t maximum)
{
    size_t index, size;
    if (value == NULL)
        return 0;
    size = strnlen(value, maximum + 1U);
    if (size == 0 || size > maximum)
        return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z')
                || (byte >= '0' && byte <= '9') || byte == '.'
                || byte == '_' || byte == '-'))
            return 0;
    }
    return 1;
}

static int
expected_socket(uint16_t scope, uint32_t uid, uint32_t gid,
    char output[PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX + 1])
{
    int amount;
    if (scope == PLAMEN_LINUX_INSTALL_SCOPE_GUEST_ROOT) {
        if (uid != 0 || gid != 0)
            return -1;
        memcpy(output, PLAMEN_LINUX_GUEST_SOCKET_PATH,
            sizeof(PLAMEN_LINUX_GUEST_SOCKET_PATH));
        return 0;
    }
    if (scope != PLAMEN_LINUX_INSTALL_SCOPE_OUTER_USER || uid == 0)
        return -1;
    amount = snprintf(output, PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX + 1,
        "%s%u%s", PLAMEN_LINUX_OUTER_SOCKET_PREFIX, uid,
        PLAMEN_LINUX_OUTER_SOCKET_SUFFIX);
    return amount > 0
        && amount <= (int)PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX ? 0 : -1;
}

static int
member_valid(const struct plamen_linux_install_member_v2 *member,
    uint16_t role, uint16_t architecture, uint32_t uid, uint32_t gid)
{
    const char *expected_interp;
    if (member == NULL || member->role != role
        || !string_slot_valid(member->relative_path,
            PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX, 0)
        || !string_slot_valid(member->elf_interp_path,
            PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX, 1)
        || member->mode != member_modes[role - 1U]
        || member->uid != uid || member->gid != gid
        || member->byte_count == 0 || member->device == 0
        || member->inode == 0 || member->link_count != 1
        || !digest_present(member->sha256)
        || !digest_present(member->fd_identity)
        || !digest_present(member->elf_interp_identity_sha256)
        || !digest_present(member->elf_needed_closure_sha256))
        return 0;
    expected_interp = architecture == PLAMEN_LINUX_INSTALL_ARCH_X86_64
        ? "/lib64/ld-linux-x86-64.so.2"
        : "/lib/ld-linux-aarch64.so.1";
    return strcmp(member->elf_interp_path, expected_interp) == 0;
}

static int
receipt_valid(const struct plamen_linux_install_receipt_v2 *receipt)
{
    char socket_path[PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX + 1];
    uint16_t expected_machine;
    size_t index;
    if (receipt == NULL
        || expected_socket(receipt->scope, receipt->expected_uid,
            receipt->expected_gid, socket_path) != 0
        || strcmp(socket_path, receipt->socket_path) != 0
        || (receipt->target_arch != PLAMEN_LINUX_INSTALL_ARCH_X86_64
            && receipt->target_arch != PLAMEN_LINUX_INSTALL_ARCH_AARCH64)
        || receipt->elf_class != 2 || receipt->elf_data != 1
        || receipt->trust_boundary !=
            PLAMEN_LINUX_INSTALL_TRUST_RETAINED_IMMUTABLE_SIGNED_GENERATION
        || receipt->python_major != 3 || receipt->python_minor != 12
        || strcmp(receipt->python_implementation, "cpython") != 0
        || !identifier_valid(receipt->python_soabi,
            PLAMEN_LINUX_INSTALL_RECEIPT_V2_SOABI_MAX))
        return 0;
    expected_machine = receipt->target_arch == PLAMEN_LINUX_INSTALL_ARCH_X86_64
        ? 62U : 183U;
    if (receipt->elf_machine != expected_machine
        || !digest_present(receipt->generation_id_sha256)
        || !digest_present(receipt->install_provenance_sha256)
        || !digest_present(receipt->installed_closure_sha256)
        || !digest_present(receipt->protocol_schema_sha256)
        || !digest_present(receipt->runtime_package_manifest_sha256)
        || !digest_present(receipt->native_deployment_receipt_sha256)
        || !digest_present(receipt->install_root_fd_identity)
        || !digest_present(receipt->receipt_producer_identity_sha256))
        return 0;
    for (index = 0; index < PLAMEN_LINUX_INSTALL_RECEIPT_V2_MEMBER_COUNT;
            ++index) {
        if (!member_valid(&receipt->members[index], (uint16_t)(index + 1),
                receipt->target_arch, receipt->expected_uid,
                receipt->expected_gid))
            return 0;
    }
    return 1;
}

static void
encode_member(const struct plamen_linux_install_member_v2 *member,
    uint8_t output[RECEIPT_MEMBER_SIZE])
{
    size_t path_size = strlen(member->relative_path);
    size_t interp_size = strlen(member->elf_interp_path);
    memset(output, 0, RECEIPT_MEMBER_SIZE);
    store_u16(output, member->role);
    store_u16(output + 2, (uint16_t)path_size);
    store_u16(output + 4, (uint16_t)interp_size);
    store_u32(output + 8, member->mode);
    store_u32(output + 12, member->uid);
    store_u32(output + 16, member->gid);
    store_u64(output + 24, member->byte_count);
    store_u64(output + 32, member->device);
    store_u64(output + 40, member->inode);
    store_u64(output + 48, member->link_count);
    memcpy(output + 56, member->sha256, 32);
    memcpy(output + 88, member->fd_identity, 32);
    memcpy(output + 120, member->elf_interp_identity_sha256, 32);
    memcpy(output + 152, member->elf_needed_closure_sha256, 32);
    memcpy(output + MEMBER_PATH_OFFSET, member->relative_path, path_size);
    memcpy(output + MEMBER_INTERP_OFFSET, member->elf_interp_path, interp_size);
}

int
plamen_linux_install_receipt_v2_encode_exact(
    const struct plamen_linux_install_receipt_v2 *receipt,
    uint8_t *output, size_t output_size)
{
    size_t index;
    uint8_t digest[32];
    if (output == NULL || output_size != PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE
        || !receipt_valid(receipt))
        return -1;
    memset(output, 0, output_size);
    memcpy(output, receipt_magic, sizeof(receipt_magic));
    store_u16(output + 8, PLAMEN_LINUX_INSTALL_RECEIPT_V2_VERSION);
    store_u16(output + 10, RECEIPT_HEADER_SIZE);
    store_u32(output + 12, PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE);
    store_u16(output + 16, receipt->scope);
    store_u16(output + 18, receipt->target_arch);
    store_u16(output + 20, receipt->elf_class);
    store_u16(output + 22, receipt->elf_data);
    store_u32(output + 24, receipt->elf_machine);
    store_u16(output + 28, receipt->trust_boundary);
    store_u16(output + 30, PLAMEN_LINUX_INSTALL_RECEIPT_V2_MEMBER_COUNT);
    store_u32(output + 32, receipt->expected_uid);
    store_u32(output + 36, receipt->expected_gid);
    store_u16(output + 40, (uint16_t)strlen(receipt->socket_path));
    store_u16(output + 42, (uint16_t)strlen(receipt->python_soabi));
    store_u16(output + 44,
        (uint16_t)strlen(receipt->python_implementation));
    store_u16(output + 46, receipt->python_major);
    store_u16(output + 48, receipt->python_minor);
    memcpy(output + 64, receipt->generation_id_sha256, 32);
    memcpy(output + 96, receipt->install_provenance_sha256, 32);
    memcpy(output + 128, receipt->installed_closure_sha256, 32);
    memcpy(output + 160, receipt->protocol_schema_sha256, 32);
    memcpy(output + 192, receipt->runtime_package_manifest_sha256, 32);
    memcpy(output + 224, receipt->native_deployment_receipt_sha256, 32);
    memcpy(output + 256, receipt->install_root_fd_identity, 32);
    memcpy(output + 288, receipt->receipt_producer_identity_sha256, 32);
    memcpy(output + RECEIPT_SOCKET_OFFSET, receipt->socket_path,
        strlen(receipt->socket_path));
    memcpy(output + RECEIPT_SOABI_OFFSET, receipt->python_soabi,
        strlen(receipt->python_soabi));
    memcpy(output + RECEIPT_IMPLEMENTATION_OFFSET,
        receipt->python_implementation, strlen(receipt->python_implementation));
    for (index = 0; index < PLAMEN_LINUX_INSTALL_RECEIPT_V2_MEMBER_COUNT;
            ++index)
        encode_member(&receipt->members[index], output + RECEIPT_MEMBERS_OFFSET
            + index * RECEIPT_MEMBER_SIZE);
    if (plamen_broker_v2_sha256(output,
            PLAMEN_LINUX_INSTALL_RECEIPT_V2_HASHED_SIZE, digest) != 0)
        return -1;
    memcpy(output + PLAMEN_LINUX_INSTALL_RECEIPT_V2_HASHED_SIZE, digest, 32);
    return 0;
}

static int
decode_string(const uint8_t *slot, size_t slot_size, uint16_t length,
    char *output, size_t output_size, int absolute)
{
    if (length == 0 || length >= output_size || length > slot_size
        || !all_zero(slot + length, slot_size - length))
        return -1;
    memcpy(output, slot, length);
    output[length] = '\0';
    return string_slot_valid(output, output_size - 1U, absolute) ? 0 : -1;
}

static int
decode_member(const uint8_t *input, uint16_t role,
    struct plamen_linux_install_member_v2 *member)
{
    uint16_t path_size = load_u16(input + 2);
    uint16_t interp_size = load_u16(input + 4);
    memset(member, 0, sizeof(*member));
    if (load_u16(input) != role || load_u16(input + 6) != 0
        || load_u32(input + 20) != 0 || !all_zero(input + 696, 328)
        || decode_string(input + MEMBER_PATH_OFFSET, 256, path_size,
            member->relative_path, sizeof(member->relative_path), 0) != 0
        || decode_string(input + MEMBER_INTERP_OFFSET, 256, interp_size,
            member->elf_interp_path, sizeof(member->elf_interp_path), 1) != 0)
        return -1;
    member->role = role;
    member->mode = load_u32(input + 8);
    member->uid = load_u32(input + 12);
    member->gid = load_u32(input + 16);
    member->byte_count = load_u64(input + 24);
    member->device = load_u64(input + 32);
    member->inode = load_u64(input + 40);
    member->link_count = load_u64(input + 48);
    memcpy(member->sha256, input + 56, 32);
    memcpy(member->fd_identity, input + 88, 32);
    memcpy(member->elf_interp_identity_sha256, input + 120, 32);
    memcpy(member->elf_needed_closure_sha256, input + 152, 32);
    return 0;
}

int
plamen_linux_install_receipt_v2_decode_exact(const uint8_t *input,
    size_t input_size, struct plamen_linux_install_receipt_v2 *receipt)
{
    uint8_t digest[32], canonical[PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE];
    size_t index;
    if (input == NULL || receipt == NULL
        || input_size != PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE)
        return -1;
    memset(receipt, 0, sizeof(*receipt));
    if (memcmp(input, receipt_magic, 8) != 0
        || load_u16(input + 8) != PLAMEN_LINUX_INSTALL_RECEIPT_V2_VERSION
        || load_u16(input + 10) != RECEIPT_HEADER_SIZE
        || load_u32(input + 12) != PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE
        || load_u16(input + 30) !=
            PLAMEN_LINUX_INSTALL_RECEIPT_V2_MEMBER_COUNT
        || load_u16(input + 50) != 0 || load_u32(input + 52) != 0
        || load_u64(input + 56) != 0 || !all_zero(input + 320, 192)
        || !all_zero(input + 960, 64)
        || !all_zero(input + RECEIPT_RESERVED_OFFSET,
            PLAMEN_LINUX_INSTALL_RECEIPT_V2_HASHED_SIZE
                - RECEIPT_RESERVED_OFFSET)
        || plamen_broker_v2_sha256(input,
            PLAMEN_LINUX_INSTALL_RECEIPT_V2_HASHED_SIZE, digest) != 0
        || memcmp(digest,
            input + PLAMEN_LINUX_INSTALL_RECEIPT_V2_HASHED_SIZE, 32) != 0)
        goto invalid;
    receipt->scope = load_u16(input + 16);
    receipt->target_arch = load_u16(input + 18);
    receipt->elf_class = load_u16(input + 20);
    receipt->elf_data = load_u16(input + 22);
    receipt->elf_machine = load_u32(input + 24);
    receipt->trust_boundary = load_u16(input + 28);
    receipt->expected_uid = load_u32(input + 32);
    receipt->expected_gid = load_u32(input + 36);
    receipt->python_major = load_u16(input + 46);
    receipt->python_minor = load_u16(input + 48);
    if (decode_string(input + RECEIPT_SOCKET_OFFSET, 256,
            load_u16(input + 40), receipt->socket_path,
            sizeof(receipt->socket_path), 1) != 0
        || decode_string(input + RECEIPT_SOABI_OFFSET, 128,
            load_u16(input + 42), receipt->python_soabi,
            sizeof(receipt->python_soabi), 0) != 0
        || decode_string(input + RECEIPT_IMPLEMENTATION_OFFSET, 64,
            load_u16(input + 44), receipt->python_implementation,
            sizeof(receipt->python_implementation), 0) != 0)
        goto invalid;
    memcpy(receipt->generation_id_sha256, input + 64, 32);
    memcpy(receipt->install_provenance_sha256, input + 96, 32);
    memcpy(receipt->installed_closure_sha256, input + 128, 32);
    memcpy(receipt->protocol_schema_sha256, input + 160, 32);
    memcpy(receipt->runtime_package_manifest_sha256, input + 192, 32);
    memcpy(receipt->native_deployment_receipt_sha256, input + 224, 32);
    memcpy(receipt->install_root_fd_identity, input + 256, 32);
    memcpy(receipt->receipt_producer_identity_sha256, input + 288, 32);
    for (index = 0; index < PLAMEN_LINUX_INSTALL_RECEIPT_V2_MEMBER_COUNT;
            ++index) {
        if (decode_member(input + RECEIPT_MEMBERS_OFFSET
                + index * RECEIPT_MEMBER_SIZE, (uint16_t)(index + 1),
                &receipt->members[index]) != 0)
            goto invalid;
    }
    memcpy(receipt->receipt_sha256,
        input + PLAMEN_LINUX_INSTALL_RECEIPT_V2_HASHED_SIZE, 32);
    if (!receipt_valid(receipt)
        || plamen_linux_install_receipt_v2_encode_exact(receipt, canonical,
            sizeof(canonical)) != 0
        || memcmp(canonical, input, sizeof(canonical)) != 0)
        goto invalid;
    memset(canonical, 0, sizeof(canonical));
    return 0;
invalid:
    memset(canonical, 0, sizeof(canonical));
    memset(receipt, 0, sizeof(*receipt));
    return -1;
}

#ifdef __linux__
static int
sha256_fd(int fd, uint8_t output[32], struct stat *identity)
{
    struct stat before, after;
    uint8_t buffer[65536];
    off_t offset = 0;
    EVP_MD_CTX *context = NULL;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size <= 0)
        return -1;
    context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
        goto invalid;
    while (offset < before.st_size) {
        size_t wanted = sizeof(buffer);
        ssize_t amount;
        if ((off_t)wanted > before.st_size - offset)
            wanted = (size_t)(before.st_size - offset);
        do {
            amount = pread(fd, buffer, wanted, offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            goto invalid;
        if (EVP_DigestUpdate(context, buffer, (size_t)amount) != 1)
            goto invalid;
        offset += amount;
    }
    if (pread(fd, buffer, 1, before.st_size) != 0 || fstat(fd, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_mode != after.st_mode || before.st_uid != after.st_uid
        || before.st_gid != after.st_gid || before.st_size != after.st_size
        || before.st_nlink != after.st_nlink)
        goto invalid;
    {
        unsigned int size = 0;
        if (EVP_DigestFinal_ex(context, output, &size) != 1 || size != 32)
            goto invalid;
    }
    EVP_MD_CTX_free(context);
    if (identity != NULL)
        *identity = after;
    return 0;
invalid:
    EVP_MD_CTX_free(context);
    memset(output, 0, 32);
    return -1;
}

static int
member_revalidate(int fd, const struct plamen_linux_install_member_v2 *member)
{
    struct stat information;
    uint8_t sha256[32], identity[32];
    int flags = fcntl(fd, F_GETFL), descriptor_flags = fcntl(fd, F_GETFD);
    if (flags < 0 || descriptor_flags < 0
        || (flags & O_ACCMODE) != O_RDONLY
        || (descriptor_flags & FD_CLOEXEC) == 0
        || sha256_fd(fd, sha256, &information) != 0
        || plamen_broker_v2_fd_identity(fd, identity) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || (uint32_t)(information.st_mode & 07777) != member->mode
        || information.st_uid != member->uid || information.st_gid != member->gid
        || (uint64_t)information.st_size != member->byte_count
        || (uint64_t)information.st_dev != member->device
        || (uint64_t)information.st_ino != member->inode
        || (uint64_t)information.st_nlink != member->link_count
        || memcmp(sha256, member->sha256, 32) != 0
        || memcmp(identity, member->fd_identity, 32) != 0)
        return -1;
    return 0;
}
#endif

int
plamen_linux_install_receipt_v2_open_member(int install_root_fd,
    const struct plamen_linux_install_member_v2 *member, int *member_fd)
{
#ifdef __linux__
    struct open_how how;
    int child;
    if (install_root_fd < 0 || member == NULL || member_fd == NULL
        || !string_slot_valid(member->relative_path,
            PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX, 0))
        return -1;
    *member_fd = -1;
    memset(&how, 0, sizeof(how));
    how.flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
        | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    child = (int)syscall(SYS_openat2, install_root_fd,
        member->relative_path, &how, sizeof(how));
    if (child < 0 || member_revalidate(child, member) != 0) {
        if (child >= 0)
            close(child);
        return -1;
    }
    *member_fd = child;
    return 0;
#else
    (void)install_root_fd;
    (void)member;
    (void)member_fd;
    errno = ENOTSUP;
    return -1;
#endif
}

static int
read_receipt_exact(int fd, uint8_t output[PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE],
    uint32_t uid)
{
    struct stat before, after;
    size_t offset = 0;
    int flags = fcntl(fd, F_GETFL), descriptor_flags = fcntl(fd, F_GETFD);
    if (flags < 0 || descriptor_flags < 0
        || (flags & O_ACCMODE) != O_RDONLY
        || (descriptor_flags & FD_CLOEXEC) == 0 || fstat(fd, &before) != 0
        || !S_ISREG(before.st_mode) || before.st_nlink != 1
        || before.st_uid != uid || (before.st_mode & 07777) != 0400
        || before.st_size != PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE)
        return -1;
    while (offset < PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE) {
        ssize_t amount;
        do {
            amount = pread(fd, output + offset,
                PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE - offset, (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            return -1;
        offset += (size_t)amount;
    }
    if (pread(fd, output, 1, PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE) != 0
        || fstat(fd, &after) != 0 || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid || before.st_gid != after.st_gid
        || before.st_nlink != after.st_nlink || before.st_size != after.st_size)
        return -1;
    return 0;
}

int
plamen_linux_install_receipt_v2_revalidate_authority(int receipt_fd,
    int install_root_fd, uint16_t expected_scope, uint32_t expected_uid,
    uint32_t expected_gid, const uint8_t expected_provenance[32],
    const uint8_t expected_protocol[32], const uint8_t expected_deployment[32],
    struct plamen_linux_install_receipt_v2 *receipt)
{
    uint8_t bytes[PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE], root_identity[32];
    struct stat root;
    size_t index;
    int flags, member_fd = -1, result = -1;
    if (receipt == NULL || expected_provenance == NULL
        || expected_protocol == NULL || expected_deployment == NULL
        || !digest_present(expected_provenance)
        || !digest_present(expected_protocol) || !digest_present(expected_deployment)
        || read_receipt_exact(receipt_fd, bytes, expected_uid) != 0
        || plamen_linux_install_receipt_v2_decode_exact(bytes, sizeof(bytes),
            receipt) != 0
        || receipt->scope != expected_scope
        || receipt->expected_uid != expected_uid
        || receipt->expected_gid != expected_gid
        || memcmp(receipt->install_provenance_sha256,
            expected_provenance, 32) != 0
        || memcmp(receipt->protocol_schema_sha256, expected_protocol, 32) != 0
        || memcmp(receipt->native_deployment_receipt_sha256,
            expected_deployment, 32) != 0)
        goto done;
    flags = fcntl(install_root_fd, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) == 0
        || fstat(install_root_fd, &root) != 0 || !S_ISDIR(root.st_mode)
        || root.st_uid != expected_uid || root.st_gid != expected_gid
        || root.st_nlink == 0 || (root.st_mode & 0222) != 0
        || plamen_broker_v2_fd_identity(install_root_fd, root_identity) != 0
        || memcmp(root_identity, receipt->install_root_fd_identity, 32) != 0)
        goto done;
    for (index = 0; index < PLAMEN_LINUX_INSTALL_RECEIPT_V2_MEMBER_COUNT;
            ++index) {
        if (plamen_linux_install_receipt_v2_open_member(install_root_fd,
                &receipt->members[index], &member_fd) != 0)
            goto done;
        close(member_fd);
        member_fd = -1;
    }
    result = 0;
done:
    if (member_fd >= 0)
        close(member_fd);
    memset(bytes, 0, sizeof(bytes));
    if (result != 0 && receipt != NULL)
        memset(receipt, 0, sizeof(*receipt));
    return result;
}

int
plamen_linux_install_receipt_v2_session_binding(
    const struct plamen_linux_install_receipt_v2 *receipt, uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-LINUX-INSTALL-RECEIPT-V2-SESSION-BINDING\0";
    uint8_t bytes[sizeof(domain) + 4 + 4 + 4 + 9 * 32];
    size_t offset = 0;
    if (output == NULL || !receipt_valid(receipt)
        || !digest_present(receipt->receipt_sha256))
        return -1;
    memcpy(bytes + offset, domain, sizeof(domain));
    offset += sizeof(domain);
    store_u32(bytes + offset, receipt->scope);
    offset += 4;
    store_u32(bytes + offset, receipt->expected_uid);
    offset += 4;
    store_u32(bytes + offset, receipt->expected_gid);
    offset += 4;
#define APPEND_DIGEST(field) do { \
    memcpy(bytes + offset, receipt->field, 32); offset += 32; \
} while (0)
    APPEND_DIGEST(generation_id_sha256);
    APPEND_DIGEST(install_provenance_sha256);
    APPEND_DIGEST(installed_closure_sha256);
    APPEND_DIGEST(protocol_schema_sha256);
    APPEND_DIGEST(runtime_package_manifest_sha256);
    APPEND_DIGEST(native_deployment_receipt_sha256);
    APPEND_DIGEST(install_root_fd_identity);
    APPEND_DIGEST(receipt_producer_identity_sha256);
    APPEND_DIGEST(receipt_sha256);
#undef APPEND_DIGEST
    if (plamen_broker_v2_sha256(bytes, offset, output) != 0) {
        memset(bytes, 0, sizeof(bytes));
        return -1;
    }
    memset(bytes, 0, sizeof(bytes));
    return 0;
}
