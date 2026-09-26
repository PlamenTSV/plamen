#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include "plamen_native_installer_v2.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#define INSTALL_RECEIPT_HASHED_SIZE 16352U
#define INSTALL_RECEIPT_MEMBER_COUNT 10U
#define INSTALL_RECEIPT_MEMBERS_OFFSET 2496U
#define INSTALL_RECEIPT_MEMBER_SIZE 896U
#define INSTALL_RECEIPT_MEMBER_PATH_OFFSET 112U
#define INSTALL_RECEIPT_MEMBER_PATH_SIZE 256U
#define INSTALL_RECEIPT_GENERATION_PATH_OFFSET 320U
#define INSTALL_RECEIPT_GENERATION_PATH_SIZE 1024U
#define INSTALL_RECEIPT_BROKER_PLIST_PATH_OFFSET 1344U
#define INSTALL_RECEIPT_BROKER_PLIST_IDENTITY_OFFSET 2368U
#define INSTALL_RECEIPT_CUSTODY_PLIST_PATH_OFFSET 11456U
#define INSTALL_RECEIPT_CUSTODY_PLIST_IDENTITY_OFFSET 12480U
#define INSTALL_RECEIPT_RESERVED_OFFSET 12608U
#define INSTALL_RECEIPT_HEADER_FLAGS_OFFSET 192U
#define INSTALL_RECEIPT_FLAG_SPECIALIZED_AUTHORITY 1U
#define INSTALL_RECEIPT_FLAG_SOURCE_BOOTSTRAP_AUTHORITY 2U
#define INSTALL_RECEIPT_SPECIALIZED_OFFSET 12608U
#define INSTALL_RECEIPT_SPECIALIZED_SIZE 512U
#define INSTALL_RECEIPT_SPECIALIZED_PATH_OFFSET 128U
#define INSTALL_RECEIPT_SPECIALIZED_PATH_SIZE 256U
#define INSTALL_RECEIPT_SPECIALIZED_PATH \
    "share/plamen/image-member-receipt-v2.bin"
#define INSTALL_RECEIPT_SOURCE_BOOTSTRAP_OFFSET 13120U
#define INSTALL_RECEIPT_SOURCE_BOOTSTRAP_SIZE 512U
#define INSTALL_RECEIPT_SOURCE_BOOTSTRAP_PATH_OFFSET 192U
#define INSTALL_RECEIPT_SOURCE_BOOTSTRAP_PATH_SIZE 256U
#define INSTALL_RECEIPT_SOURCE_BOOTSTRAP_PATH \
    "share/plamen/native-source-bootstrap-coordinator-receipt-v1.bin"
#define INSTALL_MAX_TREE_ENTRIES 65536U
#define INSTALL_MAX_TREE_DEPTH 64U

#define INSTALL_LOCK ".plamen-native-install-v2.lock"
#define INSTALL_MARKER ".plamen-native-install-v2.transaction"
#define INSTALL_MARKER_NEXT ".plamen-native-install-v2.transaction.next"
#define LAUNCHER_NAME "plamen-native-launcher"
#define LAUNCHER_NEXT ".plamen-native-launcher.next-v2"
#define LAUNCHER_BACKUP ".plamen-native-launcher.rollback-v2"
#define RECEIPT_NAME "native-install-receipt-v2.bin"
#define RECEIPT_NEXT ".native-install-receipt-v2.next-v2"
#define RECEIPT_BACKUP ".native-install-receipt-v2.rollback-v2"

#define MARKER_SIZE 320U
#define MARKER_HASHED_SIZE 288U
#define MARKER_VERSION 3U
#define MARKER_FLAG_OLD_LAUNCHER 1U
#define MARKER_FLAG_OLD_RECEIPT 2U
#define MARKER_FLAG_DEPLOYMENT 4U
#define MARKER_FLAG_POSTCOMMIT_RETAIN 8U

enum transaction_phase {
    TRANSACTION_PREPARE = 1,
    TRANSACTION_PREPARED = 2,
    TRANSACTION_GENERATION = 3,
    TRANSACTION_RECEIPT = 4,
    TRANSACTION_DEPLOYMENT_PREPARED = 5,
    TRANSACTION_DEPLOYMENT_ACTIVATED = 6,
    TRANSACTION_LAUNCHER = 7,
    TRANSACTION_COMMITTED = 8,
    TRANSACTION_POSTCOMMIT_ROLLBACK = 9
};

struct sha256_context {
    uint32_t state[8];
    uint64_t total;
    uint8_t block[64];
    size_t used;
};

struct retained_identity {
    uint64_t device;
    uint64_t inode;
    uint64_t size;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t links;
    uint8_t sha256[32];
};

struct receipt_member {
    char path[INSTALL_RECEIPT_MEMBER_PATH_SIZE + 1U];
    uint32_t mode;
    struct retained_identity identity;
};

struct deployment_plist {
    char absolute_path[INSTALL_RECEIPT_GENERATION_PATH_SIZE + 1U];
    const char *relative_path;
    struct retained_identity identity;
};

struct receipt_observation {
    uint8_t bytes[PLAMEN_NATIVE_INSTALLER_V2_RECEIPT_SIZE];
    uint8_t generation_id[32];
    uint8_t receipt_sha256[32];
    uint8_t file_sha256[32];
    char generation_path[INSTALL_RECEIPT_GENERATION_PATH_SIZE + 1U];
    struct deployment_plist broker_plist;
    struct deployment_plist custody_plist;
    struct receipt_member members[INSTALL_RECEIPT_MEMBER_COUNT];
    int specialized_present;
    struct receipt_member specialized;
    uint8_t specialized_runtime_manifest_sha256[32];
    int source_bootstrap_present;
    struct receipt_member source_bootstrap;
    uint8_t source_bootstrap_acquisition_roster_sha256[32];
    uint8_t source_bootstrap_producer_verifier_key_sha256[32];
    uint8_t source_bootstrap_installed_authority_roster_sha256[32];
    uint8_t source_bootstrap_coordinator_member_identity_sha256[32];
    uint8_t source_bootstrap_coordinator_code_identity_sha256[32];
};

struct transaction_marker {
    uint16_t phase;
    uint32_t flags;
    uint8_t generation_id[32];
    uint64_t root_device;
    uint64_t root_inode;
    uint32_t owner_uid;
    struct retained_identity old_launcher;
    struct retained_identity old_receipt;
    uint32_t deployment_state;
};

struct install_handles {
    int root;
    int generations;
    int bin;
    int share;
    int lock;
    uid_t owner;
    char root_path[INSTALL_RECEIPT_GENERATION_PATH_SIZE + 1U];
    struct stat root_identity;
};

static uint32_t
rotate_right(uint32_t value, unsigned int count)
{
    return (value >> count) | (value << (32U - count));
}

static void
sha256_transform(struct sha256_context *context, const uint8_t block[64])
{
    static const uint32_t constants[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };
    uint32_t schedule[64];
    uint32_t a, b, c, d, e, f, g, h;
    size_t index;
    for (index = 0; index < 16U; ++index) {
        const uint8_t *p = block + index * 4U;
        schedule[index] = ((uint32_t)p[0] << 24)
            | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
    }
    for (index = 16U; index < 64U; ++index) {
        uint32_t s0 = rotate_right(schedule[index - 15U], 7U)
            ^ rotate_right(schedule[index - 15U], 18U)
            ^ (schedule[index - 15U] >> 3);
        uint32_t s1 = rotate_right(schedule[index - 2U], 17U)
            ^ rotate_right(schedule[index - 2U], 19U)
            ^ (schedule[index - 2U] >> 10);
        schedule[index] = schedule[index - 16U] + s0
            + schedule[index - 7U] + s1;
    }
    a = context->state[0]; b = context->state[1];
    c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5];
    g = context->state[6]; h = context->state[7];
    for (index = 0; index < 64U; ++index) {
        uint32_t s1 = rotate_right(e, 6U) ^ rotate_right(e, 11U)
            ^ rotate_right(e, 25U);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + s1 + choice + constants[index]
            + schedule[index];
        uint32_t s0 = rotate_right(a, 2U) ^ rotate_right(a, 13U)
            ^ rotate_right(a, 22U);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = s0 + majority;
        h = g; g = f; f = e; e = d + temporary1;
        d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f;
    context->state[6] += g; context->state[7] += h;
    memset(schedule, 0, sizeof(schedule));
}

static void
sha256_init(struct sha256_context *context)
{
    static const uint32_t initial[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    memcpy(context->state, initial, sizeof(initial));
    context->total = 0;
    context->used = 0;
    memset(context->block, 0, sizeof(context->block));
}

static void
sha256_update(struct sha256_context *context, const uint8_t *input,
    size_t size)
{
    while (size != 0U) {
        size_t room = sizeof(context->block) - context->used;
        size_t amount = size < room ? size : room;
        memcpy(context->block + context->used, input, amount);
        context->used += amount;
        context->total += amount;
        input += amount;
        size -= amount;
        if (context->used == sizeof(context->block)) {
            sha256_transform(context, context->block);
            context->used = 0;
        }
    }
}

static void
sha256_final(struct sha256_context *context, uint8_t output[32])
{
    uint64_t bits = context->total * 8U;
    size_t index;
    context->block[context->used++] = 0x80U;
    if (context->used > 56U) {
        memset(context->block + context->used, 0,
            sizeof(context->block) - context->used);
        sha256_transform(context, context->block);
        context->used = 0;
    }
    memset(context->block + context->used, 0, 56U - context->used);
    for (index = 0; index < 8U; ++index)
        context->block[63U - index] = (uint8_t)(bits >> (index * 8U));
    sha256_transform(context, context->block);
    for (index = 0; index < 8U; ++index) {
        output[index * 4U] = (uint8_t)(context->state[index] >> 24);
        output[index * 4U + 1U] = (uint8_t)(context->state[index] >> 16);
        output[index * 4U + 2U] = (uint8_t)(context->state[index] >> 8);
        output[index * 4U + 3U] = (uint8_t)context->state[index];
    }
    memset(context, 0, sizeof(*context));
}

static void
sha256_bytes(const uint8_t *input, size_t size, uint8_t output[32])
{
    struct sha256_context context;
    sha256_init(&context);
    sha256_update(&context, input, size);
    sha256_final(&context, output);
}

static int
install_member_code_identity_sha256(const uint8_t row[896],
    uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-INSTALL-CODE-IDENTITY-V1\0";
    uint8_t preimage[sizeof(domain) + 6U + 128U + 128U + 32U];
    uint16_t identifier_size, team_size, cdhash_size;
    size_t offset = 0U, index;
    uint8_t aggregate = 0U;
    if (row == NULL || output == NULL)
        return -1;
    identifier_size = (uint16_t)(((uint16_t)row[4] << 8) | row[5]);
    team_size = (uint16_t)(((uint16_t)row[6] << 8) | row[7]);
    cdhash_size = (uint16_t)(((uint16_t)row[8] << 8) | row[9]);
    if (identifier_size > 128U || team_size > 128U || cdhash_size > 32U)
        return -1;
    memset(preimage, 0, sizeof(preimage));
    memcpy(preimage + offset, domain, sizeof(domain)); offset += sizeof(domain);
    preimage[offset++] = (uint8_t)(identifier_size >> 8);
    preimage[offset++] = (uint8_t)identifier_size;
    preimage[offset++] = (uint8_t)(team_size >> 8);
    preimage[offset++] = (uint8_t)team_size;
    preimage[offset++] = (uint8_t)(cdhash_size >> 8);
    preimage[offset++] = (uint8_t)cdhash_size;
    memcpy(preimage + offset, row + 368U, identifier_size);
    offset += identifier_size;
    memcpy(preimage + offset, row + 496U, team_size);
    offset += team_size;
    memcpy(preimage + offset, row + 80U, cdhash_size);
    offset += cdhash_size;
    sha256_bytes(preimage, offset, output);
    memset(preimage, 0, sizeof(preimage));
    for (index = 0U; index < 32U; ++index)
        aggregate |= output[index];
    return aggregate == 0U ? -1 : 0;
}

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
    p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value;
}

static void
store_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static void
store_u64(uint8_t *p, uint64_t value)
{
    store_u32(p, (uint32_t)(value >> 32));
    store_u32(p + 4, (uint32_t)value);
}

static void
derive_intrinsic_digests(const struct receipt_observation *receipt,
    uint8_t generation_id[32], uint8_t roster_sha256[32])
{
    static const uint8_t generation_domain[] =
        "PLAMEN-INTRINSIC-GENERATION-V2\0";
    static const uint8_t roster_domain[] =
        "PLAMEN-INTRINSIC-ROSTER-V2\0";
    struct sha256_context generation, roster;
    uint8_t generation_header[8], count[2], row_header[16];
    uint16_t index;

    sha256_init(&generation);
    sha256_init(&roster);
    sha256_update(&generation, generation_domain,
        sizeof(generation_domain) - 1U);
    sha256_update(&roster, roster_domain, sizeof(roster_domain) - 1U);
    store_u16(generation_header, 2U); /* receipt/generation version */
    store_u16(generation_header + 2U, 1U); /* Darwin */
    store_u16(generation_header + 4U, 1U); /* arm64 */
    store_u16(generation_header + 6U, INSTALL_RECEIPT_MEMBER_COUNT);
    store_u16(count, INSTALL_RECEIPT_MEMBER_COUNT);
    sha256_update(&generation, generation_header, sizeof(generation_header));
    sha256_update(&roster, count, sizeof(count));
    for (index = 0; index < INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        const struct receipt_member *member = &receipt->members[index];
        size_t path_size = strlen(member->path);
        store_u16(row_header, (uint16_t)(index + 1U));
        store_u16(row_header + 2U, (uint16_t)path_size);
        store_u32(row_header + 4U, member->mode);
        store_u64(row_header + 8U, member->identity.size);
        sha256_update(&generation, row_header, sizeof(row_header));
        sha256_update(&generation, member->identity.sha256, 32U);
        sha256_update(&generation, (const uint8_t *)member->path, path_size);
        sha256_update(&roster, row_header, sizeof(row_header));
        sha256_update(&roster, member->identity.sha256, 32U);
        sha256_update(&roster, (const uint8_t *)member->path, path_size);
    }
    sha256_final(&generation, generation_id);
    sha256_final(&roster, roster_sha256);
    memset(generation_header, 0, sizeof(generation_header));
    memset(count, 0, sizeof(count));
    memset(row_header, 0, sizeof(row_header));
}

static int
all_zero(const uint8_t *value, size_t size)
{
    uint8_t aggregate = 0;
    size_t index;
    for (index = 0; index < size; ++index)
        aggregate |= value[index];
    return aggregate == 0;
}

static int
stat_same(const struct stat *left, const struct stat *right)
{
    if (left->st_dev != right->st_dev || left->st_ino != right->st_ino
        || left->st_mode != right->st_mode || left->st_uid != right->st_uid
        || left->st_gid != right->st_gid || left->st_nlink != right->st_nlink
        || left->st_size != right->st_size)
        return 0;
#ifdef __APPLE__
    return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec
        && left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec
        && left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec
        && left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_mtim.tv_sec == right->st_mtim.tv_sec
        && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec
        && left->st_ctim.tv_sec == right->st_ctim.tv_sec
        && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static void
identity_from_stat(struct retained_identity *identity,
    const struct stat *information, const uint8_t digest[32])
{
    memset(identity, 0, sizeof(*identity));
    identity->device = (uint64_t)information->st_dev;
    identity->inode = (uint64_t)information->st_ino;
    identity->size = (uint64_t)information->st_size;
    identity->mode = (uint32_t)(information->st_mode & 07777);
    identity->uid = (uint32_t)information->st_uid;
    identity->gid = (uint32_t)information->st_gid;
    identity->links = (uint64_t)information->st_nlink;
    memcpy(identity->sha256, digest, 32);
}

static int
identity_matches_stat(const struct retained_identity *identity,
    const struct stat *information, int compare_links)
{
    return identity->device == (uint64_t)information->st_dev
        && identity->inode == (uint64_t)information->st_ino
        && identity->size == (uint64_t)information->st_size
        && identity->mode == (uint32_t)(information->st_mode & 07777)
        && identity->uid == (uint32_t)information->st_uid
        && identity->gid == (uint32_t)information->st_gid
        && (!compare_links
            || identity->links == (uint64_t)information->st_nlink);
}

static int
read_exact_at(int fd, uint8_t *output, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount;
        do {
            amount = pread(fd, output + offset, size - offset, (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int
hash_fd_retained(int fd, uint8_t digest[32], struct stat *identity)
{
    struct sha256_context context;
    struct stat before, after;
    uint8_t buffer[65536];
    off_t offset = 0;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size <= 0)
        return -1;
    sha256_init(&context);
    while (offset < before.st_size) {
        size_t wanted = sizeof(buffer);
        ssize_t amount;
        if ((off_t)wanted > before.st_size - offset)
            wanted = (size_t)(before.st_size - offset);
        do {
            amount = pread(fd, buffer, wanted, offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            return -1;
        sha256_update(&context, buffer, (size_t)amount);
        offset += amount;
    }
    sha256_final(&context, digest);
    if (fstat(fd, &after) != 0 || !stat_same(&before, &after))
        return -1;
    if (identity != NULL)
        *identity = after;
    return 0;
}

static int
write_exact(int fd, const uint8_t *input, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount;
        do {
            amount = write(fd, input + offset, size - offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int
valid_absolute_path(const char *path)
{
    size_t length, index;
    if (path == NULL || path[0] != '/')
        return 0;
    length = strlen(path);
    if (length < 2U || length > INSTALL_RECEIPT_GENERATION_PATH_SIZE
        || path[length - 1U] == '/')
        return 0;
    for (index = 0; index < length; ++index) {
        unsigned char byte = (unsigned char)path[index];
        if (byte < 0x21U || byte > 0x7eU || byte == '\\')
            return 0;
    }
    return strstr(path, "//") == NULL && strstr(path, "/./") == NULL
        && strstr(path, "/../") == NULL
        && strcmp(path + (length > 2U ? length - 2U : 0U), "/.") != 0
        && strcmp(path + (length > 3U ? length - 3U : 0U), "/..") != 0;
}

static int
valid_component(const char *name)
{
    size_t length, index;
    if (name == NULL || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return 0;
    length = strlen(name);
    if (length == 0U || length > NAME_MAX)
        return 0;
    for (index = 0; index < length; ++index) {
        unsigned char byte = (unsigned char)name[index];
        if (byte < 0x21U || byte > 0x7eU || byte == '/' || byte == '\\')
            return 0;
    }
    return 1;
}

static int
decode_generation_id(const char *hex, uint8_t output[32])
{
    size_t index;
    if (hex == NULL || strlen(hex) != 64U)
        return -1;
    for (index = 0; index < 32U; ++index) {
        unsigned char high = (unsigned char)hex[index * 2U];
        unsigned char low = (unsigned char)hex[index * 2U + 1U];
        if (!((high >= '0' && high <= '9') || (high >= 'a' && high <= 'f'))
            || !((low >= '0' && low <= '9') || (low >= 'a' && low <= 'f')))
            return -1;
        output[index] = (uint8_t)(((high <= '9' ? high - '0'
            : high - 'a' + 10U) << 4)
            | (low <= '9' ? low - '0' : low - 'a' + 10U));
    }
    return 0;
}

static int
copy_fixed_path(const uint8_t *slot, size_t slot_size, uint16_t length,
    char *output, size_t output_size, int absolute)
{
    size_t index;
    if (length == 0U || length >= output_size || length > slot_size
        || !all_zero(slot + length, slot_size - length))
        return -1;
    for (index = 0; index < length; ++index) {
        uint8_t byte = slot[index];
        if (byte < 0x21U || byte > 0x7eU || byte == '\\')
            return -1;
    }
    if ((absolute && slot[0] != '/') || (!absolute && slot[0] == '/'))
        return -1;
    memcpy(output, slot, length);
    output[length] = '\0';
    if ((absolute && !valid_absolute_path(output))
        || (!absolute && (!valid_component(strrchr(output, '/') == NULL
                ? output : strrchr(output, '/') + 1)
            || strstr(output, "//") != NULL || strstr(output, "/./") != NULL
            || strstr(output, "/../") != NULL)))
        return -1;
    return 0;
}

static int
duplicate_cloexec(int fd)
{
#ifdef F_DUPFD_CLOEXEC
    return fcntl(fd, F_DUPFD_CLOEXEC, 3);
#else
    int copy = fcntl(fd, F_DUPFD, 3);
    if (copy >= 0 && fcntl(copy, F_SETFD, FD_CLOEXEC) != 0) {
        int saved = errno;
        close(copy);
        errno = saved;
        return -1;
    }
    return copy;
#endif
}

static int
open_absolute_nofollow(const char *path, int final_flags)
{
    char copy[PATH_MAX + 1U];
    char *component, *next;
    int current = -1, child = -1;
    if (!valid_absolute_path(path) || strlen(path) > PATH_MAX) {
        errno = EINVAL;
        return -1;
    }
    memcpy(copy, path + 1, strlen(path));
    current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0)
        return -1;
    component = copy;
    while (component != NULL && component[0] != '\0') {
        next = strchr(component, '/');
        if (next != NULL)
            *next = '\0';
        if (!valid_component(component)) {
            errno = EINVAL;
            goto invalid;
        }
        child = openat(current, component,
            (next == NULL ? final_flags : O_RDONLY | O_DIRECTORY)
                | O_CLOEXEC | O_NOFOLLOW);
        if (child < 0)
            goto invalid;
        close(current);
        current = child;
        child = -1;
        component = next == NULL ? NULL : next + 1;
    }
    memset(copy, 0, sizeof(copy));
    return current;
invalid:
    {
        int saved = errno;
        if (child >= 0)
            close(child);
        if (current >= 0)
            close(current);
        memset(copy, 0, sizeof(copy));
        errno = saved;
        return -1;
    }
}

static int
directory_safe(const struct stat *information, uid_t owner, int writable)
{
    mode_t mode = information->st_mode;
    if (!S_ISDIR(mode) || information->st_uid != owner
        || information->st_nlink == 0 || (mode & 0022) != 0
        || (mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0
        || (mode & 0500) != 0500)
        return 0;
    if (!writable && (mode & 0222) != 0)
        return 0;
    return 1;
}

static int
regular_safe(const struct stat *information, uid_t owner, uint32_t mode,
    int exact_one_link)
{
    return S_ISREG(information->st_mode) && information->st_uid == owner
        && information->st_nlink != 0
        && (!exact_one_link || information->st_nlink == 1)
        && (uint32_t)(information->st_mode & 07777) == mode
        && (mode == 0400U || mode == 0500U);
}

static int
open_control_directory(int parent, const char *name, uid_t owner)
{
    struct stat information;
    int fd = openat(parent, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &information) != 0
        || !directory_safe(&information, owner, 1)) {
        int saved = errno == 0 ? EPERM : errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int
install_handles_open(int input_root, const char *root_path, uid_t owner,
    struct install_handles *handles)
{
    struct stat supplied, reopened, share_info;
    int check = -1, share_parent = -1;
    memset(handles, 0, sizeof(*handles));
    handles->root = -1; handles->generations = -1;
    handles->bin = -1; handles->share = -1; handles->lock = -1;
    if (owner != getuid() || owner != geteuid()
        || !valid_absolute_path(root_path)) {
        errno = EPERM;
        return -1;
    }
    handles->root = duplicate_cloexec(input_root);
    if (handles->root < 0 || fstat(handles->root, &supplied) != 0
        || !directory_safe(&supplied, owner, 1))
        goto invalid;
    check = open_absolute_nofollow(root_path, O_RDONLY | O_DIRECTORY);
    if (check < 0 || fstat(check, &reopened) != 0
        || supplied.st_dev != reopened.st_dev
        || supplied.st_ino != reopened.st_ino) {
        errno = EPERM;
        goto invalid;
    }
    close(check); check = -1;
    handles->generations = open_control_directory(handles->root,
        "generations", owner);
    handles->bin = open_control_directory(handles->root, "bin", owner);
    share_parent = open_control_directory(handles->root, "share", owner);
    if (handles->generations < 0 || handles->bin < 0 || share_parent < 0)
        goto invalid;
    handles->share = openat(share_parent, "plamen",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (handles->share < 0 || fstat(handles->share, &share_info) != 0
        || !directory_safe(&share_info, owner, 1))
        goto invalid;
    close(share_parent); share_parent = -1;
    handles->owner = owner;
    handles->root_identity = supplied;
    memcpy(handles->root_path, root_path, strlen(root_path) + 1U);
    return 0;
invalid:
    {
        int saved = errno == 0 ? EPERM : errno;
        if (check >= 0) close(check);
        if (share_parent >= 0) close(share_parent);
        if (handles->share >= 0) close(handles->share);
        if (handles->bin >= 0) close(handles->bin);
        if (handles->generations >= 0) close(handles->generations);
        if (handles->root >= 0) close(handles->root);
        memset(handles, 0, sizeof(*handles));
        handles->root = handles->generations = handles->bin = -1;
        handles->share = handles->lock = -1;
        errno = saved;
        return -1;
    }
}

static void
install_handles_close(struct install_handles *handles)
{
    if (handles->lock >= 0) close(handles->lock);
    if (handles->share >= 0) close(handles->share);
    if (handles->bin >= 0) close(handles->bin);
    if (handles->generations >= 0) close(handles->generations);
    if (handles->root >= 0) close(handles->root);
    memset(handles, 0, sizeof(*handles));
}

static int
acquire_install_lock(struct install_handles *handles)
{
    struct flock lock;
    struct stat information;
    handles->lock = openat(handles->root, INSTALL_LOCK,
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (handles->lock < 0 || fstat(handles->lock, &information) != 0
        || !S_ISREG(information.st_mode)
        || information.st_uid != handles->owner
        || information.st_nlink != 1
        || (information.st_mode & 07777) != 0600) {
        errno = EPERM;
        return -1;
    }
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(handles->lock, F_SETLK, &lock) != 0)
        return -1;
    return 0;
}

static int
acquire_existing_validation_lock(struct install_handles *handles)
{
    struct flock lock;
    struct stat information;
    handles->lock = openat(handles->root, INSTALL_LOCK,
        O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (handles->lock < 0 || fstat(handles->lock, &information) != 0
        || !S_ISREG(information.st_mode)
        || information.st_uid != handles->owner
        || information.st_nlink != 1
        || (information.st_mode & 07777) != 0600) {
        errno = EPERM;
        return -1;
    }
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_RDLCK;
    lock.l_whence = SEEK_SET;
    return fcntl(handles->lock, F_SETLK, &lock);
}

static int
receipt_decode(int receipt_fd, const char *expected_generation_path,
    const uint8_t expected_generation_id[32], uid_t owner,
    struct receipt_observation *receipt)
{
    static const uint8_t magic[8] = {
        'P', 'L', 'M', 'I', 'N', 'S', '2', '\0'
    };
    struct stat before, after;
    static const uint8_t checkpoint_domain[] =
        "PLAMEN-INSTALL-PRECOMMIT-V2\0";
    static const uint8_t zeros[32] = {0};
    struct sha256_context checkpoint_context;
    uint8_t digest[32], checkpoint[32], derived_generation[32], roster[32];
    uint16_t index, path_size, broker_path_size, custody_path_size;
    uint32_t receipt_flags;
    char bound_path[INSTALL_RECEIPT_GENERATION_PATH_SIZE + 1U];
    int flags;
    memset(receipt, 0, sizeof(*receipt));
    errno = 0;
    flags = fcntl(receipt_fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY
        || fstat(receipt_fd, &before) != 0
        || !regular_safe(&before, owner, 0400U, 1)
        || before.st_size != (off_t)sizeof(receipt->bytes)
        || read_exact_at(receipt_fd, receipt->bytes,
            sizeof(receipt->bytes)) != 0
        || fstat(receipt_fd, &after) != 0 || !stat_same(&before, &after))
        goto invalid;
    sha256_bytes(receipt->bytes, INSTALL_RECEIPT_HASHED_SIZE, digest);
    sha256_init(&checkpoint_context);
    sha256_update(&checkpoint_context, checkpoint_domain,
        sizeof(checkpoint_domain) - 1U);
    sha256_update(&checkpoint_context, receipt->bytes, 80U);
    sha256_update(&checkpoint_context, zeros, sizeof(zeros));
    sha256_update(&checkpoint_context, receipt->bytes + 112U,
        INSTALL_RECEIPT_HASHED_SIZE - 112U);
    sha256_final(&checkpoint_context, checkpoint);
    path_size = load_u16(receipt->bytes + 122U);
    broker_path_size = load_u16(receipt->bytes + 124U);
    custody_path_size = load_u16(receipt->bytes + 126U);
    receipt_flags = load_u32(
        receipt->bytes + INSTALL_RECEIPT_HEADER_FLAGS_OFFSET);
    if (memcmp(receipt->bytes, magic, sizeof(magic)) != 0
        || load_u16(receipt->bytes + 8U) != 2U
        || load_u16(receipt->bytes + 10U) != 256U
        || load_u32(receipt->bytes + 12U) != sizeof(receipt->bytes)
        || load_u16(receipt->bytes + 112U) != INSTALL_RECEIPT_MEMBER_COUNT
        || memcmp(digest, receipt->bytes + INSTALL_RECEIPT_HASHED_SIZE,
            sizeof(digest)) != 0
        || memcmp(checkpoint, receipt->bytes + 80U,
            sizeof(checkpoint)) != 0
        || memcmp(receipt->bytes + 16U, expected_generation_id, 32U) != 0
        || all_zero(receipt->bytes + 48U, 32U)
        || all_zero(receipt->bytes + 80U, 32U)
        || all_zero(receipt->bytes + 128U, 32U)
        || all_zero(receipt->bytes + 160U, 32U)
        || (receipt_flags & ~(INSTALL_RECEIPT_FLAG_SPECIALIZED_AUTHORITY
                | INSTALL_RECEIPT_FLAG_SOURCE_BOOTSTRAP_AUTHORITY)) != 0U
        || !all_zero(receipt->bytes + 196U, 60U)
        || copy_fixed_path(receipt->bytes
                + INSTALL_RECEIPT_GENERATION_PATH_OFFSET,
            INSTALL_RECEIPT_GENERATION_PATH_SIZE, path_size,
            receipt->generation_path, sizeof(receipt->generation_path), 1)
                != 0
        || strcmp(receipt->generation_path, expected_generation_path) != 0) {
        errno = EBADMSG;
        goto invalid;
    }
    receipt->broker_plist.relative_path =
        "Library/LaunchAgents/com.plamen.audit.broker.v2.plist";
    receipt->custody_plist.relative_path =
        "Library/LaunchAgents/com.plamen.audit.process-custody.v2.plist";
    if (copy_fixed_path(receipt->bytes
            + INSTALL_RECEIPT_BROKER_PLIST_PATH_OFFSET,
            INSTALL_RECEIPT_GENERATION_PATH_SIZE, broker_path_size,
            receipt->broker_plist.absolute_path,
            sizeof(receipt->broker_plist.absolute_path), 1) != 0
        || copy_fixed_path(receipt->bytes
            + INSTALL_RECEIPT_CUSTODY_PLIST_PATH_OFFSET,
            INSTALL_RECEIPT_GENERATION_PATH_SIZE, custody_path_size,
            receipt->custody_plist.absolute_path,
            sizeof(receipt->custody_plist.absolute_path), 1) != 0
        || snprintf(bound_path, sizeof(bound_path), "%s/%s",
            receipt->generation_path, receipt->broker_plist.relative_path)
            >= (int)sizeof(bound_path)
        || strcmp(bound_path, receipt->broker_plist.absolute_path) != 0
        || snprintf(bound_path, sizeof(bound_path), "%s/%s",
            receipt->generation_path, receipt->custody_plist.relative_path)
            >= (int)sizeof(bound_path)
        || strcmp(bound_path, receipt->custody_plist.absolute_path) != 0) {
        errno = EBADMSG;
        goto invalid;
    }
    {
        struct deployment_plist *plists[2] = {
            &receipt->broker_plist, &receipt->custody_plist
        };
        const size_t offsets[2] = {
            INSTALL_RECEIPT_BROKER_PLIST_IDENTITY_OFFSET,
            INSTALL_RECEIPT_CUSTODY_PLIST_IDENTITY_OFFSET
        };
        size_t plist_index;
        for (plist_index = 0; plist_index < 2U; ++plist_index) {
            const uint8_t *identity = receipt->bytes + offsets[plist_index];
            struct retained_identity *out = &plists[plist_index]->identity;
            memcpy(out->sha256, identity, 32U);
            out->size = load_u64(identity + 32U);
            out->device = load_u64(identity + 40U);
            out->inode = load_u64(identity + 48U);
            out->mode = load_u32(identity + 56U);
            out->uid = load_u32(identity + 60U);
            out->gid = load_u32(identity + 64U);
            out->links = 1U;
            if (out->size == 0U || out->device == 0U || out->inode == 0U
                || out->mode != 0400U || out->uid != (uint32_t)owner
                || all_zero(out->sha256, 32U)
                || !all_zero(identity + 68U, 60U)) {
                errno = EBADMSG;
                goto invalid;
            }
        }
    }
    memcpy(receipt->generation_id, receipt->bytes + 16U, 32U);
    memcpy(receipt->receipt_sha256,
        receipt->bytes + INSTALL_RECEIPT_HASHED_SIZE, 32U);
    sha256_bytes(receipt->bytes, sizeof(receipt->bytes),
        receipt->file_sha256);
    for (index = 0; index < INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        const uint8_t *row = receipt->bytes
            + INSTALL_RECEIPT_MEMBERS_OFFSET
            + (size_t)index * INSTALL_RECEIPT_MEMBER_SIZE;
        struct receipt_member *member = &receipt->members[index];
        uint16_t other;
        path_size = load_u16(row + 2U);
        if (load_u16(row) != (uint16_t)(index + 1U)
            || load_u16(row + 10U) != 0U
            || !all_zero(row + 624U, 272U)
            || copy_fixed_path(row + INSTALL_RECEIPT_MEMBER_PATH_OFFSET,
                INSTALL_RECEIPT_MEMBER_PATH_SIZE, path_size,
                member->path, sizeof(member->path), 0) != 0)
        {
            errno = EBADMSG;
            goto invalid;
        }
        member->mode = load_u32(row + 12U);
        member->identity.mode = member->mode;
        member->identity.size = load_u64(row + 16U);
        member->identity.device = load_u64(row + 24U);
        member->identity.inode = load_u64(row + 32U);
        member->identity.uid = load_u32(row + 40U);
        member->identity.gid = load_u32(row + 44U);
        memcpy(member->identity.sha256, row + 48U, 32U);
        if ((member->mode != 0400U && member->mode != 0500U)
            || member->identity.size == 0U
            || member->identity.device == 0U || member->identity.inode == 0U
            || member->identity.uid != (uint32_t)owner
            || all_zero(member->identity.sha256, 32U))
        {
            errno = EBADMSG;
            goto invalid;
        }
        for (other = 0; other < index; ++other) {
            if (strcmp(member->path, receipt->members[other].path) == 0
                || (member->identity.device
                        == receipt->members[other].identity.device
                    && member->identity.inode
                        == receipt->members[other].identity.inode))
            {
                errno = EBADMSG;
                goto invalid;
            }
        }
    }
    if ((receipt_flags & INSTALL_RECEIPT_FLAG_SPECIALIZED_AUTHORITY) != 0U) {
        const uint8_t *specialized = receipt->bytes
            + INSTALL_RECEIPT_SPECIALIZED_OFFSET;
        uint16_t specialized_path_size = load_u16(specialized + 16U);
        struct receipt_member *member = &receipt->specialized;
        static const uint8_t magic[8] = {
            'P', 'L', 'M', 'I', 'R', 'A', '1', 0
        };
        if (memcmp(specialized, magic, sizeof(magic)) != 0
            || load_u16(specialized + 8U) != 1U
            || load_u16(specialized + 10U)
                != INSTALL_RECEIPT_SPECIALIZED_SIZE
            || load_u32(specialized + 12U) != 1U
            || !all_zero(specialized + 18U, 6U)
            || copy_fixed_path(
                specialized + INSTALL_RECEIPT_SPECIALIZED_PATH_OFFSET,
                INSTALL_RECEIPT_SPECIALIZED_PATH_SIZE,
                specialized_path_size, member->path,
                sizeof(member->path), 0) != 0
            || strcmp(member->path, INSTALL_RECEIPT_SPECIALIZED_PATH) != 0
            || all_zero(specialized + 24U, 32U)
            || all_zero(specialized + 56U, 32U)
            || load_u64(specialized + 88U) == 0U
            || load_u64(specialized + 96U) == 0U
            || load_u64(specialized + 104U) == 0U
            || load_u32(specialized + 112U) != 0400U
            || !all_zero(specialized + 124U, 4U)
            || !all_zero(specialized + 384U,
                INSTALL_RECEIPT_SPECIALIZED_SIZE - 384U)
            || memcmp(specialized + 24U,
                receipt->members[7].identity.sha256, 32U) != 0) {
            errno = EBADMSG;
            goto invalid;
        }
        receipt->specialized_present = 1;
        member->mode = 0400U;
        member->identity.mode = 0400U;
        memcpy(receipt->specialized_runtime_manifest_sha256,
            specialized + 24U, 32U);
        memcpy(member->identity.sha256, specialized + 56U, 32U);
        member->identity.size = load_u64(specialized + 88U);
        member->identity.device = load_u64(specialized + 96U);
        member->identity.inode = load_u64(specialized + 104U);
        member->identity.uid = load_u32(specialized + 116U);
        member->identity.gid = load_u32(specialized + 120U);
        member->identity.links = 1U;
        if (member->identity.uid != (uint32_t)owner)
            goto invalid;
    } else if (!all_zero(receipt->bytes + INSTALL_RECEIPT_SPECIALIZED_OFFSET,
            INSTALL_RECEIPT_SPECIALIZED_SIZE)) {
        goto invalid;
    }
    if ((receipt_flags
            & INSTALL_RECEIPT_FLAG_SOURCE_BOOTSTRAP_AUTHORITY) != 0U) {
        const uint8_t *source = receipt->bytes
            + INSTALL_RECEIPT_SOURCE_BOOTSTRAP_OFFSET;
        struct receipt_member *member = &receipt->source_bootstrap;
        uint8_t member_identity_sha256[32];
        uint8_t code_identity_sha256[32];
        uint16_t source_path_size = load_u16(source + 16U);
        static const uint8_t magic[8] = {
            'P', 'L', 'M', 'S', 'B', 'A', '1', 0
        };
        sha256_bytes(receipt->bytes + INSTALL_RECEIPT_MEMBERS_OFFSET
                + 9U * INSTALL_RECEIPT_MEMBER_SIZE,
            INSTALL_RECEIPT_MEMBER_SIZE, member_identity_sha256);
        if (install_member_code_identity_sha256(receipt->bytes
                + INSTALL_RECEIPT_MEMBERS_OFFSET
                + 9U * INSTALL_RECEIPT_MEMBER_SIZE,
                code_identity_sha256) != 0) {
            errno = EBADMSG;
            goto invalid;
        }
        if (memcmp(source, magic, sizeof(magic)) != 0
            || load_u16(source + 8U) != 1U
            || load_u16(source + 10U)
                != INSTALL_RECEIPT_SOURCE_BOOTSTRAP_SIZE
            || load_u32(source + 12U) != 1U
            || !all_zero(source + 18U, 6U)
            || copy_fixed_path(
                source + INSTALL_RECEIPT_SOURCE_BOOTSTRAP_PATH_OFFSET,
                INSTALL_RECEIPT_SOURCE_BOOTSTRAP_PATH_SIZE,
                source_path_size, member->path, sizeof(member->path), 0) != 0
            || strcmp(member->path,
                INSTALL_RECEIPT_SOURCE_BOOTSTRAP_PATH) != 0
            || all_zero(source + 24U, 32U)
            || memcmp(source + 56U, member_identity_sha256, 32U) != 0
            || memcmp(source + 88U, code_identity_sha256, 32U) != 0
            || all_zero(source + 120U, 32U)
            || all_zero(source + 448U, 32U)
            || all_zero(source + 480U, 32U)
            || load_u64(source + 152U) != 8192U
            || load_u64(source + 160U) == 0U
            || load_u64(source + 168U) == 0U
            || load_u32(source + 176U) != 0400U
            || !all_zero(source + 188U, 4U)
            ) {
            memset(member_identity_sha256, 0,
                sizeof(member_identity_sha256));
            errno = EBADMSG;
            goto invalid;
        }
        receipt->source_bootstrap_present = 1;
        member->mode = 0400U;
        member->identity.mode = 0400U;
        memcpy(receipt->source_bootstrap_acquisition_roster_sha256,
            source + 24U, 32U);
        memcpy(receipt->source_bootstrap_producer_verifier_key_sha256,
            source + 448U, 32U);
        memcpy(receipt->source_bootstrap_installed_authority_roster_sha256,
            source + 480U, 32U);
        memcpy(receipt->source_bootstrap_coordinator_member_identity_sha256,
            source + 56U, 32U);
        memcpy(receipt->source_bootstrap_coordinator_code_identity_sha256,
            source + 88U, 32U);
        memcpy(member->identity.sha256, source + 120U, 32U);
        member->identity.size = load_u64(source + 152U);
        member->identity.device = load_u64(source + 160U);
        member->identity.inode = load_u64(source + 168U);
        member->identity.uid = load_u32(source + 180U);
        member->identity.gid = load_u32(source + 184U);
        member->identity.links = 1U;
        memset(member_identity_sha256, 0, sizeof(member_identity_sha256));
        if (member->identity.uid != (uint32_t)owner)
            goto invalid;
    } else if (!all_zero(receipt->bytes
            + INSTALL_RECEIPT_SOURCE_BOOTSTRAP_OFFSET,
        INSTALL_RECEIPT_SOURCE_BOOTSTRAP_SIZE)) {
        goto invalid;
    }
    if (!all_zero(receipt->bytes + INSTALL_RECEIPT_SOURCE_BOOTSTRAP_OFFSET
            + INSTALL_RECEIPT_SOURCE_BOOTSTRAP_SIZE,
        INSTALL_RECEIPT_HASHED_SIZE - INSTALL_RECEIPT_SOURCE_BOOTSTRAP_OFFSET
            - INSTALL_RECEIPT_SOURCE_BOOTSTRAP_SIZE))
        goto invalid;
    if (strcmp(receipt->members[0].path,
            "bin/plamen-native-launcher") != 0
        || receipt->members[0].mode != 0500U)
    {
        errno = EBADMSG;
        goto invalid;
    }
    derive_intrinsic_digests(receipt, derived_generation, roster);
    if (memcmp(derived_generation, receipt->bytes + 16U, 32U) != 0
        || memcmp(derived_generation, expected_generation_id, 32U) != 0
        || memcmp(roster, receipt->bytes + 48U, 32U) != 0)
    {
        errno = EBADMSG;
        goto invalid;
    }
    memset(digest, 0, sizeof(digest));
    memset(checkpoint, 0, sizeof(checkpoint));
    memset(derived_generation, 0, sizeof(derived_generation));
    memset(roster, 0, sizeof(roster));
    return 0;
invalid:
    memset(digest, 0, sizeof(digest));
    memset(checkpoint, 0, sizeof(checkpoint));
    memset(derived_generation, 0, sizeof(derived_generation));
    memset(roster, 0, sizeof(roster));
    memset(receipt, 0, sizeof(*receipt));
    if (errno == 0)
        errno = EPERM;
    return -1;
}

static int
open_relative_member(int generation_fd, const char *path, uid_t owner,
    int *member_fd)
{
    char copy[INSTALL_RECEIPT_MEMBER_PATH_SIZE + 1U];
    char *component, *next;
    struct stat information;
    int current = -1, child = -1;
    if (path == NULL || strlen(path) > INSTALL_RECEIPT_MEMBER_PATH_SIZE) {
        errno = EINVAL;
        return -1;
    }
    memcpy(copy, path, strlen(path) + 1U);
    current = duplicate_cloexec(generation_fd);
    if (current < 0)
        return -1;
    component = copy;
    while ((next = strchr(component, '/')) != NULL) {
        *next = '\0';
        if (!valid_component(component)) {
            errno = EINVAL;
            goto invalid;
        }
        child = openat(current, component,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child < 0 || fstat(child, &information) != 0
            || !directory_safe(&information, owner, 0))
            goto invalid;
        close(current); current = child; child = -1;
        component = next + 1;
    }
    if (!valid_component(component)) {
        errno = EINVAL;
        goto invalid;
    }
    child = openat(current, component, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (child < 0)
        goto invalid;
    close(current);
    memset(copy, 0, sizeof(copy));
    *member_fd = child;
    return 0;
invalid:
    {
        int saved = errno == 0 ? EPERM : errno;
        if (child >= 0) close(child);
        if (current >= 0) close(current);
        memset(copy, 0, sizeof(copy));
        errno = saved;
        return -1;
    }
}

static int
validate_receipt_members(int generation_fd,
    const struct receipt_observation *receipt, uid_t owner,
    int initial_stage, const int *retained_member_fds,
    int *launcher_parent_fd, int *launcher_fd)
{
    uint16_t index;
    if (launcher_parent_fd != NULL) *launcher_parent_fd = -1;
    if (launcher_fd != NULL) *launcher_fd = -1;
    for (index = 0; index < INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        const struct receipt_member *member = &receipt->members[index];
        struct stat information;
        uint8_t digest[32];
        int fd = -1;
        if (open_relative_member(generation_fd, member->path, owner, &fd) != 0
            || hash_fd_retained(fd, digest, &information) != 0
            || !regular_safe(&information, owner, member->mode,
                initial_stage || index != 0U)
            || !identity_matches_stat(&member->identity, &information, 0)
            || memcmp(digest, member->identity.sha256, 32U) != 0) {
            if (fd >= 0) close(fd);
            errno = EPERM;
            return -1;
        }
        if (retained_member_fds != NULL) {
            struct stat retained_information;
            uint8_t retained_digest[32];
            int retained_flags = fcntl(retained_member_fds[index], F_GETFL);
            if (retained_flags < 0
                || (retained_flags & O_ACCMODE) != O_RDONLY
                || hash_fd_retained(retained_member_fds[index],
                    retained_digest, &retained_information) != 0
                || retained_information.st_dev != information.st_dev
                || retained_information.st_ino != information.st_ino
                || !identity_matches_stat(&member->identity,
                    &retained_information, 0)
                || memcmp(retained_digest, member->identity.sha256, 32U)
                    != 0) {
                close(fd);
                memset(retained_digest, 0, sizeof(retained_digest));
                errno = EPERM;
                return -1;
            }
            memset(retained_digest, 0, sizeof(retained_digest));
        }
        if (index == 0U && launcher_fd != NULL) {
            int parent = openat(generation_fd, "bin",
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (parent < 0) {
                close(fd);
                return -1;
            }
            *launcher_parent_fd = parent;
            *launcher_fd = fd;
        } else {
            close(fd);
        }
    }
    return 0;
}

static int
validate_specialized_authority(int generation_fd,
    const struct receipt_observation *receipt, uid_t owner,
    int retained_authority_fd)
{
    struct stat information;
    uint8_t digest[32];
    int fd = -1;
    if (!receipt->specialized_present)
        return retained_authority_fd < 0 ? 0 : -1;
    if (open_relative_member(generation_fd, receipt->specialized.path,
            owner, &fd) != 0
        || hash_fd_retained(fd, digest, &information) != 0
        || !regular_safe(&information, owner, 0400U, 1)
        || !identity_matches_stat(&receipt->specialized.identity,
            &information, 0)
        || memcmp(digest, receipt->specialized.identity.sha256, 32U) != 0) {
        if (fd >= 0)
            close(fd);
        errno = EPERM;
        return -1;
    }
    if (retained_authority_fd >= 0) {
        struct stat retained_information;
        uint8_t retained_digest[32];
        int flags = fcntl(retained_authority_fd, F_GETFL);
        if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY
            || hash_fd_retained(retained_authority_fd, retained_digest,
                &retained_information) != 0
            || retained_information.st_dev != information.st_dev
            || retained_information.st_ino != information.st_ino
            || !identity_matches_stat(&receipt->specialized.identity,
                &retained_information, 0)
            || memcmp(retained_digest,
                receipt->specialized.identity.sha256, 32U) != 0) {
            close(fd);
            memset(retained_digest, 0, sizeof(retained_digest));
            errno = EPERM;
            return -1;
        }
        memset(retained_digest, 0, sizeof(retained_digest));
    }
    close(fd);
    memset(digest, 0, sizeof(digest));
    return 0;
}

static int
validate_source_bootstrap_authority(int generation_fd,
    const struct receipt_observation *receipt, uid_t owner,
    int retained_authority_fd)
{
    struct stat information;
    uint8_t digest[32];
    int fd = -1;
    if (!receipt->source_bootstrap_present)
        return retained_authority_fd < 0 ? 0 : -1;
    if (open_relative_member(generation_fd, receipt->source_bootstrap.path,
            owner, &fd) != 0
        || hash_fd_retained(fd, digest, &information) != 0
        || !regular_safe(&information, owner, 0400U, 1)
        || !identity_matches_stat(&receipt->source_bootstrap.identity,
            &information, 0)
        || memcmp(digest, receipt->source_bootstrap.identity.sha256, 32U)
            != 0) {
        if (fd >= 0)
            close(fd);
        errno = EPERM;
        return -1;
    }
    if (retained_authority_fd >= 0) {
        struct stat retained_information;
        uint8_t retained_digest[32];
        int flags = fcntl(retained_authority_fd, F_GETFL);
        if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY
            || hash_fd_retained(retained_authority_fd, retained_digest,
                &retained_information) != 0
            || retained_information.st_dev != information.st_dev
            || retained_information.st_ino != information.st_ino
            || !identity_matches_stat(&receipt->source_bootstrap.identity,
                &retained_information, 0)
            || memcmp(retained_digest,
                receipt->source_bootstrap.identity.sha256, 32U) != 0) {
            close(fd);
            memset(retained_digest, 0, sizeof(retained_digest));
            errno = EPERM;
            return -1;
        }
        memset(retained_digest, 0, sizeof(retained_digest));
    }
    close(fd);
    memset(digest, 0, sizeof(digest));
    return 0;
}

static int
validate_deployment_plists(int generation_fd,
    const struct receipt_observation *receipt, uid_t owner)
{
    const struct deployment_plist *plists[2] = {
        &receipt->broker_plist, &receipt->custody_plist
    };
    size_t index;
    for (index = 0; index < 2U; ++index) {
        struct stat information;
        uint8_t digest[32];
        int fd = -1;
        if (open_relative_member(generation_fd, plists[index]->relative_path,
                owner, &fd) != 0
            || hash_fd_retained(fd, digest, &information) != 0
            || !regular_safe(&information, owner, 0400U, 1)
            || !identity_matches_stat(&plists[index]->identity,
                &information, 0)
            || memcmp(digest, plists[index]->identity.sha256, 32U) != 0) {
            if (fd >= 0) close(fd);
            memset(digest, 0, sizeof(digest));
            errno = EPERM;
            return -1;
        }
        close(fd);
        memset(digest, 0, sizeof(digest));
    }
    return 0;
}

static int
validate_tree_recursive(int directory_fd, uid_t owner, unsigned int depth,
    uint64_t *entries)
{
    DIR *directory = NULL;
    struct dirent *entry;
    int iteration_fd = duplicate_cloexec(directory_fd);
    if (iteration_fd < 0 || depth > INSTALL_MAX_TREE_DEPTH)
        goto invalid;
    directory = fdopendir(iteration_fd);
    if (directory == NULL)
        goto invalid;
    iteration_fd = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        struct stat before, after;
        int child = -1;
        if (strcmp(entry->d_name, ".") == 0
            || strcmp(entry->d_name, "..") == 0)
            continue;
        if (!valid_component(entry->d_name)
            || ++*entries > INSTALL_MAX_TREE_ENTRIES
            || fstatat(directory_fd, entry->d_name, &before,
                AT_SYMLINK_NOFOLLOW) != 0)
            goto invalid;
        if (S_ISDIR(before.st_mode)) {
            child = openat(directory_fd, entry->d_name,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || fstat(child, &after) != 0
                || before.st_dev != after.st_dev
                || before.st_ino != after.st_ino
                || !directory_safe(&after, owner, 0)
                || validate_tree_recursive(child, owner, depth + 1U,
                    entries) != 0) {
                if (child >= 0) close(child);
                goto invalid;
            }
            close(child);
        } else if (S_ISREG(before.st_mode)) {
            child = openat(directory_fd, entry->d_name,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || fstat(child, &after) != 0
                || before.st_dev != after.st_dev
                || before.st_ino != after.st_ino
                || !regular_safe(&after, owner,
                    (uint32_t)(after.st_mode & 07777), 1)
                || ((after.st_mode & 07777) != 0400
                    && (after.st_mode & 07777) != 0500)) {
                if (child >= 0) close(child);
                goto invalid;
            }
            close(child);
        } else {
            goto invalid;
        }
        errno = 0;
    }
    if (errno != 0)
        goto invalid;
    closedir(directory);
    return 0;
invalid:
    {
        int saved = errno == 0 ? EPERM : errno;
        if (directory != NULL) closedir(directory);
        else if (iteration_fd >= 0) close(iteration_fd);
        errno = saved;
        return -1;
    }
}

static int
validate_staged_tree(int generation_fd, uid_t owner)
{
    struct stat information;
    uint64_t entries = 0;
    if (fstat(generation_fd, &information) != 0
        || !directory_safe(&information, owner, 1)
        || (information.st_mode & 07777) != 0700) {
        errno = EPERM;
        return -1;
    }
    return validate_tree_recursive(generation_fd, owner, 0U, &entries);
}

static void
marker_store_identity(uint8_t *output,
    const struct retained_identity *identity)
{
    store_u64(output, identity->device);
    store_u64(output + 8U, identity->inode);
    store_u64(output + 16U, identity->size);
    store_u32(output + 24U, identity->mode);
    store_u32(output + 28U, identity->uid);
    store_u32(output + 32U, identity->gid);
    store_u64(output + 40U, identity->links);
    memcpy(output + 48U, identity->sha256, 32U);
}

static void
marker_load_identity(const uint8_t *input,
    struct retained_identity *identity)
{
    memset(identity, 0, sizeof(*identity));
    identity->device = load_u64(input);
    identity->inode = load_u64(input + 8U);
    identity->size = load_u64(input + 16U);
    identity->mode = load_u32(input + 24U);
    identity->uid = load_u32(input + 28U);
    identity->gid = load_u32(input + 32U);
    identity->links = load_u64(input + 40U);
    memcpy(identity->sha256, input + 48U, 32U);
}

static int
marker_encode(const struct transaction_marker *marker,
    const struct install_handles *handles, uint8_t output[MARKER_SIZE])
{
    static const uint8_t magic[8] = {
        'P', 'L', 'M', 'N', 'I', 'T', '3', '\0'
    };
    uint8_t digest[32];
    if (marker->phase < TRANSACTION_PREPARE
        || marker->phase > TRANSACTION_POSTCOMMIT_ROLLBACK
        || (marker->flags
            & ~(MARKER_FLAG_OLD_LAUNCHER | MARKER_FLAG_OLD_RECEIPT
                | MARKER_FLAG_DEPLOYMENT
                | MARKER_FLAG_POSTCOMMIT_RETAIN)) != 0
        || ((marker->flags
                & (MARKER_FLAG_OLD_LAUNCHER | MARKER_FLAG_OLD_RECEIPT)) != 0U
            && (marker->flags
                & (MARKER_FLAG_OLD_LAUNCHER | MARKER_FLAG_OLD_RECEIPT))
                != (MARKER_FLAG_OLD_LAUNCHER | MARKER_FLAG_OLD_RECEIPT))
        || (marker->phase == TRANSACTION_POSTCOMMIT_ROLLBACK
            && (marker->flags & MARKER_FLAG_POSTCOMMIT_RETAIN) == 0)
        || marker->root_device != (uint64_t)handles->root_identity.st_dev
        || marker->root_inode != (uint64_t)handles->root_identity.st_ino
        || marker->owner_uid != (uint32_t)handles->owner
        || all_zero(marker->generation_id, 32U)) {
        errno = EINVAL;
        return -1;
    }
    memset(output, 0, MARKER_SIZE);
    memcpy(output, magic, sizeof(magic));
    store_u16(output + 8U, MARKER_VERSION);
    store_u16(output + 10U, marker->phase);
    store_u32(output + 12U, marker->flags);
    memcpy(output + 16U, marker->generation_id, 32U);
    store_u64(output + 48U, marker->root_device);
    store_u64(output + 56U, marker->root_inode);
    store_u32(output + 64U, marker->owner_uid);
    marker_store_identity(output + 72U, &marker->old_launcher);
    marker_store_identity(output + 152U, &marker->old_receipt);
    store_u32(output + 232U, marker->deployment_state);
    sha256_bytes(output, MARKER_HASHED_SIZE, digest);
    memcpy(output + MARKER_HASHED_SIZE, digest, 32U);
    memset(digest, 0, sizeof(digest));
    return 0;
}

static int
marker_decode(const uint8_t input[MARKER_SIZE],
    const struct install_handles *handles, struct transaction_marker *marker)
{
    static const uint8_t magic[8] = {
        'P', 'L', 'M', 'N', 'I', 'T', '3', '\0'
    };
    uint8_t digest[32];
    memset(marker, 0, sizeof(*marker));
    sha256_bytes(input, MARKER_HASHED_SIZE, digest);
    if (memcmp(input, magic, sizeof(magic)) != 0
        || load_u16(input + 8U) != MARKER_VERSION
        || memcmp(input + MARKER_HASHED_SIZE, digest, 32U) != 0
        || !all_zero(input + 68U, 4U)
        || !all_zero(input + 236U, MARKER_HASHED_SIZE - 236U))
        goto invalid;
    marker->phase = load_u16(input + 10U);
    marker->flags = load_u32(input + 12U);
    memcpy(marker->generation_id, input + 16U, 32U);
    marker->root_device = load_u64(input + 48U);
    marker->root_inode = load_u64(input + 56U);
    marker->owner_uid = load_u32(input + 64U);
    marker_load_identity(input + 72U, &marker->old_launcher);
    marker_load_identity(input + 152U, &marker->old_receipt);
    marker->deployment_state = load_u32(input + 232U);
    if (marker->phase < TRANSACTION_PREPARE
        || marker->phase > TRANSACTION_POSTCOMMIT_ROLLBACK
        || (marker->flags
            & ~(MARKER_FLAG_OLD_LAUNCHER | MARKER_FLAG_OLD_RECEIPT
                | MARKER_FLAG_DEPLOYMENT
                | MARKER_FLAG_POSTCOMMIT_RETAIN)) != 0
        || ((marker->flags
                & (MARKER_FLAG_OLD_LAUNCHER | MARKER_FLAG_OLD_RECEIPT)) != 0U
            && (marker->flags
                & (MARKER_FLAG_OLD_LAUNCHER | MARKER_FLAG_OLD_RECEIPT))
                != (MARKER_FLAG_OLD_LAUNCHER | MARKER_FLAG_OLD_RECEIPT))
        || (marker->phase == TRANSACTION_POSTCOMMIT_ROLLBACK
            && (marker->flags & MARKER_FLAG_POSTCOMMIT_RETAIN) == 0)
        || marker->root_device != (uint64_t)handles->root_identity.st_dev
        || marker->root_inode != (uint64_t)handles->root_identity.st_ino
        || marker->owner_uid != (uint32_t)handles->owner
        || all_zero(marker->generation_id, 32U))
        goto invalid;
    if ((marker->flags & MARKER_FLAG_OLD_LAUNCHER) == 0
        && !all_zero(input + 72U, 80U))
        goto invalid;
    if ((marker->flags & MARKER_FLAG_OLD_RECEIPT) == 0
        && !all_zero(input + 152U, 80U))
        goto invalid;
    if ((marker->flags & MARKER_FLAG_DEPLOYMENT) == 0
        && marker->deployment_state != 0U)
        goto invalid;
    memset(digest, 0, sizeof(digest));
    return 0;
invalid:
    memset(digest, 0, sizeof(digest));
    memset(marker, 0, sizeof(*marker));
    errno = EPERM;
    return -1;
}

static int
write_marker(struct install_handles *handles,
    const struct transaction_marker *marker)
{
    uint8_t bytes[MARKER_SIZE];
    int fd = -1, result = -1;
    if (marker_encode(marker, handles, bytes) != 0)
        goto done;
    fd = openat(handles->root, INSTALL_MARKER_NEXT,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || write_exact(fd, bytes, sizeof(bytes)) != 0
        || fchmod(fd, 0400) != 0 || fsync(fd) != 0
        || renameat(handles->root, INSTALL_MARKER_NEXT,
            handles->root, INSTALL_MARKER) != 0
        || fsync(handles->root) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        if (fd >= 0) close(fd);
        memset(bytes, 0, sizeof(bytes));
        if (result != 0) {
            (void)unlinkat(handles->root, INSTALL_MARKER_NEXT, 0);
            errno = saved;
        }
        return result;
    }
}

static int
read_marker(struct install_handles *handles,
    struct transaction_marker *marker, int *exists)
{
    uint8_t bytes[MARKER_SIZE];
    struct stat before, after;
    int fd = openat(handles->root, INSTALL_MARKER,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    *exists = 0;
    if (fd < 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    if (fstat(fd, &before) != 0
        || !regular_safe(&before, handles->owner, 0400U, 1)
        || before.st_size != (off_t)sizeof(bytes)
        || read_exact_at(fd, bytes, sizeof(bytes)) != 0
        || fstat(fd, &after) != 0 || !stat_same(&before, &after)
        || marker_decode(bytes, handles, marker) != 0) {
        int saved = errno == 0 ? EPERM : errno;
        close(fd);
        memset(bytes, 0, sizeof(bytes));
        errno = saved;
        return -1;
    }
    close(fd);
    memset(bytes, 0, sizeof(bytes));
    *exists = 1;
    return 0;
}

static int
observe_named_regular(int directory, const char *name, uid_t owner,
    uint32_t mode, int minimum_links, struct retained_identity *identity,
    int *exists)
{
    struct stat before, after;
    uint8_t digest[32];
    int fd;
    *exists = 0;
    fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    if (fstat(fd, &before) != 0 || !regular_safe(&before, owner, mode, 0)
        || before.st_nlink < minimum_links
        || hash_fd_retained(fd, digest, &after) != 0
        || !stat_same(&before, &after)) {
        int saved = errno == 0 ? EPERM : errno;
        close(fd);
        memset(digest, 0, sizeof(digest));
        errno = saved;
        return -1;
    }
    identity_from_stat(identity, &after, digest);
    memset(digest, 0, sizeof(digest));
    close(fd);
    *exists = 1;
    return 0;
}

static int
named_matches_identity(int directory, const char *name, uid_t owner,
    const struct retained_identity *identity, int *exists)
{
    struct retained_identity observed;
    if (observe_named_regular(directory, name, owner, identity->mode, 1,
            &observed, exists) != 0)
        return -1;
    if (*exists && (identity->device != observed.device
            || identity->inode != observed.inode
            || identity->size != observed.size
            || identity->mode != observed.mode
            || identity->uid != observed.uid
            || identity->gid != observed.gid
            || memcmp(identity->sha256, observed.sha256, 32U) != 0)) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int
ensure_absent(int directory, const char *name)
{
    struct stat information;
    if (fstatat(directory, name, &information, AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EEXIST;
        return -1;
    }
    return errno == ENOENT ? 0 : -1;
}

static int
unlink_safe_regular(int directory, const char *name, uid_t owner,
    int permit_missing)
{
    struct stat information;
    if (fstatat(directory, name, &information, AT_SYMLINK_NOFOLLOW) != 0) {
        if (permit_missing && errno == ENOENT)
            return 0;
        return -1;
    }
    if (!S_ISREG(information.st_mode) || information.st_uid != owner
        || information.st_nlink == 0
        || (information.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0) {
        errno = EPERM;
        return -1;
    }
    return unlinkat(directory, name, 0);
}

static int
snapshot_current_pair(struct install_handles *handles,
    struct transaction_marker *marker)
{
    int launcher_exists, receipt_exists;
    if (observe_named_regular(handles->bin, LAUNCHER_NAME, handles->owner,
            0500U, 2, &marker->old_launcher, &launcher_exists) != 0
        || observe_named_regular(handles->share, RECEIPT_NAME, handles->owner,
            0400U, 1, &marker->old_receipt, &receipt_exists) != 0)
        return -1;
    if (launcher_exists != receipt_exists) {
        errno = EPERM;
        return -1;
    }
    if (launcher_exists)
        marker->flags = MARKER_FLAG_OLD_LAUNCHER | MARKER_FLAG_OLD_RECEIPT;
    return 0;
}

static int
preflight_transient_names(struct install_handles *handles)
{
    return ensure_absent(handles->root, INSTALL_MARKER_NEXT) == 0
        && ensure_absent(handles->bin, LAUNCHER_NEXT) == 0
        && ensure_absent(handles->bin, LAUNCHER_BACKUP) == 0
        && ensure_absent(handles->share, RECEIPT_NEXT) == 0
        && ensure_absent(handles->share, RECEIPT_BACKUP) == 0 ? 0 : -1;
}

static int
create_backups(struct install_handles *handles,
    const struct transaction_marker *marker)
{
    struct retained_identity observed;
    int exists;
    if ((marker->flags & MARKER_FLAG_OLD_LAUNCHER) != 0) {
        if (linkat(handles->bin, LAUNCHER_NAME,
                handles->bin, LAUNCHER_BACKUP, 0) != 0
            || named_matches_identity(handles->bin, LAUNCHER_BACKUP,
                handles->owner, &marker->old_launcher, &exists) != 0
            || !exists || fsync(handles->bin) != 0)
            return -1;
    }
    if ((marker->flags & MARKER_FLAG_OLD_RECEIPT) != 0) {
        if (linkat(handles->share, RECEIPT_NAME,
                handles->share, RECEIPT_BACKUP, 0) != 0
            || named_matches_identity(handles->share, RECEIPT_BACKUP,
                handles->owner, &marker->old_receipt, &exists) != 0
            || !exists || fsync(handles->share) != 0)
            return -1;
    }
    memset(&observed, 0, sizeof(observed));
    return 0;
}

static int
publish_receipt_next(struct install_handles *handles,
    const struct receipt_observation *receipt)
{
    struct stat information;
    uint8_t digest[32];
    int fd = -1, result = -1;
    fd = openat(handles->share, RECEIPT_NEXT,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || write_exact(fd, receipt->bytes,
            sizeof(receipt->bytes)) != 0
        || fchmod(fd, 0400) != 0 || fsync(fd) != 0)
        goto done;
    close(fd); fd = -1;
    fd = openat(handles->share, RECEIPT_NEXT,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || hash_fd_retained(fd, digest, &information) != 0
        || !regular_safe(&information, handles->owner, 0400U, 1)
        || information.st_size != (off_t)sizeof(receipt->bytes)
        || memcmp(digest, receipt->file_sha256, 32U) != 0
        || fsync(handles->share) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        if (fd >= 0) close(fd);
        memset(digest, 0, sizeof(digest));
        if (result != 0) {
            (void)unlink_safe_regular(handles->share, RECEIPT_NEXT,
                handles->owner, 1);
            errno = saved;
        }
        return result;
    }
}

static int
publish_launcher_next(struct install_handles *handles, int launcher_parent,
    int retained_launcher, const struct receipt_member *member)
{
    struct stat retained, linked;
    uint8_t digest[32];
    int fd = -1, result = -1;
    if (fstat(retained_launcher, &retained) != 0
        || !regular_safe(&retained, handles->owner, 0500U, 0)
        || !identity_matches_stat(&member->identity, &retained, 0)
        || linkat(launcher_parent, LAUNCHER_NAME,
            handles->bin, LAUNCHER_NEXT, 0) != 0)
        goto done;
    fd = openat(handles->bin, LAUNCHER_NEXT,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || hash_fd_retained(fd, digest, &linked) != 0
        || !regular_safe(&linked, handles->owner, 0500U, 0)
        || linked.st_nlink < 2
        || retained.st_dev != linked.st_dev
        || retained.st_ino != linked.st_ino
        || !identity_matches_stat(&member->identity, &linked, 0)
        || memcmp(digest, member->identity.sha256, 32U) != 0
        || fsync(handles->bin) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        if (fd >= 0) close(fd);
        memset(digest, 0, sizeof(digest));
        if (result != 0) {
            (void)unlink_safe_regular(handles->bin, LAUNCHER_NEXT,
                handles->owner, 1);
            errno = saved;
        }
        return result;
    }
}

static int
verify_name_unchanged(int directory, const char *name, uid_t owner,
    const struct retained_identity *old, int expected_exists)
{
    int exists;
    if (!expected_exists)
        return ensure_absent(directory, name);
    if (named_matches_identity(directory, name, owner, old, &exists) != 0
        || !exists)
        return -1;
    return 0;
}

static int
restore_one(int directory, const char *active, const char *backup,
    uid_t owner, const struct retained_identity *old, int old_exists)
{
    int backup_exists, active_exists;
    if (!old_exists)
        return unlink_safe_regular(directory, active, owner, 1);
    if (named_matches_identity(directory, backup, owner, old,
            &backup_exists) != 0)
        return -1;
    if (backup_exists)
        return renameat(directory, backup, directory, active);
    if (named_matches_identity(directory, active, owner, old,
            &active_exists) != 0 || !active_exists) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int
cleanup_transaction_files(struct install_handles *handles,
    int remove_backups)
{
    if (unlink_safe_regular(handles->bin, LAUNCHER_NEXT,
            handles->owner, 1) != 0
        || unlink_safe_regular(handles->share, RECEIPT_NEXT,
            handles->owner, 1) != 0)
        return -1;
    if (remove_backups
        && (unlink_safe_regular(handles->bin, LAUNCHER_BACKUP,
                handles->owner, 1) != 0
            || unlink_safe_regular(handles->share, RECEIPT_BACKUP,
                handles->owner, 1) != 0))
        return -1;
    if (fsync(handles->bin) != 0 || fsync(handles->share) != 0)
        return -1;
    return 0;
}

static void
generation_hex(const uint8_t input[32], char output[65])
{
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32U; ++index) {
        output[index * 2U] = alphabet[input[index] >> 4];
        output[index * 2U + 1U] = alphabet[input[index] & 15U];
    }
    output[64] = '\0';
}

static int
open_generation(struct install_handles *handles, const char *generation_id,
    int *generation_fd)
{
    struct stat information;
    int fd = openat(handles->generations, generation_id,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &information) != 0
        || !directory_safe(&information, handles->owner, 0)) {
        int saved = errno == 0 ? EPERM : errno;
        close(fd);
        errno = saved;
        return -1;
    }
    *generation_fd = fd;
    return 0;
}

static int
validate_active_pair(struct install_handles *handles,
    const uint8_t generation_id[32])
{
    char hex[65], expected_path[INSTALL_RECEIPT_GENERATION_PATH_SIZE + 1U];
    struct receipt_observation receipt;
    struct stat launcher_info, stable_info;
    uint8_t stable_digest[32];
    int receipt_fd = -1, generation_fd = -1;
    int launcher_parent = -1, launcher_fd = -1, stable_fd = -1;
    int result = -1;
    generation_hex(generation_id, hex);
    if (snprintf(expected_path, sizeof(expected_path), "%s/generations/%s",
            handles->root_path, hex) >= (int)sizeof(expected_path)) {
        errno = ENAMETOOLONG;
        goto done;
    }
    receipt_fd = openat(handles->share, RECEIPT_NAME,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (receipt_fd < 0
        || receipt_decode(receipt_fd, expected_path, generation_id,
            handles->owner, &receipt) != 0
        || open_generation(handles, hex, &generation_fd) != 0
        || validate_receipt_members(generation_fd, &receipt, handles->owner,
            0, NULL, &launcher_parent, &launcher_fd) != 0
        || validate_specialized_authority(generation_fd, &receipt,
            handles->owner, -1) != 0
        || validate_source_bootstrap_authority(generation_fd, &receipt,
            handles->owner, -1) != 0)
        goto done;
    stable_fd = openat(handles->bin, LAUNCHER_NAME,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (stable_fd < 0 || fstat(launcher_fd, &launcher_info) != 0
        || hash_fd_retained(stable_fd, stable_digest, &stable_info) != 0
        || !regular_safe(&stable_info, handles->owner, 0500U, 0)
        || stable_info.st_nlink < 2
        || launcher_info.st_dev != stable_info.st_dev
        || launcher_info.st_ino != stable_info.st_ino
        || !identity_matches_stat(&receipt.members[0].identity,
            &stable_info, 0)
        || memcmp(stable_digest, receipt.members[0].identity.sha256, 32U) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (stable_fd >= 0) close(stable_fd);
        if (launcher_fd >= 0) close(launcher_fd);
        if (launcher_parent >= 0) close(launcher_parent);
        if (generation_fd >= 0) close(generation_fd);
        if (receipt_fd >= 0) close(receipt_fd);
        memset(&receipt, 0, sizeof(receipt));
        memset(stable_digest, 0, sizeof(stable_digest));
        memset(expected_path, 0, sizeof(expected_path));
        memset(hex, 0, sizeof(hex));
        if (result != 0) errno = saved;
        return result;
    }
}

static int
remove_marker(struct install_handles *handles)
{
    if (unlink_safe_regular(handles->root, INSTALL_MARKER,
            handles->owner, 1) != 0
        || unlink_safe_regular(handles->root, INSTALL_MARKER_NEXT,
            handles->owner, 1) != 0
        || fsync(handles->root) != 0)
        return -1;
    return 0;
}

static int
deployment_valid(const struct plamen_native_install_deployment_v2 *deployment)
{
    return deployment != NULL && deployment->prepare != NULL
        && deployment->activate != NULL && deployment->rollback != NULL
        && deployment->restore != NULL && deployment->commit != NULL;
}

static int
bind_marker_deployment(struct install_handles *handles,
    const struct transaction_marker *marker,
    const struct plamen_native_install_deployment_v2 *deployment)
{
    int exists;
    if ((marker->flags & MARKER_FLAG_DEPLOYMENT) == 0)
        return deployment == NULL ? 0 : -1;
    if (!deployment_valid(deployment) || deployment->bind_recovery == NULL
        || named_matches_identity(handles->share, RECEIPT_BACKUP,
            handles->owner, &marker->old_receipt, &exists) != 0
        || exists != ((marker->flags & MARKER_FLAG_OLD_RECEIPT) != 0)
        || deployment->bind_recovery(deployment->context,
            marker->deployment_state, marker->generation_id,
            (marker->flags & MARKER_FLAG_OLD_RECEIPT) != 0) != 0) {
        if (errno == 0) errno = ENOTRECOVERABLE;
        return -1;
    }
    return 0;
}

static int
validate_expected_successor(struct install_handles *handles,
    const struct transaction_marker *marker, int expected_receipt_fd)
{
    char hex[65], expected_path[INSTALL_RECEIPT_GENERATION_PATH_SIZE + 1U];
    struct receipt_observation expected;
    struct stat active_info;
    uint8_t active_digest[32];
    int active = -1, result = -1;
    memset(&expected, 0, sizeof(expected));
    memset(active_digest, 0, sizeof(active_digest));
    generation_hex(marker->generation_id, hex);
    if (expected_receipt_fd < 0
        || snprintf(expected_path, sizeof(expected_path), "%s/generations/%s",
            handles->root_path, hex) >= (int)sizeof(expected_path)
        || receipt_decode(expected_receipt_fd, expected_path,
            marker->generation_id, handles->owner, &expected) != 0
        || validate_active_pair(handles, marker->generation_id) != 0
        || (active = openat(handles->share, RECEIPT_NAME,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || hash_fd_retained(active, active_digest, &active_info) != 0
        || !regular_safe(&active_info, handles->owner, 0400U, 1)
        || memcmp(active_digest, expected.file_sha256, 32U) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (active >= 0) close(active);
        memset(&expected, 0, sizeof(expected));
        memset(active_digest, 0, sizeof(active_digest));
        memset(expected_path, 0, sizeof(expected_path));
        memset(hex, 0, sizeof(hex));
        if (result != 0) errno = saved;
        return result;
    }
}

static int
expected_prior_matches_marker(const struct transaction_marker *marker,
    int expected_prior_receipt_fd, int expected_prior_present)
{
    struct stat information;
    uint8_t digest[32];
    int result = -1;
    memset(digest, 0, sizeof(digest));
    if (expected_prior_present != 0 && expected_prior_present != 1) {
        errno = EINVAL;
        goto done;
    }
    if (expected_prior_present
        != ((marker->flags & MARKER_FLAG_OLD_RECEIPT) != 0)) {
        errno = EPERM;
        goto done;
    }
    if (!expected_prior_present) {
        if (expected_prior_receipt_fd >= 0) {
            errno = EINVAL;
            goto done;
        }
        result = 0;
        goto done;
    }
    if (expected_prior_receipt_fd < 0
        || hash_fd_retained(expected_prior_receipt_fd, digest,
            &information) != 0
        || !regular_safe(&information, (uid_t)marker->owner_uid, 0400U, 1)
        || information.st_size != (off_t)marker->old_receipt.size
        || memcmp(digest, marker->old_receipt.sha256, 32U) != 0) {
        if (errno == 0) errno = EPERM;
        goto done;
    }
    result = 0;
done:
    memset(digest, 0, sizeof(digest));
    return result;
}

static int
validate_expected_prior_active(struct install_handles *handles,
    int expected_prior_receipt_fd, int expected_prior_present)
{
    uint8_t generation_id[32];
    uint8_t digest[32];
    struct stat expected_info, active_info;
    int active = -1, result = -1;
    memset(generation_id, 0, sizeof(generation_id));
    memset(digest, 0, sizeof(digest));
    if (!expected_prior_present) {
        if (expected_prior_receipt_fd >= 0) {
            errno = EINVAL;
            return -1;
        }
        return ensure_absent(handles->bin, LAUNCHER_NAME) == 0
            && ensure_absent(handles->share, RECEIPT_NAME) == 0 ? 0 : -1;
    }
    if (expected_prior_receipt_fd < 0
        || pread(expected_prior_receipt_fd, generation_id, 32U, 16) != 32
        || all_zero(generation_id, 32U)
        || hash_fd_retained(expected_prior_receipt_fd, digest,
            &expected_info) != 0
        || !regular_safe(&expected_info, handles->owner, 0400U, 1)
        || validate_active_pair(handles, generation_id) != 0
        || (active = openat(handles->share, RECEIPT_NAME,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || hash_fd_retained(active, generation_id, &active_info) != 0
        || memcmp(generation_id, digest, 32U) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (active >= 0) close(active);
        memset(generation_id, 0, sizeof(generation_id));
        memset(digest, 0, sizeof(digest));
        if (result != 0) errno = saved;
        return result;
    }
}

static int
rollback_marker_locked(struct install_handles *handles,
    const struct transaction_marker *marker,
    const struct plamen_native_install_deployment_v2 *deployment)
{
    if ((marker->flags & MARKER_FLAG_DEPLOYMENT) != 0
        && marker->phase >= TRANSACTION_DEPLOYMENT_PREPARED
        && deployment->rollback(deployment->context,
            marker->deployment_state) != 0)
        return -1;
    if (marker->phase == TRANSACTION_PREPARE) {
        if (verify_name_unchanged(handles->bin, LAUNCHER_NAME,
                handles->owner, &marker->old_launcher,
                (marker->flags & MARKER_FLAG_OLD_LAUNCHER) != 0) != 0
            || verify_name_unchanged(handles->share, RECEIPT_NAME,
                handles->owner, &marker->old_receipt,
                (marker->flags & MARKER_FLAG_OLD_RECEIPT) != 0) != 0)
            return -1;
    } else if ((marker->flags & MARKER_FLAG_OLD_LAUNCHER) != 0) {
        if (restore_one(handles->share, RECEIPT_NAME, RECEIPT_BACKUP,
                handles->owner, &marker->old_receipt, 1) != 0
            || fsync(handles->share) != 0
            || restore_one(handles->bin, LAUNCHER_NAME, LAUNCHER_BACKUP,
                handles->owner, &marker->old_launcher, 1) != 0
            || fsync(handles->bin) != 0)
            return -1;
    } else {
        if (restore_one(handles->bin, LAUNCHER_NAME, LAUNCHER_BACKUP,
                handles->owner, &marker->old_launcher, 0) != 0
            || fsync(handles->bin) != 0
            || restore_one(handles->share, RECEIPT_NAME, RECEIPT_BACKUP,
                handles->owner, &marker->old_receipt, 0) != 0
            || fsync(handles->share) != 0)
            return -1;
    }
    if (verify_name_unchanged(handles->bin, LAUNCHER_NAME,
            handles->owner, &marker->old_launcher,
            (marker->flags & MARKER_FLAG_OLD_LAUNCHER) != 0) != 0
        || verify_name_unchanged(handles->share, RECEIPT_NAME,
            handles->owner, &marker->old_receipt,
            (marker->flags & MARKER_FLAG_OLD_RECEIPT) != 0) != 0
        || ((marker->flags & MARKER_FLAG_DEPLOYMENT) != 0
            && marker->phase >= TRANSACTION_DEPLOYMENT_PREPARED
            && deployment->restore(deployment->context,
                marker->deployment_state) != 0)
        || cleanup_transaction_files(handles, 1) != 0
        || remove_marker(handles) != 0)
        return -1;
    return 0;
}

static int
recover_locked(struct install_handles *handles,
    const struct plamen_native_install_deployment_v2 *deployment,
    int *recovered)
{
    struct transaction_marker marker;
    int exists;
    *recovered = 0;
    if (read_marker(handles, &marker, &exists) != 0)
        return -1;
    if (!exists) {
        struct stat information;
        if (fstatat(handles->root, INSTALL_MARKER_NEXT, &information,
                AT_SYMLINK_NOFOLLOW) == 0) {
            if (unlink_safe_regular(handles->root, INSTALL_MARKER_NEXT,
                    handles->owner, 0) != 0
                || fsync(handles->root) != 0)
                return -1;
            *recovered = 1;
        } else if (errno != ENOENT) {
            return -1;
        }
        return 0;
    }
    *recovered = 1;
    if ((marker.flags & MARKER_FLAG_DEPLOYMENT) != 0
        && !deployment_valid(deployment)) {
        memset(&marker, 0, sizeof(marker));
        errno = ENOTRECOVERABLE;
        return -1;
    }
    if ((marker.flags & MARKER_FLAG_DEPLOYMENT) != 0
        && marker.phase >= TRANSACTION_DEPLOYMENT_PREPARED
        && bind_marker_deployment(handles, &marker, deployment) != 0) {
        int saved = errno == 0 ? ENOTRECOVERABLE : errno;
        memset(&marker, 0, sizeof(marker));
        errno = saved;
        return -1;
    }
    if (marker.phase == TRANSACTION_COMMITTED) {
        if ((marker.flags & MARKER_FLAG_POSTCOMMIT_RETAIN) != 0) {
            if (validate_active_pair(handles, marker.generation_id) != 0)
                return -1;
            memset(&marker, 0, sizeof(marker));
            errno = EBUSY;
            return -1;
        }
        if (((marker.flags & MARKER_FLAG_DEPLOYMENT) != 0
                && deployment->commit(deployment->context,
                    marker.deployment_state) != 0)
            || validate_active_pair(handles, marker.generation_id) != 0
            || cleanup_transaction_files(handles, 1) != 0
            || remove_marker(handles) != 0)
            return -1;
        memset(&marker, 0, sizeof(marker));
        return 0;
    }
    if (rollback_marker_locked(handles, &marker, deployment) != 0)
        return -1;
    memset(&marker, 0, sizeof(marker));
    return 0;
}

#ifdef PLAMEN_NATIVE_INSTALLER_V2_TESTING
static int test_crash_after_phase;
struct test_deployment_context { const char *log_path; };

static int
test_deployment_append(void *opaque, char value)
{
    struct test_deployment_context *context = opaque;
    int fd = open(context->log_path,
        O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    int result = -1;
    if (fd >= 0 && write_exact(fd, (const uint8_t *)&value, 1U) == 0
        && fsync(fd) == 0)
        result = 0;
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        if (fd >= 0) close(fd);
        if (result != 0) errno = saved;
        return result;
    }
}

static int test_deployment_prepare(void *value, uint32_t *state)
{ *state = UINT32_C(0x504c4d4e); return test_deployment_append(value, 'P'); }
static int test_deployment_activate(void *value, uint32_t state)
{ return state == UINT32_C(0x504c4d4e) ? test_deployment_append(value, 'A') : -1; }
static int test_deployment_rollback(void *value, uint32_t state)
{ return state == UINT32_C(0x504c4d4e) ? test_deployment_append(value, 'R') : -1; }
static int test_deployment_restore(void *value, uint32_t state)
{ return state == UINT32_C(0x504c4d4e) ? test_deployment_append(value, 'S') : -1; }
static int test_deployment_commit(void *value, uint32_t state)
{ return state == UINT32_C(0x504c4d4e) ? test_deployment_append(value, 'C') : -1; }
static int test_deployment_bind(void *value, uint32_t state,
    const uint8_t generation_id[32], int prior_present)
{
    (void)value; (void)generation_id; (void)prior_present;
    return state == UINT32_C(0x504c4d4e) ? 0 : -1;
}

static void
maybe_test_crash(int phase)
{
    if (test_crash_after_phase == phase)
        _exit(99);
}

int
plamen_native_installer_test_crash_after_phase_v2(int phase)
{
    if (phase < TRANSACTION_PREPARE || phase > TRANSACTION_COMMITTED) {
        errno = EINVAL; return -1;
    }
    test_crash_after_phase = phase;
    return 0;
}
#else
static void
maybe_test_crash(int phase)
{
    (void)phase;
}
#endif

static int
revalidate_root(const struct install_handles *handles)
{
    struct stat information;
    if (fstat(handles->root, &information) != 0
        || information.st_dev != handles->root_identity.st_dev
        || information.st_ino != handles->root_identity.st_ino
        || !directory_safe(&information, handles->owner, 1)) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int
plamen_native_installer_recover_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int *recovered_transaction)
{
    struct install_handles handles;
    int recovered = 0, result = -1;
    if (recovered_transaction != NULL)
        *recovered_transaction = 0;
    if (install_handles_open(install_root_fd, install_root_absolute,
            owner_uid, &handles) != 0)
        return -1;
    if (acquire_install_lock(&handles) == 0
        && recover_locked(&handles, NULL, &recovered) == 0
        && revalidate_root(&handles) == 0)
        result = 0;
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        install_handles_close(&handles);
        if (recovered_transaction != NULL)
            *recovered_transaction = recovered;
        if (result != 0) errno = saved;
    }
    return result;
}

int
plamen_native_installer_recover_with_deployment_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    const struct plamen_native_install_deployment_v2 *deployment,
    int *recovered_transaction)
{
    struct install_handles handles;
    int recovered = 0, result = -1;
    if (recovered_transaction != NULL)
        *recovered_transaction = 0;
    if (!deployment_valid(deployment)) {
        errno = EINVAL;
        return -1;
    }
    if (install_handles_open(install_root_fd, install_root_absolute,
            owner_uid, &handles) != 0)
        return -1;
    if (acquire_install_lock(&handles) == 0
        && recover_locked(&handles, deployment, &recovered) == 0
        && revalidate_root(&handles) == 0)
        result = 0;
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        install_handles_close(&handles);
        if (recovered_transaction != NULL)
            *recovered_transaction = recovered;
        if (result != 0) errno = saved;
    }
    return result;
}

int
plamen_native_installer_validate_installed_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int expected_active_receipt_fd)
{
    struct install_handles handles;
    int result = -1;
    memset(&handles, 0, sizeof(handles));
    if (install_handles_open(install_root_fd, install_root_absolute,
            owner_uid, &handles) != 0)
        return -1;
    if (acquire_existing_validation_lock(&handles) == 0
        && validate_expected_prior_active(&handles,
            expected_active_receipt_fd, 1) == 0
        && revalidate_root(&handles) == 0)
        result = 0;
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        install_handles_close(&handles);
        if (result != 0) errno = saved;
    }
    return result;
}

int
plamen_native_installer_finalize_committed_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int expected_successor_receipt_fd,
    const struct plamen_native_install_deployment_v2 *deployment)
{
    struct install_handles handles;
    struct transaction_marker marker;
    int exists = 0, result = -1;
    memset(&handles, 0, sizeof(handles));
    memset(&marker, 0, sizeof(marker));
    if (install_handles_open(install_root_fd, install_root_absolute,
            owner_uid, &handles) != 0)
        return -1;
    if (acquire_install_lock(&handles) != 0
        || read_marker(&handles, &marker, &exists) != 0)
        goto done;
    if (!exists) {
        /* Exact active successor proves a prior successful finalization. */
        if (validate_expected_prior_active(&handles,
                expected_successor_receipt_fd, 1) != 0)
            goto done;
        result = 0;
        goto done;
    }
    if (marker.phase != TRANSACTION_COMMITTED
        || (marker.flags & MARKER_FLAG_POSTCOMMIT_RETAIN) == 0
        || bind_marker_deployment(&handles, &marker, deployment) != 0
        || validate_expected_successor(&handles, &marker,
            expected_successor_receipt_fd) != 0
        || ((marker.flags & MARKER_FLAG_DEPLOYMENT) != 0
            && deployment->commit(deployment->context,
                marker.deployment_state) != 0)
        || cleanup_transaction_files(&handles, 1) != 0
        || remove_marker(&handles) != 0
        || revalidate_root(&handles) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        install_handles_close(&handles);
        memset(&marker, 0, sizeof(marker));
        if (result != 0) errno = saved;
        return result;
    }
}

int
plamen_native_installer_rollback_committed_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int expected_successor_receipt_fd, int expected_prior_receipt_fd,
    int expected_prior_present,
    const struct plamen_native_install_deployment_v2 *deployment)
{
    struct install_handles handles;
    struct transaction_marker marker;
    int exists = 0, result = -1;
    memset(&handles, 0, sizeof(handles));
    memset(&marker, 0, sizeof(marker));
    if (install_handles_open(install_root_fd, install_root_absolute,
            owner_uid, &handles) != 0)
        return -1;
    if (acquire_install_lock(&handles) != 0
        || read_marker(&handles, &marker, &exists) != 0)
        goto done;
    if (!exists) {
        /* Exact predecessor state proves a prior successful rollback. */
        result = validate_expected_prior_active(&handles,
            expected_prior_receipt_fd, expected_prior_present);
        goto done;
    }
    if (marker.phase != TRANSACTION_COMMITTED
        || (marker.flags & MARKER_FLAG_POSTCOMMIT_RETAIN) == 0
        || bind_marker_deployment(&handles, &marker, deployment) != 0
        || validate_expected_successor(&handles, &marker,
            expected_successor_receipt_fd) != 0
        || expected_prior_matches_marker(&marker,
            expected_prior_receipt_fd, expected_prior_present) != 0)
        goto done;
    marker.phase = TRANSACTION_POSTCOMMIT_ROLLBACK;
    if (write_marker(&handles, &marker) != 0)
        goto done;
    maybe_test_crash(TRANSACTION_POSTCOMMIT_ROLLBACK);
    if (rollback_marker_locked(&handles, &marker, deployment) != 0
        || revalidate_root(&handles) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        install_handles_close(&handles);
        memset(&marker, 0, sizeof(marker));
        if (result != 0) errno = saved;
        return result;
    }
}

int
plamen_native_installer_publish_v2(
    const struct plamen_native_install_request_v2 *request,
    struct plamen_native_install_result_v2 *result)
{
    struct install_handles handles;
    struct transaction_marker marker;
    struct receipt_observation receipt;
    struct stat stage_parent_info, staged_info, destination_info;
    uint8_t generation_id[32];
    char expected_path[INSTALL_RECEIPT_GENERATION_PATH_SIZE + 1U];
    int stage_parent = -1, receipt_fd = -1, generation_fd = -1;
    int specialized_authority_fd = -1;
    int source_bootstrap_authority_fd = -1;
    int launcher_parent = -1, launcher_fd = -1, destination = -1;
    int retained_members[PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT];
    size_t member_index;
    int recovered = 0, marker_started = 0, generation_present = 0;
    int completed = 0;
    if (result != NULL)
        memset(result, 0, sizeof(*result));
    memset(&handles, 0, sizeof(handles));
    handles.root = handles.generations = handles.bin = handles.share = -1;
    handles.lock = -1;
    memset(&marker, 0, sizeof(marker));
    memset(&receipt, 0, sizeof(receipt));
    for (member_index = 0;
            member_index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT;
            ++member_index)
        retained_members[member_index] = -1;
    if (request == NULL || request->require_specialized_authority > 1U
        || request->require_source_bootstrap_authority > 1U
        || request->retain_postcommit_rollback > 1U
        || !valid_component(request->staged_generation_name)
        || decode_generation_id(request->generation_id_hex,
            generation_id) != 0
        || install_handles_open(request->install_root_fd,
            request->install_root_absolute, request->owner_uid,
            &handles) != 0)
        goto done;
    stage_parent = duplicate_cloexec(request->staging_parent_fd);
    receipt_fd = duplicate_cloexec(request->receipt_fd);
    if (request->require_specialized_authority != 0U)
        specialized_authority_fd = duplicate_cloexec(
            request->specialized_authority_fd);
    if (request->require_source_bootstrap_authority != 0U)
        source_bootstrap_authority_fd = duplicate_cloexec(
            request->source_bootstrap_authority_fd);
    for (member_index = 0;
            member_index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT;
            ++member_index) {
        retained_members[member_index] = duplicate_cloexec(
            request->generation_member_fds[member_index]);
        if (retained_members[member_index] < 0)
            goto done;
    }
    if (stage_parent < 0 || receipt_fd < 0
        || (request->require_specialized_authority != 0U
            && specialized_authority_fd < 0)
        || (request->require_source_bootstrap_authority != 0U
            && source_bootstrap_authority_fd < 0)
        || fstat(stage_parent, &stage_parent_info) != 0
        || !directory_safe(&stage_parent_info, handles.owner, 1)
        || snprintf(expected_path, sizeof(expected_path),
            "%s/generations/%s", handles.root_path,
            request->generation_id_hex) >= (int)sizeof(expected_path)
        || receipt_decode(receipt_fd, expected_path, generation_id,
            handles.owner, &receipt) != 0
        || receipt.specialized_present
            != (request->require_specialized_authority != 0U)
        || receipt.source_bootstrap_present
            != (request->require_source_bootstrap_authority != 0U)
        || acquire_install_lock(&handles) != 0
        || recover_locked(&handles, request->deployment, &recovered) != 0
        || preflight_transient_names(&handles) != 0)
        goto done;

    destination = openat(handles.generations, request->generation_id_hex,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (destination >= 0) {
        if (fstat(destination, &destination_info) != 0
            || !directory_safe(&destination_info, handles.owner, 0)
            || validate_receipt_members(destination, &receipt,
                handles.owner, 0, retained_members,
                &launcher_parent, &launcher_fd) != 0)
            goto done;
        if (validate_specialized_authority(destination, &receipt,
                handles.owner, specialized_authority_fd) != 0)
            goto done;
        if (validate_source_bootstrap_authority(destination, &receipt,
                handles.owner, source_bootstrap_authority_fd) != 0)
            goto done;
        if (validate_deployment_plists(destination, &receipt,
                handles.owner) != 0)
            goto done;
        generation_fd = destination; destination = -1;
        generation_present = 1;
    } else if (errno == ENOENT) {
        generation_fd = openat(stage_parent, request->staged_generation_name,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (generation_fd < 0)
            goto done;
        if (fstat(generation_fd, &staged_info) != 0
            || !directory_safe(&staged_info, handles.owner, 1)
            || (staged_info.st_mode & 07777) != 0700)
            goto done;
        if (validate_staged_tree(generation_fd, handles.owner) != 0)
            goto done;
        if (validate_receipt_members(generation_fd, &receipt,
                handles.owner, 1, retained_members,
                &launcher_parent, &launcher_fd) != 0)
            goto done;
        if (validate_specialized_authority(generation_fd, &receipt,
                handles.owner, specialized_authority_fd) != 0)
            goto done;
        if (validate_source_bootstrap_authority(generation_fd, &receipt,
                handles.owner, source_bootstrap_authority_fd) != 0)
            goto done;
        if (validate_deployment_plists(generation_fd, &receipt,
                handles.owner) != 0)
            goto done;
    } else {
        goto done;
    }

    marker.phase = TRANSACTION_PREPARE;
    marker.root_device = (uint64_t)handles.root_identity.st_dev;
    marker.root_inode = (uint64_t)handles.root_identity.st_ino;
    marker.owner_uid = (uint32_t)handles.owner;
    memcpy(marker.generation_id, generation_id, sizeof(generation_id));
    if (snapshot_current_pair(&handles, &marker) != 0)
        goto done;
    if (request->deployment != NULL) {
        if (!deployment_valid(request->deployment)) {
            errno = EINVAL;
            goto done;
        }
        marker.flags |= MARKER_FLAG_DEPLOYMENT;
    }
    if (request->retain_postcommit_rollback != 0U)
        marker.flags |= MARKER_FLAG_POSTCOMMIT_RETAIN;
    if (write_marker(&handles, &marker) != 0)
        goto done;
    marker_started = 1;
    maybe_test_crash(TRANSACTION_PREPARE);

    if (create_backups(&handles, &marker) != 0)
        goto done;
    marker.phase = TRANSACTION_PREPARED;
    if (write_marker(&handles, &marker) != 0)
        goto done;
    maybe_test_crash(TRANSACTION_PREPARED);

    if (!generation_present) {
        struct stat before_rename, after_rename;
        if (fstatat(stage_parent, request->staged_generation_name,
                &before_rename, AT_SYMLINK_NOFOLLOW) != 0)
            goto done;
        if (before_rename.st_dev != staged_info.st_dev) {
            errno = EXDEV;
            goto done;
        }
        if (before_rename.st_ino != staged_info.st_ino) {
            errno = ESTALE;
            goto done;
        }
        if (ensure_absent(handles.generations,
                request->generation_id_hex) != 0)
            goto done;
        if (renameat(stage_parent, request->staged_generation_name,
                handles.generations, request->generation_id_hex) != 0)
            goto done;
        if (fchmod(generation_fd, 0500) != 0
            || fsync(generation_fd) != 0
            || fsync(handles.generations) != 0
            || fstatat(handles.generations, request->generation_id_hex,
                &after_rename, AT_SYMLINK_NOFOLLOW) != 0
            || after_rename.st_dev != staged_info.st_dev
            || after_rename.st_ino != staged_info.st_ino)
            goto done;
    }
    marker.phase = TRANSACTION_GENERATION;
    if (write_marker(&handles, &marker) != 0)
        goto done;
    maybe_test_crash(TRANSACTION_GENERATION);

    if (publish_receipt_next(&handles, &receipt) != 0
        || publish_launcher_next(&handles, launcher_parent, launcher_fd,
            &receipt.members[0]) != 0
        || verify_name_unchanged(handles.bin, LAUNCHER_NAME,
            handles.owner, &marker.old_launcher,
            (marker.flags & MARKER_FLAG_OLD_LAUNCHER) != 0) != 0
        || verify_name_unchanged(handles.share, RECEIPT_NAME,
            handles.owner, &marker.old_receipt,
            (marker.flags & MARKER_FLAG_OLD_RECEIPT) != 0) != 0
        || renameat(handles.share, RECEIPT_NEXT,
            handles.share, RECEIPT_NAME) != 0
        || fsync(handles.share) != 0)
        goto done;
    marker.phase = TRANSACTION_RECEIPT;
    if (write_marker(&handles, &marker) != 0)
        goto done;
    maybe_test_crash(TRANSACTION_RECEIPT);

    if ((marker.flags & MARKER_FLAG_DEPLOYMENT) != 0) {
        if (request->deployment->prepare(request->deployment->context,
                &marker.deployment_state) != 0)
            goto done;
        marker.phase = TRANSACTION_DEPLOYMENT_PREPARED;
        if (write_marker(&handles, &marker) != 0)
            goto done;
        maybe_test_crash(TRANSACTION_DEPLOYMENT_PREPARED);
        if (request->deployment->activate(request->deployment->context,
                marker.deployment_state) != 0)
            goto done;
        marker.phase = TRANSACTION_DEPLOYMENT_ACTIVATED;
        if (write_marker(&handles, &marker) != 0)
            goto done;
        maybe_test_crash(TRANSACTION_DEPLOYMENT_ACTIVATED);
    }
    if (verify_name_unchanged(handles.bin, LAUNCHER_NAME,
            handles.owner, &marker.old_launcher,
            (marker.flags & MARKER_FLAG_OLD_LAUNCHER) != 0) != 0
        || renameat(handles.bin, LAUNCHER_NEXT,
            handles.bin, LAUNCHER_NAME) != 0
        || fsync(handles.bin) != 0)
        goto done;
    marker.phase = TRANSACTION_LAUNCHER;
    if (write_marker(&handles, &marker) != 0)
        goto done;
    maybe_test_crash(TRANSACTION_LAUNCHER);
    if (validate_active_pair(&handles, generation_id) != 0)
        goto done;
    marker.phase = TRANSACTION_COMMITTED;
    if (write_marker(&handles, &marker) != 0)
        goto done;
    maybe_test_crash(TRANSACTION_COMMITTED);
    if (((marker.flags & MARKER_FLAG_DEPLOYMENT) != 0
            && request->deployment->commit(request->deployment->context,
                marker.deployment_state) != 0)
        || ((marker.flags & MARKER_FLAG_POSTCOMMIT_RETAIN) == 0
            && (cleanup_transaction_files(&handles, 1) != 0
                || remove_marker(&handles) != 0))
        || revalidate_root(&handles) != 0)
        goto done;
    completed = 1;
done:
    {
        int saved = completed ? 0 : (errno == 0 ? EIO : errno);
        if (!completed && marker_started) {
            int ignored;
            if (recover_locked(&handles, request->deployment, &ignored) != 0)
                saved = errno == 0 ? EIO : errno;
        }
        if (destination >= 0) close(destination);
        if (launcher_fd >= 0) close(launcher_fd);
        if (launcher_parent >= 0) close(launcher_parent);
        if (generation_fd >= 0) close(generation_fd);
        if (specialized_authority_fd >= 0) close(specialized_authority_fd);
        if (source_bootstrap_authority_fd >= 0)
            close(source_bootstrap_authority_fd);
        if (receipt_fd >= 0) close(receipt_fd);
        if (stage_parent >= 0) close(stage_parent);
        for (member_index = 0;
                member_index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT;
                ++member_index) {
            if (retained_members[member_index] >= 0)
                close(retained_members[member_index]);
        }
        install_handles_close(&handles);
        memset(&marker, 0, sizeof(marker));
        memset(&receipt, 0, sizeof(receipt));
        memset(generation_id, 0, sizeof(generation_id));
        memset(expected_path, 0, sizeof(expected_path));
        if (result != NULL) {
            result->recovered_prior_transaction = recovered;
            result->generation_already_present = generation_present;
        }
        if (!completed) errno = saved;
        return completed ? 0 : -1;
    }
}

#ifdef PLAMEN_NATIVE_INSTALLER_V2_MAIN
static int
cli_read_member_paths(int receipt_fd,
    char paths[INSTALL_RECEIPT_MEMBER_COUNT]
        [INSTALL_RECEIPT_MEMBER_PATH_SIZE + 1U])
{
    uint8_t bytes[PLAMEN_NATIVE_INSTALLER_V2_RECEIPT_SIZE];
    uint16_t index;
    if (read_exact_at(receipt_fd, bytes, sizeof(bytes)) != 0)
        goto invalid;
    for (index = 0; index < INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        const uint8_t *row = bytes + INSTALL_RECEIPT_MEMBERS_OFFSET
            + (size_t)index * INSTALL_RECEIPT_MEMBER_SIZE;
        if (load_u16(row) != (uint16_t)(index + 1U)
            || copy_fixed_path(row + INSTALL_RECEIPT_MEMBER_PATH_OFFSET,
                INSTALL_RECEIPT_MEMBER_PATH_SIZE, load_u16(row + 2U),
                paths[index], INSTALL_RECEIPT_MEMBER_PATH_SIZE + 1U, 0)
                    != 0)
            goto invalid;
    }
    memset(bytes, 0, sizeof(bytes));
    return 0;
invalid:
    memset(bytes, 0, sizeof(bytes));
    memset(paths, 0, INSTALL_RECEIPT_MEMBER_COUNT
        * (INSTALL_RECEIPT_MEMBER_PATH_SIZE + 1U));
    if (errno == 0) errno = EBADMSG;
    return -1;
}

static int
cli_open_generation(int root_fd, int stage_parent_fd, const char *stage_name,
    const char *generation_id)
{
    int generation = openat(stage_parent_fd, stage_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int generations = -1;
    if (generation >= 0)
        return generation;
    if (errno != ENOENT)
        return -1;
    generations = openat(root_fd, "generations",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (generations < 0)
        return -1;
    generation = openat(generations, generation_id,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(generations);
    return generation;
}

static void
cli_diagnostic(void)
{
    static const char message[] = "Plamen native install denied.\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1U);
}

int
main(int argc, char **argv)
{
    struct plamen_native_install_request_v2 request;
    struct plamen_native_install_result_v2 result;
    char member_paths[INSTALL_RECEIPT_MEMBER_COUNT]
        [INSTALL_RECEIPT_MEMBER_PATH_SIZE + 1U];
    int root_fd = -1, stage_parent_fd = -1, receipt_fd = -1;
    int generation_fd = -1, status = 75;
    size_t index;
#ifdef PLAMEN_NATIVE_INSTALLER_V2_TESTING
    struct test_deployment_context deployment_context;
    struct plamen_native_install_deployment_v2 deployment;
    int deployment_requested = 0;
    int specialized_requested = 0;
    memset(&deployment_context, 0, sizeof(deployment_context));
    memset(&deployment, 0, sizeof(deployment));
#endif
    memset(&request, 0, sizeof(request));
    request.specialized_authority_fd = -1;
    memset(member_paths, 0, sizeof(member_paths));
    for (index = 0; index < INSTALL_RECEIPT_MEMBER_COUNT; ++index)
        request.generation_member_fds[index] = -1;
    if (argc == 3 && strcmp(argv[1], "recover") == 0) {
        int recovered;
        root_fd = open_absolute_nofollow(argv[2], O_RDONLY | O_DIRECTORY);
        if (root_fd >= 0 && plamen_native_installer_recover_v2(root_fd,
                argv[2], getuid(), &recovered) == 0)
            status = 0;
        goto done;
    }
    if (argc == 4 && strcmp(argv[1], "validate-installed") == 0) {
        root_fd = open_absolute_nofollow(argv[2], O_RDONLY | O_DIRECTORY);
        receipt_fd = open_absolute_nofollow(argv[3], O_RDONLY);
        if (root_fd >= 0 && receipt_fd >= 0
            && plamen_native_installer_validate_installed_v2(root_fd,
                argv[2], getuid(), receipt_fd) == 0)
            status = 0;
        goto done;
    }
#ifdef PLAMEN_NATIVE_INSTALLER_V2_TESTING
    if ((argc == 5 || argc == 6)
            && strcmp(argv[1], "finalize-retained-deploy") == 0) {
        deployment_context.log_path = argv[4];
        deployment.context = &deployment_context;
        deployment.bind_recovery = test_deployment_bind;
        deployment.prepare = test_deployment_prepare;
        deployment.activate = test_deployment_activate;
        deployment.rollback = test_deployment_rollback;
        deployment.restore = test_deployment_restore;
        deployment.commit = test_deployment_commit;
        if (argc == 6) {
            char *end = NULL; long phase = strtol(argv[5], &end, 10);
            if (end == argv[5] || *end != '\0'
                || phase != TRANSACTION_POSTCOMMIT_ROLLBACK) goto done;
            test_crash_after_phase = (int)phase;
        }
        root_fd = open_absolute_nofollow(argv[2], O_RDONLY | O_DIRECTORY);
        receipt_fd = open_absolute_nofollow(argv[3], O_RDONLY);
        if (root_fd >= 0 && receipt_fd >= 0
            && plamen_native_installer_finalize_committed_v2(root_fd,
                argv[2], getuid(), receipt_fd, &deployment) == 0)
            status = 0;
        goto done;
    }
    if ((argc == 6 || argc == 7)
            && strcmp(argv[1], "rollback-retained-deploy") == 0) {
        int prior_fd = -1;
        deployment_context.log_path = argv[5];
        deployment.context = &deployment_context;
        deployment.bind_recovery = test_deployment_bind;
        deployment.prepare = test_deployment_prepare;
        deployment.activate = test_deployment_activate;
        deployment.rollback = test_deployment_rollback;
        deployment.restore = test_deployment_restore;
        deployment.commit = test_deployment_commit;
        if (argc == 7) {
            char *end = NULL; long phase = strtol(argv[6], &end, 10);
            if (end == argv[6] || *end != '\0'
                || phase != TRANSACTION_POSTCOMMIT_ROLLBACK) goto done;
            test_crash_after_phase = (int)phase;
        }
        root_fd = open_absolute_nofollow(argv[2], O_RDONLY | O_DIRECTORY);
        receipt_fd = open_absolute_nofollow(argv[3], O_RDONLY);
        if (strcmp(argv[4], "-") != 0)
            prior_fd = open_absolute_nofollow(argv[4], O_RDONLY);
        if (root_fd >= 0 && receipt_fd >= 0
            && (strcmp(argv[4], "-") == 0 || prior_fd >= 0)
            && plamen_native_installer_rollback_committed_v2(root_fd,
                argv[2], getuid(), receipt_fd, prior_fd,
                strcmp(argv[4], "-") != 0, &deployment) == 0)
            status = 0;
        if (prior_fd >= 0) close(prior_fd);
        goto done;
    }
    if (argc == 4 && strcmp(argv[1], "recover-deploy") == 0) {
        int recovered;
        deployment_context.log_path = argv[3];
        deployment.context = &deployment_context;
        deployment.bind_recovery = test_deployment_bind;
        deployment.prepare = test_deployment_prepare;
        deployment.activate = test_deployment_activate;
        deployment.rollback = test_deployment_rollback;
        deployment.restore = test_deployment_restore;
        deployment.commit = test_deployment_commit;
        root_fd = open_absolute_nofollow(argv[2], O_RDONLY | O_DIRECTORY);
        if (root_fd >= 0
            && plamen_native_installer_recover_with_deployment_v2(root_fd,
                argv[2], getuid(), &deployment, &recovered) == 0)
            status = 0;
        goto done;
    }
    if ((argc == 8 || argc == 9)
            && strcmp(argv[1], "publish-specialized") == 0) {
        specialized_requested = 1;
        if (argc == 9) {
            char *end = NULL; long phase = strtol(argv[8], &end, 10);
            if (end == argv[8] || *end != '\0'
                || phase < TRANSACTION_PREPARE
                || phase > TRANSACTION_COMMITTED) goto done;
            test_crash_after_phase = (int)phase;
        }
    } else if (argc == 8 && strcmp(argv[1], "publish") == 0) {
        char *end = NULL; long phase = strtol(argv[7], &end, 10);
        if (end == argv[7] || *end != '\0' || phase < TRANSACTION_PREPARE
            || phase > TRANSACTION_COMMITTED) goto done;
        test_crash_after_phase = (int)phase;
    } else if ((argc == 8 || argc == 9)
            && (strcmp(argv[1], "publish-deploy") == 0
                || strcmp(argv[1], "publish-retained-deploy") == 0)) {
        deployment_requested = 1; deployment_context.log_path = argv[7];
        request.retain_postcommit_rollback =
            strcmp(argv[1], "publish-retained-deploy") == 0;
        deployment.context = &deployment_context;
        deployment.bind_recovery = test_deployment_bind;
        deployment.prepare = test_deployment_prepare;
        deployment.activate = test_deployment_activate;
        deployment.rollback = test_deployment_rollback;
        deployment.restore = test_deployment_restore;
        deployment.commit = test_deployment_commit;
        if (argc == 9) {
            char *end = NULL; long phase = strtol(argv[8], &end, 10);
            if (end == argv[8] || *end != '\0'
                || phase < TRANSACTION_PREPARE
                || phase > TRANSACTION_COMMITTED) goto done;
            test_crash_after_phase = (int)phase;
        }
    } else
#endif
    if (
#ifdef PLAMEN_NATIVE_INSTALLER_V2_TESTING
        (!specialized_requested && argc != 7)
            || (specialized_requested && argc != 8)
#else
        argc != 7
#endif
        )
        goto done;
    if (strcmp(argv[1], "publish") != 0
#ifdef PLAMEN_NATIVE_INSTALLER_V2_TESTING
        && strcmp(argv[1], "publish-specialized") != 0
        && strcmp(argv[1], "publish-deploy") != 0
        && strcmp(argv[1], "publish-retained-deploy") != 0
#endif
        )
        goto done;
    root_fd = open_absolute_nofollow(argv[2], O_RDONLY | O_DIRECTORY);
    stage_parent_fd = open_absolute_nofollow(argv[3],
        O_RDONLY | O_DIRECTORY);
    receipt_fd = open_absolute_nofollow(argv[6], O_RDONLY);
    if (root_fd < 0 || stage_parent_fd < 0 || receipt_fd < 0
        || cli_read_member_paths(receipt_fd, member_paths) != 0)
        goto done;
    generation_fd = cli_open_generation(root_fd, stage_parent_fd,
        argv[4], argv[5]);
    if (generation_fd < 0)
        goto done;
    for (index = 0; index < INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        if (open_relative_member(generation_fd, member_paths[index],
                getuid(), &request.generation_member_fds[index]) != 0)
            goto done;
    }
#ifdef PLAMEN_NATIVE_INSTALLER_V2_TESTING
    if (specialized_requested) {
        request.specialized_authority_fd = open_absolute_nofollow(
            argv[7], O_RDONLY);
        if (request.specialized_authority_fd < 0)
            goto done;
        request.require_specialized_authority = 1U;
    }
#endif
    request.install_root_fd = root_fd;
    request.staging_parent_fd = stage_parent_fd;
    request.receipt_fd = receipt_fd;
    request.install_root_absolute = argv[2];
    request.staged_generation_name = argv[4];
    request.generation_id_hex = argv[5];
    request.owner_uid = getuid();
#ifdef PLAMEN_NATIVE_INSTALLER_V2_TESTING
    if (deployment_requested) request.deployment = &deployment;
#endif
    if (plamen_native_installer_publish_v2(&request, &result) == 0)
        status = 0;
done:
    for (index = 0; index < INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        if (request.generation_member_fds[index] >= 0)
            close(request.generation_member_fds[index]);
    }
    if (request.specialized_authority_fd >= 0)
        close(request.specialized_authority_fd);
    if (generation_fd >= 0) close(generation_fd);
    if (receipt_fd >= 0) close(receipt_fd);
    if (stage_parent_fd >= 0) close(stage_parent_fd);
    if (root_fd >= 0) close(root_fd);
    memset(member_paths, 0, sizeof(member_paths));
    if (status != 0) cli_diagnostic();
    return status;
}
#endif
