#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_native_builder_v2.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define MANIFEST_FIXED_SIZE \
    (PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE \
    + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE \
    + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_TRAILER_SIZE)
#define ROW_PATH_OFFSET 56U
#define ROW_PATH_SLOT_SIZE 512U
#define ROW_RESERVED_OFFSET 568U
#define RUNTIME_DIRECTORY_KIND 1U
#define RUNTIME_FILE_KIND 2U
#define RUNTIME_FLAGS 1U
#define BINDING_FLAGS 1U
#define BINDING_FLAG_SPECIALIZED_AUTHORITY 2U
#define SPECIALIZED_AUTHORITY_OFFSET 1536U
#define SPECIALIZED_AUTHORITY_SIZE 256U
#define SPECIALIZED_AUTHORITY_PATH_OFFSET 120U
#define SPECIALIZED_AUTHORITY_PATH_SIZE 128U
#define MAX_COMPONENT_BYTES 255U

static const uint8_t manifest_magic[8] = {
    'P', 'L', 'M', 'R', 'P', 'M', '2', 0
};
static const uint8_t binding_magic[8] = {
    'P', 'L', 'M', 'R', 'P', 'B', '2', 0
};
static const uint8_t specialized_authority_magic[8] = {
    'P', 'L', 'M', 'S', 'R', 'A', '1', 0
};
static const char specialized_receipt_path[] =
    PLAMEN_RUNTIME_PACKAGE_SPECIALIZED_RECEIPT_PATH_V2;
static const char runtime_root_name[] = "lib/plamen/runtime";
static const char init_reference[] = "/usr/local/libexec/plamen-guest";
static const char tree_domain[] = "plamen.runtime-package.tree.v2";
static const uint8_t binding_field_order_kat[32] = {
    0xcb, 0xec, 0x56, 0xec, 0xf9, 0x48, 0x5c, 0xc1,
    0xca, 0x05, 0xd2, 0xfa, 0xa0, 0x9e, 0xa6, 0x15,
    0x75, 0xe9, 0xde, 0xff, 0xd7, 0x36, 0xfd, 0x1a,
    0xd8, 0xe4, 0x11, 0xa1, 0x86, 0x29, 0xff, 0xbe
};
static const char *const required_files[] = {
    "profiles/claude-v2.bin",
    "profiles/codex-v2.bin",
    "scripts/plamen_driver.py",
    "scripts/posix_audit_entrypoint.py",
    "scripts/posix_native_authority_adapter.py",
    "scripts/posix_specialized_tool_worker.py",
    "scripts/report_output_routing.py",
    "scripts/native_managed_evm_driver_preflight.py",
    "scripts/native_managed_evm_setup_effects.py",
    "scripts/posix_managed_evm_setup_transaction.py"
};
static const char intrinsic_generation_domain[] =
    "PLAMEN-INTRINSIC-GENERATION-V2";
static const char intrinsic_roster_domain[] = "PLAMEN-INTRINSIC-ROSTER-V2";
static const char *const intrinsic_generation_paths[] = {
    "bin/plamen-native-launcher",
    "lib/plamen/plamen-audit-broker-v2",
    "lib/plamen/_plamen_native_supervisor.cpython-312-darwin.so",
    "share/plamen/plamen_broker_v2.h",
    "share/plamen/native-supervisor-schema-v2.json",
    "bin/python3.12",
    "lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
    "share/plamen/runtime-package-manifest-v2.bin",
    "libexec/plamen-native-installer-v2",
    "libexec/plamen-native-source-bootstrap-coordinator-v1"
};
static const uint32_t intrinsic_generation_modes[] = {
    0500U, 0500U, 0400U, 0400U, 0400U, 0500U, 0400U, 0400U, 0500U,
    0500U
};

struct sha256_context {
    uint32_t state[8];
    uint64_t total;
    uint8_t block[64];
    size_t used;
};

struct runtime_row {
    char path[PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES + 1U];
    uint16_t kind;
    uint16_t depth;
    uint32_t mode;
    uint32_t links;
    uint64_t size;
    uint8_t sha256[32];
};

struct runtime_census {
    struct runtime_row *rows;
    size_t count;
    size_t capacity;
    uint32_t directory_count;
    uint32_t file_count;
    uint64_t total_file_bytes;
    uid_t owner;
};

struct name_list {
    char **items;
    size_t count;
};

static int digest_nonzero(const uint8_t digest[32]);

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
    context->total = 0U;
    context->used = 0U;
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
            context->used = 0U;
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
        context->used = 0U;
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

static void store_u16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value;
}

static void store_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static void store_u64(uint8_t *p, uint64_t value)
{
    size_t index;
    for (index = 0; index < 8U; ++index)
        p[7U - index] = (uint8_t)(value >> (index * 8U));
}

static uint16_t load_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t load_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t load_u64(const uint8_t *p)
{
    uint64_t value = 0U;
    size_t index;
    for (index = 0; index < 8U; ++index)
        value = (value << 8) | p[index];
    return value;
}

int
plamen_intrinsic_generation_id_and_roster_v2(
    const struct plamen_intrinsic_generation_member_v2
        members[PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2],
    uint8_t generation_id[PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2],
    uint8_t intrinsic_roster_sha256[
        PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2])
{
    struct sha256_context generation_context;
    struct sha256_context roster_context;
    uint8_t header[8];
    uint8_t count[2];
    uint8_t row[48];
    size_t index;

    if (members == NULL || generation_id == NULL
            || intrinsic_roster_sha256 == NULL) {
        errno = EINVAL;
        return -1;
    }
    sha256_init(&generation_context);
    sha256_update(&generation_context,
        (const uint8_t *)intrinsic_generation_domain,
        sizeof(intrinsic_generation_domain));
    store_u16(header, 2U);
    store_u16(header + 2U, 1U);
    store_u16(header + 4U, 1U);
    store_u16(header + 6U, PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2);
    sha256_update(&generation_context, header, sizeof(header));
    sha256_init(&roster_context);
    sha256_update(&roster_context, (const uint8_t *)intrinsic_roster_domain,
        sizeof(intrinsic_roster_domain));
    store_u16(count, PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2);
    sha256_update(&roster_context, count, sizeof(count));
    for (index = 0U; index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2;
            ++index) {
        const struct plamen_intrinsic_generation_member_v2 *member =
            &members[index];
        size_t expected_size = strlen(intrinsic_generation_paths[index]);
        if (member->role != index + 1U || member->relative_path == NULL
                || member->relative_path_size != expected_size
                || expected_size > PLAMEN_INTRINSIC_GENERATION_MAX_PATH_BYTES_V2
                || memcmp(member->relative_path,
                    intrinsic_generation_paths[index], expected_size) != 0
                || member->mode != intrinsic_generation_modes[index]
                || member->size == 0U || !digest_nonzero(member->sha256)) {
            memset(&generation_context, 0, sizeof(generation_context));
            memset(&roster_context, 0, sizeof(roster_context));
            errno = EINVAL;
            return -1;
        }
        memset(row, 0, sizeof(row));
        store_u16(row, member->role);
        store_u16(row + 2U, (uint16_t)member->relative_path_size);
        store_u32(row + 4U, member->mode);
        store_u64(row + 8U, member->size);
        memcpy(row + 16U, member->sha256, 32U);
        sha256_update(&generation_context, row, sizeof(row));
        sha256_update(&generation_context,
            (const uint8_t *)member->relative_path,
            member->relative_path_size);
        sha256_update(&roster_context, row, sizeof(row));
        sha256_update(&roster_context, (const uint8_t *)member->relative_path,
            member->relative_path_size);
    }
    sha256_final(&generation_context, generation_id);
    sha256_final(&roster_context, intrinsic_roster_sha256);
    memset(header, 0, sizeof(header));
    memset(count, 0, sizeof(count));
    memset(row, 0, sizeof(row));
    return 0;
}

int
plamen_intrinsic_generation_id_v2(
    const struct plamen_intrinsic_generation_member_v2
        members[PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2],
    uint8_t generation_id[PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2])
{
    uint8_t roster[PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2];
    int rc = plamen_intrinsic_generation_id_and_roster_v2(members,
        generation_id, roster);
    memset(roster, 0, sizeof(roster));
    return rc;
}

static int
all_zero(const uint8_t *p, size_t size)
{
    uint8_t value = 0U;
    size_t index;
    for (index = 0; index < size; ++index)
        value |= p[index];
    return value == 0U;
}

static int
digest_nonzero(const uint8_t digest[32])
{
    return !all_zero(digest, 32U);
}

static int
ascii_component(const char *name)
{
    size_t size;
    size_t index;
    unsigned char value;
    if (name == NULL)
        return 0;
    size = strlen(name);
    if (size == 0U || size > MAX_COMPONENT_BYTES)
        return 0;
    value = (unsigned char)name[0];
    if (!((value >= 'A' && value <= 'Z')
            || (value >= 'a' && value <= 'z')
            || (value >= '0' && value <= '9') || value == '_'))
        return 0;
    for (index = 1U; index < size; ++index) {
        value = (unsigned char)name[index];
        if (!((value >= 'A' && value <= 'Z')
                || (value >= 'a' && value <= 'z')
                || (value >= '0' && value <= '9') || value == '_'
                || value == '.' || value == '+' || value == '-'))
            return 0;
    }
    return 1;
}

static int
ascii_reference(const char *value, size_t size)
{
    size_t index;
    if (value == NULL || size == 0U || size > 511U)
        return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < 0x21U || byte > 0x7eU)
            return 0;
    }
    return 1;
}

static unsigned char
ascii_fold(unsigned char value)
{
    if (value >= 'A' && value <= 'Z')
        return (unsigned char)(value + ('a' - 'A'));
    return value;
}

static int
case_equal(const char *left, const char *right)
{
    size_t index = 0U;
    while (left[index] != '\0' && right[index] != '\0') {
        if (ascii_fold((unsigned char)left[index])
                != ascii_fold((unsigned char)right[index]))
            return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int
stat_equal(const struct stat *left, const struct stat *right)
{
    if (left->st_dev != right->st_dev || left->st_ino != right->st_ino
            || left->st_size != right->st_size
            || left->st_mode != right->st_mode || left->st_uid != right->st_uid
            || left->st_gid != right->st_gid
            || left->st_nlink != right->st_nlink)
        return 0;
#if defined(__APPLE__)
    if (left->st_mtimespec.tv_sec != right->st_mtimespec.tv_sec
            || left->st_mtimespec.tv_nsec != right->st_mtimespec.tv_nsec
            || left->st_ctimespec.tv_sec != right->st_ctimespec.tv_sec
            || left->st_ctimespec.tv_nsec != right->st_ctimespec.tv_nsec
            || left->st_flags != right->st_flags)
        return 0;
#else
    if (left->st_mtim.tv_sec != right->st_mtim.tv_sec
            || left->st_mtim.tv_nsec != right->st_mtim.tv_nsec
            || left->st_ctim.tv_sec != right->st_ctim.tv_sec
            || left->st_ctim.tv_nsec != right->st_ctim.tv_nsec)
        return 0;
#endif
    return 1;
}

static int
name_compare(const void *left, const void *right)
{
    const char *const *a = left;
    const char *const *b = right;
    return strcmp(*a, *b);
}

static void
name_list_dispose(struct name_list *names)
{
    size_t index;
    if (names == NULL)
        return;
    for (index = 0; index < names->count; ++index)
        free(names->items[index]);
    free(names->items);
    memset(names, 0, sizeof(*names));
}

static int
read_names(int directory_fd, struct name_list *names)
{
    int scan_fd = -1;
    DIR *directory = NULL;
    struct dirent *entry;
    size_t capacity = 0U;
    int saved = 0;

    memset(names, 0, sizeof(*names));
    scan_fd = openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC
        | O_NOFOLLOW);
    if (scan_fd < 0)
        return -1;
    directory = fdopendir(scan_fd);
    if (directory == NULL) {
        saved = errno;
        close(scan_fd);
        errno = saved;
        return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *copy;
        char **grown;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (!ascii_component(entry->d_name)
                || names->count >= PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES) {
            saved = EINVAL;
            goto fail;
        }
        if (names->count == capacity) {
            size_t next = capacity == 0U ? 16U : capacity * 2U;
            grown = realloc(names->items, next * sizeof(*grown));
            if (grown == NULL) {
                saved = ENOMEM;
                goto fail;
            }
            names->items = grown;
            capacity = next;
        }
        copy = strdup(entry->d_name);
        if (copy == NULL) {
            saved = ENOMEM;
            goto fail;
        }
        names->items[names->count++] = copy;
    }
    if (errno != 0) {
        saved = errno;
        goto fail;
    }
    if (closedir(directory) != 0) {
        saved = errno;
        directory = NULL;
        goto fail_no_close;
    }
    directory = NULL;
    qsort(names->items, names->count, sizeof(*names->items), name_compare);
    {
        size_t index;
        for (index = 1U; index < names->count; ++index) {
            if (strcmp(names->items[index - 1U], names->items[index]) == 0) {
                errno = EINVAL;
                name_list_dispose(names);
                return -1;
            }
        }
    }
    return 0;

fail:
    if (directory != NULL)
        (void)closedir(directory);
fail_no_close:
    name_list_dispose(names);
    errno = saved;
    return -1;
}

static int
same_name_lists(const struct name_list *left, const struct name_list *right)
{
    size_t index;
    if (left->count != right->count)
        return 0;
    for (index = 0; index < left->count; ++index) {
        if (strcmp(left->items[index], right->items[index]) != 0)
            return 0;
    }
    return 1;
}

static int
runtime_row_compare(const void *left, const void *right)
{
    const struct runtime_row *a = left;
    const struct runtime_row *b = right;
    return strcmp(a->path, b->path);
}

static int
append_row(struct runtime_census *census, const struct runtime_row *row)
{
    struct runtime_row *grown;
    size_t index;
    if (census->count >= PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES) {
        errno = EFBIG;
        return -1;
    }
    for (index = 0; index < census->count; ++index) {
        if (case_equal(census->rows[index].path, row->path)) {
            errno = EINVAL;
            return -1;
        }
    }
    if (census->count == census->capacity) {
        size_t next = census->capacity == 0U ? 32U : census->capacity * 2U;
        grown = realloc(census->rows, next * sizeof(*grown));
        if (grown == NULL)
            return -1;
        census->rows = grown;
        census->capacity = next;
    }
    census->rows[census->count++] = *row;
    return 0;
}

static int
hash_regular_fd(int fd, uint64_t size, uint8_t digest[32])
{
    struct sha256_context context;
    uint8_t buffer[32768];
    uint64_t offset = 0U;
    sha256_init(&context);
    while (offset < size) {
        size_t wanted = (size - offset) < sizeof(buffer)
            ? (size_t)(size - offset) : sizeof(buffer);
        ssize_t amount = pread(fd, buffer, wanted, (off_t)offset);
        if (amount <= 0) {
            memset(&context, 0, sizeof(context));
            errno = amount == 0 ? EIO : errno;
            return -1;
        }
        sha256_update(&context, buffer, (size_t)amount);
        offset += (uint64_t)amount;
    }
    if (pread(fd, buffer, 1U, (off_t)size) != 0) {
        memset(&context, 0, sizeof(context));
        errno = EIO;
        return -1;
    }
    sha256_final(&context, digest);
    memset(buffer, 0, sizeof(buffer));
    return 0;
}

static int
walk_directory(int directory_fd, const char *prefix, uint16_t parent_depth,
    struct runtime_census *census)
{
    struct name_list before;
    struct name_list after;
    size_t index;
    int saved = 0;

    if (read_names(directory_fd, &before) != 0)
        return -1;
    memset(&after, 0, sizeof(after));
    for (index = 0; index < before.count; ++index) {
        const char *name = before.items[index];
        struct stat named_before;
        struct stat opened;
        struct stat opened_after;
        struct stat named_after;
        struct runtime_row row;
        size_t prefix_size = strlen(prefix);
        size_t name_size = strlen(name);
        size_t path_size = prefix_size + (prefix_size == 0U ? 0U : 1U)
            + name_size;
        int fd = -1;

        memset(&row, 0, sizeof(row));
        if (path_size == 0U
                || path_size > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES
                || parent_depth >= PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH) {
            saved = EINVAL;
            goto fail;
        }
        if (prefix_size != 0U) {
            memcpy(row.path, prefix, prefix_size);
            row.path[prefix_size] = '/';
        }
        memcpy(row.path + prefix_size + (prefix_size == 0U ? 0U : 1U),
            name, name_size);
        row.path[path_size] = '\0';
        row.depth = (uint16_t)(parent_depth + 1U);
        if (fstatat(directory_fd, name, &named_before, AT_SYMLINK_NOFOLLOW) != 0) {
            saved = errno;
            goto fail;
        }
        if (S_ISDIR(named_before.st_mode)) {
            fd = openat(directory_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC
                | O_NOFOLLOW);
            if (fd < 0) {
                saved = errno;
                goto fail;
            }
            if (fstat(fd, &opened) != 0 || !stat_equal(&named_before, &opened)
                    || opened.st_uid != census->owner
                    || (opened.st_mode & 07777U) != 0500U) {
                saved = EINVAL;
                goto fail_entry;
            }
            row.kind = RUNTIME_DIRECTORY_KIND;
            row.mode = 0500U;
            if (append_row(census, &row) != 0) {
                saved = errno;
                goto fail_entry;
            }
            census->directory_count += 1U;
            if (walk_directory(fd, row.path, row.depth, census) != 0) {
                saved = errno;
                goto fail_entry;
            }
            if (fstat(fd, &opened_after) != 0
                    || fstatat(directory_fd, name, &named_after,
                        AT_SYMLINK_NOFOLLOW) != 0
                    || !stat_equal(&opened, &opened_after)
                    || !stat_equal(&opened_after, &named_after)) {
                saved = EBUSY;
                goto fail_entry;
            }
        } else if (S_ISREG(named_before.st_mode)) {
            fd = openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (fd < 0) {
                saved = errno;
                goto fail;
            }
            if (fstat(fd, &opened) != 0 || !stat_equal(&named_before, &opened)
                    || !S_ISREG(opened.st_mode) || opened.st_uid != census->owner
                    || (opened.st_mode & 07777U) != 0400U
                    || opened.st_nlink != 1
                    || opened.st_size < 0
                    || (uint64_t)opened.st_size
                        > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES) {
                saved = EINVAL;
                goto fail_entry;
            }
            if (census->total_file_bytes
                    > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_TOTAL_BYTES
                        - (uint64_t)opened.st_size) {
                saved = EFBIG;
                goto fail_entry;
            }
            row.kind = RUNTIME_FILE_KIND;
            row.mode = 0400U;
            row.links = 1U;
            row.size = (uint64_t)opened.st_size;
            if (hash_regular_fd(fd, row.size, row.sha256) != 0) {
                saved = errno;
                goto fail_entry;
            }
            if (fstat(fd, &opened_after) != 0
                    || fstatat(directory_fd, name, &named_after,
                        AT_SYMLINK_NOFOLLOW) != 0
                    || !stat_equal(&opened, &opened_after)
                    || !stat_equal(&opened_after, &named_after)) {
                saved = EBUSY;
                goto fail_entry;
            }
            if (append_row(census, &row) != 0) {
                saved = errno;
                goto fail_entry;
            }
            census->file_count += 1U;
            census->total_file_bytes += row.size;
        } else {
            saved = EINVAL;
            goto fail;
        }
        if (close(fd) != 0) {
            saved = errno;
            goto fail;
        }
        continue;

fail_entry:
        if (fd >= 0)
            (void)close(fd);
        goto fail;
    }
    if (read_names(directory_fd, &after) != 0) {
        saved = errno;
        goto fail;
    }
    if (!same_name_lists(&before, &after)) {
        saved = EBUSY;
        goto fail;
    }
    name_list_dispose(&before);
    name_list_dispose(&after);
    return 0;

fail:
    name_list_dispose(&before);
    name_list_dispose(&after);
    errno = saved == 0 ? EINVAL : saved;
    return -1;
}

static int
census_runtime(int root_fd, uid_t owner, struct runtime_census *census)
{
    struct stat before;
    struct stat after;
    size_t index;
    size_t required;
    memset(census, 0, sizeof(*census));
    census->owner = owner;
    if (fstat(root_fd, &before) != 0 || !S_ISDIR(before.st_mode)
            || before.st_uid != owner || (before.st_mode & 07777U) != 0500U) {
        errno = EINVAL;
        return -1;
    }
    if (walk_directory(root_fd, "", 0U, census) != 0)
        goto fail;
    if (fstat(root_fd, &after) != 0 || !stat_equal(&before, &after)) {
        errno = EBUSY;
        goto fail;
    }
    if (census->count == 0U) {
        errno = EINVAL;
        goto fail;
    }
    qsort(census->rows, census->count, sizeof(*census->rows),
        runtime_row_compare);
    for (index = 1U; index < census->count; ++index) {
        if (strcmp(census->rows[index - 1U].path,
                census->rows[index].path) >= 0) {
            errno = EINVAL;
            goto fail;
        }
    }
    for (required = 0U;
            required < sizeof(required_files) / sizeof(required_files[0]);
            ++required) {
        int found = 0;
        for (index = 0U; index < census->count; ++index) {
            if (census->rows[index].kind == RUNTIME_FILE_KIND
                    && strcmp(census->rows[index].path,
                        required_files[required]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            errno = EINVAL;
            goto fail;
        }
    }
    return 0;

fail:
    free(census->rows);
    memset(census, 0, sizeof(*census));
    return -1;
}

static int
has_digest_suffix(const char *reference, size_t reference_size,
    const uint8_t digest[32])
{
    static const char hex[] = "0123456789abcdef";
    char selected[73];
    size_t index;
    size_t selected_size = 72U;
    memcpy(selected, "@sha256:", 8U);
    for (index = 0U; index < 32U; ++index) {
        selected[8U + index * 2U] = hex[digest[index] >> 4];
        selected[9U + index * 2U] = hex[digest[index] & 0x0fU];
    }
    selected[selected_size] = '\0';
    if (reference_size == selected_size - 1U
            && memcmp(reference, selected + 1U, selected_size - 1U) == 0)
        return 1;
    return reference_size >= selected_size
        && memcmp(reference + reference_size - selected_size,
            selected, selected_size) == 0;
}

static int
encode_binding(const struct plamen_runtime_package_bindings_v2 *bindings,
    uint8_t output[PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE])
{
    size_t index;
    uint16_t flags;
    if (bindings == NULL
            || (bindings->target_arch
                != PLAMEN_RUNTIME_PACKAGE_TARGET_ARCH_ARM64_V2
                && bindings->target_arch
                != PLAMEN_RUNTIME_PACKAGE_TARGET_ARCH_AMD64_V2)
            || !ascii_reference(bindings->oci_image_reference,
                bindings->oci_image_reference_size)
            || !ascii_reference(bindings->oci_init_reference,
                bindings->oci_init_reference_size)
            || bindings->oci_init_reference_size != sizeof(init_reference) - 1U
            || memcmp(bindings->oci_init_reference, init_reference,
                sizeof(init_reference) - 1U) != 0
            || !has_digest_suffix(bindings->oci_image_reference,
                bindings->oci_image_reference_size,
                bindings->digests[PLAMEN_RUNTIME_PACKAGE_OCI_INDEX_V2])) {
        errno = EINVAL;
        return -1;
    }
    for (index = 0U;
            index < PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_COUNT; ++index) {
        if (!digest_nonzero(bindings->digests[index])) {
            errno = EINVAL;
            return -1;
        }
    }
    if (bindings->specialized_present != 0U
            && (bindings->specialized_present != 1U
                || bindings->specialized_member_receipt_path == NULL
                || bindings->specialized_member_receipt_path_size
                    != sizeof(specialized_receipt_path) - 1U
                || memcmp(bindings->specialized_member_receipt_path,
                    specialized_receipt_path,
                    sizeof(specialized_receipt_path) - 1U) != 0
                || !digest_nonzero(bindings->specialized_roster_sha256)
                || !digest_nonzero(bindings->specialized_policy_self_sha256)
                || !digest_nonzero(bindings->specialized_policy_bytes_sha256))) {
        errno = EINVAL;
        return -1;
    }
    if (bindings->specialized_present == 0U
            && (bindings->specialized_member_receipt_path != NULL
                || bindings->specialized_member_receipt_path_size != 0U
                || !all_zero(bindings->specialized_roster_sha256, 32U)
                || !all_zero(bindings->specialized_policy_self_sha256, 32U)
                || !all_zero(bindings->specialized_policy_bytes_sha256, 32U))) {
        errno = EINVAL;
        return -1;
    }
    flags = BINDING_FLAGS | (bindings->specialized_present != 0U
        ? BINDING_FLAG_SPECIALIZED_AUTHORITY : 0U);
    memset(output, 0, PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE);
    memcpy(output, binding_magic, sizeof(binding_magic));
    store_u16(output + 8U, PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_VERSION);
    store_u16(output + 10U, PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE);
    store_u16(output + 12U, bindings->target_arch);
    store_u16(output + 14U, 2U);
    store_u16(output + 16U, (uint16_t)bindings->oci_image_reference_size);
    store_u16(output + 18U, (uint16_t)bindings->oci_init_reference_size);
    store_u16(output + 20U,
        PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_COUNT);
    store_u16(output + 22U, flags);
    memcpy(output + 32U, binding_field_order_kat,
        sizeof(binding_field_order_kat));
    memcpy(output + 64U, bindings->digests, sizeof(bindings->digests));
    memcpy(output + 512U, bindings->oci_image_reference,
        bindings->oci_image_reference_size);
    memcpy(output + 1024U, bindings->oci_init_reference,
        bindings->oci_init_reference_size);
    if (bindings->specialized_present != 0U) {
        uint8_t *specialized = output + SPECIALIZED_AUTHORITY_OFFSET;
        memcpy(specialized, specialized_authority_magic,
            sizeof(specialized_authority_magic));
        store_u16(specialized + 8U, 1U);
        store_u16(specialized + 10U, SPECIALIZED_AUTHORITY_SIZE);
        store_u32(specialized + 12U, 1U);
        store_u16(specialized + 16U,
            (uint16_t)bindings->specialized_member_receipt_path_size);
        memcpy(specialized + 24U, bindings->specialized_roster_sha256, 32U);
        memcpy(specialized + 56U,
            bindings->specialized_policy_self_sha256, 32U);
        memcpy(specialized + 88U,
            bindings->specialized_policy_bytes_sha256, 32U);
        memcpy(specialized + SPECIALIZED_AUTHORITY_PATH_OFFSET,
            bindings->specialized_member_receipt_path,
            bindings->specialized_member_receipt_path_size);
    }
    return 0;
}

static int
decode_binding(const uint8_t *raw,
    struct plamen_runtime_package_bindings_v2 *bindings)
{
    uint16_t image_size;
    uint16_t init_size;
    uint16_t arch;
    uint16_t flags;
    uint8_t canonical[PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE];
    if (memcmp(raw, binding_magic, sizeof(binding_magic)) != 0
            || load_u16(raw + 8U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_VERSION
            || load_u16(raw + 10U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
            || load_u16(raw + 14U) != 2U
            || load_u16(raw + 20U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_COUNT
            || ((flags = load_u16(raw + 22U)) != BINDING_FLAGS
                && flags != (BINDING_FLAGS
                    | BINDING_FLAG_SPECIALIZED_AUTHORITY))
            || !all_zero(raw + 24U, 8U)
            || memcmp(raw + 32U, binding_field_order_kat, 32U) != 0) {
        errno = EINVAL;
        return -1;
    }
    arch = load_u16(raw + 12U);
    image_size = load_u16(raw + 16U);
    init_size = load_u16(raw + 18U);
    if ((arch != PLAMEN_RUNTIME_PACKAGE_TARGET_ARCH_ARM64_V2
                && arch != PLAMEN_RUNTIME_PACKAGE_TARGET_ARCH_AMD64_V2)
            || image_size == 0U || image_size > 511U
            || init_size == 0U || init_size > 511U
            || !all_zero(raw + 512U + image_size, 512U - image_size)
            || !all_zero(raw + 1024U + init_size, 512U - init_size)) {
        errno = EINVAL;
        return -1;
    }
    memset(bindings, 0, sizeof(*bindings));
    bindings->target_arch = arch;
    bindings->oci_image_reference = (const char *)(raw + 512U);
    bindings->oci_image_reference_size = image_size;
    bindings->oci_init_reference = (const char *)(raw + 1024U);
    bindings->oci_init_reference_size = init_size;
    memcpy(bindings->digests, raw + 64U, sizeof(bindings->digests));
    if ((flags & BINDING_FLAG_SPECIALIZED_AUTHORITY) != 0U) {
        const uint8_t *specialized = raw + SPECIALIZED_AUTHORITY_OFFSET;
        uint16_t path_size = load_u16(specialized + 16U);
        if (memcmp(specialized, specialized_authority_magic,
                sizeof(specialized_authority_magic)) != 0
                || load_u16(specialized + 8U) != 1U
                || load_u16(specialized + 10U) != SPECIALIZED_AUTHORITY_SIZE
                || load_u32(specialized + 12U) != 1U
                || path_size != sizeof(specialized_receipt_path) - 1U
                || !all_zero(specialized + 18U, 6U)
                || !digest_nonzero(specialized + 24U)
                || !digest_nonzero(specialized + 56U)
                || !digest_nonzero(specialized + 88U)
                || memcmp(specialized + SPECIALIZED_AUTHORITY_PATH_OFFSET,
                    specialized_receipt_path,
                    sizeof(specialized_receipt_path) - 1U) != 0
                || !all_zero(specialized
                        + SPECIALIZED_AUTHORITY_PATH_OFFSET + path_size,
                    SPECIALIZED_AUTHORITY_PATH_SIZE - path_size)
                || !all_zero(specialized + 248U, 8U)
                || !all_zero(raw + SPECIALIZED_AUTHORITY_OFFSET
                        + SPECIALIZED_AUTHORITY_SIZE,
                    PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
                        - SPECIALIZED_AUTHORITY_OFFSET
                        - SPECIALIZED_AUTHORITY_SIZE)) {
            errno = EINVAL;
            return -1;
        }
        bindings->specialized_present = 1U;
        bindings->specialized_member_receipt_path =
            (const char *)(specialized + SPECIALIZED_AUTHORITY_PATH_OFFSET);
        bindings->specialized_member_receipt_path_size = path_size;
        memcpy(bindings->specialized_roster_sha256,
            specialized + 24U, 32U);
        memcpy(bindings->specialized_policy_self_sha256,
            specialized + 56U, 32U);
        memcpy(bindings->specialized_policy_bytes_sha256,
            specialized + 88U, 32U);
    } else if (!all_zero(raw + SPECIALIZED_AUTHORITY_OFFSET,
            PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
                - SPECIALIZED_AUTHORITY_OFFSET)) {
        errno = EINVAL;
        return -1;
    }
    /* Slots are zero padded, so byte size is a safe temporary C terminator. */
    if (encode_binding(bindings, canonical) != 0
            || memcmp(raw, canonical, sizeof(canonical)) != 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int
parent_is_present(const struct runtime_row *rows, size_t count,
    const char *path)
{
    char parent[PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES + 1U];
    const char *slash = strrchr(path, '/');
    size_t size;
    size_t index;
    if (slash == NULL)
        return 1;
    size = (size_t)(slash - path);
    memcpy(parent, path, size);
    parent[size] = '\0';
    for (index = 0U; index < count; ++index) {
        if (rows[index].kind == RUNTIME_DIRECTORY_KIND
                && strcmp(rows[index].path, parent) == 0)
            return 1;
    }
    return 0;
}

static int
encode_manifest(const struct runtime_census *census,
    const struct plamen_runtime_package_bindings_v2 *bindings,
    uint8_t **bytes_out, size_t *size_out,
    struct plamen_runtime_package_manifest_result_v2 *result)
{
    uint8_t binding[PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE];
    uint8_t *bytes;
    uint8_t *rows;
    uint8_t *header;
    size_t total_size;
    size_t index;
    struct sha256_context tree;
    uint8_t counts[20];

    if (census == NULL || census->count == 0U
            || census->count > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES
            || census->count > (SIZE_MAX - MANIFEST_FIXED_SIZE)
                / PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE
            || encode_binding(bindings, binding) != 0)
        return -1;
    total_size = MANIFEST_FIXED_SIZE
        + census->count * PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE;
    bytes = calloc(1U, total_size);
    if (bytes == NULL)
        return -1;
    header = bytes;
    rows = bytes + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE
        + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE;
    for (index = 0U; index < census->count; ++index) {
        const struct runtime_row *row = &census->rows[index];
        uint8_t *encoded = rows
            + index * PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE;
        size_t path_size = strlen(row->path);
        if (path_size == 0U
                || path_size > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES
                || (index != 0U
                    && strcmp(census->rows[index - 1U].path, row->path) >= 0)
                || !parent_is_present(census->rows, index, row->path)
                || row->depth == 0U
                || row->depth > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH
                || (row->kind == RUNTIME_DIRECTORY_KIND
                    && (row->mode != 0500U || row->size != 0U
                        || row->links != 0U || !all_zero(row->sha256, 32U)))
                || (row->kind == RUNTIME_FILE_KIND
                    && (row->mode != 0400U || row->links != 1U
                        || row->size
                            > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES))
                || (row->kind != RUNTIME_DIRECTORY_KIND
                    && row->kind != RUNTIME_FILE_KIND)) {
            free(bytes);
            errno = EINVAL;
            return -1;
        }
        store_u16(encoded, row->kind);
        store_u16(encoded + 2U, (uint16_t)path_size);
        store_u32(encoded + 4U, row->mode);
        store_u64(encoded + 8U, row->size);
        store_u32(encoded + 16U, row->links);
        store_u16(encoded + 20U, row->depth);
        memcpy(encoded + 24U, row->sha256, 32U);
        memcpy(encoded + ROW_PATH_OFFSET, row->path, path_size);
    }
    memcpy(header, manifest_magic, sizeof(manifest_magic));
    store_u16(header + 8U, PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_VERSION);
    store_u16(header + 10U, PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE);
    store_u32(header + 12U, (uint32_t)total_size);
    store_u32(header + 16U, PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE);
    store_u32(header + 20U, (uint32_t)census->count);
    store_u32(header + 24U, census->directory_count);
    store_u32(header + 28U, census->file_count);
    store_u64(header + 32U, census->total_file_bytes);
    store_u64(header + 40U,
        PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES);
    store_u32(header + 48U,
        PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES);
    store_u16(header + 52U,
        PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES);
    store_u16(header + 54U, PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH);
    store_u16(header + 56U, (uint16_t)(sizeof(runtime_root_name) - 1U));
    store_u16(header + 58U,
        (uint16_t)(sizeof(required_files) / sizeof(required_files[0])));
    store_u32(header + 60U, RUNTIME_FLAGS);
    store_u32(header + 64U,
        PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE);
    store_u32(header + 68U,
        PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_COUNT);
    sha256_bytes(rows,
        census->count * PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE,
        header + 96U);
    memcpy(header + 160U, runtime_root_name, sizeof(runtime_root_name) - 1U);
    memcpy(bytes + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE, binding,
        sizeof(binding));
    store_u32(counts, (uint32_t)census->count);
    store_u32(counts + 4U, census->directory_count);
    store_u32(counts + 8U, census->file_count);
    store_u64(counts + 12U, census->total_file_bytes);
    sha256_init(&tree);
    sha256_update(&tree, (const uint8_t *)tree_domain, sizeof(tree_domain));
    sha256_update(&tree, (const uint8_t *)runtime_root_name,
        sizeof(runtime_root_name) - 1U);
    sha256_update(&tree, counts, sizeof(counts));
    sha256_update(&tree, binding, sizeof(binding));
    sha256_update(&tree, rows,
        census->count * PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE);
    sha256_final(&tree, header + 128U);
    sha256_bytes(bytes, total_size - 32U, bytes + total_size - 32U);
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
        result->entry_count = (uint32_t)census->count;
        result->directory_count = census->directory_count;
        result->file_count = census->file_count;
        result->total_file_bytes = census->total_file_bytes;
        result->manifest_size = total_size;
        memcpy(result->census_sha256, header + 96U, 32U);
        memcpy(result->tree_sha256, header + 128U, 32U);
        sha256_bytes(bytes, total_size, result->manifest_sha256);
    }
    *bytes_out = bytes;
    *size_out = total_size;
    return 0;
}

static int
complete_exact_candidate(int fd, const uint8_t *bytes, size_t size,
    uid_t owner, const struct stat *before, uint32_t final_mode)
{
    struct stat after_read, after_write;
    uint8_t buffer[4096];
    size_t offset = 0U, prefix;
    int flags;
    if (fd < 0 || bytes == NULL || before == NULL
            || !S_ISREG(before->st_mode) || before->st_uid != owner
            || before->st_nlink != 1
            || before->st_size < 0 || (uint64_t)before->st_size > size
            || (flags = fcntl(fd, F_GETFL)) < 0
            || ((before->st_mode & 07777U) == 0600U
                ? (flags & O_ACCMODE) != O_RDWR
                : ((before->st_mode & 07777U) != final_mode
                    || before->st_size != (off_t)size
                    || (flags & O_ACCMODE) != O_RDONLY))) {
        errno = EINVAL;
        return -1;
    }
    prefix = (size_t)before->st_size;
    while (offset < prefix) {
        size_t amount = prefix - offset;
        ssize_t observed;
        if (amount > sizeof(buffer)) amount = sizeof(buffer);
        observed = pread(fd, buffer, amount, (off_t)offset);
        if (observed <= 0 || (size_t)observed != amount
                || memcmp(buffer, bytes + offset, amount) != 0) {
            memset(buffer, 0, sizeof(buffer));
            errno = EPERM;
            return -1;
        }
        offset += amount;
    }
    memset(buffer, 0, sizeof(buffer));
    if (fstat(fd, &after_read) != 0
            || after_read.st_dev != before->st_dev
            || after_read.st_ino != before->st_ino
            || after_read.st_mode != before->st_mode
            || after_read.st_uid != before->st_uid
            || after_read.st_gid != before->st_gid
            || after_read.st_nlink != before->st_nlink
            || after_read.st_size != before->st_size) {
        errno = EBUSY;
        return -1;
    }
    if ((before->st_mode & 07777U) == final_mode)
        return 0;
    offset = prefix;
    while (offset < size) {
        ssize_t amount = pwrite(fd, bytes + offset, size - offset,
            (off_t)offset);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0) {
            errno = amount == 0 ? EIO : errno;
            return -1;
        }
        offset += (size_t)amount;
    }
    if (fsync(fd) != 0 || fchmod(fd, final_mode) != 0 || fsync(fd) != 0
            || fstat(fd, &after_write) != 0
            || after_write.st_dev != before->st_dev
            || after_write.st_ino != before->st_ino
            || after_write.st_uid != owner || after_write.st_nlink != 1
            || after_write.st_size != (off_t)size
            || (after_write.st_mode & 07777U) != final_mode) {
        errno = errno == 0 ? EIO : errno;
        return -1;
    }
    return 0;
}

int
plamen_runtime_package_manifest_render_v2(int runtime_root_fd,
    const struct plamen_runtime_package_bindings_v2 *bindings, int output_fd,
    uid_t owner_uid, struct plamen_runtime_package_manifest_result_v2 *result)
{
    struct runtime_census census;
    struct stat output_before;
    uint8_t *bytes = NULL;
    size_t size = 0U;
    struct plamen_runtime_package_manifest_result_v2 candidate_result;
    int flags;
    int rc = -1;

    if (runtime_root_fd < 0 || output_fd < 0 || bindings == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (result != NULL)
        memset(result, 0, sizeof(*result));
    flags = fcntl(output_fd, F_GETFL);
    if (flags < 0
            || fstat(output_fd, &output_before) != 0
            || !S_ISREG(output_before.st_mode) || output_before.st_uid != owner_uid
            || output_before.st_nlink != 1
            || output_before.st_size < 0) {
        errno = EINVAL;
        return -1;
    }
    if (census_runtime(runtime_root_fd, owner_uid, &census) != 0)
        return -1;
    if (encode_manifest(&census, bindings, &bytes, &size,
            &candidate_result) != 0)
        goto out;
    if (complete_exact_candidate(output_fd, bytes, size, owner_uid,
            &output_before, 0400U) != 0) {
        goto out;
    }
    if (result != NULL)
        *result = candidate_result;
    rc = 0;

out:
    free(bytes);
    free(census.rows);
    return rc;
}

static int
validate_manifest(const uint8_t *bytes, size_t size,
    struct plamen_runtime_package_manifest_result_v2 *result,
    struct plamen_runtime_package_bindings_v2 *bindings_out)
{
    uint32_t entry_count;
    uint32_t directory_count;
    uint32_t file_count;
    uint64_t total_file_bytes;
    size_t expected;
    size_t index;
    uint32_t observed_directories = 0U;
    uint32_t observed_files = 0U;
    uint64_t observed_bytes = 0U;
    struct runtime_row *rows = NULL;
    struct plamen_runtime_package_bindings_v2 bindings;
    uint8_t digest[32];
    uint8_t counts[20];
    struct sha256_context tree;
    int rc = -1;

    if (bytes == NULL || size < MANIFEST_FIXED_SIZE
            + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE
            || memcmp(bytes, manifest_magic, sizeof(manifest_magic)) != 0
            || load_u16(bytes + 8U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_VERSION
            || load_u16(bytes + 10U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE
            || load_u32(bytes + 16U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE
            || load_u64(bytes + 40U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES
            || load_u32(bytes + 48U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES
            || load_u16(bytes + 52U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES
            || load_u16(bytes + 54U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH
            || load_u16(bytes + 56U) != sizeof(runtime_root_name) - 1U
            || load_u16(bytes + 58U)
                != sizeof(required_files) / sizeof(required_files[0])
            || load_u32(bytes + 60U) != RUNTIME_FLAGS
            || load_u32(bytes + 64U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
            || load_u32(bytes + 68U)
                != PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_COUNT
            || !all_zero(bytes + 72U, 24U)
            || memcmp(bytes + 160U, runtime_root_name,
                sizeof(runtime_root_name) - 1U) != 0
            || !all_zero(bytes + 160U + sizeof(runtime_root_name) - 1U,
                64U - (sizeof(runtime_root_name) - 1U))
            || !all_zero(bytes + 224U, 32U)) {
        errno = EINVAL;
        return -1;
    }
    entry_count = load_u32(bytes + 20U);
    directory_count = load_u32(bytes + 24U);
    file_count = load_u32(bytes + 28U);
    total_file_bytes = load_u64(bytes + 32U);
    if (entry_count == 0U
            || entry_count > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES
            ) {
        errno = EINVAL;
        return -1;
    }
    expected = MANIFEST_FIXED_SIZE
        + (size_t)entry_count * PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE;
    if (size != expected || load_u32(bytes + 12U) != size) {
        errno = EINVAL;
        return -1;
    }
    sha256_bytes(bytes, size - 32U, digest);
    if (memcmp(digest, bytes + size - 32U, 32U) != 0
            || decode_binding(bytes
                + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE,
                &bindings) != 0)
        return -1;
    rows = calloc(entry_count, sizeof(*rows));
    if (rows == NULL)
        return -1;
    for (index = 0U; index < entry_count; ++index) {
        const uint8_t *encoded = bytes
            + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE
            + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
            + index * PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE;
        struct runtime_row *row = &rows[index];
        uint16_t path_size = load_u16(encoded + 2U);
        uint16_t depth = 1U;
        size_t path_index;
        if (path_size == 0U
                || path_size > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES
                || load_u16(encoded + 22U) != 0U
                || !all_zero(encoded + ROW_PATH_OFFSET + path_size,
                    ROW_PATH_SLOT_SIZE - path_size)
                || !all_zero(encoded + ROW_RESERVED_OFFSET,
                    PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE
                        - ROW_RESERVED_OFFSET)) {
            errno = EINVAL;
            goto out;
        }
        memcpy(row->path, encoded + ROW_PATH_OFFSET, path_size);
        row->path[path_size] = '\0';
        for (path_index = 0U; path_index < path_size; ++path_index) {
            if (row->path[path_index] == '/')
                ++depth;
        }
        {
            const char *component = row->path;
            const char *cursor;
            for (cursor = row->path; ; ++cursor) {
                if (*cursor == '/' || *cursor == '\0') {
                    char part[MAX_COMPONENT_BYTES + 1U];
                    size_t component_size = (size_t)(cursor - component);
                    if (component_size == 0U
                            || component_size > MAX_COMPONENT_BYTES) {
                        errno = EINVAL;
                        goto out;
                    }
                    memcpy(part, component, component_size);
                    part[component_size] = '\0';
                    if (!ascii_component(part)) {
                        errno = EINVAL;
                        goto out;
                    }
                    if (*cursor == '\0')
                        break;
                    component = cursor + 1;
                }
            }
        }
        row->kind = load_u16(encoded);
        row->mode = load_u32(encoded + 4U);
        row->size = load_u64(encoded + 8U);
        row->links = load_u32(encoded + 16U);
        row->depth = load_u16(encoded + 20U);
        memcpy(row->sha256, encoded + 24U, 32U);
        if (row->depth != depth
                || row->depth > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH
                || (index != 0U && strcmp(rows[index - 1U].path, row->path) >= 0)
                || !parent_is_present(rows, index, row->path)
                || (row->kind == RUNTIME_DIRECTORY_KIND
                    && (row->mode != 0500U || row->size != 0U
                        || row->links != 0U || !all_zero(row->sha256, 32U)))
                || (row->kind == RUNTIME_FILE_KIND
                    && (row->mode != 0400U || row->links != 1U
                        || row->size
                            > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES))
                || (row->kind != RUNTIME_DIRECTORY_KIND
                    && row->kind != RUNTIME_FILE_KIND)) {
            errno = EINVAL;
            goto out;
        }
        for (path_index = 0U; path_index < index; ++path_index) {
            if (case_equal(rows[path_index].path, row->path)) {
                errno = EINVAL;
                goto out;
            }
        }
        if (row->kind == RUNTIME_DIRECTORY_KIND)
            ++observed_directories;
        else {
            ++observed_files;
            if (observed_bytes
                    > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_TOTAL_BYTES
                        - row->size) {
                errno = EINVAL;
                goto out;
            }
            observed_bytes += row->size;
        }
    }
    if (observed_directories != directory_count || observed_files != file_count
            || observed_bytes != total_file_bytes) {
        errno = EINVAL;
        goto out;
    }
    {
        size_t required;
        for (required = 0U;
                required < sizeof(required_files) / sizeof(required_files[0]);
                ++required) {
            int found = 0;
            for (index = 0U; index < entry_count; ++index) {
                if (rows[index].kind == RUNTIME_FILE_KIND
                        && strcmp(rows[index].path, required_files[required]) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                errno = EINVAL;
                goto out;
            }
        }
    }
    sha256_bytes(bytes + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE
        + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE,
        (size_t)entry_count * PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE,
        digest);
    if (memcmp(digest, bytes + 96U, 32U) != 0) {
        errno = EINVAL;
        goto out;
    }
    store_u32(counts, entry_count);
    store_u32(counts + 4U, directory_count);
    store_u32(counts + 8U, file_count);
    store_u64(counts + 12U, total_file_bytes);
    sha256_init(&tree);
    sha256_update(&tree, (const uint8_t *)tree_domain, sizeof(tree_domain));
    sha256_update(&tree, (const uint8_t *)runtime_root_name,
        sizeof(runtime_root_name) - 1U);
    sha256_update(&tree, counts, sizeof(counts));
    sha256_update(&tree,
        bytes + PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE,
        PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
            + (size_t)entry_count
                * PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE);
    sha256_final(&tree, digest);
    if (memcmp(digest, bytes + 128U, 32U) != 0) {
        errno = EINVAL;
        goto out;
    }
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
        result->entry_count = entry_count;
        result->directory_count = directory_count;
        result->file_count = file_count;
        result->total_file_bytes = total_file_bytes;
        result->manifest_size = size;
        memcpy(result->census_sha256, bytes + 96U, 32U);
        memcpy(result->tree_sha256, bytes + 128U, 32U);
        sha256_bytes(bytes, size, result->manifest_sha256);
    }
    if (bindings_out != NULL)
        *bindings_out = bindings;
    rc = 0;

out:
    free(rows);
    return rc;
}

int
plamen_runtime_package_manifest_decode_exact_v2(const uint8_t *bytes,
    size_t size, struct plamen_runtime_package_manifest_result_v2 *result)
{
    return validate_manifest(bytes, size, result, NULL);
}

int
plamen_runtime_package_manifest_decode_bindings_exact_v2(
    const uint8_t *bytes, size_t size,
    struct plamen_runtime_package_manifest_result_v2 *result,
    struct plamen_runtime_package_bindings_v2 *bindings_out)
{
    if (bindings_out == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(bindings_out, 0, sizeof(*bindings_out));
    if (validate_manifest(bytes, size, result, bindings_out) != 0) {
        memset(bindings_out, 0, sizeof(*bindings_out));
        return -1;
    }
    return 0;
}

static int
read_manifest_fd(int fd, uid_t owner, uint8_t **bytes_out, size_t *size_out)
{
    struct stat identity;
    struct stat after;
    uint8_t *bytes;
    size_t size;
    size_t offset = 0U;
    if (fstat(fd, &identity) != 0 || !S_ISREG(identity.st_mode)
            || identity.st_uid != owner || identity.st_nlink != 1
            || (identity.st_mode & 07777U) != 0400U || identity.st_size < 0
            || (uint64_t)identity.st_size > (uint64_t)MANIFEST_FIXED_SIZE
                + (uint64_t)PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES
                    * PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE) {
        errno = EINVAL;
        return -1;
    }
    size = (size_t)identity.st_size;
    bytes = malloc(size == 0U ? 1U : size);
    if (bytes == NULL)
        return -1;
    while (offset < size) {
        ssize_t amount = pread(fd, bytes + offset, size - offset, (off_t)offset);
        if (amount <= 0) {
            free(bytes);
            errno = amount == 0 ? EIO : errno;
            return -1;
        }
        offset += (size_t)amount;
    }
    if (fstat(fd, &after) != 0 || !stat_equal(&identity, &after)) {
        free(bytes);
        errno = EBUSY;
        return -1;
    }
    *bytes_out = bytes;
    *size_out = size;
    return 0;
}

int
plamen_runtime_package_manifest_revalidate_v2(int runtime_root_fd,
    int manifest_fd, uid_t owner_uid,
    struct plamen_runtime_package_manifest_result_v2 *result)
{
    uint8_t *observed = NULL;
    size_t observed_size = 0U;
    struct plamen_runtime_package_bindings_v2 bindings;
    struct runtime_census census;
    uint8_t *expected = NULL;
    size_t expected_size = 0U;
    struct plamen_runtime_package_manifest_result_v2 expected_result;
    int rc = -1;
    if (runtime_root_fd < 0 || manifest_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (read_manifest_fd(manifest_fd, owner_uid, &observed, &observed_size) != 0
            || validate_manifest(observed, observed_size, NULL, &bindings) != 0)
        goto out;
    if (census_runtime(runtime_root_fd, owner_uid, &census) != 0)
        goto out;
    if (encode_manifest(&census, &bindings, &expected, &expected_size,
            &expected_result) != 0) {
        free(census.rows);
        goto out;
    }
    free(census.rows);
    if (observed_size != expected_size
            || memcmp(observed, expected, expected_size) != 0) {
        errno = EINVAL;
        goto out;
    }
    if (result != NULL)
        *result = expected_result;
    rc = 0;

out:
    free(observed);
    free(expected);
    return rc;
}

struct receipt_file_identity_v2 {
    struct stat stat;
    uint8_t sha256[32];
};

static int
receipt_identity_text(const char *text, size_t size, int permit_empty)
{
    size_t index;
    if (text == NULL || size > 128U || (!permit_empty && size == 0U))
        return 0;
    for (index = 0U; index < size; ++index) {
        unsigned char value = (unsigned char)text[index];
        if (!((value >= 'A' && value <= 'Z')
                || (value >= 'a' && value <= 'z')
                || (value >= '0' && value <= '9')
                || value == '.' || value == '-'))
            return 0;
    }
    return 1;
}

static int
receipt_absolute_path(const char *path, size_t size)
{
    size_t index;
    size_t component_start;
    if (path == NULL || size < 2U || size > 1024U || path[0] != '/')
        return 0;
    component_start = 1U;
    for (index = 1U; index <= size; ++index) {
        if (index == size || path[index] == '/') {
            size_t component_size = index - component_start;
            if (component_size == 0U
                    || (component_size == 1U && path[component_start] == '.')
                    || (component_size == 2U && path[component_start] == '.'
                        && path[component_start + 1U] == '.'))
                return 0;
            component_start = index + 1U;
        } else {
            unsigned char value = (unsigned char)path[index];
            if (value < 0x21U || value > 0x7eU || value == '\\')
                return 0;
        }
    }
    return 1;
}

static int
observe_receipt_file(int fd, uid_t owner, uint32_t mode,
    struct receipt_file_identity_v2 *identity)
{
    struct stat after;
    if (fd < 0 || identity == NULL || fstat(fd, &identity->stat) != 0
            || !S_ISREG(identity->stat.st_mode)
            || identity->stat.st_uid != owner || identity->stat.st_nlink != 1
            || identity->stat.st_size <= 0
            || (identity->stat.st_mode & 07777U) != mode
            || (uint64_t)identity->stat.st_dev == 0U
            || (uint64_t)identity->stat.st_ino == 0U
            || (uint64_t)identity->stat.st_uid > UINT32_MAX
            || (uint64_t)identity->stat.st_gid > UINT32_MAX
            || hash_regular_fd(fd, (uint64_t)identity->stat.st_size,
                identity->sha256) != 0
            || fstat(fd, &after) != 0
            || !stat_equal(&identity->stat, &after)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int
receipt_signing_is_exact(size_t index,
    const struct plamen_darwin_code_identity_v2 *identity)
{
    static const char *const fixed_identifiers[5] = {
        "com.plamen.audit.launcher.v2",
        "com.plamen.audit.broker.v2",
        "com.plamen.audit.native-supervisor.v2",
        "com.plamen.audit.installer.v2",
        "com.plamen.audit.source-bootstrap.v1"
    };
    int signed_member = index < 3U || index == 5U || index == 8U
        || index == 9U;
    if (identity == NULL
            || !receipt_identity_text(identity->signing_identifier,
                identity->signing_identifier_size, !signed_member)
            || !receipt_identity_text(identity->team_identifier,
                identity->team_identifier_size, 1))
        return 0;
    if (!signed_member)
        return identity->signing_identifier_size == 0U
            && identity->team_identifier_size == 0U
            && identity->cdhash_size == 0U
            && all_zero(identity->cdhash, sizeof(identity->cdhash));
    if (identity->cdhash_size != 20U && identity->cdhash_size != 32U)
        return 0;
    if (index < 3U || index == 8U || index == 9U) {
        size_t fixed_index = index == 8U ? 3U : index == 9U ? 4U : index;
        size_t fixed_size = strlen(fixed_identifiers[fixed_index]);
        return identity->signing_identifier_size == fixed_size
            && memcmp(identity->signing_identifier,
                fixed_identifiers[fixed_index],
                fixed_size) == 0
            && identity->team_identifier_size == 0U;
    }
    return identity->signing_identifier_size != 0U;
}

static int
receipt_code_identity_sha256(
    const struct plamen_darwin_code_identity_v2 *identity,
    uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-INSTALL-CODE-IDENTITY-V1\0";
    uint8_t preimage[sizeof(domain) + 6U + 128U + 128U + 32U];
    size_t offset = 0U;
    if (identity == NULL || output == NULL
            || identity->signing_identifier_size > 128U
            || identity->team_identifier_size > 128U
            || identity->cdhash_size > 32U)
        return -1;
    memset(preimage, 0, sizeof(preimage));
    memcpy(preimage + offset, domain, sizeof(domain));
    offset += sizeof(domain);
    store_u16(preimage + offset,
        (uint16_t)identity->signing_identifier_size); offset += 2U;
    store_u16(preimage + offset,
        (uint16_t)identity->team_identifier_size); offset += 2U;
    store_u16(preimage + offset, identity->cdhash_size); offset += 2U;
    memcpy(preimage + offset, identity->signing_identifier,
        identity->signing_identifier_size);
    offset += identity->signing_identifier_size;
    memcpy(preimage + offset, identity->team_identifier,
        identity->team_identifier_size);
    offset += identity->team_identifier_size;
    memcpy(preimage + offset, identity->cdhash, identity->cdhash_size);
    offset += identity->cdhash_size;
    sha256_bytes(preimage, offset, output);
    memset(preimage, 0, sizeof(preimage));
    return digest_nonzero(output) ? 0 : -1;
}

static int
receipt_output_is_candidate(int fd, uid_t owner, struct stat *identity)
{
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0
        && fstat(fd, identity) == 0 && S_ISREG(identity->st_mode)
        && identity->st_uid == owner && identity->st_nlink == 1
        && identity->st_size >= 0
        && (((identity->st_mode & 07777U) == 0600U
                && (flags & O_ACCMODE) == O_RDWR)
            || ((identity->st_mode & 07777U) == 0400U
                && identity->st_size
                    == (off_t)PLAMEN_DARWIN_INSTALL_RECEIPT_SIZE_V2
                && (flags & O_ACCMODE) == O_RDONLY));
}

int
plamen_darwin_install_receipt_encode_v2(
    const struct plamen_darwin_install_receipt_request_v2 *request,
    int output_fd, uid_t owner_uid,
    struct plamen_darwin_install_receipt_result_v2 *result)
{
    static const uint8_t magic[8] = {
        'P', 'L', 'M', 'I', 'N', 'S', '2', 0
    };
    static const char abi[] = "cpython-312-darwin";
    static const char broker_plist_suffix[] =
        "/Library/LaunchAgents/com.plamen.audit.broker.v2.plist";
    static const char custody_plist_suffix[] =
        "/Library/LaunchAgents/com.plamen.audit.process-custody.v2.plist";
    static const char precommit_domain[] = "PLAMEN-INSTALL-PRECOMMIT-V2";
    struct receipt_file_identity_v2 member_identities[
        PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2];
    struct receipt_file_identity_v2 broker_plist_identity;
    struct receipt_file_identity_v2 custody_plist_identity;
    struct receipt_file_identity_v2 specialized_identity;
    struct receipt_file_identity_v2 source_bootstrap_identity;
    struct receipt_file_identity_v2 source_bootstrap_verifier_identity;
    struct plamen_intrinsic_generation_member_v2 generation_members[
        PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2];
    struct stat output_before;
    uint8_t *record = NULL;
    uint8_t generation_id[32];
    uint8_t roster_sha256[32];
    uint8_t generation_hex[64];
    uint8_t precommit[32];
    uint8_t trailer[32];
    uint8_t full_digest[32];
    uint8_t source_bootstrap_acquisition_roster_sha256[32];
    uint8_t source_bootstrap_producer_verifier_key_sha256[32];
    uint8_t source_bootstrap_code_identity_sha256[32];
    uint8_t source_bootstrap_installed_authority_roster_sha256[32];
    struct sha256_context checkpoint;
    size_t index;
    int rc = -1;
    static const char hex[] = "0123456789abcdef";

    if (result != NULL)
        memset(result, 0, sizeof(*result));
    if (request == NULL || output_fd < 0 || request->python_micro == 0U
            || !digest_nonzero(request->projection_schema_sha256)
            || !digest_nonzero(request->protocol_schema_sha256)
            || !receipt_absolute_path(request->generation_absolute_path,
                request->generation_absolute_path_size)
            || !receipt_absolute_path(
                request->broker_launchd_plist.absolute_path,
                request->broker_launchd_plist.absolute_path_size)
            || !receipt_absolute_path(
                request->custody_launchd_plist.absolute_path,
                request->custody_launchd_plist.absolute_path_size)
            || request->broker_launchd_plist.absolute_path_size
                != request->generation_absolute_path_size
                    + sizeof(broker_plist_suffix) - 1U
            || request->custody_launchd_plist.absolute_path_size
                != request->generation_absolute_path_size
                    + sizeof(custody_plist_suffix) - 1U
            || memcmp(request->broker_launchd_plist.absolute_path,
                request->generation_absolute_path,
                request->generation_absolute_path_size) != 0
            || memcmp(request->custody_launchd_plist.absolute_path,
                request->generation_absolute_path,
                request->generation_absolute_path_size) != 0
            || memcmp(request->broker_launchd_plist.absolute_path
                    + request->generation_absolute_path_size,
                broker_plist_suffix, sizeof(broker_plist_suffix) - 1U) != 0
            || memcmp(request->custody_launchd_plist.absolute_path
                    + request->generation_absolute_path_size,
                custody_plist_suffix, sizeof(custody_plist_suffix) - 1U) != 0
            || !receipt_output_is_candidate(output_fd, owner_uid,
                &output_before)) {
        errno = EINVAL;
        return -1;
    }
    memset(member_identities, 0, sizeof(member_identities));
    memset(&specialized_identity, 0, sizeof(specialized_identity));
    memset(&source_bootstrap_identity, 0,
        sizeof(source_bootstrap_identity));
    memset(&source_bootstrap_verifier_identity, 0,
        sizeof(source_bootstrap_verifier_identity));
    memset(source_bootstrap_acquisition_roster_sha256, 0,
        sizeof(source_bootstrap_acquisition_roster_sha256));
    memset(source_bootstrap_producer_verifier_key_sha256, 0,
        sizeof(source_bootstrap_producer_verifier_key_sha256));
    memset(source_bootstrap_code_identity_sha256, 0,
        sizeof(source_bootstrap_code_identity_sha256));
    memset(source_bootstrap_installed_authority_roster_sha256, 0,
        sizeof(source_bootstrap_installed_authority_roster_sha256));
    memset(generation_members, 0, sizeof(generation_members));
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
        const struct plamen_darwin_install_member_input_v2 *input =
            &request->members[index];
        if (!receipt_signing_is_exact(index, &input->code_identity)
                || observe_receipt_file(input->fd, owner_uid,
                    intrinsic_generation_modes[index],
                    &member_identities[index]) != 0)
            goto out;
        generation_members[index].role = (uint16_t)(index + 1U);
        generation_members[index].relative_path =
            intrinsic_generation_paths[index];
        generation_members[index].relative_path_size =
            strlen(intrinsic_generation_paths[index]);
        generation_members[index].mode = intrinsic_generation_modes[index];
        generation_members[index].size =
            (uint64_t)member_identities[index].stat.st_size;
        memcpy(generation_members[index].sha256,
            member_identities[index].sha256, 32U);
    }
    if (observe_receipt_file(request->broker_launchd_plist.fd, owner_uid,
            0400U, &broker_plist_identity) != 0
            || observe_receipt_file(request->custody_launchd_plist.fd,
                owner_uid, 0400U, &custody_plist_identity) != 0
            || plamen_intrinsic_generation_id_and_roster_v2(
                generation_members, generation_id, roster_sha256) != 0)
        goto out;
    if (request->specialized_present > 1U
            || (request->specialized_present == 1U
                && observe_receipt_file(
                    request->specialized_member_receipt_fd,
                    owner_uid, 0400U, &specialized_identity) != 0)) {
        errno = EINVAL;
        goto out;
    }
    if (request->source_bootstrap_present > 1U
            || (request->source_bootstrap_present == 1U
                && (request->source_bootstrap_receipt_validate == NULL
                    || fcntl(request->source_bootstrap_receipt_fd, F_GETFL) < 0
                    || (fcntl(request->source_bootstrap_receipt_fd, F_GETFL)
                        & O_ACCMODE) != O_RDONLY
                    || fcntl(request->source_bootstrap_producer_verifier_key_fd,
                        F_GETFL) < 0
                    || (fcntl(
                        request->source_bootstrap_producer_verifier_key_fd,
                        F_GETFL) & O_ACCMODE) != O_RDONLY
                    || observe_receipt_file(
                        request->source_bootstrap_receipt_fd,
                        owner_uid, 0400U, &source_bootstrap_identity) != 0
                    || source_bootstrap_identity.stat.st_size != 8192
                    || observe_receipt_file(
                        request->source_bootstrap_producer_verifier_key_fd,
                        owner_uid, 0400U,
                        &source_bootstrap_verifier_identity) != 0
                    || source_bootstrap_verifier_identity.stat.st_size != 32
                    || request->source_bootstrap_receipt_validate(
                        request->source_bootstrap_receipt_context,
                        request->source_bootstrap_receipt_fd, owner_uid,
                        source_bootstrap_acquisition_roster_sha256,
                        source_bootstrap_producer_verifier_key_sha256,
                        source_bootstrap_installed_authority_roster_sha256) != 0
                    || !digest_nonzero(
                        source_bootstrap_acquisition_roster_sha256)
                    || memcmp(source_bootstrap_producer_verifier_key_sha256,
                        source_bootstrap_verifier_identity.sha256, 32U) != 0
                    || !digest_nonzero(
                        source_bootstrap_installed_authority_roster_sha256)
                    || receipt_code_identity_sha256(
                        &request->members[9].code_identity,
                        source_bootstrap_code_identity_sha256) != 0))) {
        errno = EINVAL;
        goto out;
    }
    if (request->specialized_present == 1U) {
        for (index = 0U;
                index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
            if (specialized_identity.stat.st_dev
                    == member_identities[index].stat.st_dev
                && specialized_identity.stat.st_ino
                    == member_identities[index].stat.st_ino) {
                errno = EINVAL;
                goto out;
            }
        }
        if ((specialized_identity.stat.st_dev
                    == broker_plist_identity.stat.st_dev
                && specialized_identity.stat.st_ino
                    == broker_plist_identity.stat.st_ino)
            || (specialized_identity.stat.st_dev
                    == custody_plist_identity.stat.st_dev
                && specialized_identity.stat.st_ino
                    == custody_plist_identity.stat.st_ino)) {
            errno = EINVAL;
            goto out;
        }
    }
    if (request->source_bootstrap_present == 1U) {
        for (index = 0U;
                index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
            if (source_bootstrap_identity.stat.st_dev
                    == member_identities[index].stat.st_dev
                && source_bootstrap_identity.stat.st_ino
                    == member_identities[index].stat.st_ino) {
                errno = EINVAL;
                goto out;
            }
        }
        if ((request->specialized_present == 1U
                && source_bootstrap_identity.stat.st_dev
                    == specialized_identity.stat.st_dev
                && source_bootstrap_identity.stat.st_ino
                    == specialized_identity.stat.st_ino)
            || (source_bootstrap_identity.stat.st_dev
                    == broker_plist_identity.stat.st_dev
                && source_bootstrap_identity.stat.st_ino
                    == broker_plist_identity.stat.st_ino)
            || (source_bootstrap_identity.stat.st_dev
                    == custody_plist_identity.stat.st_dev
                && source_bootstrap_identity.stat.st_ino
                    == custody_plist_identity.stat.st_ino)) {
            errno = EINVAL;
            goto out;
        }
    }
    for (index = 0U; index < 32U; ++index) {
        generation_hex[index * 2U] = (uint8_t)hex[generation_id[index] >> 4];
        generation_hex[index * 2U + 1U] =
            (uint8_t)hex[generation_id[index] & 0x0fU];
    }
    if (request->generation_absolute_path_size < 65U
            || request->generation_absolute_path[
                request->generation_absolute_path_size - 65U] != '/'
            || memcmp(request->generation_absolute_path
                    + request->generation_absolute_path_size - 64U,
                generation_hex, sizeof(generation_hex)) != 0) {
        errno = EINVAL;
        goto out;
    }
    record = calloc(1U, PLAMEN_DARWIN_INSTALL_RECEIPT_SIZE_V2);
    if (record == NULL)
        goto out;
    memcpy(record, magic, sizeof(magic));
    store_u16(record + 8U, 2U);
    store_u16(record + 10U, 256U);
    store_u32(record + 12U, PLAMEN_DARWIN_INSTALL_RECEIPT_SIZE_V2);
    memcpy(record + 16U, generation_id, 32U);
    memcpy(record + 48U, roster_sha256, 32U);
    store_u16(record + 112U, PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2);
    store_u16(record + 114U, 3U);
    store_u16(record + 116U, 12U);
    store_u16(record + 118U, request->python_micro);
    store_u16(record + 120U, (uint16_t)(sizeof(abi) - 1U));
    store_u16(record + 122U,
        (uint16_t)request->generation_absolute_path_size);
    store_u16(record + 124U,
        (uint16_t)request->broker_launchd_plist.absolute_path_size);
    store_u16(record + 126U,
        (uint16_t)request->custody_launchd_plist.absolute_path_size);
    memcpy(record + 128U, request->projection_schema_sha256, 32U);
    memcpy(record + 160U, request->protocol_schema_sha256, 32U);
    if (request->specialized_present == 1U) {
        static const uint8_t specialized_magic[8] = {
            'P', 'L', 'M', 'I', 'R', 'A', '1', 0
        };
        static const char specialized_path[] =
            PLAMEN_RUNTIME_PACKAGE_SPECIALIZED_RECEIPT_PATH_V2;
        uint8_t *specialized = record + 12608U;
        store_u32(record + 192U, load_u32(record + 192U) | 1U);
        memcpy(specialized, specialized_magic, sizeof(specialized_magic));
        store_u16(specialized + 8U, 1U);
        store_u16(specialized + 10U, 512U);
        store_u32(specialized + 12U, 1U);
        store_u16(specialized + 16U,
            (uint16_t)(sizeof(specialized_path) - 1U));
        memcpy(specialized + 24U, member_identities[7].sha256, 32U);
        memcpy(specialized + 56U, specialized_identity.sha256, 32U);
        store_u64(specialized + 88U,
            (uint64_t)specialized_identity.stat.st_size);
        store_u64(specialized + 96U,
            (uint64_t)specialized_identity.stat.st_dev);
        store_u64(specialized + 104U,
            (uint64_t)specialized_identity.stat.st_ino);
        store_u32(specialized + 112U, 0400U);
        store_u32(specialized + 116U,
            (uint32_t)specialized_identity.stat.st_uid);
        store_u32(specialized + 120U,
            (uint32_t)specialized_identity.stat.st_gid);
        memcpy(specialized + 128U, specialized_path,
            sizeof(specialized_path) - 1U);
    }
    memcpy(record + 256U, abi, sizeof(abi) - 1U);
    memcpy(record + 320U, request->generation_absolute_path,
        request->generation_absolute_path_size);
    memcpy(record + 1344U, request->broker_launchd_plist.absolute_path,
        request->broker_launchd_plist.absolute_path_size);
    memcpy(record + 2368U, broker_plist_identity.sha256, 32U);
    store_u64(record + 2400U,
        (uint64_t)broker_plist_identity.stat.st_size);
    store_u64(record + 2408U,
        (uint64_t)broker_plist_identity.stat.st_dev);
    store_u64(record + 2416U,
        (uint64_t)broker_plist_identity.stat.st_ino);
    store_u32(record + 2424U, 0400U);
    store_u32(record + 2428U,
        (uint32_t)broker_plist_identity.stat.st_uid);
    store_u32(record + 2432U,
        (uint32_t)broker_plist_identity.stat.st_gid);
    memcpy(record + 11456U, request->custody_launchd_plist.absolute_path,
        request->custody_launchd_plist.absolute_path_size);
    memcpy(record + 12480U, custody_plist_identity.sha256, 32U);
    store_u64(record + 12512U,
        (uint64_t)custody_plist_identity.stat.st_size);
    store_u64(record + 12520U,
        (uint64_t)custody_plist_identity.stat.st_dev);
    store_u64(record + 12528U,
        (uint64_t)custody_plist_identity.stat.st_ino);
    store_u32(record + 12536U, 0400U);
    store_u32(record + 12540U,
        (uint32_t)custody_plist_identity.stat.st_uid);
    store_u32(record + 12544U,
        (uint32_t)custody_plist_identity.stat.st_gid);
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
        const struct plamen_darwin_code_identity_v2 *code =
            &request->members[index].code_identity;
        const struct receipt_file_identity_v2 *identity =
            &member_identities[index];
        size_t path_size = strlen(intrinsic_generation_paths[index]);
        uint8_t *row = record + 2496U + index * 896U;
        store_u16(row, (uint16_t)(index + 1U));
        store_u16(row + 2U, (uint16_t)path_size);
        store_u16(row + 4U, (uint16_t)code->signing_identifier_size);
        store_u16(row + 6U, (uint16_t)code->team_identifier_size);
        store_u16(row + 8U, code->cdhash_size);
        store_u32(row + 12U, intrinsic_generation_modes[index]);
        store_u64(row + 16U, (uint64_t)identity->stat.st_size);
        store_u64(row + 24U, (uint64_t)identity->stat.st_dev);
        store_u64(row + 32U, (uint64_t)identity->stat.st_ino);
        store_u32(row + 40U, (uint32_t)identity->stat.st_uid);
        store_u32(row + 44U, (uint32_t)identity->stat.st_gid);
        memcpy(row + 48U, identity->sha256, 32U);
        memcpy(row + 80U, code->cdhash, code->cdhash_size);
        memcpy(row + 112U, intrinsic_generation_paths[index], path_size);
        memcpy(row + 368U, code->signing_identifier,
            code->signing_identifier_size);
        memcpy(row + 496U, code->team_identifier, code->team_identifier_size);
    }
    if (request->source_bootstrap_present == 1U) {
        static const uint8_t source_bootstrap_magic[8] = {
            'P', 'L', 'M', 'S', 'B', 'A', '1', 0
        };
        static const char source_bootstrap_path[] =
            "share/plamen/native-source-bootstrap-coordinator-receipt-v1.bin";
        uint8_t member_identity_sha256[32];
        uint8_t *source = record + 13120U;
        uint8_t *member = record + 2496U + 9U * 896U;
        sha256_bytes(member, 896U, member_identity_sha256);
        store_u32(record + 192U, load_u32(record + 192U) | 2U);
        memcpy(source, source_bootstrap_magic, sizeof(source_bootstrap_magic));
        store_u16(source + 8U, 1U);
        store_u16(source + 10U, 512U);
        store_u32(source + 12U, 1U);
        store_u16(source + 16U,
            (uint16_t)(sizeof(source_bootstrap_path) - 1U));
        memcpy(source + 24U,
            source_bootstrap_acquisition_roster_sha256, 32U);
        memcpy(source + 56U, member_identity_sha256, 32U);
        memcpy(source + 88U,
            source_bootstrap_code_identity_sha256, 32U);
        memcpy(source + 120U, source_bootstrap_identity.sha256, 32U);
        store_u64(source + 152U,
            (uint64_t)source_bootstrap_identity.stat.st_size);
        store_u64(source + 160U,
            (uint64_t)source_bootstrap_identity.stat.st_dev);
        store_u64(source + 168U,
            (uint64_t)source_bootstrap_identity.stat.st_ino);
        store_u32(source + 176U, 0400U);
        store_u32(source + 180U,
            (uint32_t)source_bootstrap_identity.stat.st_uid);
        store_u32(source + 184U,
            (uint32_t)source_bootstrap_identity.stat.st_gid);
        memcpy(source + 192U, source_bootstrap_path,
            sizeof(source_bootstrap_path) - 1U);
        memcpy(source + 448U,
            source_bootstrap_producer_verifier_key_sha256, 32U);
        memcpy(source + 480U,
            source_bootstrap_installed_authority_roster_sha256, 32U);
        memset(member_identity_sha256, 0, sizeof(member_identity_sha256));
    }
    sha256_init(&checkpoint);
    sha256_update(&checkpoint, (const uint8_t *)precommit_domain,
        sizeof(precommit_domain));
    sha256_update(&checkpoint, record,
        PLAMEN_DARWIN_INSTALL_RECEIPT_HASHED_SIZE_V2);
    sha256_final(&checkpoint, precommit);
    memcpy(record + 80U, precommit, 32U);
    sha256_bytes(record, PLAMEN_DARWIN_INSTALL_RECEIPT_HASHED_SIZE_V2,
        trailer);
    memcpy(record + PLAMEN_DARWIN_INSTALL_RECEIPT_HASHED_SIZE_V2,
        trailer, 32U);
    sha256_bytes(record, PLAMEN_DARWIN_INSTALL_RECEIPT_SIZE_V2, full_digest);
    if (complete_exact_candidate(output_fd, record,
            PLAMEN_DARWIN_INSTALL_RECEIPT_SIZE_V2, owner_uid,
            &output_before, 0400U) != 0) {
        goto out;
    }
    if (result != NULL) {
        memcpy(result->generation_id, generation_id, 32U);
        memcpy(result->intrinsic_roster_sha256, roster_sha256, 32U);
        memcpy(result->install_precommit_sha256, precommit, 32U);
        memcpy(result->receipt_hashed_prefix_sha256, trailer, 32U);
        memcpy(result->full_receipt_sha256, full_digest, 32U);
    }
    rc = 0;

out:
    free(record);
    memset(member_identities, 0, sizeof(member_identities));
    memset(&broker_plist_identity, 0, sizeof(broker_plist_identity));
    memset(&custody_plist_identity, 0, sizeof(custody_plist_identity));
    memset(&specialized_identity, 0, sizeof(specialized_identity));
    memset(&source_bootstrap_identity, 0,
        sizeof(source_bootstrap_identity));
    memset(&source_bootstrap_verifier_identity, 0,
        sizeof(source_bootstrap_verifier_identity));
    memset(generation_members, 0, sizeof(generation_members));
    memset(generation_id, 0, sizeof(generation_id));
    memset(roster_sha256, 0, sizeof(roster_sha256));
    memset(generation_hex, 0, sizeof(generation_hex));
    memset(precommit, 0, sizeof(precommit));
    memset(trailer, 0, sizeof(trailer));
    memset(full_digest, 0, sizeof(full_digest));
    memset(source_bootstrap_acquisition_roster_sha256, 0,
        sizeof(source_bootstrap_acquisition_roster_sha256));
    memset(source_bootstrap_producer_verifier_key_sha256, 0,
        sizeof(source_bootstrap_producer_verifier_key_sha256));
    memset(source_bootstrap_code_identity_sha256, 0,
        sizeof(source_bootstrap_code_identity_sha256));
    memset(source_bootstrap_installed_authority_roster_sha256, 0,
        sizeof(source_bootstrap_installed_authority_roster_sha256));
    return rc;
}

static int
stage_make_directory(int parent_fd, const char *name, uid_t owner,
    int *directory_fd)
{
    struct stat named;
    struct stat opened;
    int fd = -1;
    int saved;

    if (!ascii_component(name) || directory_fd == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mkdirat(parent_fd, name, 0700U) != 0)
        return -1;
    fd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC
        | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &opened) != 0
            || fstatat(parent_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0
            || !stat_equal(&opened, &named) || !S_ISDIR(opened.st_mode)
            || opened.st_uid != owner
            || (opened.st_mode & 07777U) != 0700U) {
        saved = errno == 0 ? EINVAL : errno;
        if (fd >= 0)
            (void)close(fd);
        (void)unlinkat(parent_fd, name, AT_REMOVEDIR);
        errno = saved;
        return -1;
    }
    *directory_fd = fd;
    return 0;
}

static int
stage_copy_regular(int source_fd, int destination_directory_fd,
    const char *name, uint32_t mode, uid_t owner, int *retained_fd)
{
    struct stat source_before;
    struct stat source_after;
    struct stat output_stat;
    struct stat named_stat;
    uint8_t source_digest[32];
    uint8_t source_digest_after[32];
    uint8_t output_digest[32];
    uint8_t buffer[32768];
    uint64_t offset = 0U;
    int output = -1;
    int retained = -1;
    int saved = 0;

    memset(source_digest, 0, sizeof(source_digest));
    memset(source_digest_after, 0, sizeof(source_digest_after));
    memset(output_digest, 0, sizeof(output_digest));
    memset(buffer, 0, sizeof(buffer));
    if (source_fd < 0 || !ascii_component(name)
            || (mode != 0400U && mode != 0500U) || retained_fd == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (fstat(source_fd, &source_before) != 0)
        return -1;
    if (!S_ISREG(source_before.st_mode) || source_before.st_size < 0
            || source_before.st_nlink < 1
            || (uint64_t)source_before.st_size
                > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_TOTAL_BYTES) {
        errno = EINVAL;
        return -1;
    }
    if (hash_regular_fd(source_fd, (uint64_t)source_before.st_size,
            source_digest) != 0)
        return -1;
    *retained_fd = -1;
    output = openat(destination_directory_fd, name,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600U);
    if (output < 0) {
        saved = errno;
        goto out;
    }
    while (offset < (uint64_t)source_before.st_size) {
        size_t wanted = ((uint64_t)source_before.st_size - offset)
                < sizeof(buffer)
            ? (size_t)((uint64_t)source_before.st_size - offset)
            : sizeof(buffer);
        ssize_t amount = pread(source_fd, buffer, wanted, (off_t)offset);
        size_t written = 0U;
        if (amount <= 0) {
            saved = amount == 0 ? EIO : errno;
            goto out;
        }
        while (written < (size_t)amount) {
            ssize_t put = write(output, buffer + written,
                (size_t)amount - written);
            if (put <= 0) {
                saved = put == 0 ? EIO : errno;
                goto out;
            }
            written += (size_t)put;
        }
        offset += (uint64_t)amount;
    }
    if (fsync(output) != 0 || fchmod(output, mode) != 0
            || fsync(output) != 0) {
        saved = errno;
        goto out;
    }
    retained = openat(destination_directory_fd, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (retained < 0) {
        saved = errno;
        goto out;
    }
    if (fstat(retained, &output_stat) != 0
            || fstatat(destination_directory_fd, name, &named_stat,
                AT_SYMLINK_NOFOLLOW) != 0) {
        saved = errno;
        goto out;
    }
    if (!stat_equal(&output_stat, &named_stat)
            || !S_ISREG(output_stat.st_mode) || output_stat.st_uid != owner
            || output_stat.st_nlink != 1
            || (output_stat.st_mode & 07777U) != mode
            || output_stat.st_size != source_before.st_size) {
        saved = EBUSY;
        goto out;
    }
    if (hash_regular_fd(retained, (uint64_t)output_stat.st_size,
            output_digest) != 0) {
        saved = errno;
        goto out;
    }
    if (memcmp(source_digest, output_digest, 32U) != 0) {
        saved = EBUSY;
        goto out;
    }
    if (fstat(source_fd, &source_after) != 0) {
        saved = errno;
        goto out;
    }
    if (!stat_equal(&source_before, &source_after)) {
        saved = EBUSY;
        goto out;
    }
    if (hash_regular_fd(source_fd, (uint64_t)source_after.st_size,
            source_digest_after) != 0) {
        saved = errno;
        goto out;
    }
    if (memcmp(source_digest, source_digest_after, 32U) != 0) {
        saved = EBUSY;
        goto out;
    }
    if (close(output) != 0) {
        saved = errno;
        output = -1;
        goto out;
    }
    output = -1;
    *retained_fd = retained;
    retained = -1;

out:
    if (retained >= 0)
        (void)close(retained);
    if (output >= 0)
        (void)close(output);
    if (*retained_fd < 0)
        (void)unlinkat(destination_directory_fd, name, 0);
    memset(source_digest, 0, sizeof(source_digest));
    memset(source_digest_after, 0, sizeof(source_digest_after));
    memset(output_digest, 0, sizeof(output_digest));
    memset(buffer, 0, sizeof(buffer));
    if (*retained_fd >= 0)
        return 0;
    errno = saved == 0 ? EIO : saved;
    return -1;
}

static int
stage_copy_runtime_directory(int source_fd, int destination_fd, uid_t owner)
{
    struct name_list before;
    struct name_list after;
    size_t index;
    int saved = 0;

    memset(&before, 0, sizeof(before));
    memset(&after, 0, sizeof(after));
    if (read_names(source_fd, &before) != 0)
        return -1;
    for (index = 0U; index < before.count; ++index) {
        const char *name = before.items[index];
        struct stat named_before;
        struct stat opened_before;
        struct stat opened_after;
        struct stat named_after;
        int input = -1;
        int output = -1;

        if (fstatat(source_fd, name, &named_before, AT_SYMLINK_NOFOLLOW) != 0) {
            saved = errno;
            goto fail;
        }
        if (S_ISDIR(named_before.st_mode)) {
            input = openat(source_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC
                | O_NOFOLLOW);
            if (input < 0) {
                saved = errno;
                goto entry_fail;
            }
            if (fstat(input, &opened_before) != 0) {
                saved = errno;
                goto entry_fail;
            }
            if (!stat_equal(&named_before, &opened_before)
                    || opened_before.st_uid != owner
                    || (opened_before.st_mode & 07777U) != 0500U) {
                saved = EINVAL;
                goto entry_fail;
            }
            if (stage_make_directory(destination_fd, name, owner,
                    &output) != 0
                    || stage_copy_runtime_directory(input, output, owner) != 0
                    || fchmod(output, 0500U) != 0 || fsync(output) != 0) {
                saved = errno;
                goto entry_fail;
            }
        } else if (S_ISREG(named_before.st_mode)) {
            input = openat(source_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (input < 0) {
                saved = errno;
                goto entry_fail;
            }
            if (fstat(input, &opened_before) != 0) {
                saved = errno;
                goto entry_fail;
            }
            if (!stat_equal(&named_before, &opened_before)
                    || opened_before.st_uid != owner
                    || (opened_before.st_mode & 07777U) != 0400U
                    || opened_before.st_nlink != 1) {
                saved = EINVAL;
                goto entry_fail;
            }
            if (stage_copy_regular(input, destination_fd, name, 0400U,
                    owner, &output) != 0) {
                saved = errno;
                goto entry_fail;
            }
        } else {
            saved = EINVAL;
            goto entry_fail;
        }
        if (fstat(input, &opened_after) != 0
                || fstatat(source_fd, name, &named_after,
                    AT_SYMLINK_NOFOLLOW) != 0
                || !stat_equal(&opened_before, &opened_after)
                || !stat_equal(&opened_after, &named_after)) {
            saved = EBUSY;
            goto entry_fail;
        }
        if (close(output) != 0) {
            saved = errno;
            (void)close(input);
            goto fail;
        }
        if (close(input) != 0) {
            saved = errno;
            goto fail;
        }
        continue;

entry_fail:
        if (output >= 0)
            (void)close(output);
        if (input >= 0)
            (void)close(input);
        goto fail;
    }
    if (read_names(source_fd, &after) != 0) {
        saved = errno;
        goto fail;
    }
    if (!same_name_lists(&before, &after)) {
        saved = EBUSY;
        goto fail;
    }
    name_list_dispose(&before);
    name_list_dispose(&after);
    return 0;

fail:
    name_list_dispose(&before);
    name_list_dispose(&after);
    errno = saved == 0 ? EINVAL : saved;
    return -1;
}

static int
stage_open_relative_regular(int root_fd, const char *path)
{
    char component[MAX_COMPONENT_BYTES + 1U];
    const char *cursor = path;
    int current = -1;
    int next = -1;

    if (path == NULL || path[0] == '\0' || path[0] == '/') {
        errno = EINVAL;
        return -1;
    }
    current = dup(root_fd);
    if (current < 0)
        return -1;
    for (;;) {
        const char *slash = strchr(cursor, '/');
        size_t size = slash == NULL ? strlen(cursor) : (size_t)(slash - cursor);
        if (size == 0U || size > MAX_COMPONENT_BYTES) {
            errno = EINVAL;
            goto fail;
        }
        memcpy(component, cursor, size);
        component[size] = '\0';
        if (!ascii_component(component)) {
            errno = EINVAL;
            goto fail;
        }
        if (slash == NULL) {
            next = openat(current, component, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (next < 0)
                goto fail;
            (void)close(current);
            return next;
        }
        next = openat(current, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC
            | O_NOFOLLOW);
        if (next < 0)
            goto fail;
        (void)close(current);
        current = next;
        next = -1;
        cursor = slash + 1;
    }

fail:
    if (next >= 0)
        (void)close(next);
    if (current >= 0)
        (void)close(current);
    return -1;
}

static int
stage_open_relative_directory(int root_fd, const char *path, uid_t owner)
{
    char component[MAX_COMPONENT_BYTES + 1U];
    const char *cursor = path;
    int current = -1;

    if (path == NULL || path[0] == '\0' || path[0] == '/') {
        errno = EINVAL;
        return -1;
    }
    current = dup(root_fd);
    if (current < 0)
        return -1;
    for (;;) {
        const char *slash = strchr(cursor, '/');
        size_t size = slash == NULL ? strlen(cursor) : (size_t)(slash - cursor);
        int next;
        struct stat information;
        if (size == 0U || size > MAX_COMPONENT_BYTES) {
            errno = EINVAL;
            goto fail;
        }
        memcpy(component, cursor, size);
        component[size] = '\0';
        if (!ascii_component(component)) {
            errno = EINVAL;
            goto fail;
        }
        next = openat(current, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC
            | O_NOFOLLOW);
        if (next < 0 || fstat(next, &information) != 0
                || !S_ISDIR(information.st_mode)
                || information.st_uid != owner
                || (information.st_mode & 07777U) != 0500U) {
            int saved = errno == 0 ? EINVAL : errno;
            if (next >= 0)
                (void)close(next);
            errno = saved;
            goto fail;
        }
        (void)close(current);
        current = next;
        if (slash == NULL)
            return current;
        cursor = slash + 1;
    }

fail:
    if (current >= 0)
        (void)close(current);
    return -1;
}

static int
stage_has_exact_names(int directory_fd, const char *const *expected,
    size_t expected_count)
{
    struct name_list names;
    size_t index, candidate;
    int result = -1;
    memset(&names, 0, sizeof(names));
    if (read_names(directory_fd, &names) != 0)
        goto done;
    if (names.count != expected_count) {
        errno = EINVAL;
        goto done;
    }
    for (index = 0U; index < names.count; ++index) {
        int found = 0;
        for (candidate = 0U; candidate < expected_count; ++candidate) {
            if (strcmp(names.items[index], expected[candidate]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            errno = EINVAL;
            goto done;
        }
    }
    result = 0;
done:
    name_list_dispose(&names);
    if (result != 0 && errno == 0)
        errno = EINVAL;
    return result;
}

static int
stage_regular_matches_source(int retained_fd, int source_fd, uid_t owner,
    uint32_t mode)
{
    struct stat retained_before, retained_after, source_before, source_after;
    uint8_t retained_sha256[32], source_sha256[32];
    int result = -1;
    memset(retained_sha256, 0, sizeof(retained_sha256));
    memset(source_sha256, 0, sizeof(source_sha256));
    if (retained_fd < 0 || source_fd < 0
            || (mode != 0400U && mode != 0500U)
            || fstat(retained_fd, &retained_before) != 0
            || fstat(source_fd, &source_before) != 0
            || !S_ISREG(retained_before.st_mode)
            || !S_ISREG(source_before.st_mode)
            || retained_before.st_uid != owner || retained_before.st_nlink != 1
            || source_before.st_nlink < 1
            || (retained_before.st_mode & 07777U) != mode
            || retained_before.st_size < 0
            || retained_before.st_size != source_before.st_size
            || (uint64_t)retained_before.st_size
                > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_TOTAL_BYTES
            || hash_regular_fd(retained_fd,
                (uint64_t)retained_before.st_size, retained_sha256) != 0
            || hash_regular_fd(source_fd,
                (uint64_t)source_before.st_size, source_sha256) != 0
            || memcmp(retained_sha256, source_sha256, 32U) != 0
            || fstat(retained_fd, &retained_after) != 0
            || fstat(source_fd, &source_after) != 0
            || !stat_equal(&retained_before, &retained_after)
            || !stat_equal(&source_before, &source_after)) {
        errno = errno == 0 ? EINVAL : errno;
        goto done;
    }
    result = 0;
done:
    memset(retained_sha256, 0, sizeof(retained_sha256));
    memset(source_sha256, 0, sizeof(source_sha256));
    return result;
}

static int
stage_remove_contents(int directory_fd)
{
    struct name_list names;
    size_t index;
    int saved = 0;

    memset(&names, 0, sizeof(names));
    (void)fchmod(directory_fd, 0700U);
    if (read_names(directory_fd, &names) != 0)
        return -1;
    for (index = 0U; index < names.count; ++index) {
        struct stat named;
        if (fstatat(directory_fd, names.items[index], &named,
                AT_SYMLINK_NOFOLLOW) != 0) {
            saved = errno;
            break;
        }
        if (S_ISDIR(named.st_mode)) {
            int child = openat(directory_fd, names.items[index],
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || stage_remove_contents(child) != 0) {
                saved = errno == 0 ? EIO : errno;
                if (child >= 0)
                    (void)close(child);
                break;
            }
            if (close(child) != 0) {
                saved = errno;
                break;
            }
            if (unlinkat(directory_fd, names.items[index],
                    AT_REMOVEDIR) != 0) {
                saved = errno;
                break;
            }
        } else if (S_ISREG(named.st_mode)) {
            if (unlinkat(directory_fd, names.items[index], 0) != 0) {
                saved = errno;
                break;
            }
        } else {
            saved = EINVAL;
            break;
        }
    }
    name_list_dispose(&names);
    if (saved != 0) {
        errno = saved;
        return -1;
    }
    return 0;
}

void
plamen_native_generation_stage_result_dispose_v2(
    struct plamen_native_generation_stage_result_v2 *result)
{
    size_t index;
    if (result == NULL)
        return;
    for (index = 0U; index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2;
            ++index) {
        if (result->generation_member_fds[index] >= 0)
            (void)close(result->generation_member_fds[index]);
    }
    if (result->specialized_authority_fd >= 0)
        (void)close(result->specialized_authority_fd);
    if (result->source_bootstrap_authority_fd >= 0)
        (void)close(result->source_bootstrap_authority_fd);
    if (result->runtime_root_fd >= 0)
        (void)close(result->runtime_root_fd);
    if (result->generation_root_fd >= 0)
        (void)close(result->generation_root_fd);
    memset(result, 0, sizeof(*result));
    result->generation_root_fd = -1;
    result->runtime_root_fd = -1;
    result->specialized_authority_fd = -1;
    result->source_bootstrap_authority_fd = -1;
    for (index = 0U; index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2;
            ++index)
        result->generation_member_fds[index] = -1;
}

int
plamen_intrinsic_generation_id_from_sources_v2(
    int runtime_root_source_fd,
    const int member_source_fds[
        PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2],
    uid_t owner_uid,
    uint8_t generation_id[PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2],
    uint8_t intrinsic_roster_sha256[
        PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2])
{
    struct plamen_intrinsic_generation_member_v2 members[
        PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2];
    struct plamen_runtime_package_manifest_result_v2 manifest;
    struct stat source_outer;
    struct stat runtime_outer;
    struct stat before;
    struct stat after;
    int runtime_outer_fd = -1;
    int result = -1;
    size_t index;

    if (generation_id != NULL)
        memset(generation_id, 0,
            PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2);
    if (intrinsic_roster_sha256 != NULL)
        memset(intrinsic_roster_sha256, 0,
            PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2);
    memset(members, 0, sizeof(members));
    memset(&manifest, 0, sizeof(manifest));
    if (runtime_root_source_fd < 0 || member_source_fds == NULL
            || generation_id == NULL || intrinsic_roster_sha256 == NULL) {
        errno = EINVAL;
        return -1;
    }
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
        if (member_source_fds[index] < 0) {
            errno = EINVAL;
            goto done;
        }
    }
    if (plamen_runtime_package_manifest_revalidate_v2(
            runtime_root_source_fd, member_source_fds[7], owner_uid,
            &manifest) != 0)
        goto done;
    runtime_outer_fd = stage_open_relative_regular(
        runtime_root_source_fd, "scripts/posix_audit_entrypoint.py");
    if (runtime_outer_fd < 0 || fstat(runtime_outer_fd, &runtime_outer) != 0
            || fstat(member_source_fds[6], &source_outer) != 0
            || !stat_equal(&runtime_outer, &source_outer)) {
        errno = errno == 0 ? EINVAL : errno;
        goto done;
    }
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
        if (fstat(member_source_fds[index], &before) != 0
                || !S_ISREG(before.st_mode) || before.st_size <= 0
                || before.st_nlink < 1
                || (uint64_t)before.st_size
                    > PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_TOTAL_BYTES
                || hash_regular_fd(member_source_fds[index],
                    (uint64_t)before.st_size, members[index].sha256) != 0
                || fstat(member_source_fds[index], &after) != 0
                || !stat_equal(&before, &after)) {
            errno = errno == 0 ? EINVAL : errno;
            goto done;
        }
        members[index].role = (uint16_t)(index + 1U);
        members[index].relative_path = intrinsic_generation_paths[index];
        members[index].relative_path_size =
            strlen(intrinsic_generation_paths[index]);
        members[index].mode = intrinsic_generation_modes[index];
        members[index].size = (uint64_t)before.st_size;
    }
    if (plamen_intrinsic_generation_id_and_roster_v2(members,
            generation_id, intrinsic_roster_sha256) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EINVAL : errno);
        if (runtime_outer_fd >= 0)
            (void)close(runtime_outer_fd);
        memset(members, 0, sizeof(members));
        memset(&manifest, 0, sizeof(manifest));
        memset(&source_outer, 0, sizeof(source_outer));
        memset(&runtime_outer, 0, sizeof(runtime_outer));
        memset(&before, 0, sizeof(before));
        memset(&after, 0, sizeof(after));
        if (result != 0) {
            if (generation_id != NULL)
                memset(generation_id, 0,
                    PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2);
            if (intrinsic_roster_sha256 != NULL)
                memset(intrinsic_roster_sha256, 0,
                    PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2);
            errno = saved;
        }
        return result;
    }
}

int
plamen_native_generation_stage_v2(
    const struct plamen_native_generation_stage_request_v2 *request,
    struct plamen_native_generation_stage_result_v2 *result)
{
    static const char *const member_names[] = {
        "plamen-native-launcher", "plamen-audit-broker-v2",
        "_plamen_native_supervisor.cpython-312-darwin.so",
        "plamen_broker_v2.h", "native-supervisor-schema-v2.json",
        "python3.12", NULL, "runtime-package-manifest-v2.bin",
        "plamen-native-installer-v2",
        "plamen-native-source-bootstrap-coordinator-v1"
    };
    struct stat parent_stat;
    struct stat root_named;
    struct stat root_opened;
    struct stat source_outer;
    struct stat source_outer_named;
    struct plamen_intrinsic_generation_member_v2 members[
        PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2];
    struct plamen_runtime_package_manifest_result_v2 manifest_result;
    int directories[6] = {-1, -1, -1, -1, -1, -1};
    int source_outer_fd = -1;
    int stage_created = 0;
    int saved = 0;
    size_t index;

    memset(members, 0, sizeof(members));
    memset(&manifest_result, 0, sizeof(manifest_result));
    if (result == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->generation_root_fd = -1;
    result->runtime_root_fd = -1;
    result->specialized_authority_fd = -1;
    result->source_bootstrap_authority_fd = -1;
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index)
        result->generation_member_fds[index] = -1;
    if (request == NULL || request->specialized_present > 1U
            || request->source_bootstrap_present > 1U
            || (request->specialized_present == 1U
                && request->specialized_authority_source_fd < 0)
            || (request->source_bootstrap_present == 1U
                && request->source_bootstrap_authority_source_fd < 0)
            || request->staging_parent_fd < 0
            || request->runtime_root_source_fd < 0
            || !ascii_component(request->staged_generation_name)
            || fstat(request->staging_parent_fd, &parent_stat) != 0
            || !S_ISDIR(parent_stat.st_mode)
            || parent_stat.st_uid != request->owner_uid
            || (parent_stat.st_mode & 07777U) != 0700U) {
        errno = errno == 0 ? EINVAL : errno;
        return -1;
    }
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
        if (request->member_source_fds[index] < 0) {
            errno = EINVAL;
            return -1;
        }
    }
    if (plamen_runtime_package_manifest_revalidate_v2(
            request->runtime_root_source_fd, request->member_source_fds[7],
            request->owner_uid, &manifest_result) != 0)
        return -1;
    source_outer_fd = stage_open_relative_regular(
        request->runtime_root_source_fd,
        "scripts/posix_audit_entrypoint.py");
    if (source_outer_fd < 0 || fstat(source_outer_fd, &source_outer_named) != 0
            || fstat(request->member_source_fds[6], &source_outer) != 0
            || !stat_equal(&source_outer_named, &source_outer)) {
        saved = errno == 0 ? EINVAL : errno;
        goto fail;
    }
    if (stage_make_directory(request->staging_parent_fd,
            request->staged_generation_name, request->owner_uid,
            &result->generation_root_fd) != 0)
        goto fail;
    stage_created = 1;
    if (stage_make_directory(result->generation_root_fd, "bin",
            request->owner_uid, &directories[0]) != 0
            || stage_make_directory(result->generation_root_fd, "lib",
                request->owner_uid, &directories[1]) != 0
            || stage_make_directory(directories[1], "plamen",
                request->owner_uid, &directories[2]) != 0
            || stage_make_directory(result->generation_root_fd, "share",
                request->owner_uid, &directories[3]) != 0
            || stage_make_directory(directories[3], "plamen",
                request->owner_uid, &directories[4]) != 0
            || stage_make_directory(result->generation_root_fd, "libexec",
                request->owner_uid, &directories[5]) != 0
            || stage_make_directory(directories[2], "runtime",
                request->owner_uid, &result->runtime_root_fd) != 0
            || stage_copy_runtime_directory(request->runtime_root_source_fd,
                result->runtime_root_fd, request->owner_uid) != 0
            || fchmod(result->runtime_root_fd, 0500U) != 0
            || fsync(result->runtime_root_fd) != 0)
        goto fail;
    result->generation_member_fds[6] = stage_open_relative_regular(
        result->runtime_root_fd, "scripts/posix_audit_entrypoint.py");
    if (result->generation_member_fds[6] < 0)
        goto fail;
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
        int destination_parent;
        if (index == 6U)
            continue;
        if (index == 0U || index == 5U)
            destination_parent = directories[0];
        else if (index == 1U || index == 2U)
            destination_parent = directories[2];
        else if (index == 8U || index == 9U)
            destination_parent = directories[5];
        else
            destination_parent = directories[4];
        if (stage_copy_regular(request->member_source_fds[index],
                destination_parent, member_names[index],
                intrinsic_generation_modes[index], request->owner_uid,
                &result->generation_member_fds[index]) != 0)
            goto fail;
    }
    if (request->specialized_present == 1U
            && stage_copy_regular(request->specialized_authority_source_fd,
                directories[4], "image-member-receipt-v2.bin", 0400U,
                request->owner_uid, &result->specialized_authority_fd) != 0)
        goto fail;
    if (request->source_bootstrap_present == 1U
            && stage_copy_regular(
                request->source_bootstrap_authority_source_fd,
                directories[4],
                "native-source-bootstrap-coordinator-receipt-v1.bin",
                0400U, request->owner_uid,
                &result->source_bootstrap_authority_fd) != 0)
        goto fail;
    if (plamen_runtime_package_manifest_revalidate_v2(
            result->runtime_root_fd, result->generation_member_fds[7],
            request->owner_uid, &manifest_result) != 0)
        goto fail;
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
        struct stat info;
        if (fstat(result->generation_member_fds[index], &info) != 0
                || !S_ISREG(info.st_mode) || info.st_uid != request->owner_uid
                || info.st_nlink != 1 || info.st_size <= 0
                || (info.st_mode & 07777U) != intrinsic_generation_modes[index]
                || hash_regular_fd(result->generation_member_fds[index],
                    (uint64_t)info.st_size, members[index].sha256) != 0) {
            saved = errno == 0 ? EINVAL : errno;
            goto fail;
        }
        members[index].role = (uint16_t)(index + 1U);
        members[index].relative_path = intrinsic_generation_paths[index];
        members[index].relative_path_size =
            strlen(intrinsic_generation_paths[index]);
        members[index].mode = intrinsic_generation_modes[index];
        members[index].size = (uint64_t)info.st_size;
    }
    if (plamen_intrinsic_generation_id_and_roster_v2(members,
            result->generation_id, result->intrinsic_roster_sha256) != 0)
        goto fail;
    for (index = 0U; index < 6U; ++index) {
        if (fchmod(directories[index], 0500U) != 0
                || fsync(directories[index]) != 0)
            goto fail;
    }
    if (fsync(result->generation_root_fd) != 0
            || fsync(request->staging_parent_fd) != 0
            || fstat(result->generation_root_fd, &root_opened) != 0
            || fstatat(request->staging_parent_fd,
                request->staged_generation_name, &root_named,
                AT_SYMLINK_NOFOLLOW) != 0
            || !stat_equal(&root_opened, &root_named)
            || (root_opened.st_mode & 07777U) != 0700U) {
        saved = errno == 0 ? EBUSY : errno;
        goto fail;
    }
    for (index = 0U; index < 6U; ++index) {
        (void)close(directories[index]);
        directories[index] = -1;
    }
    (void)close(source_outer_fd);
    memset(members, 0, sizeof(members));
    memset(&manifest_result, 0, sizeof(manifest_result));
    return 0;

fail:
    saved = saved == 0 ? (errno == 0 ? EINVAL : errno) : saved;
    if (source_outer_fd >= 0)
        (void)close(source_outer_fd);
    for (index = 0U; index < 6U; ++index) {
        if (directories[index] >= 0)
            (void)close(directories[index]);
    }
    if (stage_created && result->generation_root_fd >= 0) {
        struct stat named;
        struct stat opened;
        (void)stage_remove_contents(result->generation_root_fd);
        if (fstat(result->generation_root_fd, &opened) == 0
                && fstatat(request->staging_parent_fd,
                    request->staged_generation_name, &named,
                    AT_SYMLINK_NOFOLLOW) == 0
                && stat_equal(&opened, &named))
            (void)unlinkat(request->staging_parent_fd,
                request->staged_generation_name, AT_REMOVEDIR);
    }
    plamen_native_generation_stage_result_dispose_v2(result);
    memset(members, 0, sizeof(members));
    memset(&manifest_result, 0, sizeof(manifest_result));
    errno = saved;
    return -1;
}

void
plamen_native_generation_deployment_stage_result_dispose_v2(
    struct plamen_native_generation_deployment_stage_result_v2 *result)
{
    if (result == NULL)
        return;
    if (result->broker_launchd_plist_fd >= 0)
        (void)close(result->broker_launchd_plist_fd);
    if (result->custody_launchd_plist_fd >= 0)
        (void)close(result->custody_launchd_plist_fd);
    result->broker_launchd_plist_fd = -1;
    result->custody_launchd_plist_fd = -1;
    plamen_native_generation_stage_result_dispose_v2(&result->generation);
}

int
plamen_native_generation_deployment_stage_v2(
    const struct plamen_native_generation_deployment_stage_request_v2 *request,
    struct plamen_native_generation_deployment_stage_result_v2 *result)
{
    static const char broker_name[] = "com.plamen.audit.broker.v2.plist";
    static const char custody_name[] =
        "com.plamen.audit.process-custody.v2.plist";
    int library = -1;
    int agents = -1;
    int saved = 0;

    if (result == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->generation.generation_root_fd = -1;
    result->generation.runtime_root_fd = -1;
    result->generation.specialized_authority_fd = -1;
    result->generation.source_bootstrap_authority_fd = -1;
    result->broker_launchd_plist_fd = -1;
    result->custody_launchd_plist_fd = -1;
    {
        size_t index;
        for (index = 0U;
                index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index)
            result->generation.generation_member_fds[index] = -1;
    }
    if (request == NULL || request->broker_launchd_plist_fd < 0
            || request->custody_launchd_plist_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (plamen_native_generation_stage_v2(&request->generation,
            &result->generation) != 0)
        return -1;
    if (stage_make_directory(result->generation.generation_root_fd, "Library",
            request->generation.owner_uid, &library) != 0
            || stage_make_directory(library, "LaunchAgents",
                request->generation.owner_uid, &agents) != 0
            || stage_copy_regular(request->broker_launchd_plist_fd, agents,
                broker_name, 0400U, request->generation.owner_uid,
                &result->broker_launchd_plist_fd) != 0
            || stage_copy_regular(request->custody_launchd_plist_fd, agents,
                custody_name, 0400U, request->generation.owner_uid,
                &result->custody_launchd_plist_fd) != 0
            || fchmod(agents, 0500U) != 0 || fsync(agents) != 0
            || fchmod(library, 0500U) != 0 || fsync(library) != 0
            || fsync(result->generation.generation_root_fd) != 0
            || fsync(request->generation.staging_parent_fd) != 0) {
        saved = errno == 0 ? EIO : errno;
        goto fail;
    }
    (void)close(agents);
    (void)close(library);
    return 0;

fail:
    if (agents >= 0)
        (void)close(agents);
    if (library >= 0)
        (void)close(library);
    if (result->generation.generation_root_fd >= 0) {
        struct stat opened;
        struct stat named;
        (void)stage_remove_contents(result->generation.generation_root_fd);
        if (fstat(result->generation.generation_root_fd, &opened) == 0
                && fstatat(request->generation.staging_parent_fd,
                    request->generation.staged_generation_name, &named,
                    AT_SYMLINK_NOFOLLOW) == 0
                && stat_equal(&opened, &named))
            (void)unlinkat(request->generation.staging_parent_fd,
                request->generation.staged_generation_name, AT_REMOVEDIR);
    }
    plamen_native_generation_deployment_stage_result_dispose_v2(result);
    errno = saved;
    return -1;
}

int
plamen_native_generation_deployment_stage_revalidate_v2(
    const struct plamen_native_generation_deployment_stage_request_v2 *request,
    struct plamen_native_generation_deployment_stage_result_v2 *result)
{
    static const char *const root_names[] = {
        "Library", "bin", "lib", "libexec", "share"
    };
    static const char *const bin_names[] = {
        "plamen-native-launcher", "python3.12"
    };
    static const char *const lib_names[] = {"plamen"};
    static const char *const lib_plamen_names[] = {
        "_plamen_native_supervisor.cpython-312-darwin.so",
        "plamen-audit-broker-v2", "runtime"
    };
    static const char *const share_names[] = {"plamen"};
    static const char *const share_plamen_base_names[] = {
        "native-supervisor-schema-v2.json", "plamen_broker_v2.h",
        "runtime-package-manifest-v2.bin"
    };
    static const char *const library_names[] = {"LaunchAgents"};
    static const char *const libexec_names[] = {
        "plamen-native-installer-v2",
        "plamen-native-source-bootstrap-coordinator-v1"
    };
    static const char *const agent_names[] = {
        "com.plamen.audit.broker.v2.plist",
        "com.plamen.audit.process-custody.v2.plist"
    };
    static const char *const plist_paths[] = {
        "Library/LaunchAgents/com.plamen.audit.broker.v2.plist",
        "Library/LaunchAgents/com.plamen.audit.process-custody.v2.plist"
    };
    int directories[7] = {-1, -1, -1, -1, -1, -1, -1};
    struct plamen_runtime_package_manifest_result_v2 source_manifest;
    struct plamen_runtime_package_manifest_result_v2 staged_manifest;
    struct stat parent, root_before, root_named, root_after;
    uint8_t source_generation[32], source_roster[32];
    uint8_t staged_generation[32], staged_roster[32];
    size_t index;
    const char *share_plamen_names[6];
    size_t share_plamen_name_count = 0U;
    int saved = 0;

    memset(&source_manifest, 0, sizeof(source_manifest));
    memset(&staged_manifest, 0, sizeof(staged_manifest));
    memset(source_generation, 0, sizeof(source_generation));
    memset(source_roster, 0, sizeof(source_roster));
    memset(staged_generation, 0, sizeof(staged_generation));
    memset(staged_roster, 0, sizeof(staged_roster));
    if (result == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->generation.generation_root_fd = -1;
    result->generation.runtime_root_fd = -1;
    result->generation.specialized_authority_fd = -1;
    result->generation.source_bootstrap_authority_fd = -1;
    result->broker_launchd_plist_fd = -1;
    result->custody_launchd_plist_fd = -1;
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index)
        result->generation.generation_member_fds[index] = -1;
    if (request == NULL || request->generation.staging_parent_fd < 0
            || request->generation.runtime_root_source_fd < 0
            || request->generation.specialized_present > 1U
            || (request->generation.specialized_present == 1U
                && request->generation.specialized_authority_source_fd < 0)
            || request->generation.source_bootstrap_present > 1U
            || (request->generation.source_bootstrap_present == 1U
                && request->generation.source_bootstrap_authority_source_fd < 0)
            || request->broker_launchd_plist_fd < 0
            || request->custody_launchd_plist_fd < 0
            || !ascii_component(request->generation.staged_generation_name)
            || fstat(request->generation.staging_parent_fd, &parent) != 0
            || !S_ISDIR(parent.st_mode)
            || parent.st_uid != request->generation.owner_uid
            || (parent.st_mode & 07777U) != 0700U) {
        errno = errno == 0 ? EINVAL : errno;
        goto fail;
    }
    for (index = 0U; index < 3U; ++index)
        share_plamen_names[share_plamen_name_count++] =
            share_plamen_base_names[index];
    if (request->generation.specialized_present == 1U)
        share_plamen_names[share_plamen_name_count++] =
            "image-member-receipt-v2.bin";
    if (request->generation.source_bootstrap_present == 1U) {
        share_plamen_names[share_plamen_name_count++] =
            "native-source-bootstrap-coordinator-receipt-v1.bin";
        share_plamen_names[share_plamen_name_count++] =
            "native-source-authority-v1";
    }
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
        if (request->generation.member_source_fds[index] < 0) {
            errno = EINVAL;
            goto fail;
        }
    }
    result->generation.generation_root_fd = openat(
        request->generation.staging_parent_fd,
        request->generation.staged_generation_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (result->generation.generation_root_fd < 0
            || fstat(result->generation.generation_root_fd, &root_before) != 0
            || fstatat(request->generation.staging_parent_fd,
                request->generation.staged_generation_name, &root_named,
                AT_SYMLINK_NOFOLLOW) != 0
            || !stat_equal(&root_before, &root_named)
            || !S_ISDIR(root_before.st_mode)
            || root_before.st_uid != request->generation.owner_uid
            || (root_before.st_mode & 07777U) != 0700U
            || stage_has_exact_names(result->generation.generation_root_fd,
                root_names, sizeof(root_names) / sizeof(root_names[0])) != 0)
        goto fail;
    directories[0] = stage_open_relative_directory(
        result->generation.generation_root_fd, "bin",
        request->generation.owner_uid);
    directories[1] = stage_open_relative_directory(
        result->generation.generation_root_fd, "lib",
        request->generation.owner_uid);
    directories[2] = stage_open_relative_directory(
        result->generation.generation_root_fd, "lib/plamen",
        request->generation.owner_uid);
    result->generation.runtime_root_fd = stage_open_relative_directory(
        result->generation.generation_root_fd, "lib/plamen/runtime",
        request->generation.owner_uid);
    directories[3] = stage_open_relative_directory(
        result->generation.generation_root_fd, "share",
        request->generation.owner_uid);
    directories[4] = stage_open_relative_directory(
        result->generation.generation_root_fd, "share/plamen",
        request->generation.owner_uid);
    directories[5] = stage_open_relative_directory(
        result->generation.generation_root_fd, "Library",
        request->generation.owner_uid);
    directories[6] = stage_open_relative_directory(
        result->generation.generation_root_fd, "libexec",
        request->generation.owner_uid);
    {
        int agents = stage_open_relative_directory(
            result->generation.generation_root_fd, "Library/LaunchAgents",
            request->generation.owner_uid);
        if (directories[0] < 0 || directories[1] < 0 || directories[2] < 0
                || result->generation.runtime_root_fd < 0
                || directories[3] < 0 || directories[4] < 0
                || directories[5] < 0 || directories[6] < 0 || agents < 0
                || stage_has_exact_names(directories[0], bin_names, 2U) != 0
                || stage_has_exact_names(directories[1], lib_names, 1U) != 0
                || stage_has_exact_names(directories[2], lib_plamen_names,
                    3U) != 0
                || stage_has_exact_names(directories[3], share_names, 1U) != 0
                || stage_has_exact_names(directories[4], share_plamen_names,
                    share_plamen_name_count) != 0
                || stage_has_exact_names(directories[5], library_names,
                    1U) != 0
                || stage_has_exact_names(directories[6], libexec_names,
                    2U) != 0
                || stage_has_exact_names(agents, agent_names, 2U) != 0) {
            saved = errno == 0 ? EINVAL : errno;
            if (agents >= 0)
                (void)close(agents);
            goto fail;
        }
        (void)close(agents);
    }
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
        result->generation.generation_member_fds[index] =
            stage_open_relative_regular(
                result->generation.generation_root_fd,
                intrinsic_generation_paths[index]);
        if (result->generation.generation_member_fds[index] < 0
                || stage_regular_matches_source(
                    result->generation.generation_member_fds[index],
                    request->generation.member_source_fds[index],
                    request->generation.owner_uid,
                    intrinsic_generation_modes[index]) != 0)
            goto fail;
    }
    if (request->generation.specialized_present == 1U)
        result->generation.specialized_authority_fd =
            stage_open_relative_regular(result->generation.generation_root_fd,
                PLAMEN_RUNTIME_PACKAGE_SPECIALIZED_RECEIPT_PATH_V2);
    if (request->generation.source_bootstrap_present == 1U)
        result->generation.source_bootstrap_authority_fd =
            stage_open_relative_regular(
                result->generation.generation_root_fd,
                "share/plamen/"
                "native-source-bootstrap-coordinator-receipt-v1.bin");
    result->broker_launchd_plist_fd = stage_open_relative_regular(
        result->generation.generation_root_fd, plist_paths[0]);
    result->custody_launchd_plist_fd = stage_open_relative_regular(
        result->generation.generation_root_fd, plist_paths[1]);
    if ((request->generation.specialized_present == 1U
                && result->generation.specialized_authority_fd < 0)
            || (request->generation.source_bootstrap_present == 1U
                && (result->generation.source_bootstrap_authority_fd < 0
                    || stage_regular_matches_source(
                        result->generation.source_bootstrap_authority_fd,
                        request->generation.
                            source_bootstrap_authority_source_fd,
                        request->generation.owner_uid, 0400U) != 0))
            || result->broker_launchd_plist_fd < 0
            || result->custody_launchd_plist_fd < 0
            || (request->generation.specialized_present == 1U
                && stage_regular_matches_source(
                    result->generation.specialized_authority_fd,
                    request->generation.specialized_authority_source_fd,
                    request->generation.owner_uid, 0400U) != 0)
            || stage_regular_matches_source(result->broker_launchd_plist_fd,
                request->broker_launchd_plist_fd,
                request->generation.owner_uid, 0400U) != 0
            || stage_regular_matches_source(result->custody_launchd_plist_fd,
                request->custody_launchd_plist_fd,
                request->generation.owner_uid, 0400U) != 0
            || plamen_runtime_package_manifest_revalidate_v2(
                request->generation.runtime_root_source_fd,
                request->generation.member_source_fds[7],
                request->generation.owner_uid, &source_manifest) != 0
            || plamen_runtime_package_manifest_revalidate_v2(
                result->generation.runtime_root_fd,
                result->generation.generation_member_fds[7],
                request->generation.owner_uid, &staged_manifest) != 0
            || source_manifest.manifest_size != staged_manifest.manifest_size
            || memcmp(source_manifest.manifest_sha256,
                staged_manifest.manifest_sha256, 32U) != 0
            || plamen_intrinsic_generation_id_from_sources_v2(
                request->generation.runtime_root_source_fd,
                request->generation.member_source_fds,
                request->generation.owner_uid, source_generation,
                source_roster) != 0
            || plamen_intrinsic_generation_id_from_sources_v2(
                result->generation.runtime_root_fd,
                result->generation.generation_member_fds,
                request->generation.owner_uid, staged_generation,
                staged_roster) != 0
            || memcmp(source_generation, staged_generation, 32U) != 0
            || memcmp(source_roster, staged_roster, 32U) != 0
            || fstat(result->generation.generation_root_fd, &root_after) != 0
            || fstatat(request->generation.staging_parent_fd,
                request->generation.staged_generation_name, &root_named,
                AT_SYMLINK_NOFOLLOW) != 0
            || !stat_equal(&root_before, &root_after)
            || !stat_equal(&root_after, &root_named))
        goto fail;
    memcpy(result->generation.generation_id, staged_generation, 32U);
    memcpy(result->generation.intrinsic_roster_sha256, staged_roster, 32U);
    for (index = 0U; index < 7U; ++index) {
        (void)close(directories[index]);
        directories[index] = -1;
    }
    memset(&source_manifest, 0, sizeof(source_manifest));
    memset(&staged_manifest, 0, sizeof(staged_manifest));
    memset(source_generation, 0, sizeof(source_generation));
    memset(source_roster, 0, sizeof(source_roster));
    memset(staged_generation, 0, sizeof(staged_generation));
    memset(staged_roster, 0, sizeof(staged_roster));
    return 0;

fail:
    saved = saved == 0 ? (errno == 0 ? EINVAL : errno) : saved;
    for (index = 0U; index < 7U; ++index)
        if (directories[index] >= 0)
            (void)close(directories[index]);
    plamen_native_generation_deployment_stage_result_dispose_v2(result);
    memset(&source_manifest, 0, sizeof(source_manifest));
    memset(&staged_manifest, 0, sizeof(staged_manifest));
    memset(source_generation, 0, sizeof(source_generation));
    memset(source_roster, 0, sizeof(source_roster));
    memset(staged_generation, 0, sizeof(staged_generation));
    memset(staged_roster, 0, sizeof(staged_roster));
    errno = saved;
    return -1;
}

#ifdef PLAMEN_NATIVE_BUILDER_V2_MAIN
static int
parse_builder_fd(const char *value)
{
    char *end = NULL;
    long number;
    if (value == NULL || value[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    errno = 0;
    number = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || number < 3
            || number > 1048576L || fcntl((int)number, F_GETFD) < 0
            || fcntl((int)number, F_SETFD, FD_CLOEXEC) != 0) {
        errno = EINVAL;
        return -1;
    }
    return (int)number;
}

int
main(int argc, char **argv)
{
    struct plamen_native_generation_deployment_stage_request_v2 request;
    struct plamen_native_generation_deployment_stage_result_v2 result;
    static const char hex[] = "0123456789abcdef";
    char generation_hex[65];
    size_t index;
    int status = 75;

    memset(&request, 0, sizeof(request));
    memset(&result, 0, sizeof(result));
    memset(generation_hex, 0, sizeof(generation_hex));
    result.generation.generation_root_fd = -1;
    result.generation.runtime_root_fd = -1;
    result.broker_launchd_plist_fd = -1;
    result.custody_launchd_plist_fd = -1;
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index) {
        request.generation.member_source_fds[index] = -1;
        result.generation.generation_member_fds[index] = -1;
    }
    if (argc != 16 || strcmp(argv[1], "stage-fds") != 0)
        goto done;
    request.generation.staging_parent_fd = parse_builder_fd(argv[2]);
    request.generation.runtime_root_source_fd = parse_builder_fd(argv[3]);
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index)
        request.generation.member_source_fds[index] =
            parse_builder_fd(argv[4U + index]);
    request.broker_launchd_plist_fd = parse_builder_fd(argv[13]);
    request.custody_launchd_plist_fd = parse_builder_fd(argv[14]);
    request.generation.staged_generation_name = argv[15];
    request.generation.owner_uid = getuid();
    if (request.generation.staging_parent_fd < 0
            || request.generation.runtime_root_source_fd < 0
            || request.broker_launchd_plist_fd < 0
            || request.custody_launchd_plist_fd < 0)
        goto done;
    for (index = 0U;
            index < PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2; ++index)
        if (request.generation.member_source_fds[index] < 0)
            goto done;
    if (plamen_native_generation_deployment_stage_v2(&request, &result) != 0)
        goto done;
    for (index = 0U; index < 32U; ++index) {
        generation_hex[index * 2U] =
            hex[result.generation.generation_id[index] >> 4U];
        generation_hex[index * 2U + 1U] =
            hex[result.generation.generation_id[index] & 0x0fU];
    }
    if (write(STDOUT_FILENO, generation_hex, 64U) != 64
            || write(STDOUT_FILENO, "\n", 1U) != 1)
        goto done;
    status = 0;
done:
    plamen_native_generation_deployment_stage_result_dispose_v2(&result);
    memset(&request, 0, sizeof(request));
    memset(generation_hex, 0, sizeof(generation_hex));
    return status;
}
#endif
