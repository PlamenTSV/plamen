#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_specialized_output_census.h"

#include <CommonCrypto/CommonDigest.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CENSUS_BUFFER_MAX (64U * 1024U * 1024U)
#define CENSUS_COMPONENT_MAX 255U
#define CENSUS_DEPTH_MAX 64U

static const char algorithm[] = "PLAMEN_CANONICAL_TREE_SHA256_V1";

struct byte_buffer {
    uint8_t *bytes;
    size_t size;
    size_t capacity;
};

struct inode_identity { dev_t device; ino_t inode; };

struct census_context {
    dev_t root_device;
    uint64_t max_entries;
    uint64_t max_bytes;
    uint64_t entries;
    uint64_t bytes;
    struct inode_identity *files;
    size_t file_count;
    size_t file_capacity;
    struct byte_buffer canonical;
};

struct child_name { char *bytes; size_t size; };

static int stable_stat_equal(const struct stat *left, const struct stat *right)
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

static int buffer_reserve(struct byte_buffer *buffer, size_t amount)
{
    size_t wanted, capacity; uint8_t *grown;
    if (buffer == NULL || amount > CENSUS_BUFFER_MAX - buffer->size) return -1;
    wanted = buffer->size + amount;
    if (wanted <= buffer->capacity) return 0;
    capacity = buffer->capacity == 0U ? 4096U : buffer->capacity;
    while (capacity < wanted) {
        if (capacity > CENSUS_BUFFER_MAX / 2U) {
            capacity = CENSUS_BUFFER_MAX; break;
        }
        capacity *= 2U;
    }
    if (capacity < wanted) return -1;
    grown = realloc(buffer->bytes, capacity);
    if (grown == NULL) return -1;
    buffer->bytes = grown; buffer->capacity = capacity; return 0;
}

static int buffer_write(struct byte_buffer *buffer, const void *bytes, size_t size)
{
    if (buffer_reserve(buffer, size) != 0) return -1;
    if (size != 0U) memcpy(buffer->bytes + buffer->size, bytes, size);
    buffer->size += size; return 0;
}

static int buffer_byte(struct byte_buffer *buffer, uint8_t byte)
{ return buffer_write(buffer, &byte, 1U); }

static int buffer_decimal(struct byte_buffer *buffer, uint64_t value)
{
    char digits[32]; int amount = snprintf(digits, sizeof(digits), "%llu",
        (unsigned long long)value);
    return amount > 0 && (size_t)amount < sizeof(digits)
        ? buffer_write(buffer, digits, (size_t)amount) : -1;
}

static int json_u16_escape(struct byte_buffer *buffer, uint16_t value)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t encoded[6] = {'\\', 'u', 0, 0, 0, 0};
    encoded[2] = (uint8_t)hex[(value >> 12) & 15U];
    encoded[3] = (uint8_t)hex[(value >> 8) & 15U];
    encoded[4] = (uint8_t)hex[(value >> 4) & 15U];
    encoded[5] = (uint8_t)hex[value & 15U];
    return buffer_write(buffer, encoded, sizeof(encoded));
}

/* Python os.fsdecode + json.dumps(ensure_ascii=True), including surrogateescape. */
static int json_filesystem_string(struct byte_buffer *buffer,
    const uint8_t *bytes, size_t size)
{
    size_t index = 0;
    if (buffer_byte(buffer, '"') != 0) return -1;
    while (index < size) {
        uint32_t point; size_t width = 1U; uint8_t byte = bytes[index];
        if (byte < 0x80U) point = byte;
        else if (byte >= 0xc2U && byte <= 0xdfU && index + 1U < size
            && (bytes[index + 1U] & 0xc0U) == 0x80U) {
            point = ((uint32_t)(byte & 0x1fU) << 6)
                | (uint32_t)(bytes[index + 1U] & 0x3fU); width = 2U;
        } else if (byte >= 0xe0U && byte <= 0xefU && index + 2U < size
            && (bytes[index + 1U] & 0xc0U) == 0x80U
            && (bytes[index + 2U] & 0xc0U) == 0x80U
            && !(byte == 0xe0U && bytes[index + 1U] < 0xa0U)
            && !(byte == 0xedU && bytes[index + 1U] >= 0xa0U)) {
            point = ((uint32_t)(byte & 0x0fU) << 12)
                | ((uint32_t)(bytes[index + 1U] & 0x3fU) << 6)
                | (uint32_t)(bytes[index + 2U] & 0x3fU); width = 3U;
        } else if (byte >= 0xf0U && byte <= 0xf4U && index + 3U < size
            && (bytes[index + 1U] & 0xc0U) == 0x80U
            && (bytes[index + 2U] & 0xc0U) == 0x80U
            && (bytes[index + 3U] & 0xc0U) == 0x80U
            && !(byte == 0xf0U && bytes[index + 1U] < 0x90U)
            && !(byte == 0xf4U && bytes[index + 1U] >= 0x90U)) {
            point = ((uint32_t)(byte & 7U) << 18)
                | ((uint32_t)(bytes[index + 1U] & 0x3fU) << 12)
                | ((uint32_t)(bytes[index + 2U] & 0x3fU) << 6)
                | (uint32_t)(bytes[index + 3U] & 0x3fU); width = 4U;
        } else point = UINT32_C(0xdc00) + byte;
        if (point == '"' || point == '\\') {
            if (buffer_byte(buffer, '\\') != 0
                || buffer_byte(buffer, (uint8_t)point) != 0) return -1;
        } else if (point == '\b' || point == '\f' || point == '\n'
            || point == '\r' || point == '\t') {
            static const char codes[] = "btnrt";
            size_t code = point == '\b' ? 0U : point == '\f' ? 1U
                : point == '\n' ? 2U : point == '\r' ? 3U : 4U;
            if (buffer_byte(buffer, '\\') != 0
                || buffer_byte(buffer, (uint8_t)codes[code]) != 0) return -1;
        } else if (point < 0x20U || point >= 0x80U) {
            if (point <= 0xffffU) {
                if (json_u16_escape(buffer, (uint16_t)point) != 0) return -1;
            } else {
                uint32_t adjusted = point - UINT32_C(0x10000);
                if (json_u16_escape(buffer,
                        (uint16_t)(UINT32_C(0xd800) + (adjusted >> 10))) != 0
                    || json_u16_escape(buffer,
                        (uint16_t)(UINT32_C(0xdc00) + (adjusted & 0x3ffU))) != 0)
                    return -1;
            }
        } else if (buffer_byte(buffer, (uint8_t)point) != 0) return -1;
        index += width;
    }
    return buffer_byte(buffer, '"');
}

static int child_compare(const void *left, const void *right)
{
    const struct child_name *a = left, *b = right;
    size_t common = a->size < b->size ? a->size : b->size;
    int compared = memcmp(a->bytes, b->bytes, common);
    return compared != 0 ? compared : a->size < b->size ? -1
        : a->size > b->size ? 1 : 0;
}

static void children_destroy(struct child_name *children, size_t count)
{
    size_t index;
    if (children == NULL) return;
    for (index = 0; index < count; ++index) free(children[index].bytes);
    free(children);
}

static int children_read(int directory_fd, struct child_name **result,
    size_t *result_count)
{
    DIR *directory = NULL; struct dirent *entry; struct child_name *children = NULL;
    size_t count = 0, capacity = 0; int duplicate, status = -1;
    if (result != NULL) *result = NULL;
    if (result_count != NULL) *result_count = 0U;
    if (directory_fd < 0 || result == NULL || result_count == NULL
        || (duplicate = openat(directory_fd, ".",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0)
        return -1;
    directory = fdopendir(duplicate);
    if (directory == NULL) { close(duplicate); return -1; }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        size_t size;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        size = strlen(entry->d_name);
        if (size == 0U || size > CENSUS_COMPONENT_MAX
            || strchr(entry->d_name, '/') != NULL) goto done;
        if (count == capacity) {
            size_t grown_capacity = capacity == 0U ? 16U : capacity * 2U;
            struct child_name *grown;
            if (grown_capacity > 65536U) goto done;
            grown = realloc(children, grown_capacity * sizeof(*children));
            if (grown == NULL) goto done;
            children = grown; capacity = grown_capacity;
        }
        children[count].bytes = malloc(size + 1U);
        if (children[count].bytes == NULL) goto done;
        memcpy(children[count].bytes, entry->d_name, size + 1U);
        children[count].size = size; ++count;
    }
    if (errno != 0) goto done;
    qsort(children, count, sizeof(*children), child_compare);
    *result = children; *result_count = count; children = NULL; count = 0U;
    status = 0;
done:
    if (closedir(directory) != 0) status = -1;
    children_destroy(children, count); return status;
}

static int file_seen(struct census_context *context, dev_t device, ino_t inode)
{
    size_t index;
    for (index = 0; index < context->file_count; ++index)
        if (context->files[index].device == device
            && context->files[index].inode == inode) return 1;
    if (context->file_count == context->file_capacity) {
        size_t capacity = context->file_capacity == 0U
            ? 32U : context->file_capacity * 2U;
        struct inode_identity *grown;
        if (capacity > context->max_entries) capacity = (size_t)context->max_entries;
        if (capacity <= context->file_count) return -1;
        grown = realloc(context->files, capacity * sizeof(*context->files));
        if (grown == NULL) return -1;
        context->files = grown; context->file_capacity = capacity;
    }
    context->files[context->file_count].device = device;
    context->files[context->file_count].inode = inode;
    ++context->file_count; return 0;
}

static int hash_file(int descriptor, const struct stat *before,
    uint8_t digest[32])
{
    CC_SHA256_CTX context; uint8_t bytes[65536]; off_t offset = 0;
    struct stat after; ssize_t amount; int status = -1;
    if (CC_SHA256_Init(&context) != 1) return -1;
    while (offset < before->st_size) {
        size_t wanted = (size_t)(before->st_size - offset);
        if (wanted > sizeof(bytes)) wanted = sizeof(bytes);
        amount = pread(descriptor, bytes, wanted, offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0 || CC_SHA256_Update(&context, bytes,
                (CC_LONG)amount) != 1) goto done;
        offset += amount;
    }
    if (CC_SHA256_Final(digest, &context) != 1
        || fstat(descriptor, &after) != 0
        || !stable_stat_equal(before, &after)) goto done;
    status = 0;
done:
    memset(bytes, 0, sizeof(bytes));
    if (status != 0) memset(digest, 0, 32); return status;
}

static int write_relative(struct byte_buffer *buffer, const char *prefix,
    const char *name)
{
    size_t prefix_size = strlen(prefix), name_size = strlen(name);
    uint8_t *joined; size_t joined_size = prefix_size + (prefix_size ? 1U : 0U)
        + name_size; int status;
    if (joined_size > PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RELATIVE_MAX)
        return -1;
    joined = malloc(joined_size == 0U ? 1U : joined_size);
    if (joined == NULL) return -1;
    if (prefix_size) { memcpy(joined, prefix, prefix_size); joined[prefix_size] = '/'; }
    memcpy(joined + prefix_size + (prefix_size ? 1U : 0U), name, name_size);
    status = json_filesystem_string(buffer, joined, joined_size);
    free(joined); return status;
}

static int walk(int directory_fd, const char *prefix, unsigned int depth,
    struct census_context *context)
{
    struct child_name *children = NULL; size_t count = 0, index;
    int status = -1;
    if (depth > CENSUS_DEPTH_MAX
        || children_read(directory_fd, &children, &count) != 0) return -1;
    for (index = 0; index < count; ++index) {
        struct stat before, after; int child = -1;
        const char *name = children[index].bytes;
        if (++context->entries > context->max_entries
            || fstatat(directory_fd, name, &before, AT_SYMLINK_NOFOLLOW) != 0
            || before.st_dev != context->root_device) goto done;
        if (S_ISDIR(before.st_mode)) {
            if (buffer_write(&context->canonical, "[\"d\",", 5U) != 0
                || write_relative(&context->canonical, prefix, name) != 0
                || buffer_byte(&context->canonical, ',') != 0
                || buffer_decimal(&context->canonical,
                    (uint64_t)(before.st_mode & 0777U)) != 0
                || buffer_write(&context->canonical, "]\n", 2U) != 0
                || (child = openat(directory_fd, name,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0
                || fstat(child, &after) != 0
                || !stable_stat_equal(&before, &after)) goto done;
            {
                char next[PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RELATIVE_MAX + 1U];
                int amount = snprintf(next, sizeof(next), "%s%s%s", prefix,
                    prefix[0] ? "/" : "", name);
                if (amount <= 0 || (size_t)amount >= sizeof(next)
                    || walk(child, next, depth + 1U, context) != 0) goto done;
            }
            close(child); child = -1;
            if (fstatat(directory_fd, name, &after, AT_SYMLINK_NOFOLLOW) != 0
                || !stable_stat_equal(&before, &after)) goto done;
        } else if (S_ISREG(before.st_mode)) {
            uint8_t digest[32]; static const char hex[] = "0123456789abcdef";
            char digest_hex[64]; size_t byte;
            if (before.st_nlink != 1 || before.st_size < 0
                || (uint64_t)before.st_size > context->max_bytes - context->bytes
                || file_seen(context, before.st_dev, before.st_ino) != 0
                || (child = openat(directory_fd, name,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
                || fstat(child, &after) != 0 || !stable_stat_equal(&before, &after)
                || hash_file(child, &before, digest) != 0) goto done;
            for (byte = 0; byte < 32U; ++byte) {
                digest_hex[byte * 2U] = hex[digest[byte] >> 4];
                digest_hex[byte * 2U + 1U] = hex[digest[byte] & 15U];
            }
            if (buffer_write(&context->canonical, "[\"f\",", 5U) != 0
                || write_relative(&context->canonical, prefix, name) != 0
                || buffer_byte(&context->canonical, ',') != 0
                || buffer_decimal(&context->canonical,
                    (uint64_t)(before.st_mode & 0777U)) != 0
                || buffer_byte(&context->canonical, ',') != 0
                || buffer_decimal(&context->canonical,
                    (uint64_t)before.st_size) != 0
                || buffer_write(&context->canonical, ",\"", 2U) != 0
                || buffer_write(&context->canonical, digest_hex,
                    sizeof(digest_hex)) != 0
                || buffer_write(&context->canonical, "\"]\n", 3U) != 0)
                goto done;
            context->bytes += (uint64_t)before.st_size;
            close(child); child = -1;
            if (fstatat(directory_fd, name, &after, AT_SYMLINK_NOFOLLOW) != 0
                || !stable_stat_equal(&before, &after)) goto done;
            memset(digest, 0, sizeof(digest)); memset(digest_hex, 0, sizeof(digest_hex));
        } else goto done;
        continue;
done:
        if (child >= 0) close(child);
        goto finish;
    }
    status = 0;
finish:
    children_destroy(children, count); return status;
}

static int safe_component_path(const char *path)
{
    size_t size, index, component = 0;
    if (path == NULL || path[0] == '/' || path[0] == '\0'
        || (size = strlen(path)) > PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RELATIVE_MAX)
        return 0;
    for (index = 0; index <= size; ++index) {
        if (path[index] == '/' || path[index] == '\0') {
            if (component == 0U || (component == 1U && path[index - 1U] == '.')
                || (component == 2U && path[index - 1U] == '.'
                    && path[index - 2U] == '.')) return 0;
            component = 0U;
        } else {
            unsigned char byte = (unsigned char)path[index];
            if (byte < 0x20U || byte == 0x7fU || byte == '\\') return 0;
            ++component;
        }
    }
    return 1;
}

static int open_relative_directory(int root_fd, const char *path, int *output)
{
    int current = -1, next = -1; const char *cursor = path;
    char component[CENSUS_COMPONENT_MAX + 1U];
    if (output != NULL) *output = -1;
    if (root_fd < 0 || !safe_component_path(path) || output == NULL
        || (current = fcntl(root_fd, F_DUPFD_CLOEXEC, 3)) < 0) return -1;
    while (*cursor) {
        const char *slash = strchr(cursor, '/');
        size_t size = slash == NULL ? strlen(cursor) : (size_t)(slash - cursor);
        if (size == 0U || size > CENSUS_COMPONENT_MAX) goto done;
        memcpy(component, cursor, size); component[size] = '\0';
        next = openat(current, component,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0) goto done;
        close(current); current = next; next = -1;
        if (slash == NULL) break;
        cursor = slash + 1U;
    }
    *output = current; current = -1;
done:
    if (next >= 0) close(next); if (current >= 0) close(current);
    memset(component, 0, sizeof(component)); return *output >= 0 ? 0 : -1;
}

static int recensus_one(int scratch_fd,
    const struct plamen_broker_v2_specialized_output_spec *spec,
    struct plamen_broker_v2_specialized_output_tree *tree)
{
    struct census_context context; struct stat before, after; int root = -1;
    uint8_t digest[CC_SHA256_DIGEST_LENGTH]; size_t name_size, path_size;
    int status = -1;
    memset(&context, 0, sizeof(context)); memset(tree, 0, sizeof(*tree));
    if (spec == NULL || tree == NULL
        || spec->version != PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_CENSUS_VERSION
        || spec->role != PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_ROLE_SCRATCH
        || (name_size = strnlen(spec->name, sizeof(spec->name))) == 0U
        || name_size > PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_NAME_MAX
        || (path_size = strnlen(spec->relative_path,
            sizeof(spec->relative_path))) == 0U
        || path_size > PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RELATIVE_MAX
        || spec->max_entries == 0U || spec->max_entries > 65536U
        || spec->max_expanded_bytes == 0U
        || spec->max_expanded_bytes > UINT64_C(4294967296)
        || open_relative_directory(scratch_fd, spec->relative_path, &root) != 0
        || fstat(root, &before) != 0 || !S_ISDIR(before.st_mode)) goto done;
    context.root_device = before.st_dev; context.max_entries = spec->max_entries;
    context.max_bytes = spec->max_expanded_bytes;
    if (buffer_write(&context.canonical, algorithm, sizeof(algorithm) - 1U) != 0
        || buffer_byte(&context.canonical, '\n') != 0
        || walk(root, "", 0U, &context) != 0
        || fstat(root, &after) != 0 || !stable_stat_equal(&before, &after)
        || CC_SHA256(context.canonical.bytes, (CC_LONG)context.canonical.size,
            digest) == NULL) goto done;
    tree->version = PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_CENSUS_VERSION;
    tree->role = PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_ROLE_SCRATCH;
    memcpy(tree->name, spec->name, name_size + 1U);
    memcpy(tree->relative_path, spec->relative_path, path_size + 1U);
    memcpy(tree->tree_sha256, digest, 32); tree->entry_count = context.entries;
    tree->expanded_bytes = context.bytes; status = 0;
done:
    if (root >= 0) close(root);
    if (context.canonical.bytes != NULL) {
        memset(context.canonical.bytes, 0, context.canonical.capacity);
        free(context.canonical.bytes);
    }
    if (context.files != NULL) {
        memset(context.files, 0, context.file_capacity * sizeof(*context.files));
        free(context.files);
    }
    memset(digest, 0, sizeof(digest));
    if (status != 0) memset(tree, 0, sizeof(*tree)); return status;
}

int
plamen_broker_v2_specialized_tree_recensus_fd(int root_fd,
    uint64_t max_entries, uint64_t max_expanded_bytes,
    struct plamen_broker_v2_specialized_tree_identity *identity)
{
    struct census_context context; struct stat before, after;
    uint8_t digest[CC_SHA256_DIGEST_LENGTH]; int status = -1;
    memset(&context, 0, sizeof(context));
    if (identity != NULL) memset(identity, 0, sizeof(*identity));
    if (root_fd < 0 || identity == NULL || max_entries == 0U
        || max_entries > 65536U || max_expanded_bytes == 0U
        || max_expanded_bytes > UINT64_C(4294967296)
        || fstat(root_fd, &before) != 0 || !S_ISDIR(before.st_mode))
        return -1;
    context.root_device = before.st_dev; context.max_entries = max_entries;
    context.max_bytes = max_expanded_bytes;
    if (buffer_write(&context.canonical, algorithm, sizeof(algorithm) - 1U) != 0
        || buffer_byte(&context.canonical, '\n') != 0
        || walk(root_fd, "", 0U, &context) != 0
        || fstat(root_fd, &after) != 0 || !stable_stat_equal(&before, &after)
        || CC_SHA256(context.canonical.bytes, (CC_LONG)context.canonical.size,
            digest) == NULL) goto done;
    identity->version = PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_CENSUS_VERSION;
    memcpy(identity->tree_sha256, digest, 32);
    identity->entry_count = context.entries;
    identity->expanded_bytes = context.bytes; status = 0;
done:
    if (context.canonical.bytes != NULL) {
        memset(context.canonical.bytes, 0, context.canonical.capacity);
        free(context.canonical.bytes);
    }
    if (context.files != NULL) {
        memset(context.files, 0, context.file_capacity * sizeof(*context.files));
        free(context.files);
    }
    memset(digest, 0, sizeof(digest));
    if (status != 0) memset(identity, 0, sizeof(*identity)); return status;
}

int
plamen_broker_v2_specialized_output_recensus(int scratch_fd,
    const struct plamen_broker_v2_specialized_output_spec *specs,
    size_t spec_count, struct plamen_broker_v2_specialized_output_tree *trees)
{
    size_t index, prior;
    if (scratch_fd < 0 || specs == NULL || trees == NULL || spec_count == 0U
        || spec_count > PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_COUNT_MAX)
        return -1;
    memset(trees, 0, spec_count * sizeof(*trees));
    for (index = 0; index < spec_count; ++index) {
        for (prior = 0; prior < index; ++prior)
            if (strcmp(specs[prior].name, specs[index].name) == 0
                || strcmp(specs[prior].relative_path,
                    specs[index].relative_path) == 0) goto fail;
        if (recensus_one(scratch_fd, &specs[index], &trees[index]) != 0)
            goto fail;
    }
    return 0;
fail:
    memset(trees, 0, spec_count * sizeof(*trees)); return -1;
}
