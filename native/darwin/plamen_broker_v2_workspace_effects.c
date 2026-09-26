#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_workspace_effects.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
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

#define WORKSPACE_MAGIC UINT32_C(0x50575331)
#define TREE_MAX_DEPTH 64U
#define TREE_MAX_ENTRIES 131072U
#define TREE_MAX_FILE_SIZE (UINT64_C(256) * 1024U * 1024U)
#define TREE_MAX_TOTAL_SIZE (UINT64_C(2) * 1024U * 1024U * 1024U)
#define RECEIPT_HEADER_SIZE 76U
#define RECEIPT_MAGIC "PLMWSE1\0"

struct fd_snapshot {
    dev_t device;
    ino_t inode;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    nlink_t links;
    off_t size;
    time_t modified;
    time_t changed;
};

struct byte_buffer {
    uint8_t *data;
    size_t size;
    size_t capacity;
};

struct tree_limits {
    uint64_t bytes;
    uint64_t entries;
};

struct plamen_broker_v2_workspace_effects_context {
    uint32_t magic;
    struct plamen_broker_v2_service_registration registration;
    uint8_t *projection;
    size_t projection_size;
    int state_parent_fd;
    int generation_fd;
    struct fd_snapshot state_parent_snapshot;
    struct fd_snapshot generation_snapshot;
    int fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    struct fd_snapshot snapshots[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    int workspace_fd;
    int merged_fd;
    int scratch_fd;
    int state_fd;
    int control_fd;
    int seccomp_fd;
    int credentials_fd;
    int backend_private_fd;
    int runtime_private_fd;
    int docs_private_fd;
    int scope_private_fd;
    struct fd_snapshot workspace_snapshot;
    char workspace_name[80];
    char attempt_id[129];
    char run_id[129];
    char source_handle[72];
    char source_config_sha256[65];
    char startup_receipt_sha256[65];
    char target_identity_sha256[65];
    char scope_sha256[65];
    char seccomp_sha256[65];
    char export_identity_sha256[65];
    char runtime_layout_sha256[65];
    char docs_sha256[65];
    char backend_context_sha256[65];
    char credential_bundle_sha256[65];
    uint8_t *guest_config;
    size_t guest_config_size;
    char handles[15][72];
    char target_content_sha256[65];
    uint8_t target_commitment[32];
    uint8_t layout_commitment[32];
    uint8_t config_commitment[32];
    uint8_t private_mount_census[6][32];
    uint8_t private_mount_roster_sha256[32];
    uint8_t *precreate_recensus;
    size_t precreate_recensus_size;
    uint8_t precreate_recensus_commitment[32];
    uint8_t precreate_provider_mounts_sha256[32];
    uint8_t precreate_layout_sha256[32];
    uint8_t *postcreate_recensus;
    size_t postcreate_recensus_size;
    uint8_t postcreate_recensus_commitment[32];
    uint8_t postcreate_provider_mounts_sha256[32];
    uint8_t postcreate_layout_sha256[32];
    uint8_t layout_ready;
    uint8_t config_ready;
};

static int
constant_equal(const void *left_value, const void *right_value, size_t size)
{
    const uint8_t *left = left_value;
    const uint8_t *right = right_value;
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < size; ++index)
        difference |= (uint8_t)(left[index] ^ right[index]);
    return difference == 0;
}

static int
all_zero(const uint8_t *value, size_t size)
{
    uint8_t aggregate = 0;
    size_t index;
    for (index = 0; index < size; ++index) aggregate |= value[index];
    return aggregate == 0;
}

static void
store_u32(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static uint32_t
load_u32(const uint8_t input[4])
{
    return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16)
        | ((uint32_t)input[2] << 8) | input[3];
}

static void
store_u64(uint8_t output[8], uint64_t value)
{
    size_t index;
    for (index = 0; index < 8; ++index)
        output[index] = (uint8_t)(value >> (56U - (unsigned int)index * 8U));
}

static void
encode_hex32(const uint8_t value[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32; ++index) {
        output[index * 2] = digits[value[index] >> 4];
        output[index * 2 + 1] = digits[value[index] & 15U];
    }
    output[64] = '\0';
}

static int
snapshot_fd(int descriptor, struct fd_snapshot *snapshot)
{
    struct stat information;
    if (descriptor < 0 || snapshot == NULL
        || fstat(descriptor, &information) != 0)
        return -1;
    snapshot->device = information.st_dev;
    snapshot->inode = information.st_ino;
    snapshot->mode = information.st_mode;
    snapshot->uid = information.st_uid;
    snapshot->gid = information.st_gid;
    snapshot->links = information.st_nlink;
    snapshot->size = information.st_size;
    snapshot->modified = information.st_mtime;
    snapshot->changed = information.st_ctime;
    return 0;
}

static int
snapshot_same(const struct fd_snapshot *left, const struct fd_snapshot *right)
{
    return left->device == right->device && left->inode == right->inode
        && left->mode == right->mode && left->uid == right->uid
        && left->gid == right->gid && left->links == right->links
        && left->size == right->size && left->modified == right->modified
        && left->changed == right->changed;
}

static int
duplicate_cloexec(int descriptor)
{
#ifdef F_DUPFD_CLOEXEC
    return fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
#else
    int duplicate = dup(descriptor);
    int flags;
    if (duplicate < 0) return -1;
    flags = fcntl(duplicate, F_GETFD);
    if (flags < 0 || fcntl(duplicate, F_SETFD, flags | FD_CLOEXEC) != 0) {
        (void)close(duplicate);
        return -1;
    }
    return duplicate;
#endif
}

static int
full_sync(int descriptor)
{
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0) return 0;
#endif
    return fsync(descriptor);
}

static int
write_all(int descriptor, const uint8_t *data, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = write(descriptor, data + offset, size - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int
pread_all(int descriptor, uint8_t *data, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = pread(descriptor, data + offset, size - offset,
            (off_t)offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int
buffer_write(struct byte_buffer *buffer, const void *data, size_t size)
{
    size_t capacity;
    uint8_t *grown;
    if (buffer == NULL || (size != 0 && data == NULL)
        || size > SIZE_MAX - buffer->size
        || buffer->size + size > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX)
        return -1;
    if (buffer->size + size > buffer->capacity) {
        capacity = buffer->capacity == 0 ? 4096U : buffer->capacity;
        while (capacity < buffer->size + size) {
            if (capacity > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX / 2U) {
                capacity = PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX;
                break;
            }
            capacity *= 2U;
        }
        grown = realloc(buffer->data, capacity);
        if (grown == NULL) return -1;
        buffer->data = grown;
        buffer->capacity = capacity;
    }
    memcpy(buffer->data + buffer->size, data, size);
    buffer->size += size;
    return 0;
}

static void
buffer_destroy(struct byte_buffer *buffer)
{
    if (buffer != NULL && buffer->data != NULL) {
        plamen_broker_v2_secure_zero(buffer->data, buffer->capacity);
        free(buffer->data);
    }
    if (buffer != NULL) memset(buffer, 0, sizeof(*buffer));
}

static int
extract_projection_string(const uint8_t *projection, size_t projection_size,
    const char *key, char *output, size_t capacity)
{
    char pattern[160];
    size_t pattern_size, index, start = 0, found = 0, value_size;
    int amount;
    if (projection == NULL || key == NULL || output == NULL || capacity < 2)
        return -1;
    amount = snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    if (amount <= 0 || (size_t)amount >= sizeof(pattern)) return -1;
    pattern_size = (size_t)amount;
    for (index = 0; index + pattern_size <= projection_size; ++index) {
        if (memcmp(projection + index, pattern, pattern_size) == 0) {
            if (++found != 1) return -1;
            start = index + pattern_size;
        }
    }
    if (found != 1 || start >= projection_size) return -1;
    index = start;
    while (index < projection_size && projection[index] != '"') {
        if (projection[index] < 0x20U || projection[index] > 0x7eU
            || projection[index] == '\\') return -1;
        ++index;
    }
    if (index >= projection_size) return -1;
    value_size = index - start;
    if (value_size == 0 || value_size >= capacity) return -1;
    memcpy(output, projection + start, value_size);
    output[value_size] = '\0';
    return 0;
}

static int
base64_digit(uint8_t value)
{
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

static int
decode_base64(const char *value, uint8_t **output, size_t *output_size)
{
    size_t size, source, target = 0, decoded_size;
    uint8_t *decoded;
    if (value == NULL || output == NULL || output_size == NULL) return -1;
    *output = NULL; *output_size = 0;
    size = strlen(value);
    if (size == 0 || size % 4U != 0
        || size > ((256U * 1024U + 2U) / 3U) * 4U)
        return -1;
    decoded_size = size / 4U * 3U;
    if (value[size - 1U] == '=') --decoded_size;
    if (value[size - 2U] == '=') --decoded_size;
    if (decoded_size == 0 || decoded_size > 256U * 1024U) return -1;
    decoded = malloc(decoded_size);
    if (decoded == NULL) return -1;
    for (source = 0; source < size; source += 4U) {
        int a = base64_digit((uint8_t)value[source]);
        int b = base64_digit((uint8_t)value[source + 1U]);
        int c = value[source + 2U] == '=' ? 0
            : base64_digit((uint8_t)value[source + 2U]);
        int d = value[source + 3U] == '=' ? 0
            : base64_digit((uint8_t)value[source + 3U]);
        uint32_t word;
        if (a < 0 || b < 0 || c < 0 || d < 0
            || (value[source + 2U] == '='
                && (source + 4U != size || value[source + 3U] != '='))
            || (value[source + 3U] == '=' && source + 4U != size)
            || (value[source + 2U] == '=' && (b & 15) != 0)
            || (value[source + 2U] != '=' && value[source + 3U] == '='
                && (c & 3) != 0))
            goto fail;
        word = ((uint32_t)a << 18) | ((uint32_t)b << 12)
            | ((uint32_t)c << 6) | (uint32_t)d;
        if (target < decoded_size) decoded[target++] = (uint8_t)(word >> 16);
        if (target < decoded_size) decoded[target++] = (uint8_t)(word >> 8);
        if (target < decoded_size) decoded[target++] = (uint8_t)word;
    }
    if (target != decoded_size) goto fail;
    *output = decoded; *output_size = decoded_size;
    return 0;
fail:
    plamen_broker_v2_secure_zero(decoded, decoded_size);
    free(decoded);
    return -1;
}

static int
compare_names(const void *left_value, const void *right_value)
{
    const char *const *left = left_value;
    const char *const *right = right_value;
    return strcmp(*left, *right);
}

static void
free_names(char **names, size_t count)
{
    size_t index;
    if (names == NULL) return;
    for (index = 0; index < count; ++index) free(names[index]);
    free(names);
}

static int
directory_names(int descriptor, char ***output, size_t *output_count,
    struct tree_limits *limits)
{
    DIR *directory = NULL;
    struct dirent *entry;
    char **names = NULL, **grown;
    size_t count = 0, capacity = 0, length;
    int duplicate = -1, status = -1;
    if (output == NULL || output_count == NULL || limits == NULL) return -1;
    *output = NULL; *output_count = 0;
    /* dup shares a directory stream offset; openat(".") creates an
     * independent open file description while staying descriptor-relative. */
    duplicate = openat(descriptor, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (duplicate < 0 || (directory = fdopendir(duplicate)) == NULL) goto done;
    duplicate = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        length = strlen(entry->d_name);
        if (length == 0 || length > 255U || strchr(entry->d_name, '/') != NULL
            || strchr(entry->d_name, '\n') != NULL
            || strchr(entry->d_name, '\r') != NULL
            || limits->entries >= TREE_MAX_ENTRIES)
            goto done;
        if (count == capacity) {
            size_t next = capacity == 0 ? 32U : capacity * 2U;
            if (next > TREE_MAX_ENTRIES
                || (grown = realloc(names, next * sizeof(*names))) == NULL)
                goto done;
            names = grown; capacity = next;
        }
        names[count] = strdup(entry->d_name);
        if (names[count] == NULL) goto done;
        ++count; ++limits->entries;
    }
    if (errno != 0) goto done;
    qsort(names, count, sizeof(*names), compare_names);
    *output = names; *output_count = count;
    names = NULL; count = 0;
    status = 0;
done:
    free_names(names, count);
    if (directory != NULL) (void)closedir(directory);
    else if (duplicate >= 0) (void)close(duplicate);
    return status;
}

static int
stat_stable(const struct stat *before, const struct stat *after)
{
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino
        && before->st_mode == after->st_mode && before->st_nlink == after->st_nlink
        && before->st_size == after->st_size
        && before->st_mtime == after->st_mtime
        && before->st_ctime == after->st_ctime;
}

static int scan_directory(int, int, unsigned int, struct tree_limits *,
    uint8_t[32]);

static int
scan_regular(int source_parent, int destination_parent, const char *name,
    const struct stat *listed, struct tree_limits *limits, uint8_t digest[32])
{
    static const uint8_t domain[] = "PLAMEN-WORKSPACE-FILE-V1\0";
    struct stat before, after;
    struct byte_buffer committed = { 0 };
    uint8_t *content = NULL;
    int source = -1, destination = -1, result = -1;
    if (listed->st_size < 0 || (uint64_t)listed->st_size > TREE_MAX_FILE_SIZE
        || (uint64_t)listed->st_size > TREE_MAX_TOTAL_SIZE - limits->bytes)
        return -1;
    source = openat(source_parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source < 0 || fstat(source, &before) != 0
        || !S_ISREG(before.st_mode) || before.st_nlink != 1
        || !stat_stable(listed, &before))
        goto done;
    if (before.st_size != 0) {
        content = malloc((size_t)before.st_size);
        if (content == NULL || pread_all(source, content,
                (size_t)before.st_size) != 0)
            goto done;
    }
    if (fstat(source, &after) != 0 || !stat_stable(&before, &after)
        || buffer_write(&committed, domain, sizeof(domain) - 1U) != 0
        || buffer_write(&committed, content, (size_t)before.st_size) != 0
        || plamen_broker_v2_sha256(committed.data, committed.size, digest) != 0)
        goto done;
    if (destination_parent >= 0) {
        mode_t mode = (mode_t)((before.st_mode & 0555) | 0600);
        destination = openat(destination_parent, name,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (destination < 0
            || write_all(destination, content, (size_t)before.st_size) != 0
            || fchmod(destination, mode) != 0 || full_sync(destination) != 0
            || close(destination) != 0)
            goto done;
        destination = -1;
    }
    limits->bytes += (uint64_t)before.st_size;
    result = 0;
done:
    if (destination >= 0) (void)close(destination);
    if (source >= 0) (void)close(source);
    if (content != NULL) {
        plamen_broker_v2_secure_zero(content, (size_t)listed->st_size);
        free(content);
    }
    buffer_destroy(&committed);
    return result;
}

static int
scan_child_directory(int source_parent, int destination_parent,
    const char *name, const struct stat *listed, unsigned int depth,
    struct tree_limits *limits, uint8_t digest[32])
{
    struct stat before, after;
    int source = -1, destination = -1, result = -1;
    source = openat(source_parent, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (source < 0 || fstat(source, &before) != 0
        || !S_ISDIR(before.st_mode) || !stat_stable(listed, &before))
        goto done;
    if (destination_parent >= 0) {
        if (mkdirat(destination_parent, name, 0700) != 0) goto done;
        destination = openat(destination_parent, name,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (destination < 0) goto done;
    }
    if (scan_directory(source, destination, depth, limits, digest) != 0
        || fstat(source, &after) != 0 || !stat_stable(&before, &after)
        || (destination >= 0 && full_sync(destination) != 0))
        goto done;
    result = 0;
done:
    if (destination >= 0) (void)close(destination);
    if (source >= 0) (void)close(source);
    return result;
}

static int
scan_directory(int source, int destination, unsigned int depth,
    struct tree_limits *limits, uint8_t digest[32])
{
    static const uint8_t domain[] = "PLAMEN-WORKSPACE-DIRECTORY-V1\0";
    struct byte_buffer record = { 0 };
    char **names = NULL;
    size_t count = 0, index;
    int result = -1;
    if (depth > TREE_MAX_DEPTH
        || directory_names(source, &names, &count, limits) != 0
        || buffer_write(&record, domain, sizeof(domain) - 1U) != 0)
        goto done;
    for (index = 0; index < count; ++index) {
        struct stat information;
        uint8_t child_digest[32], header[15];
        size_t name_size = strlen(names[index]);
        memset(child_digest, 0, sizeof(child_digest));
        if (depth == 0 && strcmp(names[index], ".scratchpad") == 0)
            goto done;
        if (fstatat(source, names[index], &information,
                AT_SYMLINK_NOFOLLOW) != 0)
            goto done;
        if (S_ISREG(information.st_mode)) {
            if (scan_regular(source, destination, names[index], &information,
                    limits, child_digest) != 0)
                goto done;
            header[0] = 'f';
        } else if (S_ISDIR(information.st_mode)) {
            if (scan_child_directory(source, destination, names[index],
                    &information, depth + 1U, limits, child_digest) != 0)
                goto done;
            header[0] = 'd';
        } else {
            /* Never follow or materialize symlinks, devices, fifos or sockets. */
            goto done;
        }
        header[1] = (uint8_t)(name_size >> 8);
        header[2] = (uint8_t)name_size;
        store_u32(header + 3, (uint32_t)(information.st_mode & 0777));
        store_u64(header + 7, S_ISREG(information.st_mode)
            ? (uint64_t)information.st_size : 0);
        if (buffer_write(&record, header, sizeof(header)) != 0
            || buffer_write(&record, names[index], name_size) != 0
            || buffer_write(&record, child_digest, sizeof(child_digest)) != 0)
            goto done;
    }
    if (plamen_broker_v2_sha256(record.data, record.size, digest) != 0)
        goto done;
    result = 0;
done:
    free_names(names, count);
    buffer_destroy(&record);
    return result;
}

static int
target_census(struct plamen_broker_v2_workspace_effects_context *context,
    int destination, uint8_t digest[32])
{
    struct fd_snapshot before, after;
    struct tree_limits limits = { 0 };
    if (snapshot_fd(context->fds[PLAMEN_BROKER_V2_RETAINED_TARGET], &before) != 0
        || !snapshot_same(&before,
            &context->snapshots[PLAMEN_BROKER_V2_RETAINED_TARGET])
        || scan_directory(context->fds[PLAMEN_BROKER_V2_RETAINED_TARGET],
            destination, 0, &limits, digest) != 0
        || snapshot_fd(context->fds[PLAMEN_BROKER_V2_RETAINED_TARGET], &after) != 0
        || !snapshot_same(&before, &after)
        || (destination >= 0 && full_sync(destination) != 0))
        return -1;
    return 0;
}

static int
copy_retained_regular(int source, const struct fd_snapshot *expected,
    int destination_parent, const char *name, uint64_t maximum)
{
    struct stat before, after;
    uint8_t *bytes = NULL;
    size_t size;
    mode_t mode;
    int destination = -1, result = -1;
    if (source < 0 || expected == NULL || destination_parent < 0
        || name == NULL || fstat(source, &before) != 0
        || !S_ISREG(before.st_mode) || before.st_nlink > 1
        || !snapshot_same(expected, &(struct fd_snapshot){
            .device = before.st_dev, .inode = before.st_ino,
            .mode = before.st_mode, .uid = before.st_uid,
            .gid = before.st_gid, .links = before.st_nlink,
            .size = before.st_size, .modified = before.st_mtime,
            .changed = before.st_ctime,
        })
        || before.st_size < 0 || (uint64_t)before.st_size > maximum
        || (uint64_t)before.st_size > SIZE_MAX)
        return -1;
    size = (size_t)before.st_size;
    if (size != 0) {
        bytes = malloc(size);
        if (bytes == NULL || pread_all(source, bytes, size) != 0)
            goto done;
    }
    if (fstat(source, &after) != 0 || !stat_stable(&before, &after))
        goto done;
    mode = (mode_t)(0400 | (before.st_mode & 0111));
    destination = openat(destination_parent, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (destination < 0 || (size != 0 && write_all(destination, bytes, size) != 0)
        || fchmod(destination, mode) != 0 || full_sync(destination) != 0
        || close(destination) != 0)
        goto done;
    destination = -1;
    result = full_sync(destination_parent);
done:
    if (destination >= 0) (void)close(destination);
    if (bytes != NULL) {
        plamen_broker_v2_secure_zero(bytes, size);
        free(bytes);
    }
    return result;
}

static int
write_private_text(int directory, const char *name,
    const uint8_t *bytes, size_t size)
{
    int descriptor = openat(directory, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0 || bytes == NULL || size == 0
        || write_all(descriptor, bytes, size) != 0
        || fchmod(descriptor, 0400) != 0 || full_sync(descriptor) != 0
        || close(descriptor) != 0) {
        if (descriptor >= 0) (void)close(descriptor);
        return -1;
    }
    return full_sync(directory);
}

static int
open_runtime_source(
    struct plamen_broker_v2_workspace_effects_context *context, int *output)
{
    struct fd_snapshot generation_after;
    int library = -1, plamen = -1, runtime = -1;
    if (snapshot_fd(context->generation_fd, &generation_after) != 0
        || !snapshot_same(&context->generation_snapshot, &generation_after))
        return -1;
    library = openat(context->generation_fd, "lib",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (library >= 0)
        plamen = openat(library, "plamen",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (plamen >= 0)
        runtime = openat(plamen, "runtime",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (library >= 0) (void)close(library);
    if (plamen >= 0) (void)close(plamen);
    if (runtime < 0) return -1;
    *output = runtime;
    return 0;
}

static int
populate_private_mounts(
    struct plamen_broker_v2_workspace_effects_context *context)
{
    static const int purposes[6] = { 0, 1, 2, 3, 4, 5 };
    struct tree_limits limits;
    struct stat docs_information;
    uint8_t seccomp[65];
    int runtime_source = -1;
    int directories[6];
    size_t index;
    directories[0] = context->seccomp_fd;
    directories[1] = context->credentials_fd;
    directories[2] = context->backend_private_fd;
    directories[3] = context->runtime_private_fd;
    directories[4] = context->docs_private_fd;
    directories[5] = context->scope_private_fd;
    memcpy(seccomp, context->seccomp_sha256, 64U); seccomp[64] = '\n';
    if (write_private_text(context->seccomp_fd, "profile.sha256",
            seccomp, sizeof(seccomp)) != 0
        || copy_retained_regular(
            context->fds[PLAMEN_BROKER_V2_RETAINED_CREDENTIAL],
            &context->snapshots[PLAMEN_BROKER_V2_RETAINED_CREDENTIAL],
            context->credentials_fd, "auth.json", 16U * 1024U * 1024U) != 0
        || copy_retained_regular(
            context->fds[PLAMEN_BROKER_V2_RETAINED_BACKEND_PROFILE],
            &context->snapshots[PLAMEN_BROKER_V2_RETAINED_BACKEND_PROFILE],
            context->backend_private_fd, "codex-v2.bin", 4096U) != 0
        || open_runtime_source(context, &runtime_source) != 0) goto fail;
    memset(&limits, 0, sizeof(limits));
    if (scan_directory(runtime_source, context->runtime_private_fd, 0,
            &limits, context->private_mount_census[3]) != 0
        || close(runtime_source) != 0)
        goto fail;
    runtime_source = -1;
    if (context->fds[PLAMEN_BROKER_V2_RETAINED_DOCS] >= 0) {
        if (fstat(context->fds[PLAMEN_BROKER_V2_RETAINED_DOCS],
                &docs_information) != 0)
            goto fail;
        if (S_ISDIR(docs_information.st_mode)) {
            memset(&limits, 0, sizeof(limits));
            if (scan_directory(
                    context->fds[PLAMEN_BROKER_V2_RETAINED_DOCS],
                    context->docs_private_fd, 0, &limits,
                    context->private_mount_census[4]) != 0)
                goto fail;
        } else if (copy_retained_regular(
                context->fds[PLAMEN_BROKER_V2_RETAINED_DOCS],
                &context->snapshots[PLAMEN_BROKER_V2_RETAINED_DOCS],
                context->docs_private_fd, "document", TREE_MAX_FILE_SIZE) != 0)
            goto fail;
    }
    if (context->fds[PLAMEN_BROKER_V2_RETAINED_SCOPE] >= 0
        && copy_retained_regular(
            context->fds[PLAMEN_BROKER_V2_RETAINED_SCOPE],
            &context->snapshots[PLAMEN_BROKER_V2_RETAINED_SCOPE],
            context->scope_private_fd, "scope.json", TREE_MAX_FILE_SIZE) != 0)
        goto fail;
    for (index = 0; index < 6; ++index) {
        /* Bind the normalized private copy, not mutable source metadata. */
        memset(&limits, 0, sizeof(limits));
        if (scan_directory(directories[index], -1, 0, &limits,
                context->private_mount_census[purposes[index]]) != 0)
            goto fail;
    }
    plamen_broker_v2_secure_zero(seccomp, sizeof(seccomp));
    return 0;
fail:
    if (runtime_source >= 0) (void)close(runtime_source);
    plamen_broker_v2_secure_zero(seccomp, sizeof(seccomp));
    return -1;
}

static int
private_mounts_revalidate(
    struct plamen_broker_v2_workspace_effects_context *context)
{
    static const uint8_t domain[] = "plamen.workspace.private-mounts.v1\0";
    struct byte_buffer binding = { 0 };
    struct tree_limits limits;
    uint8_t digest[32], roster[32];
    int directories[6] = {
        context->seccomp_fd, context->credentials_fd,
        context->backend_private_fd, context->runtime_private_fd,
        context->docs_private_fd, context->scope_private_fd,
    };
    size_t index;
    int uninitialized = all_zero((const uint8_t *)context->private_mount_census,
        sizeof(context->private_mount_census));
    for (index = 0; index < 6; ++index) {
        memset(&limits, 0, sizeof(limits)); memset(digest, 0, sizeof(digest));
        if (directories[index] < 0
            || scan_directory(directories[index], -1, 0, &limits, digest) != 0
            || (!uninitialized && !constant_equal(digest,
                context->private_mount_census[index], 32))
            || buffer_write(&binding, digest, 32) != 0) {
            plamen_broker_v2_secure_zero(digest, sizeof(digest));
            buffer_destroy(&binding);
            return -1;
        }
        if (uninitialized)
            memcpy(context->private_mount_census[index], digest, 32);
    }
    if (buffer_write(&binding, domain, sizeof(domain) - 1U) != 0
        || plamen_broker_v2_sha256(binding.data, binding.size, roster) != 0
        || (!all_zero(context->private_mount_roster_sha256, 32)
            && !constant_equal(roster,
                context->private_mount_roster_sha256, 32))) {
        plamen_broker_v2_secure_zero(digest, sizeof(digest));
        plamen_broker_v2_secure_zero(roster, sizeof(roster));
        buffer_destroy(&binding);
        return -1;
    }
    if (all_zero(context->private_mount_roster_sha256, 32))
        memcpy(context->private_mount_roster_sha256, roster, 32);
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    plamen_broker_v2_secure_zero(roster, sizeof(roster));
    buffer_destroy(&binding);
    return 0;
}

static int
format_alloc(uint8_t **output, size_t *output_size, const char *format, ...)
{
    va_list first, second;
    int needed, written;
    uint8_t *value;
    if (output == NULL || output_size == NULL || format == NULL) return -1;
    *output = NULL; *output_size = 0;
    va_start(first, format);
    va_copy(second, first);
    needed = vsnprintf(NULL, 0, format, first);
    va_end(first);
    if (needed < 0 || (size_t)needed > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX) {
        va_end(second); return -1;
    }
    value = malloc((size_t)needed + 1U);
    if (value == NULL) { va_end(second); return -1; }
    written = vsnprintf((char *)value, (size_t)needed + 1U, format, second);
    va_end(second);
    if (written != needed) {
        plamen_broker_v2_secure_zero(value, (size_t)needed + 1U);
        free(value); return -1;
    }
    *output = value; *output_size = (size_t)needed;
    return 0;
}

static int
semantic_commitment(const char *format, uint8_t output[32], ...)
{
    va_list first, second;
    int needed, written, status = -1;
    uint8_t *value = NULL;
    va_start(first, output);
    va_copy(second, first);
    needed = vsnprintf(NULL, 0, format, first);
    va_end(first);
    if (needed < 0 || (size_t)needed >= PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX)
        goto done;
    value = malloc((size_t)needed + 1U);
    if (value == NULL) goto done;
    written = vsnprintf((char *)value, (size_t)needed + 1U, format, second);
    if (written != needed
        || plamen_broker_v2_sha256(value, (size_t)needed, output) != 0)
        goto done;
    status = 0;
done:
    va_end(second);
    if (value != NULL) {
        plamen_broker_v2_secure_zero(value, (size_t)(needed >= 0 ? needed : 0));
        free(value);
    }
    return status;
}

static int
make_handle(struct plamen_broker_v2_workspace_effects_context *context,
    const char *domain, const uint8_t identity[32], char output[72])
{
    struct byte_buffer input = { 0 };
    uint8_t digest[32];
    char hex[65];
    int result = -1;
    if (buffer_write(&input, domain, strlen(domain) + 1U) != 0
        || buffer_write(&input,
            context->registration.audit_request_fingerprint, 32) != 0
        || buffer_write(&input, identity, 32) != 0
        || plamen_broker_v2_sha256(input.data, input.size, digest) != 0)
        goto done;
    encode_hex32(digest, hex);
    if (snprintf(output, 72, "opaque:%s", hex) != 71) goto done;
    result = 0;
done:
    buffer_destroy(&input);
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    plamen_broker_v2_secure_zero(hex, sizeof(hex));
    return result;
}

static int
make_fd_handle(struct plamen_broker_v2_workspace_effects_context *context,
    const char *domain, int descriptor, char output[72])
{
    uint8_t identity[32];
    int result = plamen_broker_v2_fd_identity(descriptor, identity) == 0
        ? make_handle(context, domain, identity, output) : -1;
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    return result;
}

static int
stable_directory_identity(int descriptor, uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-WORKSPACE-DIRECTORY-STABLE-IDENTITY-V1\0";
    struct stat before, after;
    struct byte_buffer binding = { 0 };
    uint8_t metadata[40];
    int result = -1;
    if (descriptor < 0 || output == NULL
        || fstat(descriptor, &before) != 0 || !S_ISDIR(before.st_mode))
        return -1;
    store_u64(metadata, (uint64_t)before.st_dev);
    store_u64(metadata + 8, (uint64_t)before.st_ino);
    store_u64(metadata + 16, (uint64_t)before.st_mode);
    store_u64(metadata + 24, (uint64_t)before.st_uid);
    store_u64(metadata + 32, (uint64_t)before.st_gid);
    if (buffer_write(&binding, domain, sizeof(domain)) != 0
        || buffer_write(&binding, metadata, sizeof(metadata)) != 0
        || fstat(descriptor, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_mode != after.st_mode || before.st_uid != after.st_uid
        || before.st_gid != after.st_gid
        || plamen_broker_v2_sha256(binding.data, binding.size, output) != 0)
        goto done;
    result = 0;
done:
    buffer_destroy(&binding);
    plamen_broker_v2_secure_zero(metadata, sizeof(metadata));
    if (result != 0) plamen_broker_v2_secure_zero(output, 32);
    return result;
}

static int
make_stable_directory_handle(
    struct plamen_broker_v2_workspace_effects_context *context,
    const char *domain, int descriptor, char output[72])
{
    uint8_t identity[32];
    int result = stable_directory_identity(descriptor, identity) == 0
        ? make_handle(context, domain, identity, output) : -1;
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    return result;
}

static int
result_finish(struct plamen_broker_v2_operations_effect_result *result,
    uint8_t *wire, size_t wire_size, const uint8_t commitment[32],
    int applied)
{
    if (result == NULL || wire == NULL || wire_size == 0
        || all_zero(commitment, 32)) {
        if (wire != NULL) {
            plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
        }
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->canonical_result = wire;
    result->canonical_result_size = wire_size;
    memcpy(result->result_commitment_sha256, commitment, 32);
    result->effect_applied = applied ? 1 : 0;
    result->durability_proven = 1;
    return 0;
}

static int
build_target_result(struct plamen_broker_v2_workspace_effects_context *context,
    int lease, struct plamen_broker_v2_operations_effect_result *result)
{
    uint8_t digest[32], commitment[32], *wire = NULL;
    size_t wire_size = 0;
    char content[65];
    const char *type = lease ? "TargetLease" : "TargetRecensus";
    if (target_census(context, -1, digest) != 0) return -1;
    encode_hex32(digest, content);
    if (semantic_commitment(
            lease
                ? "{\"authenticated\":true,\"content_sha256\":\"%s\",\"identity_sha256\":\"%s\",\"readonly\":true,\"scratchpad_absent\":true,\"target_handle\":\"%s\"}\n"
                : "{\"content_sha256\":\"%s\",\"identity_sha256\":\"%s\",\"readonly\":true,\"scratchpad_absent\":true,\"target_handle\":\"%s\"}\n",
            commitment, content, context->target_identity_sha256,
            context->handles[1]) != 0
        || format_alloc(&wire, &wire_size,
            lease
                ? "{\"$type\":\"%s\",\"fields\":{\"authenticated\":true,\"content_sha256\":\"%s\",\"identity_sha256\":\"%s\",\"readonly\":true,\"scratchpad_absent\":true,\"target_handle\":\"%s\"}}"
                : "{\"$type\":\"%s\",\"fields\":{\"content_sha256\":\"%s\",\"identity_sha256\":\"%s\",\"readonly\":true,\"scratchpad_absent\":true,\"target_handle\":\"%s\"}}",
            type, content, context->target_identity_sha256,
            context->handles[1]) != 0)
        return -1;
    memcpy(context->target_content_sha256, content, sizeof(content));
    if (lease) memcpy(context->target_commitment, commitment, 32);
    return result_finish(result, wire, wire_size, commitment, 0);
}

static int
remove_tree_contents(int directory, unsigned int depth)
{
    char **names = NULL;
    size_t count = 0, index;
    struct tree_limits limits = { 0 };
    int result = -1;
    if (depth > TREE_MAX_DEPTH
        || directory_names(directory, &names, &count, &limits) != 0)
        return -1;
    for (index = 0; index < count; ++index) {
        struct stat information;
        if (fstatat(directory, names[index], &information,
                AT_SYMLINK_NOFOLLOW) != 0)
            goto done;
        if (S_ISDIR(information.st_mode)) {
            int child = openat(directory, names[index],
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || remove_tree_contents(child, depth + 1U) != 0
                || close(child) != 0
                || unlinkat(directory, names[index], AT_REMOVEDIR) != 0) {
                if (child >= 0) (void)close(child);
                goto done;
            }
        } else if (S_ISREG(information.st_mode)) {
            if (unlinkat(directory, names[index], 0) != 0) goto done;
        } else {
            goto done;
        }
    }
    result = full_sync(directory);
done:
    free_names(names, count);
    return result;
}

static void
close_layout_descriptors(
    struct plamen_broker_v2_workspace_effects_context *context)
{
    int *descriptors[] = {
        &context->scope_private_fd, &context->docs_private_fd,
        &context->runtime_private_fd, &context->backend_private_fd,
        &context->credentials_fd, &context->seccomp_fd,
        &context->control_fd, &context->state_fd,
        &context->scratch_fd, &context->merged_fd, &context->workspace_fd
    };
    size_t index;
    for (index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); ++index) {
        if (*descriptors[index] >= 0) (void)close(*descriptors[index]);
        *descriptors[index] = -1;
    }
    context->layout_ready = 0;
    context->config_ready = 0;
}

static int
open_named_directory(int parent, const char *name, int *output)
{
    struct stat information;
    int descriptor = openat(parent, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !S_ISDIR(information.st_mode) || information.st_uid != geteuid()
        || (information.st_mode & 0077) != 0) {
        if (descriptor >= 0) (void)close(descriptor);
        return -1;
    }
    *output = descriptor;
    return 0;
}

static int
create_layout_directories(
    struct plamen_broker_v2_workspace_effects_context *context)
{
    static const char *names[] = {
        "upper", "work", "merged", "scratch", "state", "control", "seccomp",
        "credentials", "backend", "runtime", "docs", "scope"
    };
    size_t index;
    if (mkdirat(context->state_parent_fd, context->workspace_name, 0700) != 0
        || open_named_directory(context->state_parent_fd,
            context->workspace_name, &context->workspace_fd) != 0)
        return -1;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index)
        if (mkdirat(context->workspace_fd, names[index], 0700) != 0)
            return -1;
    if (open_named_directory(context->workspace_fd, "merged",
            &context->merged_fd) != 0
        || open_named_directory(context->workspace_fd, "scratch",
            &context->scratch_fd) != 0
        || open_named_directory(context->workspace_fd, "state",
            &context->state_fd) != 0
        || open_named_directory(context->workspace_fd, "control",
            &context->control_fd) != 0
        || open_named_directory(context->workspace_fd, "seccomp",
            &context->seccomp_fd) != 0
        || open_named_directory(context->workspace_fd, "credentials",
            &context->credentials_fd) != 0
        || open_named_directory(context->workspace_fd, "backend",
            &context->backend_private_fd) != 0
        || open_named_directory(context->workspace_fd, "runtime",
            &context->runtime_private_fd) != 0
        || open_named_directory(context->workspace_fd, "docs",
            &context->docs_private_fd) != 0
        || open_named_directory(context->workspace_fd, "scope",
            &context->scope_private_fd) != 0)
        return -1;
    return full_sync(context->workspace_fd) == 0
        && full_sync(context->state_parent_fd) == 0 ? 0 : -1;
}

static int
open_existing_layout(
    struct plamen_broker_v2_workspace_effects_context *context)
{
    if (open_named_directory(context->state_parent_fd, context->workspace_name,
            &context->workspace_fd) != 0
        || open_named_directory(context->workspace_fd, "merged",
            &context->merged_fd) != 0
        || open_named_directory(context->workspace_fd, "scratch",
            &context->scratch_fd) != 0
        || open_named_directory(context->workspace_fd, "state",
            &context->state_fd) != 0
        || open_named_directory(context->workspace_fd, "control",
            &context->control_fd) != 0
        || open_named_directory(context->workspace_fd, "seccomp",
            &context->seccomp_fd) != 0
        || open_named_directory(context->workspace_fd, "credentials",
            &context->credentials_fd) != 0
        || open_named_directory(context->workspace_fd, "backend",
            &context->backend_private_fd) != 0
        || open_named_directory(context->workspace_fd, "runtime",
            &context->runtime_private_fd) != 0
        || open_named_directory(context->workspace_fd, "docs",
            &context->docs_private_fd) != 0
        || open_named_directory(context->workspace_fd, "scope",
            &context->scope_private_fd) != 0)
        return -1;
    return private_mounts_revalidate(context);
}

static int
receipt_write(int directory, const char *name, const uint8_t *json,
    size_t json_size, const uint8_t commitment[32],
    const uint8_t operation_key[32])
{
    uint8_t header[RECEIPT_HEADER_SIZE], digest[32];
    char key_hex[65], temporary[96] = { 0 };
    struct byte_buffer body = { 0 };
    int descriptor = -1, result = -1;
    if (json == NULL || json_size == 0
        || json_size > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX
        || all_zero(commitment, 32) || all_zero(operation_key, 32))
        return -1;
    memset(header, 0, sizeof(header));
    memcpy(header, RECEIPT_MAGIC, 8);
    store_u32(header + 8, (uint32_t)json_size);
    memcpy(header + 12, commitment, 32);
    if (buffer_write(&body, header, 44U) != 0
        || buffer_write(&body, json, json_size) != 0
        || plamen_broker_v2_sha256(body.data, body.size, digest) != 0)
        goto done;
    memcpy(header + 44, digest, 32);
    encode_hex32(operation_key, key_hex);
    if (snprintf(temporary, sizeof(temporary), ".%s.tmp", key_hex) != 69)
        goto done;
    descriptor = openat(directory, temporary,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0 || write_all(descriptor, header, sizeof(header)) != 0
        || write_all(descriptor, json, json_size) != 0
        || full_sync(descriptor) != 0 || close(descriptor) != 0) {
        if (descriptor >= 0) (void)close(descriptor);
        descriptor = -1; goto done;
    }
    descriptor = -1;
    if (renameat(directory, temporary, directory, name) != 0
        || full_sync(directory) != 0)
        goto done;
    result = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (result != 0 && temporary[0] != '\0')
        (void)unlinkat(directory, temporary, 0);
    buffer_destroy(&body);
    plamen_broker_v2_secure_zero(header, sizeof(header));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    plamen_broker_v2_secure_zero(key_hex, sizeof(key_hex));
    return result;
}

static int
receipt_read(int directory, const char *name, uint8_t **json,
    size_t *json_size, uint8_t commitment[32])
{
    struct stat information;
    struct byte_buffer body = { 0 };
    uint8_t header[RECEIPT_HEADER_SIZE], digest[32], extra;
    uint8_t *value = NULL;
    size_t size;
    int descriptor = -1, status = -1;
    *json = NULL; *json_size = 0;
    descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return errno == ENOENT ? 0 : -1;
    if (fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_uid != geteuid() || (information.st_mode & 0077) != 0
        || information.st_size < (off_t)RECEIPT_HEADER_SIZE
        || pread_all(descriptor, header, sizeof(header)) != 0
        || memcmp(header, RECEIPT_MAGIC, 8) != 0)
        goto done;
    size = load_u32(header + 8);
    if (size == 0 || size > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX
        || information.st_size != (off_t)(RECEIPT_HEADER_SIZE + size)
        || all_zero(header + 12, 32))
        goto done;
    value = malloc(size);
    if (value == NULL
        || pread(descriptor, value, size, (off_t)RECEIPT_HEADER_SIZE)
            != (ssize_t)size
        || pread(descriptor, &extra, 1, information.st_size) != 0
        || buffer_write(&body, header, 44U) != 0
        || buffer_write(&body, value, size) != 0
        || plamen_broker_v2_sha256(body.data, body.size, digest) != 0
        || !constant_equal(digest, header + 44, 32))
        goto done;
    memcpy(commitment, header + 12, 32);
    *json = value; *json_size = size; value = NULL;
    status = 1;
done:
    if (value != NULL) { plamen_broker_v2_secure_zero(value, size); free(value); }
    if (descriptor >= 0) (void)close(descriptor);
    buffer_destroy(&body);
    plamen_broker_v2_secure_zero(header, sizeof(header));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return status;
}

static int
hex_digit(uint8_t value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static int
parse_hex32(const char *value, uint8_t output[32])
{
    size_t index;
    if (value == NULL || strlen(value) != 64U) return -1;
    for (index = 0; index < 32; ++index) {
        int high = hex_digit((uint8_t)value[index * 2U]);
        int low = hex_digit((uint8_t)value[index * 2U + 1U]);
        if (high < 0 || low < 0) return -1;
        output[index] = (uint8_t)((high << 4) | low);
    }
    return all_zero(output, 32) ? -1 : 0;
}

static int
extract_canonical_digest(const uint8_t *document, size_t document_size,
    const char *key, uint8_t output[32])
{
    char pattern[128], value[65];
    size_t pattern_size, index, match = SIZE_MAX;
    int amount;
    if (document == NULL || document_size == 0U || key == NULL
        || output == NULL) return -1;
    amount = snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    if (amount <= 0 || (size_t)amount >= sizeof(pattern)) return -1;
    pattern_size = (size_t)amount;
    for (index = 0; index + pattern_size + 65U <= document_size; ++index) {
        if (memcmp(document + index, pattern, pattern_size) == 0) {
            if (match != SIZE_MAX) return -1;
            match = index + pattern_size;
        }
    }
    if (match == SIZE_MAX || document[match + 64U] != '"') return -1;
    memcpy(value, document + match, 64U); value[64] = '\0';
    amount = parse_hex32(value, output);
    plamen_broker_v2_secure_zero(value, sizeof(value));
    return amount;
}

static int
derive_layout_handles(
    struct plamen_broker_v2_workspace_effects_context *context)
{
    static const char *names[] = { "upper", "work", "seccomp" };
    static const char *domains[] = {
        "PLAMEN-WORKSPACE-UPPER", "PLAMEN-WORKSPACE-WORK",
        "PLAMEN-WORKSPACE-SECCOMP-DIRECTORY"
    };
    int transient[3] = { -1, -1, -1 };
    uint8_t seccomp[32], workspace_identity[32], layout_identity[32];
    uint8_t layout_binding[64];
    size_t index;
    int scope_fd = context->fds[PLAMEN_BROKER_V2_RETAINED_SCOPE] >= 0
        ? context->fds[PLAMEN_BROKER_V2_RETAINED_SCOPE]
        : context->scope_private_fd;
    for (index = 0; index < 3; ++index)
        if (open_named_directory(context->workspace_fd, names[index],
                &transient[index]) != 0)
            goto fail;
    if (all_zero(context->private_mount_roster_sha256, 32)
        || stable_directory_identity(context->workspace_fd,
            workspace_identity) != 0)
        goto fail;
    memcpy(layout_binding, workspace_identity, 32);
    memcpy(layout_binding + 32, context->private_mount_roster_sha256, 32);
    if (plamen_broker_v2_sha256(layout_binding, sizeof(layout_binding),
            layout_identity) != 0
        || make_handle(context, "PLAMEN-WORKSPACE-LAYOUT",
            layout_identity, context->handles[0]) != 0
        || make_handle(context, "PLAMEN-EFFECTS-TARGET",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_TARGET].identity,
            context->handles[1]) != 0
        || make_stable_directory_handle(context, domains[0], transient[0],
            context->handles[2]) != 0
        || make_stable_directory_handle(context, domains[1], transient[1],
            context->handles[3]) != 0
        || make_stable_directory_handle(context, "PLAMEN-WORKSPACE-MERGED",
            context->merged_fd, context->handles[4]) != 0
        || make_stable_directory_handle(context, "PLAMEN-WORKSPACE-SCRATCH",
            context->scratch_fd, context->handles[5]) != 0
        || make_stable_directory_handle(context, "PLAMEN-WORKSPACE-STATE",
            context->state_fd, context->handles[6]) != 0
        || make_stable_directory_handle(context, "PLAMEN-WORKSPACE-CONTROL",
            context->control_fd, context->handles[7]) != 0
        || parse_hex32(context->seccomp_sha256, seccomp) != 0
        || make_handle(context, "PLAMEN-WORKSPACE-SECCOMP", seccomp,
            context->handles[8]) != 0
        || (context->fds[PLAMEN_BROKER_V2_RETAINED_SCOPE] >= 0
            ? make_fd_handle(context, "PLAMEN-WORKSPACE-SCOPE", scope_fd,
                context->handles[9])
            : make_stable_directory_handle(context, "PLAMEN-WORKSPACE-SCOPE",
                scope_fd, context->handles[9])) != 0
        || make_handle(context, "PLAMEN-WORKSPACE-EXPORT",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_EXPORT].identity,
            context->handles[10]) != 0
        || make_handle(context, "PLAMEN-EFFECTS-CREDENTIAL",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_CREDENTIAL].identity,
            context->handles[11]) != 0
        || make_handle(context, "PLAMEN-EFFECTS-BACKEND",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_BACKEND_PROFILE].identity,
            context->handles[12]) != 0
        || make_handle(context, "PLAMEN-EFFECTS-RUNTIME",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_RUNTIME_MANIFEST].identity,
            context->handles[13]) != 0
        || make_handle(context, "PLAMEN-EFFECTS-DOCS",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_DOCS].identity,
            context->handles[14]) != 0)
        goto fail;
    for (index = 0; index < 3; ++index) (void)close(transient[index]);
    plamen_broker_v2_secure_zero(seccomp, sizeof(seccomp));
    plamen_broker_v2_secure_zero(workspace_identity,
        sizeof(workspace_identity));
    plamen_broker_v2_secure_zero(layout_identity, sizeof(layout_identity));
    plamen_broker_v2_secure_zero(layout_binding, sizeof(layout_binding));
    return 0;
fail:
    for (index = 0; index < 3; ++index)
        if (transient[index] >= 0) (void)close(transient[index]);
    plamen_broker_v2_secure_zero(seccomp, sizeof(seccomp));
    plamen_broker_v2_secure_zero(workspace_identity,
        sizeof(workspace_identity));
    plamen_broker_v2_secure_zero(layout_identity, sizeof(layout_identity));
    plamen_broker_v2_secure_zero(layout_binding, sizeof(layout_binding));
    return -1;
}

static int
build_layout_json(struct plamen_broker_v2_workspace_effects_context *context,
    uint8_t **wire, size_t *wire_size, uint8_t commitment[32])
{
    const char *semantic =
        "{\"attempt_id\":\"%s\",\"control_handle\":\"%s\",\"export_destination_handle\":\"%s\",\"export_destination_identity_sha256\":\"%s\",\"layout_handle\":\"%s\",\"merged_handle\":\"%s\",\"private_attempt_owned\":true,\"run_id\":\"%s\",\"run_store_outside_target\":true,\"scope_handle\":\"%s\",\"scope_sha256\":\"%s\",\"scratch_handle\":\"%s\",\"seccomp_handle\":\"%s\",\"seccomp_sha256\":\"%s\",\"state_handle\":\"%s\",\"target_identity_sha256\":\"%s\",\"target_lower_handle\":\"%s\",\"target_lower_readonly\":true,\"upper_handle\":\"%s\",\"work_handle\":\"%s\"}\n";
    const char *typed =
        "{\"$type\":\"AttemptLayout\",\"fields\":{\"attempt_id\":\"%s\",\"control_handle\":\"%s\",\"export_destination_handle\":\"%s\",\"export_destination_identity_sha256\":\"%s\",\"layout_handle\":\"%s\",\"merged_handle\":\"%s\",\"private_attempt_owned\":true,\"run_id\":\"%s\",\"run_store_outside_target\":true,\"scope_handle\":\"%s\",\"scope_sha256\":\"%s\",\"scratch_handle\":\"%s\",\"seccomp_handle\":\"%s\",\"seccomp_sha256\":\"%s\",\"state_handle\":\"%s\",\"target_identity_sha256\":\"%s\",\"target_lower_handle\":\"%s\",\"target_lower_readonly\":true,\"upper_handle\":\"%s\",\"work_handle\":\"%s\"}}";
#define LAYOUT_ARGUMENTS \
    context->attempt_id, context->handles[7], context->handles[10], \
    context->export_identity_sha256, context->handles[0], \
    context->handles[4], context->run_id, context->handles[9], \
    context->scope_sha256, context->handles[5], context->handles[8], \
    context->seccomp_sha256, context->handles[6], \
    context->target_identity_sha256, context->handles[1], \
    context->handles[2], context->handles[3]
    if (semantic_commitment(semantic, commitment, LAYOUT_ARGUMENTS) != 0
        || format_alloc(wire, wire_size, typed, LAYOUT_ARGUMENTS) != 0)
        return -1;
#undef LAYOUT_ARGUMENTS
    return 0;
}

static int
existing_layout(struct plamen_broker_v2_workspace_effects_context *context,
    struct plamen_broker_v2_operations_effect_result *result, int applied)
{
    uint8_t *persisted = NULL, *wire = NULL;
    uint8_t persisted_commitment[32], commitment[32];
    size_t persisted_size = 0, wire_size = 0;
    int status;
    if (open_existing_layout(context) != 0) return -1;
    status = receipt_read(context->workspace_fd, "layout.receipt",
        &persisted, &persisted_size, persisted_commitment);
    if (status != 1 || derive_layout_handles(context) != 0
        || build_layout_json(context, &wire, &wire_size, commitment) != 0
        || wire_size != persisted_size
        || !constant_equal(wire, persisted, wire_size)
        || !constant_equal(commitment, persisted_commitment, 32)) {
        if (persisted != NULL) {
            plamen_broker_v2_secure_zero(persisted, persisted_size);
            free(persisted);
        }
        if (wire != NULL) {
            plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
        }
        return -1;
    }
    plamen_broker_v2_secure_zero(persisted, persisted_size); free(persisted);
    memcpy(context->layout_commitment, commitment, 32);
    context->layout_ready = 1;
    return result_finish(result, wire, wire_size, commitment, applied);
}

static int
workspace_exists(struct plamen_broker_v2_workspace_effects_context *context)
{
    struct stat information;
    if (fstatat(context->state_parent_fd, context->workspace_name,
            &information, AT_SYMLINK_NOFOLLOW) == 0)
        return S_ISDIR(information.st_mode) ? 1 : -1;
    return errno == ENOENT ? 0 : -1;
}

static int
discard_partial_workspace(
    struct plamen_broker_v2_workspace_effects_context *context)
{
    int descriptor = -1, result = -1;
    close_layout_descriptors(context);
    if (open_named_directory(context->state_parent_fd, context->workspace_name,
            &descriptor) != 0)
        return -1;
    if (remove_tree_contents(descriptor, 0) == 0 && close(descriptor) == 0
        && unlinkat(context->state_parent_fd, context->workspace_name,
            AT_REMOVEDIR) == 0
        && full_sync(context->state_parent_fd) == 0) {
        descriptor = -1; result = 0;
    }
    if (descriptor >= 0) (void)close(descriptor);
    return result;
}

static int
prepare_layout(struct plamen_broker_v2_workspace_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    struct plamen_broker_v2_operations_effect_result target_result;
    uint8_t target_digest[32], *wire = NULL, *persisted = NULL;
    uint8_t commitment[32], persisted_commitment[32];
    size_t wire_size = 0, persisted_size = 0;
    int exists, receipt_status;
    memset(&target_result, 0, sizeof(target_result));
    if (request->argument_count != 3
        || strcmp(request->arguments[1].name, "target") != 0
        || build_target_result(context, 1, &target_result) != 0)
        return -1;
    plamen_broker_v2_workspace_effects_dispose_result(&target_result);
    if (!constant_equal(request->arguments[1].commitment_sha256,
            context->target_commitment, 32))
        return -1;
    exists = workspace_exists(context);
    if (exists < 0) return -1;
    if (exists) {
        if (open_existing_layout(context) != 0) return -1;
        receipt_status = receipt_read(context->workspace_fd,
            "layout.receipt", &persisted, &persisted_size,
            persisted_commitment);
        close_layout_descriptors(context);
        if (receipt_status == 1) {
            if (persisted != NULL) {
                plamen_broker_v2_secure_zero(persisted, persisted_size);
                free(persisted);
            }
            return existing_layout(context, result, 1);
        }
        if (receipt_status < 0 || discard_partial_workspace(context) != 0)
            return -1;
    }
    if (create_layout_directories(context) != 0
        || populate_private_mounts(context) != 0
        || private_mounts_revalidate(context) != 0
        || target_census(context, context->merged_fd, target_digest) != 0)
        goto fail;
    {
        char current[65];
        encode_hex32(target_digest, current);
        if (strcmp(current, context->target_content_sha256) != 0)
            goto fail;
    }
    if (derive_layout_handles(context) != 0
        || build_layout_json(context, &wire, &wire_size, commitment) != 0
        || receipt_write(context->workspace_fd, "layout.receipt", wire,
            wire_size, commitment, request->operation_key) != 0
        || snapshot_fd(context->workspace_fd,
            &context->workspace_snapshot) != 0)
        goto fail;
    memcpy(context->layout_commitment, commitment, 32);
    context->layout_ready = 1;
    return result_finish(result, wire, wire_size, commitment, 1);
fail:
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
    }
    if (workspace_exists(context) == 1)
        (void)discard_partial_workspace(context);
    return -1;
}

static int
layout_available(struct plamen_broker_v2_workspace_effects_context *context)
{
    struct plamen_broker_v2_operations_effect_result temporary;
    if (context->layout_ready) return 0;
    memset(&temporary, 0, sizeof(temporary));
    if (existing_layout(context, &temporary, 0) != 0) return -1;
    plamen_broker_v2_workspace_effects_dispose_result(&temporary);
    return 0;
}

static char *
hex_bytes(const uint8_t *bytes, size_t size)
{
    static const char digits[] = "0123456789abcdef";
    char *result;
    size_t index;
    if (size > (PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX - 1U) / 2U)
        return NULL;
    result = malloc(size * 2U + 1U);
    if (result == NULL) return NULL;
    for (index = 0; index < size; ++index) {
        result[index * 2U] = digits[bytes[index] >> 4];
        result[index * 2U + 1U] = digits[bytes[index] & 15U];
    }
    result[size * 2U] = '\0';
    return result;
}

static int
build_config_json(struct plamen_broker_v2_workspace_effects_context *context,
    const char *config_handle, uint8_t **wire, size_t *wire_size,
    uint8_t commitment[32], uint8_t guest_commitment[32])
{
    char *content_hex = hex_bytes(context->guest_config,
        context->guest_config_size);
    const char *guest =
        "{\"canonical_bytes\":{\"$bytes_hex\":\"%s\"},\"config_sha256\":\"%s\",\"retained_source_handle\":\"%s\"}\n";
    const char *semantic =
        "{\"attempt_id\":\"%s\",\"config_handle\":\"%s\",\"config_sha256\":\"%s\",\"guest_config\":{\"canonical_bytes\":{\"$bytes_hex\":\"%s\"},\"config_sha256\":\"%s\",\"retained_source_handle\":\"%s\"},\"run_id\":\"%s\",\"source_config_sha256\":\"%s\",\"startup_decision_receipt_sha256\":\"%s\"}\n";
    const char *typed =
        "{\"$type\":\"ConfigReceipt\",\"fields\":{\"attempt_id\":\"%s\",\"config_handle\":\"%s\",\"config_sha256\":\"%s\",\"guest_config\":{\"$type\":\"GuestConfig\",\"fields\":{\"canonical_bytes\":{\"$bytes_hex\":\"%s\"},\"config_sha256\":\"%s\",\"retained_source_handle\":\"%s\"}},\"run_id\":\"%s\",\"source_config_sha256\":\"%s\",\"startup_decision_receipt_sha256\":\"%s\"}}";
    int status = -1;
    if (content_hex == NULL) return -1;
    if (semantic_commitment(guest, guest_commitment, content_hex,
            context->source_config_sha256, context->source_handle) != 0
        || semantic_commitment(semantic, commitment, context->attempt_id,
            config_handle, context->source_config_sha256, content_hex,
            context->source_config_sha256, context->source_handle,
            context->run_id, context->source_config_sha256,
            context->startup_receipt_sha256) != 0
        || format_alloc(wire, wire_size, typed, context->attempt_id,
            config_handle, context->source_config_sha256, content_hex,
            context->source_config_sha256, context->source_handle,
            context->run_id, context->source_config_sha256,
            context->startup_receipt_sha256) != 0)
        goto done;
    status = 0;
done:
    plamen_broker_v2_secure_zero(content_hex,
        context->guest_config_size * 2U);
    free(content_hex);
    return status;
}

static int
write_config(struct plamen_broker_v2_workspace_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    uint8_t *wire = NULL, *persisted = NULL, *existing = NULL;
    uint8_t commitment[32], guest_commitment[32], persisted_commitment[32];
    size_t wire_size = 0, persisted_size = 0;
    struct stat information;
    char config_handle[72];
    int descriptor = -1, receipt_status, present = 0;
    if (request->argument_count != 4 || layout_available(context) != 0
        || !constant_equal(request->arguments[1].commitment_sha256,
            context->layout_commitment, 32))
        return -1;
    descriptor = openat(context->control_fd, "config.json",
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor >= 0) {
        present = 1;
        if (fstat(descriptor, &information) != 0
            || !S_ISREG(information.st_mode) || information.st_nlink != 1
            || information.st_size != (off_t)context->guest_config_size)
            goto fail;
        existing = malloc(context->guest_config_size);
        if (existing == NULL || pread_all(descriptor, existing,
                context->guest_config_size) != 0
            || !constant_equal(existing, context->guest_config,
                context->guest_config_size))
            goto fail;
    } else if (errno != ENOENT) {
        goto fail;
    }
    if (!present) {
        descriptor = openat(context->control_fd, ".config.tmp",
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (descriptor < 0
            || write_all(descriptor, context->guest_config,
                context->guest_config_size) != 0
            || full_sync(descriptor) != 0 || close(descriptor) != 0) {
            if (descriptor >= 0) (void)close(descriptor);
            descriptor = -1; goto fail;
        }
        descriptor = -1;
        if (renameat(context->control_fd, ".config.tmp", context->control_fd,
                "config.json") != 0 || full_sync(context->control_fd) != 0)
            goto fail;
        descriptor = openat(context->control_fd, "config.json",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0) goto fail;
    }
    if (make_fd_handle(context, "PLAMEN-WORKSPACE-CONFIG", descriptor,
            config_handle) != 0
        || build_config_json(context, config_handle, &wire, &wire_size,
            commitment, guest_commitment) != 0
        || !constant_equal(request->arguments[2].commitment_sha256,
            guest_commitment, 32))
        goto fail;
    receipt_status = receipt_read(context->control_fd, "config.receipt",
        &persisted, &persisted_size, persisted_commitment);
    if (receipt_status < 0
        || (receipt_status == 1 && (persisted_size != wire_size
            || !constant_equal(persisted, wire, wire_size)
            || !constant_equal(persisted_commitment, commitment, 32))))
        goto fail;
    if (receipt_status == 0
        && receipt_write(context->control_fd, "config.receipt", wire,
            wire_size, commitment, request->operation_key) != 0)
        goto fail;
    memcpy(context->config_commitment, commitment, 32);
    context->config_ready = 1;
    if (descriptor >= 0) (void)close(descriptor);
    if (existing != NULL) {
        plamen_broker_v2_secure_zero(existing, context->guest_config_size);
        free(existing);
    }
    if (persisted != NULL) {
        plamen_broker_v2_secure_zero(persisted, persisted_size); free(persisted);
    }
    return result_finish(result, wire, wire_size, commitment, 1);
fail:
    if (descriptor >= 0) (void)close(descriptor);
    if (existing != NULL) {
        plamen_broker_v2_secure_zero(existing, context->guest_config_size);
        free(existing);
    }
    if (persisted != NULL) {
        plamen_broker_v2_secure_zero(persisted, persisted_size); free(persisted);
    }
    if (wire != NULL) {
        plamen_broker_v2_secure_zero(wire, wire_size); free(wire);
    }
    (void)unlinkat(context->control_fd, ".config.tmp", 0);
    return -1;
}

static int
extract_projection_alloc_string(const uint8_t *projection,
    size_t projection_size, const char *key, char **output)
{
    char pattern[160];
    size_t pattern_size, index, start = 0, found = 0, value_size;
    int amount;
    char *value;
    if (projection == NULL || key == NULL || output == NULL) return -1;
    *output = NULL;
    amount = snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    if (amount <= 0 || (size_t)amount >= sizeof(pattern)) return -1;
    pattern_size = (size_t)amount;
    for (index = 0; index + pattern_size <= projection_size; ++index) {
        if (memcmp(projection + index, pattern, pattern_size) == 0) {
            if (++found != 1) return -1;
            start = index + pattern_size;
        }
    }
    if (found != 1) return -1;
    index = start;
    while (index < projection_size && projection[index] != '"') {
        if (projection[index] < 0x20U || projection[index] > 0x7eU
            || projection[index] == '\\') return -1;
        ++index;
    }
    if (index >= projection_size || index == start) return -1;
    value_size = index - start;
    value = malloc(value_size + 1U);
    if (value == NULL) return -1;
    memcpy(value, projection + start, value_size); value[value_size] = '\0';
    *output = value;
    return 0;
}

static int
recensus_component_digest(int descriptor, const char *phase,
    const char *purpose, uint8_t read_only, uint8_t identity[32],
    uint8_t provider_identity[32])
{
    static const uint8_t domain[] = "PLAMEN-WORKSPACE-PROVIDER-MOUNT-V1\0";
    struct byte_buffer binding = { 0 };
    int result = -1;
    if (descriptor < 0 || phase == NULL || purpose == NULL
        || plamen_broker_v2_fd_identity(descriptor, identity) != 0
        || buffer_write(&binding, domain, sizeof(domain)) != 0
        || buffer_write(&binding, phase, strlen(phase) + 1U) != 0
        || buffer_write(&binding, purpose, strlen(purpose) + 1U) != 0
        || buffer_write(&binding, identity, 32) != 0
        || buffer_write(&binding, &read_only, 1U) != 0
        || plamen_broker_v2_sha256(binding.data, binding.size,
            provider_identity) != 0)
        goto done;
    result = 0;
done:
    buffer_destroy(&binding);
    return result;
}

static int
append_allocated(struct byte_buffer *buffer, uint8_t *value, size_t size)
{
    int result = buffer_write(buffer, value, size);
    if (value != NULL) {
        plamen_broker_v2_secure_zero(value, size);
        free(value);
    }
    return result;
}

static int
build_layout_recensus(
    struct plamen_broker_v2_workspace_effects_context *context,
    const char *phase, const uint8_t operation_key[32],
    struct plamen_broker_v2_operations_effect_result *result)
{
    static const char *purposes[11] = {
        "target-lower", "project-merged", "scratch", "state", "control",
        "seccomp", "credentials", "backend-context", "runtime", "docs",
        "scope"
    };
    static const char *attachments[11] = {
        "HOST_OVERLAY_LOWER", "/workspace/project", "/workspace/scratch",
        "/workspace/state", "/workspace/control", "/run/plamen/seccomp",
        "/run/plamen/credentials", "/run/plamen/backend", "/opt/plamen",
        "/workspace/docs", "/workspace/scope"
    };
    static const char *modes[11] = {
        "ro", "ro", "rw", "rw", "ro", "ro", "ro", "ro", "ro", "ro",
        "ro"
    };
    const int descriptors[11] = {
        context->fds[PLAMEN_BROKER_V2_RETAINED_TARGET], context->merged_fd,
        context->scratch_fd, context->state_fd, context->control_fd,
        context->seccomp_fd, context->credentials_fd,
        context->backend_private_fd, context->runtime_private_fd,
        context->docs_private_fd, context->scope_private_fd
    };
    const char *handles[11] = {
        context->handles[1], context->handles[4], context->handles[5],
        context->handles[6], context->handles[7], context->handles[8],
        context->handles[11], context->handles[12], context->handles[13],
        context->handles[14], context->handles[9]
    };
    struct byte_buffer stable_components = { 0 }, provider_mounts = { 0 };
    struct byte_buffer semantic_components = { 0 }, typed_components = { 0 };
    struct tree_limits limits;
    uint8_t identities[11][32], provider_identities[11][32];
    uint8_t scratch_content[32], state_content[32], control_content[32];
    uint8_t layout_sha[32], commitment[32], provider_mounts_sha256[32];
    char identity_hex[65], provider_hex[65], layout_hex[65], commitment_hex[65];
    char scratch_hex[65], state_hex[65], control_hex[65];
    const char *contents[11];
    uint8_t *row = NULL, *stable = NULL, *semantic = NULL, *wire = NULL;
    uint8_t *persisted = NULL;
    size_t row_size = 0, stable_size = 0, semantic_size = 0, wire_size = 0;
    size_t persisted_size = 0;
    uint8_t **stored;
    size_t *stored_size;
    uint8_t *stored_commitment;
    uint8_t *stored_provider_mounts_sha256;
    uint8_t *stored_layout_sha256;
    size_t index;
    uint8_t persisted_commitment[32];
    const char *receipt_name;
    int receipt_status, status = -1;
    if (context == NULL || result == NULL || !context->layout_ready
        || !context->config_ready
        || (strcmp(phase, "PRE_CREATE") != 0
            && strcmp(phase, "POST_CREATE") != 0)
        || operation_key == NULL || all_zero(operation_key, 32)
        || plamen_broker_v2_workspace_effects_revalidate(context) != 0)
        return -1;
    receipt_name = strcmp(phase, "PRE_CREATE") == 0
        ? "precreate-recensus.receipt" : "postcreate-recensus.receipt";
    memset(&limits, 0, sizeof(limits));
    if (scan_directory(context->scratch_fd, -1, 0, &limits, scratch_content) != 0)
        goto done;
    memset(&limits, 0, sizeof(limits));
    if (scan_directory(context->state_fd, -1, 0, &limits, state_content) != 0
        || semantic_commitment(
            "{\"config_sha256\":\"%s\",\"startup_decision_receipt_sha256\":\"%s\"}\n",
            control_content, context->source_config_sha256,
            context->startup_receipt_sha256) != 0)
        goto done;
    encode_hex32(scratch_content, scratch_hex);
    encode_hex32(state_content, state_hex);
    encode_hex32(control_content, control_hex);
    contents[0] = context->target_content_sha256;
    contents[1] = context->target_content_sha256;
    contents[2] = scratch_hex; contents[3] = state_hex; contents[4] = control_hex;
    contents[5] = context->seccomp_sha256;
    contents[6] = context->credential_bundle_sha256;
    contents[7] = context->backend_context_sha256;
    contents[8] = context->runtime_layout_sha256;
    contents[9] = context->docs_sha256; contents[10] = context->scope_sha256;
    if (buffer_write(&stable_components, "[", 1U) != 0
        || buffer_write(&semantic_components, "[", 1U) != 0
        || buffer_write(&provider_mounts, "[", 1U) != 0
        || buffer_write(&typed_components, "{\"$tuple\":[", 11U) != 0)
        goto done;
    for (index = 0; index < 11U; ++index) {
        if (recensus_component_digest(descriptors[index], phase,
                purposes[index], modes[index][0] == 'r' && modes[index][1] == 'o',
                identities[index], provider_identities[index]) != 0)
            goto done;
        encode_hex32(identities[index], identity_hex);
        encode_hex32(provider_identities[index], provider_hex);
        if (index != 0U
            && (buffer_write(&stable_components, ",", 1U) != 0
                || buffer_write(&semantic_components, ",", 1U) != 0
                || buffer_write(&provider_mounts, ",", 1U) != 0
                || buffer_write(&typed_components, ",", 1U) != 0))
            goto done;
        if (format_alloc(&row, &row_size,
                "{\"attachment\":\"%s\",\"content_sha256\":\"%s\",\"identity_sha256\":\"%s\",\"mode\":\"%s\",\"purpose\":\"%s\",\"source_handle\":\"%s\"}",
                attachments[index], contents[index], identity_hex, modes[index],
                purposes[index], handles[index]) != 0
            || append_allocated(&stable_components, row, row_size) != 0)
            goto done;
        row = NULL; row_size = 0;
        if (format_alloc(&row, &row_size, "[\"%s\",\"%s\"]",
                purposes[index], provider_hex) != 0
            || append_allocated(&provider_mounts, row, row_size) != 0)
            goto done;
        row = NULL; row_size = 0;
        if (format_alloc(&row, &row_size,
                "{\"attachment\":\"%s\",\"content_sha256\":\"%s\",\"identity_sha256\":\"%s\",\"mode\":\"%s\",\"provider_mount_identity_sha256\":\"%s\",\"purpose\":\"%s\",\"source_handle\":\"%s\"}",
                attachments[index], contents[index], identity_hex, modes[index],
                provider_hex, purposes[index], handles[index]) != 0
            || append_allocated(&semantic_components, row, row_size) != 0)
            goto done;
        row = NULL; row_size = 0;
        if (format_alloc(&row, &row_size,
                "{\"$type\":\"LayoutComponent\",\"fields\":{\"attachment\":\"%s\",\"content_sha256\":\"%s\",\"identity_sha256\":\"%s\",\"mode\":\"%s\",\"provider_mount_identity_sha256\":\"%s\",\"purpose\":\"%s\",\"source_handle\":\"%s\"}}",
                attachments[index], contents[index], identity_hex, modes[index],
                provider_hex, purposes[index], handles[index]) != 0
            || append_allocated(&typed_components, row, row_size) != 0)
            goto done;
        row = NULL; row_size = 0;
    }
    if (buffer_write(&stable_components, "]", 1U) != 0
        || buffer_write(&semantic_components, "]", 1U) != 0
        || buffer_write(&provider_mounts, "]\n", 2U) != 0
        || buffer_write(&typed_components, "]}", 2U) != 0
        || plamen_broker_v2_sha256(provider_mounts.data,
            provider_mounts.size, provider_mounts_sha256) != 0
        || format_alloc(&stable, &stable_size,
            "{\"attempt_id\":\"%s\",\"components\":%.*s,\"layout_handle\":\"%s\",\"target_content_sha256\":\"%s\",\"target_identity_sha256\":\"%s\"}\n",
            context->attempt_id, (int)stable_components.size,
            stable_components.data, context->handles[0],
            context->target_content_sha256, context->target_identity_sha256) != 0
        || plamen_broker_v2_sha256(stable, stable_size, layout_sha) != 0)
        goto done;
    encode_hex32(layout_sha, layout_hex);
    if (format_alloc(&semantic, &semantic_size,
            "{\"attempt_id\":\"%s\",\"components\":%.*s,\"layout_handle\":\"%s\",\"layout_sha256\":\"%s\",\"phase\":\"%s\",\"target_content_sha256\":\"%s\",\"target_identity_sha256\":\"%s\",\"target_lower_readonly\":true,\"workload_nonexecuting\":true}\n",
            context->attempt_id, (int)semantic_components.size,
            semantic_components.data, context->handles[0], layout_hex, phase,
            context->target_content_sha256, context->target_identity_sha256) != 0
        || plamen_broker_v2_sha256(semantic, semantic_size, commitment) != 0)
        goto done;
    encode_hex32(commitment, commitment_hex);
    if (format_alloc(&wire, &wire_size,
            "{\"$type\":\"LayoutRecensus\",\"fields\":{\"attempt_id\":\"%s\",\"components\":%.*s,\"layout_handle\":\"%s\",\"layout_sha256\":\"%s\",\"phase\":\"%s\",\"target_content_sha256\":\"%s\",\"target_identity_sha256\":\"%s\",\"target_lower_readonly\":true,\"workload_nonexecuting\":true}}",
            context->attempt_id, (int)typed_components.size,
            typed_components.data, context->handles[0], layout_hex, phase,
            context->target_content_sha256, context->target_identity_sha256) != 0)
        goto done;
    stored = strcmp(phase, "PRE_CREATE") == 0
        ? &context->precreate_recensus : &context->postcreate_recensus;
    stored_size = strcmp(phase, "PRE_CREATE") == 0
        ? &context->precreate_recensus_size : &context->postcreate_recensus_size;
    stored_commitment = strcmp(phase, "PRE_CREATE") == 0
        ? context->precreate_recensus_commitment
        : context->postcreate_recensus_commitment;
    stored_provider_mounts_sha256 = strcmp(phase, "PRE_CREATE") == 0
        ? context->precreate_provider_mounts_sha256
        : context->postcreate_provider_mounts_sha256;
    stored_layout_sha256 = strcmp(phase, "PRE_CREATE") == 0
        ? context->precreate_layout_sha256
        : context->postcreate_layout_sha256;
    receipt_status = receipt_read(context->workspace_fd, receipt_name,
        &persisted, &persisted_size, persisted_commitment);
    if (receipt_status < 0
        || (receipt_status == 1
            && (persisted_size != wire_size
                || !constant_equal(persisted, wire, wire_size)
                || !constant_equal(persisted_commitment, commitment, 32)))
        || (receipt_status == 0
            && receipt_write(context->workspace_fd, receipt_name, wire,
                wire_size, commitment, operation_key) != 0))
        goto done;
    if (*stored != NULL
        && (*stored_size != wire_size || memcmp(*stored, wire, wire_size) != 0
            || !constant_equal(stored_commitment, commitment, 32)
            || !constant_equal(stored_provider_mounts_sha256,
                provider_mounts_sha256, 32)
            || !constant_equal(stored_layout_sha256, layout_sha, 32)))
        goto done;
    if (strcmp(phase, "POST_CREATE") == 0
        && (all_zero(context->precreate_layout_sha256, 32)
            || !constant_equal(context->precreate_layout_sha256,
                layout_sha, 32)))
        goto done;
    if (*stored == NULL) {
        *stored = malloc(wire_size);
        if (*stored == NULL) goto done;
        memcpy(*stored, wire, wire_size); *stored_size = wire_size;
        memcpy(stored_commitment, commitment, 32);
        memcpy(stored_provider_mounts_sha256, provider_mounts_sha256, 32);
        memcpy(stored_layout_sha256, layout_sha, 32);
    }
    status = result_finish(result, wire, wire_size, commitment, 0);
    if (status == 0) wire = NULL;
done:
    if (row != NULL) { plamen_broker_v2_secure_zero(row, row_size); free(row); }
    if (stable != NULL) { plamen_broker_v2_secure_zero(stable, stable_size); free(stable); }
    if (semantic != NULL) { plamen_broker_v2_secure_zero(semantic, semantic_size); free(semantic); }
    if (wire != NULL) { plamen_broker_v2_secure_zero(wire, wire_size); free(wire); }
    if (persisted != NULL) {
        plamen_broker_v2_secure_zero(persisted, persisted_size);
        free(persisted);
    }
    buffer_destroy(&stable_components);
    buffer_destroy(&provider_mounts);
    buffer_destroy(&semantic_components); buffer_destroy(&typed_components);
    plamen_broker_v2_secure_zero(identities, sizeof(identities));
    plamen_broker_v2_secure_zero(provider_identities, sizeof(provider_identities));
    plamen_broker_v2_secure_zero(scratch_content, sizeof(scratch_content));
    plamen_broker_v2_secure_zero(state_content, sizeof(state_content));
    plamen_broker_v2_secure_zero(control_content, sizeof(control_content));
    plamen_broker_v2_secure_zero(layout_sha, sizeof(layout_sha));
    plamen_broker_v2_secure_zero(commitment, sizeof(commitment));
    plamen_broker_v2_secure_zero(provider_mounts_sha256,
        sizeof(provider_mounts_sha256));
    plamen_broker_v2_secure_zero(commitment_hex, sizeof(commitment_hex));
    return status;
}

int
plamen_broker_v2_workspace_effects_capture_recensus(
    struct plamen_broker_v2_workspace_effects_context *context,
    const char *phase, const uint8_t operation_key[32],
    struct plamen_broker_v2_operations_effect_result *result)
{
    if (result != NULL) memset(result, 0, sizeof(*result));
    return build_layout_recensus(context, phase, operation_key, result);
}

static int
authority_fd_valid(
    const struct plamen_broker_v2_service_registration *registration,
    const int *descriptors, size_t index, struct fd_snapshot *snapshot)
{
    struct stat information;
    uint8_t identity[32];
    int flags, open_flags, present;
    present = (registration->authority_presence_mask
        & (uint16_t)(UINT16_C(1) << index)) != 0;
    if (!present) return descriptors[index] == -1 ? 0 : -1;
    if (descriptors[index] < 0
        || (flags = fcntl(descriptors[index], F_GETFD)) < 0
        || (flags & FD_CLOEXEC) == 0
        || (open_flags = fcntl(descriptors[index], F_GETFL)) < 0
        || (open_flags & O_ACCMODE) != O_RDONLY
        || fstat(descriptors[index], &information) != 0
        || ((index == PLAMEN_BROKER_V2_RETAINED_TARGET
                || index == PLAMEN_BROKER_V2_RETAINED_EXPORT)
            ? !S_ISDIR(information.st_mode)
            : (index == PLAMEN_BROKER_V2_RETAINED_DOCS
                ? !(S_ISDIR(information.st_mode)
                    || (S_ISREG(information.st_mode)
                        && information.st_nlink == 1))
                : !(S_ISREG(information.st_mode)
                    && (index == PLAMEN_BROKER_V2_RETAINED_CREDENTIAL
                        ? information.st_nlink == 0
                        : information.st_nlink == 1))))
        || plamen_broker_v2_fd_identity(descriptors[index], identity) != 0
        || !constant_equal(identity,
            registration->authority_descriptors[index].identity, 32)
        || snapshot_fd(descriptors[index], snapshot) != 0) {
        plamen_broker_v2_secure_zero(identity, sizeof(identity));
        return -1;
    }
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    return 0;
}

static int
private_parent(int descriptor, struct fd_snapshot *snapshot)
{
    struct stat information;
    int flags, open_flags;
    return descriptor >= 0
        && (flags = fcntl(descriptor, F_GETFD)) >= 0
        && (flags & FD_CLOEXEC) != 0
        && (open_flags = fcntl(descriptor, F_GETFL)) >= 0
        && (open_flags & O_ACCMODE) == O_RDONLY
        && fstat(descriptor, &information) == 0
        && S_ISDIR(information.st_mode) && information.st_uid == geteuid()
        && (information.st_mode & 0077) == 0
        && snapshot_fd(descriptor, snapshot) == 0 ? 0 : -1;
}

static int
load_projection(struct plamen_broker_v2_workspace_effects_context *context)
{
    char *base64 = NULL;
    uint8_t sha[32];
    char expected[72];
    int result = -1;
    if (extract_projection_string(context->projection, context->projection_size,
            "attempt_id", context->attempt_id, sizeof(context->attempt_id)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "run_id", context->run_id,
            sizeof(context->run_id)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "retained_source_handle",
            context->source_handle, sizeof(context->source_handle)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "source_config_sha256",
            context->source_config_sha256,
            sizeof(context->source_config_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "startup_decision_receipt_sha256",
            context->startup_receipt_sha256,
            sizeof(context->startup_receipt_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "target_identity_sha256",
            context->target_identity_sha256,
            sizeof(context->target_identity_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "scope_sha256", context->scope_sha256,
            sizeof(context->scope_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "seccomp_profile_sha256",
            context->seccomp_sha256, sizeof(context->seccomp_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "export_destination_identity_sha256",
            context->export_identity_sha256,
            sizeof(context->export_identity_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "runtime_layout_sha256",
            context->runtime_layout_sha256,
            sizeof(context->runtime_layout_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "docs_sha256", context->docs_sha256,
            sizeof(context->docs_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "backend_context_sha256",
            context->backend_context_sha256,
            sizeof(context->backend_context_sha256)) != 0
        || extract_projection_string(context->projection,
            context->projection_size, "credential_bundle_sha256",
            context->credential_bundle_sha256,
            sizeof(context->credential_bundle_sha256)) != 0
        || extract_projection_alloc_string(context->projection,
            context->projection_size, "canonical_utf8_b64", &base64) != 0
        || decode_base64(base64, &context->guest_config,
            &context->guest_config_size) != 0
        || plamen_broker_v2_sha256(context->guest_config,
            context->guest_config_size, sha) != 0) goto done;
    encode_hex32(sha, expected);
    if (strcmp(expected, context->source_config_sha256) != 0) goto done;
    memcpy(expected, "opaque:", 7U);
    encode_hex32(context->registration.authority_descriptors[
        PLAMEN_BROKER_V2_RETAINED_CONFIG].identity, expected + 7U);
    if (strcmp(expected, context->source_handle) != 0) goto done;
    encode_hex32(context->registration.authority_descriptors[
        PLAMEN_BROKER_V2_RETAINED_TARGET].identity, expected);
    if (strcmp(expected, context->target_identity_sha256) != 0) goto done;
    encode_hex32(context->registration.authority_descriptors[
        PLAMEN_BROKER_V2_RETAINED_EXPORT].identity, expected);
    if (strcmp(expected, context->export_identity_sha256) != 0) goto done;
    if (make_handle(context, "PLAMEN-EFFECTS-TARGET",
            context->registration.authority_descriptors[
                PLAMEN_BROKER_V2_RETAINED_TARGET].identity,
            context->handles[1]) != 0)
        goto done;
    result = 0;
done:
    if (base64 != NULL) {
        plamen_broker_v2_secure_zero(base64, strlen(base64)); free(base64);
    }
    plamen_broker_v2_secure_zero(sha, sizeof(sha));
    plamen_broker_v2_secure_zero(expected, sizeof(expected));
    return result;
}

int
plamen_broker_v2_workspace_effects_create(
    const struct plamen_broker_v2_workspace_effects_open *open,
    struct plamen_broker_v2_workspace_effects_context **output)
{
    struct plamen_broker_v2_workspace_effects_context *context = NULL;
    struct plamen_broker_v2_commitment commitment;
    char fingerprint[65];
    size_t index;
    int required, status = -1;
    if (output != NULL) *output = NULL;
    if (open == NULL || output == NULL
        || open->version != PLAMEN_BROKER_V2_WORKSPACE_EFFECTS_VERSION
        || open->registration == NULL || open->request_projection == NULL
        || open->request_projection_size == 0
        || open->generation_fd < 0
        || open->authority_fds == NULL
        || open->authority_fd_count
            != PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT)
        return -1;
    memset(&commitment, 0, sizeof(commitment));
    if (plamen_broker_v2_request_projection_validate_exact(
            open->request_projection, open->request_projection_size,
            open->registration->request_projection_sha256,
            open->registration->commitment,
            open->registration->commitment_size,
            open->registration->commitment_sha256, &commitment) != 0)
        goto done;
    context = calloc(1, sizeof(*context));
    if (context == NULL) goto done;
    context->magic = WORKSPACE_MAGIC;
    context->state_parent_fd = context->generation_fd = -1;
    context->workspace_fd = context->merged_fd = context->scratch_fd = -1;
    context->state_fd = context->control_fd = context->seccomp_fd = -1;
    context->credentials_fd = context->backend_private_fd = -1;
    context->runtime_private_fd = context->docs_private_fd = -1;
    context->scope_private_fd = -1;
    for (index = 0;
            index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index)
        context->fds[index] = -1;
    context->registration = *open->registration;
    context->projection = malloc(open->request_projection_size);
    if (context->projection == NULL) goto done;
    memcpy(context->projection, open->request_projection,
        open->request_projection_size);
    context->projection_size = open->request_projection_size;
    if (private_parent(open->state_parent_fd,
            &context->state_parent_snapshot) != 0
        || (context->state_parent_fd = duplicate_cloexec(
            open->state_parent_fd)) < 0
        || snapshot_fd(open->generation_fd, &context->generation_snapshot) != 0
        || !S_ISDIR(context->generation_snapshot.mode)
        || (context->generation_fd = duplicate_cloexec(
            open->generation_fd)) < 0)
        goto done;
    for (index = 0;
            index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index) {
        required = index != PLAMEN_BROKER_V2_RETAINED_DOCS
            && index != PLAMEN_BROKER_V2_RETAINED_SCOPE
            && index != PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT;
        if ((required && open->authority_fds[index] < 0)
            || authority_fd_valid(open->registration, open->authority_fds,
                index, &context->snapshots[index]) != 0)
            goto done;
        if (open->authority_fds[index] >= 0
            && (context->fds[index] = duplicate_cloexec(
                open->authority_fds[index])) < 0)
            goto done;
    }
    if (load_projection(context) != 0) goto done;
    encode_hex32(context->registration.audit_request_fingerprint, fingerprint);
    if (snprintf(context->workspace_name, sizeof(context->workspace_name),
            "workspace-%s", fingerprint) != 74)
        goto done;
    *output = context; context = NULL; status = 0;
done:
    if (context != NULL) plamen_broker_v2_workspace_effects_destroy(context);
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    plamen_broker_v2_secure_zero(fingerprint, sizeof(fingerprint));
    return status;
}

int
plamen_broker_v2_workspace_effects_revalidate(
    struct plamen_broker_v2_workspace_effects_context *context)
{
    struct fd_snapshot actual;
    uint8_t identity[32], digest[32];
    char content[65];
    size_t index;
    if (context == NULL || context->magic != WORKSPACE_MAGIC) return -1;
    if (snapshot_fd(context->state_parent_fd, &actual) != 0
        || actual.device != context->state_parent_snapshot.device
        || actual.inode != context->state_parent_snapshot.inode
        || actual.uid != context->state_parent_snapshot.uid
        || actual.mode != context->state_parent_snapshot.mode)
        return -1;
    if (snapshot_fd(context->generation_fd, &actual) != 0
        || !snapshot_same(&context->generation_snapshot, &actual))
        return -1;
    for (index = 0;
            index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index) {
        if (context->fds[index] < 0) continue;
        if (snapshot_fd(context->fds[index], &actual) != 0
            || plamen_broker_v2_fd_identity(context->fds[index], identity) != 0
            || !constant_equal(identity,
                context->registration.authority_descriptors[index].identity,
                32))
            return -1;
        if (index != PLAMEN_BROKER_V2_RETAINED_TARGET
            && index != PLAMEN_BROKER_V2_RETAINED_DOCS
            && index != PLAMEN_BROKER_V2_RETAINED_EXPORT
            && !snapshot_same(&actual, &context->snapshots[index]))
            return -1;
        if ((index == PLAMEN_BROKER_V2_RETAINED_TARGET
                || index == PLAMEN_BROKER_V2_RETAINED_DOCS
                || index == PLAMEN_BROKER_V2_RETAINED_EXPORT)
            && (actual.device != context->snapshots[index].device
                || actual.inode != context->snapshots[index].inode
                || actual.mode != context->snapshots[index].mode
                || actual.uid != context->snapshots[index].uid))
            return -1;
    }
    if (context->target_content_sha256[0] != '\0') {
        if (target_census(context, -1, digest) != 0) return -1;
        encode_hex32(digest, content);
        if (strcmp(content, context->target_content_sha256) != 0) return -1;
    }
    if (context->layout_ready && private_mounts_revalidate(context) != 0)
        return -1;
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    plamen_broker_v2_secure_zero(content, sizeof(content));
    return 0;
}

int
plamen_broker_v2_workspace_effects_execute(
    struct plamen_broker_v2_workspace_effects_context *context,
    const struct plamen_broker_v2_operations_effect_request *request,
    struct plamen_broker_v2_operations_effect_result *result)
{
    int status;
    if (context == NULL || context->magic != WORKSPACE_MAGIC
        || request == NULL || result == NULL
        || request->version != PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION)
        return -1;
    if (request->member != PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE) return 0;
    memset(result, 0, sizeof(*result));
    if (plamen_broker_v2_workspace_effects_revalidate(context) != 0)
        return -1;
    switch (request->method) {
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET:
        status = request->argument_count == 1
            ? build_target_result(context, 1, result) : -1;
        break;
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_REVALIDATE_TARGET:
        status = request->argument_count == 2
            && !all_zero(context->target_commitment, 32)
            && constant_equal(request->arguments[1].commitment_sha256,
                context->target_commitment, 32)
            ? build_target_result(context, 0, result) : -1;
        break;
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_PREPARE_LAYOUT:
        status = prepare_layout(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_RESUME_LAYOUT:
        status = request->argument_count == 2
            && layout_available(context) == 0
            && constant_equal(request->arguments[1].commitment_sha256,
                context->layout_commitment, 32)
            ? existing_layout(context, result, 0) : -1;
        break;
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_WRITE_GUEST_CONFIG:
        status = write_config(context, request, result);
        break;
    case PLAMEN_BROKER_V2_METHOD_WORKSPACE_RECENSUS_LAYOUT:
        status = request->argument_count == 7U
            && constant_equal(request->arguments[1].commitment_sha256,
                context->target_commitment, 32)
            && constant_equal(request->arguments[2].commitment_sha256,
                context->layout_commitment, 32)
            && constant_equal(request->arguments[5].commitment_sha256,
                context->config_commitment, 32)
            && request->arguments[6].scalar != NULL
            && request->arguments[6].scalar_size > 0U
            && request->arguments[6].scalar_size < 16U
            && strlen(request->arguments[6].scalar)
                == request->arguments[6].scalar_size
            ? plamen_broker_v2_workspace_effects_capture_recensus(
                context, request->arguments[6].scalar,
                request->operation_key, result)
            : -1;
        break;
    default:
        return 0;
    }
    return status == 0 ? 1 : -1;
}

void
plamen_broker_v2_workspace_effects_dispose_result(
    struct plamen_broker_v2_operations_effect_result *result)
{
    if (result == NULL) return;
    if (result->canonical_result != NULL) {
        plamen_broker_v2_secure_zero((void *)result->canonical_result,
            result->canonical_result_size);
        free((void *)result->canonical_result);
    }
    plamen_broker_v2_secure_zero(result, sizeof(*result));
}

int
plamen_broker_v2_workspace_effects_layout_commitment(
    struct plamen_broker_v2_workspace_effects_context *context,
    uint8_t output[32])
{
    if (output != NULL) memset(output, 0, 32);
    if (context == NULL || context->magic != WORKSPACE_MAGIC || output == NULL
        || layout_available(context) != 0
        || plamen_broker_v2_workspace_effects_revalidate(context) != 0
        || all_zero(context->layout_commitment, 32))
        return -1;
    memcpy(output, context->layout_commitment, 32);
    if (plamen_broker_v2_workspace_effects_revalidate(context) != 0) {
        memset(output, 0, 32);
        return -1;
    }
    return 0;
}

int
plamen_broker_v2_workspace_effects_borrow_fd(
    struct plamen_broker_v2_workspace_effects_context *context,
    uint16_t purpose)
{
    if (context == NULL || context->magic != WORKSPACE_MAGIC) return -1;
    switch (purpose) {
    case PLAMEN_BROKER_V2_WORKSPACE_LAYOUT_ROOT: return context->workspace_fd;
    case PLAMEN_BROKER_V2_WORKSPACE_MERGED: return context->merged_fd;
    case PLAMEN_BROKER_V2_WORKSPACE_SCRATCH: return context->scratch_fd;
    case PLAMEN_BROKER_V2_WORKSPACE_STATE: return context->state_fd;
    case PLAMEN_BROKER_V2_WORKSPACE_CONTROL: return context->control_fd;
    case PLAMEN_BROKER_V2_WORKSPACE_EXPORT:
        return context->fds[PLAMEN_BROKER_V2_RETAINED_EXPORT];
    case PLAMEN_BROKER_V2_WORKSPACE_TARGET:
        return context->fds[PLAMEN_BROKER_V2_RETAINED_TARGET];
    case PLAMEN_BROKER_V2_WORKSPACE_DOCS:
        return context->docs_private_fd;
    case PLAMEN_BROKER_V2_WORKSPACE_SCOPE:
        return context->scope_private_fd;
    case PLAMEN_BROKER_V2_WORKSPACE_SECCOMP: return context->seccomp_fd;
    case PLAMEN_BROKER_V2_WORKSPACE_CREDENTIALS:
        return context->credentials_fd;
    case PLAMEN_BROKER_V2_WORKSPACE_BACKEND:
        return context->backend_private_fd;
    case PLAMEN_BROKER_V2_WORKSPACE_RUNTIME:
        return context->runtime_private_fd;
    default: return -1;
    }
}

int
plamen_broker_v2_workspace_effects_borrow_mount(
    struct plamen_broker_v2_workspace_effects_context *context,
    uint16_t purpose, struct plamen_broker_v2_workspace_mount_view *view)
{
    struct stat descriptor_info, path_info, after;
    int descriptor;
    uint8_t read_only;
    if (view != NULL) memset(view, 0, sizeof(*view));
    if (context == NULL || context->magic != WORKSPACE_MAGIC || view == NULL
        || !context->layout_ready || !context->config_ready
        || plamen_broker_v2_workspace_effects_revalidate(context) != 0)
        return -1;
    switch (purpose) {
    case PLAMEN_BROKER_V2_WORKSPACE_MERGED:
    case PLAMEN_BROKER_V2_WORKSPACE_CONTROL:
    case PLAMEN_BROKER_V2_WORKSPACE_SECCOMP:
    case PLAMEN_BROKER_V2_WORKSPACE_CREDENTIALS:
    case PLAMEN_BROKER_V2_WORKSPACE_BACKEND:
    case PLAMEN_BROKER_V2_WORKSPACE_RUNTIME:
    case PLAMEN_BROKER_V2_WORKSPACE_DOCS:
    case PLAMEN_BROKER_V2_WORKSPACE_SCOPE:
        read_only = 1U;
        break;
    case PLAMEN_BROKER_V2_WORKSPACE_SCRATCH:
    case PLAMEN_BROKER_V2_WORKSPACE_STATE:
        read_only = 0U;
        break;
    default:
        return -1;
    }
    descriptor = plamen_broker_v2_workspace_effects_borrow_fd(context, purpose);
    if (descriptor < 0 || fstat(descriptor, &descriptor_info) != 0
        || !S_ISDIR(descriptor_info.st_mode)) return -1;
#ifdef F_GETPATH
    if (fcntl(descriptor, F_GETPATH, view->source_path) != 0)
        return -1;
#else
    return -1;
#endif
    if (view->source_path[0] != '/'
        || lstat(view->source_path, &path_info) != 0
        || S_ISLNK(path_info.st_mode) || !S_ISDIR(path_info.st_mode)
        || descriptor_info.st_dev != path_info.st_dev
        || descriptor_info.st_ino != path_info.st_ino
        || descriptor_info.st_mode != path_info.st_mode
        || descriptor_info.st_uid != path_info.st_uid
        || fstat(descriptor, &after) != 0
        || !stat_stable(&descriptor_info, &after)
        || plamen_broker_v2_fd_identity(descriptor, view->identity) != 0
        || plamen_broker_v2_workspace_effects_revalidate(context) != 0)
        goto fail;
    view->version = PLAMEN_BROKER_V2_WORKSPACE_EFFECTS_VERSION;
    view->purpose = purpose;
    view->read_only = read_only;
    view->source_fd = descriptor;
    return 0;
fail:
    plamen_broker_v2_secure_zero(view, sizeof(*view));
    return -1;
}

int
plamen_broker_v2_workspace_effects_borrow_recensus(
    struct plamen_broker_v2_workspace_effects_context *context,
    const char *phase, const uint8_t **canonical_result,
    size_t *canonical_result_size, uint8_t semantic_commitment_sha256[32])
{
    uint8_t **stored;
    size_t *stored_size;
    uint8_t *commitment;
    uint8_t *layout_sha256;
    const char *receipt_name;
    int receipt_status;
    if (canonical_result != NULL) *canonical_result = NULL;
    if (canonical_result_size != NULL) *canonical_result_size = 0;
    if (semantic_commitment_sha256 != NULL)
        memset(semantic_commitment_sha256, 0, 32);
    if (context == NULL || context->magic != WORKSPACE_MAGIC || phase == NULL
        || canonical_result == NULL || canonical_result_size == NULL
        || semantic_commitment_sha256 == NULL
        || !context->layout_ready || !context->config_ready
        || plamen_broker_v2_workspace_effects_revalidate(context) != 0)
        return -1;
    if (strcmp(phase, "PRE_CREATE") == 0) {
        stored = &context->precreate_recensus;
        stored_size = &context->precreate_recensus_size;
        commitment = context->precreate_recensus_commitment;
        layout_sha256 = context->precreate_layout_sha256;
        receipt_name = "precreate-recensus.receipt";
    } else if (strcmp(phase, "POST_CREATE") == 0) {
        stored = &context->postcreate_recensus;
        stored_size = &context->postcreate_recensus_size;
        commitment = context->postcreate_recensus_commitment;
        layout_sha256 = context->postcreate_layout_sha256;
        receipt_name = "postcreate-recensus.receipt";
    } else return -1;
    if (*stored == NULL) {
        receipt_status = receipt_read(context->workspace_fd, receipt_name,
            stored, stored_size, commitment);
        if (receipt_status != 1) return -1;
    }
    if ((all_zero(layout_sha256, 32)
            && extract_canonical_digest(*stored, *stored_size,
                "layout_sha256", layout_sha256) != 0)
        || *stored_size == 0U || all_zero(commitment, 32)) return -1;
    *canonical_result = *stored;
    *canonical_result_size = *stored_size;
    memcpy(semantic_commitment_sha256, commitment, 32);
    return 0;
}

int
plamen_broker_v2_workspace_effects_provider_mounts_sha256(
    struct plamen_broker_v2_workspace_effects_context *context,
    const char *phase, uint8_t output[32])
{
    static const char *purposes[11] = {
        "target-lower", "project-merged", "scratch", "state", "control",
        "seccomp", "credentials", "backend-context", "runtime", "docs",
        "scope"
    };
    const int descriptors[11] = {
        context != NULL
            ? context->fds[PLAMEN_BROKER_V2_RETAINED_TARGET] : -1,
        context != NULL ? context->merged_fd : -1,
        context != NULL ? context->scratch_fd : -1,
        context != NULL ? context->state_fd : -1,
        context != NULL ? context->control_fd : -1,
        context != NULL ? context->seccomp_fd : -1,
        context != NULL ? context->credentials_fd : -1,
        context != NULL ? context->backend_private_fd : -1,
        context != NULL ? context->runtime_private_fd : -1,
        context != NULL ? context->docs_private_fd : -1,
        context != NULL ? context->scope_private_fd : -1
    };
    static const uint8_t read_only[11] = {
        1U, 1U, 0U, 0U, 1U, 1U, 1U, 1U, 1U, 1U, 1U
    };
    struct byte_buffer pairs = { 0 };
    uint8_t identity[32], provider_identity[32];
    char provider_hex[65];
    uint8_t *row = NULL;
    size_t row_size = 0, index;
    const uint8_t *recensus;
    size_t recensus_size;
    uint8_t recensus_commitment[32], *stored_digest;
    int result = -1;
    if (output != NULL) memset(output, 0, 32);
    if (context == NULL || phase == NULL || output == NULL
        || plamen_broker_v2_workspace_effects_borrow_recensus(context, phase,
            &recensus, &recensus_size, recensus_commitment) != 0
        || recensus == NULL || recensus_size == 0U
        || buffer_write(&pairs, "[", 1U) != 0)
        goto done;
    stored_digest = strcmp(phase, "PRE_CREATE") == 0
        ? context->precreate_provider_mounts_sha256
        : context->postcreate_provider_mounts_sha256;
    for (index = 0; index < 11U; ++index) {
        if (recensus_component_digest(descriptors[index], phase,
                purposes[index], read_only[index], identity,
                provider_identity) != 0
            || (index != 0U && buffer_write(&pairs, ",", 1U) != 0))
            goto done;
        encode_hex32(provider_identity, provider_hex);
        if (format_alloc(&row, &row_size, "[\"%s\",\"%s\"]",
                purposes[index], provider_hex) != 0
            || append_allocated(&pairs, row, row_size) != 0)
            goto done;
        row = NULL; row_size = 0;
    }
    if (buffer_write(&pairs, "]\n", 2U) != 0
        || plamen_broker_v2_sha256(pairs.data, pairs.size, output) != 0
        || (!all_zero(stored_digest, 32)
            && !constant_equal(stored_digest, output, 32)))
        goto done;
    if (all_zero(stored_digest, 32)) memcpy(stored_digest, output, 32);
    result = 0;
done:
    if (row != NULL) {
        plamen_broker_v2_secure_zero(row, row_size); free(row);
    }
    buffer_destroy(&pairs);
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    plamen_broker_v2_secure_zero(provider_identity,
        sizeof(provider_identity));
    plamen_broker_v2_secure_zero(provider_hex, sizeof(provider_hex));
    plamen_broker_v2_secure_zero(recensus_commitment,
        sizeof(recensus_commitment));
    if (result != 0) plamen_broker_v2_secure_zero(output, 32);
    return result;
}

int
plamen_broker_v2_workspace_effects_allowed_delta_sha256(
    struct plamen_broker_v2_workspace_effects_context *context,
    uint8_t output[32])
{
    static const char *purposes[11] = {
        "target-lower", "project-merged", "scratch", "state", "control",
        "seccomp", "credentials", "backend-context", "runtime", "docs",
        "scope"
    };
    const int descriptors[11] = {
        context != NULL
            ? context->fds[PLAMEN_BROKER_V2_RETAINED_TARGET] : -1,
        context != NULL ? context->merged_fd : -1,
        context != NULL ? context->scratch_fd : -1,
        context != NULL ? context->state_fd : -1,
        context != NULL ? context->control_fd : -1,
        context != NULL ? context->seccomp_fd : -1,
        context != NULL ? context->credentials_fd : -1,
        context != NULL ? context->backend_private_fd : -1,
        context != NULL ? context->runtime_private_fd : -1,
        context != NULL ? context->docs_private_fd : -1,
        context != NULL ? context->scope_private_fd : -1
    };
    static const uint8_t read_only[11] = {
        1U, 1U, 0U, 0U, 1U, 1U, 1U, 1U, 1U, 1U, 1U
    };
    struct byte_buffer rows = { 0 };
    const uint8_t *precreate, *postcreate;
    size_t precreate_size, postcreate_size, index;
    uint8_t precreate_commitment[32], postcreate_commitment[32];
    uint8_t identity[32], pre_identity[32], post_identity[32];
    char pre_hex[65], post_hex[65];
    uint8_t *row = NULL;
    size_t row_size = 0;
    int result = -1;
    if (output != NULL) memset(output, 0, 32);
    if (context == NULL || output == NULL
        || plamen_broker_v2_workspace_effects_borrow_recensus(context,
            "PRE_CREATE", &precreate, &precreate_size,
            precreate_commitment) != 0
        || plamen_broker_v2_workspace_effects_borrow_recensus(context,
            "POST_CREATE", &postcreate, &postcreate_size,
            postcreate_commitment) != 0
        || precreate == NULL || postcreate == NULL
        || precreate_size == 0U || postcreate_size == 0U
        || !constant_equal(context->precreate_layout_sha256,
            context->postcreate_layout_sha256, 32)
        || buffer_write(&rows, "[", 1U) != 0)
        goto done;
    for (index = 0; index < 11U; ++index) {
        if (recensus_component_digest(descriptors[index], "PRE_CREATE",
                purposes[index], read_only[index], identity, pre_identity) != 0
            || recensus_component_digest(descriptors[index], "POST_CREATE",
                purposes[index], read_only[index], identity,
                post_identity) != 0
            || (index != 0U && buffer_write(&rows, ",", 1U) != 0))
            goto done;
        encode_hex32(pre_identity, pre_hex); encode_hex32(post_identity, post_hex);
        if (format_alloc(&row, &row_size,
                "[\"%s\",\"%s\",\"%s\"]", purposes[index], pre_hex,
                post_hex) != 0
            || append_allocated(&rows, row, row_size) != 0)
            goto done;
        row = NULL; row_size = 0;
    }
    if (buffer_write(&rows, "]\n", 2U) != 0
        || plamen_broker_v2_sha256(rows.data, rows.size, output) != 0)
        goto done;
    result = 0;
done:
    if (row != NULL) {
        plamen_broker_v2_secure_zero(row, row_size); free(row);
    }
    buffer_destroy(&rows);
    plamen_broker_v2_secure_zero(precreate_commitment,
        sizeof(precreate_commitment));
    plamen_broker_v2_secure_zero(postcreate_commitment,
        sizeof(postcreate_commitment));
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    plamen_broker_v2_secure_zero(pre_identity, sizeof(pre_identity));
    plamen_broker_v2_secure_zero(post_identity, sizeof(post_identity));
    plamen_broker_v2_secure_zero(pre_hex, sizeof(pre_hex));
    plamen_broker_v2_secure_zero(post_hex, sizeof(post_hex));
    if (result != 0) plamen_broker_v2_secure_zero(output, 32);
    return result;
}

void
plamen_broker_v2_workspace_effects_destroy(
    struct plamen_broker_v2_workspace_effects_context *context)
{
    size_t index;
    if (context == NULL || context->magic != WORKSPACE_MAGIC) return;
    close_layout_descriptors(context);
    if (context->state_parent_fd >= 0) (void)close(context->state_parent_fd);
    if (context->generation_fd >= 0) (void)close(context->generation_fd);
    for (index = 0;
            index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index)
        if (context->fds[index] >= 0) (void)close(context->fds[index]);
    if (context->projection != NULL) {
        plamen_broker_v2_secure_zero(context->projection,
            context->projection_size); free(context->projection);
    }
    if (context->guest_config != NULL) {
        plamen_broker_v2_secure_zero(context->guest_config,
            context->guest_config_size); free(context->guest_config);
    }
    if (context->precreate_recensus != NULL) {
        plamen_broker_v2_secure_zero(context->precreate_recensus,
            context->precreate_recensus_size);
        free(context->precreate_recensus);
    }
    if (context->postcreate_recensus != NULL) {
        plamen_broker_v2_secure_zero(context->postcreate_recensus,
            context->postcreate_recensus_size);
        free(context->postcreate_recensus);
    }
    plamen_broker_v2_secure_zero(context, sizeof(*context)); free(context);
}
