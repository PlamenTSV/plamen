#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_broker_v2_podman_admission.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <dirent.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#endif

#define EXECUTABLE_MAX (512U * 1024U * 1024U)
#define PACKAGE_RECEIPT_MAX (1024U * 1024U)
#define UNIT_MAX (1024U * 1024U)
#define CLOSURE_BUFFER_MAX (128U * 1024U)
#define IMAGE_TEMPLATE \
    "{\"id\":{{json .Id}},\"digest\":{{json .Digest}}," \
    "\"os\":{{json .Os}},\"architecture\":{{json .Architecture}}," \
    "\"repo_digests\":{{json .RepoDigests}}}"

struct closure_buffer {
    uint8_t bytes[CLOSURE_BUFFER_MAX];
    size_t size;
};

static int buffer_append(struct closure_buffer *, const void *, size_t);
#ifdef __linux__
static int buffer_u32(struct closure_buffer *, uint32_t);
static int buffer_u64(struct closure_buffer *, uint64_t);
static int hash_buffer(const struct closure_buffer *, uint8_t[32]);
#endif

static void
custody_initialize(struct plamen_broker_v2_podman_admission_custody *custody)
{
    size_t index;
    memset(custody, 0, sizeof(*custody));
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT; ++index) {
        custody->component_fds[index] = -1;
        custody->package_receipt_fds[index] = -1;
    }
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT; ++index)
        custody->root_fds[index] = -1;
    custody->systemd_unit_fd = -1;
    custody->cgroup_fd = -1;
}

void
plamen_broker_v2_podman_custody_close(
    struct plamen_broker_v2_podman_admission_custody *custody)
{
    size_t index;
    if (custody == NULL) return;
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT; ++index) {
        if (custody->component_fds[index] >= 0)
            (void)close(custody->component_fds[index]);
        if (custody->package_receipt_fds[index] >= 0)
            (void)close(custody->package_receipt_fds[index]);
    }
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT; ++index)
        if (custody->root_fds[index] >= 0) (void)close(custody->root_fds[index]);
    if (custody->systemd_unit_fd >= 0) (void)close(custody->systemd_unit_fd);
    if (custody->cgroup_fd >= 0) (void)close(custody->cgroup_fd);
    plamen_broker_v2_secure_zero(custody, sizeof(*custody));
    custody_initialize(custody);
}

#ifdef __linux__
static int
mount_identity(int fd, uint64_t *mount_id)
{
    struct statx identity;
    if (fd < 0 || mount_id == NULL) return -1;
    memset(&identity, 0, sizeof(identity));
    if (statx(fd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC,
            STATX_INO | STATX_MNT_ID, &identity) != 0
        || (identity.stx_mask & (STATX_INO | STATX_MNT_ID))
            != (STATX_INO | STATX_MNT_ID)
        || identity.stx_mnt_id == 0) return -1;
    *mount_id = identity.stx_mnt_id;
    return 0;
}

static int
directory_identity(int fd, const struct plamen_broker_v2_podman_root_binding *expected,
    uint32_t uid, int private_root)
{
    struct stat value;
    uint64_t mount_id;
    int access_mode;
    if (fd < 0 || expected == NULL || fstat(fd, &value) != 0
        || !S_ISDIR(value.st_mode) || value.st_nlink < 1
        || (fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0
        || (access_mode = fcntl(fd, F_GETFL)) < 0
        || (access_mode & O_ACCMODE) != O_RDONLY
        || mount_identity(fd, &mount_id) != 0
        || (uint64_t)value.st_dev != expected->device
        || (uint64_t)value.st_ino != expected->inode
        || mount_id != expected->mount_id
        || (uint32_t)value.st_uid != expected->uid
        || (uint32_t)value.st_gid != expected->gid
        || (uint32_t)(value.st_mode & 07777U) != expected->mode)
        return -1;
    if (private_root) {
        if ((uint32_t)value.st_uid != uid
            || (value.st_mode & 0777U) != 0700U) return -1;
    } else if ((value.st_mode & (S_IWGRP | S_IWOTH)) != 0) return -1;
    return 0;
}

static int
read_small_child(int parent_fd, const char *name, uint8_t *output,
    size_t capacity, size_t *size)
{
    int fd;
    ssize_t amount;
    size_t offset = 0;
    fd = plamen_broker_v2_podman_open_beneath(parent_fd, name, O_RDONLY, 0);
    if (fd < 0) return -1;
    while (offset < capacity) {
        amount = read(fd, output + offset, capacity - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) { (void)close(fd); return -1; }
        if (amount == 0) break;
        offset += (size_t)amount;
    }
    if (offset == capacity) {
        uint8_t extra;
        do amount = read(fd, &extra, 1); while (amount < 0 && errno == EINTR);
        if (amount != 0) { (void)close(fd); return -1; }
    }
    if (close(fd) != 0) return -1;
    *size = offset;
    return 0;
}

static int
token_present(const uint8_t *bytes, size_t size, const char *token)
{
    size_t cursor = 0, start, length = strlen(token);
    while (cursor < size) {
        while (cursor < size && isspace(bytes[cursor])) ++cursor;
        start = cursor;
        while (cursor < size && !isspace(bytes[cursor])) ++cursor;
        if (cursor - start == length && memcmp(bytes + start, token, length) == 0)
            return 1;
    }
    return 0;
}

static int
cgroup_events_empty(const uint8_t *bytes, size_t size)
{
    size_t cursor = 0, start, end;
    int populated = 0, frozen = 0;
    while (cursor < size) {
        start = cursor;
        while (cursor < size && bytes[cursor] != '\n') ++cursor;
        end = cursor;
        if (cursor < size) ++cursor;
        if (end == start) continue;
        if (end - start == 11 && memcmp(bytes + start, "populated 0", 11) == 0) {
            if (populated) return 0;
            populated = 1;
        } else if (end - start == 8 && memcmp(bytes + start, "frozen 0", 8) == 0) {
            if (frozen) return 0;
            frozen = 1;
        } else return 0;
    }
    return populated;
}

static int
cgroup_stat_empty(const uint8_t *bytes, size_t size)
{
    size_t cursor = 0, start, end;
    int descendants = 0, dying = 0;
    while (cursor < size) {
        start = cursor;
        while (cursor < size && bytes[cursor] != '\n') ++cursor;
        end = cursor;
        if (cursor < size) ++cursor;
        if (end == start) continue;
        if (end - start == 16
            && memcmp(bytes + start, "nr_descendants 0", 16) == 0) {
            if (descendants) return 0;
            descendants = 1;
        } else if (end - start == 22
            && memcmp(bytes + start, "nr_dying_descendants 0", 22) == 0) {
            if (dying) return 0;
            dying = 1;
        } else return 0;
    }
    return descendants && dying;
}

static int
cgroup_has_no_child_directory(int cgroup_fd)
{
    DIR *directory;
    struct dirent *entry;
    struct stat value;
    int duplicate, ok = 1;
    duplicate = fcntl(cgroup_fd, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0 || (directory = fdopendir(duplicate)) == NULL) {
        if (duplicate >= 0) (void)close(duplicate);
        return 0;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (fstatat(cgroup_fd, entry->d_name, &value, AT_SYMLINK_NOFOLLOW) != 0
            || S_ISLNK(value.st_mode)) { ok = 0; break; }
        if (S_ISDIR(value.st_mode)) { ok = 0; break; }
    }
    if (errno != 0) ok = 0;
    if (closedir(directory) != 0) ok = 0;
    return ok;
}

static int
validate_cgroup(int fd, uint64_t device, uint64_t inode, uint64_t expected_mount,
    uint8_t identity_sha256[32])
{
    static const char domain[] = "PLAMEN-PODMAN-CGROUP-V1";
    struct stat value;
    struct statfs filesystem;
    struct closure_buffer identity;
    uint8_t bytes[4096];
    size_t size;
    uint64_t mount_id;
    int kill_fd;
    if (fd < 0 || fstat(fd, &value) != 0 || !S_ISDIR(value.st_mode)
        || (fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0
        || (uint64_t)value.st_dev != device || (uint64_t)value.st_ino != inode
        || mount_identity(fd, &mount_id) != 0 || mount_id != expected_mount
        || fstatfs(fd, &filesystem) != 0
        || (unsigned long)filesystem.f_type != (unsigned long)CGROUP2_SUPER_MAGIC
        || read_small_child(fd, "cgroup.procs", bytes, sizeof(bytes), &size) != 0)
        return -1;
    while (size != 0 && isspace(bytes[size - 1U])) --size;
    if (size != 0
        || read_small_child(fd, "cgroup.type", bytes, sizeof(bytes), &size) != 0
        || (size != 7 || memcmp(bytes, "domain\n", 7) != 0)
        || read_small_child(fd, "cgroup.events", bytes, sizeof(bytes), &size) != 0
        || !cgroup_events_empty(bytes, size)
        || read_small_child(fd, "cgroup.stat", bytes, sizeof(bytes), &size) != 0
        || !cgroup_stat_empty(bytes, size)
        || read_small_child(fd, "cgroup.controllers", bytes, sizeof(bytes), &size) != 0
        || !token_present(bytes, size, "cpu")
        || !token_present(bytes, size, "memory")
        || !token_present(bytes, size, "pids")
        || read_small_child(fd, "memory.swap.max", bytes, sizeof(bytes), &size) != 0
        || !cgroup_has_no_child_directory(fd)) return -1;
    kill_fd = plamen_broker_v2_podman_open_beneath(fd, "cgroup.kill", O_WRONLY, 0);
    if (kill_fd < 0 || close(kill_fd) != 0) return -1;
    memset(&identity, 0, sizeof(identity));
    if (buffer_append(&identity, domain, sizeof(domain)) != 0
        || buffer_u64(&identity, device) != 0 || buffer_u64(&identity, inode) != 0
        || buffer_u64(&identity, mount_id) != 0
        || hash_buffer(&identity, identity_sha256) != 0) return -1;
    return 0;
}

static int
validate_roots(const struct plamen_broker_v2_podman_admission_spec *spec,
    uint8_t root_sha256[32])
{
    static const char domain[] = "PLAMEN-PODMAN-ROOTS-V1";
    struct closure_buffer closure;
    struct stat upper, work;
    struct statfs merged_fs;
    size_t index, prior;
    const struct plamen_broker_v2_podman_root_binding *item;
    memset(&closure, 0, sizeof(closure));
    if (buffer_append(&closure, domain, sizeof(domain)) != 0)
        return -1;
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT; ++index) {
        item = &spec->roots[index];
        if (item->role != index
            || directory_identity(item->fd, item, spec->native_uid,
                index <= PLAMEN_BROKER_V2_PODMAN_ROOT_OVERLAY
                || index == PLAMEN_BROKER_V2_PODMAN_ROOT_UPPER
                || index == PLAMEN_BROKER_V2_PODMAN_ROOT_WORK) != 0
            || (index == PLAMEN_BROKER_V2_PODMAN_ROOT_MERGED
                && item->uid != spec->native_uid))
            return -1;
        for (prior = 0; prior < index; ++prior)
            if (item->device == spec->roots[prior].device
                && item->inode == spec->roots[prior].inode) return -1;
        if (buffer_u32(&closure, item->role) != 0
            || buffer_u64(&closure, item->device) != 0
            || buffer_u64(&closure, item->inode) != 0
            || buffer_u64(&closure, item->mount_id) != 0
            || buffer_u32(&closure, item->uid) != 0
            || buffer_u32(&closure, item->gid) != 0
            || buffer_u32(&closure, item->mode) != 0) return -1;
    }
    if (fstat(spec->roots[PLAMEN_BROKER_V2_PODMAN_ROOT_UPPER].fd, &upper) != 0
        || fstat(spec->roots[PLAMEN_BROKER_V2_PODMAN_ROOT_WORK].fd, &work) != 0
        || upper.st_dev != work.st_dev
        || fstatfs(spec->roots[PLAMEN_BROKER_V2_PODMAN_ROOT_MERGED].fd,
            &merged_fs) != 0
        || (unsigned long)merged_fs.f_type != (unsigned long)OVERLAYFS_SUPER_MAGIC
        || spec->roots[PLAMEN_BROKER_V2_PODMAN_ROOT_MERGED].mount_id
            == spec->roots[PLAMEN_BROKER_V2_PODMAN_ROOT_UPPER].mount_id
        || spec->roots[PLAMEN_BROKER_V2_PODMAN_ROOT_MERGED].mount_id
            == spec->roots[PLAMEN_BROKER_V2_PODMAN_ROOT_LOWER].mount_id)
        return -1;
    return hash_buffer(&closure, root_sha256);
}
#endif

static const char *const fixed_version_lines[
    PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT] = {
    "podman version 6.1.1",
    "conmon version 2.2.1",
    "crun version 1.28",
    NULL,
    NULL,
    "fuse-overlayfs: version 1.17",
    NULL
};

static int
component_has_version_command(uint32_t role)
{
    return role == PLAMEN_BROKER_V2_PODMAN_COMPONENT_PODMAN
        || role == PLAMEN_BROKER_V2_PODMAN_COMPONENT_CONMON
        || role == PLAMEN_BROKER_V2_PODMAN_COMPONENT_CRUN
        || role == PLAMEN_BROKER_V2_PODMAN_COMPONENT_FUSE_OVERLAYFS
        || role == PLAMEN_BROKER_V2_PODMAN_COMPONENT_SYSTEMD;
}

static int
constant_equal(const void *left_value, const void *right_value, size_t size)
{
    const uint8_t *left = left_value, *right = right_value;
    uint8_t difference = 0;
    size_t index;
    if (left == NULL || right == NULL) return 0;
    for (index = 0; index < size; ++index)
        difference |= left[index] ^ right[index];
    return difference == 0;
}

static int
digest_present(const uint8_t value[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE])
{
    uint8_t aggregate = 0;
    size_t index;
    if (value == NULL) return 0;
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE; ++index)
        aggregate |= value[index];
    return aggregate != 0;
}

#ifdef __linux__
static int
safe_text(const char *value, size_t maximum)
{
    const unsigned char *cursor = (const unsigned char *)value;
    size_t length;
    if (value == NULL || (length = strlen(value)) == 0 || length > maximum)
        return 0;
    while (*cursor != '\0') {
        if (*cursor < 0x21 || *cursor > 0x7e || *cursor == '\\'
            || *cursor == '\'' || *cursor == '"') return 0;
        ++cursor;
    }
    return 1;
}
#endif

static int
lower_hex(const char *value, size_t length)
{
    size_t index;
    if (value == NULL) return 0;
    for (index = 0; index < length; ++index)
        if (!((value[index] >= '0' && value[index] <= '9')
                || (value[index] >= 'a' && value[index] <= 'f'))) return 0;
    return value[length] == '\0';
}

static int
digest_text(const char *value)
{
    return value != NULL && strlen(value) == 71
        && memcmp(value, "sha256:", 7) == 0 && lower_hex(value + 7, 64);
}

static int
reference_valid(const char *value, const char *digest)
{
    const char *marker;
    size_t index, component = 0, prefix;
    unsigned char byte;
    if (value == NULL || digest == NULL || !digest_text(digest)
        || strlen(value) >= PLAMEN_BROKER_V2_PODMAN_REFERENCE_MAX
        || (marker = strstr(value, "@sha256:")) == NULL
        || marker == value || strchr(marker + 1, '@') != NULL
        || strcmp(marker + 1, digest) != 0) return 0;
    prefix = (size_t)(marker - value);
    for (index = 0; index < prefix; ++index) {
        byte = (unsigned char)value[index];
        if (!((byte >= 'a' && byte <= 'z')
                || (byte >= '0' && byte <= '9') || byte == '.'
                || byte == '_' || byte == '-' || byte == '/'
                || byte == ':')) return 0;
        if (byte == '/') {
            if (index == component || (index - component == 1
                    && value[component] == '.')
                || (index - component == 2 && value[component] == '.'
                    && value[component + 1] == '.')) return 0;
            component = index + 1U;
        }
    }
    return component < prefix && value[0] != '.' && value[0] != '-';
}

static int
buffer_append(struct closure_buffer *buffer, const void *data, size_t size)
{
    if (buffer == NULL || (size != 0 && data == NULL)
        || size > sizeof(buffer->bytes) - buffer->size) return -1;
    if (size != 0) memcpy(buffer->bytes + buffer->size, data, size);
    buffer->size += size;
    return 0;
}

#ifdef __linux__
static int
buffer_u32(struct closure_buffer *buffer, uint32_t value)
{
    uint8_t encoded[4] = {
        (uint8_t)(value >> 24), (uint8_t)(value >> 16),
        (uint8_t)(value >> 8), (uint8_t)value
    };
    return buffer_append(buffer, encoded, sizeof(encoded));
}

static int
buffer_u64(struct closure_buffer *buffer, uint64_t value)
{
    uint8_t encoded[8];
    size_t index;
    for (index = 0; index < sizeof(encoded); ++index)
        encoded[index] = (uint8_t)(value >> ((7U - index) * 8U));
    return buffer_append(buffer, encoded, sizeof(encoded));
}

static int
buffer_text(struct closure_buffer *buffer, const char *value, size_t maximum)
{
    size_t length;
    if (!safe_text(value, maximum) || (length = strlen(value)) > UINT32_MAX
        || buffer_u32(buffer, (uint32_t)length) != 0)
        return -1;
    return buffer_append(buffer, value, length);
}

static int
hash_buffer(const struct closure_buffer *buffer,
    uint8_t output[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE])
{
    return plamen_broker_v2_sha256(buffer->bytes, buffer->size, output);
}

static int
hash_fd(int fd, size_t maximum, uint8_t output[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE],
    struct stat *identity)
{
    struct stat before, after;
    void *mapping = MAP_FAILED;
    int status = -1;
    if (fd < 0 || output == NULL || fstat(fd, &before) != 0
        || !S_ISREG(before.st_mode) || before.st_size <= 0
        || (uint64_t)before.st_size > maximum || before.st_nlink != 1
        || (before.st_mode & (S_IWGRP | S_IWOTH)) != 0
        || (fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0) return -1;
    mapping = mmap(NULL, (size_t)before.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED) return -1;
    if (plamen_broker_v2_sha256(mapping, (size_t)before.st_size, output) != 0)
        goto done;
    if (fstat(fd, &after) != 0 || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime) goto done;
    if (identity != NULL) *identity = after;
    status = 0;
done:
    (void)munmap(mapping, (size_t)before.st_size);
    return status;
}
#endif

static int
version_line_valid(uint32_t role, const char *line)
{
    const char *cursor, *scan;
    if (role < PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT
        && role != PLAMEN_BROKER_V2_PODMAN_COMPONENT_SYSTEMD)
        return line != NULL && strcmp(line, fixed_version_lines[role]) == 0;
    if (role != PLAMEN_BROKER_V2_PODMAN_COMPONENT_SYSTEMD
        || line == NULL || strncmp(line, "systemd ", 8) != 0
        || strlen(line) > 255) return 0;
    for (scan = line; *scan != '\0'; ++scan)
        if ((unsigned char)*scan < 0x20 || (unsigned char)*scan > 0x7e
            || *scan == '\\' || *scan == '\'' || *scan == '"') return 0;
    cursor = line + 8;
    if (!isdigit((unsigned char)*cursor)) return 0;
    while (isdigit((unsigned char)*cursor)) ++cursor;
    return *cursor == '\0' || *cursor == ' ' || *cursor == '(';
}

#if !defined(__linux__) && \
    !defined(PLAMEN_BROKER_V2_PODMAN_ADMISSION_TEST_ONLY)
#define PLAMEN_PODMAN_LINUX_ONLY_UNUSED __attribute__((unused))
#else
#define PLAMEN_PODMAN_LINUX_ONLY_UNUSED
#endif

static int PLAMEN_PODMAN_LINUX_ONLY_UNUSED
validate_component_version(uint32_t role, const uint8_t *bytes, size_t size,
    const char *exact_line, const uint8_t expected_sha256[32])
{
    uint8_t digest[32];
    size_t first = 0, cursor;
    if (bytes == NULL || size == 0
        || size > PLAMEN_BROKER_V2_PODMAN_TRANSCRIPT_MAX
        || !version_line_valid(role, exact_line)
        || plamen_broker_v2_sha256(bytes, size, digest) != 0
        || !constant_equal(digest, expected_sha256, sizeof(digest))) return -1;
    while (first < size && bytes[first] != '\n') ++first;
    if (first != strlen(exact_line)
        || memcmp(bytes, exact_line, first) != 0) return -1;
    for (cursor = first; cursor < size; ++cursor) {
        if (bytes[cursor] == '\0' || bytes[cursor] == '\r'
            || (bytes[cursor] < 0x20 && bytes[cursor] != '\n'
                && bytes[cursor] != '\t') || bytes[cursor] > 0x7e) return -1;
    }
    return 0;
}

static int PLAMEN_PODMAN_LINUX_ONLY_UNUSED
validate_image(const uint8_t *bytes, size_t size, const char *reference,
    const char *manifest_digest, uint32_t architecture,
    const uint8_t expected_sha256[32])
{
    static const char prefix[] = "{\"id\":\"sha256:";
    static const char middle_digest[] = "\",\"digest\":\"";
    static const char middle_platform[] =
        "\",\"os\":\"linux\",\"architecture\":\"";
    static const char middle_repos[] = "\",\"repo_digests\":[\"";
    static const char suffix[] = "\"]}";
    const char *arch;
    struct closure_buffer expected;
    uint8_t digest[32];
    size_t cursor;
    if (bytes == NULL || size == 0
        || size > PLAMEN_BROKER_V2_PODMAN_TRANSCRIPT_MAX
        || !reference_valid(reference, manifest_digest)
        || !digest_text(manifest_digest)
        || plamen_broker_v2_sha256(bytes, size, digest) != 0
        || !constant_equal(digest, expected_sha256, sizeof(digest))
        || size < sizeof(prefix) - 1U + 64U) return -1;
    arch = architecture == PLAMEN_BROKER_V2_PODMAN_ARCH_AMD64 ? "amd64"
        : architecture == PLAMEN_BROKER_V2_PODMAN_ARCH_ARM64 ? "arm64" : NULL;
    if (arch == NULL || memcmp(bytes, prefix, sizeof(prefix) - 1U) != 0)
        return -1;
    for (cursor = sizeof(prefix) - 1U;
         cursor < sizeof(prefix) - 1U + 64U; ++cursor)
        if (!((bytes[cursor] >= '0' && bytes[cursor] <= '9')
                || (bytes[cursor] >= 'a' && bytes[cursor] <= 'f'))) return -1;
    memset(&expected, 0, sizeof(expected));
    if (buffer_append(&expected, prefix, sizeof(prefix) - 1U) != 0
        || buffer_append(&expected, bytes + sizeof(prefix) - 1U, 64U) != 0
        || buffer_append(&expected, middle_digest,
            sizeof(middle_digest) - 1U) != 0
        || buffer_append(&expected, manifest_digest, strlen(manifest_digest)) != 0
        || buffer_append(&expected, middle_platform,
            sizeof(middle_platform) - 1U) != 0
        || buffer_append(&expected, arch, strlen(arch)) != 0
        || buffer_append(&expected, middle_repos,
            sizeof(middle_repos) - 1U) != 0
        || buffer_append(&expected, reference, strlen(reference)) != 0
        || buffer_append(&expected, suffix, sizeof(suffix) - 1U) != 0)
        return -1;
    return expected.size == size
        && memcmp(expected.bytes, bytes, size) == 0 ? 0 : -1;
}

static int PLAMEN_PODMAN_LINUX_ONLY_UNUSED
relative_path_valid(const char *value)
{
    const char *component, *cursor;
    size_t length;
    if (value == NULL || value[0] == '/' || (length = strlen(value)) == 0
        || length > 4096 || value[length - 1U] == '/') return 0;
    component = value;
    for (cursor = value; ; ++cursor) {
        if (*cursor == '/' || *cursor == '\0') {
            length = (size_t)(cursor - component);
            if (length == 0 || (length == 1 && component[0] == '.')
                || (length == 2 && component[0] == '.'
                    && component[1] == '.')) return 0;
            if (*cursor == '\0') break;
            component = cursor + 1;
        } else if ((unsigned char)*cursor < 0x21
            || (unsigned char)*cursor > 0x7e || *cursor == '\\') return 0;
    }
    return 1;
}

int
plamen_broker_v2_podman_open_beneath(int parent_fd,
    const char *relative_path, int flags, unsigned int mode)
{
#ifdef __linux__
    struct open_how how;
    if (parent_fd < 0 || !relative_path_valid(relative_path)
        || (flags & (O_CREAT | O_TRUNC | O_TMPFILE)) != 0) {
        errno = EINVAL;
        return -1;
    }
    memset(&how, 0, sizeof(how));
    how.flags = (uint64_t)(flags | O_CLOEXEC | O_NOFOLLOW);
    how.mode = mode;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
        | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    return (int)syscall(SYS_openat2, parent_fd, relative_path, &how,
        sizeof(how));
#else
    (void)parent_fd; (void)relative_path; (void)flags; (void)mode;
    errno = ENOTSUP;
    return -1;
#endif
}

static int
command_add(struct plamen_broker_v2_podman_read_command *command,
    const char *format, int descriptor)
{
    int written;
    size_t index;
    if (command == NULL || command->argc >= PLAMEN_BROKER_V2_PODMAN_COMMAND_MAX_ARGS)
        return -1;
    index = command->argc;
    written = descriptor >= 0
        ? snprintf(command->storage[index], sizeof(command->storage[index]),
            format, descriptor)
        : snprintf(command->storage[index], sizeof(command->storage[index]),
            "%s", format);
    if (written < 0 || (size_t)written >= sizeof(command->storage[index]))
        return -1;
    command->argv[index] = command->storage[index];
    command->argc += 1U;
    command->argv[command->argc] = NULL;
    return 0;
}

int
plamen_broker_v2_podman_render_read_command(
    const struct plamen_broker_v2_podman_admission_spec *spec,
    uint32_t operation,
    struct plamen_broker_v2_podman_read_command *command)
{
    static const char *const fixed[] = {
        "--remote=false", "--root", NULL, "--runroot", NULL, "--tmpdir", NULL,
        "--runtime", NULL, "--conmon", NULL, "--cgroup-manager", "cgroupfs",
        "--events-backend", "file", "--storage-driver", "overlay",
        "--storage-opt", NULL, "--network-config-dir", NULL,
        "--hooks-dir", NULL, "image", "inspect", "--format", IMAGE_TEMPLATE,
        NULL
    };
    size_t index;
    int fd_values[] = {
        -1, -1, PLAMEN_BROKER_V2_PODMAN_ROOT_STORAGE,
        -1, PLAMEN_BROKER_V2_PODMAN_ROOT_RUNROOT,
        -1, PLAMEN_BROKER_V2_PODMAN_ROOT_TMP,
        -1, -(PLAMEN_BROKER_V2_PODMAN_COMPONENT_CRUN + 2),
        -1, -(PLAMEN_BROKER_V2_PODMAN_COMPONENT_CONMON + 2),
        -1, -1, -1, -1, -1, -1, -1,
        -(PLAMEN_BROKER_V2_PODMAN_COMPONENT_FUSE_OVERLAYFS + 2),
        -1, PLAMEN_BROKER_V2_PODMAN_ROOT_HOME,
        -1, PLAMEN_BROKER_V2_PODMAN_ROOT_HOME,
        -1, -1, -1, -1, -1
    };
    char mount_program[PLAMEN_BROKER_V2_PODMAN_COMMAND_ARG_MAX];
    char empty_networks[PLAMEN_BROKER_V2_PODMAN_COMMAND_ARG_MAX];
    char empty_hooks[PLAMEN_BROKER_V2_PODMAN_COMMAND_ARG_MAX];
    const char *value;
    int descriptor;
    if (spec == NULL || command == NULL) return -1;
    memset(command, 0, sizeof(*command));
    command->operation = operation;
    if (operation >= PLAMEN_BROKER_V2_PODMAN_READ_COMPONENT_VERSION_BASE
        && operation < PLAMEN_BROKER_V2_PODMAN_READ_COMPONENT_VERSION_BASE
            + PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT) {
        index = operation - PLAMEN_BROKER_V2_PODMAN_READ_COMPONENT_VERSION_BASE;
        if (!component_has_version_command((uint32_t)index)
            || command_add(command, "/proc/self/fd/%d",
                spec->components[index].executable_fd) != 0
            || command_add(command, "--version", -1) != 0) return -1;
        return 0;
    }
    if (operation != PLAMEN_BROKER_V2_PODMAN_READ_IMAGE_INSPECT
        || !reference_valid(spec->image_reference, spec->image_manifest_digest)
        || snprintf(mount_program, sizeof(mount_program),
            "mount_program=/proc/self/fd/%d",
            spec->components[PLAMEN_BROKER_V2_PODMAN_COMPONENT_FUSE_OVERLAYFS]
                .executable_fd) < 0
        || snprintf(empty_networks, sizeof(empty_networks),
            "/proc/self/fd/%d/empty-networks",
            spec->roots[PLAMEN_BROKER_V2_PODMAN_ROOT_HOME].fd) < 0
        || snprintf(empty_hooks, sizeof(empty_hooks),
            "/proc/self/fd/%d/empty-hooks",
            spec->roots[PLAMEN_BROKER_V2_PODMAN_ROOT_HOME].fd) < 0)
        return -1;
    if (command_add(command, "/proc/self/fd/%d",
            spec->components[PLAMEN_BROKER_V2_PODMAN_COMPONENT_PODMAN]
                .executable_fd) != 0) return -1;
    for (index = 0; index < sizeof(fixed) / sizeof(fixed[0]); ++index) {
        value = fixed[index]; descriptor = fd_values[index];
        if (index == 18U) value = mount_program;
        else if (index == 20U) value = empty_networks;
        else if (index == 22U) value = empty_hooks;
        else if (index == 27U) value = spec->image_reference;
        if (value == NULL) {
            if (descriptor >= 0)
                descriptor = spec->roots[(size_t)descriptor].fd;
            else
                descriptor = spec->components[(size_t)(-descriptor - 2)].executable_fd;
            if (command_add(command, "/proc/self/fd/%d", descriptor) != 0)
                return -1;
        } else if (command_add(command, value, -1) != 0) return -1;
    }
    return 0;
}

#ifdef __linux__
static int
component_closures(
    const struct plamen_broker_v2_podman_admission_spec *spec,
    uint8_t component_sha256[32], uint8_t package_sha256[32])
{
    static const char component_domain[] = "PLAMEN-PODMAN-COMPONENTS-V1";
    static const char package_domain[] = "PLAMEN-PODMAN-PACKAGES-V1";
    struct closure_buffer components, packages;
    struct stat executable_identity, package_identity;
    uint8_t executable_digest[32], package_digest[32];
    size_t index, prior;
    const struct plamen_broker_v2_podman_component_binding *item;
    memset(&components, 0, sizeof(components));
    memset(&packages, 0, sizeof(packages));
    if (buffer_append(&components, component_domain,
            sizeof(component_domain)) != 0
        || buffer_append(&packages, package_domain,
            sizeof(package_domain)) != 0)
        return -1;
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT; ++index) {
        item = &spec->components[index];
        if (item->role != index || item->offline_signature_verified != 1U
            || item->package_file_manifest_verified != 1U
            || !digest_present(item->executable_sha256)
            || !digest_present(item->package_receipt_sha256)
            || !digest_present(item->package_manifest_sha256)
            || !digest_present(item->package_signature_sha256)
            || !digest_present(item->package_signer_sha256)
            || !safe_text(item->package_manager, 32)
            || !safe_text(item->package_name, 128)
            || !safe_text(item->package_version, 128)
            || !safe_text(item->package_architecture, 32)
            || hash_fd(item->executable_fd, EXECUTABLE_MAX,
                executable_digest, &executable_identity) != 0
            || hash_fd(item->package_receipt_fd, PACKAGE_RECEIPT_MAX,
                package_digest, &package_identity) != 0
            || executable_identity.st_uid != 0
            || (executable_identity.st_mode & 0111U) == 0
            || package_identity.st_uid != 0
            || (uint64_t)executable_identity.st_dev != item->executable_device
            || (uint64_t)executable_identity.st_ino != item->executable_inode
            || (uint64_t)executable_identity.st_size != item->executable_size
            || !constant_equal(executable_digest, item->executable_sha256, 32)
            || !constant_equal(package_digest,
                item->package_receipt_sha256, 32)) return -1;
        if (component_has_version_command(item->role)) {
            if (!digest_present(item->version_transcript_sha256)
                || validate_component_version(item->role,
                    item->version_transcript, item->version_transcript_size,
                    item->exact_version_line,
                    item->version_transcript_sha256) != 0) return -1;
        } else if (item->exact_version_line != NULL
            || item->version_transcript != NULL
            || item->version_transcript_size != 0
            || digest_present(item->version_transcript_sha256)) return -1;
        for (prior = 0; prior < index; ++prior) {
            if ((item->executable_device == spec->components[prior].executable_device
                    && item->executable_inode == spec->components[prior].executable_inode)
                || item->executable_fd == spec->components[prior].executable_fd
                || item->package_receipt_fd
                    == spec->components[prior].package_receipt_fd) return -1;
        }
        if (buffer_u32(&components, item->role) != 0
            || buffer_u64(&components, item->executable_device) != 0
            || buffer_u64(&components, item->executable_inode) != 0
            || buffer_u64(&components, item->executable_size) != 0
            || buffer_append(&components, item->executable_sha256, 32) != 0
            || buffer_append(&components, item->version_transcript_sha256, 32) != 0
            || buffer_u32(&packages, item->role) != 0
            || buffer_text(&packages, item->package_manager, 32) != 0
            || buffer_text(&packages, item->package_name, 128) != 0
            || buffer_text(&packages, item->package_version, 128) != 0
            || buffer_text(&packages, item->package_architecture, 32) != 0
            || buffer_append(&packages, item->package_receipt_sha256, 32) != 0
            || buffer_append(&packages, item->package_manifest_sha256, 32) != 0
            || buffer_append(&packages, item->package_signature_sha256, 32) != 0
            || buffer_append(&packages, item->package_signer_sha256, 32) != 0)
            return -1;
    }
    return hash_buffer(&components, component_sha256) == 0
        && hash_buffer(&packages, package_sha256) == 0 ? 0 : -1;
}

static int
image_closure(const struct plamen_broker_v2_podman_admission_spec *spec,
    uint8_t image_sha256[32])
{
    static const char domain[] = "PLAMEN-PODMAN-IMAGE-V1";
    struct closure_buffer closure;
    if (!reference_valid(spec->image_reference, spec->image_manifest_digest)
        || !digest_text(spec->image_index_digest)
        || !digest_text(spec->image_manifest_digest)
        || !digest_text(spec->image_config_digest)
        || strcmp(spec->image_index_digest, spec->image_manifest_digest) == 0
        || strcmp(spec->image_config_digest, spec->image_manifest_digest) == 0
        || validate_image(spec->image_inspect_transcript,
            spec->image_inspect_transcript_size, spec->image_reference,
            spec->image_manifest_digest, spec->architecture,
            spec->image_inspect_transcript_sha256) != 0) return -1;
    memset(&closure, 0, sizeof(closure));
    if (buffer_append(&closure, domain, sizeof(domain)) != 0
        || buffer_text(&closure, spec->image_reference,
            PLAMEN_BROKER_V2_PODMAN_REFERENCE_MAX - 1U) != 0
        || buffer_text(&closure, spec->image_index_digest, 71) != 0
        || buffer_text(&closure, spec->image_manifest_digest, 71) != 0
        || buffer_text(&closure, spec->image_config_digest, 71) != 0
        || buffer_u32(&closure, spec->architecture) != 0
        || buffer_append(&closure, spec->image_inspect_transcript_sha256, 32) != 0)
        return -1;
    return hash_buffer(&closure, image_sha256);
}
#endif

static int
receipt_digest(struct plamen_broker_v2_podman_admission_receipt *receipt,
    uint8_t output[32])
{
    struct plamen_broker_v2_podman_admission_receipt copy;
    if (receipt == NULL || output == NULL) return -1;
    memcpy(&copy, receipt, sizeof(copy));
    memset(copy.admission_sha256, 0, sizeof(copy.admission_sha256));
    return plamen_broker_v2_sha256(&copy, sizeof(copy), output);
}

int
plamen_broker_v2_podman_receipt_validate(
    const struct plamen_broker_v2_podman_admission_receipt *receipt)
{
    struct plamen_broker_v2_podman_admission_receipt copy;
    uint8_t digest[32];
    if (receipt == NULL) return -1;
    memcpy(&copy, receipt, sizeof(copy));
    if (receipt_digest(&copy, digest) != 0
        || copy.version != PLAMEN_BROKER_V2_PODMAN_RECEIPT_VERSION
        || copy.status != PLAMEN_BROKER_V2_PODMAN_ADMISSION_OK
        || copy.native_uid == 0 || copy.native_gid == 0
        || (copy.architecture != PLAMEN_BROKER_V2_PODMAN_ARCH_AMD64
            && copy.architecture != PLAMEN_BROKER_V2_PODMAN_ARCH_ARM64)
        || !digest_present(copy.request_fingerprint_sha256)
        || !digest_present(copy.provider_provenance_sha256)
        || !digest_present(copy.installed_closure_sha256)
        || !digest_present(copy.component_closure_sha256)
        || !digest_present(copy.package_closure_sha256)
        || !digest_present(copy.root_closure_sha256)
        || !digest_present(copy.cgroup_identity_sha256)
        || !digest_present(copy.systemd_unit_sha256)
        || !digest_present(copy.image_inspect_transcript_sha256)
        || !digest_present(copy.image_identity_sha256)
        || !constant_equal(digest, copy.admission_sha256, 32)
        || copy.component_descriptors_retained != 1U
        || copy.package_receipts_retained != 1U
        || copy.roots_componentwise_nofollow != 1U
        || copy.roots_descriptors_retained != 1U
        || copy.rootless_user_proven != 1U
        || copy.cgroup_v2_leaf_empty != 1U
        || copy.cgroup_kill_available != 1U
        || copy.overlay_topology_proven != 1U
        || copy.image_immutable_and_platform_exact != 1U
        || copy.commands_read_only != 1U
        || copy.receipt_requires_broker_authentication != 1U
        || copy.lifecycle_authority_granted != 0U) return -1;
    return 0;
}

int
plamen_broker_v2_podman_admit(
    const struct plamen_broker_v2_podman_admission_spec *spec,
    struct plamen_broker_v2_podman_admission_custody *custody)
{
    struct plamen_broker_v2_podman_admission_receipt *receipt;
    struct stat unit_identity;
    uint8_t unit_digest[32];
    size_t index;
#ifdef __linux__
    struct utsname host;
    uint8_t digest[32];
    int duplicate;
#endif
    if (custody == NULL) return PLAMEN_BROKER_V2_PODMAN_ADMISSION_REJECTED;
    custody_initialize(custody);
    receipt = &custody->receipt;
    receipt->version = PLAMEN_BROKER_V2_PODMAN_RECEIPT_VERSION;
#ifndef __linux__
    (void)spec; (void)unit_identity; (void)unit_digest; (void)index;
    receipt->status = PLAMEN_BROKER_V2_PODMAN_ADMISSION_UNSUPPORTED;
    return PLAMEN_BROKER_V2_PODMAN_ADMISSION_UNSUPPORTED;
#else
    if (spec == NULL || spec->version != PLAMEN_BROKER_V2_PODMAN_ADMISSION_VERSION
        || spec->native_uid == 0 || spec->native_gid == 0
        || spec->native_uid != (uint32_t)getuid()
        || spec->native_uid != (uint32_t)geteuid()
        || spec->native_gid != (uint32_t)getgid()
        || spec->native_gid != (uint32_t)getegid()
        || uname(&host) != 0
        || !((spec->architecture == PLAMEN_BROKER_V2_PODMAN_ARCH_AMD64
                && strcmp(host.machine, "x86_64") == 0)
            || (spec->architecture == PLAMEN_BROKER_V2_PODMAN_ARCH_ARM64
                && (strcmp(host.machine, "aarch64") == 0
                    || strcmp(host.machine, "arm64") == 0)))
        || !digest_present(spec->request_fingerprint_sha256)
        || !digest_present(spec->provider_provenance_sha256)
        || !digest_present(spec->installed_closure_sha256)
        || component_closures(spec, receipt->component_closure_sha256,
            receipt->package_closure_sha256) != 0
        || validate_roots(spec, receipt->root_closure_sha256) != 0
        || validate_cgroup(spec->cgroup_fd, spec->cgroup_device,
            spec->cgroup_inode, spec->cgroup_mount_id,
            receipt->cgroup_identity_sha256) != 0
        || hash_fd(spec->systemd_unit_fd, UNIT_MAX, unit_digest,
            &unit_identity) != 0
        || unit_identity.st_uid != 0
        || !constant_equal(unit_digest, spec->systemd_unit_sha256, 32)
        || image_closure(spec, receipt->image_identity_sha256) != 0)
        goto rejected;
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT; ++index) {
        duplicate = fcntl(spec->components[index].executable_fd,
            F_DUPFD_CLOEXEC, 3);
        if (duplicate < 0) goto rejected;
        custody->component_fds[index] = duplicate;
        duplicate = fcntl(spec->components[index].package_receipt_fd,
            F_DUPFD_CLOEXEC, 3);
        if (duplicate < 0) goto rejected;
        custody->package_receipt_fds[index] = duplicate;
        memcpy(custody->component_sha256[index],
            spec->components[index].executable_sha256, 32);
        memcpy(custody->package_receipt_sha256[index],
            spec->components[index].package_receipt_sha256, 32);
    }
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT; ++index) {
        duplicate = fcntl(spec->roots[index].fd, F_DUPFD_CLOEXEC, 3);
        if (duplicate < 0) goto rejected;
        custody->root_fds[index] = duplicate;
        custody->root_identity[index] = spec->roots[index];
        custody->root_identity[index].fd = duplicate;
    }
    custody->systemd_unit_fd = fcntl(spec->systemd_unit_fd,
        F_DUPFD_CLOEXEC, 3);
    custody->cgroup_fd = fcntl(spec->cgroup_fd, F_DUPFD_CLOEXEC, 3);
    if (custody->systemd_unit_fd < 0 || custody->cgroup_fd < 0) goto rejected;
    custody->cgroup_device = spec->cgroup_device;
    custody->cgroup_inode = spec->cgroup_inode;
    custody->cgroup_mount_id = spec->cgroup_mount_id;
    receipt->status = PLAMEN_BROKER_V2_PODMAN_ADMISSION_OK;
    receipt->native_uid = spec->native_uid;
    receipt->native_gid = spec->native_gid;
    receipt->architecture = spec->architecture;
    memcpy(receipt->request_fingerprint_sha256,
        spec->request_fingerprint_sha256, 32);
    memcpy(receipt->provider_provenance_sha256,
        spec->provider_provenance_sha256, 32);
    memcpy(receipt->installed_closure_sha256,
        spec->installed_closure_sha256, 32);
    memcpy(receipt->systemd_unit_sha256, unit_digest, 32);
    memcpy(receipt->image_inspect_transcript_sha256,
        spec->image_inspect_transcript_sha256, 32);
    receipt->component_descriptors_retained = 1U;
    receipt->package_receipts_retained = 1U;
    receipt->roots_componentwise_nofollow = 1U;
    receipt->roots_descriptors_retained = 1U;
    receipt->rootless_user_proven = 1U;
    receipt->cgroup_v2_leaf_empty = 1U;
    receipt->cgroup_kill_available = 1U;
    receipt->overlay_topology_proven = 1U;
    receipt->image_immutable_and_platform_exact = 1U;
    receipt->commands_read_only = 1U;
    receipt->receipt_requires_broker_authentication = 1U;
    receipt->lifecycle_authority_granted = 0U;
    if (receipt_digest(receipt, digest) != 0) goto rejected;
    memcpy(receipt->admission_sha256, digest, 32);
    custody->sealed = 1U;
    if (plamen_broker_v2_podman_custody_revalidate(custody) != 0)
        goto rejected;
    return PLAMEN_BROKER_V2_PODMAN_ADMISSION_OK;
rejected:
    plamen_broker_v2_podman_custody_close(custody);
    receipt = &custody->receipt;
    receipt->version = PLAMEN_BROKER_V2_PODMAN_RECEIPT_VERSION;
    receipt->status = PLAMEN_BROKER_V2_PODMAN_ADMISSION_REJECTED;
    return PLAMEN_BROKER_V2_PODMAN_ADMISSION_REJECTED;
#endif
}

int
plamen_broker_v2_podman_custody_revalidate(
    const struct plamen_broker_v2_podman_admission_custody *custody)
{
#ifndef __linux__
    (void)custody;
    return -1;
#else
    struct stat ignored;
    uint8_t digest[32], cgroup_digest[32];
    size_t index;
    if (custody == NULL || custody->sealed != 1U
        || plamen_broker_v2_podman_receipt_validate(&custody->receipt) != 0)
        return -1;
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT; ++index) {
        if (hash_fd(custody->component_fds[index], EXECUTABLE_MAX,
                digest, &ignored) != 0
            || !constant_equal(digest, custody->component_sha256[index], 32)
            || hash_fd(custody->package_receipt_fds[index],
                PACKAGE_RECEIPT_MAX, digest, &ignored) != 0
            || !constant_equal(digest,
                custody->package_receipt_sha256[index], 32)) return -1;
    }
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT; ++index)
        if (directory_identity(custody->root_fds[index],
                &custody->root_identity[index], custody->receipt.native_uid,
                index <= PLAMEN_BROKER_V2_PODMAN_ROOT_OVERLAY
                || index == PLAMEN_BROKER_V2_PODMAN_ROOT_UPPER
                || index == PLAMEN_BROKER_V2_PODMAN_ROOT_WORK) != 0
            || (index == PLAMEN_BROKER_V2_PODMAN_ROOT_MERGED
                && custody->root_identity[index].uid
                    != custody->receipt.native_uid)) return -1;
    if (hash_fd(custody->systemd_unit_fd, UNIT_MAX, digest, &ignored) != 0
        || !constant_equal(digest, custody->receipt.systemd_unit_sha256, 32)
        || validate_cgroup(custody->cgroup_fd, custody->cgroup_device,
            custody->cgroup_inode, custody->cgroup_mount_id,
            cgroup_digest) != 0
        || !constant_equal(cgroup_digest,
            custody->receipt.cgroup_identity_sha256, 32)) return -1;
    return 0;
#endif
}

#ifdef PLAMEN_BROKER_V2_PODMAN_ADMISSION_TEST_ONLY
int
plamen_broker_v2_podman_test_validate_component_version(uint32_t role,
    const uint8_t *bytes, size_t size, const char *exact_line,
    const uint8_t expected_sha256[32])
{
    return validate_component_version(role, bytes, size, exact_line,
        expected_sha256);
}

int
plamen_broker_v2_podman_test_validate_image(const uint8_t *bytes, size_t size,
    const char *reference, const char *manifest_digest, uint32_t architecture,
    const uint8_t expected_sha256[32])
{
    return validate_image(bytes, size, reference, manifest_digest,
        architecture, expected_sha256);
}

int
plamen_broker_v2_podman_test_render_read_command(uint32_t operation,
    const int component_fds[PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT],
    const int root_fds[PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT],
    const char *reference, const char *manifest_digest,
    uint8_t *output, size_t capacity, size_t *output_size)
{
    struct plamen_broker_v2_podman_admission_spec spec;
    struct plamen_broker_v2_podman_read_command command;
    size_t index, cursor = 0, length;
    if (component_fds == NULL || root_fds == NULL || output == NULL
        || output_size == NULL) return -1;
    memset(&spec, 0, sizeof(spec));
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT; ++index)
        spec.components[index].executable_fd = component_fds[index];
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT; ++index)
        spec.roots[index].fd = root_fds[index];
    spec.image_reference = reference;
    spec.image_manifest_digest = manifest_digest;
    if (plamen_broker_v2_podman_render_read_command(&spec, operation,
            &command) != 0) return -1;
    for (index = 0; index < command.argc; ++index) {
        length = strlen(command.argv[index]);
        if (length + 1U > capacity - cursor) return -1;
        memcpy(output + cursor, command.argv[index], length + 1U);
        cursor += length + 1U;
    }
    *output_size = cursor;
    return 0;
}

int
plamen_broker_v2_podman_test_relative_path_valid(const char *value)
{
    return relative_path_valid(value);
}

int
plamen_broker_v2_podman_test_receipt_integrity(void)
{
    struct plamen_broker_v2_podman_admission_receipt receipt;
    uint8_t digest[32];
    memset(&receipt, 0, sizeof(receipt));
    receipt.version = PLAMEN_BROKER_V2_PODMAN_RECEIPT_VERSION;
    receipt.status = PLAMEN_BROKER_V2_PODMAN_ADMISSION_OK;
    receipt.native_uid = 1000U;
    receipt.native_gid = 1000U;
    receipt.architecture = PLAMEN_BROKER_V2_PODMAN_ARCH_ARM64;
    memset(receipt.request_fingerprint_sha256, 1, 32);
    memset(receipt.provider_provenance_sha256, 2, 32);
    memset(receipt.installed_closure_sha256, 3, 32);
    memset(receipt.component_closure_sha256, 4, 32);
    memset(receipt.package_closure_sha256, 5, 32);
    memset(receipt.root_closure_sha256, 6, 32);
    memset(receipt.cgroup_identity_sha256, 7, 32);
    memset(receipt.systemd_unit_sha256, 8, 32);
    memset(receipt.image_inspect_transcript_sha256, 9, 32);
    memset(receipt.image_identity_sha256, 10, 32);
    receipt.component_descriptors_retained = 1U;
    receipt.package_receipts_retained = 1U;
    receipt.roots_componentwise_nofollow = 1U;
    receipt.roots_descriptors_retained = 1U;
    receipt.rootless_user_proven = 1U;
    receipt.cgroup_v2_leaf_empty = 1U;
    receipt.cgroup_kill_available = 1U;
    receipt.overlay_topology_proven = 1U;
    receipt.image_immutable_and_platform_exact = 1U;
    receipt.commands_read_only = 1U;
    receipt.receipt_requires_broker_authentication = 1U;
    receipt.lifecycle_authority_granted = 0U;
    if (receipt_digest(&receipt, digest) != 0) return -1;
    memcpy(receipt.admission_sha256, digest, sizeof(digest));
    if (plamen_broker_v2_podman_receipt_validate(&receipt) != 0) return -1;
    receipt.package_closure_sha256[0] ^= 1U;
    return plamen_broker_v2_podman_receipt_validate(&receipt) != 0 ? 0 : -1;
}
#endif
