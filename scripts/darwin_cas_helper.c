/*
 * Crash-isolated Darwin durable write-once publication helper.
 *
 * Python deliberately does not bind Darwin's private/non-POSIX filesystem
 * entry points through ctypes.  This small, typed helper receives already
 * opened directory/source descriptors and uses fclonefileat(2)'s atomic
 * absent-destination clone.
 */

#include <sys/acl.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <sys/stdio.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define PLAMEN_EXIT_EXISTS 17
#define PLAMEN_EXIT_UNSUPPORTED 74
#define PLAMEN_EXIT_FAILED 75
#define PLAMEN_EXIT_QUARANTINED_FOREIGN 76

#ifndef PLAMEN_MAX_PAYLOAD_BYTES
#define PLAMEN_MAX_PAYLOAD_BYTES (1024ULL * 1024ULL * 1024ULL)
#endif

static int
fail_at(const char *stage, int error, int code)
{
    if (error == 0) {
        error = EIO;
    }
    (void)fprintf(stderr,
        "PLAMEN_DARWIN_CAS_ERROR stage=%s errno=%d detail=%s\n",
        stage, error, strerror(error));
    return code;
}

static int
parse_fd(const char *value, int *result)
{
    char *end = NULL;
    long parsed;

    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < 3 ||
        parsed > INT32_MAX) {
        return -1;
    }
    *result = (int)parsed;
    return 0;
}

static int
parse_u64(const char *value, uint64_t *result)
{
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return -1;
    }
    *result = (uint64_t)parsed;
    return 0;
}

static int
safe_component(const char *value)
{
    if (value == NULL || value[0] == '\0' || strcmp(value, ".") == 0 ||
        strcmp(value, "..") == 0 || strchr(value, '/') != NULL) {
        return 0;
    }
    return strlen(value) <= 255;
}

static int
read_stdin(unsigned char **bytes, size_t *size, uint64_t declared_size)
{
    unsigned char *buffer = NULL;
    size_t used = 0;
    unsigned char trailing;

    if (declared_size > PLAMEN_MAX_PAYLOAD_BYTES ||
        declared_size > SIZE_MAX) {
        errno = EFBIG;
        return -1;
    }
    if (declared_size > 0) {
        buffer = malloc((size_t)declared_size);
        if (buffer == NULL) {
            errno = ENOMEM;
            return -1;
        }
    }
    while (used < (size_t)declared_size) {
        ssize_t amount;

        amount = read(STDIN_FILENO, buffer + used,
            (size_t)declared_size - used);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount < 0) {
            int saved = errno;
            free(buffer);
            errno = saved;
            return -1;
        }
        if (amount == 0) {
            free(buffer);
            errno = EMSGSIZE;
            return -1;
        }
        used += (size_t)amount;
    }
    for (;;) {
        ssize_t amount = read(STDIN_FILENO, &trailing, 1);

        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount < 0) {
            int saved = errno;
            free(buffer);
            errno = saved;
            return -1;
        }
        if (amount != 0) {
            free(buffer);
            errno = EMSGSIZE;
            return -1;
        }
        break;
    }
    *bytes = buffer;
    *size = used;
    return 0;
}

static int
descriptor_is_exact(int descriptor, const unsigned char *bytes, size_t size)
{
    struct stat row;
    unsigned char buffer[65536];
    size_t offset = 0;

    if (fstat(descriptor, &row) != 0 || !S_ISREG(row.st_mode) ||
        row.st_size < 0 || (uint64_t)row.st_size != (uint64_t)size) {
        return 0;
    }
    while (offset < size) {
        size_t requested = size - offset;
        ssize_t amount;

        if (requested > sizeof(buffer)) {
            requested = sizeof(buffer);
        }
        amount = pread(descriptor, buffer, requested, (off_t)offset);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0 || memcmp(buffer, bytes + offset, (size_t)amount) != 0) {
            return 0;
        }
        offset += (size_t)amount;
    }
    return 1;
}

static int
same_identity(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int
descriptor_has_extended_acl(int descriptor)
{
    acl_t acl;
    acl_entry_t entry;
    int result;
    int saved;

    errno = 0;
    acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        return -1;
    }
    errno = 0;
    result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    saved = errno;
    if (acl_free(acl) != 0) {
        return -1;
    }
    if (result == 0) {
        return 1;
    }
    if (result < 0 && saved == EINVAL) {
        return 0;
    }
    errno = saved == 0 ? EIO : saved;
    return -1;
}

static int
descriptor_metadata_is_clean(int descriptor, int directory)
{
    struct stat row;
    int has_acl;

    if (fstat(descriptor, &row) != 0 || row.st_uid != geteuid() ||
        row.st_flags != 0) {
        errno = ESTALE;
        return 0;
    }
    if (directory) {
        if (!S_ISDIR(row.st_mode) || (row.st_mode & 0022) != 0) {
            errno = EPERM;
            return 0;
        }
    } else {
        if (!S_ISREG(row.st_mode) ||
            (row.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != 0600 ||
            flistxattr(descriptor, NULL, 0, 0) != 0) {
            errno = ESTALE;
            return 0;
        }
    }
    has_acl = descriptor_has_extended_acl(descriptor);
    if (has_acl != 0) {
        if (has_acl > 0) {
            errno = EACCES;
        }
        return 0;
    }
    return 1;
}

static int
durable_sync(int descriptor)
{
    if (fsync(descriptor) != 0) {
        return -1;
    }
    if (fcntl(descriptor, F_FULLFSYNC, 0) != 0) {
        return -1;
    }
    return 0;
}

static int
validate_named_destination(int directory_fd, const char *name,
    int descriptor, const unsigned char *bytes, size_t size)
{
    struct stat opened;
    struct stat named;

    if (fstat(descriptor, &opened) != 0 ||
        fstatat(directory_fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    if (!S_ISREG(opened.st_mode) || !S_ISREG(named.st_mode) ||
        opened.st_nlink != 1 || named.st_nlink != 1 ||
        !same_identity(&opened, &named) ||
        !descriptor_metadata_is_clean(descriptor, 0) ||
        !descriptor_is_exact(descriptor, bytes, size)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int
publish_clone(int source_fd, int directory_fd, const char *destination,
    const unsigned char *bytes, size_t size)
{
    int destination_fd = -1;

    if (!descriptor_metadata_is_clean(source_fd, 0) ||
        !descriptor_is_exact(source_fd, bytes, size)) {
        return fail_at("source-pre-clone", ESTALE, PLAMEN_EXIT_FAILED);
    }
    if (durable_sync(source_fd) != 0) {
        return fail_at("source-fsync", errno, PLAMEN_EXIT_FAILED);
    }
    if (fclonefileat(source_fd, directory_fd, destination,
        CLONE_NOOWNERCOPY) != 0) {
        int saved = errno;
        if (saved == EEXIST) {
            return fail_at("destination-exists", saved, PLAMEN_EXIT_EXISTS);
        }
        if (saved == ENOTSUP || saved == EXDEV) {
            return fail_at("clone-unsupported", saved,
                PLAMEN_EXIT_UNSUPPORTED);
        }
        return fail_at("clone", saved, PLAMEN_EXIT_FAILED);
    }
    destination_fd = openat(directory_fd, destination,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (destination_fd < 0 ||
        validate_named_destination(directory_fd, destination, destination_fd,
            bytes, size) != 0) {
        int saved = errno == 0 ? ESTALE : errno;
        if (destination_fd >= 0) {
            (void)close(destination_fd);
        }
        return fail_at("destination-first-validation", saved,
            PLAMEN_EXIT_FAILED);
    }
    if (durable_sync(destination_fd) != 0 ||
        durable_sync(directory_fd) != 0) {
        int saved = errno;
        (void)close(destination_fd);
        return fail_at("destination-durability", saved, PLAMEN_EXIT_FAILED);
    }
    if (validate_named_destination(directory_fd, destination, destination_fd,
        bytes, size) != 0 ||
        !descriptor_metadata_is_clean(directory_fd, 1)) {
        int saved = errno == 0 ? ESTALE : errno;
        (void)close(destination_fd);
        return fail_at("destination-final-validation", saved,
            PLAMEN_EXIT_FAILED);
    }
    if (close(destination_fd) != 0) {
        return fail_at("destination-close", errno, PLAMEN_EXIT_FAILED);
    }
    return 0;
}

static int
quarantine_stage(int source_fd, int directory_fd, const char *stage,
    uint64_t expected_device, uint64_t expected_inode,
    const unsigned char *bytes, size_t size)
{
    char quarantine[512];
    int quarantine_fd = -1;
    struct stat row;

    if (snprintf(quarantine, sizeof(quarantine), "%s.abandoned", stage) < 0 ||
        strlen(quarantine) >= sizeof(quarantine) ||
        !safe_component(quarantine)) {
        return fail_at("quarantine-name", ENAMETOOLONG, PLAMEN_EXIT_FAILED);
    }
    if (renameatx_np(directory_fd, stage, directory_fd, quarantine,
        RENAME_EXCL | RENAME_NOFOLLOW_ANY) != 0) {
        return fail_at("stage-quarantine-rename", errno, PLAMEN_EXIT_FAILED);
    }
    quarantine_fd = openat(directory_fd, quarantine,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (quarantine_fd >= 0 && fstat(quarantine_fd, &row) == 0 &&
        (uint64_t)row.st_dev == expected_device &&
        (uint64_t)row.st_ino == expected_inode && row.st_nlink == 1 &&
        descriptor_metadata_is_clean(source_fd, 0) &&
        descriptor_metadata_is_clean(quarantine_fd, 0) &&
        descriptor_is_exact(source_fd, bytes, size) &&
        descriptor_is_exact(quarantine_fd, bytes, size)) {
        if (durable_sync(quarantine_fd) == 0 &&
            durable_sync(directory_fd) == 0 &&
            descriptor_metadata_is_clean(directory_fd, 1) &&
            validate_named_destination(directory_fd, quarantine, source_fd,
                bytes, size) == 0 &&
            validate_named_destination(directory_fd, quarantine,
                quarantine_fd, bytes, size) == 0) {
            if (fstatat(directory_fd, stage, &row,
                AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT) {
                (void)close(quarantine_fd);
                return 0;
            }
        }
    }
    if (quarantine_fd >= 0) {
        (void)close(quarantine_fd);
    }
    /* Preserve the raced object under one of the two names; never unlink it. */
    (void)renameatx_np(directory_fd, quarantine, directory_fd, stage,
        RENAME_EXCL | RENAME_NOFOLLOW_ANY);
    (void)fsync(directory_fd);
    return fail_at("stage-quarantine-foreign", ESTALE,
        PLAMEN_EXIT_QUARANTINED_FOREIGN);
}

int
main(int argc, char **argv)
{
    const char *mode;
    const char *destination;
    const char *stage;
    unsigned char *bytes = NULL;
    size_t size = 0;
    int directory_fd;
    int source_fd = -1;
    uint64_t expected_device = 0;
    uint64_t expected_inode = 0;
    uint64_t declared_size = 0;
    struct stat directory_row;
    struct stat source_row;
    int result;

    if (argc != 9 || parse_fd(argv[2], &directory_fd) != 0 ||
        parse_fd(argv[4], &source_fd) != 0 ||
        parse_u64(argv[5], &expected_device) != 0 ||
        parse_u64(argv[6], &expected_inode) != 0 ||
        parse_u64(argv[8], &declared_size) != 0) {
        return fail_at("arguments", EINVAL, PLAMEN_EXIT_FAILED);
    }
    mode = argv[1];
    destination = argv[3];
    stage = argv[7];
    if ((strcmp(mode, "publish") != 0 && strcmp(mode, "retire") != 0 &&
        strcmp(mode, "validate") != 0) ||
        !safe_component(destination) ||
        ((strcmp(mode, "validate") == 0) != (strcmp(stage, "-") == 0)) ||
        (strcmp(stage, "-") != 0 && !safe_component(stage)) ||
        fstat(directory_fd, &directory_row) != 0 ||
        !S_ISDIR(directory_row.st_mode) ||
        !descriptor_metadata_is_clean(directory_fd, 1)) {
        return fail_at("arguments", EINVAL, PLAMEN_EXIT_FAILED);
    }
    if (read_stdin(&bytes, &size, declared_size) != 0) {
        return fail_at("stdin", errno, PLAMEN_EXIT_FAILED);
    }
    if (fstat(source_fd, &source_row) != 0 ||
        !S_ISREG(source_row.st_mode) || source_row.st_nlink != 1 ||
        (uint64_t)source_row.st_dev != expected_device ||
        (uint64_t)source_row.st_ino != expected_inode ||
        !descriptor_metadata_is_clean(source_fd, 0)) {
        result = fail_at("source-identity", ESTALE, PLAMEN_EXIT_FAILED);
        goto out;
    }
    if (!descriptor_is_exact(source_fd, bytes, size)) {
        result = fail_at("source-postimage", ESTALE, PLAMEN_EXIT_FAILED);
        goto out;
    }
    if (strcmp(mode, "validate") == 0) {
        if (validate_named_destination(directory_fd, destination, source_fd,
            bytes, size) != 0 || fsync(source_fd) != 0 ||
            durable_sync(directory_fd) != 0 ||
            !descriptor_metadata_is_clean(directory_fd, 1) ||
            validate_named_destination(directory_fd, destination, source_fd,
            bytes, size) != 0) {
            result = fail_at("validation", errno, PLAMEN_EXIT_FAILED);
            goto out;
        }
    } else if (strcmp(mode, "publish") == 0) {
        result = publish_clone(source_fd, directory_fd, destination,
            bytes, size);
        if (result != 0) {
            goto out;
        }
    }
    if (strcmp(mode, "validate") != 0) {
        result = quarantine_stage(source_fd, directory_fd, stage,
            expected_device, expected_inode, bytes, size);
        if (result != 0) {
            goto out;
        }
    }
    result = 0;

out:
    free(bytes);
    return result;
}
