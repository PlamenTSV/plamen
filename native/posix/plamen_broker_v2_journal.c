#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_broker_v2_journal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#error "broker v2 journal requires O_NOFOLLOW"
#endif
#ifndef O_CLOEXEC
#error "broker v2 journal requires O_CLOEXEC"
#endif

static const uint8_t journal_magic[8] = {
    'P', 'L', 'M', 'J', 'R', 'N', '2', '\0'
};

struct plamen_broker_v2_journal {
    int directory_fd;
    int lock_fd;
    int poisoned;
};

struct owned_record {
    struct plamen_broker_v2_journal_record view;
    uint8_t *bytes;
};

static void
put_u16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void
put_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void
put_u64(uint8_t *out, uint64_t value)
{
    unsigned index;
    for (index = 0; index < 8; ++index)
        out[index] = (uint8_t)(value >> (56U - index * 8U));
}

static uint16_t
get_u16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint32_t
get_u32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | in[3];
}

static uint64_t
get_u64(const uint8_t *in)
{
    uint64_t value = 0;
    unsigned index;
    for (index = 0; index < 8; ++index)
        value = (value << 8) | in[index];
    return value;
}

static int
is_zero(const uint8_t value[32])
{
    uint8_t total = 0;
    unsigned index;
    for (index = 0; index < 32; ++index) total |= value[index];
    return total == 0;
}

static int
valid_identifier(const char *value)
{
    size_t index, size;
    if (value == NULL || (size = strnlen(value, PLAMEN_BROKER_V2_MAX_ID + 1)) == 0
        || size > PLAMEN_BROKER_V2_MAX_ID)
        return 0;
    for (index = 0; index < size; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == ':'
            || c == '-'))
            return 0;
    }
    return 1;
}

static int
private_directory(int fd)
{
    struct stat info;
    return fstat(fd, &info) == 0 && S_ISDIR(info.st_mode)
        && info.st_uid == geteuid() && (info.st_mode & 0077) == 0;
}

static int
valid_lock(int fd)
{
    struct stat info;
    return fstat(fd, &info) == 0 && S_ISREG(info.st_mode)
        && info.st_uid == geteuid() && info.st_nlink == 1
        && (info.st_mode & 0777) == 0600;
}

static int
set_lock(int fd, short type)
{
    struct flock lock;
    int result;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = type;
    lock.l_whence = SEEK_SET;
    do {
        result = fcntl(fd, type == F_UNLCK ? F_SETLK : F_SETLKW, &lock);
    } while (result != 0 && errno == EINTR);
    return result == 0 ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_SYSTEM;
}

int
plamen_broker_v2_journal_open(int parent_fd, const char *journal_id,
    struct plamen_broker_v2_journal **out)
{
    struct plamen_broker_v2_journal *journal = NULL;
    int directory_fd = -1, lock_fd = -1, created_directory = 0, created_lock = 0;
    if (out == NULL || !valid_identifier(journal_id) || !private_directory(parent_fd))
        return PLAMEN_BROKER_V2_INVALID;
    *out = NULL;
    if (mkdirat(parent_fd, journal_id, 0700) == 0) {
        created_directory = 1;
    } else if (errno != EEXIST) {
        return PLAMEN_BROKER_V2_SYSTEM;
    }
    directory_fd = openat(parent_fd, journal_id,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0 || !private_directory(directory_fd))
        goto invalid;
    if (created_directory && fsync(parent_fd) != 0)
        goto system;
    lock_fd = openat(directory_fd, ".lock",
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock_fd >= 0) {
        created_lock = 1;
    } else if (errno == EEXIST) {
        lock_fd = openat(directory_fd, ".lock", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    }
    if (lock_fd < 0 || !valid_lock(lock_fd))
        goto invalid;
    if (created_lock && (fsync(lock_fd) != 0 || fsync(directory_fd) != 0))
        goto system;
    journal = calloc(1, sizeof(*journal));
    if (journal == NULL)
        goto system;
    journal->directory_fd = directory_fd;
    journal->lock_fd = lock_fd;
    *out = journal;
    return PLAMEN_BROKER_V2_OK;
invalid:
    if (lock_fd >= 0) close(lock_fd);
    if (directory_fd >= 0) close(directory_fd);
    return PLAMEN_BROKER_V2_INVALID;
system:
    if (lock_fd >= 0) close(lock_fd);
    if (directory_fd >= 0) close(directory_fd);
    free(journal);
    return PLAMEN_BROKER_V2_SYSTEM;
}

void
plamen_broker_v2_journal_close(struct plamen_broker_v2_journal *journal)
{
    if (journal != NULL) {
        if (journal->lock_fd >= 0) close(journal->lock_fd);
        if (journal->directory_fd >= 0) close(journal->directory_fd);
        plamen_broker_v2_secure_zero(journal, sizeof(*journal));
        free(journal);
    }
}

static int
record_filename(uint64_t sequence, char out[25])
{
    int count;
    if (sequence == 0 || sequence > PLAMEN_BROKER_V2_JOURNAL_MAX_RECORDS)
        return PLAMEN_BROKER_V2_INVALID;
    count = snprintf(out, 25, "%020" PRIu64 ".rec", sequence);
    return count == 24 ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_INVALID;
}

static int
parse_record_filename(const char *name, uint64_t *sequence)
{
    uint64_t value = 0;
    unsigned index;
    if (name == NULL || sequence == NULL || strlen(name) != 24
        || memcmp(name + 20, ".rec", 4) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    for (index = 0; index < 20; ++index) {
        if (name[index] < '0' || name[index] > '9')
            return PLAMEN_BROKER_V2_INVALID;
        if (value > (UINT64_MAX - (uint64_t)(name[index] - '0')) / 10)
            return PLAMEN_BROKER_V2_INVALID;
        value = value * 10 + (uint64_t)(name[index] - '0');
    }
    if (value == 0 || value > PLAMEN_BROKER_V2_JOURNAL_MAX_RECORDS)
        return PLAMEN_BROKER_V2_INVALID;
    *sequence = value;
    return PLAMEN_BROKER_V2_OK;
}

static int
scan_directory(struct plamen_broker_v2_journal *journal, uint64_t *count)
{
    DIR *directory;
    struct dirent *entry;
    uint64_t seen = 0, maximum = 0, sequence;
    int scan_fd = openat(journal->directory_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0 || (directory = fdopendir(scan_fd)) == NULL) {
        if (scan_fd >= 0) close(scan_fd);
        return PLAMEN_BROKER_V2_SYSTEM;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0
            || strcmp(entry->d_name, ".lock") == 0)
            continue;
        if (parse_record_filename(entry->d_name, &sequence) != 0) {
            closedir(directory);
            return PLAMEN_BROKER_V2_CORRUPT;
        }
        ++seen;
        if (sequence > maximum) maximum = sequence;
    }
    if (errno != 0) {
        closedir(directory);
        return PLAMEN_BROKER_V2_SYSTEM;
    }
    closedir(directory);
    if (seen != maximum) return PLAMEN_BROKER_V2_CORRUPT;
    *count = seen;
    return PLAMEN_BROKER_V2_OK;
}

static void
owned_record_clear(struct owned_record *record)
{
    if (record != NULL) {
        if (record->bytes != NULL) {
            plamen_broker_v2_secure_zero(record->bytes, record->view.canonical_size);
            free(record->bytes);
        }
        memset(record, 0, sizeof(*record));
    }
}

static int
read_full_at(int fd, uint8_t *data, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = pread(fd, data + offset, size - offset, (off_t)offset);
        if (amount <= 0) return PLAMEN_BROKER_V2_CORRUPT;
        offset += (size_t)amount;
    }
    return PLAMEN_BROKER_V2_OK;
}

static int
hash_record_prefix_payload(const uint8_t *bytes, size_t size, uint8_t out[32])
{
    uint8_t *canonical;
    size_t payload_size;
    int result;
    if (size < PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE)
        return PLAMEN_BROKER_V2_CORRUPT;
    payload_size = size - PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE;
    canonical = malloc(160 + payload_size);
    if (canonical == NULL) return PLAMEN_BROKER_V2_NOMEM;
    memcpy(canonical, bytes, 160);
    if (payload_size != 0)
        memcpy(canonical + 160, bytes + PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE,
            payload_size);
    result = plamen_broker_v2_sha256(canonical, 160 + payload_size, out);
    plamen_broker_v2_secure_zero(canonical, 160 + payload_size);
    free(canonical);
    return result;
}

static int
read_record(struct plamen_broker_v2_journal *journal, uint64_t sequence,
    struct owned_record *record)
{
    char name[25];
    struct stat before, after;
    uint8_t payload_digest[32], record_digest[32];
    uint32_t payload_size;
    size_t total;
    int fd = -1, result = PLAMEN_BROKER_V2_CORRUPT;
    memset(record, 0, sizeof(*record));
    if (record_filename(sequence, name) != 0)
        return PLAMEN_BROKER_V2_CORRUPT;
    fd = openat(journal->directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_uid != geteuid() || before.st_nlink != 1
        || (before.st_mode & 0777) != 0400
        || before.st_size < PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE
        || before.st_size > (off_t)(PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE
            + PLAMEN_BROKER_V2_MAX_PAYLOAD))
        goto done;
    total = (size_t)before.st_size;
    record->bytes = malloc(total);
    if (record->bytes == NULL) { result = PLAMEN_BROKER_V2_NOMEM; goto done; }
    if (read_full_at(fd, record->bytes, total) != 0 || fstat(fd, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_size != after.st_size
#ifdef __APPLE__
        || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
        || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
        || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec
        || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec
#else
        || before.st_mtim.tv_sec != after.st_mtim.tv_sec
        || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec
        || before.st_ctim.tv_sec != after.st_ctim.tv_sec
        || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec
#endif
        || after.st_nlink != 1)
        goto done;
    payload_size = get_u32(record->bytes + 16);
    if (memcmp(record->bytes, journal_magic, 8) != 0
        || get_u16(record->bytes + 8) != PLAMEN_BROKER_V2_JOURNAL_VERSION
        || get_u32(record->bytes + 12) != PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE
        || get_u32(record->bytes + 20) != 0
        || get_u64(record->bytes + 24) != sequence
        || payload_size > PLAMEN_BROKER_V2_MAX_PAYLOAD
        || total != PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE + (size_t)payload_size
        || plamen_broker_v2_sha256(
            record->bytes + PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE, payload_size,
            payload_digest) != 0
        || memcmp(payload_digest, record->bytes + 128, 32) != 0
        || hash_record_prefix_payload(record->bytes, total, record_digest) != 0
        || memcmp(record_digest, record->bytes + 160, 32) != 0)
        goto done;
    record->view.sequence = sequence;
    record->view.state = get_u16(record->bytes + 10);
    memcpy(record->view.operation_key, record->bytes + 32, 32);
    memcpy(record->view.request_sha256, record->bytes + 64, 32);
    memcpy(record->view.previous_checkpoint_sha256, record->bytes + 96, 32);
    memcpy(record->view.payload_sha256, record->bytes + 128, 32);
    memcpy(record->view.checkpoint_sha256, record->bytes + 160, 32);
    record->view.payload = record->bytes + PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE;
    record->view.payload_size = payload_size;
    record->view.canonical_bytes = record->bytes;
    record->view.canonical_size = total;
    result = PLAMEN_BROKER_V2_OK;
done:
    if (fd >= 0) close(fd);
    if (result != 0) owned_record_clear(record);
    return result;
}

static int
state_known(uint16_t state)
{
    return state >= PLAMEN_BROKER_V2_JOURNAL_PREPARED
        && state <= PLAMEN_BROKER_V2_JOURNAL_REVOKED;
}

static int
transition_valid(const struct owned_record *previous,
    const struct owned_record *current)
{
    uint16_t from = previous == NULL ? 0 : previous->view.state;
    uint16_t to = current->view.state;
    int same_effect = 0;
    if ((from == 0 && to == PLAMEN_BROKER_V2_JOURNAL_PREPARED)
        || (from == PLAMEN_BROKER_V2_JOURNAL_PREPARED
            && (to == PLAMEN_BROKER_V2_JOURNAL_STARTED
                || to == PLAMEN_BROKER_V2_JOURNAL_REVOKE_PREPARED))
        || (from == PLAMEN_BROKER_V2_JOURNAL_STARTED
            && (to == PLAMEN_BROKER_V2_JOURNAL_WAIT_PREPARED
                || to == PLAMEN_BROKER_V2_JOURNAL_REVOKE_PREPARED))
        || (from == PLAMEN_BROKER_V2_JOURNAL_WAIT_PREPARED
            && (to == PLAMEN_BROKER_V2_JOURNAL_EXITED
                || to == PLAMEN_BROKER_V2_JOURNAL_REVOKE_PREPARED))
        || (from == PLAMEN_BROKER_V2_JOURNAL_EXITED
            && to == PLAMEN_BROKER_V2_JOURNAL_REVOKE_PREPARED)
        || (from == PLAMEN_BROKER_V2_JOURNAL_REVOKE_PREPARED
            && to == PLAMEN_BROKER_V2_JOURNAL_REVOKED)) {
        same_effect = (from == PLAMEN_BROKER_V2_JOURNAL_PREPARED
                && to == PLAMEN_BROKER_V2_JOURNAL_STARTED)
            || (from == PLAMEN_BROKER_V2_JOURNAL_WAIT_PREPARED
                && to == PLAMEN_BROKER_V2_JOURNAL_EXITED)
            || (from == PLAMEN_BROKER_V2_JOURNAL_REVOKE_PREPARED
                && to == PLAMEN_BROKER_V2_JOURNAL_REVOKED);
        if (!same_effect) return 1;
        return memcmp(previous->view.operation_key, current->view.operation_key, 32) == 0
            && memcmp(previous->view.request_sha256,
                current->view.request_sha256, 32) == 0;
    }
    return 0;
}

static int
replay_locked(struct plamen_broker_v2_journal *journal,
    plamen_broker_v2_journal_visitor visitor, void *visitor_context,
    struct owned_record *head)
{
    uint64_t count = 0, sequence;
    struct owned_record previous, current;
    int result;
    memset(&previous, 0, sizeof(previous));
    memset(&current, 0, sizeof(current));
    memset(head, 0, sizeof(*head));
    result = scan_directory(journal, &count);
    if (result != 0) goto done;
    for (sequence = 1; sequence <= count; ++sequence) {
        result = read_record(journal, sequence, &current);
        if (result != 0 || !state_known(current.view.state)
            || is_zero(current.view.operation_key) || is_zero(current.view.request_sha256)
            || (sequence == 1
                ? !is_zero(current.view.previous_checkpoint_sha256)
                : memcmp(current.view.previous_checkpoint_sha256,
                    previous.view.checkpoint_sha256, 32) != 0)
            || !transition_valid(sequence == 1 ? NULL : &previous, &current)) {
            if (result == 0) result = PLAMEN_BROKER_V2_CORRUPT;
            goto done;
        }
        if (visitor != NULL && visitor(&current.view, visitor_context) != 0) {
            result = PLAMEN_BROKER_V2_INVALID;
            goto done;
        }
        owned_record_clear(&previous);
        previous = current;
        memset(&current, 0, sizeof(current));
    }
    *head = previous;
    memset(&previous, 0, sizeof(previous));
    result = PLAMEN_BROKER_V2_OK;
done:
    owned_record_clear(&current);
    owned_record_clear(&previous);
    if (result == PLAMEN_BROKER_V2_CORRUPT)
        journal->poisoned = 1;
    return result;
}

int
plamen_broker_v2_journal_replay(struct plamen_broker_v2_journal *journal,
    plamen_broker_v2_journal_visitor visitor, void *visitor_context,
    struct plamen_broker_v2_journal_record *head)
{
    struct owned_record owned_head;
    int result;
    if (journal == NULL || head == NULL || journal->poisoned)
        return journal != NULL && journal->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    memset(head, 0, sizeof(*head));
    if (set_lock(journal->lock_fd, F_WRLCK) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    result = replay_locked(journal, visitor, visitor_context, &owned_head);
    if (result == 0) {
        *head = owned_head.view;
        head->payload = NULL;
        head->canonical_bytes = NULL;
        owned_record_clear(&owned_head);
    }
    if (set_lock(journal->lock_fd, F_UNLCK) != 0 && result == 0)
        result = PLAMEN_BROKER_V2_SYSTEM;
    return result;
}

static int
build_record(uint64_t sequence, uint16_t state, const uint8_t operation_key[32],
    const uint8_t request_sha256[32], const uint8_t previous[32],
    const uint8_t *payload, uint32_t payload_size, struct owned_record *record)
{
    size_t total = PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE + (size_t)payload_size;
    int result;
    memset(record, 0, sizeof(*record));
    record->bytes = calloc(1, total);
    if (record->bytes == NULL) return PLAMEN_BROKER_V2_NOMEM;
    memcpy(record->bytes, journal_magic, 8);
    put_u16(record->bytes + 8, PLAMEN_BROKER_V2_JOURNAL_VERSION);
    put_u16(record->bytes + 10, state);
    put_u32(record->bytes + 12, PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE);
    put_u32(record->bytes + 16, payload_size);
    put_u32(record->bytes + 20, 0);
    put_u64(record->bytes + 24, sequence);
    memcpy(record->bytes + 32, operation_key, 32);
    memcpy(record->bytes + 64, request_sha256, 32);
    memcpy(record->bytes + 96, previous, 32);
    if (payload_size != 0)
        memcpy(record->bytes + PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE,
            payload, payload_size);
    result = plamen_broker_v2_sha256(payload, payload_size, record->bytes + 128);
    if (result == 0)
        result = hash_record_prefix_payload(record->bytes, total, record->bytes + 160);
    if (result != 0) { owned_record_clear(record); return result; }
    record->view.sequence = sequence;
    record->view.state = state;
    memcpy(record->view.operation_key, operation_key, 32);
    memcpy(record->view.request_sha256, request_sha256, 32);
    memcpy(record->view.previous_checkpoint_sha256, previous, 32);
    memcpy(record->view.payload_sha256, record->bytes + 128, 32);
    memcpy(record->view.checkpoint_sha256, record->bytes + 160, 32);
    record->view.payload = record->bytes + PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE;
    record->view.payload_size = payload_size;
    record->view.canonical_bytes = record->bytes;
    record->view.canonical_size = total;
    return PLAMEN_BROKER_V2_OK;
}

static int
write_full(int fd, const uint8_t *data, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = write(fd, data + offset, size - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return PLAMEN_BROKER_V2_SYSTEM;
        offset += (size_t)amount;
    }
    return PLAMEN_BROKER_V2_OK;
}

static int
commit_record(struct plamen_broker_v2_journal *journal,
    const struct owned_record *record)
{
    char name[25];
    int fd;
    if (record_filename(record->view.sequence, name) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    fd = openat(journal->directory_fd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0400);
    if (fd < 0) return errno == EEXIST
        ? PLAMEN_BROKER_V2_CONFLICT : PLAMEN_BROKER_V2_SYSTEM;
    if (write_full(fd, record->bytes, record->view.canonical_size) != 0
        || fsync(fd) != 0) {
        close(fd);
        return PLAMEN_BROKER_V2_SYSTEM;
    }
    if (close(fd) != 0 || fsync(journal->directory_fd) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_journal_append(struct plamen_broker_v2_journal *journal,
    uint16_t state, const uint8_t operation_key[32],
    const uint8_t request_sha256[32], const uint8_t expected_previous[32],
    const uint8_t *payload, uint32_t payload_size, uint8_t checkpoint[32])
{
    struct owned_record head, candidate;
    uint64_t next_sequence;
    int result;
    if (journal == NULL || operation_key == NULL || request_sha256 == NULL
        || expected_previous == NULL || checkpoint == NULL || !state_known(state)
        || is_zero(operation_key) || is_zero(request_sha256)
        || payload_size > PLAMEN_BROKER_V2_MAX_PAYLOAD
        || (payload_size != 0 && payload == NULL) || journal->poisoned)
        return journal != NULL && journal->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    memset(&head, 0, sizeof(head));
    memset(&candidate, 0, sizeof(candidate));
    if (set_lock(journal->lock_fd, F_WRLCK) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    result = replay_locked(journal, NULL, NULL, &head);
    if (result != 0) goto done;
    if (head.bytes != NULL
        && memcmp(head.view.previous_checkpoint_sha256, expected_previous, 32) == 0
        && head.view.state == state) {
        result = build_record(head.view.sequence, state, operation_key, request_sha256,
            expected_previous, payload, payload_size, &candidate);
        if (result == 0
            && (candidate.view.canonical_size != head.view.canonical_size
                || memcmp(candidate.bytes, head.bytes,
                    candidate.view.canonical_size) != 0))
            result = PLAMEN_BROKER_V2_CONFLICT;
        if (result == 0)
            memcpy(checkpoint, head.view.checkpoint_sha256, 32);
        goto done;
    }
    if ((head.bytes == NULL && !is_zero(expected_previous))
        || (head.bytes != NULL && memcmp(head.view.checkpoint_sha256,
            expected_previous, 32) != 0)) {
        result = PLAMEN_BROKER_V2_CONFLICT;
        goto done;
    }
    next_sequence = head.bytes == NULL ? 1 : head.view.sequence + 1;
    result = build_record(next_sequence, state, operation_key, request_sha256,
        expected_previous, payload, payload_size, &candidate);
    if (result != 0) goto done;
    if (!transition_valid(head.bytes == NULL ? NULL : &head, &candidate)) {
        result = PLAMEN_BROKER_V2_CONFLICT;
        goto done;
    }
    result = commit_record(journal, &candidate);
    if (result == 0)
        memcpy(checkpoint, candidate.view.checkpoint_sha256, 32);
done:
    owned_record_clear(&candidate);
    owned_record_clear(&head);
    if (set_lock(journal->lock_fd, F_UNLCK) != 0 && result == 0)
        result = PLAMEN_BROKER_V2_SYSTEM;
    return result;
}

struct recover_context {
    uint16_t state;
    const uint8_t *operation_key;
    const uint8_t *request_sha256;
    uint8_t *payload;
    uint32_t payload_size;
    uint8_t checkpoint[32];
    int matches;
};

static int
recover_visitor(const struct plamen_broker_v2_journal_record *record, void *opaque)
{
    struct recover_context *context = opaque;
    if (record->state != context->state
        || memcmp(record->operation_key, context->operation_key, 32) != 0
        || memcmp(record->request_sha256, context->request_sha256, 32) != 0)
        return 0;
    if (context->matches != 0) return -1;
    context->payload = malloc(record->payload_size == 0 ? 1 : record->payload_size);
    if (context->payload == NULL) return -1;
    if (record->payload_size != 0)
        memcpy(context->payload, record->payload, record->payload_size);
    context->payload_size = record->payload_size;
    memcpy(context->checkpoint, record->checkpoint_sha256, 32);
    context->matches = 1;
    return 0;
}

int
plamen_broker_v2_journal_recover(struct plamen_broker_v2_journal *journal,
    uint16_t state, const uint8_t operation_key[32],
    const uint8_t request_sha256[32], uint8_t **payload, uint32_t *payload_size,
    uint8_t checkpoint[32])
{
    struct recover_context context;
    struct owned_record head;
    int result;
    if (journal == NULL || operation_key == NULL || request_sha256 == NULL
        || payload == NULL || payload_size == NULL || checkpoint == NULL
        || !state_known(state) || journal->poisoned)
        return journal != NULL && journal->poisoned
            ? PLAMEN_BROKER_V2_CORRUPT : PLAMEN_BROKER_V2_INVALID;
    *payload = NULL;
    *payload_size = 0;
    memset(checkpoint, 0, 32);
    memset(&context, 0, sizeof(context));
    context.state = state;
    context.operation_key = operation_key;
    context.request_sha256 = request_sha256;
    if (set_lock(journal->lock_fd, F_WRLCK) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    result = replay_locked(journal, recover_visitor, &context, &head);
    owned_record_clear(&head);
    if (result == PLAMEN_BROKER_V2_INVALID && context.payload == NULL)
        result = PLAMEN_BROKER_V2_CORRUPT;
    if (result == 0 && context.matches == 0)
        result = PLAMEN_BROKER_V2_CONFLICT;
    if (result == 0) {
        *payload = context.payload;
        *payload_size = context.payload_size;
        memcpy(checkpoint, context.checkpoint, 32);
        context.payload = NULL;
    }
    if (context.payload != NULL) {
        plamen_broker_v2_secure_zero(context.payload, context.payload_size);
        free(context.payload);
    }
    if (set_lock(journal->lock_fd, F_UNLCK) != 0 && result == 0)
        result = PLAMEN_BROKER_V2_SYSTEM;
    return result;
}
