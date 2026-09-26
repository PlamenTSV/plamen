#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_artifact_export.h"
#include "../include/plamen_broker_v2.h"

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

struct json_buffer {
    uint8_t *bytes;
    size_t size;
    size_t capacity;
};

static void
json_dispose(struct json_buffer *buffer)
{
    if (buffer != NULL && buffer->bytes != NULL) {
        memset(buffer->bytes, 0, buffer->capacity);
        free(buffer->bytes);
    }
    if (buffer != NULL) memset(buffer, 0, sizeof(*buffer));
}

static int
json_append(struct json_buffer *buffer, const char *format, ...)
{
    va_list arguments, copied;
    int needed;
    size_t required, capacity;
    uint8_t *grown;
    if (buffer == NULL || format == NULL) return -1;
    va_start(arguments, format);
    va_copy(copied, arguments);
    needed = vsnprintf(NULL, 0, format, copied);
    va_end(copied);
    if (needed < 0 || (size_t)needed > SIZE_MAX - buffer->size - 1U) {
        va_end(arguments); return -1;
    }
    required = buffer->size + (size_t)needed + 1U;
    if (required > buffer->capacity) {
        capacity = buffer->capacity == 0 ? 4096U : buffer->capacity;
        while (capacity < required) {
            if (capacity > (16U * 1024U * 1024U) / 2U) {
                va_end(arguments); return -1;
            }
            capacity *= 2U;
        }
        grown = realloc(buffer->bytes, capacity);
        if (grown == NULL) { va_end(arguments); return -1; }
        buffer->bytes = grown; buffer->capacity = capacity;
    }
    (void)vsnprintf((char *)buffer->bytes + buffer->size,
        buffer->capacity - buffer->size, format, arguments);
    va_end(arguments);
    buffer->size += (size_t)needed;
    return 0;
}
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0
#endif

static int
constant_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0;
    size_t index;
    if (left == NULL || right == NULL) return 0;
    for (index = 0; index < size; ++index)
        difference |= (uint8_t)(left[index] ^ right[index]);
    return difference == 0;
}

static int
digest_present(const uint8_t *digest)
{
    uint8_t aggregate = 0;
    size_t index;
    if (digest == NULL) return 0;
    for (index = 0; index < 32U; ++index) aggregate |= digest[index];
    return aggregate != 0;
}

static void encode_hex32(const uint8_t input[32], char output[65]);

static int
valid_identifier(const char *value, size_t limit)
{
    size_t index, size;
    if (value == NULL) return 0;
    size = strlen(value);
    if (size == 0 || size >= limit) return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (!((byte >= 'A' && byte <= 'Z')
                || (byte >= 'a' && byte <= 'z')
                || (byte >= '0' && byte <= '9') || byte == '_'
                || byte == '.' || byte == ':' || byte == '-'))
            return 0;
    }
    return 1;
}

static int
valid_relative_path(const char *value)
{
    size_t index, size, component = 0;
    if (value == NULL) return 0;
    size = strlen(value);
    if (size == 0 || size >= PLAMEN_BROKER_V2_ARTIFACT_PATH_MAX
        || value[0] == '/' || value[size - 1U] == '/') return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte == '\\' || byte == ':' || byte == '"'
            || byte < 0x20U || byte > 0x7eU)
            return 0;
        if (byte == '/') {
            if (component == 0U
                || (component == 1U && value[index - 1U] == '.')
                || (component == 2U && value[index - 1U] == '.'
                    && value[index - 2U] == '.')) return 0;
            component = 0;
        } else ++component;
    }
    return component != 0U
        && !(component == 1U && value[size - 1U] == '.')
        && !(component == 2U && value[size - 1U] == '.'
            && value[size - 2U] == '.');
}

static int
duplicate_cloexec(int descriptor)
{
#ifdef F_DUPFD_CLOEXEC
    return fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
#else
    int copy = dup(descriptor), flags;
    if (copy < 0) return -1;
    flags = fcntl(copy, F_GETFD);
    if (flags < 0 || fcntl(copy, F_SETFD, flags | FD_CLOEXEC) != 0) {
        (void)close(copy); return -1;
    }
    return copy;
#endif
}

static int
open_relative_nofollow(int parent_fd, const char *path)
{
    char copy[PLAMEN_BROKER_V2_ARTIFACT_PATH_MAX];
    char *component, *slash;
    int current = -1, next = -1;
    if (parent_fd < 0 || !valid_relative_path(path)) return -1;
    memcpy(copy, path, strlen(path) + 1U);
    current = duplicate_cloexec(parent_fd);
    if (current < 0) return -1;
    component = copy;
    for (;;) {
        slash = strchr(component, '/');
        if (slash != NULL) *slash = '\0';
        next = openat(current, component,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW
                | (slash == NULL ? 0 : O_DIRECTORY));
        if (next < 0) {
            int saved_errno = errno;
            (void)close(current); errno = saved_errno; return -1;
        }
        (void)close(current); current = next;
        if (slash == NULL) break;
        component = slash + 1;
    }
    return current;
}

static int
ascii_casecmp(const char *left, const char *right)
{
    size_t index = 0;
    while (left[index] != '\0' && right[index] != '\0') {
        unsigned char a = (unsigned char)left[index];
        unsigned char b = (unsigned char)right[index];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + ('a' - 'A'));
        if (a != b) return a < b ? -1 : 1;
        ++index;
    }
    return left[index] == right[index] ? 0
        : left[index] == '\0' ? -1 : 1;
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
ordinary_single_link(const struct stat *information)
{
    return information != NULL && S_ISREG(information->st_mode)
        && information->st_nlink == 1 && information->st_size >= 0
        && (uint64_t)information->st_size
            <= PLAMEN_BROKER_V2_ARTIFACT_REPORT_MAX;
}

static int
read_exact_file(int descriptor, const struct stat *expected,
    uint8_t **bytes, size_t *size, uint8_t digest[32])
{
    struct stat before, after;
    uint8_t *value = NULL;
    size_t offset = 0, amount;
    ssize_t received;
    if (descriptor < 0 || expected == NULL || bytes == NULL || size == NULL
        || digest == NULL || !ordinary_single_link(expected)
        || (uint64_t)expected->st_size > SIZE_MAX)
        return -1;
    *bytes = NULL; *size = 0;
    if (fstat(descriptor, &before) != 0 || !ordinary_single_link(&before)
        || before.st_dev != expected->st_dev || before.st_ino != expected->st_ino
        || before.st_size != expected->st_size
        || before.st_ctime != expected->st_ctime)
        return -1;
    amount = (size_t)before.st_size;
    value = malloc(amount == 0 ? 1U : amount);
    if (value == NULL) return -1;
    while (offset < amount) {
        received = pread(descriptor, value + offset, amount - offset,
            (off_t)offset);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) goto error;
        offset += (size_t)received;
    }
    if (fstat(descriptor, &after) != 0 || !ordinary_single_link(&after)
        || after.st_dev != before.st_dev || after.st_ino != before.st_ino
        || after.st_size != before.st_size || after.st_ctime != before.st_ctime
        || plamen_broker_v2_sha256(value, amount, digest) != 0)
        goto error;
    *bytes = value; *size = amount;
    return 0;
error:
    if (value != NULL) { memset(value, 0, amount); free(value); }
    return -1;
}

static int
spec_roster_valid(const struct plamen_broker_v2_artifact_session *session)
{
    size_t index, other;
    int saw_report = 0, saw_checkpoint = 0, saw_log = 0;
    if (session->artifacts == NULL || session->artifact_count == 0U
        || session->artifact_count > PLAMEN_BROKER_V2_ARTIFACT_FILES_MAX
        || session->export_max_total_bytes == 0U
        || session->export_max_total_bytes
            > UINT64_C(2) * UINT64_C(1024) * UINT64_C(1024) * UINT64_C(1024))
        return 0;
    for (index = 0; index < session->artifact_count; ++index) {
        const struct plamen_broker_v2_artifact_spec *spec =
            &session->artifacts[index];
        struct stat parent;
        if (spec->parent_fd < 0 || !valid_relative_path(spec->physical_path)
            || !valid_relative_path(spec->logical_path)
            || (spec->required_on_success != 0U
                && spec->required_on_success != 1U)
            || (spec->required_on_failure != 0U
                && spec->required_on_failure != 1U)
            || fstat(spec->parent_fd, &parent) != 0 || !S_ISDIR(parent.st_mode)
            || (index != 0U
                && strcmp(session->artifacts[index - 1U].logical_path,
                    spec->logical_path) >= 0)
            || (index != 0U
                && ascii_casecmp(session->artifacts[index - 1U].logical_path,
                    spec->logical_path) == 0))
            return 0;
        if (strcmp(spec->logical_path,
                PLAMEN_BROKER_V2_ARTIFACT_LOGICAL_REPORT) == 0) {
            if (saw_report || strcmp(spec->physical_path,
                    PLAMEN_BROKER_V2_ARTIFACT_PHYSICAL_REPORT) != 0
                || spec->parent_fd != session->scratch_fd
                || spec->required_on_success != 1U) return 0;
            saw_report = 1;
        }
        if (strcmp(spec->logical_path, "scratch/_v2_checkpoint.json") == 0) {
            if (saw_checkpoint || strcmp(spec->physical_path,
                    "_v2_checkpoint.json") != 0
                || spec->parent_fd != session->scratch_fd
                || spec->required_on_success != 1U) return 0;
            saw_checkpoint = 1;
        }
        if (strcmp(spec->logical_path, "scratch/_plamen.log") == 0) {
            if (saw_log || strcmp(spec->physical_path, "_plamen.log") != 0
                || spec->parent_fd != session->scratch_fd
                || spec->required_on_failure != 1U) return 0;
            saw_log = 1;
        }
    }
    for (index = 0; index < session->artifact_count; ++index) {
        const char *left = session->artifacts[index].logical_path;
        size_t left_size = strlen(left);
        for (other = index + 1U; other < session->artifact_count; ++other) {
            const char *right = session->artifacts[other].logical_path;
            size_t right_size = strlen(right);
            if (ascii_casecmp(left, right) == 0
                || (left_size < right_size
                    && right[left_size] == '/'
                    && strncmp(left, right, left_size) == 0)
                || (right_size < left_size
                    && left[right_size] == '/'
                    && strncmp(left, right, right_size) == 0))
                return 0;
        }
    }
    return saw_report && saw_checkpoint && saw_log;
}

static int
session_valid(const struct plamen_broker_v2_artifact_session *session)
{
    struct stat scratch, target;
    return session != NULL
        && session->version == PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION
        && session->scratch_fd >= 0 && session->target_fd >= 0
        && valid_identifier(session->attempt_id,
            PLAMEN_BROKER_V2_ARTIFACT_ID_MAX)
        && valid_identifier(session->run_id, PLAMEN_BROKER_V2_ARTIFACT_ID_MAX)
        && valid_identifier(session->census_handle,
            PLAMEN_BROKER_V2_ARTIFACT_HANDLE_MAX)
        && valid_identifier(session->destination_handle,
            PLAMEN_BROKER_V2_ARTIFACT_HANDLE_MAX)
        && digest_present(session->terminal_sha256)
        && digest_present(session->destination_identity_sha256)
        && digest_present(session->source_content_sha256)
        && spec_roster_valid(session)
        && fstat(session->scratch_fd, &scratch) == 0
        && fstat(session->target_fd, &target) == 0
        && S_ISDIR(scratch.st_mode) && S_ISDIR(target.st_mode);
}

static int
append_entries(struct json_buffer *buffer,
    const struct plamen_broker_v2_artifact_census *census)
{
    size_t index;
    if (json_append(buffer, "[") != 0) return -1;
    for (index = 0; index < census->entry_count; ++index) {
        char digest[65];
        const struct plamen_broker_v2_artifact_entry *entry =
            &census->entries[index];
        encode_hex32(entry->sha256, digest);
        if (json_append(buffer,
                "%s{\"hardlink_count\":1,\"object_kind\":\"regular\","
                "\"relative_path\":\"%s\",\"sha256\":\"%s\","
                "\"size\":%llu,\"symlink\":false}",
                index == 0U ? "" : ",", entry->relative_path, digest,
                (unsigned long long)entry->size) != 0) return -1;
    }
    return json_append(buffer, "]");
}

static int
append_dispositions(struct json_buffer *buffer,
    const struct plamen_broker_v2_artifact_census *census)
{
    size_t index;
    if (json_append(buffer, "[") != 0) return -1;
    for (index = 0; index < census->disposition_count; ++index) {
        char digest[65];
        const struct plamen_broker_v2_artifact_disposition *disposition =
            &census->dispositions[index];
        encode_hex32(disposition->entry_sha256, digest);
        if (json_append(buffer,
                "%s{\"entry_sha256\":\"%s\",\"relative_path\":\"%s\","
                "\"status\":\"PRESENT\"}", index == 0U ? "" : ",",
                digest, disposition->relative_path) != 0) return -1;
    }
    return json_append(buffer, "]");
}

static int
census_digest(const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census,
    uint8_t output[32])
{
    char terminal_hex[65];
    struct json_buffer canonical;
    int status = -1;
    memset(&canonical, 0, sizeof(canonical));
    encode_hex32(session->terminal_sha256, terminal_hex);
    if (json_append(&canonical,
            "{\"attempt_id\":\"%s\",\"census_handle\":\"%s\","
            "\"dispositions\":", session->attempt_id,
            session->census_handle) != 0
        || append_dispositions(&canonical, census) != 0
        || json_append(&canonical, ",\"driver_exit_code\":%u,\"entries\":",
            (unsigned int)session->driver_exit_code) != 0)
        goto done;
    if (append_entries(&canonical, census) != 0
        || json_append(&canonical,
            ",\"run_id\":\"%s\",\"terminal_sha256\":\"%s\"}\n",
            session->run_id, terminal_hex) != 0
        || plamen_broker_v2_sha256(canonical.bytes, canonical.size,
            output) != 0) goto done;
    status = 0;
done:
    json_dispose(&canonical);
    return status;
}

static int
manifest_digest(const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census,
    uint8_t output[32])
{
    char report_hex[65], census_hex[65], destination_hex[65];
    struct json_buffer canonical;
    int status = -1;
    const struct plamen_broker_v2_artifact_entry *report = NULL;
    size_t index;
    memset(&canonical, 0, sizeof(canonical));
    for (index = 0; index < census->entry_count; ++index)
        if (strcmp(census->entries[index].relative_path,
                PLAMEN_BROKER_V2_ARTIFACT_LOGICAL_REPORT) == 0)
            report = &census->entries[index];
    if (report == NULL) goto done;
    encode_hex32(report->sha256, report_hex);
    encode_hex32(census->census_sha256, census_hex);
    encode_hex32(session->destination_identity_sha256, destination_hex);
    if (json_append(&canonical,
        "{\"attempt_id\":\"%s\",\"census_sha256\":\"%s\","
        "\"destination_identity_sha256\":\"%s\","
        "\"dispositions\":", session->attempt_id, census_hex,
        destination_hex) != 0
        || append_dispositions(&canonical, census) != 0
        || json_append(&canonical, ",\"entries\":") != 0
        || append_entries(&canonical, census) != 0
        || json_append(&canonical,
        ","
        "\"report_publication\":{\"census_relative_path\":"
        "\"project/AUDIT_REPORT.md\",\"guest_staging_path\":"
        "\"/workspace/scratch/AUDIT_REPORT.md\",\"sha256\":\"%s\","
        "\"size\":%llu,\"status\":\"PUBLISHED\","
        "\"target_relative_path\":\"AUDIT_REPORT.md\"},"
        "\"run_id\":\"%s\"}\n",
        report_hex, (unsigned long long)report->size, session->run_id) != 0
        || plamen_broker_v2_sha256(canonical.bytes, canonical.size,
            output) != 0) goto done;
    status = 0;
done:
    json_dispose(&canonical);
    return status;
}

static int
export_digest(const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census,
    const uint8_t manifest[32], uint8_t output[32])
{
    char terminal_hex[65], census_hex[65], destination_hex[65];
    char manifest_hex[65], canonical[2048];
    int amount;
    encode_hex32(session->terminal_sha256, terminal_hex);
    encode_hex32(census->census_sha256, census_hex);
    encode_hex32(session->destination_identity_sha256, destination_hex);
    encode_hex32(manifest, manifest_hex);
    amount = snprintf(canonical, sizeof(canonical),
        "{\"attempt_id\":\"%s\",\"census_sha256\":\"%s\","
        "\"destination_handle\":\"%s\","
        "\"destination_identity_sha256\":\"%s\","
        "\"driver_exit_code\":%u,\"exported_bytes\":%llu,"
        "\"exported_count\":%llu,\"manifest_sha256\":\"%s\","
        "\"run_id\":\"%s\",\"terminal_sha256\":\"%s\"}\n",
        session->attempt_id, census_hex, session->destination_handle,
        destination_hex, (unsigned int)session->driver_exit_code,
        (unsigned long long)census->total_bytes,
        (unsigned long long)census->entry_count, manifest_hex,
        session->run_id, terminal_hex);
    if (amount <= 0 || (size_t)amount >= sizeof(canonical)) return -1;
    return plamen_broker_v2_sha256(canonical, (size_t)amount, output);
}

static int
postpublication_digest(
    const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census,
    uint8_t output[32])
{
    char source_hex[65], report_hex[65], canonical[1024];
    int amount;
    encode_hex32(session->source_content_sha256, source_hex);
    encode_hex32(census->report_sha256, report_hex);
    amount = snprintf(canonical, sizeof(canonical),
        "{\"published_artifact\":{\"relative_path\":\"AUDIT_REPORT.md\","
        "\"sha256\":\"%s\",\"size\":%llu},"
        "\"source_content_sha256\":\"%s\"}\n",
        report_hex, (unsigned long long)census->report_size, source_hex);
    if (amount <= 0 || (size_t)amount >= sizeof(canonical)) return -1;
    return plamen_broker_v2_sha256(canonical, (size_t)amount, output);
}

int
plamen_broker_v2_artifact_census_report(
    const struct plamen_broker_v2_artifact_session *session,
    struct plamen_broker_v2_artifact_census *census)
{
    size_t index, prior;
    int status = PLAMEN_BROKER_V2_ARTIFACT_ERROR;
    if (census != NULL) memset(census, 0, sizeof(*census));
    if (!session_valid(session) || census == NULL) return status;
    census->version = PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION;
    if (session->terminal_authenticated != 1
        || session->extinction_proven != 1
        || session->driver_terminal_proven != 1)
        return status;
    census->entries = calloc(session->artifact_count,
        sizeof(*census->entries));
    census->dispositions = calloc(session->artifact_count,
        sizeof(*census->dispositions));
    if (census->entries == NULL || census->dispositions == NULL) goto done;
    for (index = 0; index < session->artifact_count; ++index) {
        const struct plamen_broker_v2_artifact_spec *spec =
            &session->artifacts[index];
        struct plamen_broker_v2_artifact_entry *entry;
        struct stat information;
        uint8_t *bytes = NULL;
        size_t size = 0;
        int descriptor = open_relative_nofollow(spec->parent_fd,
            spec->physical_path);
        int required = spec->required_on_success
            || (session->driver_exit_code != 0U
                && spec->required_on_failure);
        if (descriptor < 0) {
            if (!required && errno == ENOENT) continue;
            goto done;
        }
        if (fstat(descriptor, &information) != 0
            || !ordinary_single_link(&information)) {
            (void)close(descriptor); goto done;
        }
        entry = &census->entries[census->entry_count];
        if (read_exact_file(descriptor, &information, &bytes, &size,
                entry->sha256) != 0) {
            (void)close(descriptor); goto done;
        }
        (void)close(descriptor);
        if (bytes != NULL) { memset(bytes, 0, size); free(bytes); }
        if ((uint64_t)size > session->export_max_total_bytes
            || census->total_bytes
                > session->export_max_total_bytes - (uint64_t)size)
            goto done;
        entry->relative_path = spec->logical_path;
        entry->size = (uint64_t)size;
        entry->device = (uint64_t)information.st_dev;
        entry->inode = (uint64_t)information.st_ino;
        entry->change_token = (uint64_t)information.st_ctime;
        entry->spec_index = index;
        for (prior = 0; prior < census->entry_count; ++prior)
            if (census->entries[prior].device == entry->device
                && census->entries[prior].inode == entry->inode)
                goto done;
        census->total_bytes += entry->size;
        ++census->entry_count;
        if (strcmp(spec->logical_path,
                PLAMEN_BROKER_V2_ARTIFACT_LOGICAL_REPORT) == 0) {
            census->report_size = entry->size;
            memcpy(census->report_sha256, entry->sha256, 32U);
        }
        if (required) {
            struct plamen_broker_v2_artifact_disposition *disposition =
                &census->dispositions[census->disposition_count++];
            disposition->relative_path = spec->logical_path;
            memcpy(disposition->entry_sha256, entry->sha256, 32U);
        }
    }
    if (!digest_present(census->report_sha256)
        || census->disposition_count == 0U
        || census_digest(session, census, census->census_sha256) != 0)
        goto done;
    census->status = PLAMEN_BROKER_V2_ARTIFACT_COMPLETE;
    status = PLAMEN_BROKER_V2_ARTIFACT_COMPLETE;
done:
    if (status != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE)
        plamen_broker_v2_artifact_census_dispose(census);
    return status;
}

void
plamen_broker_v2_artifact_census_dispose(
    struct plamen_broker_v2_artifact_census *census)
{
    if (census == NULL) return;
    if (census->entries != NULL) {
        memset(census->entries, 0,
            census->entry_count * sizeof(*census->entries));
        free(census->entries);
    }
    if (census->dispositions != NULL) {
        memset(census->dispositions, 0,
            census->disposition_count * sizeof(*census->dispositions));
        free(census->dispositions);
    }
    memset(census, 0, sizeof(*census));
}

static void
encode_hex32(const uint8_t input[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32U; ++index) {
        output[index * 2U] = digits[input[index] >> 4];
        output[index * 2U + 1U] = digits[input[index] & 15U];
    }
    output[64] = '\0';
}

static int
write_all(int descriptor, const uint8_t *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = write(descriptor, bytes + offset, size - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int
destination_precondition(
    const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_publication *publication)
{
    struct stat information;
    uint8_t *bytes = NULL, digest[32];
    size_t size = 0;
    int descriptor, saved_errno, status = -1;
    descriptor = openat(session->target_fd,
        PLAMEN_BROKER_V2_ARTIFACT_TARGET_REPORT,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (!publication->authorize_replace) {
        saved_errno = errno;
        if (descriptor >= 0) (void)close(descriptor);
        return descriptor < 0 && saved_errno == ENOENT ? 0 : -1;
    }
    if (descriptor < 0 || !digest_present(publication->expected_existing_sha256)
        || fstat(descriptor, &information) != 0
        || !ordinary_single_link(&information)
        || read_exact_file(descriptor, &information, &bytes, &size,
            digest) != 0
        || !constant_equal(digest,
            publication->expected_existing_sha256, 32U))
        goto done;
    status = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (bytes != NULL) { memset(bytes, 0, size); free(bytes); }
    memset(digest, 0, sizeof(digest));
    return status;
}

static int
source_lease_revalidate(
    const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census,
    uint8_t **bytes, size_t *size)
{
    struct plamen_broker_v2_artifact_census observed;
    struct stat information;
    uint8_t digest[32];
    size_t index;
    int descriptor = -1, status = -1;
    memset(&observed, 0, sizeof(observed));
    if (plamen_broker_v2_artifact_census_report(session, &observed)
            != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || observed.entry_count != census->entry_count
        || observed.disposition_count != census->disposition_count
        || observed.total_bytes != census->total_bytes
        || !constant_equal(observed.census_sha256,
            census->census_sha256, 32U)) goto done;
    for (index = 0; index < census->entry_count; ++index)
        if (strcmp(observed.entries[index].relative_path,
                census->entries[index].relative_path) != 0
            || observed.entries[index].size != census->entries[index].size
            || observed.entries[index].device != census->entries[index].device
            || observed.entries[index].inode != census->entries[index].inode
            || observed.entries[index].change_token
                != census->entries[index].change_token
            || !constant_equal(observed.entries[index].sha256,
                census->entries[index].sha256, 32U)) goto done;
    descriptor = openat(session->scratch_fd,
        PLAMEN_BROKER_V2_ARTIFACT_PHYSICAL_REPORT,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !ordinary_single_link(&information)
        || (uint64_t)information.st_size != census->report_size
        || read_exact_file(descriptor, &information, bytes, size, digest) != 0
        || !constant_equal(digest, census->report_sha256, 32U))
        goto done;
    status = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    plamen_broker_v2_artifact_census_dispose(&observed);
    memset(digest, 0, sizeof(digest));
    return status;
}

static int
postpublication_recensus(
    const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census)
{
    struct stat information;
    uint8_t *bytes = NULL, digest[32];
    size_t size = 0;
    size_t index;
    int descriptor, status = -1;
    descriptor = openat(session->target_fd,
        PLAMEN_BROKER_V2_ARTIFACT_TARGET_REPORT,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !ordinary_single_link(&information)
        || (uint64_t)information.st_size != census->report_size
        || read_exact_file(descriptor, &information, &bytes, &size,
            digest) != 0
        || !constant_equal(digest, census->report_sha256, 32U))
        goto done;
    for (index = 0; index < census->entry_count; ++index)
        if ((uint64_t)information.st_dev == census->entries[index].device
            && (uint64_t)information.st_ino == census->entries[index].inode)
            goto done;
    status = 0;
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (bytes != NULL) { memset(bytes, 0, size); free(bytes); }
    memset(digest, 0, sizeof(digest));
    return status;
}

static int
distinct_publication_roots(
    const struct plamen_broker_v2_artifact_session *session)
{
    struct stat scratch, target;
    return fstat(session->scratch_fd, &scratch) == 0
        && fstat(session->target_fd, &target) == 0
        && S_ISDIR(scratch.st_mode) && S_ISDIR(target.st_mode)
        && !(scratch.st_dev == target.st_dev && scratch.st_ino == target.st_ino);
}

static int
complete_census_valid(
    const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census)
{
    uint8_t digest[32];
    int valid;
    if (census == NULL
        || census->version != PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION
        || census->status != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || !digest_present(census->report_sha256)
        || !digest_present(census->census_sha256)
        || census->entries == NULL || census->entry_count == 0U
        || census->entry_count > PLAMEN_BROKER_V2_ARTIFACT_FILES_MAX
        || census->dispositions == NULL || census->disposition_count == 0U
        || census->disposition_count > census->entry_count
        || census->report_size > PLAMEN_BROKER_V2_ARTIFACT_REPORT_MAX
        || census_digest(session, census, digest) != 0)
        return 0;
    valid = constant_equal(digest, census->census_sha256, 32U);
    memset(digest, 0, sizeof(digest));
    return valid;
}

static int
build_complete_receipt(
    const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census,
    struct plamen_broker_v2_artifact_export_receipt *receipt)
{
    memset(receipt, 0, sizeof(*receipt));
    receipt->version = PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION;
    if (manifest_digest(session, census, receipt->manifest_sha256) != 0
        || export_digest(session, census, receipt->manifest_sha256,
            receipt->export_sha256) != 0
        || postpublication_digest(session, census,
            receipt->postpublication_sha256) != 0) {
        memset(receipt, 0, sizeof(*receipt));
        return -1;
    }
    receipt->status = PLAMEN_BROKER_V2_ARTIFACT_COMPLETE;
    receipt->complete = 1;
    receipt->exported_count = census->entry_count;
    receipt->exported_bytes = census->total_bytes;
    memcpy(receipt->report_sha256, census->report_sha256, 32U);
    memcpy(receipt->census_sha256, census->census_sha256, 32U);
    return 0;
}

static int
receipt_equal(
    const struct plamen_broker_v2_artifact_export_receipt *left,
    const struct plamen_broker_v2_artifact_export_receipt *right)
{
    return left->version == right->version
        && left->status == right->status
        && left->complete == right->complete
        && left->exported_count == right->exported_count
        && left->exported_bytes == right->exported_bytes
        && constant_equal(left->report_sha256, right->report_sha256, 32U)
        && constant_equal(left->census_sha256, right->census_sha256, 32U)
        && constant_equal(left->manifest_sha256, right->manifest_sha256, 32U)
        && constant_equal(left->export_sha256, right->export_sha256, 32U)
        && constant_equal(left->postpublication_sha256,
            right->postpublication_sha256, 32U);
}

int
plamen_broker_v2_artifact_reopen_publication(
    const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census,
    struct plamen_broker_v2_artifact_export_receipt *receipt_out)
{
    struct plamen_broker_v2_artifact_export_receipt rebuilt;
    uint8_t *source_bytes = NULL;
    size_t source_size = 0;
    int status = PLAMEN_BROKER_V2_ARTIFACT_ERROR;
    memset(&rebuilt, 0, sizeof(rebuilt));
    if (receipt_out != NULL) memset(receipt_out, 0, sizeof(*receipt_out));
    if (!session_valid(session) || receipt_out == NULL
        || session->driver_exit_code != 0U
        || session->terminal_authenticated != 1U
        || session->extinction_proven != 1U
        || session->driver_terminal_proven != 1U
        || !distinct_publication_roots(session)
        || !complete_census_valid(session, census)
        || source_lease_revalidate(session, census, &source_bytes,
            &source_size) != 0
        || source_size != census->report_size
        || postpublication_recensus(session, census) != 0
        || build_complete_receipt(session, census, &rebuilt) != 0)
        goto done;
    memcpy(receipt_out, &rebuilt, sizeof(*receipt_out));
    status = PLAMEN_BROKER_V2_ARTIFACT_COMPLETE;
done:
    if (source_bytes != NULL) {
        memset(source_bytes, 0, source_size);
        free(source_bytes);
    }
    memset(&rebuilt, 0, sizeof(rebuilt));
    if (status != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE && receipt_out != NULL)
        memset(receipt_out, 0, sizeof(*receipt_out));
    return status;
}

int
plamen_broker_v2_artifact_validate_publication_receipt(
    const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census,
    const struct plamen_broker_v2_artifact_export_receipt *expected_receipt)
{
    struct plamen_broker_v2_artifact_export_receipt rebuilt;
    int status = PLAMEN_BROKER_V2_ARTIFACT_ERROR;
    memset(&rebuilt, 0, sizeof(rebuilt));
    if (expected_receipt != NULL
        && plamen_broker_v2_artifact_reopen_publication(session, census,
            &rebuilt) == PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        && receipt_equal(&rebuilt, expected_receipt))
        status = PLAMEN_BROKER_V2_ARTIFACT_COMPLETE;
    memset(&rebuilt, 0, sizeof(rebuilt));
    return status;
}

int
plamen_broker_v2_artifact_publish_report(
    const struct plamen_broker_v2_artifact_session *session,
    const struct plamen_broker_v2_artifact_census *census,
    const struct plamen_broker_v2_artifact_publication *publication,
    struct plamen_broker_v2_artifact_export_receipt *receipt)
{
    uint8_t *bytes = NULL;
    size_t size = 0;
    char census_hex[65], temporary[96];
    struct stat temp_information;
    uint8_t temp_digest[32];
    int temp_fd = -1, temp_present = 0;
    int status = PLAMEN_BROKER_V2_ARTIFACT_ERROR;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (!session_valid(session) || census == NULL || publication == NULL
        || receipt == NULL
        || publication->version != PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION)
        return status;
    receipt->version = PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION;
    if (session->driver_exit_code != 0
        || census->status == PLAMEN_BROKER_V2_ARTIFACT_SUPPRESSED) {
        receipt->status = PLAMEN_BROKER_V2_ARTIFACT_SUPPRESSED;
        return PLAMEN_BROKER_V2_ARTIFACT_SUPPRESSED;
    }
    if (session->terminal_authenticated != 1
        || session->extinction_proven != 1
        || session->driver_terminal_proven != 1
        || census->version != PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION
        || census->status != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || !digest_present(census->report_sha256)
        || !digest_present(census->census_sha256)
        || census->entries == NULL || census->entry_count == 0U
        || census->dispositions == NULL || census->disposition_count == 0U
        || census->report_size > PLAMEN_BROKER_V2_ARTIFACT_REPORT_MAX
        || census_digest(session, census, temp_digest) != 0
        || !constant_equal(temp_digest, census->census_sha256, 32U)
        || source_lease_revalidate(session, census, &bytes, &size) != 0
        || size != census->report_size
        || destination_precondition(session, publication) != 0)
        goto done;
    encode_hex32(census->census_sha256, census_hex);
    if (snprintf(temporary, sizeof(temporary), ".plamen-report-%.48s.tmp",
            census_hex) <= 0)
        goto done;
    temp_fd = openat(session->target_fd, temporary,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (temp_fd >= 0) temp_present = 1;
    if (temp_fd < 0 || fstat(temp_fd, &temp_information) != 0
        || !ordinary_single_link(&temp_information)
        || write_all(temp_fd, bytes, size) != 0 || full_sync(temp_fd) != 0)
        goto done;
    if (close(temp_fd) != 0) { temp_fd = -1; goto done; }
    temp_fd = -1;
    if (destination_precondition(session, publication) != 0) goto done;
    if (publication->authorize_replace) {
        if (renameat(session->target_fd, temporary, session->target_fd,
                PLAMEN_BROKER_V2_ARTIFACT_TARGET_REPORT) != 0)
            goto done;
    } else {
        if (linkat(session->target_fd, temporary, session->target_fd,
                PLAMEN_BROKER_V2_ARTIFACT_TARGET_REPORT, 0) != 0)
            goto done;
        if (unlinkat(session->target_fd, temporary, 0) != 0) goto done;
        temp_present = 0;
    }
    if (publication->authorize_replace) temp_present = 0;
    if (full_sync(session->target_fd) != 0
        || postpublication_recensus(session, census) != 0
        || build_complete_receipt(session, census, receipt) != 0)
        goto done;
    status = PLAMEN_BROKER_V2_ARTIFACT_COMPLETE;
done:
    if (temp_fd >= 0) (void)close(temp_fd);
    if (temp_present) (void)unlinkat(session->target_fd, temporary, 0);
    if (bytes != NULL) { memset(bytes, 0, size); free(bytes); }
    memset(temp_digest, 0, sizeof(temp_digest));
    memset(census_hex, 0, sizeof(census_hex));
    memset(temporary, 0, sizeof(temporary));
    if (status != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE)
        memset(receipt, 0, sizeof(*receipt));
    return status;
}
