#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_apple_container.h"
#include "../include/plamen_broker_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TOKEN_MAX 1024U
#define JSON_MAX (1024U * 1024U)
#define OUTPUT_CHUNK 65536U
#define OCI_INDEX_MEDIA "application/vnd.oci.image.index.v1+json"
#define INIT_INDEX "sha256:cde8a93f9861c664bf2b74b4e2893cf877680806f12e7e989eb9c51b2f2e93bf"
#define INIT_MANIFEST "sha256:71f6c228becbb32398ee44b8569249524722c2e11030f61cc7a5673695e5a422"
#define INIT_REFERENCE "ghcr.io/apple/containerization/vminit@" INIT_INDEX
#define CLI_IDENTIFIER "com.apple.container.cli"
#define APPLE_TEAM "UPBK2H6LZM"
#define KERNEL_SHA "fb2cfb79eb1ae19447a85d75682d7fa5cfec97e24beb2609a492b806e8072c8d"
#define POLICY_TEXT \
    "apple-container-compatible-baseline=1.3.1\n" \
    "containerization-compatible-baseline=0.42.0\n" \
    "installed-release-closure=descriptor-authenticated\n" \
    "package=com.apple.container-installer\n" \
    "package-install=/usr/local\n" \
    "package-authorization=root\n" \
    "package-team=UPBK2H6LZM\n" \
    "installer-leaf=4519b43d00f55ec63138d403de1f3c542390eae3d82e59c1843846fbdfe14f5b\n" \
    "kernel-archive=8736c054d9223974735394f822000823baef509e1c33405ec798240fa9b6e4b5\n" \
    "implicit-kernel-install=disabled\n" \
    "untrusted-build-context=forbidden\n"

enum token_type { TOKEN_OBJECT = 1, TOKEN_ARRAY = 2, TOKEN_STRING = 3,
    TOKEN_PRIMITIVE = 4 };
struct token { uint8_t type; int parent; size_t start, end; };
struct document { const uint8_t *bytes; size_t size; struct token tokens[TOKEN_MAX];
    size_t count; };

static int json_structure(const struct document *, int, unsigned int);
static int next_direct(const struct document *, int, int);

static int
all_zero(const uint8_t value[32])
{
    uint8_t aggregate = 0;
    size_t index;
    for (index = 0; index < 32; ++index) aggregate |= value[index];
    return aggregate == 0;
}

static int
hex_digest(const char *text, uint8_t output[32])
{
    size_t index;
    int high, low;
    if (text == NULL || strlen(text) != 64) return -1;
    for (index = 0; index < 32; ++index) {
        high = text[index * 2]; low = text[index * 2 + 1];
        high = high >= '0' && high <= '9' ? high - '0'
            : high >= 'a' && high <= 'f' ? high - 'a' + 10 : -1;
        low = low >= '0' && low <= '9' ? low - '0'
            : low >= 'a' && low <= 'f' ? low - 'a' + 10 : -1;
        if (high < 0 || low < 0) return -1;
        output[index] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static const char *
pinned_closure_digest(size_t role)
{
    switch (role) {
    case PLAMEN_BROKER_V2_APPLE_CONTAINER_KERNEL: return KERNEL_SHA;
    default: return NULL;
    }
}

int
plamen_broker_v2_apple_container_production_closure_sha256(uint32_t role,
    uint8_t output[32])
{
    const char *pin = pinned_closure_digest(role);
    return output != NULL && pin != NULL ? hex_digest(pin, output) : -1;
}

static int
constant_equal(const void *a_value, const void *b_value, size_t size)
{
    const uint8_t *a = a_value, *b = b_value;
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < size; ++index) difference |= a[index] ^ b[index];
    return difference == 0;
}

static int
sha256_fd(int fd, uint8_t output[32])
{
    CC_SHA256_CTX context;
    struct stat before, after;
    uint8_t buffer[65536];
    off_t offset = 0;
    ssize_t amount;
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size <= 0 || before.st_nlink != 1
        || CC_SHA256_Init(&context) != 1) return -1;
    while (offset < before.st_size) {
        amount = pread(fd, buffer, sizeof(buffer), offset);
        if (amount <= 0 || CC_SHA256_Update(&context, buffer,
                (CC_LONG)amount) != 1) return -1;
        offset += amount;
    }
    if (offset != before.st_size || fstat(fd, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_size != after.st_size || before.st_mtimespec.tv_sec
            != after.st_mtimespec.tv_sec
        || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
        || CC_SHA256_Final(output, &context) != 1) return -1;
    return 0;
}

static int
token_add(struct document *document, uint8_t type, int parent, size_t start,
    size_t end, int *index)
{
    if (document->count >= TOKEN_MAX) return -1;
    *index = (int)document->count++;
    document->tokens[*index].type = type;
    document->tokens[*index].parent = parent;
    document->tokens[*index].start = start;
    document->tokens[*index].end = end;
    return 0;
}

static int
json_parse(const uint8_t *bytes, size_t size, struct document *document)
{
    int stack[64], depth = 0, index, parent = -1;
    size_t cursor, start;
    uint8_t value;
    if (bytes == NULL || document == NULL || size == 0 || size > JSON_MAX)
        return -1;
    memset(document, 0, sizeof(*document));
    document->bytes = bytes; document->size = size;
    for (cursor = 0; cursor < size;) {
        value = bytes[cursor];
        if (value == ' ' || value == '\t' || value == '\r' || value == '\n') {
            ++cursor; continue;
        }
        if (value == '{' || value == '[') {
            if (depth >= 64 || token_add(document,
                    value == '{' ? TOKEN_OBJECT : TOKEN_ARRAY, parent,
                    cursor, 0, &index) != 0) return -1;
            stack[depth++] = index; parent = index; ++cursor; continue;
        }
        if (value == '}' || value == ']') {
            if (depth <= 0 || document->tokens[stack[depth - 1]].type
                    != (value == '}' ? TOKEN_OBJECT : TOKEN_ARRAY)) return -1;
            document->tokens[stack[--depth]].end = cursor + 1U;
            parent = depth == 0 ? -1 : stack[depth - 1]; ++cursor; continue;
        }
        if (value == ',' || value == ':') { ++cursor; continue; }
        if (value == '"') {
            start = ++cursor;
            while (cursor < size && bytes[cursor] != '"') {
                /* Apple control-plane fields used here require no escapes.
                 * Rejecting them avoids ambiguous Unicode/key spellings. */
                if (bytes[cursor] == '\\' || bytes[cursor] < 0x20) return -1;
                ++cursor;
            }
            if (cursor >= size || token_add(document, TOKEN_STRING, parent,
                    start, cursor, &index) != 0) return -1;
            ++cursor; continue;
        }
        start = cursor;
        while (cursor < size && bytes[cursor] != ',' && bytes[cursor] != ':'
            && bytes[cursor] != ']' && bytes[cursor] != '}'
            && bytes[cursor] != ' ' && bytes[cursor] != '\t'
            && bytes[cursor] != '\r' && bytes[cursor] != '\n') ++cursor;
        if (cursor == start || token_add(document, TOKEN_PRIMITIVE, parent,
                start, cursor, &index) != 0) return -1;
    }
    if (depth != 0 || document->count == 0
        || document->tokens[0].parent != -1) return -1;
    for (cursor = document->tokens[0].end; cursor < size; ++cursor)
        if (!isspace(bytes[cursor])) return -1;
    return document->tokens[0].end != 0
        && json_structure(document, 0, 0) == 0 ? 0 : -1;
}

static int
token_text(const struct document *document, int index, const char *text)
{
    size_t length = strlen(text);
    const struct token *token;
    if (index < 0 || (size_t)index >= document->count) return 0;
    token = &document->tokens[index];
    return token->type == TOKEN_STRING && token->end - token->start == length
        && memcmp(document->bytes + token->start, text, length) == 0;
}

static size_t
raw_start(const struct token *token)
{
    return token->type == TOKEN_STRING ? token->start - 1U : token->start;
}

static size_t
raw_end(const struct token *token)
{
    return token->type == TOKEN_STRING ? token->end + 1U : token->end;
}

static int
gap(const struct document *document, size_t start, size_t end, int separator)
{
    while (start < end && isspace(document->bytes[start])) ++start;
    if (separator >= 0) {
        if (start >= end || document->bytes[start++] != (uint8_t)separator)
            return -1;
        while (start < end && isspace(document->bytes[start])) ++start;
    }
    return start == end ? 0 : -1;
}

static int
primitive_valid(const struct document *document, int index)
{
    const struct token *token = &document->tokens[index];
    size_t cursor = token->start;
    const uint8_t *bytes = document->bytes;
    if ((token->end - token->start == 4
            && (!memcmp(bytes + token->start, "true", 4)
                || !memcmp(bytes + token->start, "null", 4)))
        || (token->end - token->start == 5
            && !memcmp(bytes + token->start, "false", 5))) return 0;
    if (cursor < token->end && bytes[cursor] == '-') ++cursor;
    if (cursor >= token->end) return -1;
    if (bytes[cursor] == '0') ++cursor;
    else {
        if (bytes[cursor] < '1' || bytes[cursor] > '9') return -1;
        while (cursor < token->end && isdigit(bytes[cursor])) ++cursor;
    }
    if (cursor < token->end && bytes[cursor] == '.') {
        if (++cursor >= token->end || !isdigit(bytes[cursor])) return -1;
        while (cursor < token->end && isdigit(bytes[cursor])) ++cursor;
    }
    if (cursor < token->end
        && (bytes[cursor] == 'e' || bytes[cursor] == 'E')) {
        ++cursor;
        if (cursor < token->end
            && (bytes[cursor] == '+' || bytes[cursor] == '-')) ++cursor;
        if (cursor >= token->end || !isdigit(bytes[cursor])) return -1;
        while (cursor < token->end && isdigit(bytes[cursor])) ++cursor;
    }
    return cursor == token->end ? 0 : -1;
}

static int
json_structure(const struct document *document, int container,
    unsigned int depth)
{
    const struct token *parent_token, *item_token, *value_token;
    int item = -1, value, following;
    size_t previous;
    if (depth > 32 || container < 0
        || (size_t)container >= document->count) return -1;
    parent_token = &document->tokens[container];
    if (parent_token->type == TOKEN_STRING) return 0;
    if (parent_token->type == TOKEN_PRIMITIVE)
        return primitive_valid(document, container);
    previous = parent_token->start + 1U;
    while ((item = next_direct(document, container, item)) >= 0) {
        item_token = &document->tokens[item];
        if (parent_token->type == TOKEN_OBJECT) {
            if (item_token->type != TOKEN_STRING
                || gap(document, previous, raw_start(item_token),
                    previous == parent_token->start + 1U ? -1 : ',') != 0
                || (value = next_direct(document, container, item)) < 0)
                return -1;
            value_token = &document->tokens[value];
            if (gap(document, raw_end(item_token), raw_start(value_token), ':') != 0
                || json_structure(document, value, depth + 1U) != 0) return -1;
            previous = raw_end(value_token); item = value;
        } else {
            if (gap(document, previous, raw_start(item_token),
                    previous == parent_token->start + 1U ? -1 : ',') != 0
                || json_structure(document, item, depth + 1U) != 0) return -1;
            previous = raw_end(item_token);
        }
    }
    following = parent_token->type == TOKEN_OBJECT ? '}' : ']';
    return gap(document, previous, parent_token->end - 1U, -1) == 0
        && document->bytes[parent_token->end - 1U] == following ? 0 : -1;
}

static int
token_safe_text(const struct document *document, int index, size_t maximum)
{
    const struct token *token;
    size_t cursor, length;
    if (index < 0 || (size_t)index >= document->count) return 0;
    token = &document->tokens[index]; length = token->end - token->start;
    if (token->type != TOKEN_STRING || length == 0 || length > maximum) return 0;
    for (cursor = token->start; cursor < token->end; ++cursor)
        if (document->bytes[cursor] < 0x20 || document->bytes[cursor] > 0x7e)
            return 0;
    return 1;
}

struct provider_identity {
    char version[32];
    char build[65];
    char commit[41];
};

static int
token_copy_text(const struct document *document, int index,
    char *output, size_t capacity)
{
    size_t length;
    if (output == NULL || capacity == 0
        || !token_safe_text(document, index, capacity - 1U)) return -1;
    length = document->tokens[index].end - document->tokens[index].start;
    memcpy(output, document->bytes + document->tokens[index].start, length);
    output[length] = '\0'; return 0;
}

static int
stable_version_supported(const char *value)
{
    unsigned int major, minor, patch;
    char tail;
    if (value == NULL
        || sscanf(value, "%u.%u.%u%c", &major, &minor, &patch, &tail) != 3)
        return 0;
    return major > 1U || (major == 1U && (minor > 3U
        || (minor == 3U && patch >= 1U)));
}

static int
commit_valid(const char *value)
{
    size_t index;
    if (value == NULL || strlen(value) != 40U) return 0;
    for (index = 0; index < 40U; ++index)
        if (!((value[index] >= '0' && value[index] <= '9')
                || (value[index] >= 'a' && value[index] <= 'f'))) return 0;
    return 1;
}

static int
server_banner_identity(const char *banner, struct provider_identity *identity)
{
    static const char prefix[] = "container-apiserver version ";
    static const char build_marker[] = " (build: ";
    static const char commit_marker[] = ", commit: ";
    const char *build, *commit, *end;
    size_t version_size, build_size;
    if (banner == NULL || identity == NULL
        || strncmp(banner, prefix, sizeof(prefix) - 1U) != 0
        || (build = strstr(banner + sizeof(prefix) - 1U, build_marker)) == NULL
        || (commit = strstr(build + sizeof(build_marker) - 1U,
            commit_marker)) == NULL
        || (end = strchr(commit + sizeof(commit_marker) - 1U, ')')) == NULL
        || end[1] != '\0'
        || (size_t)(end - (commit + sizeof(commit_marker) - 1U)) != 7U)
        return -1;
    version_size = (size_t)(build - (banner + sizeof(prefix) - 1U));
    build_size = (size_t)(commit - (build + sizeof(build_marker) - 1U));
    if (version_size == 0 || version_size >= sizeof(identity->version)
        || build_size == 0 || build_size >= sizeof(identity->build)) return -1;
    memcpy(identity->version, banner + sizeof(prefix) - 1U, version_size);
    identity->version[version_size] = '\0';
    memcpy(identity->build, build + sizeof(build_marker) - 1U, build_size);
    identity->build[build_size] = '\0';
    memcpy(identity->commit, commit + sizeof(commit_marker) - 1U, 7U);
    identity->commit[7] = '\0';
    return stable_version_supported(identity->version) ? 0 : -1;
}

static int
next_direct(const struct document *document, int parent, int after)
{
    size_t index;
    for (index = (size_t)(after + 1); index < document->count; ++index) {
        if (document->tokens[index].parent == parent) return (int)index;
        if (document->tokens[index].start >= document->tokens[parent].end) break;
    }
    return -1;
}

static int
object_get(const struct document *document, int object, const char *key,
    int *value)
{
    int item = -1, found = -1, next;
    if (object < 0 || document->tokens[object].type != TOKEN_OBJECT) return -1;
    while ((item = next_direct(document, object, item)) >= 0) {
        next = next_direct(document, object, item);
        if (next < 0 || document->tokens[item].type != TOKEN_STRING) return -1;
        if (token_text(document, item, key)) {
            if (found >= 0) return -1;
            found = next;
        }
        item = next;
    }
    if (found < 0) return -1;
    *value = found; return 0;
}

static int
object_keys(const struct document *document, int object,
    const char *const *allowed, size_t allowed_count, size_t minimum,
    size_t maximum)
{
    int item = -1, next, prior, prior_value;
    size_t count = 0, index;
    int accepted;
    while ((item = next_direct(document, object, item)) >= 0) {
        next = next_direct(document, object, item);
        if (next < 0 || document->tokens[item].type != TOKEN_STRING) return -1;
        prior = -1;
        while ((prior = next_direct(document, object, prior)) >= 0
            && prior < item) {
            prior_value = next_direct(document, object, prior);
            if (prior_value < 0) return -1;
            if (document->tokens[prior].type == TOKEN_STRING
                && document->tokens[prior].end - document->tokens[prior].start
                    == document->tokens[item].end - document->tokens[item].start
                && memcmp(document->bytes + document->tokens[prior].start,
                    document->bytes + document->tokens[item].start,
                    document->tokens[item].end
                        - document->tokens[item].start) == 0)
                return -1;
            prior = prior_value;
        }
        accepted = 0;
        for (index = 0; index < allowed_count; ++index)
            if (token_text(document, item, allowed[index])) { accepted = 1; break; }
        if (!accepted) return -1;
        ++count; item = next;
    }
    return count >= minimum && count <= maximum ? 0 : -1;
}

static int
primitive_positive(const struct document *document, int index)
{
    const struct token *token;
    size_t cursor;
    if (index < 0 || document->tokens[index].type != TOKEN_PRIMITIVE) return 0;
    token = &document->tokens[index];
    if (token->start == token->end || document->bytes[token->start] == '0') return 0;
    for (cursor = token->start; cursor < token->end; ++cursor)
        if (!isdigit(document->bytes[cursor])) return 0;
    return 1;
}

static int
validate_version_identity(const uint8_t *bytes, size_t size,
    struct provider_identity *output)
{
    static const char *const keys[] = {"appName", "buildType", "commit", "version"};
    struct document document;
    struct provider_identity identity, banner_identity;
    char server_build[65], server_commit[41], server_banner[160];
    int item = -1, app, build, commit, version;
    int cli = 0, server = 0;
    memset(&identity, 0, sizeof(identity));
    memset(&banner_identity, 0, sizeof(banner_identity));
    memset(server_build, 0, sizeof(server_build));
    memset(server_commit, 0, sizeof(server_commit));
    memset(server_banner, 0, sizeof(server_banner));
    if (json_parse(bytes, size, &document) != 0
        || document.tokens[0].type != TOKEN_ARRAY) return -1;
    while ((item = next_direct(&document, 0, item)) >= 0) {
        if (document.tokens[item].type != TOKEN_OBJECT
            || object_keys(&document, item, keys, 4, 4, 4) != 0
            || object_get(&document, item, "appName", &app) != 0
            || object_get(&document, item, "buildType", &build) != 0
            || object_get(&document, item, "commit", &commit) != 0
            || object_get(&document, item, "version", &version) != 0
            || !token_text(&document, build, "release")) return -1;
        if (token_text(&document, app, "container")) {
            if (cli || token_copy_text(&document, version,
                    identity.version, sizeof(identity.version)) != 0
                || token_copy_text(&document, build,
                    identity.build, sizeof(identity.build)) != 0
                || token_copy_text(&document, commit,
                    identity.commit, sizeof(identity.commit)) != 0
                || !stable_version_supported(identity.version)
                || !commit_valid(identity.commit)) return -1;
            cli = 1;
        } else if (token_text(&document, app, "container-apiserver")) {
            if (server || token_copy_text(&document, build,
                    server_build, sizeof(server_build)) != 0
                || token_copy_text(&document, commit,
                    server_commit, sizeof(server_commit)) != 0
                || token_copy_text(&document, version,
                    server_banner, sizeof(server_banner)) != 0
                || !commit_valid(server_commit)
                || server_banner_identity(server_banner, &banner_identity) != 0)
                return -1;
            server = 1;
        } else return -1;
    }
    if (!cli || !server
        || strcmp(identity.version, banner_identity.version) != 0
        || strcmp(identity.build, server_build) != 0
        || strcmp(identity.build, banner_identity.build) != 0
        || strcmp(identity.commit, server_commit) != 0
        || strncmp(identity.commit, banner_identity.commit, 7U) != 0)
        return -1;
    if (output != NULL) *output = identity;
    return 0;
}

static int
validate_status_identity(const uint8_t *bytes, size_t size,
    const struct provider_identity *expected)
{
    static const char *const keys[] = {"status", "appRoot", "installRoot",
        "logRoot", "apiServerVersion", "apiServerCommit", "apiServerBuild",
        "apiServerAppName"};
    struct document document;
    struct provider_identity observed, banner_identity;
    char banner[160];
    int value, app_root, install_root, commit, build;
    memset(&observed, 0, sizeof(observed));
    memset(&banner_identity, 0, sizeof(banner_identity));
    memset(banner, 0, sizeof(banner));
    if (json_parse(bytes, size, &document) != 0
        || document.tokens[0].type != TOKEN_OBJECT
        || object_keys(&document, 0, keys, 8, 7, 8) != 0
        || object_get(&document, 0, "status", &value) != 0
        || !token_text(&document, value, "running")
        || object_get(&document, 0, "appRoot", &app_root) != 0
        || object_get(&document, 0, "installRoot", &install_root) != 0
        || !token_safe_text(&document, app_root, 4096)
        || !token_text(&document, install_root, "/usr/local/")
        || token_text(&document, app_root, "/usr/local/")
        || object_get(&document, 0, "apiServerVersion", &value) != 0
        || token_copy_text(&document, value, banner, sizeof(banner)) != 0
        || server_banner_identity(banner, &banner_identity) != 0
        || object_get(&document, 0, "apiServerCommit", &commit) != 0
        || token_copy_text(&document, commit,
            observed.commit, sizeof(observed.commit)) != 0
        || !commit_valid(observed.commit)
        || object_get(&document, 0, "apiServerBuild", &build) != 0
        || token_copy_text(&document, build,
            observed.build, sizeof(observed.build)) != 0
        || strcmp(observed.build, "release") != 0
        || object_get(&document, 0, "apiServerAppName", &value) != 0
        || !token_text(&document, value, "container-apiserver")) return -1;
    memcpy(observed.version, banner_identity.version,
        strlen(banner_identity.version) + 1U);
    if (strcmp(observed.build, banner_identity.build) != 0
        || strncmp(observed.commit, banner_identity.commit, 7U) != 0
        || (expected != NULL
            && (strcmp(observed.version, expected->version) != 0
                || strcmp(observed.build, expected->build) != 0
                || strcmp(observed.commit, expected->commit) != 0))) return -1;
    return 0;
}

static int
digest_text_valid(const char *value)
{
    size_t index;
    if (value == NULL || strlen(value) != 71 || memcmp(value, "sha256:", 7) != 0)
        return 0;
    for (index = 7; index < 71; ++index)
        if (!(value[index] >= '0' && value[index] <= '9')
            && !(value[index] >= 'a' && value[index] <= 'f')) return 0;
    return 1;
}

static int
reference_valid(const char *reference, const char *index_digest)
{
    const char *marker;
    size_t length, index, component = 0;
    if (reference == NULL || index_digest == NULL
        || (length = strlen(reference)) == 0
        || length >= PLAMEN_BROKER_V2_APPLE_CONTAINER_REFERENCE_MAX
        || (marker = strstr(reference, "@sha256:")) == NULL
        || marker == reference || strchr(marker + 1, '@') != NULL
        || strcmp(marker + 1, index_digest) != 0) return 0;
    for (index = 0; reference + index < marker; ++index) {
        unsigned char value = (unsigned char)reference[index];
        if (!((value >= 'a' && value <= 'z')
                || (value >= '0' && value <= '9') || value == '.'
                || value == '_' || value == '-' || value == '/'
                || value == ':')) return 0;
        if (value == '/') {
            if (index == component || (index - component == 1
                    && reference[component] == '.')
                || (index - component == 2 && reference[component] == '.'
                    && reference[component + 1] == '.')) return 0;
            component = index + 1U;
        }
    }
    if (component == (size_t)(marker - reference)
        || reference[0] == '.' || reference[0] == '-'
        || marker[-1] == '.' || marker[-1] == '-' || marker[-1] == '/') return 0;
    return 1;
}

static int
validate_image(const uint8_t *bytes, size_t size, const char *reference,
    const char *index_digest, const char *manifest_digest)
{
    static const char *const root_keys[] = {"id", "configuration", "variants"};
    static const char *const configuration_keys[] = {"creationDate", "name", "descriptor"};
    static const char *const descriptor_keys[] = {"digest", "mediaType", "size"};
    static const char *const variant_keys[] = {"platform", "digest", "size", "config"};
    static const char *const platform_keys[] = {"os", "architecture"};
    struct document document;
    int resource = -1, configuration, descriptor, variants, variant = -1;
    int platform, value, matches = 0;
    if (!digest_text_valid(index_digest) || !digest_text_valid(manifest_digest)
        || strcmp(index_digest, manifest_digest) == 0
        || !reference_valid(reference, index_digest)
        || json_parse(bytes, size, &document) != 0
        || document.tokens[0].type != TOKEN_ARRAY
        || (resource = next_direct(&document, 0, -1)) < 0
        || next_direct(&document, 0, resource) >= 0
        || document.tokens[resource].type != TOKEN_OBJECT
        || object_keys(&document, resource, root_keys, 3, 3, 3) != 0
        || object_get(&document, resource, "id", &value) != 0
        || !token_text(&document, value, index_digest + 7)
        || object_get(&document, resource, "configuration", &configuration) != 0
        || document.tokens[configuration].type != TOKEN_OBJECT
        || object_keys(&document, configuration, configuration_keys, 3, 3, 3) != 0
        || object_get(&document, configuration, "name", &value) != 0
        || !token_text(&document, value, reference)
        || object_get(&document, configuration, "creationDate", &value) != 0
        || !token_safe_text(&document, value, 128)
        || object_get(&document, configuration, "descriptor", &descriptor) != 0
        || document.tokens[descriptor].type != TOKEN_OBJECT
        || object_keys(&document, descriptor, descriptor_keys, 3, 3, 3) != 0
        || object_get(&document, descriptor, "digest", &value) != 0
        || !token_text(&document, value, index_digest)
        || object_get(&document, descriptor, "mediaType", &value) != 0
        || !token_text(&document, value, OCI_INDEX_MEDIA)
        || object_get(&document, descriptor, "size", &value) != 0
        || !primitive_positive(&document, value)
        || object_get(&document, resource, "variants", &variants) != 0
        || document.tokens[variants].type != TOKEN_ARRAY) return -1;
    while ((variant = next_direct(&document, variants, variant)) >= 0) {
        if (document.tokens[variant].type != TOKEN_OBJECT
            || object_keys(&document, variant, variant_keys, 4, 4, 4) != 0
            || object_get(&document, variant, "platform", &platform) != 0
            || document.tokens[platform].type != TOKEN_OBJECT
            || object_keys(&document, platform, platform_keys, 2, 2, 2) != 0
            || object_get(&document, variant, "os", &value) == 0) return -1;
        /* platform fields belong to the nested object, not the variant. */
        if (object_get(&document, platform, "os", &value) != 0) return -1;
        if (token_text(&document, value, "linux")) {
            if (object_get(&document, platform, "architecture", &value) != 0)
                return -1;
            if (token_text(&document, value, "arm64")) {
                if (++matches != 1
                    || object_get(&document, variant, "digest", &value) != 0
                    || !token_text(&document, value, manifest_digest)
                    || object_get(&document, variant, "size", &value) != 0
                    || !primitive_positive(&document, value)
                    || object_get(&document, variant, "config", &value) != 0
                    || document.tokens[value].type != TOKEN_OBJECT) return -1;
            }
        }
    }
    return matches == 1 ? 0 : -1;
}

int
plamen_broker_v2_apple_container_validate_state(const uint8_t *bytes,
    size_t size, const char *container_id, const char *reference,
    const char *state, uint8_t observation_sha256[32])
{
    static const char *const root_keys[] = {"id", "configuration", "status"};
    struct document document;
    int resource, configuration, status_object, image, networks, value;
    if (bytes == NULL || container_id == NULL || reference == NULL
        || state == NULL || observation_sha256 == NULL
        || plamen_broker_v2_apple_container_id_validate(container_id) != 0
        || (strcmp(state, "stopped") != 0 && strcmp(state, "running") != 0)
        || json_parse(bytes, size, &document) != 0
        || document.tokens[0].type != TOKEN_ARRAY
        || (resource = next_direct(&document, 0, -1)) < 0
        || next_direct(&document, 0, resource) >= 0
        || document.tokens[resource].type != TOKEN_OBJECT
        || object_keys(&document, resource, root_keys, 3, 3, 3) != 0
        || object_get(&document, resource, "id", &value) != 0
        || !token_text(&document, value, container_id)
        || object_get(&document, resource, "configuration", &configuration) != 0
        || document.tokens[configuration].type != TOKEN_OBJECT
        || object_get(&document, configuration, "id", &value) != 0
        || !token_text(&document, value, container_id)
        || object_get(&document, configuration, "image", &image) != 0
        || document.tokens[image].type != TOKEN_OBJECT
        || object_get(&document, image, "reference", &value) != 0
        || !token_text(&document, value, reference)
        || object_get(&document, configuration, "readOnly", &value) != 0
        || document.tokens[value].type != TOKEN_PRIMITIVE
        || document.tokens[value].end - document.tokens[value].start != 4
        || memcmp(document.bytes + document.tokens[value].start, "true", 4) != 0
        || object_get(&document, configuration, "useInit", &value) != 0
        || document.tokens[value].type != TOKEN_PRIMITIVE
        || document.tokens[value].end - document.tokens[value].start != 4
        || memcmp(document.bytes + document.tokens[value].start, "true", 4) != 0
        || object_get(&document, configuration, "networks", &networks) != 0
        || document.tokens[networks].type != TOKEN_ARRAY
        || next_direct(&document, networks, -1) >= 0
        || object_get(&document, resource, "status", &status_object) != 0
        || document.tokens[status_object].type != TOKEN_OBJECT
        || object_get(&document, status_object, "state", &value) != 0
        || !token_text(&document, value, state)
        || object_get(&document, status_object, "networks", &networks) != 0
        || document.tokens[networks].type != TOKEN_ARRAY
        || next_direct(&document, networks, -1) >= 0)
        return -1;
    return plamen_broker_v2_sha256(bytes, size, observation_sha256);
}

static int
read_stdout(struct plamen_broker_v2_process *process, uint64_t size,
    uint8_t **output)
{
    uint8_t *bytes;
    uint64_t offset = 0, full_size;
    uint32_t amount, maximum;
    uint8_t eof, chunk_sha[32], full_sha[32];
    if (size == 0 || size > JSON_MAX || (bytes = malloc((size_t)size)) == NULL)
        return -1;
    while (offset < size) {
        maximum = (uint32_t)(size - offset > OUTPUT_CHUNK
            ? OUTPUT_CHUNK : size - offset);
        if (plamen_broker_v2_process_read_output(process,
                PLAMEN_BROKER_V2_PROCESS_STREAM_STDOUT, offset, maximum,
                bytes + offset, maximum, &amount, &eof, chunk_sha, full_sha,
                &full_size) != 0 || amount == 0 || full_size != size) {
            free(bytes); return -1;
        }
        offset += amount;
    }
    *output = bytes; return 0;
}

static int
run_command(const struct plamen_broker_v2_apple_container_admission_spec *spec,
    const char *const *argv, size_t argc, uint8_t **stdout_bytes,
    size_t *stdout_size, uint8_t stdout_sha[32])
{
    struct plamen_broker_v2_process_spec process_spec;
    struct plamen_broker_v2_process *process = NULL;
    struct plamen_broker_v2_process_prepared_identity prepared;
    struct plamen_broker_v2_process_start_identity started;
    struct plamen_broker_v2_process_terminal terminal;
    int result = -1;
    memset(&process_spec, 0, sizeof(process_spec));
    memset(&prepared, 0, sizeof(prepared)); memset(&started, 0, sizeof(started));
    memset(&terminal, 0, sizeof(terminal));
    process_spec.version = 1; process_spec.executable_fd = spec->cli_fd;
    process_spec.executable_path = spec->cli_path; process_spec.argv = argv;
    process_spec.argc = argc;
    process_spec.environment_policy = PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED;
    process_spec.cwd_fd = spec->cwd_fd; process_spec.stdin_fd = spec->stdin_fd;
    process_spec.timeout_seconds = spec->timeout_seconds;
    process_spec.stdout_spool_limit = JSON_MAX;
    process_spec.stderr_spool_limit = 4096;
    process_spec.expected_executable_sha256 = spec->cli_sha256;
    process_spec.expected_signing_identifier = CLI_IDENTIFIER;
    process_spec.expected_team_identifier = APPLE_TEAM;
    if (plamen_broker_v2_process_prepare(&process_spec, &prepared, &process) != 0
        || plamen_broker_v2_process_start(process, &started) != 0
        || plamen_broker_v2_process_wait(process, &terminal) != 0
        || terminal.status != PLAMEN_BROKER_V2_PROCESS_OK
        || terminal.exit_code != 0 || terminal.signal_number != 0
        || terminal.stdout_overflow || terminal.stderr_overflow
        || terminal.stderr_size != 0 || !terminal.child_reaped
        || !terminal.process_group_extinct
        || read_stdout(process, terminal.stdout_size, stdout_bytes) != 0)
        goto done;
    *stdout_size = (size_t)terminal.stdout_size;
    memcpy(stdout_sha, terminal.stdout_sha256, 32); result = 0;
done:
    if (process != NULL) {
        if (result != 0) (void)plamen_broker_v2_process_extinguish(process, NULL);
        if (plamen_broker_v2_process_close(process) != 0) result = -1;
    }
    return result;
}

static int
closure_validate(const struct plamen_broker_v2_apple_container_admission_spec *spec,
    uint8_t output[32])
{
    CC_SHA256_CTX context;
    uint8_t digest[32], role[4];
    size_t index;
    struct stat identities[PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT];
    struct stat cli_identity;
    static const uint8_t policy[] = POLICY_TEXT;
    if (fstat(spec->cli_fd, &cli_identity) != 0
        || !S_ISREG(cli_identity.st_mode)
        || CC_SHA256_Init(&context) != 1
        || CC_SHA256_Update(&context, policy, sizeof(policy)) != 1) return -1;
    for (index = 0; index < PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT;
         ++index) {
        role[0] = (uint8_t)(index >> 24); role[1] = (uint8_t)(index >> 16);
        role[2] = (uint8_t)(index >> 8); role[3] = (uint8_t)index;
        if (all_zero(spec->closure[index].expected_sha256)
            || fstat(spec->closure[index].fd, &identities[index]) != 0
            || !S_ISREG(identities[index].st_mode)
            || (identities[index].st_dev == cli_identity.st_dev
                && identities[index].st_ino == cli_identity.st_ino)
            || sha256_fd(spec->closure[index].fd, digest) != 0
            || !constant_equal(digest, spec->closure[index].expected_sha256, 32)
            || CC_SHA256_Update(&context, role, sizeof(role)) != 1
            || CC_SHA256_Update(&context, digest, sizeof(digest)) != 1) return -1;
        for (size_t prior = 0; prior < index; ++prior)
            if (identities[index].st_dev == identities[prior].st_dev
                && identities[index].st_ino == identities[prior].st_ino)
                return -1;
    }
    return CC_SHA256_Final(output, &context) == 1 ? 0 : -1;
}

int
plamen_broker_v2_apple_container_admit(
    const struct plamen_broker_v2_apple_container_admission_spec *spec,
    struct plamen_broker_v2_apple_container_admission_receipt *receipt)
{
    static const uint8_t domain[] = "plamen.apple-container.admission.v1";
    struct provider_identity provider_identity;
    const char *version_argv[5], *status_argv[5], *init_argv[4], *runtime_argv[4];
    uint8_t *outputs[4] = {NULL, NULL, NULL, NULL};
    size_t sizes[4] = {0, 0, 0, 0}, index;
    CC_SHA256_CTX digest;
    int result = PLAMEN_BROKER_V2_APPLE_CONTAINER_REJECTED;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    if (spec == NULL || receipt == NULL
        || spec->version != PLAMEN_BROKER_V2_APPLE_CONTAINER_VERSION
        || spec->cli_fd < 0 || spec->cli_path == NULL || spec->cwd_fd < 0
        || spec->stdin_fd < 0 || spec->timeout_seconds == 0
        || spec->timeout_seconds > 300 || all_zero(spec->cli_sha256)
        || all_zero(spec->request_fingerprint_sha256)
        || all_zero(spec->provider_provenance_sha256)
        || all_zero(spec->image_closure_sha256)
        || spec->package_signed != 1 || spec->package_notarized != 1
        || spec->package_timestamped != 1
        || spec->implicit_kernel_install_disabled != 1
        || !reference_valid(spec->runtime_image_reference,
            spec->runtime_index_digest)
        || !digest_text_valid(spec->runtime_manifest_digest)
        || strcmp(spec->runtime_index_digest, spec->runtime_manifest_digest) == 0
        || closure_validate(spec, receipt->closure_sha256) != 0) return result;
    version_argv[0] = spec->cli_path; version_argv[1] = "system";
    version_argv[2] = "version"; version_argv[3] = "--format";
    version_argv[4] = "json";
    status_argv[0] = spec->cli_path; status_argv[1] = "system";
    status_argv[2] = "status"; status_argv[3] = "--format";
    status_argv[4] = "json";
    init_argv[0] = spec->cli_path; init_argv[1] = "image";
    init_argv[2] = "inspect"; init_argv[3] = INIT_REFERENCE;
    runtime_argv[0] = spec->cli_path; runtime_argv[1] = "image";
    runtime_argv[2] = "inspect"; runtime_argv[3] = spec->runtime_image_reference;
    if (run_command(spec, version_argv, 5, &outputs[0], &sizes[0],
            receipt->version_stdout_sha256) != 0
        || validate_version_identity(outputs[0], sizes[0],
            &provider_identity) != 0
        || run_command(spec, status_argv, 5, &outputs[1], &sizes[1],
            receipt->status_stdout_sha256) != 0
        || validate_status_identity(outputs[1], sizes[1],
            &provider_identity) != 0
        || run_command(spec, init_argv, 4, &outputs[2], &sizes[2],
            receipt->init_image_stdout_sha256) != 0
        || validate_image(outputs[2], sizes[2], INIT_REFERENCE, INIT_INDEX,
            INIT_MANIFEST) != 0
        || run_command(spec, runtime_argv, 4, &outputs[3], &sizes[3],
            receipt->runtime_image_stdout_sha256) != 0
        || validate_image(outputs[3], sizes[3], spec->runtime_image_reference,
            spec->runtime_index_digest, spec->runtime_manifest_digest) != 0) {
        result = PLAMEN_BROKER_V2_APPLE_CONTAINER_COMMAND_FAILED; goto done;
    }
    memcpy(receipt->init_image_postcondition_sha256,
        receipt->init_image_stdout_sha256, 32);
    memcpy(receipt->runtime_image_postcondition_sha256,
        receipt->runtime_image_stdout_sha256, 32);
    memcpy(receipt->cli_sha256, spec->cli_sha256, 32);
    memcpy(receipt->request_fingerprint_sha256,
        spec->request_fingerprint_sha256, 32);
    memcpy(receipt->provider_provenance_sha256,
        spec->provider_provenance_sha256, 32);
    memcpy(receipt->image_closure_sha256, spec->image_closure_sha256, 32);
    receipt->version = PLAMEN_BROKER_V2_APPLE_CONTAINER_RECEIPT_VERSION;
    receipt->status = PLAMEN_BROKER_V2_APPLE_CONTAINER_OK;
    receipt->command_count = 4; receipt->commands_read_only = 1;
    receipt->lifecycle_authority_granted = 0;
    receipt->mutable_identifier_accepted = 0;
    receipt->control_processes_reaped = 1;
    receipt->control_process_groups_extinct = 1;
    memcpy(receipt->runtime_image_reference, spec->runtime_image_reference,
        strlen(spec->runtime_image_reference) + 1U);
    if (CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, domain, sizeof(domain)) != 1
        || CC_SHA256_Update(&digest, receipt,
            offsetof(struct plamen_broker_v2_apple_container_admission_receipt,
                admission_sha256)) != 1
        || CC_SHA256_Final(receipt->admission_sha256, &digest) != 1) {
        result = PLAMEN_BROKER_V2_APPLE_CONTAINER_INTERNAL_ERROR; goto done;
    }
    result = PLAMEN_BROKER_V2_APPLE_CONTAINER_OK;
done:
    for (index = 0; index < 4; ++index) {
        if (outputs[index] != NULL) { memset(outputs[index], 0, sizes[index]);
            free(outputs[index]); }
    }
    if (result != PLAMEN_BROKER_V2_APPLE_CONTAINER_OK)
        memset(receipt, 0, sizeof(*receipt));
    return result;
}

int
plamen_broker_v2_apple_container_receipt_validate(
    const struct plamen_broker_v2_apple_container_admission_receipt *receipt)
{
    struct plamen_broker_v2_apple_container_admission_receipt copy;
    CC_SHA256_CTX digest;
    static const uint8_t domain[] = "plamen.apple-container.admission.v1";
    uint8_t observed[32];
    const char *marker, *end;
    if (receipt == NULL
        || receipt->version != PLAMEN_BROKER_V2_APPLE_CONTAINER_RECEIPT_VERSION
        || receipt->status != PLAMEN_BROKER_V2_APPLE_CONTAINER_OK
        || receipt->command_count != 4 || receipt->commands_read_only != 1
        || receipt->lifecycle_authority_granted != 0
        || receipt->mutable_identifier_accepted != 0
        || receipt->control_processes_reaped != 1
        || receipt->control_process_groups_extinct != 1
        || all_zero(receipt->request_fingerprint_sha256)
        || all_zero(receipt->provider_provenance_sha256)
        || all_zero(receipt->image_closure_sha256)) return -1;
    end = memchr(receipt->runtime_image_reference, '\0',
        sizeof(receipt->runtime_image_reference));
    marker = memchr(receipt->runtime_image_reference, '@',
        sizeof(receipt->runtime_image_reference));
    if (end == NULL || marker == NULL || marker >= end
        || !reference_valid(receipt->runtime_image_reference, marker + 1))
        return -1;
    copy = *receipt; memset(copy.admission_sha256, 0, 32);
    if (CC_SHA256_Init(&digest) != 1
        || CC_SHA256_Update(&digest, domain, sizeof(domain)) != 1
        || CC_SHA256_Update(&digest, &copy,
            offsetof(struct plamen_broker_v2_apple_container_admission_receipt,
                admission_sha256)) != 1
        || CC_SHA256_Final(observed, &digest) != 1) return -1;
    return constant_equal(observed, receipt->admission_sha256, 32) ? 0 : -1;
}

int
plamen_broker_v2_apple_container_derive_id(const uint8_t request[32],
    const uint8_t operation[32], char output[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE])
{
    static const char hexadecimal[] = "0123456789abcdef";
    static const uint8_t domain[] = "plamen.apple-container.id.v1";
    uint8_t digest[32];
    CC_SHA256_CTX context;
    size_t index;
    if (request == NULL || operation == NULL || output == NULL
        || all_zero(request) || all_zero(operation)
        || CC_SHA256_Init(&context) != 1
        || CC_SHA256_Update(&context, domain, sizeof(domain)) != 1
        || CC_SHA256_Update(&context, request, 32) != 1
        || CC_SHA256_Update(&context, operation, 32) != 1
        || CC_SHA256_Final(digest, &context) != 1) return -1;
    memcpy(output, "plamen-", 7);
    for (index = 0; index < 16; ++index) {
        output[7 + index * 2] = hexadecimal[digest[index] >> 4];
        output[8 + index * 2] = hexadecimal[digest[index] & 15];
    }
    output[39] = '\0'; return 0;
}

int
plamen_broker_v2_apple_container_id_validate(const char *value)
{
    size_t index;
    if (value == NULL || strlen(value) != 39 || memcmp(value, "plamen-", 7) != 0)
        return -1;
    for (index = 7; index < 39; ++index)
        if (!(value[index] >= '0' && value[index] <= '9')
            && !(value[index] >= 'a' && value[index] <= 'f')) return -1;
    return 0;
}

#ifdef PLAMEN_BROKER_V2_APPLE_CONTAINER_TEST_ONLY
int plamen_broker_v2_apple_container_test_validate_version(
    const uint8_t *bytes, size_t size)
{ return validate_version_identity(bytes, size, NULL); }
int plamen_broker_v2_apple_container_test_validate_status(
    const uint8_t *bytes, size_t size)
{ return validate_status_identity(bytes, size, NULL); }
int plamen_broker_v2_apple_container_test_validate_image(const uint8_t *bytes,
    size_t size, const char *reference, const char *index, const char *manifest)
{ return validate_image(bytes, size, reference, index, manifest); }
#endif
