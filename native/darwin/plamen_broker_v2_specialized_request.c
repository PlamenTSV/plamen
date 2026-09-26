#include "plamen_broker_v2_specialized_request.h"
#include "plamen_broker_v2_specialized_output_receipt.h"
#include "plamen_broker_v2_fuzz_campaign.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define JSON_DEPTH_MAX 32U
#define JSON_NODE_MAX 65536U
#define STRING_MAX 65536U

static const char *const role_names[8] = {
    "acquisition", "cache", "generation", "project",
    "scratch", "source", "state", "tool"
};

static int js_operation_name(const char *operation)
{
    return operation != NULL
        && (strcmp(operation, "PREPARE_TOOLCHAIN") == 0
            || strcmp(operation, "ONLINE_INSTALL") == 0
            || strcmp(operation, "CACHE_HANDOFF") == 0
            || strcmp(operation, "OFFLINE_REPLAY") == 0);
}

static const char *js_operation_subcommand(const char *operation)
{
    if (operation == NULL) return NULL;
    if (strcmp(operation, "PREPARE_TOOLCHAIN") == 0) return "prepare-toolchain";
    if (strcmp(operation, "ONLINE_INSTALL") == 0) return "online-install";
    if (strcmp(operation, "CACHE_HANDOFF") == 0) return "cache-handoff";
    if (strcmp(operation, "OFFLINE_REPLAY") == 0) return "offline-replay";
    return NULL;
}

int
plamen_broker_v2_specialized_worker_tool_anchor_path(uint16_t lane,
    uint16_t method, const char *anchor, const char **guest_path)
{
    const char *path = NULL;
    if (guest_path != NULL) *guest_path = NULL;
    if (anchor == NULL || guest_path == NULL) return -1;
    if (lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        && method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE
        && strcmp(anchor, "js-python") == 0)
        path = "/usr/local/lib/plamen/python/bin/python3.12";
    else if (lane == PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM
        && method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE
        && strcmp(anchor, "managed-python") == 0)
        path = "/usr/local/lib/plamen/python/bin/python3.12";
    else if (lane == PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
        && method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
        && strcmp(anchor, "js-python") == 0)
        path = "/usr/local/lib/plamen/python/bin/python3.12";
    else if (lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        && method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE
        && strcmp(anchor, "forge") == 0)
        path = "/usr/local/lib/plamen/toolchains/foundry/bin/forge";
    else if (lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        && method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE
        && strcmp(anchor, "opengrep") == 0)
        path = "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep";
    else if (lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        && method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE
        && strcmp(anchor, "slither") == 0)
        path = "/usr/local/lib/plamen/toolchains/managed-evm/bin/slither";
    else if (lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        && method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE
        && strcmp(anchor, "solc") == 0)
        path = "/usr/local/lib/plamen/toolchains/solc-amd64/solc";
    if (path == NULL) return -1;
    *guest_path = path; return 0;
}

enum json_kind { J_NULL, J_BOOL, J_INTEGER, J_STRING, J_ARRAY, J_OBJECT };
struct json_node;
struct json_member { char *key; struct json_node *value; };
struct json_node {
    enum json_kind kind;
    int boolean;
    int negative;
    uint64_t integer;
    char *string;
    struct json_node **items;
    struct json_member *members;
    size_t count;
    size_t raw_start;
    size_t raw_end;
};
struct json_parser {
    const uint8_t *raw;
    size_t size;
    size_t offset;
    size_t nodes;
};

static int digest_zero(const uint8_t value[32])
{
    size_t i; uint8_t joined = 0;
    if (value == NULL) return 1;
    for (i = 0; i < 32U; ++i) joined |= value[i];
    return joined == 0;
}

int
plamen_broker_v2_specialized_slither_internal_environment_sha256(
    uint8_t output[32])
{
    static const uint8_t canonical[] =
        "[[\"FOUNDRY_CACHE_PATH\",\"@fd:state/foundry-cache\"],"
        "[\"FOUNDRY_OUT\",\"@fd:scratch/foundry-out\"],"
        "[\"HOME\",\"@fd:state/home\"],"
        "[\"PATH\",\"/usr/local/lib/plamen/toolchains/managed-evm/bin:"
        "/usr/local/lib/plamen/toolchains/foundry/bin:"
        "/usr/local/lib/plamen/toolchains/solc-amd64:/usr/bin:/bin\"],"
        "[\"XDG_CACHE_HOME\",\"@fd:state/cache\"]]";
    if (output == NULL
        || plamen_broker_v2_sha256(canonical, sizeof(canonical) - 1U,
            output) != 0 || digest_zero(output)) return -1;
    return 0;
}

static int constant_equal(const uint8_t *a, const uint8_t *b, size_t size)
{
    size_t i; uint8_t value = 0;
    if (a == NULL || b == NULL) return 0;
    for (i = 0; i < size; ++i) value |= (uint8_t)(a[i] ^ b[i]);
    return value == 0;
}

/* Worker terminals contain only the closed ASCII vocabulary validated below.
 * Reject alternate JSON spellings before parsing: insignificant whitespace,
 * escaped/string aliases, non-ASCII octets, and negative zero are not
 * canonical worker bytes. */
static int terminal_canonical_octets(const uint8_t *raw, size_t size)
{
    size_t i; int string = 0;
    if (raw == NULL || size < 2U || raw[0] != '{' || raw[size - 1U] != '}')
        return 0;
    for (i = 0; i < size; ++i) {
        uint8_t current = raw[i];
        if (current < 0x20U || current >= 0x7fU || current == '\\') return 0;
        if (current == '"') { string = !string; continue; }
        if (!string && (current == ' ' || current == '\t'
                || current == '\r' || current == '\n')) return 0;
        if (!string && current == '-' && i + 1U < size && raw[i + 1U] == '0'
            && (i + 2U == size || raw[i + 2U] == ','
                || raw[i + 2U] == '}' || raw[i + 2U] == ']')) return 0;
    }
    return !string;
}

static void json_destroy(struct json_node *node)
{
    size_t i;
    if (node == NULL) return;
    if (node->kind == J_STRING) free(node->string);
    if (node->kind == J_ARRAY) {
        for (i = 0; i < node->count; ++i) json_destroy(node->items[i]);
        free(node->items);
    }
    if (node->kind == J_OBJECT) {
        for (i = 0; i < node->count; ++i) {
            free(node->members[i].key);
            json_destroy(node->members[i].value);
        }
        free(node->members);
    }
    free(node);
}

static int hex_digit(uint8_t value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

/* Canonical worker JSON is ensure_ascii=True.  Object keys may not escape. */
static char *json_string(struct json_parser *parser, int key)
{
    char *result; size_t used = 0, capacity = 32U;
    (void)key;
    if (parser->offset >= parser->size || parser->raw[parser->offset++] != '"')
        return NULL;
    result = malloc(capacity);
    if (result == NULL) return NULL;
    while (parser->offset < parser->size) {
        uint8_t c = parser->raw[parser->offset++];
        if (c == '"') { result[used] = '\0'; return result; }
        if (c < 0x20U || c >= 0x7fU || used >= STRING_MAX) goto failed;
        if (c != '\\') {
            if (used + 2U > capacity) {
                char *grown; size_t next = capacity * 2U;
                if (next > STRING_MAX + 1U) next = STRING_MAX + 1U;
                grown = realloc(result, next); if (grown == NULL) goto failed;
                result = grown; capacity = next;
            }
            result[used++] = (char)c; continue;
        }
        if (parser->offset >= parser->size) goto failed;
        c = parser->raw[parser->offset++];
        if (used + 5U > capacity) {
            char *grown; size_t next = capacity * 2U;
            while (next < used + 5U) next *= 2U;
            if (next > STRING_MAX + 1U) next = STRING_MAX + 1U;
            if (next < used + 5U) goto failed;
            grown = realloc(result, next); if (grown == NULL) goto failed;
            result = grown; capacity = next;
        }
        if (c == '"' || c == '\\') result[used++] = (char)c;
        else if (c == 'b') result[used++] = '\b';
        else if (c == 'f') result[used++] = '\f';
        else if (c == 'n') result[used++] = '\n';
        else if (c == 'r') result[used++] = '\r';
        else if (c == 't') result[used++] = '\t';
        else if (c == 'u') {
            int a, b, d, e; unsigned value, codepoint;
            if (parser->offset + 4U > parser->size
                || (a = hex_digit(parser->raw[parser->offset])) < 0
                || (b = hex_digit(parser->raw[parser->offset + 1U])) < 0
                || (d = hex_digit(parser->raw[parser->offset + 2U])) < 0
                || (e = hex_digit(parser->raw[parser->offset + 3U])) < 0)
                goto failed;
            value = (unsigned)((a << 12) | (b << 8) | (d << 4) | e);
            parser->offset += 4U;
            if (value < 0x20U) {
                if (value == 8U || value == 9U || value == 10U
                    || value == 12U || value == 13U) goto failed;
                result[used++] = (char)value; continue;
            }
            /* Printable ASCII has a shorter canonical spelling. */
            if (value < 0x80U) goto failed;
            codepoint = value;
            if (value >= 0xd800U && value <= 0xdbffU) {
                unsigned low;
                if (parser->offset + 6U > parser->size
                    || parser->raw[parser->offset] != '\\'
                    || parser->raw[parser->offset + 1U] != 'u'
                    || (a = hex_digit(parser->raw[parser->offset + 2U])) < 0
                    || (b = hex_digit(parser->raw[parser->offset + 3U])) < 0
                    || (d = hex_digit(parser->raw[parser->offset + 4U])) < 0
                    || (e = hex_digit(parser->raw[parser->offset + 5U])) < 0)
                    goto failed;
                low = (unsigned)((a << 12) | (b << 8) | (d << 4) | e);
                if (low < 0xdc00U || low > 0xdfffU) goto failed;
                parser->offset += 6U;
                codepoint = 0x10000U + ((value - 0xd800U) << 10)
                    + (low - 0xdc00U);
            } else if (value >= 0xdc00U && value <= 0xdfffU) goto failed;
            if (codepoint < 0x800U) {
                result[used++] = (char)(0xc0U | (codepoint >> 6));
                result[used++] = (char)(0x80U | (codepoint & 0x3fU));
            } else if (codepoint < 0x10000U) {
                result[used++] = (char)(0xe0U | (codepoint >> 12));
                result[used++] = (char)(0x80U | ((codepoint >> 6) & 0x3fU));
                result[used++] = (char)(0x80U | (codepoint & 0x3fU));
            } else {
                result[used++] = (char)(0xf0U | (codepoint >> 18));
                result[used++] = (char)(0x80U | ((codepoint >> 12) & 0x3fU));
                result[used++] = (char)(0x80U | ((codepoint >> 6) & 0x3fU));
                result[used++] = (char)(0x80U | (codepoint & 0x3fU));
            }
        } else goto failed;
    }
failed:
    free(result); return NULL;
}

static struct json_node *json_value(struct json_parser *, unsigned);

static struct json_node *json_new(struct json_parser *parser,
    enum json_kind kind)
{
    struct json_node *node;
    if (++parser->nodes > JSON_NODE_MAX) return NULL;
    node = calloc(1, sizeof(*node));
    if (node != NULL) node->kind = kind;
    return node;
}

static struct json_node *json_array(struct json_parser *parser, unsigned depth)
{
    struct json_node *node = json_new(parser, J_ARRAY), *child;
    struct json_node **grown;
    if (node == NULL || parser->raw[parser->offset++] != '[') goto failed;
    if (parser->offset < parser->size && parser->raw[parser->offset] == ']') {
        ++parser->offset; return node;
    }
    for (;;) {
        child = json_value(parser, depth + 1U);
        if (child == NULL) goto failed;
        grown = realloc(node->items, (node->count + 1U) * sizeof(*grown));
        if (grown == NULL) { json_destroy(child); goto failed; }
        node->items = grown; node->items[node->count++] = child;
        if (parser->offset >= parser->size) goto failed;
        if (parser->raw[parser->offset] == ']') { ++parser->offset; return node; }
        if (parser->raw[parser->offset++] != ',') goto failed;
    }
failed:
    json_destroy(node); return NULL;
}

static struct json_node *json_object(struct json_parser *parser, unsigned depth)
{
    struct json_node *node = json_new(parser, J_OBJECT), *child;
    struct json_member *grown; char *key = NULL;
    if (node == NULL || parser->raw[parser->offset++] != '{') goto failed;
    if (parser->offset < parser->size && parser->raw[parser->offset] == '}') {
        ++parser->offset; return node;
    }
    for (;;) {
        key = json_string(parser, 1);
        if (key == NULL || (node->count > 0U
            && strcmp(node->members[node->count - 1U].key, key) >= 0)
            || parser->offset >= parser->size
            || parser->raw[parser->offset++] != ':') goto failed;
        child = json_value(parser, depth + 1U);
        if (child == NULL) goto failed;
        grown = realloc(node->members,
            (node->count + 1U) * sizeof(*grown));
        if (grown == NULL) { json_destroy(child); goto failed; }
        node->members = grown;
        node->members[node->count].key = key;
        node->members[node->count].value = child;
        ++node->count; key = NULL;
        if (parser->offset >= parser->size) goto failed;
        if (parser->raw[parser->offset] == '}') { ++parser->offset; return node; }
        if (parser->raw[parser->offset++] != ',') goto failed;
    }
failed:
    free(key); json_destroy(node); return NULL;
}

static struct json_node *json_value(struct json_parser *parser, unsigned depth)
{
    struct json_node *node = NULL; size_t start, number_start; uint8_t c;
    if (parser == NULL || depth > JSON_DEPTH_MAX
        || parser->offset >= parser->size) return NULL;
    start = parser->offset; c = parser->raw[parser->offset];
    if (c == '{') node = json_object(parser, depth);
    else if (c == '[') node = json_array(parser, depth);
    if (c == '"') {
        node = json_new(parser, J_STRING);
        if (node == NULL || (node->string = json_string(parser, 0)) == NULL) {
            json_destroy(node); return NULL;
        }
    } else if (c == 'n' && parser->offset + 4U <= parser->size
        && memcmp(parser->raw + parser->offset, "null", 4) == 0) {
        parser->offset += 4U; node = json_new(parser, J_NULL);
    } else if ((c == 't' || c == 'f')) {
        const char *word = c == 't' ? "true" : "false";
        size_t amount = c == 't' ? 4U : 5U;
        if (parser->offset + amount > parser->size
            || memcmp(parser->raw + parser->offset, word, amount) != 0)
            return NULL;
        parser->offset += amount; node = json_new(parser, J_BOOL);
        if (node != NULL) node->boolean = c == 't';
    } else if (c == '-' || (c >= '0' && c <= '9')) {
        node = json_new(parser, J_INTEGER);
        if (node == NULL) return NULL;
        node->negative = c == '-';
        if (node->negative && (++parser->offset >= parser->size
            || parser->raw[parser->offset] == '0')) goto number_failed;
        number_start = parser->offset;
        if (parser->raw[parser->offset] == '0') ++parser->offset;
        else {
            if (parser->raw[parser->offset] < '1'
                || parser->raw[parser->offset] > '9') goto number_failed;
            while (parser->offset < parser->size
                && parser->raw[parser->offset] >= '0'
                && parser->raw[parser->offset] <= '9') {
                unsigned digit = parser->raw[parser->offset++] - '0';
                if (node->integer > (UINT64_MAX - digit) / 10U)
                    goto number_failed;
                node->integer = node->integer * 10U + digit;
            }
        }
        if (parser->offset == number_start || (parser->offset < parser->size
            && (parser->raw[parser->offset] == '.'
                || parser->raw[parser->offset] == 'e'
                || parser->raw[parser->offset] == 'E'))) goto number_failed;
    } else if (c != '{' && c != '[') return NULL;
    if (node == NULL) return NULL;
    node->raw_start = start; node->raw_end = parser->offset;
    return node;
number_failed:
    json_destroy(node); return NULL;
}

static struct json_node *json_parse(const uint8_t *raw, size_t size)
{
    struct json_parser parser; struct json_node *node; size_t i;
    if (raw == NULL || size < 2U || raw[size - 1U] == '\n') return NULL;
    for (i = 0; i < size; ++i)
        if (raw[i] == 0 || raw[i] >= 0x80U
            || raw[i] == '\t' || raw[i] == '\r' || raw[i] == '\n') return NULL;
    memset(&parser, 0, sizeof(parser)); parser.raw = raw; parser.size = size;
    node = json_value(&parser, 0);
    if (node == NULL || parser.offset != size) { json_destroy(node); return NULL; }
    return node;
}

static struct json_node *object_get(const struct json_node *node,
    const char *key)
{
    size_t i;
    if (node == NULL || node->kind != J_OBJECT || key == NULL) return NULL;
    for (i = 0; i < node->count; ++i) {
        int compared = strcmp(node->members[i].key, key);
        if (compared == 0) return node->members[i].value;
        if (compared > 0) break;
    }
    return NULL;
}

static int string_is(const struct json_node *node, const char *value)
{ return node != NULL && node->kind == J_STRING && value != NULL
    && strcmp(node->string, value) == 0; }

static int object_keys(const struct json_node *node,
    const char *const *keys, size_t count)
{
    size_t i;
    if (node == NULL || node->kind != J_OBJECT || node->count != count)
        return 0;
    for (i = 0; i < count; ++i)
        if (strcmp(node->members[i].key, keys[i]) != 0) return 0;
    return 1;
}

struct buffer { uint8_t *data; size_t size; size_t capacity; int failed; };
static void put(struct buffer *out, const char *format, ...)
{
    va_list args; int amount;
    if (out == NULL || out->failed) return;
    va_start(args, format);
    amount = vsnprintf((char *)out->data + out->size,
        out->capacity > out->size ? out->capacity - out->size : 0,
        format, args);
    va_end(args);
    if (amount < 0 || (size_t)amount >= out->capacity - out->size) {
        out->failed = 1; return;
    }
    out->size += (size_t)amount;
}

static void hex32(const uint8_t input[32], char output[65])
{
    static const char alphabet[] = "0123456789abcdef"; size_t i;
    for (i = 0; i < 32U; ++i) {
        output[i * 2U] = alphabet[input[i] >> 4];
        output[i * 2U + 1U] = alphabet[input[i] & 15U];
    }
    output[64] = '\0';
}

static int decode_hex32(const struct json_node *node, uint8_t output[32])
{
    size_t i;
    if (node == NULL || node->kind != J_STRING
        || strlen(node->string) != 64U) return -1;
    for (i = 0; i < 32U; ++i) {
        int high = hex_digit((uint8_t)node->string[i * 2U]);
        int low = hex_digit((uint8_t)node->string[i * 2U + 1U]);
        if (high < 0 || low < 0) return -1;
        output[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int safe_ascii(const char *value, size_t maximum, int relative)
{
    size_t i, size;
    if (value == NULL || (size = strlen(value)) == 0 || size > maximum
        || (relative && (value[0] == '/' || value[0] == '~'
            || strstr(value, "\\") != NULL || strstr(value, "//") != NULL)))
        return 0;
    if (relative && (strcmp(value, "..") == 0 || strstr(value, "/../")
        || strncmp(value, "../", 3) == 0
        || (size >= 3U && strcmp(value + size - 3U, "/..") == 0))) return 0;
    for (i = 0; i < size; ++i)
        if ((unsigned char)value[i] < 0x20U
            || (unsigned char)value[i] >= 0x7fU) return 0;
    return 1;
}

int
plamen_broker_v2_fuzz_campaign_request_decode(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_fuzz_campaign_request_storage *storage)
{
    static const char *const keys[] = {
        "attempt_id", "authority_sha256", "cli_executable_sha256",
        "container_id", "guest_argv", "guest_cwd", "guest_environment",
        "guest_executable_sha256", "launch_policy_sha256",
        "operation_key_sha256", "phase_io_binding_sha256",
        "prepared_campaign_sha256", "provider_preflight_sha256",
        "provider_provenance_sha256", "request_sha256", "rosetta_required",
        "schema", "secure_launcher_sha256", "spec_sha256", "timeout_seconds"
    };
    struct json_node *root = NULL, *argv, *environment, *node;
    struct plamen_broker_v2_fuzz_campaign_request *request;
    size_t index, amount;
    int result = -1;
    if (storage != NULL) memset(storage, 0, sizeof(*storage));
    if (view == NULL || storage == NULL
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        || (view->method != PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE
            && view->method != PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE)
        || view->payload == NULL || view->payload_size < 2U)
        return -1;
    root = json_parse(view->payload, view->payload_size);
    if (!object_keys(root, keys, sizeof(keys) / sizeof(keys[0]))
        || !string_is(object_get(root, "schema"),
            "plamen.apple-fuzz-campaign-native-request.v1"))
        goto done;
    request = &storage->request;
    request->version = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_VERSION;
#define DIGEST(json_name, field) do { \
    if (decode_hex32(object_get(root, json_name), request->field) != 0) \
        goto done; \
} while (0)
    DIGEST("request_sha256", request_sha256);
    DIGEST("operation_key_sha256", operation_key);
    DIGEST("authority_sha256", authority_sha256);
    DIGEST("prepared_campaign_sha256", prepared_campaign_sha256);
    DIGEST("secure_launcher_sha256", secure_launcher_sha256);
    DIGEST("phase_io_binding_sha256", phase_io_binding_sha256);
    DIGEST("provider_preflight_sha256", provider_preflight_sha256);
    DIGEST("provider_provenance_sha256", provider_provenance_sha256);
    DIGEST("cli_executable_sha256", cli_executable_sha256);
    DIGEST("guest_executable_sha256", guest_executable_sha256);
    DIGEST("spec_sha256", spec_sha256);
    DIGEST("launch_policy_sha256", launch_policy_sha256);
#undef DIGEST
#define COPY_TEXT(json_name, field) do { \
    node = object_get(root, json_name); \
    if (node == NULL || node->kind != J_STRING \
        || (amount = strlen(node->string)) == 0U \
        || amount >= sizeof(storage->field)) goto done; \
    memcpy(storage->field, node->string, amount + 1U); \
} while (0)
    COPY_TEXT("container_id", container_id);
    COPY_TEXT("attempt_id", attempt_id);
    COPY_TEXT("guest_cwd", guest_cwd);
#undef COPY_TEXT
    argv = object_get(root, "guest_argv");
    environment = object_get(root, "guest_environment");
    node = object_get(root, "timeout_seconds");
    if (argv == NULL || argv->kind != J_ARRAY || argv->count == 0U
        || argv->count > PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX
        || environment == NULL || environment->kind != J_ARRAY
        || environment->count != 1U
        || !string_is(environment->items[0], PLAMEN_BROKER_V2_FUZZ_PATH)
        || node == NULL || node->kind != J_INTEGER || node->negative
        || node->integer == 0U || node->integer > 3600U)
        goto done;
    for (index = 0U; index < argv->count; ++index) {
        node = argv->items[index];
        if (node == NULL || node->kind != J_STRING
            || (amount = strlen(node->string)) == 0U
            || amount >= sizeof(storage->argv_text[index]))
            goto done;
        memcpy(storage->argv_text[index], node->string, amount + 1U);
        storage->argv[index] = storage->argv_text[index];
    }
    node = object_get(root, "rosetta_required");
    if (node == NULL || node->kind != J_BOOL) goto done;
    request->rosetta_required = (uint8_t)node->boolean;
    request->container_id = storage->container_id;
    request->attempt_id = storage->attempt_id;
    request->guest_executable = storage->argv_text[0];
    request->guest_argv = storage->argv;
    request->guest_argc = argv->count;
    storage->environment[0] = PLAMEN_BROKER_V2_FUZZ_PATH;
    request->guest_environment = storage->environment;
    request->guest_environment_count = 1U;
    request->guest_cwd = storage->guest_cwd;
    /* Recover timeout after node was reused for the boolean. */
    node = object_get(root, "timeout_seconds");
    request->timeout_seconds = (uint32_t)node->integer;
    if (strcmp(request->guest_executable,
            PLAMEN_BROKER_V2_FUZZ_FORGE_ANCHOR) == 0)
        request->tool = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE;
    else if (strcmp(request->guest_executable,
            PLAMEN_BROKER_V2_FUZZ_MEDUSA_ANCHOR) == 0)
        request->tool = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_MEDUSA;
    else goto done;
    result = 0;
done:
    json_destroy(root);
    if (result != 0) memset(storage, 0, sizeof(*storage));
    return result;
}

int
plamen_broker_v2_fuzz_service_admission_request_decode(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_fuzz_service_admission_storage *storage)
{
    static const char *const keys[] = {
        "attempt_id", "authority_sha256", "guest_argv",
        "phase_io_binding_sha256", "provider_preflight_sha256",
        "rosetta_required", "schema", "timeout_seconds", "workspace_root"
    };
    struct json_node *root = NULL, *argv, *node;
    size_t index, amount; int result = -1;
    if (storage != NULL) memset(storage, 0, sizeof(*storage));
    if (view == NULL || storage == NULL
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        || view->method != PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT
        || view->payload == NULL || view->payload_size < 2U) return -1;
    root = json_parse(view->payload, view->payload_size);
    if (!object_keys(root, keys, sizeof(keys) / sizeof(keys[0]))
        || !string_is(object_get(root, "schema"),
            PLAMEN_BROKER_V2_FUZZ_SERVICE_REQUEST_SCHEMA)
        || decode_hex32(object_get(root, "authority_sha256"),
            storage->request.authority_sha256) != 0
        || decode_hex32(object_get(root, "phase_io_binding_sha256"),
            storage->request.phase_io_binding_sha256) != 0
        || decode_hex32(object_get(root, "provider_preflight_sha256"),
            storage->request.provider_preflight_sha256) != 0)
        goto done;
#define COPY_SERVICE_TEXT(name, field) do { \
    node = object_get(root, name); \
    if (node == NULL || node->kind != J_STRING \
        || (amount = strlen(node->string)) == 0U \
        || amount >= sizeof(storage->field)) goto done; \
    memcpy(storage->field, node->string, amount + 1U); \
} while (0)
    COPY_SERVICE_TEXT("attempt_id", attempt_id);
    COPY_SERVICE_TEXT("workspace_root", workspace_root);
#undef COPY_SERVICE_TEXT
    argv = object_get(root, "guest_argv");
    if (argv == NULL || argv->kind != J_ARRAY || argv->count == 0U
        || argv->count > PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX) goto done;
    for (index = 0U; index < argv->count; ++index) {
        node = argv->items[index];
        if (node == NULL || node->kind != J_STRING
            || (amount = strlen(node->string)) == 0U
            || amount >= sizeof(storage->argv_text[index])) goto done;
        memcpy(storage->argv_text[index], node->string, amount + 1U);
        storage->argv[index] = storage->argv_text[index];
    }
    node = object_get(root, "timeout_seconds");
    if (node == NULL || node->kind != J_INTEGER || node->negative
        || node->integer == 0U || node->integer > 3600U) goto done;
    storage->request.timeout_seconds = (uint32_t)node->integer;
    node = object_get(root, "rosetta_required");
    if (node == NULL || node->kind != J_BOOL) goto done;
    storage->request.rosetta_required = (uint8_t)node->boolean;
    storage->request.version = PLAMEN_BROKER_V2_FUZZ_SERVICE_ADMISSION_VERSION;
    storage->request.attempt_id = storage->attempt_id;
    storage->request.workspace_root = storage->workspace_root;
    storage->request.guest_argv = storage->argv;
    storage->request.guest_argc = argv->count;
    if (strcmp(storage->argv_text[0], PLAMEN_BROKER_V2_FUZZ_FORGE_ANCHOR) == 0)
        storage->request.tool = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE;
    else if (strcmp(storage->argv_text[0],
            PLAMEN_BROKER_V2_FUZZ_MEDUSA_ANCHOR) == 0)
        storage->request.tool = PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_MEDUSA;
    else goto done;
    if (plamen_broker_v2_sha256(view->payload, view->payload_size,
            storage->request.admission_request_sha256) != 0) goto done;
    result = 0;
done:
    json_destroy(root);
    if (result != 0) memset(storage, 0, sizeof(*storage));
    return result;
}

int
plamen_broker_v2_fuzz_service_execute_request_decode(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    struct plamen_broker_v2_fuzz_service_execute_request *request)
{
    static const char *const keys[] = {
        "prepared_campaign_sha256", "schema", "secure_receipt_sha256"
    };
    struct json_node *root = NULL; int result = -1;
    if (request != NULL) memset(request, 0, sizeof(*request));
    if (view == NULL || request == NULL
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        || view->method != PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE
        || view->payload == NULL || view->payload_size < 2U) return -1;
    root = json_parse(view->payload, view->payload_size);
    if (!object_keys(root, keys, sizeof(keys) / sizeof(keys[0]))
        || !string_is(object_get(root, "schema"),
            PLAMEN_BROKER_V2_FUZZ_SERVICE_EXECUTE_SCHEMA)
        || decode_hex32(object_get(root, "prepared_campaign_sha256"),
            request->prepared_campaign_sha256) != 0
        || decode_hex32(object_get(root, "secure_receipt_sha256"),
            request->secure_receipt_sha256) != 0) goto done;
    result = 0;
done:
    json_destroy(root);
    if (result != 0) memset(request, 0, sizeof(*request));
    return result;
}

static int safe_request_id(const char *value)
{
    size_t i, size;
    if (!safe_ascii(value, 128U, 0) || (size = strlen(value)) == 0U
        || !((value[0] >= 'a' && value[0] <= 'z')
            || (value[0] >= '0' && value[0] <= '9'))) return 0;
    for (i = 1U; i < size; ++i)
        if (!((value[i] >= 'a' && value[i] <= 'z')
            || (value[i] >= '0' && value[i] <= '9')
            || value[i] == '.' || value[i] == '_' || value[i] == '-')) return 0;
    return 1;
}

static int safe_env_name(const char *value)
{
    size_t i, size;
    if (!safe_ascii(value, 64U, 0) || (size = strlen(value)) == 0U
        || value[0] < 'A' || value[0] > 'Z') return 0;
    for (i = 1U; i < size; ++i)
        if (!((value[i] >= 'A' && value[i] <= 'Z')
            || (value[i] >= '0' && value[i] <= '9') || value[i] == '_')) return 0;
    return 1;
}

static int role_index_name(const char *name)
{
    size_t i;
    for (i = 0; i < 8U; ++i) if (strcmp(name, role_names[i]) == 0) return (int)i;
    return -1;
}

static int has_noncanonical_path_segment(const char *value)
{
    const char *segment = value, *cursor;
    if (value == NULL) return 1;
    for (cursor = value; ; ++cursor) {
        if (*cursor == '/' || *cursor == '\0') {
            size_t size = (size_t)(cursor - segment);
            if (size == 0U || (size == 1U && segment[0] == '.')
                || (size == 2U && segment[0] == '.' && segment[1] == '.'))
                return 1;
            if (*cursor == '\0') break;
            segment = cursor + 1;
        }
    }
    return 0;
}

static int canonical_relative_path(const char *value, int allow_dot)
{
    return safe_ascii(value, 65535U, 1)
        && ((allow_dot && strcmp(value, ".") == 0)
            || !has_noncanonical_path_segment(value));
}

static int symbolic_token(const char *value, const uint8_t present[8])
{
    const char *body, *slash; char role[32]; size_t amount; int index;
    if (!safe_ascii(value, 65535U, 0)) return 0;
    if (strncmp(value, "@fd:", 4) != 0)
        return value[0] != '/' && value[0] != '~'
            && strstr(value, "\\") == NULL && strstr(value, "://") == NULL
            && !has_noncanonical_path_segment(value);
    body = value + 4; slash = strchr(body, '/');
    amount = slash == NULL ? strlen(body) : (size_t)(slash - body);
    if (amount == 0 || amount >= sizeof(role)) return 0;
    memcpy(role, body, amount); role[amount] = '\0';
    index = role_index_name(role);
    if (index < 0 || !present[index]) return 0;
    return slash == NULL || canonical_relative_path(slash + 1, 0);
}

static int denied_env(const char *name)
{
    static const char *const exact[] = { "BASH_ENV", "ENV", "GCONV_PATH",
        "NODE_OPTIONS", "PATH", "PERL5OPT", "PYTHONHOME", "PYTHONINSPECT",
        "PYTHONPATH", "PYTHONSTARTUP", "RUBYOPT", "SHELLOPTS" };
    size_t i;
    for (i = 0; i < sizeof(exact) / sizeof(exact[0]); ++i)
        if (strcmp(name, exact[i]) == 0) return 1;
    return strncmp(name, "DYLD_", 5) == 0 || strncmp(name, "LD_", 3) == 0
        || strncmp(name, "http_", 5) == 0 || strncmp(name, "https_", 6) == 0
        || strncmp(name, "HTTP_", 5) == 0 || strncmp(name, "HTTPS_", 6) == 0;
}

static int native_identity(int fd, const uint8_t expected[32])
{
    uint8_t observed[32]; int result;
    memset(observed, 0, sizeof(observed));
    result = plamen_broker_v2_fd_identity(fd, observed) == 0
        && constant_equal(observed, expected, 32);
    plamen_broker_v2_secure_zero(observed, sizeof(observed)); return result;
}

static int file_sha256(int fd, const struct stat *info, uint8_t output[32])
{
    uint8_t *bytes; size_t size, offset = 0; ssize_t amount; int result = -1;
    if (info->st_size < 0 || (uint64_t)info->st_size > 536870912ULL) return -1;
    size = (size_t)info->st_size; bytes = malloc(size == 0U ? 1U : size);
    if (bytes == NULL) return -1;
    while (offset < size) {
        amount = pread(fd, bytes + offset, size - offset, (off_t)offset);
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    result = plamen_broker_v2_sha256(bytes, size, output) == 0 ? 0 : -1;
done:
    plamen_broker_v2_secure_zero(bytes, size); free(bytes); return result;
}

static int apple_payload_validate(
    const struct plamen_broker_v2_specialized_worker_fd *fd)
{
    struct stat info; uint8_t digest[32]; int valid = 0;
    if (fd == NULL || digest_zero(fd->payload_sha256)
        || fd->payload_entries > 65536ULL
        || fd->payload_bytes > 4294967296ULL) return 0;
    if (fd->kind == PLAMEN_BROKER_V2_WORKER_IMAGE_MEMBER)
        return fd->host_fd == -1 && fd->payload_entries == 1U
            && fd->payload_bytes > 0U;
    if (fstat(fd->host_fd, &info) != 0) return 0;
    memset(digest, 0, sizeof(digest));
    if (fd->kind == PLAMEN_BROKER_V2_WORKER_REGULAR_FILE) {
        valid = S_ISREG(info.st_mode) && info.st_size >= 0
            && fd->payload_entries == 1U
            && fd->payload_bytes == (uint64_t)info.st_size
            && file_sha256(fd->host_fd, &info, digest) == 0
            && constant_equal(digest, fd->payload_sha256, 32);
    } else if (fd->kind == PLAMEN_BROKER_V2_WORKER_DIRECTORY) {
        /* The provider's independently authenticated mount recensus supplies
         * the canonical tree payload tuple.  This layer still retains and
         * validates the exact physical directory FD and binds that tuple into
         * both the request digest and effects context. */
        valid = S_ISDIR(info.st_mode);
    }
    plamen_broker_v2_secure_zero(digest, sizeof(digest)); return valid;
}

static int worker_identity(const struct plamen_broker_v2_specialized_worker_fd *fd,
    uint8_t output[32])
{
    struct stat info; uint8_t content[32]; char content_hex[65];
    uint8_t raw[1024]; struct buffer out; const char *access, *kind, *role;
    if (fd == NULL || fd->role < 1U || fd->role > 8U
        || fstat(fd->host_fd, &info) != 0) return -1;
    role = role_names[fd->role - 1U];
    access = fd->access_mode == PLAMEN_BROKER_V2_FD_READ
        ? "READ_ONLY" : "READ_WRITE";
    kind = fd->kind == PLAMEN_BROKER_V2_WORKER_REGULAR_FILE
        ? "REGULAR_FILE" : "DIRECTORY";
    memset(content, 0, sizeof(content)); memset(content_hex, 0, sizeof(content_hex));
    memset(&out, 0, sizeof(out)); out.data = raw; out.capacity = sizeof(raw);
    if (fd->kind == PLAMEN_BROKER_V2_WORKER_REGULAR_FILE) {
        if (!S_ISREG(info.st_mode) || file_sha256(fd->host_fd, &info, content) != 0)
            return -1;
        hex32(content, content_hex);
        put(&out, "{\"access\":\"%s\",\"content_sha256\":\"%s\",", access, content_hex);
    } else {
        if (!S_ISDIR(info.st_mode)) return -1;
        put(&out, "{\"access\":\"%s\",\"content_sha256\":null,", access);
    }
    put(&out, "\"device\":%llu,\"fd\":%u,\"gid\":%llu,\"inode\":%llu,"
        "\"kind\":\"%s\",\"link_count\":%llu,\"mode\":%u,\"role\":\"%s\","
        "\"size\":%llu,\"uid\":%llu}",
        (unsigned long long)info.st_dev, fd->guest_fd,
        (unsigned long long)info.st_gid, (unsigned long long)info.st_ino,
        kind, (unsigned long long)info.st_nlink,
        (unsigned int)(info.st_mode & 07777U), role,
        (unsigned long long)info.st_size, (unsigned long long)info.st_uid);
    plamen_broker_v2_secure_zero(content, sizeof(content));
    if (out.failed || plamen_broker_v2_sha256(raw, out.size, output) != 0) return -1;
    return 0;
}

static int snapshot_directory_source_policy(const struct json_node *root,
    const char *tool_anchor_id)
{
    static const char *const mount_keys[] = {
        "guest_path", "mode", "mount_id", "source_sha256"
    };
    static const char *const mount_ids[] = {
        "analysis-input", "project", "scratch", "state"
    };
    static const char *const guest_paths[] = {
        "/workspace/source", "/workspace/project", "/workspace/scratch",
        "/workspace/state"
    };
    static const char *const modes[] = {
        "READ_ONLY", "READ_ONLY", "READ_WRITE_EXCLUSIVE",
        "READ_WRITE_EXCLUSIVE"
    };
    struct json_node *source, *mounts, *row, *descriptor_node, *mount_node;
    uint8_t descriptor_sha[32], mount_sha[32]; size_t index;
    memset(descriptor_sha, 0, sizeof(descriptor_sha));
    memset(mount_sha, 0, sizeof(mount_sha));
    if (root == NULL || tool_anchor_id == NULL
        || (strcmp(tool_anchor_id, "forge") != 0
            && strcmp(tool_anchor_id, "opengrep") != 0
            && strcmp(tool_anchor_id, "slither") != 0
            && strcmp(tool_anchor_id, "solc") != 0)
        || (source = object_get(root, "source_descriptor")) == NULL
        || source->kind != J_OBJECT
        || !string_is(object_get(source, "kind"), "directory")
        || (descriptor_node = object_get(source, "descriptor_sha256")) == NULL
        || decode_hex32(descriptor_node, descriptor_sha) != 0
        || (mounts = object_get(root, "mounts")) == NULL
        || mounts->kind != J_ARRAY || mounts->count != 4U)
        goto failed;
    for (index = 0U; index < 4U; ++index) {
        row = mounts->items[index];
        if (!object_keys(row, mount_keys, 4U)
            || !string_is(object_get(row, "mount_id"), mount_ids[index])
            || !string_is(object_get(row, "guest_path"), guest_paths[index])
            || !string_is(object_get(row, "mode"), modes[index])
            || (mount_node = object_get(row, "source_sha256")) == NULL
            || decode_hex32(mount_node, mount_sha) != 0
            || (index == 0U
                && !constant_equal(mount_sha, descriptor_sha, 32U)))
            goto failed;
    }
    memset(descriptor_sha, 0, sizeof(descriptor_sha));
    memset(mount_sha, 0, sizeof(mount_sha));
    return 0;
failed:
    memset(descriptor_sha, 0, sizeof(descriptor_sha));
    memset(mount_sha, 0, sizeof(mount_sha));
    return -1;
}

static int payload_policy(const struct plamen_broker_v2_tool_effect_plan_view *view,
    const char **operation, const char *tool_anchor_id)
{
    struct json_node *root = NULL, *schema, *mode, *method_operation;
    size_t json_size;
    int result = -1;
    if (view == NULL || view->payload == NULL || view->payload_size == 0U
        || view->payload_size > PLAMEN_BROKER_V2_SPECIALIZED_WORKER_REQUEST_MAX)
        return -1;
    json_size = view->payload_size;
    if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER) {
        if (json_size < 3U || view->payload[json_size - 1U] != '\n'
            || view->payload[json_size - 2U] == '\n') return -1;
        --json_size;
    }
    root = json_parse(view->payload, json_size);
    if (root == NULL || root->kind != J_OBJECT) goto done;
    schema = object_get(root, "schema");
    if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        && view->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE) {
        method_operation = object_get(root, "operation");
        mode = object_get(root, "network_mode");
        if (!string_is(schema, "plamen.js-dependency-native-request.v2")
            || method_operation == NULL || method_operation->kind != J_STRING
            || !js_operation_name(method_operation->string)
            || (strcmp(method_operation->string, "ONLINE_INSTALL") == 0
                ? !string_is(mode, "VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST")
                : !string_is(mode, "NO_NETWORK"))
            || (tool_anchor_id != NULL
                && strcmp(tool_anchor_id, "js-python") != 0)) goto done;
        *operation = strcmp(method_operation->string, "PREPARE_TOOLCHAIN") == 0
            ? "PREPARE_TOOLCHAIN"
            : strcmp(method_operation->string, "ONLINE_INSTALL") == 0
            ? "ONLINE_INSTALL"
            : strcmp(method_operation->string, "CACHE_HANDOFF") == 0
            ? "CACHE_HANDOFF" : "OFFLINE_REPLAY";
    } else if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM
        && view->method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE) {
        if (!string_is(schema, "plamen.managed-evm-python-native-plan.v1")
            || (tool_anchor_id != NULL
                && strcmp(tool_anchor_id, "managed-python") != 0)) goto done;
        *operation = "MANAGED_EVM_EXECUTE";
    } else if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        && view->method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE) {
        mode = object_get(root, "egress_policy");
        if (!string_is(schema, "plamen.snapshot-bound-tool-execution-request.v3")
            || !string_is(mode, "DENY_ALL")
            || (tool_anchor_id != NULL
                && (!string_is(object_get(root, "tool_id"), tool_anchor_id)
                    || snapshot_directory_source_policy(root,
                        tool_anchor_id) != 0))) goto done;
        *operation = "SNAPSHOT_TOOL_EXECUTE";
    } else if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
        && view->method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT) {
        if (!string_is(schema,
                "plamen.evm-analysis-projection-native-request.v1")
            || (tool_anchor_id != NULL
                && strcmp(tool_anchor_id, "js-python") != 0)) goto done;
        *operation = "EVM_PROJECTION_COMMIT";
    } else goto done;
    result = 0;
done:
    json_destroy(root); return result;
}

int
plamen_broker_v2_specialized_worker_tool_anchor_id(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    char tool_anchor_id[32])
{
    struct json_node *root = NULL, *node;
    const char *anchor = NULL, *operation = NULL, *guest_path = NULL;
    size_t json_size, anchor_size;
    int result = -1;
    if (tool_anchor_id != NULL) memset(tool_anchor_id, 0, 32U);
    if (view == NULL || tool_anchor_id == NULL || view->payload == NULL
        || view->payload_size < 2U) return -1;
    json_size = view->payload_size;
    if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER) {
        if (json_size < 3U || view->payload[json_size - 1U] != '\n')
            return -1;
        --json_size;
    }
    root = json_parse(view->payload, json_size);
    if (root == NULL || root->kind != J_OBJECT) goto done;
    if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        && view->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE)
        anchor = "js-python";
    else if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM
        && view->method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE)
        anchor = "managed-python";
    else if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
        && view->method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT)
        anchor = "js-python";
    else if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        && view->method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE) {
        node = object_get(root, "tool_id");
        if (node == NULL || node->kind != J_STRING) goto done;
        anchor = node->string;
    } else goto done;
    anchor_size = strlen(anchor);
    if (anchor_size == 0U || anchor_size >= 32U
        || !safe_ascii(anchor, 31U, 0)
        || payload_policy(view, &operation, anchor) != 0
        || plamen_broker_v2_specialized_worker_tool_anchor_path(view->lane,
            view->method, anchor, &guest_path) != 0 || guest_path == NULL)
        goto done;
    memcpy(tool_anchor_id, anchor, anchor_size + 1U);
    result = 0;
done:
    json_destroy(root);
    if (result != 0) memset(tool_anchor_id, 0, 32U);
    return result;
}

static int roster_validate(const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_fd *fds, size_t fd_count,
    const char *operation, uint16_t provider_mode,
    uint8_t present[8], uint8_t identities[8][32])
{
    size_t i, j; uint8_t matched[PLAMEN_BROKER_V2_MAX_FDS];
    int snapshot = strcmp(operation, "SNAPSHOT_TOOL_EXECUTE") == 0;
    int projection = strcmp(operation, "EVM_PROJECTION_COMMIT") == 0;
    int js = js_operation_name(operation);
    int managed = strcmp(operation, "MANAGED_EVM_EXECUTE") == 0;
    memset(present, 0, 8); memset(identities, 0, 8U * 32U);
    memset(matched, 0, sizeof(matched));
    if (fds == NULL || fd_count != ((snapshot || projection) ? 5U
            : (js && provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER)
                ? 5U : 8U)
        || view->fd_count > PLAMEN_BROKER_V2_MAX_FDS
        || (view->fd_count > 0U
            && (view->fds == NULL || view->descriptors == NULL))) return -1;
    for (i = 0; i < fd_count; ++i) {
        const struct plamen_broker_v2_specialized_worker_fd *item = &fds[i];
        size_t index;
        int image_member = provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
            && item->role == PLAMEN_BROKER_V2_WORKER_TOOL
            && item->kind == PLAMEN_BROKER_V2_WORKER_IMAGE_MEMBER;
        if (item->version != PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_CODEC_VERSION
            || item->role < 1U || item->role > 8U
            || (!image_member && item->host_fd < 0)
            || (provider_mode == PLAMEN_BROKER_V2_WORKER_RETAINED_FD
                && (item->guest_fd < 3U || item->guest_fd > 1048575U))
            || (provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
                && item->guest_fd != 0U)
            || item->purpose == 0U || item->target == 0U
            || (item->provenance != PLAMEN_BROKER_V2_WORKER_FD_FROM_PLAN
                && item->provenance != PLAMEN_BROKER_V2_WORKER_FD_FROM_AUTHENTICATED_CONTEXT)
            || (!image_member && digest_zero(item->native_identity))
            || (image_member && (!digest_zero(item->native_identity)
                || item->host_fd != -1 || item->payload_entries != 1U
                || item->payload_bytes == 0U || digest_zero(item->payload_sha256)
                || item->provenance != PLAMEN_BROKER_V2_WORKER_FD_FROM_AUTHENTICATED_CONTEXT)))
            return -1;
        index = item->role - 1U;
        if (present[index] || (!image_member
            && !native_identity(item->host_fd, item->native_identity))) return -1;
        for (j = 0; j < i; ++j)
            if ((!image_member && fds[j].host_fd == item->host_fd)
                || (provider_mode == PLAMEN_BROKER_V2_WORKER_RETAINED_FD
                    && fds[j].guest_fd == item->guest_fd)
                || (!image_member && constant_equal(fds[j].native_identity,
                    item->native_identity, 32)))
                return -1;
        if (index == 1U || index == 2U || index == 4U || index == 6U) {
            if (item->access_mode != PLAMEN_BROKER_V2_FD_READ_WRITE
                || item->kind != PLAMEN_BROKER_V2_WORKER_DIRECTORY) return -1;
        } else if (item->access_mode != PLAMEN_BROKER_V2_FD_READ) return -1;
        if ((index == 3U || index == 4U || index == 6U)
            && item->kind != PLAMEN_BROKER_V2_WORKER_DIRECTORY) return -1;
        if (js && (index == 0U || index == 5U)
            && item->kind != PLAMEN_BROKER_V2_WORKER_DIRECTORY) return -1;
        if ((snapshot || projection) && index == 5U
            && item->kind != PLAMEN_BROKER_V2_WORKER_DIRECTORY) return -1;
        if (managed && (index == 0U || index == 5U)
            && item->kind != PLAMEN_BROKER_V2_WORKER_REGULAR_FILE) return -1;
        if (index == 7U && item->kind != PLAMEN_BROKER_V2_WORKER_REGULAR_FILE
            && item->kind != PLAMEN_BROKER_V2_WORKER_IMAGE_MEMBER)
            return -1;
        if (item->kind != PLAMEN_BROKER_V2_WORKER_REGULAR_FILE
            && item->kind != PLAMEN_BROKER_V2_WORKER_DIRECTORY
            && item->kind != PLAMEN_BROKER_V2_WORKER_IMAGE_MEMBER) return -1;
        if (provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
            && !apple_payload_validate(item)) return -1;
        if (item->provenance == PLAMEN_BROKER_V2_WORKER_FD_FROM_PLAN) {
            int found = 0;
            for (j = 0; j < view->fd_count; ++j) {
                if (!matched[j] && view->fds[j] == item->host_fd
                    && view->descriptors[j].purpose == item->purpose
                    && view->descriptors[j].target == item->target
                    && view->descriptors[j].access_mode == item->access_mode
                    && constant_equal(view->descriptors[j].identity,
                        item->native_identity, 32)) {
                    matched[j] = 1; found = 1; break;
                }
            }
            if (!found) return -1;
        }
        if (image_member) memcpy(identities[index], item->payload_sha256, 32);
        else if (worker_identity(item, identities[index]) != 0) return -1;
        present[index] = 1;
    }
    for (i = 0; i < view->fd_count; ++i) if (!matched[i]) return -1;
    for (i = 0; i < 8U; ++i) {
        int required = js
            ? (provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
                ? (i == 0U || i == 4U || i == 5U || i == 6U || i == 7U)
                : 1)
            : (snapshot || projection)
                ? (i == 3U || i == 4U || i == 5U || i == 6U || i == 7U)
            : 1;
        if (required && !present[i]) return -1;
        if (!required && present[i]) return -1;
    }
    return 0;
}

static int launch_validate(const struct plamen_broker_v2_specialized_worker_launch *launch,
    const uint8_t present[8], const char *operation)
{
    static const char *const managed_argv[] = { "@fd:tool", "-I", "-S", "-B",
        "@image:managed-provisioner", "--policy", "@fd:source",
        "--generation", "@fd:generation", "--cache", "@fd:cache",
        "--project-root", "@fd:project", "--acquisition-receipt",
        "@fd:acquisition", "--offline" };
    static const char *const js_argv[] = { "@fd:tool", "-I", "-S", "-B",
        "@image:js-offline-materializer", NULL, "--acquisition-root",
        "@fd:acquisition", "--source-root", "@fd:source", "--scratch-root",
        "@fd:scratch", "--state-root", "@fd:state" };
    uint8_t slither_environment[32]; size_t i; const char *prior = "";
    int slither, projection;
    memset(slither_environment, 0, sizeof(slither_environment));
    if (launch == NULL || launch->version != 1U
        || (launch->provider_mode != PLAMEN_BROKER_V2_WORKER_RETAINED_FD
            && launch->provider_mode != PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER)
        || digest_zero(launch->worker_runtime_sha256)) return -1;
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && (!safe_ascii(launch->tool_anchor_id, 31U, 0)
            || digest_zero(launch->oci_image_sha256)
            || digest_zero(launch->runtime_manifest_sha256)
            || launch->worker_runtime_size == 0U
            || digest_zero(launch->tool_image_member_sha256)
            || launch->tool_image_member_size == 0U)) return -1;
    slither = operation != NULL
        && strcmp(operation, "SNAPSHOT_TOOL_EXECUTE") == 0
        && launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && strcmp(launch->tool_anchor_id, "slither") == 0;
    projection = operation != NULL
        && strcmp(operation, "EVM_PROJECTION_COMMIT") == 0
        && launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER;
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && operation != NULL && strcmp(operation, "MANAGED_EVM_EXECUTE") == 0) {
        if (digest_zero(launch->managed_provisioner_sha256)
            || launch->managed_provisioner_size == 0U
            || !digest_zero(launch->js_offline_materializer_sha256)
            || launch->js_offline_materializer_size != 0U) return -1;
    } else if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && js_operation_name(operation)) {
        if (digest_zero(launch->js_offline_materializer_sha256)
            || launch->js_offline_materializer_size == 0U
            || !digest_zero(launch->managed_provisioner_sha256)
            || launch->managed_provisioner_size != 0U) return -1;
    } else if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && (!digest_zero(launch->managed_provisioner_sha256)
            || launch->managed_provisioner_size != 0U
            || !digest_zero(launch->js_offline_materializer_sha256)
            || launch->js_offline_materializer_size != 0U)) return -1;
    if (slither
        && (digest_zero(launch->slither_forge_sha256)
            || launch->slither_forge_size == 0U
            || digest_zero(launch->slither_solc_sha256)
            || launch->slither_solc_size == 0U
            || digest_zero(launch->slither_python_sha256)
            || launch->slither_python_size == 0U
            || plamen_broker_v2_specialized_slither_internal_environment_sha256(
                slither_environment) != 0
            || !constant_equal(slither_environment,
                launch->slither_internal_environment_sha256, 32U))) {
        memset(slither_environment, 0, sizeof(slither_environment));
        return -1;
    }
    if (projection && (digest_zero(launch->slither_solc_sha256)
            || launch->slither_solc_size == 0U)) {
        memset(slither_environment, 0, sizeof(slither_environment));
        return -1;
    }
    memset(slither_environment, 0, sizeof(slither_environment));
    if (!safe_request_id(launch->request_id)) return -2;
    if (launch->argc == 0U || launch->argc > 1024U || launch->argv == NULL
        || launch->argv[0] == NULL
        || strcmp(launch->argv[0], "@fd:tool") != 0) return -3;
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && operation != NULL && strcmp(operation, "MANAGED_EVM_EXECUTE") == 0
        && (launch->argc != sizeof(managed_argv) / sizeof(managed_argv[0])
            || launch->environment_count != 0U
            || launch->cwd_role != PLAMEN_BROKER_V2_WORKER_PROJECT
            || launch->cwd_relative == NULL
            || strcmp(launch->cwd_relative, ".") != 0)) return -3;
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && js_operation_name(operation)
        && (launch->argc != sizeof(js_argv) / sizeof(js_argv[0])
            || launch->environment_count != 0U
            || launch->cwd_role != PLAMEN_BROKER_V2_WORKER_SCRATCH
            || launch->cwd_relative == NULL
            || strcmp(launch->cwd_relative, ".") != 0)) return -3;
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && operation != NULL && strcmp(operation, "EVM_PROJECTION_COMMIT") == 0
        && (launch->argc != 1U || launch->environment_count != 0U
            || launch->cwd_role != PLAMEN_BROKER_V2_WORKER_SCRATCH
            || launch->cwd_relative == NULL
            || strcmp(launch->cwd_relative, ".") != 0)) return -3;
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && operation != NULL && strcmp(operation, "MANAGED_EVM_EXECUTE") == 0)
        for (i = 0; i < sizeof(managed_argv) / sizeof(managed_argv[0]); ++i)
            if (launch->argv[i] == NULL
                || strcmp(launch->argv[i], managed_argv[i]) != 0) return -3;
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && js_operation_name(operation))
        for (i = 0; i < sizeof(js_argv) / sizeof(js_argv[0]); ++i)
            if (launch->argv[i] == NULL
                || strcmp(launch->argv[i], i == 5U
                    ? js_operation_subcommand(operation) : js_argv[i]) != 0)
                return -3;
    if (launch->environment_count > 128U
        || (launch->environment_count > 0U && launch->environment == NULL)) return -4;
    if (launch->cwd_role < 1U || launch->cwd_role > 8U
        || !present[launch->cwd_role - 1U]
        || !canonical_relative_path(launch->cwd_relative, 1)) return -5;
    for (i = 0; i < launch->argc; ++i)
        if (!symbolic_token(launch->argv[i], present)) return -6;
    for (i = 0; i < launch->environment_count; ++i) {
        const char *name = launch->environment[i].name;
        if (!safe_env_name(name) || strcmp(name, prior) <= 0
            || denied_env(name) || strchr(name, '=') != NULL
            || !symbolic_token(launch->environment[i].value, present)) return -7;
        prior = name;
    }
    return launch->limits.duration_ms >= 1U && launch->limits.duration_ms <= 1800000ULL
        && launch->limits.memory_bytes >= 1U && launch->limits.memory_bytes <= 8589934592ULL
        && launch->limits.open_fds >= (launch->provider_mode
            == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER ? 19U : 8U)
        && launch->limits.open_fds <= 64U
        && launch->limits.output_bytes >= 1U && launch->limits.output_bytes <= 4294967296ULL
        && launch->limits.output_files >= 1U && launch->limits.output_files <= 65536U
        && launch->limits.stderr_bytes >= 1U && launch->limits.stderr_bytes <= 2097152ULL
        && launch->limits.stdout_bytes >= 1U && launch->limits.stdout_bytes <= 8388608ULL ? 0 : -8;
}

static void put_string(struct buffer *out, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;
    put(out, "\"");
    while (!out->failed && *cursor != 0) {
        if (*cursor == '"' || *cursor == '\\') put(out, "\\%c", *cursor);
        else if (*cursor == '\b') put(out, "\\b");
        else if (*cursor == '\f') put(out, "\\f");
        else if (*cursor == '\n') put(out, "\\n");
        else if (*cursor == '\r') put(out, "\\r");
        else if (*cursor == '\t') put(out, "\\t");
        else put(out, "%c", *cursor);
        ++cursor;
    }
    put(out, "\"");
}

static void put_ascii_bytes_string(struct buffer *out,
    const uint8_t *value, size_t size)
{
    size_t i;
    put(out, "\"");
    for (i = 0; !out->failed && i < size; ++i) {
        uint8_t current = value[i];
        if (current == '"' || current == '\\') put(out, "\\%c", current);
        else if (current == '\n') put(out, "\\n");
        else if (current < 0x20U || current >= 0x7fU) {
            out->failed = 1;
            break;
        } else put(out, "%c", current);
    }
    put(out, "\"");
}

static const struct plamen_broker_v2_specialized_worker_fd *fd_for_role(
    const struct plamen_broker_v2_specialized_worker_fd *fds, size_t count,
    size_t role)
{
    size_t i;
    for (i = 0; i < count; ++i) if (fds[i].role == role + 1U) return &fds[i];
    return NULL;
}

static void render_descriptors(struct buffer *out,
    const struct plamen_broker_v2_specialized_worker_fd *fds, size_t fd_count,
    const struct plamen_broker_v2_specialized_worker_launch *launch,
    const uint8_t present[8], const uint8_t identities[8][32])
{
    size_t i;
    const struct plamen_broker_v2_specialized_worker_fd *item;
    char hex[65];
    put(out, "{");
    for (i = 0; i < 8U; ++i) {
        if (i) put(out, ",");
        put(out, "\"%s\":", role_names[i]);
        if (!present[i]) { put(out, "null"); continue; }
        item = fd_for_role(fds, fd_count, i);
        hex32(identities[i], hex);
        if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER) {
            char payload_hex[65];
            hex32(item->payload_sha256, payload_hex);
            put(out, "{\"access\":\"%s\",\"kind\":\"%s\",\"payload_bytes\":%llu,"
                "\"payload_entries\":%llu,\"payload_sha256\":\"%s\"}",
                item->access_mode == PLAMEN_BROKER_V2_FD_READ ? "READ_ONLY" : "READ_WRITE",
                item->kind == PLAMEN_BROKER_V2_WORKER_REGULAR_FILE ? "REGULAR_FILE"
                    : item->kind == PLAMEN_BROKER_V2_WORKER_DIRECTORY ? "DIRECTORY" : "IMAGE_MEMBER",
                (unsigned long long)item->payload_bytes,
                (unsigned long long)item->payload_entries, payload_hex);
        } else {
            put(out, "{\"access\":\"%s\",\"fd\":%u,\"identity_sha256\":\"%s\",\"kind\":\"%s\"}",
                item->access_mode == PLAMEN_BROKER_V2_FD_READ ? "READ_ONLY" : "READ_WRITE",
                item->guest_fd, hex,
                item->kind == PLAMEN_BROKER_V2_WORKER_REGULAR_FILE ? "REGULAR_FILE" : "DIRECTORY");
        }
    }
    put(out, "}");
}

static void render_request(struct buffer *out,
    const struct plamen_broker_v2_specialized_worker_fd *fds, size_t fd_count,
    const struct plamen_broker_v2_specialized_worker_launch *launch,
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const char *operation, const uint8_t present[8], const uint8_t identities[8][32],
    const uint8_t effects[32], const uint8_t runtime_closure[32],
    const uint8_t method_payload_sha256[32],
    const uint8_t *request_digest)
{
    size_t i; char hex[65];
    put(out, "{\"argv\":[");
    for (i = 0; i < launch->argc; ++i) { if (i) put(out, ","); put_string(out, launch->argv[i]); }
    put(out, "],\"cwd\":{\"relative\":"); put_string(out, launch->cwd_relative);
    put(out, ",\"role\":\"%s\"},\"descriptors\":", role_names[launch->cwd_role - 1U]);
    render_descriptors(out, fds, fd_count, launch, present, identities);
    hex32(effects, hex); put(out, ",\"effects_binding_sha256\":\"%s\",\"environment\":[", hex);
    for (i = 0; i < launch->environment_count; ++i) {
        if (i) put(out, ","); put(out, "["); put_string(out, launch->environment[i].name);
        put(out, ","); put_string(out, launch->environment[i].value); put(out, "]");
    }
    put(out, "]");
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && js_operation_name(operation)) {
        hex32(launch->js_offline_materializer_sha256, hex);
        put(out, ",\"js_offline_materializer_sha256\":\"%s\","
            "\"js_offline_materializer_size\":%llu", hex,
            (unsigned long long)launch->js_offline_materializer_size);
    }
    put(out, ",\"limits\":{\"duration_ms\":%llu,\"memory_bytes\":%llu,\"open_fds\":%llu,"
        "\"output_bytes\":%llu,\"output_files\":%llu,\"stderr_bytes\":%llu,\"stdout_bytes\":%llu}",
        (unsigned long long)launch->limits.duration_ms,
        (unsigned long long)launch->limits.memory_bytes,
        (unsigned long long)launch->limits.open_fds,
        (unsigned long long)launch->limits.output_bytes,
        (unsigned long long)launch->limits.output_files,
        (unsigned long long)launch->limits.stderr_bytes,
        (unsigned long long)launch->limits.stdout_bytes);
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && strcmp(operation, "MANAGED_EVM_EXECUTE") == 0) {
        hex32(launch->managed_provisioner_sha256, hex);
        put(out, ",\"managed_provisioner_sha256\":\"%s\","
            "\"managed_provisioner_size\":%llu", hex,
            (unsigned long long)launch->managed_provisioner_size);
    }
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && (js_operation_name(operation)
            || strcmp(operation, "MANAGED_EVM_EXECUTE") == 0
            || strcmp(operation, "EVM_PROJECTION_COMMIT") == 0)) {
        hex32(method_payload_sha256, hex);
        put(out, ",\"method_payload_ascii\":");
        put_ascii_bytes_string(out, view->payload, view->payload_size);
        put(out, ",\"method_payload_sha256\":\"%s\"", hex);
    }
    put(out, ",\"network_mode\":\"%s\",\"operation\":\"%s\"",
        strcmp(operation, "ONLINE_INSTALL") == 0
            ? "VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST" : "DENY_ALL",
        operation);
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && strcmp(operation, "EVM_PROJECTION_COMMIT") == 0) {
        hex32(launch->slither_solc_sha256, hex);
        put(out, ",\"projection_solc_sha256\":\"%s\","
            "\"projection_solc_size\":%llu", hex,
            (unsigned long long)launch->slither_solc_size);
    }
    put(out, ",\"request_id\":");
    put_string(out, launch->request_id);
    if (request_digest != NULL) { hex32(request_digest, hex); put(out, ",\"request_sha256\":\"%s\"", hex); }
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER) {
        hex32(runtime_closure, hex);
        put(out, ",\"runtime_closure_sha256\":\"%s\"", hex);
    }
    hex32(launch->worker_runtime_sha256, hex);
    put(out, ",\"schema\":\"%s\"",
        launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
            ? "plamen.posix-specialized-tool-worker-apple-request.v2"
            : "plamen.posix-specialized-tool-worker-request.v1");
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && strcmp(operation, "SNAPSHOT_TOOL_EXECUTE") == 0
        && strcmp(launch->tool_anchor_id, "slither") == 0) {
        hex32(launch->slither_forge_sha256, hex);
        put(out, ",\"slither_forge_sha256\":\"%s\","
            "\"slither_forge_size\":%llu", hex,
            (unsigned long long)launch->slither_forge_size);
        hex32(launch->slither_internal_environment_sha256, hex);
        put(out, ",\"slither_internal_environment_sha256\":\"%s\"", hex);
        hex32(launch->slither_python_sha256, hex);
        put(out, ",\"slither_python_sha256\":\"%s\","
            "\"slither_python_size\":%llu", hex,
            (unsigned long long)launch->slither_python_size);
        hex32(launch->slither_solc_sha256, hex);
        put(out, ",\"slither_solc_sha256\":\"%s\","
            "\"slither_solc_size\":%llu", hex,
            (unsigned long long)launch->slither_solc_size);
    }
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER) {
        put(out, ",\"tool_anchor_id\":"); put_string(out, launch->tool_anchor_id);
    }
    /* Slither renders dependency identities after the first worker digest
     * conversion above.  Recompute here so the final field cannot alias the
     * last dependency digest held in the shared hex scratch buffer. */
    hex32(launch->worker_runtime_sha256, hex);
    put(out, ",\"worker_runtime_sha256\":\"%s\"}", hex);
}

int
plamen_broker_v2_specialized_worker_request_build(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_fd *fds, size_t fd_count,
    const struct plamen_broker_v2_specialized_worker_launch *launch,
    uint8_t *output, size_t capacity, size_t *output_size,
    struct plamen_broker_v2_specialized_worker_request_binding *binding)
{
    static const uint8_t domain[] = "PLAMEN-SPECIALIZED-WORKER-REQUEST-BINDING-V1\0";
    const char *operation = NULL; uint8_t present[8], identities[8][32];
    static const uint8_t closure_domain[] = "PLAMEN-APPLE-IMAGE-TOOL-CLOSURE-V1\0";
    static const char worker_path[] = "/opt/plamen/scripts/posix_specialized_tool_worker.py";
    static const char provisioner_path[] = "/usr/local/libexec/plamen-managed-evm-provisioner.py";
    static const char js_materializer_path[] = "/usr/local/libexec/plamen-js-offline-materializer.py";
    uint8_t payload_sha[32], preimage[640], closure_preimage[1024];
    uint8_t runtime_closure[32], unsigned_raw[1048576];
    uint8_t descriptor_raw[8192], apple_mount_payload[32];
    struct buffer unsigned_out, final_out, descriptor_out; size_t i, offset = 0;
    size_t closure_size = 0; const char *anchor_path = NULL;
    const struct plamen_broker_v2_specialized_worker_fd *tool = NULL;
    int result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_INVALID;
    if (output_size != NULL) *output_size = 0;
    if (binding != NULL) memset(binding, 0, sizeof(*binding));
    if (view == NULL || launch == NULL || output == NULL || output_size == NULL
        || binding == NULL || capacity < 2U
        || view->version != PLAMEN_BROKER_V2_TOOL_EFFECT_PLAN_VERSION
        || digest_zero(view->request_sha256) || digest_zero(view->effects_context_sha256))
        goto done;
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
        && plamen_broker_v2_specialized_worker_tool_anchor_path(view->lane,
            view->method, launch->tool_anchor_id, &anchor_path) != 0) {
        result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_PAYLOAD; goto done;
    }
    if (payload_policy(view, &operation,
            launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER
                ? launch->tool_anchor_id : NULL) != 0) {
        result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_PAYLOAD; goto done;
    }
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_RETAINED_FD
        && strcmp(operation, "ONLINE_INSTALL") == 0) {
        result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_PAYLOAD; goto done;
    }
    if ((digest_zero(view->archive_root_identity_sha256)
            != digest_zero(view->archive_manifest_sha256))
        || (digest_zero(view->archive_root_identity_sha256)
            != digest_zero(view->archive_census_sha256))) {
        result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_ROSTER; goto done;
    }
    if (roster_validate(view, fds, fd_count, operation,
            launch->provider_mode, present, identities) != 0) {
        result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_ROSTER; goto done;
    }
    if (launch_validate(launch, present, operation) != 0) {
        result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_LAUNCH;
        goto done;
    }
    if (plamen_broker_v2_sha256(view->payload, view->payload_size, payload_sha) != 0) {
        result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_CRYPTO; goto done;
    }
    memset(runtime_closure, 0, sizeof(runtime_closure));
    memset(apple_mount_payload, 0, sizeof(apple_mount_payload));
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER) {
        size_t anchor_size = strlen(launch->tool_anchor_id);
        size_t path_size = strlen(anchor_path);
        size_t worker_path_size = strlen(worker_path);
        int managed = strcmp(operation, "MANAGED_EVM_EXECUTE") == 0;
        int js = js_operation_name(operation);
        const char *auxiliary_path = managed ? provisioner_path
            : js ? js_materializer_path : NULL;
        const uint8_t *auxiliary_sha = managed
            ? launch->managed_provisioner_sha256
            : js ? launch->js_offline_materializer_sha256 : NULL;
        uint64_t auxiliary_size = managed ? launch->managed_provisioner_size
            : js ? launch->js_offline_materializer_size : 0U;
        size_t auxiliary_path_size = auxiliary_path == NULL
            ? 0U : strlen(auxiliary_path);
        tool = fd_for_role(fds, fd_count, 7U);
        if (tool == NULL
            || !constant_equal(tool->payload_sha256,
                launch->tool_image_member_sha256, 32)
            || tool->payload_bytes != launch->tool_image_member_size
            || sizeof(closure_domain) + 64U + 2U
            + worker_path_size + 1U + 32U + 8U + anchor_size + 1U
            + path_size + 1U + 32U + 8U + (auxiliary_path != NULL
                ? auxiliary_path_size + 1U + 32U + 8U : 0U)
            > sizeof(closure_preimage)) {
            result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_INVALID; goto done;
        }
        memcpy(closure_preimage + closure_size, closure_domain,
            sizeof(closure_domain)); closure_size += sizeof(closure_domain);
        memcpy(closure_preimage + closure_size, launch->oci_image_sha256, 32);
        closure_size += 32U;
        memcpy(closure_preimage + closure_size, launch->runtime_manifest_sha256, 32);
        closure_size += 32U;
        closure_preimage[closure_size++] = (uint8_t)(view->method >> 8);
        closure_preimage[closure_size++] = (uint8_t)view->method;
        memcpy(closure_preimage + closure_size, worker_path, worker_path_size + 1U);
        closure_size += worker_path_size + 1U;
        memcpy(closure_preimage + closure_size, launch->worker_runtime_sha256, 32);
        closure_size += 32U;
        for (i = 0; i < 8U; ++i)
            closure_preimage[closure_size++] =
                (uint8_t)(launch->worker_runtime_size >> ((7U - i) * 8U));
        memcpy(closure_preimage + closure_size, launch->tool_anchor_id, anchor_size + 1U);
        closure_size += anchor_size + 1U;
        memcpy(closure_preimage + closure_size, anchor_path, path_size + 1U);
        closure_size += path_size + 1U;
        memcpy(closure_preimage + closure_size, tool->payload_sha256, 32);
        closure_size += 32U;
        for (i = 0; i < 8U; ++i)
            closure_preimage[closure_size++] =
                (uint8_t)(tool->payload_bytes >> ((7U - i) * 8U));
        if (auxiliary_path != NULL) {
            memcpy(closure_preimage + closure_size, auxiliary_path,
                auxiliary_path_size + 1U);
            closure_size += auxiliary_path_size + 1U;
            memcpy(closure_preimage + closure_size, auxiliary_sha, 32);
            closure_size += 32U;
            for (i = 0; i < 8U; ++i)
                closure_preimage[closure_size++] =
                    (uint8_t)(auxiliary_size >> ((7U - i) * 8U));
        }
        if (strcmp(operation, "SNAPSHOT_TOOL_EXECUTE") == 0
            && strcmp(launch->tool_anchor_id, "slither") == 0) {
            static const char *const dependency_paths[] = {
                "/usr/local/lib/plamen/toolchains/foundry/bin/forge",
                "/usr/local/lib/plamen/python/bin/python3.12",
                "/usr/local/lib/plamen/toolchains/solc-amd64/solc"
            };
            const uint8_t *const dependency_sha[] = {
                launch->slither_forge_sha256,
                launch->slither_python_sha256,
                launch->slither_solc_sha256
            };
            const uint64_t dependency_size[] = {
                launch->slither_forge_size,
                launch->slither_python_size,
                launch->slither_solc_size
            };
            for (i = 0U; i < 3U; ++i) {
                size_t byte, dependency_path_size = strlen(dependency_paths[i]);
                if (closure_size + dependency_path_size + 1U + 32U + 8U
                        > sizeof(closure_preimage)) {
                    result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_INVALID;
                    goto done;
                }
                memcpy(closure_preimage + closure_size, dependency_paths[i],
                    dependency_path_size + 1U);
                closure_size += dependency_path_size + 1U;
                memcpy(closure_preimage + closure_size, dependency_sha[i], 32U);
                closure_size += 32U;
                for (byte = 0U; byte < 8U; ++byte)
                    closure_preimage[closure_size++] = (uint8_t)
                        (dependency_size[i] >> ((7U - byte) * 8U));
            }
            if (closure_size + 32U > sizeof(closure_preimage)) {
                result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_INVALID;
                goto done;
            }
            memcpy(closure_preimage + closure_size,
                launch->slither_internal_environment_sha256, 32U);
            closure_size += 32U;
        }
        if (strcmp(operation, "EVM_PROJECTION_COMMIT") == 0) {
            static const char projection_solc_path[] =
                "/usr/local/lib/plamen/toolchains/solc-amd64/solc";
            size_t byte, dependency_path_size = strlen(projection_solc_path);
            if (digest_zero(launch->slither_solc_sha256)
                || launch->slither_solc_size == 0U
                || closure_size + dependency_path_size + 1U + 32U + 8U
                    > sizeof(closure_preimage)) {
                result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_INVALID;
                goto done;
            }
            memcpy(closure_preimage + closure_size, projection_solc_path,
                dependency_path_size + 1U);
            closure_size += dependency_path_size + 1U;
            memcpy(closure_preimage + closure_size,
                launch->slither_solc_sha256, 32U);
            closure_size += 32U;
            for (byte = 0U; byte < 8U; ++byte)
                closure_preimage[closure_size++] = (uint8_t)
                    (launch->slither_solc_size >> ((7U - byte) * 8U));
        }
        if (plamen_broker_v2_sha256(closure_preimage, closure_size,
                runtime_closure) != 0) {
            result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_CRYPTO; goto done;
        }
        memset(&descriptor_out, 0, sizeof(descriptor_out));
        descriptor_out.data = descriptor_raw;
        descriptor_out.capacity = sizeof(descriptor_raw);
        render_descriptors(&descriptor_out, fds, fd_count, launch, present,
            identities);
        if (descriptor_out.failed || plamen_broker_v2_sha256(descriptor_raw,
                descriptor_out.size, apple_mount_payload) != 0) {
            result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_CRYPTO; goto done;
        }
    }
    memcpy(preimage + offset, domain, sizeof(domain)); offset += sizeof(domain);
    preimage[offset++] = (uint8_t)(view->lane >> 8); preimage[offset++] = (uint8_t)view->lane;
    preimage[offset++] = (uint8_t)(view->method >> 8); preimage[offset++] = (uint8_t)view->method;
    memcpy(preimage + offset, view->request_sha256, 32); offset += 32;
    memcpy(preimage + offset, view->effects_context_sha256, 32); offset += 32;
    memcpy(preimage + offset, payload_sha, 32); offset += 32;
    memcpy(preimage + offset, launch->worker_runtime_sha256, 32); offset += 32;
    memcpy(preimage + offset, runtime_closure, 32); offset += 32;
    memcpy(preimage + offset, view->archive_root_identity_sha256, 32); offset += 32;
    memcpy(preimage + offset, view->archive_manifest_sha256, 32); offset += 32;
    memcpy(preimage + offset, view->archive_census_sha256, 32); offset += 32;
    for (i = 0; i < 8U; ++i) { memcpy(preimage + offset, identities[i], 32); offset += 32; }
    if (plamen_broker_v2_sha256(preimage, offset, binding->effects_binding_sha256) != 0)
        { result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_CRYPTO; goto done; }
    memset(&unsigned_out, 0, sizeof(unsigned_out)); unsigned_out.data = unsigned_raw;
    unsigned_out.capacity = sizeof(unsigned_raw);
    render_request(&unsigned_out, fds, fd_count, launch, view, operation,
        present, identities, binding->effects_binding_sha256, runtime_closure,
        payload_sha, NULL);
    if (unsigned_out.failed) { result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_OUTPUT; goto done; }
    if (plamen_broker_v2_sha256(unsigned_raw,
            unsigned_out.size, binding->worker_request_sha256) != 0) {
        result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_CRYPTO; goto done;
    }
    memset(&final_out, 0, sizeof(final_out)); final_out.data = output;
    final_out.capacity = capacity;
    render_request(&final_out, fds, fd_count, launch, view, operation, present,
        identities, binding->effects_binding_sha256, runtime_closure,
        payload_sha, binding->worker_request_sha256);
    if (final_out.failed || final_out.size > 1048576U) {
        result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_OUTPUT; goto done;
    }
    binding->version = 1U; binding->provider_mode = launch->provider_mode;
    binding->lane = view->lane; binding->method = view->method;
    memcpy(binding->operation, operation, strlen(operation) + 1U);
    memcpy(binding->request_id, launch->request_id, strlen(launch->request_id) + 1U);
    memcpy(binding->method_payload_sha256, payload_sha, 32);
    memcpy(binding->worker_runtime_sha256, launch->worker_runtime_sha256, 32);
    binding->worker_runtime_size = launch->worker_runtime_size;
    memcpy(binding->runtime_closure_sha256, runtime_closure, 32);
    memcpy(binding->apple_mount_payload_sha256, apple_mount_payload, 32);
    if (launch->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER) {
        memcpy(binding->tool_image_member_sha256, tool->payload_sha256, 32);
        binding->tool_image_member_size = tool->payload_bytes;
        memcpy(binding->tool_anchor_id, launch->tool_anchor_id,
            strlen(launch->tool_anchor_id) + 1U);
        if (strcmp(operation, "MANAGED_EVM_EXECUTE") == 0) {
            memcpy(binding->managed_provisioner_sha256,
                launch->managed_provisioner_sha256, 32);
            binding->managed_provisioner_size = launch->managed_provisioner_size;
        } else if (js_operation_name(operation)) {
            memcpy(binding->js_offline_materializer_sha256,
                launch->js_offline_materializer_sha256, 32);
            binding->js_offline_materializer_size =
                launch->js_offline_materializer_size;
        } else if (strcmp(operation, "SNAPSHOT_TOOL_EXECUTE") == 0
            && strcmp(launch->tool_anchor_id, "slither") == 0) {
            memcpy(binding->slither_forge_sha256,
                launch->slither_forge_sha256, 32U);
            binding->slither_forge_size = launch->slither_forge_size;
            memcpy(binding->slither_solc_sha256,
                launch->slither_solc_sha256, 32U);
            binding->slither_solc_size = launch->slither_solc_size;
            memcpy(binding->slither_python_sha256,
                launch->slither_python_sha256, 32U);
            binding->slither_python_size = launch->slither_python_size;
            memcpy(binding->slither_internal_environment_sha256,
                launch->slither_internal_environment_sha256, 32U);
        } else if (strcmp(operation, "EVM_PROJECTION_COMMIT") == 0) {
            memcpy(binding->slither_solc_sha256,
                launch->slither_solc_sha256, 32U);
            binding->slither_solc_size = launch->slither_solc_size;
        }
    }
    memcpy(binding->descriptor_identity_sha256, identities, sizeof(identities));
    memcpy(binding->role_present, present, sizeof(present)); binding->limits = launch->limits;
    *output_size = final_out.size; result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_OK;
done:
    if (result != 0 && binding != NULL) memset(binding, 0, sizeof(*binding));
    plamen_broker_v2_secure_zero(payload_sha, sizeof(payload_sha));
    plamen_broker_v2_secure_zero(preimage, sizeof(preimage));
    plamen_broker_v2_secure_zero(closure_preimage, sizeof(closure_preimage));
    plamen_broker_v2_secure_zero(runtime_closure, sizeof(runtime_closure));
    plamen_broker_v2_secure_zero(apple_mount_payload, sizeof(apple_mount_payload));
    plamen_broker_v2_secure_zero(descriptor_raw, sizeof(descriptor_raw));
    plamen_broker_v2_secure_zero(unsigned_raw, sizeof(unsigned_raw));
    return result;
}

static int json_u64(const struct json_node *node, uint64_t maximum, uint64_t *value)
{
    if (node == NULL || node->kind != J_INTEGER || node->negative
        || node->integer > maximum || value == NULL) return -1;
    *value = node->integer; return 0;
}

static int derived_store(
    struct plamen_broker_v2_specialized_derived_launch *storage,
    const char *value, const char **result)
{
    size_t size;
    if (storage == NULL || value == NULL || result == NULL
        || (size = strlen(value) + 1U) > sizeof(storage->text) - storage->text_size)
        return -1;
    memcpy(storage->text + storage->text_size, value, size);
    *result = storage->text + storage->text_size;
    storage->text_size += size;
    return 0;
}

static int derived_guest_token(
    struct plamen_broker_v2_specialized_derived_launch *storage,
    const char *value, const char **result)
{
    static const struct { const char *guest; const char *symbolic; } roots[] = {
        { "/workspace/project", "@fd:project" },
        { "/workspace/scratch", "@fd:scratch" },
        { "/workspace/source", "@fd:source" },
        { "/workspace/state", "@fd:state" }
    };
    size_t i;
    if (value == NULL || result == NULL) return -1;
    for (i = 0; i < sizeof(roots) / sizeof(roots[0]); ++i) {
        size_t root_size = strlen(roots[i].guest);
        size_t prefix_size = strlen(roots[i].symbolic);
        size_t suffix_size;
        char *target;
        if (strncmp(value, roots[i].guest, root_size) != 0
            || (value[root_size] != '\0' && value[root_size] != '/')) continue;
        suffix_size = strlen(value + root_size);
        if (prefix_size + suffix_size + 1U
            > sizeof(storage->text) - storage->text_size) return -1;
        target = storage->text + storage->text_size;
        memcpy(target, roots[i].symbolic, prefix_size);
        memcpy(target + prefix_size, value + root_size, suffix_size + 1U);
        storage->text_size += prefix_size + suffix_size + 1U;
        *result = target;
        return 0;
    }
    if (value[0] == '/' || value[0] == '~' || strstr(value, "://") != NULL)
        return -1;
    return derived_store(storage, value, result);
}

int
plamen_broker_v2_specialized_worker_launch_derive_apple(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_apple_runtime *runtime,
    struct plamen_broker_v2_specialized_derived_launch *storage)
{
    static const char *const managed_argv[] = { "@fd:tool", "-I", "-S", "-B",
        "@image:managed-provisioner", "--policy", "@fd:source",
        "--generation", "@fd:generation", "--cache", "@fd:cache",
        "--project-root", "@fd:project", "--acquisition-receipt",
        "@fd:acquisition", "--offline" };
    static const char *const js_argv[] = { "@fd:tool", "-I", "-S", "-B",
        "@image:js-offline-materializer", NULL, "--acquisition-root",
        "@fd:acquisition", "--source-root", "@fd:source", "--scratch-root",
        "@fd:scratch", "--state-root", "@fd:state" };
    static const char *const limit_keys[] = { "duration_ms", "memory_bytes",
        "output_bytes", "output_files", "stderr_bytes", "stdout_bytes" };
    struct json_node *root = NULL, *node, *limits, *environment;
    const char *operation = NULL, *anchor = NULL, *cwd = NULL;
    const char *anchor_path = NULL;
    char request_id[65]; size_t i, json_size; uint64_t timeout;
    int managed, js, snapshot, projection;
    int result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_PAYLOAD;
    if (storage != NULL) memset(storage, 0, sizeof(*storage));
    if (view == NULL || runtime == NULL || storage == NULL
        || runtime->version != 1U || view->version != 1U
        || digest_zero(view->request_sha256)
        || digest_zero(runtime->oci_image_sha256)
        || digest_zero(runtime->runtime_manifest_sha256)
        || digest_zero(runtime->worker_runtime_sha256)
        || runtime->worker_runtime_size == 0U
        || digest_zero(runtime->tool_image_member_sha256)
        || runtime->tool_image_member_size == 0U) return result;
    json_size = view->payload_size;
    if (view->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER) {
        if (json_size < 3U || view->payload == NULL
            || view->payload[json_size - 1U] != '\n') return result;
        --json_size;
    }
    root = json_parse(view->payload, json_size);
    if (root == NULL || root->kind != J_OBJECT) goto done;
    managed = view->lane == PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM
        && view->method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE;
    js = view->lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        && view->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE;
    snapshot = view->lane == PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        && view->method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE;
    projection = view->lane == PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION
        && view->method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT;
    if (managed) anchor = "managed-python";
    else if (js) anchor = "js-python";
    else if (projection) anchor = "js-python";
    else if (snapshot) {
        node = object_get(root, "tool_id");
        if (node == NULL || node->kind != J_STRING) goto done;
        anchor = node->string;
    } else goto done;
    if (payload_policy(view, &operation, anchor) != 0
        || plamen_broker_v2_specialized_worker_tool_anchor_path(view->lane,
            view->method, anchor, &anchor_path) != 0 || anchor_path == NULL)
        goto done;
    if ((managed && (digest_zero(runtime->managed_provisioner_sha256)
            || runtime->managed_provisioner_size == 0U
            || !digest_zero(runtime->js_offline_materializer_sha256)
            || runtime->js_offline_materializer_size != 0U))
        || (js && (digest_zero(runtime->js_offline_materializer_sha256)
            || runtime->js_offline_materializer_size == 0U
            || !digest_zero(runtime->managed_provisioner_sha256)
            || runtime->managed_provisioner_size != 0U))
        || ((snapshot || projection)
            && (!digest_zero(runtime->managed_provisioner_sha256)
            || runtime->managed_provisioner_size != 0U
            || !digest_zero(runtime->js_offline_materializer_sha256)
            || runtime->js_offline_materializer_size != 0U))) goto done;
    hex32(view->request_sha256, request_id);
    if (derived_store(storage, request_id, &storage->launch.request_id) != 0
        || derived_store(storage, anchor, &storage->launch.tool_anchor_id) != 0)
        goto done;
    memcpy(storage->request_id, request_id, sizeof(request_id));
    memcpy(storage->tool_anchor_id, anchor, strlen(anchor) + 1U);
    storage->launch.version = 1U;
    storage->launch.provider_mode = PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER;
    memcpy(storage->launch.worker_runtime_sha256,
        runtime->worker_runtime_sha256, 32);
    storage->launch.worker_runtime_size = runtime->worker_runtime_size;
    memcpy(storage->launch.oci_image_sha256, runtime->oci_image_sha256, 32);
    memcpy(storage->launch.runtime_manifest_sha256,
        runtime->runtime_manifest_sha256, 32);
    memcpy(storage->launch.tool_image_member_sha256,
        runtime->tool_image_member_sha256, 32);
    storage->launch.tool_image_member_size = runtime->tool_image_member_size;
    memcpy(storage->launch.managed_provisioner_sha256,
        runtime->managed_provisioner_sha256, 32);
    storage->launch.managed_provisioner_size = runtime->managed_provisioner_size;
    memcpy(storage->launch.js_offline_materializer_sha256,
        runtime->js_offline_materializer_sha256, 32);
    storage->launch.js_offline_materializer_size =
        runtime->js_offline_materializer_size;
    memcpy(storage->launch.slither_forge_sha256,
        runtime->slither_forge_sha256, 32U);
    storage->launch.slither_forge_size = runtime->slither_forge_size;
    memcpy(storage->launch.slither_solc_sha256,
        runtime->slither_solc_sha256, 32U);
    storage->launch.slither_solc_size = runtime->slither_solc_size;
    memcpy(storage->launch.slither_python_sha256,
        runtime->slither_python_sha256, 32U);
    storage->launch.slither_python_size = runtime->slither_python_size;
    memcpy(storage->launch.slither_internal_environment_sha256,
        runtime->slither_internal_environment_sha256, 32U);
    storage->launch.argv = storage->argv;
    storage->launch.environment = storage->environment;
    storage->launch.limits.open_fds = 32U;
    if (projection) {
        if (derived_store(storage, "@fd:tool", &storage->argv[0]) != 0
            || derived_store(storage, ".", &storage->launch.cwd_relative) != 0)
            goto done;
        storage->launch.argc = 1U;
        storage->launch.environment_count = 0U;
        storage->launch.cwd_role = PLAMEN_BROKER_V2_WORKER_SCRATCH;
        storage->launch.limits.duration_ms = 1800000U;
        storage->launch.limits.memory_bytes = 8589934592ULL;
        storage->launch.limits.output_bytes = 4294967296ULL;
        storage->launch.limits.output_files = 65536U;
        storage->launch.limits.stderr_bytes = 2097152U;
        storage->launch.limits.stdout_bytes = 8388608U;
    } else if (managed || js) {
        const char *const *fixed = managed ? managed_argv : js_argv;
        size_t fixed_count = managed
            ? sizeof(managed_argv) / sizeof(managed_argv[0])
            : sizeof(js_argv) / sizeof(js_argv[0]);
        for (i = 0; i < fixed_count; ++i) {
            const char *value = js && i == 5U
                ? js_operation_subcommand(operation) : fixed[i];
            if (derived_store(storage, value, &storage->argv[i]) != 0) goto done;
        }
        storage->launch.argc = fixed_count;
        storage->launch.environment_count = 0U;
        storage->launch.cwd_role = managed ? PLAMEN_BROKER_V2_WORKER_PROJECT
            : PLAMEN_BROKER_V2_WORKER_SCRATCH;
        if (derived_store(storage, ".", &storage->launch.cwd_relative) != 0)
            goto done;
        if (js) {
            if (json_u64(object_get(root, "timeout_seconds"), 1800U,
                    &timeout) != 0 || timeout == 0U) goto done;
            storage->launch.limits.duration_ms = timeout * 1000U;
        } else storage->launch.limits.duration_ms = 1800000U;
        storage->launch.limits.memory_bytes = 8589934592ULL;
        storage->launch.limits.output_bytes = 4294967296ULL;
        storage->launch.limits.output_files = 65536U;
        storage->launch.limits.stderr_bytes = 2097152U;
        storage->launch.limits.stdout_bytes = 8388608U;
    } else {
        node = object_get(root, "argv");
        if (node == NULL || node->kind != J_ARRAY || node->count == 0U
            || node->count > PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ARG_MAX)
            goto done;
        for (i = 0; i < node->count; ++i) {
            const struct json_node *item = node->items[i];
            if (item == NULL || item->kind != J_STRING) goto done;
            if (i == 0U) {
                if (strcmp(item->string, anchor) != 0
                    || derived_store(storage, "@fd:tool",
                        &storage->argv[i]) != 0) goto done;
            } else if (derived_guest_token(storage, item->string,
                    &storage->argv[i]) != 0) goto done;
        }
        storage->launch.argc = node->count;
        environment = object_get(root, "environment");
        if (environment == NULL || environment->kind != J_OBJECT
            || environment->count > PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ENV_MAX)
            goto done;
        for (i = 0; i < environment->count; ++i) {
            node = environment->members[i].value;
            if (node == NULL || node->kind != J_STRING
                || derived_store(storage, environment->members[i].key,
                    &storage->environment[i].name) != 0
                || derived_guest_token(storage, node->string,
                    &storage->environment[i].value) != 0) goto done;
        }
        storage->launch.environment_count = environment->count;
        node = object_get(root, "cwd");
        if (node == NULL || node->kind != J_STRING
            || strncmp(node->string, "/workspace/project", 18U) != 0
            || (node->string[18] != '\0' && node->string[18] != '/')) goto done;
        cwd = node->string + 18U;
        if (*cwd == '/') ++cwd;
        if (*cwd == '\0') cwd = ".";
        storage->launch.cwd_role = PLAMEN_BROKER_V2_WORKER_PROJECT;
        if (derived_store(storage, cwd, &storage->launch.cwd_relative) != 0)
            goto done;
        limits = object_get(root, "limits");
        if (!object_keys(limits, limit_keys, 6U)
            || json_u64(object_get(limits, "duration_ms"), 1800000U,
                &storage->launch.limits.duration_ms) != 0
            || json_u64(object_get(limits, "memory_bytes"), 8589934592ULL,
                &storage->launch.limits.memory_bytes) != 0
            || json_u64(object_get(limits, "output_bytes"), 4294967296ULL,
                &storage->launch.limits.output_bytes) != 0
            || json_u64(object_get(limits, "output_files"), 65536U,
                &storage->launch.limits.output_files) != 0
            || json_u64(object_get(limits, "stderr_bytes"), 2097152U,
                &storage->launch.limits.stderr_bytes) != 0
            || json_u64(object_get(limits, "stdout_bytes"), 8388608U,
                &storage->launch.limits.stdout_bytes) != 0) goto done;
    }
    result = PLAMEN_BROKER_V2_SPECIALIZED_CODEC_OK;
done:
    json_destroy(root);
    if (result != PLAMEN_BROKER_V2_SPECIALIZED_CODEC_OK)
        memset(storage, 0, sizeof(*storage));
    return result;
}

static int stream_parse(const struct json_node *node, uint64_t bound,
    uint64_t *observed, uint64_t *retained, uint8_t digest[32])
{
    static const char *const keys[] = { "observed_bytes", "retained_bytes", "sha256" };
    if (!object_keys(node, keys, 3U)
        || json_u64(object_get(node, "observed_bytes"), bound, observed) != 0
        || json_u64(object_get(node, "retained_bytes"), bound, retained) != 0
        || *retained > *observed || decode_hex32(object_get(node, "sha256"), digest) != 0)
        return -1;
    return 0;
}

static int descriptor_replay(const struct json_node *node,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    int post, uint8_t output[8][32])
{
    size_t i, expected = 0;
    if (node == NULL || node->kind != J_OBJECT) return -1;
    for (i = 0; i < 8U; ++i) expected += binding->role_present[i] != 0;
    if (node->count != expected) return -1;
    expected = 0;
    for (i = 0; i < 8U; ++i) {
        uint8_t digest[32];
        if (!binding->role_present[i]) continue;
        if (expected >= node->count || strcmp(node->members[expected].key, role_names[i]) != 0
            || decode_hex32(node->members[expected].value, digest) != 0) return -1;
        if (!post || i == 0U || i == 3U || i == 5U || i == 7U) {
            if (!constant_equal(digest, binding->descriptor_identity_sha256[i], 32))
                return -1;
        }
        if (post && output != NULL) memcpy(output[i], digest, 32);
        ++expected;
    }
    return 0;
}

static int descriptor_replay_apple(const struct json_node *node,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    uint8_t output[8][32])
{
    size_t i, expected = 0;
    if (node == NULL || node->kind != J_OBJECT || output == NULL) return -1;
    for (i = 0; i < 8U; ++i) expected += binding->role_present[i] != 0;
    if (node->count != expected) return -1;
    expected = 0;
    memset(output, 0, 8U * 32U);
    for (i = 0; i < 8U; ++i) {
        if (!binding->role_present[i]) continue;
        if (expected >= node->count
            || strcmp(node->members[expected].key, role_names[i]) != 0
            || decode_hex32(node->members[expected].value, output[i]) != 0)
            return -1;
        ++expected;
    }
    return 0;
}

int
plamen_broker_v2_specialized_worker_terminal_parse(const uint8_t *raw,
    size_t raw_size,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const struct plamen_broker_v2_specialized_worker_terminal_auth *auth,
    struct plamen_broker_v2_specialized_worker_terminal_observation *observed)
{
    static const uint8_t hmac_domain[] = "PLAMEN-SPECIALIZED-WORKER-TERMINAL-V1\0";
    static const char *const root_keys[] = { "descriptor_post", "descriptor_pre",
        "duration_ms", "effects_binding_sha256", "host_authority_required",
        "network", "operation", "output_manifest", "peak_memory_bytes",
        "process_group_kill_issued", "request_id", "request_sha256", "returncode",
        "schema", "status", "stderr", "stdout", "worker_runtime_sha256" };
    static const char *const apple_root_keys[] = { "apple_mount_payload_sha256",
        "descriptor_post", "descriptor_pre", "duration_ms", "effects_binding_sha256",
        "host_authority_required", "network", "operation", "output_manifest",
        "peak_memory_bytes", "process_group_kill_issued", "request_id",
        "request_sha256", "returncode", "runtime_closure_sha256", "schema",
        "status", "stderr", "stdout", "tool_anchor_id",
        "tool_image_member_sha256", "worker_runtime_sha256" };
    static const char *const apple_managed_root_keys[] = {
        "apple_mount_payload_sha256", "descriptor_post", "descriptor_pre",
        "duration_ms", "effects_binding_sha256", "host_authority_required",
        "managed_provisioner_sha256", "managed_provisioner_size",
        "method_payload_sha256", "network",
        "operation", "output_manifest", "peak_memory_bytes",
        "process_group_kill_issued", "request_id", "request_sha256", "returncode",
        "runtime_closure_sha256", "schema", "status", "stderr", "stdout",
        "tool_anchor_id", "tool_image_member_sha256", "worker_runtime_sha256" };
    static const char *const apple_js_root_keys[] = {
        "apple_mount_payload_sha256", "descriptor_post", "descriptor_pre",
        "duration_ms", "effects_binding_sha256", "host_authority_required",
        "js_offline_materializer_sha256", "js_offline_materializer_size",
        "method_payload_sha256", "network", "operation", "output_manifest", "peak_memory_bytes",
        "process_group_kill_issued", "request_id", "request_sha256", "returncode",
        "runtime_closure_sha256", "schema", "status", "stderr", "stdout",
        "tool_anchor_id", "tool_image_member_sha256", "worker_runtime_sha256" };
    static const char *const apple_slither_root_keys[] = {
        "apple_mount_payload_sha256", "descriptor_post", "descriptor_pre",
        "duration_ms", "effects_binding_sha256", "host_authority_required",
        "network", "operation", "output_manifest", "peak_memory_bytes",
        "process_group_kill_issued", "request_id", "request_sha256", "returncode",
        "runtime_closure_sha256", "schema", "slither_forge_sha256",
        "slither_forge_size", "slither_internal_environment_sha256",
        "slither_python_sha256", "slither_python_size", "slither_solc_sha256",
        "slither_solc_size", "status", "stderr", "stdout", "tool_anchor_id",
        "tool_image_member_sha256", "worker_runtime_sha256" };
    static const char *const apple_projection_root_keys[] = {
        "apple_mount_payload_sha256", "descriptor_post", "descriptor_pre",
        "duration_ms", "effects_binding_sha256", "host_authority_required",
        "method_payload_sha256", "network", "operation", "output_manifest",
        "peak_memory_bytes", "process_group_kill_issued",
        "projection_observation_sha256", "projection_solc_sha256",
        "projection_solc_size", "request_id", "request_sha256",
        "returncode", "runtime_closure_sha256", "schema", "status",
        "stderr", "stdout", "tool_anchor_id", "tool_image_member_sha256",
        "worker_runtime_sha256" };
    static const char *const network_keys[] = { "guest_observation", "mode", "observed_egress_sha256" };
    static const char *const manifest_keys[] = { "byte_count", "file_count", "sha256" };
    static const char *const authorities[] = { "HMAC_AUTHENTICATION", "MOUNT_RECENSUS",
        "NETWORK_DENIAL", "POPULATION_ZERO" };
    struct json_node *root = NULL, *node, *network, *manifest, *required;
    uint8_t digest[32], expected_hmac[32], empty_sha[32];
    uint8_t descriptor_pre[8][32];
    size_t i; uint64_t provisioner_size = 0;
    int result = -1, apple, managed, js, slither, projection;
    if (observed != NULL) memset(observed, 0, sizeof(*observed));
    if (raw == NULL || raw_size < 2U || raw_size > 2097152U
        || !terminal_canonical_octets(raw, raw_size) || binding == NULL
        || binding->version != 1U || auth == NULL || auth->version != 1U
        || digest_zero(auth->terminal_hmac_key) || digest_zero(auth->terminal_hmac_sha256)
        || observed == NULL
        || plamen_broker_v2_hmac_sha256(auth->terminal_hmac_key, hmac_domain,
            sizeof(hmac_domain), raw, raw_size, expected_hmac) != 0
        || !constant_equal(expected_hmac, auth->terminal_hmac_sha256, 32)) goto done;
    apple = binding->provider_mode == PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER;
    managed = strcmp(binding->operation, "MANAGED_EVM_EXECUTE") == 0;
    js = js_operation_name(binding->operation);
    if ((!apple && binding->provider_mode != PLAMEN_BROKER_V2_WORKER_RETAINED_FD)
        || (apple && (digest_zero(binding->runtime_closure_sha256)
            || digest_zero(binding->apple_mount_payload_sha256)
            || digest_zero(binding->tool_image_member_sha256)
            || binding->tool_image_member_size == 0U
            || !safe_ascii(binding->tool_anchor_id, 31U, 0)))
        || (apple && managed && (digest_zero(binding->managed_provisioner_sha256)
            || binding->managed_provisioner_size == 0U))
        || (apple && js && (digest_zero(binding->js_offline_materializer_sha256)
            || binding->js_offline_materializer_size == 0U))) goto done;
    slither = apple && strcmp(binding->operation, "SNAPSHOT_TOOL_EXECUTE") == 0
        && strcmp(binding->tool_anchor_id, "slither") == 0;
    projection = apple
        && strcmp(binding->operation, "EVM_PROJECTION_COMMIT") == 0;
    root = json_parse(raw, raw_size);
    if (!(apple
            ? object_keys(root, managed ? apple_managed_root_keys
                    : js ? apple_js_root_keys
                    : slither ? apple_slither_root_keys
                    : projection ? apple_projection_root_keys
                    : apple_root_keys,
                managed ? sizeof(apple_managed_root_keys) / sizeof(apple_managed_root_keys[0])
                    : js ? sizeof(apple_js_root_keys) / sizeof(apple_js_root_keys[0])
                    : slither ? sizeof(apple_slither_root_keys) / sizeof(apple_slither_root_keys[0])
                    : projection ? sizeof(apple_projection_root_keys) / sizeof(apple_projection_root_keys[0])
                    : sizeof(apple_root_keys) / sizeof(apple_root_keys[0]))
            : object_keys(root, root_keys, sizeof(root_keys) / sizeof(root_keys[0])))
        || !string_is(object_get(root, "schema"), apple
            ? "plamen.posix-specialized-tool-worker-apple-terminal.v2"
            : "plamen.posix-specialized-tool-worker-terminal.v1")
        || !string_is(object_get(root, "operation"), binding->operation)
        || !string_is(object_get(root, "request_id"), binding->request_id)
        || decode_hex32(object_get(root, "effects_binding_sha256"), digest) != 0
        || !constant_equal(digest, binding->effects_binding_sha256, 32)
        || decode_hex32(object_get(root, "request_sha256"), digest) != 0
        || !constant_equal(digest, binding->worker_request_sha256, 32)
        || decode_hex32(object_get(root, "worker_runtime_sha256"), digest) != 0
        || !constant_equal(digest, binding->worker_runtime_sha256, 32)) goto done;
    if (apple) {
        if (decode_hex32(object_get(root, "apple_mount_payload_sha256"), digest) != 0
            || !constant_equal(digest, binding->apple_mount_payload_sha256, 32)
            || decode_hex32(object_get(root, "runtime_closure_sha256"), digest) != 0
            || !constant_equal(digest, binding->runtime_closure_sha256, 32)
            || !string_is(object_get(root, "tool_anchor_id"), binding->tool_anchor_id)
            || decode_hex32(object_get(root, "tool_image_member_sha256"), digest) != 0
            || !constant_equal(digest, binding->tool_image_member_sha256, 32)
            || ((managed || js || projection)
                && (decode_hex32(object_get(root, "method_payload_sha256"),
                        digest) != 0
                    || !constant_equal(digest,
                        binding->method_payload_sha256, 32)))
            || (managed && (decode_hex32(
                    object_get(root, "managed_provisioner_sha256"), digest) != 0
                || !constant_equal(digest, binding->managed_provisioner_sha256, 32)
                || json_u64(object_get(root, "managed_provisioner_size"),
                    UINT64_MAX, &provisioner_size) != 0
                || provisioner_size != binding->managed_provisioner_size))
            || (js && (decode_hex32(
                    object_get(root, "js_offline_materializer_sha256"), digest) != 0
                || !constant_equal(digest,
                    binding->js_offline_materializer_sha256, 32)
                || json_u64(object_get(root, "js_offline_materializer_size"),
                    UINT64_MAX, &provisioner_size) != 0
                || provisioner_size != binding->js_offline_materializer_size))
            || (projection && (decode_hex32(object_get(root,
                    "projection_observation_sha256"),
                    observed->projection_observation_sha256) != 0
                || decode_hex32(object_get(root,
                    "projection_solc_sha256"), digest) != 0
                || !constant_equal(digest,
                    binding->slither_solc_sha256, 32U)
                || json_u64(object_get(root, "projection_solc_size"),
                    UINT64_MAX, &provisioner_size) != 0
                || provisioner_size != binding->slither_solc_size))
            || (slither && (decode_hex32(object_get(root,
                    "slither_forge_sha256"), digest) != 0
                || !constant_equal(digest, binding->slither_forge_sha256, 32U)
                || json_u64(object_get(root, "slither_forge_size"), UINT64_MAX,
                    &provisioner_size) != 0
                || provisioner_size != binding->slither_forge_size
                || decode_hex32(object_get(root,
                    "slither_internal_environment_sha256"), digest) != 0
                || !constant_equal(digest,
                    binding->slither_internal_environment_sha256, 32U)
                || decode_hex32(object_get(root,
                    "slither_python_sha256"), digest) != 0
                || !constant_equal(digest, binding->slither_python_sha256, 32U)
                || json_u64(object_get(root, "slither_python_size"), UINT64_MAX,
                    &provisioner_size) != 0
                || provisioner_size != binding->slither_python_size
                || decode_hex32(object_get(root,
                    "slither_solc_sha256"), digest) != 0
                || !constant_equal(digest, binding->slither_solc_sha256, 32U)
                || json_u64(object_get(root, "slither_solc_size"), UINT64_MAX,
                    &provisioner_size) != 0
                || provisioner_size != binding->slither_solc_size))
            || descriptor_replay_apple(object_get(root, "descriptor_pre"),
                binding, descriptor_pre) != 0
            || descriptor_replay_apple(object_get(root, "descriptor_post"),
                binding, observed->descriptor_post_sha256) != 0) goto done;
        for (i = 0; i < 8U; ++i)
            if (binding->role_present[i]
                && (i == 0U || i == 3U || i == 5U || i == 7U)
                && !constant_equal(descriptor_pre[i],
                    observed->descriptor_post_sha256[i], 32)) goto done;
    } else if (descriptor_replay(object_get(root, "descriptor_pre"), binding,
            0, NULL) != 0
        || descriptor_replay(object_get(root, "descriptor_post"), binding, 1,
            observed->descriptor_post_sha256) != 0) goto done;
    required = object_get(root, "host_authority_required");
    if (required == NULL || required->kind != J_ARRAY || required->count != 4U) goto done;
    for (i = 0; i < 4U; ++i) if (!string_is(required->items[i], authorities[i])) goto done;
    network = object_get(root, "network");
    if (!object_keys(network, network_keys, 3U)
        || !string_is(object_get(network, "guest_observation"), "NATIVE_PROVIDER_EVIDENCE_REQUIRED")
        || !string_is(object_get(network, "mode"), "DENY_ALL")
        || decode_hex32(object_get(network, "observed_egress_sha256"),
            observed->observed_egress_sha256) != 0
        || plamen_broker_v2_sha256("[]", 2U, empty_sha) != 0
        || !constant_equal(empty_sha, observed->observed_egress_sha256, 32)) goto done;
    node = object_get(root, "process_group_kill_issued");
    if (node == NULL || node->kind != J_BOOL
        || (projection ? node->boolean : !node->boolean)) goto done;
    if (json_u64(object_get(root, "duration_ms"), binding->limits.duration_ms,
            &observed->duration_ms) != 0
        || json_u64(object_get(root, "peak_memory_bytes"), binding->limits.memory_bytes,
            &observed->peak_memory_bytes) != 0
        || stream_parse(object_get(root, "stdout"), binding->limits.stdout_bytes,
            &observed->stdout_observed_bytes, &observed->stdout_retained_bytes,
            observed->stdout_sha256) != 0
        || stream_parse(object_get(root, "stderr"), binding->limits.stderr_bytes,
            &observed->stderr_observed_bytes, &observed->stderr_retained_bytes,
            observed->stderr_sha256) != 0) goto done;
    manifest = object_get(root, "output_manifest");
    if (!object_keys(manifest, manifest_keys, 3U)
        || json_u64(object_get(manifest, "byte_count"), binding->limits.output_bytes,
            &observed->output_bytes) != 0
        || json_u64(object_get(manifest, "file_count"), binding->limits.output_files,
            &observed->output_file_count) != 0
        || decode_hex32(object_get(manifest, "sha256"),
            observed->output_manifest_sha256) != 0) goto done;
    node = object_get(root, "returncode");
    if (node == NULL || node->kind != J_INTEGER || node->integer > INT32_MAX
        || (node->negative && node->integer > (uint64_t)INT32_MAX + 1U)) goto done;
    if (node->negative && node->integer == (uint64_t)INT32_MAX + 1U)
        observed->returncode = INT32_MIN;
    else
        observed->returncode = node->negative
            ? -(int32_t)node->integer : (int32_t)node->integer;
    node = object_get(root, "status");
    if (node == NULL || node->kind != J_STRING || strlen(node->string) >= sizeof(observed->status)
        || strcmp(node->string, "READ_ONLY_DESCRIPTOR_CHANGED") == 0) goto done;
    if ((strcmp(node->string, "COMPLETE") == 0 && observed->returncode != 0)
        || (strcmp(node->string, "FAILED") == 0 && observed->returncode == 0)
        || (strcmp(node->string, "COMPLETE") != 0 && strcmp(node->string, "FAILED") != 0
            && strcmp(node->string, "TIMED_OUT") != 0
            && strcmp(node->string, "OUTPUT_LIMIT_EXCEEDED") != 0)) goto done;
    memcpy(observed->status, node->string, strlen(node->string) + 1U);
    if (plamen_broker_v2_sha256(raw, raw_size, observed->terminal_sha256) != 0) goto done;
    memcpy(observed->terminal_hmac_sha256, auth->terminal_hmac_sha256, 32);
    observed->version = 1U; result = 0;
done:
    json_destroy(root);
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    plamen_broker_v2_secure_zero(expected_hmac, sizeof(expected_hmac));
    plamen_broker_v2_secure_zero(empty_sha, sizeof(empty_sha));
    plamen_broker_v2_secure_zero(descriptor_pre, sizeof(descriptor_pre));
    if (result != 0 && observed != NULL) memset(observed, 0, sizeof(*observed));
    return result;
}

static int projection_closure_parse(const struct json_node *node,
    uint8_t closure[32], uint64_t *files, uint64_t *directories,
    uint64_t *bytes)
{
    static const char *const keys[] = { "byte_count", "closure_sha256",
        "directory_count", "entry_stream_sha256", "file_count",
        "schema_version" };
    uint8_t entry_stream[32];
    if (!object_keys(node, keys, sizeof(keys) / sizeof(keys[0]))
        || !string_is(object_get(node, "schema_version"),
            "plamen.evm_dependency_content_closure.v1")
        || decode_hex32(object_get(node, "closure_sha256"), closure) != 0
        || decode_hex32(object_get(node, "entry_stream_sha256"),
            entry_stream) != 0
        || json_u64(object_get(node, "file_count"), 65536U, files) != 0
        || json_u64(object_get(node, "directory_count"), 65536U,
            directories) != 0
        || json_u64(object_get(node, "byte_count"), UINT64_C(4294967296),
            bytes) != 0)
        return -1;
    memset(entry_stream, 0, sizeof(entry_stream));
    return 0;
}

int
plamen_broker_v2_specialized_projection_observation_parse(
    const uint8_t *raw, size_t raw_size,
    struct plamen_broker_v2_specialized_projection_observation *output)
{
    static const char *const keys[] = { "analysis_workspace",
        "dependency_materialization_receipt_sha256",
        "js_lock_selection_sha256", "materialization_lineage_byte_count",
        "materialization_lineage_sha256", "materialized_node_modules",
        "native_materialization_request_sha256",
        "original_source_scope_sha256", "schema", "source_copy",
        "workspace_relative_path" };
    struct json_node *root = NULL;
    int result = -1;
    if (output != NULL) memset(output, 0, sizeof(*output));
    if (raw == NULL || raw_size == 0U || raw_size > 1048576U
        || output == NULL || !terminal_canonical_octets(raw, raw_size))
        return -1;
    root = json_parse(raw, raw_size);
    if (!object_keys(root, keys, sizeof(keys) / sizeof(keys[0]))
        || !string_is(object_get(root, "schema"),
            "plamen.evm-analysis-projection-worker-observation.v1")
        || !string_is(object_get(root, "workspace_relative_path"),
            "analysis-workspace")
        || decode_hex32(object_get(root, "original_source_scope_sha256"),
            output->original_source_scope_sha256) != 0
        || decode_hex32(object_get(root,
            "dependency_materialization_receipt_sha256"),
            output->dependency_materialization_receipt_sha256) != 0
        || decode_hex32(object_get(root, "js_lock_selection_sha256"),
            output->js_lock_selection_sha256) != 0
        || decode_hex32(object_get(root, "materialization_lineage_sha256"),
            output->materialization_lineage_sha256) != 0
        || json_u64(object_get(root, "materialization_lineage_byte_count"),
            1048576U, &output->materialization_lineage_byte_count) != 0
        || output->materialization_lineage_byte_count == 0U
        || decode_hex32(object_get(root,
            "native_materialization_request_sha256"),
            output->native_materialization_request_sha256) != 0
        || projection_closure_parse(object_get(root, "source_copy"),
            output->source_copy_closure_sha256,
            &output->source_copy_file_count,
            &output->source_copy_directory_count,
            &output->source_copy_bytes) != 0
        || projection_closure_parse(object_get(root,
                "materialized_node_modules"),
            output->materialized_node_modules_closure_sha256,
            &output->materialized_node_modules_file_count,
            &output->materialized_node_modules_directory_count,
            &output->materialized_node_modules_bytes) != 0
        || projection_closure_parse(object_get(root, "analysis_workspace"),
            output->analysis_workspace_closure_sha256,
            &output->analysis_workspace_file_count,
            &output->analysis_workspace_directory_count,
            &output->analysis_workspace_bytes) != 0)
        goto done;
    output->version = 1U;
    result = 0;
done:
    json_destroy(root);
    if (result != 0) memset(output, 0, sizeof(*output));
    return result;
}

int
plamen_broker_v2_specialized_method_output_specs(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    struct plamen_broker_v2_specialized_output_spec specs[2],
    size_t *count)
{
    struct json_node *root = NULL, *outputs, *controller_outputs, *bounds, *row, *node;
    uint8_t digest[32]; size_t amount = 0, i; uint64_t entries, bytes;
    const char *names[2], *paths[2]; int result = -1;
    if (count != NULL) *count = 0;
    if (specs != NULL) memset(specs, 0, sizeof(*specs) * 2U);
    if (view == NULL || binding == NULL || specs == NULL || count == NULL
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        || view->method != PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE
        || view->payload == NULL || view->payload_size < 3U
        || view->payload[view->payload_size - 1U] != '\n'
        || plamen_broker_v2_sha256(view->payload, view->payload_size, digest) != 0
        || !constant_equal(digest, binding->method_payload_sha256, 32)
        || !js_operation_name(binding->operation)) goto done;
    root = json_parse(view->payload, view->payload_size - 1U);
    if (root == NULL || !string_is(object_get(root, "operation"), binding->operation)
        || (outputs = object_get(root, "guest_outputs")) == NULL
        || outputs->kind != J_OBJECT || (bounds = object_get(root, "bounds")) == NULL
        || bounds->kind != J_OBJECT
        || (controller_outputs = object_get(root, "outputs")) == NULL
        || controller_outputs->kind != J_OBJECT) goto done;
    if (strcmp(binding->operation, "PREPARE_TOOLCHAIN") == 0) {
        names[0] = "toolchain"; paths[0] = "toolchain"; amount = 1U;
    } else if (strcmp(binding->operation, "ONLINE_INSTALL") == 0) {
        names[0] = "cache"; paths[0] = "online/cache";
        names[1] = "modules"; paths[1] = "online/modules"; amount = 2U;
    } else if (strcmp(binding->operation, "CACHE_HANDOFF") == 0) {
        names[0] = "offline_cache_seed"; paths[0] = "offline-replay/cache";
        names[1] = "retained_cache_snapshot"; paths[1] = "online-cache-snapshot"; amount = 2U;
    } else { names[0] = "modules"; paths[0] = "offline-replay/modules"; amount = 1U; }
    if (outputs->count != amount || controller_outputs->count != amount
        || bounds->count != amount) goto done;
    for (i = 0; i < amount; ++i) {
        char guest[160];
        struct json_node *controller_node;
        snprintf(guest, sizeof(guest), "/workspace/scratch/%s", paths[i]);
        row = object_get(bounds, names[i]); node = object_get(outputs, names[i]);
        controller_node = object_get(controller_outputs, names[i]);
        if (!string_is(node, guest) || row == NULL || row->kind != J_OBJECT
            || controller_node == NULL || controller_node->kind != J_STRING
            || json_u64(object_get(row, "max_entries"), 65536U, &entries) != 0
            || json_u64(object_get(row, "max_bytes"), 4294967296ULL, &bytes) != 0
            || entries == 0U || bytes == 0U) goto done;
        snprintf(specs[i].name, sizeof(specs[i].name), "%s", names[i]);
        specs[i].version = PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_CENSUS_VERSION;
        specs[i].role = PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_ROLE_SCRATCH;
        snprintf(specs[i].relative_path, sizeof(specs[i].relative_path), "%s", paths[i]);
        specs[i].max_entries = entries; specs[i].max_expanded_bytes = bytes;
    }
    *count = amount; result = 0;
done:
    json_destroy(root); plamen_broker_v2_secure_zero(digest, sizeof(digest));
    if (result != 0) {
        if (specs != NULL) memset(specs, 0, sizeof(*specs) * 2U);
        if (count != NULL) *count = 0;
    }
    return result;
}

static const char *json_text(const struct json_node *root, const char *name)
{
    struct json_node *node = object_get(root, name);
    return node != NULL && node->kind == J_STRING ? node->string : NULL;
}

static int json_node_sha256(const uint8_t *raw, size_t raw_size,
    const struct json_node *node, uint8_t output[32])
{
    if (raw == NULL || node == NULL || output == NULL
        || node->raw_end <= node->raw_start || node->raw_end > raw_size)
        return -1;
    return plamen_broker_v2_sha256(raw + node->raw_start,
        node->raw_end - node->raw_start, output);
}

static void render_js_method_terminal(struct buffer *out,
    const struct json_node *request,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *observed,
    const struct plamen_broker_v2_specialized_output_receipt *host,
    const char *receipt)
{
    const char *copy[] = { "contract_sha256", "dependency_expectation_sha256",
        "generation_id", "guest_execution_binding_sha256", "launch_object_kind",
        "native_custody_receipt_sha256", "native_deployment_receipt_sha256",
        "native_module_sha256", "network_authority_sha256", "network_mode" };
    char hex[65]; size_t i;
    put(out, "{\"bounds_enforced\":true,\"cleanup_complete\":true");
    for (i = 0; i < 2U; ++i) { put(out, ",\"%s\":", copy[i]); put_string(out, json_text(request, copy[i])); }
    put(out, ",\"duration_ms\":%llu,\"exclusive_operation_key_lease\":true,"
        "\"exhaustive_descendant_termination\":true,\"exit_code\":0",
        (unsigned long long)observed->duration_ms);
    for (i = 2U; i < 8U; ++i) { put(out, ",\"%s\":", copy[i]); put_string(out, json_text(request, copy[i])); }
    put(out, ",\"native_provider_authenticated\":true");
    for (i = 8U; i < 10U; ++i) { put(out, ",\"%s\":", copy[i]); put_string(out, json_text(request, copy[i])); }
    hex32(host->network_policy_sha256, hex);
    put(out, ",\"network_policy_sha256\":\"%s\",\"network_violation\":false,"
        "\"observed_egress_origins\":[]", hex);
    hex32(host->observed_egress_sha256, hex);
    put(out, ",\"observed_egress_sha256\":\"%s\",\"operation\":", hex);
    put_string(out, binding->operation); put(out, ",\"output_trees\":{");
    for (i = 0; i < host->tree_count; ++i) {
        const struct plamen_broker_v2_specialized_output_tree *row = &host->trees[i];
        if (i) put(out, ","); put(out, "\"%s\":{\"algorithm\":\"PLAMEN_CANONICAL_TREE_SHA256_V1\","
            "\"entry_count\":%llu,\"expanded_bytes\":%llu,\"path\":\"%s\",",
            row->name, (unsigned long long)row->entry_count,
            (unsigned long long)row->expanded_bytes,
            json_text(object_get(request, "outputs"), row->name));
        hex32(row->tree_sha256, hex); put(out, "\"sha256\":\"%s\"}", hex);
    }
    hex32(host->post_spawn_dynamic_identity_sha256, hex);
    put(out, "},\"population_zero\":true,\"post_spawn_dynamic_identity_kind\":"
        "\"APPLE_CODEDIRECTORY_CDHASH\",\"post_spawn_dynamic_identity_sha256\":\"%s\","
        "\"projected_closure_manifest_sha256\":", hex);
    put_string(out, json_text(request, "projected_closure_manifest_sha256"));
    put(out, ",\"request_sha256\":"); put_string(out, json_text(request, "request_sha256"));
    put(out, ",\"schema\":\"plamen.js-dependency-native-terminal.v2\","
        "\"scratch_writes_only\":true,\"session_admission_sha256\":");
    put_string(out, json_text(request, "session_admission_sha256"));
    put(out, ",\"source_read_only\":true");
    hex32(observed->stderr_sha256, hex); put(out, ",\"stderr_bytes\":%llu,\"stderr_sha256\":\"%s\"",
        (unsigned long long)observed->stderr_retained_bytes, hex);
    hex32(observed->stdout_sha256, hex); put(out, ",\"stdout_bytes\":%llu,\"stdout_sha256\":\"%s\"",
        (unsigned long long)observed->stdout_retained_bytes, hex);
    if (receipt != NULL) put(out, ",\"terminal_receipt_sha256\":\"%s\"", receipt);
    put(out, ",\"timed_out\":false,\"toolchain_identity_sha256\":");
    put_string(out, json_text(request, "toolchain_binding_sha256")); put(out, "}");
}

int
plamen_broker_v2_specialized_js_method_terminal_render(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *observed,
    const struct plamen_broker_v2_specialized_output_receipt *host,
    const uint8_t session_key[32], const uint8_t lifecycle_receipt_sha256[32],
    uint8_t **terminal, size_t *terminal_size)
{
    struct plamen_broker_v2_specialized_output_spec specs[2];
    struct json_node *request = NULL, *policy; struct buffer out; uint8_t *raw = NULL;
    uint8_t digest[32], empty[32]; char receipt[65]; size_t count = 0, i; int result = -1;
    static const char *const required[] = { "contract_sha256",
        "dependency_expectation_sha256", "generation_id",
        "guest_execution_binding_sha256", "launch_object_kind",
        "native_custody_receipt_sha256", "native_deployment_receipt_sha256",
        "native_module_sha256", "network_authority_sha256", "network_mode",
        "projected_closure_manifest_sha256", "request_sha256",
        "session_admission_sha256", "toolchain_binding_sha256" };
    if (terminal != NULL) *terminal = NULL; if (terminal_size != NULL) *terminal_size = 0;
    if (terminal == NULL || terminal_size == NULL || view == NULL
        || binding == NULL || observed == NULL || host == NULL
        || observed->version != 1U || strcmp(observed->status, "COMPLETE") != 0
        || observed->returncode != 0 || host->version != 1U
        || session_key == NULL || lifecycle_receipt_sha256 == NULL
        || strcmp(binding->operation, "ONLINE_INSTALL") == 0
        || plamen_broker_v2_specialized_method_output_specs(view, binding, specs, &count) != 0
        || host->tree_count != count
        || plamen_broker_v2_specialized_output_receipt_validate(host, session_key,
            view, binding, lifecycle_receipt_sha256, specs, count) != 0) goto done;
    request = json_parse(view->payload, view->payload_size - 1U);
    policy = object_get(request, "network_policy");
    if (request == NULL || policy == NULL
        || decode_hex32(object_get(policy, "policy_sha256"), digest) != 0
        || !constant_equal(digest, host->network_policy_sha256, 32)
        || plamen_broker_v2_sha256("[]", 2U, empty) != 0
        || !constant_equal(empty, host->observed_egress_sha256, 32)) goto done;
    for (i = 0; i < sizeof(required) / sizeof(required[0]); ++i)
        if (json_text(request, required[i]) == NULL) goto done;
    for (i = 0; i < count; ++i)
        if (digest_zero(host->trees[i].tree_sha256)) goto done;
    raw = malloc(1048576U); if (raw == NULL) goto done;
    memset(&out, 0, sizeof(out)); out.data = raw; out.capacity = 1048576U;
    render_js_method_terminal(&out, request, binding, observed, host, NULL);
    if (out.failed || plamen_broker_v2_sha256(raw, out.size, digest) != 0) goto done;
    hex32(digest, receipt); memset(&out, 0, sizeof(out)); out.data = raw; out.capacity = 1048576U;
    render_js_method_terminal(&out, request, binding, observed, host, receipt);
    if (out.failed || out.size >= out.capacity) goto done;
    raw[out.size++] = '\n';
    *terminal = raw; *terminal_size = out.size; raw = NULL; result = 0;
done:
    json_destroy(request); if (raw != NULL) free(raw); return result;
}

static void render_snapshot_method_terminal(struct buffer *out,
    const struct json_node *request,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *observed,
    const struct plamen_broker_v2_specialized_output_receipt *host,
    const uint8_t request_sha256[32], const uint8_t runtime_sha256[32],
    const uint8_t argv_sha256[32], const uint8_t environment_sha256[32],
    const uint8_t cwd_sha256[32], const uint8_t mounts_sha256[32])
{
    char request_hex[65], runtime_hex[65], argv_hex[65], environment_hex[65];
    char cwd_hex[65], mounts_hex[65], dynamic_hex[65], output_hex[65];
    char stdout_hex[65], stderr_hex[65];
    int stdout_truncated = observed->stdout_observed_bytes
        != observed->stdout_retained_bytes;
    int stderr_truncated = observed->stderr_observed_bytes
        != observed->stderr_retained_bytes;
    const char *exit_state = stdout_truncated || stderr_truncated
        ? "COMPLETED_WITH_TRUNCATION_DEBT" : "COMPLETED";
    hex32(request_sha256, request_hex); hex32(runtime_sha256, runtime_hex);
    hex32(argv_sha256, argv_hex); hex32(environment_sha256, environment_hex);
    hex32(cwd_sha256, cwd_hex); hex32(mounts_sha256, mounts_hex);
    hex32(host->post_spawn_dynamic_identity_sha256, dynamic_hex);
    hex32(observed->output_manifest_sha256, output_hex);
    hex32(observed->stdout_sha256, stdout_hex);
    hex32(observed->stderr_sha256, stderr_hex);
    put(out, "{\"argv_sha256\":\"%s\",\"audit_snapshot_sha256\":", argv_hex);
    put_string(out, json_text(request, "audit_snapshot_sha256"));
    put(out, ",\"cleanup_complete\":true,\"cwd_sha256\":\"%s\","
        "\"duration_ms\":%llu,\"egress_denied\":true,"
        "\"egress_policy\":\"DENY_ALL\","
        "\"environment_sha256\":\"%s\",\"exit_state\":\"%s\","
        "\"materialization_lineage_sha256\":", cwd_hex,
        (unsigned long long)observed->duration_ms, environment_hex, exit_state);
    put_string(out, json_text(request, "materialization_lineage_sha256"));
    put(out, ",\"mounts_sha256\":\"%s\","
        "\"native_runtime_identity_sha256\":\"%s\","
        "\"output_bytes\":%llu,\"output_file_count\":%llu,"
        "\"output_limit_exceeded\":false,\"output_tree_sha256\":\"%s\","
        "\"peak_memory_bytes\":%llu,\"population_zero\":true,"
        "\"post_spawn_dynamic_identity_sha256\":\"%s\","
        "\"request_sha256\":\"%s\",\"returncode\":0,\"run_id\":",
        mounts_hex, runtime_hex, (unsigned long long)observed->output_bytes,
        (unsigned long long)observed->output_file_count, output_hex,
        (unsigned long long)observed->peak_memory_bytes, dynamic_hex,
        request_hex);
    put_string(out, json_text(request, "run_id"));
    put(out, ",\"schema\":\"plamen.snapshot-bound-tool-execution-terminal.v3\","
        "\"source_descriptor_sha256\":");
    put_string(out, json_text(object_get(request, "source_descriptor"),
        "descriptor_sha256"));
    put(out, ",\"source_scope_sha256\":");
    put_string(out, json_text(request, "source_scope_sha256"));
    put(out, ",\"stderr_observed_bytes\":%llu,"
        "\"stderr_retained_bytes\":%llu,\"stderr_sha256\":\"%s\","
        "\"stdout_observed_bytes\":%llu,"
        "\"stdout_retained_bytes\":%llu,\"stdout_sha256\":\"%s\","
        "\"tool_id\":", (unsigned long long)observed->stderr_observed_bytes,
        (unsigned long long)observed->stderr_retained_bytes, stderr_hex,
        (unsigned long long)observed->stdout_observed_bytes,
        (unsigned long long)observed->stdout_retained_bytes, stdout_hex);
    put_string(out, json_text(request, "tool_id"));
    put(out, ",\"toolchain_governance_sha256\":");
    put_string(out, json_text(request, "toolchain_governance_sha256"));
    put(out, ",\"toolchain_version_lock_sha256\":");
    put_string(out, json_text(request, "toolchain_version_lock_sha256"));
    put(out, ",\"truncation_debt\":");
    if (!stdout_truncated && !stderr_truncated) put(out, "null");
    else {
        put(out, "{\"can_certify_clean\":false,\"findings_complete\":false,"
            "\"schema\":\"plamen.tool-output-truncation-debt.v1\",\"streams\":[");
        if (stderr_truncated) put(out, "\"stderr\"");
        if (stderr_truncated && stdout_truncated) put(out, ",");
        if (stdout_truncated) put(out, "\"stdout\"");
        put(out, "]}");
    }
    put(out, "}");
}

static void authority_put16(uint8_t output[2], uint16_t value)
{ output[0] = (uint8_t)(value >> 8); output[1] = (uint8_t)value; }

static void authority_put32(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)(value >> 24); output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8); output[3] = (uint8_t)value;
}

static int snapshot_host_authority_hmac(
    const struct plamen_broker_v2_specialized_output_receipt *host,
    const uint8_t session_key[32], uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-SNAPSHOT-HOST-AUTHORITY-V1\0";
    uint8_t bytes[4U + 2U + 2U + 32U + 32U * 7U + 4U + 4U + 4U];
    size_t offset = 0U;
    if (host == NULL || session_key == NULL || output == NULL
        || digest_zero(session_key)) return -1;
    authority_put32(bytes + offset, host->version); offset += 4U;
    authority_put16(bytes + offset, host->lane); offset += 2U;
    authority_put16(bytes + offset, host->method); offset += 2U;
    memcpy(bytes + offset, host->operation, sizeof(host->operation));
    offset += sizeof(host->operation);
#define COPY_AUTHORITY(field) do { \
    memcpy(bytes + offset, host->field, 32U); offset += 32U; \
} while (0)
    COPY_AUTHORITY(request_sha256);
    COPY_AUTHORITY(effects_binding_sha256);
    COPY_AUTHORITY(worker_request_sha256);
    COPY_AUTHORITY(lifecycle_receipt_sha256);
    authority_put32(bytes + offset, host->post_spawn_dynamic_identity_kind);
    offset += 4U;
    authority_put32(bytes + offset, host->post_spawn_dynamic_identity_size);
    offset += 4U;
    COPY_AUTHORITY(post_spawn_dynamic_identity_sha256);
    COPY_AUTHORITY(network_policy_sha256);
    COPY_AUTHORITY(observed_egress_sha256);
#undef COPY_AUTHORITY
    bytes[offset++] = host->provider_authenticated;
    bytes[offset++] = host->network_policy_enforced;
    bytes[offset++] = host->population_zero;
    bytes[offset++] = host->cleanup_complete;
    if (offset != sizeof(bytes)
        || plamen_broker_v2_hmac_sha256(session_key, domain, sizeof(domain),
            bytes, offset, output) != 0 || digest_zero(output)) {
        memset(bytes, 0, sizeof(bytes)); return -1;
    }
    memset(bytes, 0, sizeof(bytes)); return 0;
}

int
plamen_broker_v2_specialized_snapshot_host_authority_seal(
    struct plamen_broker_v2_specialized_output_receipt *host,
    const uint8_t session_key[32])
{
    uint8_t digest[32]; int result = -1;
    memset(digest, 0, sizeof(digest));
    if (host == NULL || session_key == NULL
        || host->version != PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RECEIPT_VERSION
        || host->lane != PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        || host->method != PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE
        || strcmp(host->operation, "SNAPSHOT_TOOL_EXECUTE") != 0
        || digest_zero(host->request_sha256)
        || digest_zero(host->effects_binding_sha256)
        || digest_zero(host->worker_request_sha256)
        || digest_zero(host->lifecycle_receipt_sha256)
        || host->post_spawn_dynamic_identity_kind
            != PLAMEN_BROKER_V2_SPECIALIZED_DYNAMIC_IDENTITY_APPLE_CDHASH
        || (host->post_spawn_dynamic_identity_size != 20U
            && host->post_spawn_dynamic_identity_size != 32U)
        || digest_zero(host->post_spawn_dynamic_identity_sha256)
        || digest_zero(host->network_policy_sha256)
        || digest_zero(host->observed_egress_sha256)
        || host->provider_authenticated != 1U
        || host->network_policy_enforced != 1U || host->population_zero != 1U
        || host->cleanup_complete != 1U || host->tree_count != 0U
        || !digest_zero(host->tree_roster_sha256)
        || !digest_zero(host->receipt_hmac_sha256)
        || snapshot_host_authority_hmac(host, session_key, digest) != 0)
        goto done;
    memcpy(host->receipt_hmac_sha256, digest, 32U); result = 0;
done:
    memset(digest, 0, sizeof(digest)); return result;
}

int
plamen_broker_v2_specialized_snapshot_method_terminal_render(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const struct plamen_broker_v2_specialized_worker_request_binding *binding,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *observed,
    const struct plamen_broker_v2_specialized_output_receipt *host,
    const uint8_t session_key[32], const uint8_t lifecycle_receipt_sha256[32],
    uint8_t **terminal, size_t *terminal_size)
{
    static const char *const root_keys[] = {
        "argv", "audit_snapshot_sha256", "authentic_content_authority",
        "authority_tier", "build_system", "can_certify_clean", "cwd",
        "egress_policy", "environment", "evidence_ceiling",
        "execution_authority", "limits", "materialization_lineage_sha256",
        "mounts", "native_runtime_identity", "platform", "run_id", "schema",
        "snapshot_projection_bytes", "snapshot_projection_sha256",
        "source_descriptor", "source_scope_sha256", "tool_id",
        "toolchain_governance_sha256", "toolchain_version_lock_sha256",
        "trust_assumption"
    };
    static const char *const digest_fields[] = {
        "audit_snapshot_sha256", "materialization_lineage_sha256",
        "snapshot_projection_sha256", "source_scope_sha256",
        "toolchain_governance_sha256", "toolchain_version_lock_sha256"
    };
    struct json_node *request = NULL, *node;
    struct buffer out;
    uint8_t request_sha[32], runtime_sha[32], argv_sha[32], environment_sha[32];
    uint8_t cwd_sha[32], mounts_sha[32], digest[32], authority_hmac[32];
    uint8_t *raw = NULL; char tool_anchor_id[32];
    size_t index;
    int result = -1;
    if (terminal != NULL) *terminal = NULL;
    if (terminal_size != NULL) *terminal_size = 0U;
    memset(request_sha, 0, sizeof(request_sha)); memset(runtime_sha, 0, sizeof(runtime_sha));
    memset(argv_sha, 0, sizeof(argv_sha)); memset(environment_sha, 0, sizeof(environment_sha));
    memset(cwd_sha, 0, sizeof(cwd_sha)); memset(mounts_sha, 0, sizeof(mounts_sha));
    memset(digest, 0, sizeof(digest)); memset(authority_hmac, 0, sizeof(authority_hmac));
    memset(tool_anchor_id, 0, sizeof(tool_anchor_id));
    if (terminal == NULL || terminal_size == NULL || view == NULL
        || binding == NULL || observed == NULL || host == NULL
        || session_key == NULL || digest_zero(session_key)
        || lifecycle_receipt_sha256 == NULL || digest_zero(lifecycle_receipt_sha256)
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        || view->method != PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE
        || plamen_broker_v2_specialized_worker_tool_anchor_id(view,
            tool_anchor_id) != 0
        || strcmp(binding->operation, "SNAPSHOT_TOOL_EXECUTE") != 0
        || observed->version != 1U || strcmp(observed->status, "COMPLETE") != 0
        || observed->returncode != 0 || digest_zero(observed->output_manifest_sha256)
        || host->version != PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RECEIPT_VERSION
        || host->lane != view->lane || host->method != view->method
        || strcmp(host->operation, binding->operation) != 0
        || !constant_equal(host->request_sha256, view->request_sha256, 32)
        || !constant_equal(host->effects_binding_sha256,
            binding->effects_binding_sha256, 32)
        || !constant_equal(host->worker_request_sha256,
            binding->worker_request_sha256, 32)
        || host->provider_authenticated != 1U
        || host->network_policy_enforced != 1U || host->population_zero != 1U
        || host->cleanup_complete != 1U
        || host->post_spawn_dynamic_identity_kind
            != PLAMEN_BROKER_V2_SPECIALIZED_DYNAMIC_IDENTITY_APPLE_CDHASH
        || (host->post_spawn_dynamic_identity_size != 20U
            && host->post_spawn_dynamic_identity_size != 32U)
        || digest_zero(host->post_spawn_dynamic_identity_sha256)
        || digest_zero(host->network_policy_sha256)
        || digest_zero(host->observed_egress_sha256)
        || !constant_equal(host->observed_egress_sha256,
            observed->observed_egress_sha256, 32)
        || !constant_equal(host->lifecycle_receipt_sha256,
            lifecycle_receipt_sha256, 32)
        || host->tree_count != 0U || !digest_zero(host->tree_roster_sha256)
        || digest_zero(host->receipt_hmac_sha256)
        || snapshot_host_authority_hmac(host, session_key,
            authority_hmac) != 0
        || !constant_equal(host->receipt_hmac_sha256, authority_hmac, 32)
        || view->payload == NULL || view->payload_size < 2U
        || plamen_broker_v2_sha256(view->payload, view->payload_size,
            request_sha) != 0)
        goto done;
    request = json_parse(view->payload, view->payload_size);
    if (!object_keys(request, root_keys,
            sizeof(root_keys) / sizeof(root_keys[0]))
        || !string_is(object_get(request, "schema"),
            "plamen.snapshot-bound-tool-execution-request.v3")
        || !string_is(object_get(request, "platform"), "MACOS")
        || !string_is(object_get(request, "authority_tier"),
            "SNAPSHOT_BOUND_LOCAL")
        || !string_is(object_get(request, "egress_policy"), "DENY_ALL")
        || !string_is(object_get(request, "trust_assumption"),
            "OPERATOR_LOCAL_TOOL_INSTALL")
        || !string_is(object_get(request, "evidence_ceiling"),
            "POSITIVE_FINDINGS_AND_HEURISTIC_COVERAGE_ONLY")
        || !safe_request_id(json_text(request, "run_id"))) goto done;
    node = object_get(request, "execution_authority");
    if (node == NULL || node->kind != J_BOOL || !node->boolean) goto done;
    node = object_get(request, "authentic_content_authority");
    if (node == NULL || node->kind != J_BOOL || node->boolean) goto done;
    node = object_get(request, "can_certify_clean");
    if (node == NULL || node->kind != J_BOOL || node->boolean) goto done;
    for (index = 0; index < sizeof(digest_fields) / sizeof(digest_fields[0]); ++index)
        if (decode_hex32(object_get(request, digest_fields[index]), digest) != 0)
            goto done;
    node = object_get(request, "source_descriptor");
    if (node == NULL || node->kind != J_OBJECT
        || decode_hex32(object_get(node, "descriptor_sha256"), digest) != 0)
        goto done;
    if (json_node_sha256(view->payload, view->payload_size,
            object_get(request, "native_runtime_identity"), runtime_sha) != 0
        || json_node_sha256(view->payload, view->payload_size,
            object_get(request, "argv"), argv_sha) != 0
        || json_node_sha256(view->payload, view->payload_size,
            object_get(request, "environment"), environment_sha) != 0
        || json_node_sha256(view->payload, view->payload_size,
            object_get(request, "cwd"), cwd_sha) != 0
        || json_node_sha256(view->payload, view->payload_size,
            object_get(request, "mounts"), mounts_sha) != 0)
        goto done;
    raw = malloc(PLAMEN_BROKER_V2_SPECIALIZED_WORKER_REQUEST_MAX);
    if (raw == NULL) goto done;
    memset(&out, 0, sizeof(out)); out.data = raw;
    out.capacity = PLAMEN_BROKER_V2_SPECIALIZED_WORKER_REQUEST_MAX;
    render_snapshot_method_terminal(&out, request, observed, host,
        request_sha, runtime_sha, argv_sha, environment_sha, cwd_sha,
        mounts_sha);
    if (out.failed || out.size == 0U || out.size >= out.capacity) goto done;
    *terminal = raw; *terminal_size = out.size; raw = NULL; result = 0;
done:
    json_destroy(request);
    if (raw != NULL) { memset(raw, 0, PLAMEN_BROKER_V2_SPECIALIZED_WORKER_REQUEST_MAX); free(raw); }
    memset(request_sha, 0, sizeof(request_sha)); memset(runtime_sha, 0, sizeof(runtime_sha));
    memset(argv_sha, 0, sizeof(argv_sha)); memset(environment_sha, 0, sizeof(environment_sha));
    memset(cwd_sha, 0, sizeof(cwd_sha)); memset(mounts_sha, 0, sizeof(mounts_sha));
    memset(digest, 0, sizeof(digest)); memset(authority_hmac, 0, sizeof(authority_hmac));
    memset(tool_anchor_id, 0, sizeof(tool_anchor_id));
    return result;
}

int
plamen_broker_v2_specialized_js_replay_terminal_binding(
    const struct plamen_broker_v2_tool_effect_plan_view *view,
    const uint8_t **terminal, size_t *terminal_size,
    uint8_t terminal_sha256[32])
{
    static const char prefix[] = "{\"request\":";
    static const char join[] = ",\"terminal\":";
    static const char *const request_keys[] = { "archives", "argv", "bounds",
        "contract_sha256", "cwd", "dependency_expectation_sha256", "environment",
        "expected_inputs", "generation_id", "guest_argv", "guest_cwd",
        "guest_environment", "guest_execution_binding_sha256", "guest_expected_inputs",
        "guest_outputs", "guest_platform", "launch_object_kind", "mounts",
        "native_custody_receipt_sha256", "native_deployment_receipt_sha256",
        "native_module_sha256", "network_authority_sha256", "network_mode",
        "network_policy", "operation", "outputs", "projected_closure_manifest_sha256",
        "request_sha256", "required_dynamic_identity_kind", "schema",
        "session_admission_sha256", "source_access", "source_guard_sha256",
        "source_snapshot_sha256", "timeout_seconds", "toolchain_binding_sha256",
        "write_access" };
    static const char *const terminal_keys[] = { "bounds_enforced", "cleanup_complete",
        "contract_sha256", "dependency_expectation_sha256", "duration_ms",
        "exclusive_operation_key_lease", "exhaustive_descendant_termination", "exit_code",
        "generation_id", "guest_execution_binding_sha256", "launch_object_kind",
        "native_custody_receipt_sha256", "native_deployment_receipt_sha256",
        "native_module_sha256", "native_provider_authenticated", "network_authority_sha256",
        "network_mode", "network_policy_sha256", "network_violation",
        "observed_egress_origins", "observed_egress_sha256", "operation", "output_trees",
        "population_zero", "post_spawn_dynamic_identity_kind",
        "post_spawn_dynamic_identity_sha256", "projected_closure_manifest_sha256",
        "request_sha256", "schema", "scratch_writes_only", "session_admission_sha256",
        "source_read_only", "stderr_bytes", "stderr_sha256", "stdout_bytes",
        "stdout_sha256", "terminal_receipt_sha256", "timed_out",
        "toolchain_identity_sha256" };
    const uint8_t *raw, *request_raw, *terminal_raw; size_t size, request_size, result_size;
    size_t index; int depth = 0, in_string = 0; struct json_node *root = NULL;
    struct json_node *request, *result; const char *links[] = { "contract_sha256",
        "dependency_expectation_sha256", "generation_id", "guest_execution_binding_sha256",
        "launch_object_kind", "native_custody_receipt_sha256",
        "native_deployment_receipt_sha256", "native_module_sha256",
        "network_authority_sha256", "network_mode", "operation",
        "projected_closure_manifest_sha256", "request_sha256", "session_admission_sha256" };
    uint8_t *wire = NULL; int status = -1;
    if (terminal != NULL) *terminal = NULL; if (terminal_size != NULL) *terminal_size = 0;
    if (terminal_sha256 != NULL) memset(terminal_sha256, 0, 32);
    if (view == NULL || terminal == NULL || terminal_size == NULL || terminal_sha256 == NULL
        || view->lane != PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        || view->method != PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY
        || (raw = view->payload) == NULL || (size = view->payload_size) < sizeof(prefix)+sizeof(join)
        || memcmp(raw, prefix, sizeof(prefix)-1U) != 0 || raw[size-1U] != '}') return -1;
    request_raw = raw + sizeof(prefix)-1U;
    for (index = (size_t)(request_raw-raw); index < size; ++index) {
        uint8_t byte = raw[index];
        if (byte == '\\' || byte < 0x20U || byte >= 0x7fU) return -1;
        if (byte == '"') { in_string = !in_string; continue; }
        if (in_string) continue;
        if (byte == '{' || byte == '[') ++depth;
        else if (byte == '}' || byte == ']') {
            if (--depth < 0) return -1;
            if (depth == 0) { ++index; break; }
        } else if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n') return -1;
    }
    request_size = index - (size_t)(request_raw-raw);
    if (depth != 0 || in_string || index + sizeof(join)-1U >= size
        || memcmp(raw+index, join, sizeof(join)-1U) != 0) return -1;
    terminal_raw = raw + index + sizeof(join)-1U;
    result_size = size - (size_t)(terminal_raw-raw) - 1U;
    if (!terminal_canonical_octets(request_raw, request_size)
        || !terminal_canonical_octets(terminal_raw, result_size)) return -1;
    root = json_parse(raw, size);
    request = object_get(root, "request"); result = object_get(root, "terminal");
    if (!object_keys(root, (const char *const[]){"request", "terminal"}, 2U)
        || !object_keys(request, request_keys, sizeof(request_keys)/sizeof(request_keys[0]))
        || !object_keys(result, terminal_keys, sizeof(terminal_keys)/sizeof(terminal_keys[0]))
        || !string_is(object_get(request, "schema"), "plamen.js-dependency-native-request.v2")
        || !string_is(object_get(result, "schema"), "plamen.js-dependency-native-terminal.v2"))
        goto done;
    for (index = 0; index < sizeof(request_keys)/sizeof(request_keys[0]); ++index)
        if (strcmp(request->members[index].key, request_keys[index]) != 0) goto done;
    for (index = 0; index < sizeof(terminal_keys)/sizeof(terminal_keys[0]); ++index)
        if (strcmp(result->members[index].key, terminal_keys[index]) != 0) goto done;
    for (index = 0; index < sizeof(links)/sizeof(links[0]); ++index) {
        const char *a = json_text(request, links[index]), *b = json_text(result, links[index]);
        if (a == NULL || b == NULL || strcmp(a, b) != 0) goto done;
    }
    wire = malloc(result_size + 1U);
    if (wire == NULL) goto done;
    memcpy(wire, terminal_raw, result_size); wire[result_size] = '\n';
    if (plamen_broker_v2_sha256(wire, result_size + 1U, terminal_sha256) != 0
        || digest_zero(terminal_sha256)) goto done;
    *terminal = terminal_raw; *terminal_size = result_size; status = 0;
done:
    if (wire != NULL) { memset(wire, 0, result_size + 1U); free(wire); }
    json_destroy(root);
    if (status != 0) { *terminal = NULL; *terminal_size = 0; memset(terminal_sha256, 0, 32); }
    return status;
}
