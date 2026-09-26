#ifdef __linux__
#define _GNU_SOURCE 1
#endif
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_broker_v2_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#elif defined(__linux__)
#include <linux/magic.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/vfs.h>
#else
#error "plamen broker v2 requires an audited platform SHA-256/HMAC provider"
#endif

static const uint8_t plamen_v2_magic[8] = {
    'P', 'L', 'M', 'B', 'R', 'K', '2', '\0'
};
static const uint8_t plamen_v2_service_magic[8] = {
    'P', 'L', 'M', 'S', 'V', 'C', '2', '\0'
};

struct digest_context {
#ifdef __APPLE__
    CC_SHA256_CTX value;
#else
    EVP_MD_CTX *value;
#endif
};

static int
digest_init(struct digest_context *context)
{
#ifdef __APPLE__
    return CC_SHA256_Init(&context->value) == 1 ? 0 : -1;
#else
    context->value = EVP_MD_CTX_new();
    if (context->value == NULL)
        return -1;
    if (EVP_DigestInit_ex(context->value, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(context->value);
        context->value = NULL;
        return -1;
    }
    return 0;
#endif
}

static int
digest_update(struct digest_context *context, const void *data, size_t size)
{
    if (size != 0 && data == NULL)
        return -1;
#ifdef __APPLE__
    while (size != 0) {
        CC_LONG amount = size > UINT32_MAX ? UINT32_MAX : (CC_LONG)size;
        if (CC_SHA256_Update(&context->value, data, amount) != 1)
            return -1;
        data = (const uint8_t *)data + amount;
        size -= amount;
    }
    return 0;
#else
    return EVP_DigestUpdate(context->value, data, size) == 1 ? 0 : -1;
#endif
}

static int
digest_final(struct digest_context *context, uint8_t out[32])
{
#ifdef __APPLE__
    return CC_SHA256_Final(out, &context->value) == 1 ? 0 : -1;
#else
    unsigned length = 0;
    int ok = EVP_DigestFinal_ex(context->value, out, &length) == 1 && length == 32;
    EVP_MD_CTX_free(context->value);
    context->value = NULL;
    return ok ? 0 : -1;
#endif
}

static void
digest_destroy(struct digest_context *context)
{
    if (context == NULL) return;
#ifdef __APPLE__
    plamen_broker_v2_secure_zero(&context->value, sizeof(context->value));
#else
    if (context->value != NULL) EVP_MD_CTX_free(context->value);
    context->value = NULL;
#endif
}

void
plamen_broker_v2_secure_zero(void *data, size_t size)
{
    volatile uint8_t *cursor = (volatile uint8_t *)data;
    if (cursor == NULL)
        return;
    while (size-- != 0)
        *cursor++ = 0;
}

int
plamen_broker_v2_sha256(const void *data, size_t size, uint8_t out[32])
{
    struct digest_context context;
    int result = PLAMEN_BROKER_V2_SYSTEM;
    memset(&context, 0, sizeof(context));
    if (out == NULL || (size != 0 && data == NULL))
        return PLAMEN_BROKER_V2_INVALID;
    if (digest_init(&context) == 0 && digest_update(&context, data, size) == 0
        && digest_final(&context, out) == 0)
        result = PLAMEN_BROKER_V2_OK;
    digest_destroy(&context);
    if (result != PLAMEN_BROKER_V2_OK)
        plamen_broker_v2_secure_zero(out, 32);
    return result;
}

int
plamen_broker_v2_hmac_sha256(const uint8_t key[32], const void *first,
    size_t first_size, const void *second, size_t second_size, uint8_t out[32])
{
    uint8_t *joined;
    size_t total;
    if (key == NULL || out == NULL || (first_size != 0 && first == NULL)
        || (second_size != 0 && second == NULL) || first_size > SIZE_MAX - second_size)
        return PLAMEN_BROKER_V2_INVALID;
    total = first_size + second_size;
    joined = malloc(total == 0 ? 1 : total);
    if (joined == NULL)
        return PLAMEN_BROKER_V2_NOMEM;
    if (first_size != 0)
        memcpy(joined, first, first_size);
    if (second_size != 0)
        memcpy(joined + first_size, second, second_size);
#ifdef __APPLE__
    CCHmac(kCCHmacAlgSHA256, key, 32, joined, total, out);
#else
    {
        unsigned length = 0;
        if (HMAC(EVP_sha256(), key, 32, joined, total, out, &length) == NULL
            || length != 32) {
            plamen_broker_v2_secure_zero(joined, total);
            free(joined);
            return PLAMEN_BROKER_V2_SYSTEM;
        }
    }
#endif
    plamen_broker_v2_secure_zero(joined, total);
    free(joined);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_specialized_session_binding(
    const uint8_t key[32], const uint8_t parent_session_id[32],
    const uint8_t specialized_session_id[32], uint16_t lane,
    const uint8_t authority_binding_sha256[32], uint8_t out[32])
{
    uint8_t binding[98];
    uint8_t key_nonzero = 0, parent_nonzero = 0;
    uint8_t specialized_nonzero = 0, authority_nonzero = 0;
    size_t index;
    int status;
    if (key == NULL || parent_session_id == NULL ||
            specialized_session_id == NULL ||
            authority_binding_sha256 == NULL || out == NULL ||
            lane < PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER ||
            lane > PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    for (index = 0; index < 32U; ++index) {
        key_nonzero |= key[index];
        parent_nonzero |= parent_session_id[index];
        specialized_nonzero |= specialized_session_id[index];
        authority_nonzero |= authority_binding_sha256[index];
    }
    if (key_nonzero == 0 || parent_nonzero == 0 ||
            specialized_nonzero == 0 || authority_nonzero == 0) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    memcpy(binding, parent_session_id, 32);
    memcpy(binding + 32, specialized_session_id, 32);
    memcpy(binding + 64, authority_binding_sha256, 32);
    binding[96] = (uint8_t)(lane >> 8);
    binding[97] = (uint8_t)lane;
    status = plamen_broker_v2_hmac_sha256(key,
        PLAMEN_BROKER_V2_SPECIALIZED_SESSION_BINDING_DOMAIN,
        sizeof(PLAMEN_BROKER_V2_SPECIALIZED_SESSION_BINDING_DOMAIN),
        binding, sizeof(binding), out);
    plamen_broker_v2_secure_zero(binding, sizeof(binding));
    return status;
}

static void
store_u16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void
store_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void
store_u64(uint8_t *out, uint64_t value)
{
    unsigned index;
    for (index = 0; index < 8; ++index)
        out[index] = (uint8_t)(value >> (56U - index * 8U));
}

static uint16_t
load_u16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | in[1]);
}

static uint32_t
load_u32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | in[3];
}

static uint64_t
load_u64(const uint8_t *in)
{
    uint64_t value = 0;
    unsigned index;
    for (index = 0; index < 8; ++index)
        value = (value << 8) | in[index];
    return value;
}

void
plamen_broker_v2_writer_init(struct plamen_broker_v2_writer *writer,
    uint8_t *data, size_t capacity)
{
    if (writer != NULL) {
        writer->data = data;
        writer->capacity = capacity;
        writer->offset = 0;
    }
}

void
plamen_broker_v2_reader_init(struct plamen_broker_v2_reader *reader,
    const uint8_t *data, size_t size)
{
    if (reader != NULL) {
        reader->data = data;
        reader->size = size;
        reader->offset = 0;
    }
}

static int
writer_reserve(struct plamen_broker_v2_writer *writer, size_t amount, uint8_t **out)
{
    if (writer == NULL || out == NULL || writer->data == NULL
        || writer->offset > writer->capacity
        || amount > writer->capacity - writer->offset)
        return PLAMEN_BROKER_V2_INVALID;
    *out = writer->data + writer->offset;
    writer->offset += amount;
    return PLAMEN_BROKER_V2_OK;
}

static int
reader_take(struct plamen_broker_v2_reader *reader, size_t amount,
    const uint8_t **out)
{
    if (reader == NULL || out == NULL || reader->data == NULL
        || reader->offset > reader->size || amount > reader->size - reader->offset)
        return PLAMEN_BROKER_V2_INVALID;
    *out = reader->data + reader->offset;
    reader->offset += amount;
    return PLAMEN_BROKER_V2_OK;
}

int plamen_broker_v2_put_u8(struct plamen_broker_v2_writer *w, uint8_t v)
{ uint8_t *p; if (writer_reserve(w, 1, &p) != 0) return -1; *p=v; return 0; }
int plamen_broker_v2_put_u16(struct plamen_broker_v2_writer *w, uint16_t v)
{ uint8_t *p; if (writer_reserve(w, 2, &p) != 0) return -1; store_u16(p,v); return 0; }
int plamen_broker_v2_put_u32(struct plamen_broker_v2_writer *w, uint32_t v)
{ uint8_t *p; if (writer_reserve(w, 4, &p) != 0) return -1; store_u32(p,v); return 0; }
int plamen_broker_v2_put_u64(struct plamen_broker_v2_writer *w, uint64_t v)
{ uint8_t *p; if (writer_reserve(w, 8, &p) != 0) return -1; store_u64(p,v); return 0; }
int plamen_broker_v2_put_bool(struct plamen_broker_v2_writer *w, int v)
{ return (v == 0 || v == 1) ? plamen_broker_v2_put_u8(w,(uint8_t)v) : -1; }

int
plamen_broker_v2_put_digest(struct plamen_broker_v2_writer *writer,
    const uint8_t digest[32])
{
    uint8_t *out;
    if (digest == NULL || writer_reserve(writer, 32, &out) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, digest, 32);
    return PLAMEN_BROKER_V2_OK;
}

static int
valid_id(const uint8_t *value, size_t size)
{
    size_t index;
    if (value == NULL || size == 0 || size > PLAMEN_BROKER_V2_MAX_ID)
        return 0;
    for (index = 0; index < size; ++index) {
        uint8_t c = value[index];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == ':'
            || c == '-'))
            return 0;
    }
    return 1;
}

static int
valid_utf8(const uint8_t *value, size_t size)
{
    size_t i = 0;
    if (value == NULL || size == 0 || size > PLAMEN_BROKER_V2_MAX_TEXT)
        return 0;
    while (i < size) {
        uint32_t cp;
        uint8_t c = value[i++];
        if (c == 0)
            return 0;
        if (c < 0x80)
            continue;
        if (c >= 0xc2 && c <= 0xdf) {
            if (i >= size || (value[i] & 0xc0) != 0x80) return 0;
            ++i; continue;
        }
        if (c >= 0xe0 && c <= 0xef) {
            if (i + 1 >= size || (value[i] & 0xc0) != 0x80
                || (value[i + 1] & 0xc0) != 0x80) return 0;
            cp = ((uint32_t)(c & 0x0f) << 12)
                | ((uint32_t)(value[i] & 0x3f) << 6) | (value[i + 1] & 0x3f);
            if (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
            i += 2; continue;
        }
        if (c >= 0xf0 && c <= 0xf4) {
            if (i + 2 >= size || (value[i] & 0xc0) != 0x80
                || (value[i + 1] & 0xc0) != 0x80
                || (value[i + 2] & 0xc0) != 0x80) return 0;
            cp = ((uint32_t)(c & 7) << 18)
                | ((uint32_t)(value[i] & 0x3f) << 12)
                | ((uint32_t)(value[i + 1] & 0x3f) << 6)
                | (value[i + 2] & 0x3f);
            if (cp < 0x10000 || cp > 0x10ffff) return 0;
            i += 3; continue;
        }
        return 0;
    }
    return 1;
}

int
plamen_broker_v2_put_id(struct plamen_broker_v2_writer *writer,
    const char *value, size_t size)
{
    uint8_t *out;
    if (!valid_id((const uint8_t *)value, size)
        || plamen_broker_v2_put_u16(writer, (uint16_t)size) != 0
        || writer_reserve(writer, size, &out) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value, size);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_put_text(struct plamen_broker_v2_writer *writer,
    const uint8_t *value, size_t size)
{
    uint8_t *out;
    if (!valid_utf8(value, size)
        || plamen_broker_v2_put_u32(writer, (uint32_t)size) != 0
        || writer_reserve(writer, size, &out) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value, size);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_put_bytes(struct plamen_broker_v2_writer *writer,
    const uint8_t *value, size_t size, size_t maximum)
{
    uint8_t *out;
    if (size > maximum || size > UINT32_MAX || (size != 0 && value == NULL)
        || plamen_broker_v2_put_u32(writer, (uint32_t)size) != 0
        || writer_reserve(writer, size, &out) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    if (size != 0) memcpy(out, value, size);
    return PLAMEN_BROKER_V2_OK;
}

int plamen_broker_v2_get_u8(struct plamen_broker_v2_reader *r, uint8_t *v)
{ const uint8_t *p; if(v==NULL||reader_take(r,1,&p)!=0)return -1; *v=*p;return 0; }
int plamen_broker_v2_get_u16(struct plamen_broker_v2_reader *r, uint16_t *v)
{ const uint8_t *p; if(v==NULL||reader_take(r,2,&p)!=0)return -1; *v=load_u16(p);return 0; }
int plamen_broker_v2_get_u32(struct plamen_broker_v2_reader *r, uint32_t *v)
{ const uint8_t *p; if(v==NULL||reader_take(r,4,&p)!=0)return -1; *v=load_u32(p);return 0; }
int plamen_broker_v2_get_u64(struct plamen_broker_v2_reader *r, uint64_t *v)
{ const uint8_t *p; if(v==NULL||reader_take(r,8,&p)!=0)return -1; *v=load_u64(p);return 0; }

int
plamen_broker_v2_get_bool(struct plamen_broker_v2_reader *reader, int *value)
{
    uint8_t raw;
    if (value == NULL || plamen_broker_v2_get_u8(reader, &raw) != 0 || raw > 1)
        return PLAMEN_BROKER_V2_INVALID;
    *value = raw;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_get_digest(struct plamen_broker_v2_reader *reader,
    uint8_t digest[32])
{
    const uint8_t *raw;
    if (digest == NULL || reader_take(reader, 32, &raw) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(digest, raw, 32);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_get_id(struct plamen_broker_v2_reader *reader,
    char *value, size_t capacity)
{
    uint16_t size;
    const uint8_t *raw;
    if (value == NULL || plamen_broker_v2_get_u16(reader, &size) != 0
        || capacity <= size || reader_take(reader, size, &raw) != 0
        || !valid_id(raw, size))
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(value, raw, size);
    value[size] = '\0';
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_get_text(struct plamen_broker_v2_reader *reader,
    const uint8_t **value, uint32_t *size)
{
    const uint8_t *raw;
    if (value == NULL || size == NULL || plamen_broker_v2_get_u32(reader, size) != 0
        || *size == 0 || *size > PLAMEN_BROKER_V2_MAX_TEXT
        || reader_take(reader, *size, &raw) != 0 || !valid_utf8(raw, *size))
        return PLAMEN_BROKER_V2_INVALID;
    *value = raw;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_get_bytes(struct plamen_broker_v2_reader *reader,
    const uint8_t **value, uint32_t *size, uint32_t maximum)
{
    if (value == NULL || size == NULL || plamen_broker_v2_get_u32(reader, size) != 0
        || *size > maximum || reader_take(reader, *size, value) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_encode_commitment(struct plamen_broker_v2_writer *writer,
    const struct plamen_broker_v2_commitment *value)
{
    if (writer == NULL || value == NULL
        || plamen_broker_v2_put_digest(writer, value->request_fingerprint) != 0
        || plamen_broker_v2_put_id(writer, value->attempt_id,
            strnlen(value->attempt_id, sizeof(value->attempt_id))) != 0
        || plamen_broker_v2_put_id(writer, value->run_identity,
            strnlen(value->run_identity, sizeof(value->run_identity))) != 0
        || plamen_broker_v2_put_digest(writer, value->config_sha256) != 0
        || plamen_broker_v2_put_digest(writer, value->runtime_closure_sha256) != 0
        || plamen_broker_v2_put_digest(writer, value->image_closure_sha256) != 0
        || plamen_broker_v2_put_digest(writer, value->provider_provenance_sha256) != 0
        || plamen_broker_v2_put_digest(writer, value->backend_admission_sha256) != 0
        || plamen_broker_v2_put_digest(writer, value->credential_isolation_sha256) != 0
        || plamen_broker_v2_put_digest(writer, value->egress_admission_sha256) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_decode_commitment_exact(const uint8_t *data, size_t size,
    struct plamen_broker_v2_commitment *value)
{
    struct plamen_broker_v2_reader reader;
    if (data == NULL || value == NULL)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    plamen_broker_v2_reader_init(&reader, data, size);
    if (plamen_broker_v2_get_digest(&reader, value->request_fingerprint) != 0
        || plamen_broker_v2_get_id(&reader, value->attempt_id,
            sizeof(value->attempt_id)) != 0
        || plamen_broker_v2_get_id(&reader, value->run_identity,
            sizeof(value->run_identity)) != 0
        || plamen_broker_v2_get_digest(&reader, value->config_sha256) != 0
        || plamen_broker_v2_get_digest(&reader, value->runtime_closure_sha256) != 0
        || plamen_broker_v2_get_digest(&reader, value->image_closure_sha256) != 0
        || plamen_broker_v2_get_digest(&reader, value->provider_provenance_sha256) != 0
        || plamen_broker_v2_get_digest(&reader, value->backend_admission_sha256) != 0
        || plamen_broker_v2_get_digest(&reader, value->credential_isolation_sha256) != 0
        || plamen_broker_v2_get_digest(&reader, value->egress_admission_sha256) != 0
        || reader.offset != reader.size) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

static int
known_type(uint16_t type)
{
    switch (type) {
    case PLAMEN_BROKER_V2_HELLO: case PLAMEN_BROKER_V2_AUTH_CONSUME:
    case PLAMEN_BROKER_V2_AUTH_ACCEPTED:
    case PLAMEN_BROKER_V2_REQUEST_PROJECTION:
    case PLAMEN_BROKER_V2_REQUEST_PROJECTED:
    case PLAMEN_BROKER_V2_CLI_PREPARE:
    case PLAMEN_BROKER_V2_CLI_COMMITTED: case PLAMEN_BROKER_V2_START_PREPARE:
    case PLAMEN_BROKER_V2_STARTED: case PLAMEN_BROKER_V2_START_RECOVER:
    case PLAMEN_BROKER_V2_WAIT_PREPARE: case PLAMEN_BROKER_V2_EXITED:
    case PLAMEN_BROKER_V2_WAIT_RECOVER: case PLAMEN_BROKER_V2_REVOKE_PREPARE:
    case PLAMEN_BROKER_V2_REVOKED:
    case PLAMEN_BROKER_V2_BACKEND_PREPARE:
    case PLAMEN_BROKER_V2_BACKEND_PREPARED:
    case PLAMEN_BROKER_V2_OUTPUT_READ: case PLAMEN_BROKER_V2_OUTPUT_CHUNK:
    case PLAMEN_BROKER_V2_OPERATION_CLOSE:
    case PLAMEN_BROKER_V2_OPERATION_FINISHED:
    case PLAMEN_BROKER_V2_OPERATION_REQUEST:
    case PLAMEN_BROKER_V2_OPERATION_RESPONSE:
    case PLAMEN_BROKER_V2_OPERATION_ERROR:
    case PLAMEN_BROKER_V2_WORKER_SESSION_OPEN:
    case PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED:
    case PLAMEN_BROKER_V2_ERROR:
        return 1;
    default: return 0;
    }
}

static int
type_from_extension(uint16_t type)
{
    return type == PLAMEN_BROKER_V2_AUTH_CONSUME
        || type == PLAMEN_BROKER_V2_REQUEST_PROJECTION
        || type == PLAMEN_BROKER_V2_CLI_PREPARE
        || type == PLAMEN_BROKER_V2_START_PREPARE
        || type == PLAMEN_BROKER_V2_START_RECOVER
        || type == PLAMEN_BROKER_V2_WAIT_PREPARE
        || type == PLAMEN_BROKER_V2_WAIT_RECOVER
        || type == PLAMEN_BROKER_V2_REVOKE_PREPARE
        || type == PLAMEN_BROKER_V2_BACKEND_PREPARE
        || type == PLAMEN_BROKER_V2_OUTPUT_READ
        || type == PLAMEN_BROKER_V2_OPERATION_CLOSE
        || type == PLAMEN_BROKER_V2_OPERATION_REQUEST
        || type == PLAMEN_BROKER_V2_WORKER_SESSION_OPEN;
}

static int
type_from_broker(uint16_t type)
{
    return type == PLAMEN_BROKER_V2_HELLO
        || type == PLAMEN_BROKER_V2_AUTH_ACCEPTED
        || type == PLAMEN_BROKER_V2_REQUEST_PROJECTED
        || type == PLAMEN_BROKER_V2_CLI_COMMITTED
        || type == PLAMEN_BROKER_V2_STARTED
        || type == PLAMEN_BROKER_V2_EXITED
        || type == PLAMEN_BROKER_V2_REVOKED
        || type == PLAMEN_BROKER_V2_BACKEND_PREPARED
        || type == PLAMEN_BROKER_V2_OUTPUT_CHUNK
        || type == PLAMEN_BROKER_V2_OPERATION_FINISHED
        || type == PLAMEN_BROKER_V2_OPERATION_RESPONSE
        || type == PLAMEN_BROKER_V2_OPERATION_ERROR
        || type == PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED;
}

static int
direction_valid(uint8_t local_role, uint16_t type, int sending)
{
    if (type == PLAMEN_BROKER_V2_ERROR)
        return 1;
    if (sending)
        return local_role == PLAMEN_BROKER_V2_ROLE_EXTENSION
            ? type_from_extension(type) : type_from_broker(type);
    return local_role == PLAMEN_BROKER_V2_ROLE_EXTENSION
        ? type_from_broker(type) : type_from_extension(type);
}

static int
all_zero(const uint8_t *data, size_t size)
{
    uint8_t result = 0;
    size_t index;
    for (index = 0; index < size; ++index) result |= data[index];
    return result == 0;
}

static int
nonce_valid(uint16_t type, const uint8_t nonce[32])
{
    int must_zero = type == PLAMEN_BROKER_V2_HELLO
        || type == PLAMEN_BROKER_V2_AUTH_CONSUME
        || type == PLAMEN_BROKER_V2_AUTH_ACCEPTED
        || type == PLAMEN_BROKER_V2_REQUEST_PROJECTION
        || type == PLAMEN_BROKER_V2_REQUEST_PROJECTED
        || type == PLAMEN_BROKER_V2_ERROR;
    return must_zero ? all_zero(nonce, 32) : !all_zero(nonce, 32);
}

static int
frame_state_valid(const struct plamen_broker_v2_session *session, uint16_t type)
{
    if (session == NULL) return 0;
    if (type == PLAMEN_BROKER_V2_ERROR) return session->hello_seen;
    if (type == PLAMEN_BROKER_V2_HELLO)
        return !session->hello_seen && session->next_sequence == 0;
    if (!session->hello_seen) return 0;
    if (type == PLAMEN_BROKER_V2_REQUEST_PROJECTION)
        return !session->authenticated && !session->auth_consumed
            && !session->projection_requested;
    if (type == PLAMEN_BROKER_V2_REQUEST_PROJECTED)
        return !session->authenticated && !session->auth_consumed
            && session->projection_requested;
    if (type == PLAMEN_BROKER_V2_AUTH_CONSUME)
        return session->projection_seen && !session->projection_requested
            && !session->authenticated && !session->auth_consumed;
    if (type == PLAMEN_BROKER_V2_AUTH_ACCEPTED)
        return session->auth_consumed && !session->authenticated;
    return session->authenticated;
}

static void
frame_state_advance(struct plamen_broker_v2_session *session, uint16_t type)
{
    if (type == PLAMEN_BROKER_V2_HELLO) session->hello_seen = 1;
    else if (type == PLAMEN_BROKER_V2_REQUEST_PROJECTION)
        session->projection_requested = 1;
    else if (type == PLAMEN_BROKER_V2_REQUEST_PROJECTED) {
        session->projection_requested = 0;
        session->projection_seen = 1;
    } else if (type == PLAMEN_BROKER_V2_AUTH_CONSUME) {
        session->auth_consumed = 1;
    } else if (type == PLAMEN_BROKER_V2_AUTH_ACCEPTED) {
        session->authenticated = 1;
    }
}

int
plamen_broker_v2_session_init(struct plamen_broker_v2_session *session,
    uint8_t role, const uint8_t key[32], const uint8_t session_id[32])
{
    if (session == NULL)
        return PLAMEN_BROKER_V2_INVALID;
    plamen_broker_v2_secure_zero(session, sizeof(*session));
    if (key == NULL || session_id == NULL
        || (role != PLAMEN_BROKER_V2_ROLE_EXTENSION
            && role != PLAMEN_BROKER_V2_ROLE_BROKER)
        || all_zero(key, 32) || all_zero(session_id, 32))
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(session->key, key, 32);
    memcpy(session->session_id, session_id, 32);
    session->role = role;
    return PLAMEN_BROKER_V2_OK;
}

void
plamen_broker_v2_session_burn(struct plamen_broker_v2_session *session)
{
    if (session != NULL) {
        plamen_broker_v2_secure_zero(session->key, sizeof(session->key));
        plamen_broker_v2_secure_zero(session->previous_frame_sha256,
            sizeof(session->previous_frame_sha256));
        plamen_broker_v2_secure_zero(session->session_id,
            sizeof(session->session_id));
        session->next_sequence = 0;
        session->burned = 1;
    }
}

static int
constant_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < size; ++index) difference |= left[index] ^ right[index];
    return difference == 0;
}

static int
commitment_binding_decode(const uint8_t *encoded, size_t size,
    const uint8_t expected_sha256[32], const uint8_t expected_fingerprint[32],
    struct plamen_broker_v2_commitment *value)
{
    uint8_t actual[32];
    int status;
    if (encoded == NULL || size == 0
        || size > PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE
        || expected_sha256 == NULL || expected_fingerprint == NULL
        || value == NULL || all_zero(expected_sha256, 32)
        || all_zero(expected_fingerprint, 32))
        return PLAMEN_BROKER_V2_INVALID;
    status = plamen_broker_v2_sha256(encoded, size, actual);
    if (status == 0 && !constant_equal(actual, expected_sha256, 32))
        status = PLAMEN_BROKER_V2_AUTH_FAILED;
    if (status == 0)
        status = plamen_broker_v2_decode_commitment_exact(encoded, size, value);
    if (status == 0 && !constant_equal(value->request_fingerprint,
            expected_fingerprint, 32))
        status = PLAMEN_BROKER_V2_AUTH_FAILED;
    if (status != 0) plamen_broker_v2_secure_zero(value, sizeof(*value));
    plamen_broker_v2_secure_zero(actual, sizeof(actual));
    return status;
}

#define PROJECTION_AUDIT_FIELD_COUNT 31U
#define PROJECTION_CONFIG_MAX_SIZE 262144U
#define PROJECTION_CONFIG_MAX_DEPTH 32U
#define PROJECTION_CONFIG_MAX_NODES 8192U
#define PROJECTION_ARTIFACT_MAX_COUNT 4096U
#define PROJECTION_ARTIFACT_MAX_SIZE 1024U

/*
 * This parser deliberately recognizes the closed request-projection schema,
 * rather than accepting a generic JSON value and trusting caller-provided
 * commitment bytes.  Operational identifiers and paths are ASCII by contract.
 * The current portable core rejects non-ASCII semantic text fail-closed; this
 * is a strict subset of NFC and avoids platform-dependent normalization.
 */
struct projection_parser {
    const uint8_t *data;
    size_t size;
    size_t offset;
    unsigned depth;
    unsigned nodes;
};

struct projection_span {
    size_t start;
    size_t end;
};

struct projection_roster {
    char **items;
    size_t count;
};

struct parsed_projection {
    struct projection_span values[PROJECTION_AUDIT_FIELD_COUNT];
    struct projection_span source_handle;
    struct projection_span source_sha;
    char attempt_id[PLAMEN_BROKER_V2_MAX_ID + 1U];
    char run_id[PLAMEN_BROKER_V2_MAX_ID + 1U];
    char request_type[16];
    char pipeline[8];
    char mode[16];
    char backend[16];
    char language[33];
    uint8_t source_config_sha256[32];
    uint8_t runtime_layout_sha256[32];
    uint8_t image_closure_sha256[32];
    uint8_t provider_provenance_sha256[32];
    uint8_t backend_admission_sha256[32];
    uint8_t credential_isolation_sha256[32];
    uint8_t egress_admission_sha256[32];
    struct projection_roster export_allowlist;
    struct projection_roster required_artifacts;
    struct projection_roster failure_required_artifacts;
};

static const char *const projection_audit_fields[PROJECTION_AUDIT_FIELD_COUNT] = {
    "attempt_id", "backend", "backend_admission_sha256",
    "backend_context_sha256", "credential_bundle_sha256",
    "credential_isolation_sha256", "docs_sha256",
    "egress_admission_sha256", "egress_policy_sha256", "export_allowlist",
    "export_destination_identity_sha256", "export_max_total_bytes",
    "failure_required_artifacts", "image_closure_sha256",
    "image_manifest_digest", "language", "mode", "pipeline",
    "provider_provenance_sha256", "request_id", "request_type",
    "required_artifacts", "run_id", "runtime_layout_sha256", "schema",
    "scope_sha256", "seccomp_profile_sha256", "source_config",
    "source_config_sha256", "startup_decision_receipt_sha256",
    "target_identity_sha256"
};

enum projection_audit_field_index {
    PF_ATTEMPT_ID = 0,
    PF_BACKEND = 1,
    PF_BACKEND_ADMISSION = 2,
    PF_CREDENTIAL_ISOLATION = 5,
    PF_EGRESS_ADMISSION = 7,
    PF_EXPORT_ALLOWLIST = 9,
    PF_EXPORT_MAX_TOTAL_BYTES = 11,
    PF_FAILURE_REQUIRED_ARTIFACTS = 12,
    PF_IMAGE_CLOSURE = 13,
    PF_LANGUAGE = 15,
    PF_MODE = 16,
    PF_PIPELINE = 17,
    PF_PROVIDER_PROVENANCE = 18,
    PF_REQUEST_ID = 19,
    PF_REQUEST_TYPE = 20,
    PF_REQUIRED_ARTIFACTS = 21,
    PF_RUN_ID = 22,
    PF_RUNTIME_LAYOUT = 23,
    PF_SCHEMA = 24,
    PF_SOURCE_CONFIG = 27,
    PF_SOURCE_CONFIG_SHA = 28
};

static void
projection_roster_destroy(struct projection_roster *roster)
{
    size_t index;
    if (roster == NULL) return;
    for (index = 0; index < roster->count; ++index) free(roster->items[index]);
    free(roster->items);
    roster->items = NULL;
    roster->count = 0;
}

static void
parsed_projection_destroy(struct parsed_projection *value)
{
    if (value == NULL) return;
    projection_roster_destroy(&value->export_allowlist);
    projection_roster_destroy(&value->required_artifacts);
    projection_roster_destroy(&value->failure_required_artifacts);
    plamen_broker_v2_secure_zero(value, sizeof(*value));
}

static int
projection_take(struct projection_parser *parser, uint8_t value)
{
    if (parser == NULL || parser->offset >= parser->size
        || parser->data[parser->offset] != value)
        return -1;
    ++parser->offset;
    return 0;
}

static int
projection_literal(struct projection_parser *parser, const char *literal)
{
    size_t size = strlen(literal);
    if (parser == NULL || parser->size - parser->offset < size
        || memcmp(parser->data + parser->offset, literal, size) != 0)
        return -1;
    parser->offset += size;
    return 0;
}

static int
projection_hex_digit(uint8_t value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

/* JSON string decoder for the fail-closed portable ASCII semantic profile. */
static int
projection_string(struct projection_parser *parser, char *out, size_t capacity,
    size_t maximum, int controls_allowed, struct projection_span *span)
{
    size_t used = 0, start;
    uint8_t value;
    if (parser == NULL || out == NULL || capacity == 0
        || projection_take(parser, '"') != 0)
        return -1;
    start = parser->offset - 1;
    while (parser->offset < parser->size) {
        value = parser->data[parser->offset++];
        if (value == '"') {
            if (used == 0 || used > maximum || used >= capacity) return -1;
            out[used] = '\0';
            if (span != NULL) {
                span->start = start;
                span->end = parser->offset;
            }
            return 0;
        }
        if (value >= 0x80 || value == 0 || value < 0x20) return -1;
        if (value == '\\') {
            if (parser->offset >= parser->size) return -1;
            value = parser->data[parser->offset++];
            if (value != '"' && value != '\\') {
                if (!controls_allowed) return -1;
                switch (value) {
                case 'b': value = '\b'; break;
                case 'f': value = '\f'; break;
                case 'n': value = '\n'; break;
                case 'r': value = '\r'; break;
                case 't': value = '\t'; break;
                default: return -1;
                }
            }
        }
        if (!controls_allowed && value < 0x20) return -1;
        if (used >= maximum || used + 1 >= capacity) return -1;
        out[used++] = (char)value;
    }
    return -1;
}

static int
projection_exact_string(struct projection_parser *parser, const char *expected)
{
    char value[PLAMEN_BROKER_V2_MAX_TEXT + 1U];
    return projection_string(parser, value, sizeof(value),
            PLAMEN_BROKER_V2_MAX_TEXT, 0, NULL) == 0
        && strcmp(value, expected) == 0 ? 0 : -1;
}

static int
projection_identifier(struct projection_parser *parser, char *out,
    size_t capacity, struct projection_span *span)
{
    size_t index;
    if (projection_string(parser, out, capacity, PLAMEN_BROKER_V2_MAX_ID,
            0, span) != 0
        || !((out[0] >= 'A' && out[0] <= 'Z')
            || (out[0] >= 'a' && out[0] <= 'z')
            || (out[0] >= '0' && out[0] <= '9')))
        return -1;
    for (index = 1; out[index] != '\0'; ++index) {
        if (!((out[index] >= 'A' && out[index] <= 'Z')
            || (out[index] >= 'a' && out[index] <= 'z')
            || (out[index] >= '0' && out[index] <= '9')
            || out[index] == '_' || out[index] == '.' || out[index] == ':'
            || out[index] == '-'))
            return -1;
    }
    return 0;
}

static int
projection_digest(struct projection_parser *parser, uint8_t out[32],
    int oci, struct projection_span *span)
{
    char value[72];
    size_t index, prefix = oci ? 7U : 0U;
    int high, low;
    if (projection_string(parser, value, sizeof(value), 71U, 0, span) != 0
        || strlen(value) != 64U + prefix
        || (oci && memcmp(value, "sha256:", 7) != 0))
        return -1;
    for (index = 0; index < 32; ++index) {
        high = projection_hex_digit((uint8_t)value[prefix + index * 2]);
        low = projection_hex_digit((uint8_t)value[prefix + index * 2 + 1]);
        if (high < 0 || low < 0) return -1;
        if (out != NULL) out[index] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int
projection_u64(struct projection_parser *parser, uint64_t *out,
    uint64_t maximum)
{
    uint64_t value = 0;
    size_t start;
    if (parser == NULL || out == NULL || parser->offset >= parser->size)
        return -1;
    start = parser->offset;
    if (parser->data[parser->offset] == '0') {
        ++parser->offset;
        if (parser->offset < parser->size
            && parser->data[parser->offset] >= '0'
            && parser->data[parser->offset] <= '9')
            return -1;
    } else {
        if (parser->data[parser->offset] < '1'
            || parser->data[parser->offset] > '9')
            return -1;
        while (parser->offset < parser->size
            && parser->data[parser->offset] >= '0'
            && parser->data[parser->offset] <= '9') {
            unsigned digit = parser->data[parser->offset++] - '0';
            if (value > (maximum - digit) / 10U) return -1;
            value = value * 10U + digit;
        }
    }
    if (parser->offset == start || value == 0 || value > maximum) return -1;
    *out = value;
    return 0;
}

static int
projection_artifact_valid(const char *path)
{
    const char *part, *slash;
    size_t length;
    if (path == NULL || path[0] == '\0' || path[0] == '/'
        || path[0] == '~' || strchr(path, '\\') != NULL
        || strchr(path, ':') != NULL)
        return 0;
    length = strlen(path);
    if (length > PROJECTION_ARTIFACT_MAX_SIZE || path[length - 1] == '/')
        return 0;
    part = path;
    while (part != NULL) {
        slash = strchr(part, '/');
        length = slash == NULL ? strlen(part) : (size_t)(slash - part);
        if (length == 0 || (length == 1 && part[0] == '.')
            || (length == 2 && part[0] == '.' && part[1] == '.'))
            return 0;
        part = slash == NULL ? NULL : slash + 1;
    }
    return 1;
}

static int
projection_ascii_casecmp(const char *left, const char *right)
{
    unsigned char a, b;
    while (*left != '\0' && *right != '\0') {
        a = (unsigned char)*left++;
        b = (unsigned char)*right++;
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + ('a' - 'A'));
        if (a != b) return a < b ? -1 : 1;
    }
    return *left == *right ? 0 : (*left == '\0' ? -1 : 1);
}

static int
projection_casefold_compare(const void *left, const void *right)
{
    return projection_ascii_casecmp(*(const char *const *)left,
        *(const char *const *)right);
}

static int
projection_roster_alias_free(const struct projection_roster *roster)
{
    char **ordered;
    size_t index, length;
    int result = 0;
    if (roster == NULL || roster->count == 0) return 0;
    ordered = malloc(roster->count * sizeof(*ordered));
    if (ordered == NULL) return 0;
    memcpy(ordered, roster->items, roster->count * sizeof(*ordered));
    qsort(ordered, roster->count, sizeof(*ordered), projection_casefold_compare);
    for (index = 1; index < roster->count; ++index) {
        length = strlen(ordered[index - 1]);
        if (projection_ascii_casecmp(ordered[index - 1], ordered[index]) == 0
            || (strlen(ordered[index]) > length
                && ordered[index][length] == '/'
                && strncasecmp(ordered[index - 1], ordered[index], length) == 0))
            goto done;
    }
    result = 1;
done:
    free(ordered);
    return result;
}

static int
projection_roster_parse(struct projection_parser *parser,
    struct projection_roster *roster)
{
    char value[PROJECTION_ARTIFACT_MAX_SIZE + 1U];
    char **grown;
    size_t capacity = 0;
    if (projection_take(parser, '[') != 0) return -1;
    while (parser->offset < parser->size
        && parser->data[parser->offset] != ']') {
        if (roster->count != 0 && projection_take(parser, ',') != 0) return -1;
        if (projection_string(parser, value, sizeof(value),
                PROJECTION_ARTIFACT_MAX_SIZE, 0, NULL) != 0
            || !projection_artifact_valid(value)
            || (roster->count != 0
                && strcmp(roster->items[roster->count - 1], value) >= 0)
            || roster->count == PROJECTION_ARTIFACT_MAX_COUNT)
            return -1;
        if (roster->count == capacity) {
            capacity = capacity == 0 ? 16U : capacity * 2U;
            grown = realloc(roster->items, capacity * sizeof(*grown));
            if (grown == NULL) return -1;
            roster->items = grown;
        }
        roster->items[roster->count] = strdup(value);
        if (roster->items[roster->count] == NULL) return -1;
        ++roster->count;
    }
    return roster->count != 0 && projection_take(parser, ']') == 0
        && projection_roster_alias_free(roster) ? 0 : -1;
}

static int
projection_roster_contains(const struct projection_roster *roster,
    const char *value)
{
    size_t low = 0, high = roster->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        int comparison = strcmp(roster->items[middle], value);
        if (comparison < 0) low = middle + 1U;
        else if (comparison > 0) high = middle;
        else return 1;
    }
    return 0;
}

static int
projection_rosters_valid(const struct parsed_projection *value)
{
    size_t index;
    for (index = 0; index < value->export_allowlist.count; ++index) {
        const char *path = value->export_allowlist.items[index];
        if (strncmp(path, "project/", 8) != 0
            && strncmp(path, "scratch/", 8) != 0)
            return 0;
    }
    for (index = 0; index < value->required_artifacts.count; ++index)
        if (!projection_roster_contains(&value->export_allowlist,
                value->required_artifacts.items[index]))
            return 0;
    for (index = 0; index < value->failure_required_artifacts.count; ++index)
        if (!projection_roster_contains(&value->export_allowlist,
                value->failure_required_artifacts.items[index]))
            return 0;
    return projection_roster_contains(&value->required_artifacts,
            "project/AUDIT_REPORT.md")
        && projection_roster_contains(&value->required_artifacts,
            "scratch/_v2_checkpoint.json")
        && projection_roster_contains(&value->failure_required_artifacts,
            "scratch/_plamen.log");
}

static int config_value(struct projection_parser *, unsigned);

static int
config_string(struct projection_parser *parser, char *out, size_t capacity,
    size_t maximum, int key)
{
    size_t used = 0;
    uint8_t value;
    int high, low;
    if (projection_take(parser, '"') != 0) return -1;
    while (parser->offset < parser->size) {
        value = parser->data[parser->offset++];
        if (value == '"') {
            if ((key && used == 0) || used > maximum || used >= capacity)
                return -1;
            out[used] = '\0';
            return 0;
        }
        if (value >= 0x80 || value == 0 || value < 0x20) return -1;
        if (value == '\\') {
            if (parser->offset >= parser->size) return -1;
            value = parser->data[parser->offset++];
            switch (value) {
            case '"': case '\\': break;
            case 'b': value = '\b'; break;
            case 'f': value = '\f'; break;
            case 'n': value = '\n'; break;
            case 'r': value = '\r'; break;
            case 't': value = '\t'; break;
            case 'u':
                if (parser->size - parser->offset < 4
                    || parser->data[parser->offset] != '0'
                    || parser->data[parser->offset + 1] != '0')
                    return -1;
                high = projection_hex_digit(parser->data[parser->offset + 2]);
                low = projection_hex_digit(parser->data[parser->offset + 3]);
                if (high < 0 || low < 0) return -1;
                value = (uint8_t)((high << 4) | low);
                parser->offset += 4;
                if (value == 0 || value >= 0x20
                    || value == '\b' || value == '\t' || value == '\n'
                    || value == '\f' || value == '\r')
                    return -1;
                break;
            default: return -1;
            }
        }
        if (key && value < 0x20) return -1;
        if (used >= maximum || used + 1 >= capacity) return -1;
        out[used++] = (char)value;
    }
    return -1;
}

static int
config_integer(struct projection_parser *parser)
{
    size_t start = parser->offset, digits;
    uint64_t magnitude = 0, limit;
    int negative = 0;
    if (parser->offset < parser->size && parser->data[parser->offset] == '-') {
        negative = 1;
        ++parser->offset;
    }
    if (parser->offset >= parser->size) return -1;
    if (parser->data[parser->offset] == '0') {
        ++parser->offset;
        if (parser->offset < parser->size
            && parser->data[parser->offset] >= '0'
            && parser->data[parser->offset] <= '9')
            return -1;
    } else {
        if (parser->data[parser->offset] < '1'
            || parser->data[parser->offset] > '9')
            return -1;
        limit = negative ? UINT64_C(9223372036854775808)
            : UINT64_C(9223372036854775807);
        while (parser->offset < parser->size
            && parser->data[parser->offset] >= '0'
            && parser->data[parser->offset] <= '9') {
            unsigned digit = parser->data[parser->offset++] - '0';
            if (magnitude > (limit - digit) / 10U) return -1;
            magnitude = magnitude * 10U + digit;
        }
    }
    digits = parser->offset - start;
    return digits <= 19U && !(negative && magnitude == 0) ? 0 : -1;
}

static int
config_array(struct projection_parser *parser, unsigned depth)
{
    if (projection_take(parser, '[') != 0) return -1;
    if (parser->offset < parser->size && parser->data[parser->offset] == ']') {
        ++parser->offset;
        return 0;
    }
    for (;;) {
        if (config_value(parser, depth + 1U) != 0) return -1;
        if (parser->offset >= parser->size) return -1;
        if (parser->data[parser->offset] == ']') {
            ++parser->offset;
            return 0;
        }
        if (projection_take(parser, ',') != 0) return -1;
    }
}

static int
config_object(struct projection_parser *parser, unsigned depth)
{
    char key[257], previous[257] = {0};
    int first = 1;
    if (projection_take(parser, '{') != 0) return -1;
    if (parser->offset < parser->size && parser->data[parser->offset] == '}') {
        ++parser->offset;
        return 0;
    }
    for (;;) {
        if (!first && projection_take(parser, ',') != 0) return -1;
        if (config_string(parser, key, sizeof(key), 256U, 1) != 0
            || (!first && strcmp(previous, key) >= 0)
            || projection_take(parser, ':') != 0)
            return -1;
        strcpy(previous, key);
        if (config_value(parser, depth + 1U) != 0) return -1;
        if (parser->offset >= parser->size) return -1;
        if (parser->data[parser->offset] == '}') {
            ++parser->offset;
            return 0;
        }
        first = 0;
    }
}

static int
config_value(struct projection_parser *parser, unsigned depth)
{
    char text[PLAMEN_BROKER_V2_MAX_TEXT + 1U];
    if (parser == NULL || depth > PROJECTION_CONFIG_MAX_DEPTH
        || ++parser->nodes > PROJECTION_CONFIG_MAX_NODES
        || parser->offset >= parser->size)
        return -1;
    switch (parser->data[parser->offset]) {
    case '{': return config_object(parser, depth);
    case '[': return config_array(parser, depth);
    case '"': return config_string(parser, text, sizeof(text),
        PLAMEN_BROKER_V2_MAX_TEXT, 0);
    case 't': return projection_literal(parser, "true");
    case 'f': return projection_literal(parser, "false");
    case 'n': return projection_literal(parser, "null");
    default: return config_integer(parser);
    }
}

struct config_route {
    char pipeline[8];
    char mode[16];
    char backend[16];
    char language[33];
    char run_id[PLAMEN_BROKER_V2_MAX_ID + 1U];
    unsigned required;
};

static int
config_guest_path(const char *path, const char *exact, const char *prefix)
{
    size_t length;
    if (path == NULL || path[0] != '/' || path[1] == '/' || strchr(path, '\\')
        || (exact != NULL && strcmp(path, exact) != 0))
        return 0;
    length = strlen(path);
    if (length > 1 && path[length - 1] == '/') return 0;
    if (prefix != NULL && strncmp(path, prefix, strlen(prefix)) != 0) return 0;
    return strstr(path, "/./") == NULL && strstr(path, "/../") == NULL
        && strcmp(path + (length >= 2 ? length - 2 : 0), "/.") != 0
        && strcmp(path + (length >= 3 ? length - 3 : 0), "/..") != 0;
}

static int
config_docs_inputs(struct projection_parser *parser)
{
    char path[PLAMEN_BROKER_V2_MAX_TEXT + 1U];
    char **items = NULL, **grown;
    size_t count = 0, capacity = 0, index;
    int result = -1;
    if (parser->offset < parser->size && parser->data[parser->offset] == 'n')
        return projection_literal(parser, "null");
    if (projection_take(parser, '[') != 0) return -1;
    while (parser->offset < parser->size && parser->data[parser->offset] != ']') {
        if (count != 0 && projection_take(parser, ',') != 0) goto done;
        if (config_string(parser, path, sizeof(path), PLAMEN_BROKER_V2_MAX_TEXT,
                0) != 0
            || !config_guest_path(path, NULL, "/workspace/docs/"))
            goto done;
        for (index = 0; index < count; ++index)
            if (projection_ascii_casecmp(items[index], path) == 0) goto done;
        if (count == capacity) {
            capacity = capacity == 0 ? 8U : capacity * 2U;
            grown = realloc(items, capacity * sizeof(*grown));
            if (grown == NULL) goto done;
            items = grown;
        }
        items[count] = strdup(path);
        if (items[count] == NULL) goto done;
        ++count;
    }
    if (count != 0 && projection_take(parser, ']') == 0) result = 0;
done:
    for (index = 0; index < count; ++index) free(items[index]);
    free(items);
    return result;
}

static int
config_top_object(struct projection_parser *parser, struct config_route *route)
{
    char key[257], previous[257] = {0};
    char value[PLAMEN_BROKER_V2_MAX_TEXT + 1U];
    int first = 1;
    if (projection_take(parser, '{') != 0) return -1;
    while (parser->offset < parser->size && parser->data[parser->offset] != '}') {
        if (!first && projection_take(parser, ',') != 0) return -1;
        if (config_string(parser, key, sizeof(key), 256U, 1) != 0
            || (!first && strcmp(previous, key) >= 0)
            || strcmp(key, "backend") == 0
            || projection_take(parser, ':') != 0)
            return -1;
        strcpy(previous, key);
        if (strcmp(key, "pipeline") == 0 || strcmp(key, "mode") == 0
            || strcmp(key, "cli_backend") == 0 || strcmp(key, "language") == 0
            || strcmp(key, "_run_id") == 0 || strcmp(key, "project_root") == 0
            || strcmp(key, "scratchpad") == 0 || strcmp(key, "docs_path") == 0
            || strcmp(key, "scope_file") == 0) {
            if ((strcmp(key, "docs_path") == 0 || strcmp(key, "scope_file") == 0)
                && parser->offset < parser->size
                && parser->data[parser->offset] == 'n') {
                if (projection_literal(parser, "null") != 0) return -1;
            } else if (config_string(parser, value, sizeof(value),
                    PLAMEN_BROKER_V2_MAX_TEXT, 0) != 0) {
                return -1;
            } else if (strcmp(key, "pipeline") == 0) {
                if (strlen(value) >= sizeof(route->pipeline)) return -1;
                strcpy(route->pipeline, value); route->required |= 1U;
            } else if (strcmp(key, "mode") == 0) {
                if (strlen(value) >= sizeof(route->mode)) return -1;
                strcpy(route->mode, value); route->required |= 2U;
            } else if (strcmp(key, "cli_backend") == 0) {
                if (strlen(value) >= sizeof(route->backend)) return -1;
                strcpy(route->backend, value); route->required |= 4U;
            } else if (strcmp(key, "language") == 0) {
                if (strlen(value) == 0 || strlen(value) >= sizeof(route->language))
                    return -1;
                strcpy(route->language, value); route->required |= 8U;
            } else if (strcmp(key, "_run_id") == 0) {
                if (strlen(value) >= sizeof(route->run_id)) return -1;
                strcpy(route->run_id, value); route->required |= 16U;
            } else if (strcmp(key, "project_root") == 0) {
                if (!config_guest_path(value, "/workspace/project", NULL)) return -1;
                route->required |= 32U;
            } else if (strcmp(key, "scratchpad") == 0) {
                if (!config_guest_path(value, "/workspace/scratch", NULL)) return -1;
                route->required |= 64U;
            } else if (strcmp(key, "docs_path") == 0) {
                if (value[0] != '\0'
                    && !config_guest_path(value, "/workspace/docs", NULL)) return -1;
            } else if (strcmp(key, "scope_file") == 0) {
                if (value[0] != '\0'
                    && !config_guest_path(value, "/workspace/scope", NULL)) return -1;
            }
        } else if (strcmp(key, "docs_inputs") == 0) {
            if (config_docs_inputs(parser) != 0) return -1;
        } else if (config_value(parser, 1U) != 0) {
            return -1;
        }
        first = 0;
    }
    return route->required == 127U && projection_take(parser, '}') == 0 ? 0 : -1;
}

static int
projection_base64_value(struct projection_parser *parser, uint8_t **decoded,
    size_t *decoded_size, struct projection_span *span)
{
    static const int8_t table[80] = {
        62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
        -1, -1, -1, -2, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
        51
    };
    size_t start, encoded_size, index, output = 0;
    uint8_t *bytes;
    int a, b, c, d;
    if (projection_take(parser, '"') != 0) return -1;
    start = parser->offset;
    while (parser->offset < parser->size
        && parser->data[parser->offset] != '"') {
        uint8_t ch = parser->data[parser->offset++];
        if (ch < '+' || ch > 'z' || table[ch - '+'] == -1) return -1;
    }
    encoded_size = parser->offset - start;
    if (encoded_size == 0 || encoded_size % 4U != 0
        || projection_take(parser, '"') != 0
        || encoded_size / 4U * 3U > PROJECTION_CONFIG_MAX_SIZE + 2U)
        return -1;
    bytes = malloc(encoded_size / 4U * 3U);
    if (bytes == NULL) return -1;
    for (index = 0; index < encoded_size; index += 4U) {
        uint8_t ca = parser->data[start + index];
        uint8_t cb = parser->data[start + index + 1U];
        uint8_t cc = parser->data[start + index + 2U];
        uint8_t cd = parser->data[start + index + 3U];
        a = table[ca - '+']; b = table[cb - '+'];
        c = table[cc - '+']; d = table[cd - '+'];
        if (a < 0 || b < 0 || (c == -2 && d != -2)
            || (index + 4U != encoded_size && (c < 0 || d < 0))
            || c == -1 || d == -1
            || (c == -2 && (b & 15) != 0)
            || (d == -2 && c >= 0 && (c & 3) != 0)) {
            free(bytes); return -1;
        }
        bytes[output++] = (uint8_t)((a << 2) | (b >> 4));
        if (c >= 0) {
            bytes[output++] = (uint8_t)((b << 4) | (c >> 2));
            if (d >= 0) bytes[output++] = (uint8_t)((c << 6) | d);
        }
    }
    if (output < 2U || output > PROJECTION_CONFIG_MAX_SIZE) {
        free(bytes); return -1;
    }
    if (span != NULL) { span->start = start - 1U; span->end = parser->offset; }
    *decoded = bytes;
    *decoded_size = output;
    return 0;
}

static int
projection_source_config(struct projection_parser *parser,
    struct parsed_projection *value)
{
    uint8_t *config = NULL, digest[32];
    size_t config_size = 0;
    struct projection_span ignored;
    struct config_route route;
    struct projection_parser config_parser;
    char handle[72];
    int result = -1;
    memset(&route, 0, sizeof(route));
    if (projection_literal(parser, "{\"authenticated\":true,\"canonical_utf8_b64\":") != 0
        || projection_base64_value(parser, &config, &config_size, &ignored) != 0
        || projection_literal(parser, ",\"retained_source_handle\":") != 0
        || projection_string(parser, handle, sizeof(handle), 71U, 0,
            &value->source_handle) != 0
        || strlen(handle) != 71U || memcmp(handle, "opaque:", 7) != 0
        || projection_literal(parser, ",\"sha256\":") != 0
        || projection_digest(parser, value->source_config_sha256, 0,
            &value->source_sha) != 0
        || projection_take(parser, '}') != 0
        || plamen_broker_v2_sha256(config, config_size, digest) != 0
        || !constant_equal(digest, value->source_config_sha256, 32)
        || config_size < 3U || config[config_size - 1U] != '\n')
        goto done;
    for (size_t index = 7; index < 71U; ++index)
        if (projection_hex_digit((uint8_t)handle[index]) < 0) goto done;
    memset(&config_parser, 0, sizeof(config_parser));
    config_parser.data = config;
    config_parser.size = config_size - 1U;
    config_parser.nodes = 1U;
    if (config_top_object(&config_parser, &route) != 0
        || config_parser.offset != config_parser.size
        || strcmp(route.pipeline, value->pipeline) != 0
        || strcmp(route.mode, value->mode) != 0
        || strcmp(route.backend, value->backend) != 0
        || strcmp(route.language, value->language) != 0
        || strcmp(route.run_id, value->run_id) != 0)
        goto done;
    result = 0;
done:
    if (config != NULL) {
        plamen_broker_v2_secure_zero(config, config_size);
        free(config);
    }
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return result;
}

static int
projection_audit_value(struct projection_parser *parser, unsigned index,
    struct parsed_projection *value)
{
    uint8_t digest[32];
    uint64_t integer;
    char text[PLAMEN_BROKER_V2_MAX_TEXT + 1U];
    int result = -1;
    switch (index) {
    case PF_ATTEMPT_ID:
        return projection_identifier(parser, value->attempt_id,
            sizeof(value->attempt_id), NULL);
    case PF_BACKEND:
        if (projection_string(parser, value->backend, sizeof(value->backend),
                sizeof(value->backend) - 1U, 0, NULL) == 0
            && (strcmp(value->backend, "codex") == 0
                || strcmp(value->backend, "claude") == 0)) return 0;
        return -1;
    case PF_BACKEND_ADMISSION:
        return projection_digest(parser, value->backend_admission_sha256, 0, NULL);
    case PF_CREDENTIAL_ISOLATION:
        return projection_digest(parser, value->credential_isolation_sha256, 0,
            NULL);
    case PF_EGRESS_ADMISSION:
        return projection_digest(parser, value->egress_admission_sha256, 0, NULL);
    case PF_EXPORT_ALLOWLIST:
        return projection_roster_parse(parser, &value->export_allowlist);
    case PF_EXPORT_MAX_TOTAL_BYTES:
        return projection_u64(parser, &integer, UINT64_C(2147483648));
    case PF_FAILURE_REQUIRED_ARTIFACTS:
        return projection_roster_parse(parser, &value->failure_required_artifacts);
    case PF_IMAGE_CLOSURE:
        return projection_digest(parser, value->image_closure_sha256, 0, NULL);
    case PF_LANGUAGE:
        return projection_string(parser, value->language, sizeof(value->language),
            32U, 0, NULL);
    case PF_MODE:
        if (projection_string(parser, value->mode, sizeof(value->mode),
                sizeof(value->mode) - 1U, 0, NULL) == 0
            && (strcmp(value->mode, "light") == 0
                || strcmp(value->mode, "core") == 0
                || strcmp(value->mode, "thorough") == 0)) return 0;
        return -1;
    case PF_PIPELINE:
        if (projection_string(parser, value->pipeline, sizeof(value->pipeline),
                sizeof(value->pipeline) - 1U, 0, NULL) == 0
            && (strcmp(value->pipeline, "sc") == 0
                || strcmp(value->pipeline, "l1") == 0)) return 0;
        return -1;
    case PF_PROVIDER_PROVENANCE:
        return projection_digest(parser, value->provider_provenance_sha256, 0,
            NULL);
    case PF_REQUEST_ID:
        return projection_identifier(parser, text, sizeof(text), NULL);
    case PF_REQUEST_TYPE:
        if (projection_string(parser, value->request_type,
                sizeof(value->request_type), sizeof(value->request_type) - 1U,
                0, NULL) == 0
            && (strcmp(value->request_type, "SC_NEW") == 0
                || strcmp(value->request_type, "L1_NEW") == 0
                || strcmp(value->request_type, "START_CONFIG") == 0
                || strcmp(value->request_type, "RESUME") == 0)) return 0;
        return -1;
    case PF_REQUIRED_ARTIFACTS:
        return projection_roster_parse(parser, &value->required_artifacts);
    case PF_RUN_ID:
        return projection_identifier(parser, value->run_id,
            sizeof(value->run_id), NULL);
    case PF_RUNTIME_LAYOUT:
        return projection_digest(parser, value->runtime_layout_sha256, 0, NULL);
    case PF_SCHEMA:
        return projection_exact_string(parser, PLAMEN_BROKER_V2_AUDIT_REQUEST_SCHEMA);
    case PF_SOURCE_CONFIG:
        return projection_source_config(parser, value);
    case PF_SOURCE_CONFIG_SHA:
        result = projection_digest(parser, digest, 0, NULL);
        if (result == 0 && !constant_equal(digest,
                value->source_config_sha256, 32)) result = -1;
        plamen_broker_v2_secure_zero(digest, sizeof(digest));
        return result;
    case 14: /* image_manifest_digest */
        return projection_digest(parser, digest, 1, NULL);
    default:
        return projection_digest(parser, digest, 0, NULL);
    }
}

static int
projection_fingerprint(const struct projection_parser *parser,
    const struct parsed_projection *value, uint8_t out[32])
{
    struct digest_context context;
    static const uint8_t colon = ':', comma = ',', open = '{', close_lf[] = "}\n";
    unsigned index;
    int status = -1;
    memset(&context, 0, sizeof(context));
    if (digest_init(&context) != 0) return PLAMEN_BROKER_V2_SYSTEM;
    if (digest_update(&context, &open, 1) != 0) goto done;
    for (index = 0; index < PROJECTION_AUDIT_FIELD_COUNT; ++index) {
        const char *key = projection_audit_fields[index];
        if ((index != 0 && digest_update(&context, &comma, 1) != 0)
            || digest_update(&context, "\"", 1) != 0
            || digest_update(&context, key, strlen(key)) != 0
            || digest_update(&context, "\"", 1) != 0
            || digest_update(&context, &colon, 1) != 0)
            goto done;
        if (index == PF_SOURCE_CONFIG) {
            static const char prefix[] = "{\"authenticated\":true,\"retained_source_handle\":";
            static const char middle[] = ",\"sha256\":";
            if (digest_update(&context, prefix, sizeof(prefix) - 1U) != 0
                || digest_update(&context,
                    parser->data + value->source_handle.start,
                    value->source_handle.end - value->source_handle.start) != 0
                || digest_update(&context, middle, sizeof(middle) - 1U) != 0
                || digest_update(&context, parser->data + value->source_sha.start,
                    value->source_sha.end - value->source_sha.start) != 0
                || digest_update(&context, "}", 1) != 0)
                goto done;
        } else if (digest_update(&context,
                parser->data + value->values[index].start,
                value->values[index].end - value->values[index].start) != 0) {
            goto done;
        }
    }
    if (digest_update(&context, close_lf, sizeof(close_lf) - 1U) != 0
        || digest_final(&context, out) != 0)
        goto done;
    status = 0;
done:
    if (status != 0) digest_destroy(&context);
    return status;
}

static int
projection_parse_derive(const uint8_t *projection, size_t size,
    struct plamen_broker_v2_commitment *commitment)
{
    struct projection_parser parser;
    struct parsed_projection value;
    unsigned index;
    int status = PLAMEN_BROKER_V2_INVALID;
    memset(&parser, 0, sizeof(parser));
    memset(&value, 0, sizeof(value));
    parser.data = projection;
    parser.size = size;
    if (projection_literal(&parser, "{\"audit_request\":{") != 0) goto done;
    for (index = 0; index < PROJECTION_AUDIT_FIELD_COUNT; ++index) {
        if ((index != 0 && projection_take(&parser, ',') != 0)
            || projection_take(&parser, '"') != 0
            || projection_literal(&parser, projection_audit_fields[index]) != 0
            || projection_literal(&parser, "\":") != 0)
            goto done;
        value.values[index].start = parser.offset;
        if (projection_audit_value(&parser, index, &value) != 0) goto done;
        value.values[index].end = parser.offset;
    }
    if (projection_literal(&parser, "},\"projection_schema\":") != 0
        || projection_exact_string(&parser,
            PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA) != 0
        || projection_take(&parser, '}') != 0 || parser.offset != parser.size
        || !projection_rosters_valid(&value)
        || (strcmp(value.request_type, "SC_NEW") == 0
            && strcmp(value.pipeline, "sc") != 0)
        || (strcmp(value.request_type, "L1_NEW") == 0
            && strcmp(value.pipeline, "l1") != 0))
        goto done;
    memset(commitment, 0, sizeof(*commitment));
    if (projection_fingerprint(&parser, &value,
            commitment->request_fingerprint) != 0) {
        status = PLAMEN_BROKER_V2_SYSTEM;
        goto done;
    }
    strcpy(commitment->attempt_id, value.attempt_id);
    strcpy(commitment->run_identity, value.run_id);
    memcpy(commitment->config_sha256, value.source_config_sha256, 32);
    memcpy(commitment->runtime_closure_sha256,
        value.runtime_layout_sha256, 32);
    memcpy(commitment->image_closure_sha256, value.image_closure_sha256, 32);
    memcpy(commitment->provider_provenance_sha256,
        value.provider_provenance_sha256, 32);
    memcpy(commitment->backend_admission_sha256,
        value.backend_admission_sha256, 32);
    memcpy(commitment->credential_isolation_sha256,
        value.credential_isolation_sha256, 32);
    memcpy(commitment->egress_admission_sha256,
        value.egress_admission_sha256, 32);
    status = PLAMEN_BROKER_V2_OK;
done:
    if (status != 0 && commitment != NULL)
        plamen_broker_v2_secure_zero(commitment, sizeof(*commitment));
    parsed_projection_destroy(&value);
    return status;
}

int
plamen_broker_v2_request_projection_derive_exact(const uint8_t *projection,
    size_t size, struct plamen_broker_v2_commitment *commitment,
    uint8_t *encoded_commitment, size_t encoded_capacity,
    size_t *encoded_commitment_size, uint8_t projection_sha256[32],
    uint8_t commitment_sha256[32])
{
    struct plamen_broker_v2_writer writer;
    int status;
    if (projection == NULL || commitment == NULL || encoded_commitment == NULL
        || encoded_commitment_size == NULL || projection_sha256 == NULL
        || commitment_sha256 == NULL || size == 0
        || size > PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX
        || encoded_capacity < PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE
        || memchr(projection, '\0', size) != NULL || !valid_utf8(projection, size))
        return PLAMEN_BROKER_V2_INVALID;
    *encoded_commitment_size = 0;
    status = projection_parse_derive(projection, size, commitment);
    if (status != 0) return status;
    plamen_broker_v2_writer_init(&writer, encoded_commitment, encoded_capacity);
    status = plamen_broker_v2_encode_commitment(&writer, commitment);
    if (status == 0) status = plamen_broker_v2_sha256(projection, size,
        projection_sha256);
    if (status == 0) status = plamen_broker_v2_sha256(encoded_commitment,
        writer.offset, commitment_sha256);
    if (status != 0) {
        plamen_broker_v2_secure_zero(commitment, sizeof(*commitment));
        plamen_broker_v2_secure_zero(encoded_commitment, encoded_capacity);
        plamen_broker_v2_secure_zero(projection_sha256, 32);
        plamen_broker_v2_secure_zero(commitment_sha256, 32);
        return status;
    }
    *encoded_commitment_size = writer.offset;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_request_projection_validate_exact(const uint8_t *projection,
    size_t size, const uint8_t expected_projection_sha256[32],
    const uint8_t *expected_commitment, size_t expected_commitment_size,
    const uint8_t expected_commitment_sha256[32],
    struct plamen_broker_v2_commitment *commitment)
{
    uint8_t actual_projection[32], actual_commitment_sha[32];
    uint8_t actual_commitment[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    size_t actual_commitment_size = 0;
    int status;
    if (projection == NULL || expected_projection_sha256 == NULL
        || expected_commitment == NULL || expected_commitment_sha256 == NULL
        || commitment == NULL || size == 0
        || size > PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX
        || all_zero(expected_projection_sha256, 32))
        return PLAMEN_BROKER_V2_INVALID;
    memset(actual_commitment, 0, sizeof(actual_commitment));
    status = plamen_broker_v2_request_projection_derive_exact(projection, size,
        commitment, actual_commitment, sizeof(actual_commitment),
        &actual_commitment_size, actual_projection, actual_commitment_sha);
    if (status == 0 && !constant_equal(actual_projection,
            expected_projection_sha256, 32))
        status = PLAMEN_BROKER_V2_AUTH_FAILED;
    if (status == 0 && (!constant_equal(actual_commitment_sha,
            expected_commitment_sha256, 32)
        || actual_commitment_size != expected_commitment_size
        || !constant_equal(actual_commitment, expected_commitment,
            actual_commitment_size)))
        status = PLAMEN_BROKER_V2_AUTH_FAILED;
    if (status != 0) plamen_broker_v2_secure_zero(commitment,
        sizeof(*commitment));
    plamen_broker_v2_secure_zero(actual_projection,
        sizeof(actual_projection));
    plamen_broker_v2_secure_zero(actual_commitment_sha,
        sizeof(actual_commitment_sha));
    plamen_broker_v2_secure_zero(actual_commitment,
        sizeof(actual_commitment));
    return status;
}

int
plamen_broker_v2_frame_build(struct plamen_broker_v2_session *session,
    uint16_t type, const uint8_t operation_nonce[32], const uint8_t *payload,
    uint32_t payload_size, uint16_t fd_count, uint8_t **frame, size_t *frame_size)
{
    uint8_t *raw, digest[32], tag[32];
    size_t total;
    int status;
    if (session == NULL || session->burned)
        return PLAMEN_BROKER_V2_BURNED;
    if (frame != NULL) *frame = NULL;
    if (frame_size != NULL) *frame_size = 0;
    if (frame == NULL || frame_size == NULL || operation_nonce == NULL
        || !known_type(type) || !direction_valid(session->role, type, 1)
        || payload_size > PLAMEN_BROKER_V2_MAX_PAYLOAD
        || (payload_size != 0 && payload == NULL)
        || fd_count > PLAMEN_BROKER_V2_MAX_FDS || !nonce_valid(type, operation_nonce)
        || (type == PLAMEN_BROKER_V2_WORKER_SESSION_OPEN && fd_count != 1U)
        || (type == PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED && fd_count != 0U)
        || !frame_state_valid(session, type)
        || session->next_sequence == UINT64_MAX
        || (session->next_sequence == 0 && type != PLAMEN_BROKER_V2_HELLO)
        || (session->next_sequence != 0 && type == PLAMEN_BROKER_V2_HELLO)) {
        plamen_broker_v2_session_burn(session);
        return PLAMEN_BROKER_V2_INVALID;
    }
    total = PLAMEN_BROKER_V2_HEADER_SIZE + (size_t)payload_size;
    raw = calloc(1, total);
    if (raw == NULL) return PLAMEN_BROKER_V2_NOMEM;
    memcpy(raw, plamen_v2_magic, 8);
    store_u16(raw + 8, PLAMEN_BROKER_V2_VERSION);
    store_u16(raw + 10, type);
    store_u32(raw + 12, 0);
    store_u32(raw + 16, PLAMEN_BROKER_V2_HEADER_SIZE);
    store_u32(raw + 20, payload_size);
    store_u16(raw + 24, fd_count);
    store_u16(raw + 26, 0);
    store_u64(raw + 28, session->next_sequence);
    memcpy(raw + 36, session->session_id, 32);
    memcpy(raw + 68, operation_nonce, 32);
    if (session->next_sequence != 0)
        memcpy(raw + 100, session->previous_frame_sha256, 32);
    if (payload_size != 0) memcpy(raw + PLAMEN_BROKER_V2_HEADER_SIZE, payload,
        payload_size);
    status = plamen_broker_v2_sha256(payload, payload_size, raw + 132);
    if (status == 0)
        status = plamen_broker_v2_hmac_sha256(session->key, raw,
            PLAMEN_BROKER_V2_AUTH_OFFSET,
            raw + PLAMEN_BROKER_V2_HEADER_SIZE, payload_size, tag);
    if (status == 0) {
        memcpy(raw + PLAMEN_BROKER_V2_AUTH_OFFSET, tag, 32);
        status = plamen_broker_v2_sha256(raw, total, digest);
    }
    plamen_broker_v2_secure_zero(tag, sizeof(tag));
    if (status != 0) { free(raw); return status; }
    memcpy(session->previous_frame_sha256, digest, 32);
    ++session->next_sequence;
    frame_state_advance(session, type);
    *frame = raw;
    *frame_size = total;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_frame_accept(struct plamen_broker_v2_session *session,
    const uint8_t *frame, size_t frame_size, size_t received_fd_count,
    struct plamen_broker_v2_frame_view *view)
{
    uint16_t type, fd_count;
    uint32_t payload_size;
    uint64_t sequence;
    uint8_t payload_digest[32], tag[32], frame_digest[32];
    int status = PLAMEN_BROKER_V2_INVALID;
    if (session == NULL || session->burned)
        return PLAMEN_BROKER_V2_BURNED;
    if (view != NULL) memset(view, 0, sizeof(*view));
    if (frame == NULL || view == NULL || frame_size < PLAMEN_BROKER_V2_HEADER_SIZE)
        goto fail;
    type = load_u16(frame + 10);
    payload_size = load_u32(frame + 20);
    fd_count = load_u16(frame + 24);
    sequence = load_u64(frame + 28);
    if (!constant_equal(frame, plamen_v2_magic, 8)
        || load_u16(frame + 8) != PLAMEN_BROKER_V2_VERSION || !known_type(type)
        || !direction_valid(session->role, type, 0) || load_u32(frame + 12) != 0
        || load_u32(frame + 16) != PLAMEN_BROKER_V2_HEADER_SIZE
        || payload_size > PLAMEN_BROKER_V2_MAX_PAYLOAD
        || frame_size != PLAMEN_BROKER_V2_HEADER_SIZE + (size_t)payload_size
        || fd_count > PLAMEN_BROKER_V2_MAX_FDS || fd_count != received_fd_count
        || (type == PLAMEN_BROKER_V2_WORKER_SESSION_OPEN && fd_count != 1U)
        || (type == PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED && fd_count != 0U)
        || load_u16(frame + 26) != 0
        || !constant_equal(frame + 36, session->session_id, 32)
        || !nonce_valid(type, frame + 68))
        goto fail;
    if (sequence != session->next_sequence
        || (sequence == 0 && type != PLAMEN_BROKER_V2_HELLO)
        || (sequence != 0 && type == PLAMEN_BROKER_V2_HELLO)
        || (sequence == 0 && !all_zero(frame + 100, 32))
        || (sequence != 0
            && !constant_equal(frame + 100, session->previous_frame_sha256, 32))) {
        status = PLAMEN_BROKER_V2_REPLAY;
        goto fail;
    }
    if (!frame_state_valid(session, type)) goto fail;
    if (plamen_broker_v2_sha256(frame + PLAMEN_BROKER_V2_HEADER_SIZE,
            payload_size, payload_digest) != 0
        || !constant_equal(payload_digest, frame + 132, 32)
        || plamen_broker_v2_hmac_sha256(session->key, frame,
            PLAMEN_BROKER_V2_AUTH_OFFSET,
            frame + PLAMEN_BROKER_V2_HEADER_SIZE, payload_size, tag) != 0
        || !constant_equal(tag, frame + PLAMEN_BROKER_V2_AUTH_OFFSET, 32)) {
        status = PLAMEN_BROKER_V2_AUTH_FAILED;
        goto fail;
    }
    if (plamen_broker_v2_sha256(frame, frame_size, frame_digest) != 0)
        goto fail;
    memset(view, 0, sizeof(*view));
    view->type = type;
    view->fd_count = fd_count;
    view->sequence = sequence;
    memcpy(view->operation_nonce, frame + 68, 32);
    view->payload = frame + PLAMEN_BROKER_V2_HEADER_SIZE;
    view->payload_size = payload_size;
    memcpy(view->frame_sha256, frame_digest, 32);
    memcpy(session->previous_frame_sha256, frame_digest, 32);
    ++session->next_sequence;
    frame_state_advance(session, type);
    plamen_broker_v2_secure_zero(tag, sizeof(tag));
    return PLAMEN_BROKER_V2_OK;
fail:
    plamen_broker_v2_secure_zero(tag, sizeof(tag));
    plamen_broker_v2_session_burn(session);
    return status;
}

static int
fd_access(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    switch (flags & O_ACCMODE) {
    case O_RDONLY: return PLAMEN_BROKER_V2_FD_READ;
    case O_WRONLY: return PLAMEN_BROKER_V2_FD_WRITE;
    case O_RDWR: return PLAMEN_BROKER_V2_FD_READ_WRITE;
    default: return -1;
    }
}

static int
fd_purpose_known(uint16_t purpose)
{
    return (purpose >= PLAMEN_BROKER_V2_FD_APPLE_CLI_EXECUTABLE
            && purpose <= PLAMEN_BROKER_V2_FD_WORKING_DIRECTORY)
        || (purpose >= PLAMEN_BROKER_V2_FD_BACKEND_EXECUTABLE
            && purpose <= PLAMEN_BROKER_V2_FD_CHILD_PASS)
        || purpose == PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET
        || purpose == PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ
        || purpose == PLAMEN_BROKER_V2_FD_SERVICE_REQUEST_PROJECTION
        || purpose == PLAMEN_BROKER_V2_FD_GUEST_BOOTSTRAP_RECORD
        || (purpose >= PLAMEN_BROKER_V2_FD_AUTHORITY_CONFIG
            && purpose <= PLAMEN_BROKER_V2_FD_AUTHORITY_RESUME_CHECKPOINT)
        || (purpose >= PLAMEN_BROKER_V2_FD_JS_SOURCE
            && purpose <= PLAMEN_BROKER_V2_FD_JS_ARCHIVE_ROOT)
        || (purpose >= PLAMEN_BROKER_V2_FD_PROJECTION_PROJECT
            && purpose <=
                PLAMEN_BROKER_V2_FD_PROJECTION_MODULES)
        || (purpose >= PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE
            && purpose <= PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT)
        || (purpose >= PLAMEN_BROKER_V2_FD_MANAGED_EVM_POLICY
            && purpose <=
                PLAMEN_BROKER_V2_FD_MANAGED_EVM_ACQUISITION_RECEIPT);
}

int
plamen_broker_v2_fd_identity(int fd, uint8_t out[32])
{
    static const uint8_t domain[] = "PLAMEN-BROKER-V2-FD-IDENTITY\0";
    struct stat info, after;
    struct digest_context context, content;
    uint8_t metadata[88], content_sha[32], buffer[65536];
    off_t offset = 0;
    ssize_t amount;
    int result = PLAMEN_BROKER_V2_FD_INVALID;
    memset(&context, 0, sizeof(context));
    memset(&content, 0, sizeof(content));
    if (fd < 0 || out == NULL || fstat(fd, &info) != 0
        || (!S_ISREG(info.st_mode) && !S_ISDIR(info.st_mode)
            && !S_ISFIFO(info.st_mode) && !S_ISSOCK(info.st_mode))
        || info.st_size < 0)
        return PLAMEN_BROKER_V2_FD_INVALID;
    if (digest_init(&context) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    memset(content_sha, 0, sizeof(content_sha));
    if (S_ISREG(info.st_mode)) {
        if (digest_init(&content) != 0) {
            result = PLAMEN_BROKER_V2_SYSTEM;
            goto done;
        }
        while (offset < info.st_size) {
            size_t wanted = (uint64_t)(info.st_size - offset) > sizeof(buffer)
                ? sizeof(buffer) : (size_t)(info.st_size - offset);
            amount = pread(fd, buffer, wanted, offset);
            if (amount <= 0 || digest_update(&content, buffer, (size_t)amount) != 0)
                goto done;
            offset += amount;
        }
        if (pread(fd, buffer, 1, info.st_size) != 0)
            goto done;
        if (digest_final(&content, content_sha) != 0) {
            result = PLAMEN_BROKER_V2_SYSTEM;
            goto done;
        }
    }
    if (fstat(fd, &after) != 0 || info.st_dev != after.st_dev
        || info.st_ino != after.st_ino || info.st_mode != after.st_mode
        || info.st_uid != after.st_uid || info.st_gid != after.st_gid
        || info.st_size != after.st_size || info.st_nlink != after.st_nlink
#ifdef __APPLE__
        || info.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
        || info.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
        || info.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec
        || info.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec
#else
        || info.st_mtim.tv_sec != after.st_mtim.tv_sec
        || info.st_mtim.tv_nsec != after.st_mtim.tv_nsec
        || info.st_ctim.tv_sec != after.st_ctim.tv_sec
        || info.st_ctim.tv_nsec != after.st_ctim.tv_nsec
#endif
        )
        goto done;
    store_u64(metadata, (uint64_t)info.st_dev);
    store_u64(metadata + 8, (uint64_t)info.st_ino);
    store_u64(metadata + 16, (uint64_t)info.st_mode);
    store_u64(metadata + 24, (uint64_t)info.st_uid);
    store_u64(metadata + 32, (uint64_t)info.st_gid);
    store_u64(metadata + 40, (uint64_t)info.st_size);
    store_u64(metadata + 48, (uint64_t)info.st_nlink);
#ifdef __APPLE__
    store_u64(metadata + 56, (uint64_t)info.st_mtimespec.tv_sec);
    store_u64(metadata + 64, (uint64_t)info.st_mtimespec.tv_nsec);
    store_u64(metadata + 72, (uint64_t)info.st_ctimespec.tv_sec);
    store_u64(metadata + 80, (uint64_t)info.st_ctimespec.tv_nsec);
#else
    store_u64(metadata + 56, (uint64_t)info.st_mtim.tv_sec);
    store_u64(metadata + 64, (uint64_t)info.st_mtim.tv_nsec);
    store_u64(metadata + 72, (uint64_t)info.st_ctim.tv_sec);
    store_u64(metadata + 80, (uint64_t)info.st_ctim.tv_nsec);
#endif
    if (digest_update(&context, domain, sizeof(domain)) != 0
        || digest_update(&context, metadata, sizeof(metadata)) != 0
        || digest_update(&context, content_sha, sizeof(content_sha)) != 0
        || digest_final(&context, out) != 0) {
        result = PLAMEN_BROKER_V2_SYSTEM;
        goto done;
    }
    result = PLAMEN_BROKER_V2_OK;
done:
    digest_destroy(&content);
    digest_destroy(&context);
    plamen_broker_v2_secure_zero(metadata, sizeof(metadata));
    plamen_broker_v2_secure_zero(content_sha, sizeof(content_sha));
    plamen_broker_v2_secure_zero(buffer, sizeof(buffer));
    if (result != PLAMEN_BROKER_V2_OK && out != NULL)
        plamen_broker_v2_secure_zero(out, 32);
    return result;
}

static int
connected_unix_stream(int fd)
{
    struct sockaddr_storage local, peer;
    socklen_t local_size = sizeof(local), peer_size = sizeof(peer);
    socklen_t type_size = sizeof(int);
    int type = 0;
    memset(&local, 0, sizeof(local));
    memset(&peer, 0, sizeof(peer));
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) == 0
        && type_size == sizeof(int) && type == SOCK_STREAM
        && getsockname(fd, (struct sockaddr *)&local, &local_size) == 0
        && local_size >= sizeof(sa_family_t) && local.ss_family == AF_UNIX
        && getpeername(fd, (struct sockaddr *)&peer, &peer_size) == 0
        && peer_size >= sizeof(sa_family_t) && peer.ss_family == AF_UNIX;
}

static int
purpose_shape_valid(int fd, const struct stat *info,
    const struct plamen_broker_v2_fd_metadata *metadata)
{
    switch (metadata->purpose) {
    case PLAMEN_BROKER_V2_FD_APPLE_CLI_EXECUTABLE:
    case PLAMEN_BROKER_V2_FD_BACKEND_EXECUTABLE:
        return metadata->target != 0 && S_ISREG(info->st_mode)
            && (info->st_mode & 0111) != 0;
    case PLAMEN_BROKER_V2_FD_JOURNAL_DIRECTORY:
    case PLAMEN_BROKER_V2_FD_WORKING_DIRECTORY:
    case PLAMEN_BROKER_V2_FD_AUTHORITY_TARGET:
    case PLAMEN_BROKER_V2_FD_AUTHORITY_EXPORT:
        return metadata->target != 0 && S_ISDIR(info->st_mode);
    case PLAMEN_BROKER_V2_FD_AUTHORITY_DOCS:
        return metadata->target != 0
            && (S_ISREG(info->st_mode) || S_ISDIR(info->st_mode));
    case PLAMEN_BROKER_V2_FD_AUTHORITY_PROVIDER_EXECUTABLE:
    case PLAMEN_BROKER_V2_FD_AUTHORITY_BACKEND_EXECUTABLE:
        return metadata->target != 0 && S_ISREG(info->st_mode)
            && (info->st_mode & 0111) != 0;
    case PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET:
        return metadata->target == 0 && S_ISSOCK(info->st_mode)
            && metadata->access_mode == PLAMEN_BROKER_V2_FD_READ_WRITE
            && connected_unix_stream(fd);
    case PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ:
        return metadata->target == 1 && S_ISFIFO(info->st_mode)
            && metadata->access_mode == PLAMEN_BROKER_V2_FD_READ;
    case PLAMEN_BROKER_V2_FD_SERVICE_REQUEST_PROJECTION:
        return metadata->target == 0 && S_ISREG(info->st_mode)
            && metadata->access_mode == PLAMEN_BROKER_V2_FD_READ;
    case PLAMEN_BROKER_V2_FD_GUEST_BOOTSTRAP_RECORD:
        return metadata->target != 0 && S_ISREG(info->st_mode)
            && metadata->access_mode == PLAMEN_BROKER_V2_FD_READ;
    case PLAMEN_BROKER_V2_FD_JS_SOURCE:
    case PLAMEN_BROKER_V2_FD_JS_SCRATCH:
    case PLAMEN_BROKER_V2_FD_JS_STATE:
    case PLAMEN_BROKER_V2_FD_JS_ARCHIVE_ROOT:
    case PLAMEN_BROKER_V2_FD_PROJECTION_PROJECT:
    case PLAMEN_BROKER_V2_FD_PROJECTION_SCRATCH:
    case PLAMEN_BROKER_V2_FD_PROJECTION_STATE:
    case PLAMEN_BROKER_V2_FD_PROJECTION_MODULES:
    case PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH:
    case PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE:
    case PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT:
    case PLAMEN_BROKER_V2_FD_MANAGED_EVM_PROJECT:
    case PLAMEN_BROKER_V2_FD_MANAGED_EVM_CACHE:
    case PLAMEN_BROKER_V2_FD_MANAGED_EVM_GENERATIONS:
        return metadata->target != 0 && S_ISDIR(info->st_mode);
    case PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE:
        return metadata->target != 0 &&
            (S_ISDIR(info->st_mode) ||
             (S_ISREG(info->st_mode) && info->st_nlink == 1));
    case PLAMEN_BROKER_V2_FD_PROJECTION_RECEIPT:
    case PLAMEN_BROKER_V2_FD_PROJECTION_LINEAGE:
    case PLAMEN_BROKER_V2_FD_PROJECTION_MATERIALIZATION_TERMINAL:
    case PLAMEN_BROKER_V2_FD_MANAGED_EVM_POLICY:
    case PLAMEN_BROKER_V2_FD_MANAGED_EVM_ACQUISITION_RECEIPT:
        return metadata->target != 0 && S_ISREG(info->st_mode) &&
            info->st_nlink == 1;
    case PLAMEN_BROKER_V2_FD_CHILD_PASS:
        return metadata->target != 0 && (S_ISREG(info->st_mode)
            || S_ISDIR(info->st_mode) || S_ISFIFO(info->st_mode)
            || S_ISSOCK(info->st_mode));
    default:
        return metadata->target != 0 && S_ISREG(info->st_mode);
    }
}

void
plamen_broker_v2_close_fds(int *fds, size_t fd_count)
{
    size_t index;
    if (fds == NULL) return;
    for (index = 0; index < fd_count; ++index) {
        if (fds[index] >= 0) close(fds[index]);
        fds[index] = -1;
    }
}

int
plamen_broker_v2_validate_received_fds(int *fds, size_t fd_count,
    const struct plamen_broker_v2_fd_metadata *metadata, size_t metadata_count)
{
    struct stat stats[PLAMEN_BROKER_V2_MAX_FDS];
    uint8_t identity[32];
    size_t i, j;
    if (fd_count > PLAMEN_BROKER_V2_MAX_FDS || fd_count != metadata_count
        || (fd_count != 0 && (fds == NULL || metadata == NULL))) {
        plamen_broker_v2_close_fds(fds, fd_count);
        return PLAMEN_BROKER_V2_FD_INVALID;
    }
    for (i = 0; i < fd_count; ++i) {
        int flags;
        if (fds[i] < 0 || (flags = fcntl(fds[i], F_GETFD)) < 0
            || fcntl(fds[i], F_SETFD, flags | FD_CLOEXEC) != 0)
            goto fail;
    }
    for (i = 0; i < fd_count; ++i) {
        int observed_access;
        int writable_directory_capability;
        writable_directory_capability =
            metadata[i].purpose == PLAMEN_BROKER_V2_FD_JS_SCRATCH ||
            metadata[i].purpose == PLAMEN_BROKER_V2_FD_JS_STATE ||
            metadata[i].purpose == PLAMEN_BROKER_V2_FD_PROJECTION_SCRATCH ||
            metadata[i].purpose == PLAMEN_BROKER_V2_FD_PROJECTION_STATE ||
            metadata[i].purpose ==
                PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH ||
            metadata[i].purpose == PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE ||
            metadata[i].purpose == PLAMEN_BROKER_V2_FD_MANAGED_EVM_CACHE ||
            metadata[i].purpose ==
                PLAMEN_BROKER_V2_FD_MANAGED_EVM_GENERATIONS;
        observed_access = fd_access(fds[i]);
        if (!fd_purpose_known(metadata[i].purpose)
            || metadata[i].access_mode < PLAMEN_BROKER_V2_FD_READ
            || metadata[i].access_mode > PLAMEN_BROKER_V2_FD_READ_WRITE
            || (i != 0 && metadata[i - 1].target >= metadata[i].target)
            || (writable_directory_capability
                    ? (metadata[i].access_mode !=
                           PLAMEN_BROKER_V2_FD_READ_WRITE ||
                       observed_access != PLAMEN_BROKER_V2_FD_READ)
                    : observed_access != metadata[i].access_mode)
            || fstat(fds[i], &stats[i]) != 0
            || !purpose_shape_valid(fds[i], &stats[i], &metadata[i])
            || plamen_broker_v2_fd_identity(fds[i], identity) != 0
            || !constant_equal(identity, metadata[i].identity, 32))
            goto fail;
        for (j = 0; j < i; ++j) {
            if (fds[j] == fds[i]
                || (stats[j].st_dev == stats[i].st_dev
                    && stats[j].st_ino == stats[i].st_ino))
                goto fail;
        }
    }
    return PLAMEN_BROKER_V2_OK;
fail:
    plamen_broker_v2_close_fds(fds, fd_count);
    return PLAMEN_BROKER_V2_FD_INVALID;
}

static int
service_type_known(uint16_t type)
{
    return type == PLAMEN_BROKER_V2_SERVICE_READINESS
        || type == PLAMEN_BROKER_V2_SERVICE_READY
        || type == PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
        || type == PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY
        || type == PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACCEPTED
        || type == PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP
        || type == PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE
        || type == PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN
        || type == PLAMEN_BROKER_V2_SERVICE_SESSION_ACCEPTED
        || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP
        || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE
        || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN
        || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACCEPTED
        || type == PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP
        || type == PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE
        || type == PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN
        || type == PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACCEPTED
        || type == PLAMEN_BROKER_V2_SERVICE_ERROR;
}

static int
service_shape(uint16_t type, uint32_t *payload_size, uint16_t *fd_count)
{
    switch (type) {
    case PLAMEN_BROKER_V2_SERVICE_READINESS:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_READINESS_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_READY:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_READY_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL:
    case PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE;
        *fd_count = UINT16_MAX; return 1; /* projection + presence mask */
    case PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACCEPTED:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACK_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE;
        *fd_count = 2; return 1;
    case PLAMEN_BROKER_V2_SERVICE_SESSION_ACCEPTED:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_SESSION_ACK_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE;
        *fd_count = 2; return 1;
    case PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACCEPTED:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACK_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN_SIZE;
        *fd_count = 2; return 1;
    case PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACCEPTED:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACK_SIZE;
        *fd_count = 0; return 1;
    case PLAMEN_BROKER_V2_SERVICE_ERROR:
        *payload_size = PLAMEN_BROKER_V2_SERVICE_ERROR_SIZE;
        *fd_count = 0; return 1;
    default:
        return 0;
    }
}

static int service_payload_canonical(uint16_t, const uint8_t *, size_t);

static int
service_fd_count_valid(uint16_t type, const uint8_t *payload,
    size_t payload_size, uint16_t required, uint16_t actual)
{
    struct plamen_broker_v2_service_registration registration;
    uint16_t expected;
    int status;
    if (required != UINT16_MAX) return actual == required;
    if (type != PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
        && type != PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY)
        return 0;
    memset(&registration, 0, sizeof(registration));
    status = plamen_broker_v2_service_registration_decode(payload,
        payload_size, &registration);
    if (status == 0)
        status = plamen_broker_v2_service_registration_fd_count(&registration,
            &expected);
    plamen_broker_v2_secure_zero(&registration, sizeof(registration));
    return status == 0 && actual == expected;
}

static int
service_direction(uint8_t local_role, uint16_t type, int sending)
{
    int launcher_request = type == PLAMEN_BROKER_V2_SERVICE_READINESS
        || type == PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
        || type == PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY;
    int extension_request = type == PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP
        || type == PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN
        || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP
        || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN
        || type == PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP
        || type == PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN;
    int broker_registration = type == PLAMEN_BROKER_V2_SERVICE_READY
        || type == PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACCEPTED;
    int broker_session = type == PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE
        || type == PLAMEN_BROKER_V2_SERVICE_SESSION_ACCEPTED
        || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE
        || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACCEPTED
        || type == PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE
        || type == PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACCEPTED;
    int broker_error = type == PLAMEN_BROKER_V2_SERVICE_ERROR;
    if (local_role == PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER)
        return sending ? launcher_request : (broker_registration || broker_error);
    if (local_role == PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION)
        return sending ? extension_request : (broker_session || broker_error);
    if (local_role == PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER)
        return sending ? (broker_registration || broker_session || broker_error)
            : (launcher_request || extension_request);
    return 0;
}

int
plamen_broker_v2_service_envelope_build(uint8_t local_role, uint16_t type,
    const uint8_t transaction_nonce[32], const uint8_t invocation_nonce[32],
    const uint8_t *payload, uint32_t payload_size, uint16_t fd_count,
    uint8_t **envelope, size_t *envelope_size)
{
    uint32_t required_payload = 0;
    uint16_t required_fds = 0;
    uint8_t *raw;
    size_t total;
    if (envelope != NULL) *envelope = NULL;
    if (envelope_size != NULL) *envelope_size = 0;
    if (transaction_nonce == NULL || invocation_nonce == NULL || envelope == NULL
        || envelope_size == NULL || payload == NULL
        || !service_type_known(type) || !service_direction(local_role, type, 1)
        || !service_shape(type, &required_payload, &required_fds)
        || payload_size != required_payload
        || payload_size > PLAMEN_BROKER_V2_SERVICE_MAX_PAYLOAD
        || fd_count > PLAMEN_BROKER_V2_SERVICE_MAX_FDS
        || !service_payload_canonical(type, payload, payload_size)
        || !service_fd_count_valid(type, payload, payload_size, required_fds,
            fd_count)
        || all_zero(transaction_nonce, 32) || all_zero(invocation_nonce, 32))
        return PLAMEN_BROKER_V2_INVALID;
    total = PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE + (size_t)payload_size;
    raw = calloc(1, total);
    if (raw == NULL) return PLAMEN_BROKER_V2_NOMEM;
    memcpy(raw, plamen_v2_service_magic, 8);
    store_u16(raw + 8, PLAMEN_BROKER_V2_SERVICE_ABI_VERSION);
    store_u16(raw + 10, type);
    store_u32(raw + 12, 0);
    store_u32(raw + 16, PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE);
    store_u32(raw + 20, payload_size);
    store_u16(raw + 24, fd_count);
    store_u16(raw + 26, 0);
    memcpy(raw + 28, transaction_nonce, 32);
    memcpy(raw + 60, invocation_nonce, 32);
    memcpy(raw + PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE, payload, payload_size);
    if (plamen_broker_v2_sha256(payload, payload_size, raw + 92) != 0) {
        free(raw); return PLAMEN_BROKER_V2_SYSTEM;
    }
    *envelope = raw;
    *envelope_size = total;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_envelope_accept(uint8_t local_role,
    const uint8_t *envelope, size_t envelope_size, size_t received_fd_count,
    struct plamen_broker_v2_service_envelope_view *view)
{
    uint16_t type, fds, required_fds;
    uint32_t payload_size, required_payload;
    uint8_t digest[32];
    if (view != NULL) memset(view, 0, sizeof(*view));
    if (envelope == NULL || view == NULL
        || envelope_size < PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE)
        return PLAMEN_BROKER_V2_INVALID;
    type = load_u16(envelope + 10);
    payload_size = load_u32(envelope + 20);
    fds = load_u16(envelope + 24);
    if (!constant_equal(envelope, plamen_v2_service_magic, 8)
        || load_u16(envelope + 8) != PLAMEN_BROKER_V2_SERVICE_ABI_VERSION
        || !service_type_known(type) || !service_direction(local_role, type, 0)
        || !service_shape(type, &required_payload, &required_fds)
        || load_u32(envelope + 12) != 0
        || load_u32(envelope + 16) != PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE
        || payload_size != required_payload
        || payload_size > PLAMEN_BROKER_V2_SERVICE_MAX_PAYLOAD
        || fds > PLAMEN_BROKER_V2_SERVICE_MAX_FDS || fds != received_fd_count
        || load_u16(envelope + 26) != 0
        || all_zero(envelope + 28, 32) || all_zero(envelope + 60, 32)
        || envelope_size != PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE
            + (size_t)payload_size
        || !service_payload_canonical(type,
            envelope + PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE, payload_size)
        || !service_fd_count_valid(type,
            envelope + PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE, payload_size,
            required_fds, fds)
        || plamen_broker_v2_sha256(
            envelope + PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE, payload_size,
            digest) != 0 || !constant_equal(digest, envelope + 92, 32))
        return PLAMEN_BROKER_V2_INVALID;
    if (type == PLAMEN_BROKER_V2_SERVICE_ERROR) {
        struct plamen_broker_v2_service_error error;
        if (plamen_broker_v2_service_error_decode(
                envelope + PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE,
                payload_size, &error) != 0
            || (local_role == PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER
                && (error.failed_message_type
                        == PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP
                    || error.failed_message_type
                        == PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN
                    || error.failed_message_type
                        == PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP
                    || error.failed_message_type
                        == PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN))
            || (local_role == PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION
                && (error.failed_message_type == PLAMEN_BROKER_V2_SERVICE_READINESS
                    || error.failed_message_type
                        == PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
                    || error.failed_message_type
                        == PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY)))
            return PLAMEN_BROKER_V2_INVALID;
    }
    memset(view, 0, sizeof(*view));
    view->type = type;
    view->fd_count = fds;
    memcpy(view->transaction_nonce, envelope + 28, 32);
    memcpy(view->invocation_nonce, envelope + 60, 32);
    view->payload = envelope + PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE;
    view->payload_size = payload_size;
    if (plamen_broker_v2_sha256(envelope, envelope_size,
            view->envelope_sha256) != 0)
        return PLAMEN_BROKER_V2_SYSTEM;
    return PLAMEN_BROKER_V2_OK;
}

static int
peer_valid(const struct plamen_broker_v2_peer_identity *peer)
{
    if (peer == NULL || peer->pid == 0 || peer->birth_primary == 0)
        return 0;
    if (peer->birth_kind == PLAMEN_BROKER_V2_BIRTH_DARWIN_EPOCH)
        return peer->birth_secondary < UINT64_C(1000000000)
            && all_zero(peer->boot_id_sha256, 32);
    if (peer->birth_kind == PLAMEN_BROKER_V2_BIRTH_LINUX_BOOT_TICKS)
        return peer->birth_secondary != 0 && !all_zero(peer->boot_id_sha256, 32);
    return 0;
}

static void
peer_store(uint8_t out[76], const struct plamen_broker_v2_peer_identity *peer)
{
    store_u64(out, peer->pid);
    store_u64(out + 8, peer->uid);
    store_u64(out + 16, peer->gid);
    store_u16(out + 24, peer->birth_kind);
    store_u16(out + 26, 0);
    store_u64(out + 28, peer->birth_primary);
    store_u64(out + 36, peer->birth_secondary);
    memcpy(out + 44, peer->boot_id_sha256, 32);
}

static int
peer_load(const uint8_t in[76], struct plamen_broker_v2_peer_identity *peer)
{
    memset(peer, 0, sizeof(*peer));
    peer->pid = load_u64(in);
    peer->uid = load_u64(in + 8);
    peer->gid = load_u64(in + 16);
    peer->birth_kind = load_u16(in + 24);
    peer->birth_primary = load_u64(in + 28);
    peer->birth_secondary = load_u64(in + 36);
    memcpy(peer->boot_id_sha256, in + 44, 32);
    return load_u16(in + 26) == 0 && peer_valid(peer);
}

static int
required_digest(const uint8_t value[32])
{
    return value != NULL && !all_zero(value, 32);
}

static void fd_metadata_store(uint8_t out[37],
    const struct plamen_broker_v2_fd_metadata *value);
static void fd_metadata_load(const uint8_t in[37],
    struct plamen_broker_v2_fd_metadata *value);

static int
initial_authority_role_valid(uint16_t role)
{
    return role >= PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR
        && role <= PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER;
}

int
plamen_broker_v2_initial_authority_allows_frame(uint16_t role, uint16_t type)
{
    if (!initial_authority_role_valid(role) || !known_type(type)) return 0;
    if (type == PLAMEN_BROKER_V2_HELLO || type == PLAMEN_BROKER_V2_ERROR
        || type == PLAMEN_BROKER_V2_AUTH_CONSUME
        || type == PLAMEN_BROKER_V2_AUTH_ACCEPTED
        || type == PLAMEN_BROKER_V2_REQUEST_PROJECTION
        || type == PLAMEN_BROKER_V2_REQUEST_PROJECTED)
        return 1;
    if (type == PLAMEN_BROKER_V2_CLI_PREPARE
        || type == PLAMEN_BROKER_V2_CLI_COMMITTED)
        return role == PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    if (type == PLAMEN_BROKER_V2_BACKEND_PREPARE
        || type == PLAMEN_BROKER_V2_BACKEND_PREPARED
        || type == PLAMEN_BROKER_V2_OUTPUT_READ
        || type == PLAMEN_BROKER_V2_OUTPUT_CHUNK
        || type == PLAMEN_BROKER_V2_OPERATION_CLOSE
        || type == PLAMEN_BROKER_V2_OPERATION_FINISHED)
        return role == PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER;
    if (type == PLAMEN_BROKER_V2_OPERATION_REQUEST
        || type == PLAMEN_BROKER_V2_OPERATION_RESPONSE
        || type == PLAMEN_BROKER_V2_OPERATION_ERROR)
        return 1;
    if (type == PLAMEN_BROKER_V2_WORKER_SESSION_OPEN
        || type == PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED)
        return role == PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER;
    return type == PLAMEN_BROKER_V2_START_PREPARE
        || type == PLAMEN_BROKER_V2_STARTED
        || type == PLAMEN_BROKER_V2_START_RECOVER
        || type == PLAMEN_BROKER_V2_WAIT_PREPARE
        || type == PLAMEN_BROKER_V2_EXITED
        || type == PLAMEN_BROKER_V2_WAIT_RECOVER
        || type == PLAMEN_BROKER_V2_REVOKE_PREPARE
        || type == PLAMEN_BROKER_V2_REVOKED;
}

int
plamen_broker_v2_service_session_open_matches_registration(
    const struct plamen_broker_v2_service_registration_ack *registration,
    const struct plamen_broker_v2_service_session_open *open)
{
    return registration != NULL && open != NULL
        && registration->issuance_state == 0
        && registration->initial_interpreter_slot == open->initial_interpreter_slot
        && registration->initial_authority_role == open->initial_authority_role
        && memcmp(registration->registration_sha256,
            open->registration_sha256, 32) == 0
        && registration->suspended_child.pid == open->extension_peer.pid
        && registration->suspended_child.uid == open->extension_peer.uid
        && registration->suspended_child.gid == open->extension_peer.gid
        && registration->suspended_child.birth_kind == open->extension_peer.birth_kind
        && registration->suspended_child.birth_primary
            == open->extension_peer.birth_primary
        && registration->suspended_child.birth_secondary
            == open->extension_peer.birth_secondary
        && memcmp(registration->suspended_child.boot_id_sha256,
            open->extension_peer.boot_id_sha256, 32) == 0;
}

int
plamen_broker_v2_service_session_challenge_matches_lookup(
    const struct plamen_broker_v2_service_session_lookup *lookup,
    const uint8_t lookup_envelope_sha256[32],
    const struct plamen_broker_v2_service_session_challenge *challenge)
{
    return lookup != NULL && lookup_envelope_sha256 != NULL && challenge != NULL
        && required_digest(lookup_envelope_sha256)
        && memcmp(lookup_envelope_sha256,
            challenge->request_envelope_sha256, 32) == 0
        && memcmp(lookup->extension_closure_sha256,
            challenge->extension_closure_sha256, 32) == 0
        && memcmp(lookup->interpreter_executable_sha256,
            challenge->interpreter_executable_sha256, 32) == 0
        && memcmp(lookup->session_id, challenge->session_id, 32) == 0;
}

int
plamen_broker_v2_service_session_open_matches_challenge(
    const struct plamen_broker_v2_service_session_challenge *challenge,
    const uint8_t challenge_envelope_sha256[32],
    const struct plamen_broker_v2_service_session_open *open)
{
    return challenge != NULL && challenge_envelope_sha256 != NULL && open != NULL
        && required_digest(challenge_envelope_sha256)
        && memcmp(challenge_envelope_sha256,
            open->challenge_envelope_sha256, 32) == 0
        && memcmp(challenge->challenge_nonce, open->challenge_nonce, 32) == 0
        && memcmp(challenge->commitment_sha256,
            open->commitment_sha256, 32) == 0
        && memcmp(challenge->registration_sha256,
            open->registration_sha256, 32) == 0
        && memcmp(challenge->committed_audit_generation_sha256,
            open->committed_audit_generation_sha256, 32) == 0
        && memcmp(challenge->extension_closure_sha256,
            open->extension_closure_sha256, 32) == 0
        && memcmp(challenge->interpreter_executable_sha256,
            open->interpreter_executable_sha256, 32) == 0
        && challenge->extension_peer.pid == open->extension_peer.pid
        && challenge->extension_peer.uid == open->extension_peer.uid
        && challenge->extension_peer.gid == open->extension_peer.gid
        && challenge->extension_peer.birth_kind == open->extension_peer.birth_kind
        && challenge->extension_peer.birth_primary
            == open->extension_peer.birth_primary
        && challenge->extension_peer.birth_secondary
            == open->extension_peer.birth_secondary
        && memcmp(challenge->extension_peer.boot_id_sha256,
            open->extension_peer.boot_id_sha256, 32) == 0
        && challenge->initial_interpreter_slot == open->initial_interpreter_slot
        && challenge->initial_authority_role == open->initial_authority_role
        && memcmp(challenge->session_id, open->session_id, 32) == 0;
}

int
plamen_broker_v2_service_session_ack_matches_open(
    const struct plamen_broker_v2_service_session_open *open,
    const struct plamen_broker_v2_service_session_ack *ack)
{
    return open != NULL && ack != NULL
        && open->initial_authority_role == ack->initial_authority_role
        && memcmp(open->registration_sha256, ack->registration_sha256, 32) == 0
        && memcmp(open->session_id, ack->session_id, 32) == 0;
}

static uint16_t
authority_member_count(uint16_t role)
{
    if (role == PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR)
        return PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT;
    if (role == PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER)
        return PLAMEN_BROKER_V2_GUEST_AUTHORITY_MEMBER_COUNT;
    return 0;
}

static int
authority_members_valid(
    const struct plamen_broker_v2_authority_bundle_binding *value)
{
    uint16_t expected, index, prior;
    if (value == NULL
        || (expected = authority_member_count(value->role)) == 0
        || value->member_count != expected
        || !required_digest(value->registration_sha256)
        || !required_digest(value->issuance_checkpoint_sha256))
        return 0;
    for (index = 0; index < expected; ++index) {
        if (!required_digest(value->member_sha256[index])) return 0;
        for (prior = 0; prior < index; ++prior) {
            if (constant_equal(value->member_sha256[index],
                    value->member_sha256[prior], 32))
                return 0;
        }
    }
    for (; index < PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT; ++index) {
        if (!all_zero(value->member_sha256[index], 32)) return 0;
    }
    return 1;
}

int
plamen_broker_v2_authority_bundle_binding_encode(
    const struct plamen_broker_v2_authority_bundle_binding *value,
    uint8_t *out, size_t capacity, size_t *size)
{
    uint16_t index;
    size_t required;
    if (size != NULL) *size = 0;
    if (!authority_members_valid(value) || out == NULL || size == NULL)
        return PLAMEN_BROKER_V2_INVALID;
    required = value->role == PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR
        ? PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE
        : PLAMEN_BROKER_V2_GUEST_AUTHORITY_BUNDLE_SIZE;
    if (capacity < required) return PLAMEN_BROKER_V2_INVALID;
    store_u16(out, PLAMEN_BROKER_V2_VERSION);
    store_u16(out + 2, value->role);
    store_u16(out + 4, value->member_count);
    store_u16(out + 6, 0);
    memcpy(out + 8, value->registration_sha256, 32);
    memcpy(out + 40, value->issuance_checkpoint_sha256, 32);
    for (index = 0; index < value->member_count; ++index)
        memcpy(out + 72 + (size_t)index * 32, value->member_sha256[index], 32);
    *size = required;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_authority_bundle_binding_decode(const uint8_t *in,
    size_t size, struct plamen_broker_v2_authority_bundle_binding *value)
{
    uint16_t index, role, count;
    size_t required;
    if (in == NULL || value == NULL || size < 8)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    role = load_u16(in + 2);
    count = authority_member_count(role);
    required = role == PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR
        ? PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE
        : role == PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER
            ? PLAMEN_BROKER_V2_GUEST_AUTHORITY_BUNDLE_SIZE : 0;
    if (load_u16(in) != PLAMEN_BROKER_V2_VERSION || required == 0
        || size != required || load_u16(in + 4) != count
        || load_u16(in + 6) != 0)
        goto invalid_bundle;
    value->role = role;
    value->member_count = count;
    memcpy(value->registration_sha256, in + 8, 32);
    memcpy(value->issuance_checkpoint_sha256, in + 40, 32);
    for (index = 0; index < count; ++index)
        memcpy(value->member_sha256[index], in + 72 + (size_t)index * 32, 32);
    if (!authority_members_valid(value)) goto invalid_bundle;
    return PLAMEN_BROKER_V2_OK;
invalid_bundle:
    plamen_broker_v2_secure_zero(value, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_auth_consume_matches_challenge(
    const struct plamen_broker_v2_service_session_challenge *challenge,
    const uint8_t *payload, size_t payload_size,
    struct plamen_broker_v2_commitment *commitment)
{
    if (challenge == NULL || payload == NULL || commitment == NULL
        || payload_size != challenge->commitment_size
        || payload_size == 0
        || payload_size > PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE
        || !constant_equal(payload, challenge->commitment, payload_size))
        return PLAMEN_BROKER_V2_AUTH_FAILED;
    return commitment_binding_decode(payload, payload_size,
        challenge->commitment_sha256, challenge->commitment, commitment);
}

int
plamen_broker_v2_auth_accepted_matches_session_ack(
    const struct plamen_broker_v2_service_session_ack *ack,
    const uint8_t *payload, size_t payload_size,
    struct plamen_broker_v2_authority_bundle_binding *binding)
{
    uint8_t digest[32];
    int status;
    if (ack == NULL || payload == NULL || binding == NULL
        || !required_digest(ack->authority_bundle_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    status = plamen_broker_v2_sha256(payload, payload_size, digest);
    if (status == 0 && !constant_equal(digest,
            ack->authority_bundle_sha256, 32))
        status = PLAMEN_BROKER_V2_AUTH_FAILED;
    if (status == 0)
        status = plamen_broker_v2_authority_bundle_binding_decode(payload,
            payload_size, binding);
    if (status == 0 && (binding->role != ack->initial_authority_role
        || !constant_equal(binding->registration_sha256,
            ack->registration_sha256, 32)
        || !constant_equal(binding->issuance_checkpoint_sha256,
            ack->registration_burn_checkpoint_sha256, 32)))
        status = PLAMEN_BROKER_V2_AUTH_FAILED;
    if (status != 0)
        plamen_broker_v2_secure_zero(binding, sizeof(*binding));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return status;
}

static int
operation_kind_valid(uint16_t kind)
{
    return (kind >= PLAMEN_BROKER_V2_OUTER_PREPARE_LAYOUT
            && kind <= PLAMEN_BROKER_V2_OUTER_DELETE_GUEST)
        || (kind >= PLAMEN_BROKER_V2_BACKEND_OPERATION_PREPARE
            && kind <= PLAMEN_BROKER_V2_BACKEND_OPERATION_CLOSE);
}

int
plamen_broker_v2_derive_operation_key(
    const struct plamen_broker_v2_commitment *commitment, uint16_t kind,
    const uint8_t operation_nonce[32], const uint8_t spec_sha256[32],
    const uint8_t launch_request_sha256[32],
    const uint8_t prior_native_checkpoint_sha256[32], uint8_t out[32])
{
    static const uint8_t domain[] = PLAMEN_BROKER_V2_OPERATION_KEY_DOMAIN;
    struct digest_context context;
    struct plamen_broker_v2_writer writer;
    uint8_t encoded[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE], kind_bytes[2];
    int status = PLAMEN_BROKER_V2_INVALID;
    memset(&context, 0, sizeof(context));
    memset(encoded, 0, sizeof(encoded));
    if (commitment == NULL || !operation_kind_valid(kind)
        || operation_nonce == NULL || spec_sha256 == NULL
        || launch_request_sha256 == NULL
        || prior_native_checkpoint_sha256 == NULL || out == NULL
        || all_zero(operation_nonce, 32) || all_zero(spec_sha256, 32)
        || all_zero(launch_request_sha256, 32)
        || all_zero(prior_native_checkpoint_sha256, 32))
        return PLAMEN_BROKER_V2_INVALID;
    plamen_broker_v2_writer_init(&writer, encoded, sizeof(encoded));
    if (plamen_broker_v2_encode_commitment(&writer, commitment) != 0
        || digest_init(&context) != 0)
        goto done;
    store_u16(kind_bytes, kind);
    if (digest_update(&context, domain, sizeof(domain) - 1U) != 0
        || digest_update(&context, encoded, writer.offset) != 0
        || digest_update(&context, kind_bytes, sizeof(kind_bytes)) != 0
        || digest_update(&context, operation_nonce, 32) != 0
        || digest_update(&context, spec_sha256, 32) != 0
        || digest_update(&context, launch_request_sha256, 32) != 0
        || digest_update(&context, prior_native_checkpoint_sha256, 32) != 0
        || digest_final(&context, out) != 0)
        goto done;
    status = PLAMEN_BROKER_V2_OK;
done:
    if (status != 0) {
        digest_destroy(&context);
        if (out != NULL) plamen_broker_v2_secure_zero(out, 32);
    }
    plamen_broker_v2_secure_zero(encoded, sizeof(encoded));
    return status;
}

int
plamen_broker_v2_derive_rpc_operation_key(
    const struct plamen_broker_v2_commitment *commitment,
    const uint8_t member_capability_id[32], uint16_t authority_role,
    uint16_t member, uint16_t method,
    const uint8_t payload_sha256[32],
    const uint8_t prior_native_checkpoint_sha256[32], uint8_t out[32])
{
    static const uint8_t domain[] = PLAMEN_BROKER_V2_RPC_OPERATION_KEY_DOMAIN;
    struct digest_context context;
    struct plamen_broker_v2_writer writer;
    uint8_t encoded[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE], selector[6];
    int status = PLAMEN_BROKER_V2_INVALID;
    memset(&context, 0, sizeof(context));
    memset(encoded, 0, sizeof(encoded));
    if (commitment == NULL || !required_digest(member_capability_id)
        || !plamen_broker_v2_authority_method_valid(authority_role, member,
            method, 0)
        || !required_digest(payload_sha256)
        || !required_digest(prior_native_checkpoint_sha256) || out == NULL)
        return PLAMEN_BROKER_V2_INVALID;
    plamen_broker_v2_writer_init(&writer, encoded, sizeof(encoded));
    if (plamen_broker_v2_encode_commitment(&writer, commitment) != 0
        || digest_init(&context) != 0)
        goto done;
    store_u16(selector, authority_role);
    store_u16(selector + 2, member);
    store_u16(selector + 4, method);
    if (digest_update(&context, domain, sizeof(domain) - 1U) != 0
        || digest_update(&context, encoded, writer.offset) != 0
        || digest_update(&context, member_capability_id, 32) != 0
        || digest_update(&context, selector, sizeof(selector)) != 0
        || digest_update(&context, payload_sha256, 32) != 0
        || digest_update(&context, prior_native_checkpoint_sha256, 32) != 0
        || digest_final(&context, out) != 0)
        goto done;
    status = PLAMEN_BROKER_V2_OK;
done:
    if (status != 0) {
        digest_destroy(&context);
        if (out != NULL) plamen_broker_v2_secure_zero(out, 32);
    }
    plamen_broker_v2_secure_zero(encoded, sizeof(encoded));
    return status;
}

static int
output_stream_valid(uint8_t stream)
{
    return stream == PLAMEN_BROKER_V2_OUTPUT_STDOUT
        || stream == PLAMEN_BROKER_V2_OUTPUT_STDERR;
}

int
plamen_broker_v2_output_read_encode(
    const struct plamen_broker_v2_output_read *value, uint8_t out[79])
{
    if (value == NULL || out == NULL || !required_digest(value->operation_key)
        || !required_digest(value->exited_receipt_sha256)
        || !output_stream_valid(value->stream)
        || value->offset > PLAMEN_BROKER_V2_OUTPUT_STREAM_MAX
        || value->max_bytes == 0
        || value->max_bytes > PLAMEN_BROKER_V2_OUTPUT_CHUNK_MAX)
        return PLAMEN_BROKER_V2_INVALID;
    store_u16(out, PLAMEN_BROKER_V2_VERSION);
    memcpy(out + 2, value->operation_key, 32);
    memcpy(out + 34, value->exited_receipt_sha256, 32);
    out[66] = value->stream;
    store_u64(out + 67, value->offset);
    store_u32(out + 75, value->max_bytes);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_output_read_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_output_read *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_OUTPUT_READ_SIZE];
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_OUTPUT_READ_SIZE
        || load_u16(in) != PLAMEN_BROKER_V2_VERSION)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->operation_key, in + 2, 32);
    memcpy(value->exited_receipt_sha256, in + 34, 32);
    value->stream = in[66];
    value->offset = load_u64(in + 67);
    value->max_bytes = load_u32(in + 75);
    if (plamen_broker_v2_output_read_encode(value, canonical) != 0
        || !constant_equal(canonical, in, sizeof(canonical))) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_output_chunk_encode(
    const struct plamen_broker_v2_output_chunk *value, uint8_t *out,
    size_t capacity, size_t *size)
{
    uint8_t digest[32];
    size_t required;
    if (size != NULL) *size = 0;
    if (value == NULL || out == NULL || size == NULL
        || !required_digest(value->operation_key)
        || !required_digest(value->request_sha256)
        || !required_digest(value->exited_receipt_sha256)
        || !output_stream_valid(value->stream)
        || value->length > PLAMEN_BROKER_V2_OUTPUT_CHUNK_MAX
        || (value->length != 0 && value->chunk == NULL)
        || value->eof > 1 || value->full_stream_size
            > PLAMEN_BROKER_V2_OUTPUT_STREAM_MAX
        || value->offset > value->full_stream_size
        || value->length > value->full_stream_size - value->offset
        || (value->eof != (value->offset + value->length
            == value->full_stream_size))
        || !required_digest(value->chunk_sha256)
        || !required_digest(value->full_stream_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    required = PLAMEN_BROKER_V2_OUTPUT_CHUNK_PREFIX_SIZE + value->length;
    if (capacity < required
        || plamen_broker_v2_sha256(value->chunk, value->length, digest) != 0
        || !constant_equal(digest, value->chunk_sha256, 32)) {
        plamen_broker_v2_secure_zero(digest, sizeof(digest));
        return PLAMEN_BROKER_V2_INVALID;
    }
    store_u16(out, PLAMEN_BROKER_V2_VERSION);
    memcpy(out + 2, value->operation_key, 32);
    memcpy(out + 34, value->request_sha256, 32);
    memcpy(out + 66, value->exited_receipt_sha256, 32);
    out[98] = value->stream;
    store_u64(out + 99, value->offset);
    store_u32(out + 107, value->length);
    out[111] = value->eof;
    memcpy(out + 112, value->chunk_sha256, 32);
    memcpy(out + 144, value->full_stream_sha256, 32);
    store_u64(out + 176, value->full_stream_size);
    store_u32(out + 184, value->length);
    if (value->length != 0) memcpy(out + 188, value->chunk, value->length);
    *size = required;
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_output_chunk_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_output_chunk *value)
{
    uint32_t bytes_length;
    uint8_t digest[32];
    if (in == NULL || value == NULL
        || size < PLAMEN_BROKER_V2_OUTPUT_CHUNK_PREFIX_SIZE
        || size > PLAMEN_BROKER_V2_OUTPUT_CHUNK_PAYLOAD_MAX
        || load_u16(in) != PLAMEN_BROKER_V2_VERSION)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->operation_key, in + 2, 32);
    memcpy(value->request_sha256, in + 34, 32);
    memcpy(value->exited_receipt_sha256, in + 66, 32);
    value->stream = in[98];
    value->offset = load_u64(in + 99);
    value->length = load_u32(in + 107);
    value->eof = in[111];
    memcpy(value->chunk_sha256, in + 112, 32);
    memcpy(value->full_stream_sha256, in + 144, 32);
    value->full_stream_size = load_u64(in + 176);
    bytes_length = load_u32(in + 184);
    value->chunk = in + PLAMEN_BROKER_V2_OUTPUT_CHUNK_PREFIX_SIZE;
    if (!required_digest(value->operation_key)
        || !required_digest(value->request_sha256)
        || !required_digest(value->exited_receipt_sha256)
        || !output_stream_valid(value->stream) || value->eof > 1
        || value->length != bytes_length
        || value->length > PLAMEN_BROKER_V2_OUTPUT_CHUNK_MAX
        || size != PLAMEN_BROKER_V2_OUTPUT_CHUNK_PREFIX_SIZE + value->length
        || value->full_stream_size > PLAMEN_BROKER_V2_OUTPUT_STREAM_MAX
        || value->offset > value->full_stream_size
        || value->length > value->full_stream_size - value->offset
        || value->eof != (value->offset + value->length
            == value->full_stream_size)
        || !required_digest(value->chunk_sha256)
        || !required_digest(value->full_stream_sha256)
        || plamen_broker_v2_sha256(value->chunk, value->length, digest) != 0
        || !constant_equal(digest, value->chunk_sha256, 32)) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        plamen_broker_v2_secure_zero(digest, sizeof(digest));
        return PLAMEN_BROKER_V2_INVALID;
    }
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_authority_method_valid(uint16_t role, uint16_t member,
    uint16_t method, uint16_t flags)
{
    int method_matches = 0, recoverable = 0;
    if ((flags & ~PLAMEN_BROKER_V2_OPERATION_RECOVER) != 0)
        return 0;
    if (role == PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR) {
        switch (member) {
        case PLAMEN_BROKER_V2_AUTHORITY_RUNTIME_IMAGE:
            method_matches = method == PLAMEN_BROKER_V2_METHOD_RUNTIME_AUTHENTICATE;
            break;
        case PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE:
            method_matches = method >= PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET
                && method <= PLAMEN_BROKER_V2_METHOD_WORKSPACE_RECENSUS_LAYOUT;
            break;
        case PLAMEN_BROKER_V2_AUTHORITY_BACKEND_CONTEXT:
            method_matches = method == PLAMEN_BROKER_V2_METHOD_BACKEND_AUTHENTICATE;
            break;
        case PLAMEN_BROKER_V2_AUTHORITY_PROVIDER_LIFECYCLE:
            method_matches = method >= PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND
                && method <= PLAMEN_BROKER_V2_METHOD_PROVIDER_DELETE_GUEST;
            break;
        case PLAMEN_BROKER_V2_AUTHORITY_GUEST_ADMISSION:
            method_matches = method >= PLAMEN_BROKER_V2_METHOD_GUEST_ADMIT_STOPPED
                && method <= PLAMEN_BROKER_V2_METHOD_GUEST_RESUME_ADMISSION;
            break;
        case PLAMEN_BROKER_V2_AUTHORITY_EXTINCTION:
            method_matches = method == PLAMEN_BROKER_V2_METHOD_EXTINCTION_EXTINGUISH;
            break;
        case PLAMEN_BROKER_V2_AUTHORITY_ARTIFACT:
            method_matches = method == PLAMEN_BROKER_V2_METHOD_ARTIFACT_CENSUS;
            break;
        case PLAMEN_BROKER_V2_AUTHORITY_EXPORT:
            method_matches = method == PLAMEN_BROKER_V2_METHOD_EXPORT_EXPORT;
            break;
        case PLAMEN_BROKER_V2_AUTHORITY_DURABLE_JOURNAL:
            method_matches = method >= PLAMEN_BROKER_V2_METHOD_JOURNAL_OPEN
                && method <= PLAMEN_BROKER_V2_METHOD_JOURNAL_FINISH;
            break;
        case PLAMEN_BROKER_V2_AUTHORITY_RECOVERY:
            method_matches = method == PLAMEN_BROKER_V2_METHOD_RECOVERY_RECOVER;
            recoverable = method_matches;
            break;
        default:
            break;
        }
    } else if (role == PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER
        && member == PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION) {
        method_matches = method >= PLAMEN_BROKER_V2_METHOD_BACKEND_PREPARE
            && method <= PLAMEN_BROKER_V2_METHOD_BACKEND_CLOSE_OPERATION;
        recoverable = method == PLAMEN_BROKER_V2_METHOD_BACKEND_START_OR_RECOVER
            || method == PLAMEN_BROKER_V2_METHOD_BACKEND_WAIT_OR_RECOVER
            || method == PLAMEN_BROKER_V2_METHOD_BACKEND_EXTINGUISH_OR_RECOVER
            || method == PLAMEN_BROKER_V2_METHOD_BACKEND_READ_OUTPUT_OR_RECOVER;
    }
    return method_matches
        && (!(flags & PLAMEN_BROKER_V2_OPERATION_RECOVER) || recoverable);
}

int
plamen_broker_v2_authority_method_deadline(uint16_t role, uint16_t member,
    uint16_t method, uint32_t *service_seconds, uint32_t *client_seconds)
{
    uint32_t service = PLAMEN_BROKER_V2_RPC_QUICK_DEADLINE_SECONDS;
    if (service_seconds == NULL || client_seconds == NULL
        || !plamen_broker_v2_authority_method_valid(role, member, method,
            (method == PLAMEN_BROKER_V2_METHOD_RECOVERY_RECOVER
                || method == PLAMEN_BROKER_V2_METHOD_BACKEND_START_OR_RECOVER
                || method == PLAMEN_BROKER_V2_METHOD_BACKEND_WAIT_OR_RECOVER
                || method == PLAMEN_BROKER_V2_METHOD_BACKEND_EXTINGUISH_OR_RECOVER
                || method == PLAMEN_BROKER_V2_METHOD_BACKEND_READ_OUTPUT_OR_RECOVER)
                ? PLAMEN_BROKER_V2_OPERATION_RECOVER : 0))
        return PLAMEN_BROKER_V2_INVALID;
    if (method == PLAMEN_BROKER_V2_METHOD_PROVIDER_WAIT_DRIVER
        || method == PLAMEN_BROKER_V2_METHOD_BACKEND_WAIT_OR_RECOVER)
        service = PLAMEN_BROKER_V2_RPC_WAIT_DEADLINE_SECONDS;
    else if ((method >= PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET
            && method <= PLAMEN_BROKER_V2_METHOD_WORKSPACE_RECENSUS_LAYOUT)
        || (method >= PLAMEN_BROKER_V2_METHOD_PROVIDER_CREATE_STOPPED
            && method <= PLAMEN_BROKER_V2_METHOD_PROVIDER_DELETE_GUEST)
        || method == PLAMEN_BROKER_V2_METHOD_GUEST_ADMIT_STOPPED
        || method == PLAMEN_BROKER_V2_METHOD_GUEST_RESUME_ADMISSION
        || method == PLAMEN_BROKER_V2_METHOD_EXTINCTION_EXTINGUISH
        || method == PLAMEN_BROKER_V2_METHOD_ARTIFACT_CENSUS
        || method == PLAMEN_BROKER_V2_METHOD_EXPORT_EXPORT
        || method == PLAMEN_BROKER_V2_METHOD_BACKEND_START_OR_RECOVER
        || method == PLAMEN_BROKER_V2_METHOD_BACKEND_EXTINGUISH_OR_RECOVER)
        service = PLAMEN_BROKER_V2_RPC_MUTATION_DEADLINE_SECONDS;
    *service_seconds = service;
    *client_seconds = service + PLAMEN_BROKER_V2_RPC_CLIENT_GRACE_SECONDS;
    return PLAMEN_BROKER_V2_OK;
}

static int
canonical_payload_valid(const uint8_t *payload, uint32_t payload_size,
    const uint8_t expected_sha256[32])
{
    uint8_t digest[32];
    int valid;
    if (expected_sha256 == NULL || !required_digest(expected_sha256)
        || payload_size > PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX
        || (payload_size != 0 && payload == NULL))
        return 0;
    valid = plamen_broker_v2_sha256(payload, payload_size, digest) == 0
        && constant_equal(digest, expected_sha256, 32);
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return valid;
}

int
plamen_broker_v2_operation_request_encode(
    const struct plamen_broker_v2_operation_request *value, uint8_t *out,
    size_t capacity, size_t *size)
{
    size_t required;
    if (size != NULL) *size = 0;
    if (value == NULL || out == NULL || size == NULL
        || !plamen_broker_v2_authority_method_valid(value->authority_role,
            value->member, value->method, value->flags)
        || !required_digest(value->operation_key)
        || !required_digest(value->request_fingerprint)
        || !canonical_payload_valid(value->payload, value->payload_size,
            value->payload_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    required = PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE
        + value->payload_size;
    if (capacity < required) return PLAMEN_BROKER_V2_INVALID;
    store_u16(out, PLAMEN_BROKER_V2_VERSION);
    store_u16(out + 2, value->authority_role);
    store_u16(out + 4, value->member);
    store_u16(out + 6, value->method);
    store_u16(out + 8, value->flags);
    memcpy(out + 10, value->operation_key, 32);
    memcpy(out + 42, value->request_fingerprint, 32);
    memcpy(out + 74, value->prior_checkpoint_sha256, 32);
    memcpy(out + 106, value->payload_sha256, 32);
    store_u32(out + 138, value->payload_size);
    if (value->payload_size != 0)
        memcpy(out + PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE,
            value->payload, value->payload_size);
    *size = required;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_operation_request_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_operation_request *value)
{
    if (in == NULL || value == NULL
        || size < PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE
        || size > PLAMEN_BROKER_V2_MAX_PAYLOAD
        || load_u16(in) != PLAMEN_BROKER_V2_VERSION)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    value->authority_role = load_u16(in + 2);
    value->member = load_u16(in + 4);
    value->method = load_u16(in + 6);
    value->flags = load_u16(in + 8);
    memcpy(value->operation_key, in + 10, 32);
    memcpy(value->request_fingerprint, in + 42, 32);
    memcpy(value->prior_checkpoint_sha256, in + 74, 32);
    memcpy(value->payload_sha256, in + 106, 32);
    value->payload_size = load_u32(in + 138);
    value->payload = in + PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE;
    if (size != PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE
            + value->payload_size
        || !plamen_broker_v2_authority_method_valid(value->authority_role,
            value->member, value->method, value->flags)
        || !required_digest(value->operation_key)
        || !required_digest(value->request_fingerprint)
        || !canonical_payload_valid(value->payload, value->payload_size,
            value->payload_sha256)) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

static int
operation_response_fields_valid(
    const struct plamen_broker_v2_operation_response *value)
{
    return value != NULL
        && plamen_broker_v2_authority_method_valid(value->authority_role,
            value->member, value->method, 0)
        && value->disposition >= PLAMEN_BROKER_V2_OPERATION_OBSERVED
        && value->disposition <= PLAMEN_BROKER_V2_OPERATION_RECOVERED
        && value->state <= PLAMEN_BROKER_V2_OPERATION_STATE_FINISHED
        && required_digest(value->operation_key)
        && required_digest(value->request_sha256)
        && (value->state == PLAMEN_BROKER_V2_OPERATION_STATE_UNCHANGED
            ? constant_equal(value->prior_checkpoint_sha256,
                value->next_checkpoint_sha256, 32)
            : required_digest(value->next_checkpoint_sha256))
        && canonical_payload_valid(value->payload, value->payload_size,
            value->payload_sha256);
}

int
plamen_broker_v2_operation_response_encode(
    const struct plamen_broker_v2_operation_response *value, uint8_t *out,
    size_t capacity, size_t *size)
{
    size_t required;
    if (size != NULL) *size = 0;
    if (out == NULL || size == NULL || !operation_response_fields_valid(value))
        return PLAMEN_BROKER_V2_INVALID;
    required = PLAMEN_BROKER_V2_OPERATION_RESPONSE_PREFIX_SIZE
        + value->payload_size;
    if (capacity < required) return PLAMEN_BROKER_V2_INVALID;
    store_u16(out, PLAMEN_BROKER_V2_VERSION);
    store_u16(out + 2, value->authority_role);
    store_u16(out + 4, value->member);
    store_u16(out + 6, value->method);
    store_u16(out + 8, value->disposition);
    store_u16(out + 10, value->state);
    memcpy(out + 12, value->operation_key, 32);
    memcpy(out + 44, value->request_sha256, 32);
    memcpy(out + 76, value->prior_checkpoint_sha256, 32);
    memcpy(out + 108, value->next_checkpoint_sha256, 32);
    memcpy(out + 140, value->payload_sha256, 32);
    store_u32(out + 172, value->payload_size);
    if (value->payload_size != 0)
        memcpy(out + PLAMEN_BROKER_V2_OPERATION_RESPONSE_PREFIX_SIZE,
            value->payload, value->payload_size);
    *size = required;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_operation_response_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_operation_response *value)
{
    if (in == NULL || value == NULL
        || size < PLAMEN_BROKER_V2_OPERATION_RESPONSE_PREFIX_SIZE
        || size > PLAMEN_BROKER_V2_MAX_PAYLOAD
        || load_u16(in) != PLAMEN_BROKER_V2_VERSION)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    value->authority_role = load_u16(in + 2);
    value->member = load_u16(in + 4);
    value->method = load_u16(in + 6);
    value->disposition = load_u16(in + 8);
    value->state = load_u16(in + 10);
    memcpy(value->operation_key, in + 12, 32);
    memcpy(value->request_sha256, in + 44, 32);
    memcpy(value->prior_checkpoint_sha256, in + 76, 32);
    memcpy(value->next_checkpoint_sha256, in + 108, 32);
    memcpy(value->payload_sha256, in + 140, 32);
    value->payload_size = load_u32(in + 172);
    value->payload = in + PLAMEN_BROKER_V2_OPERATION_RESPONSE_PREFIX_SIZE;
    if (size != PLAMEN_BROKER_V2_OPERATION_RESPONSE_PREFIX_SIZE
            + value->payload_size
        || !operation_response_fields_valid(value)) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_operation_error_encode(
    const struct plamen_broker_v2_operation_error *value, uint8_t out[108])
{
    if (value == NULL || out == NULL
        || !plamen_broker_v2_authority_method_valid(value->authority_role,
            value->member, value->method, 0)
        || value->error_code < PLAMEN_BROKER_V2_SERVICE_ERR_INVALID_ENVELOPE
        || value->error_code > PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL
        || (value->flags & ~(PLAMEN_BROKER_V2_SERVICE_REGISTRATION_CONSUMED
            | PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED
            | PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED)) != 0
        || !required_digest(value->operation_key)
        || !required_digest(value->request_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    store_u16(out, PLAMEN_BROKER_V2_VERSION);
    store_u16(out + 2, value->authority_role);
    store_u16(out + 4, value->member);
    store_u16(out + 6, value->method);
    store_u16(out + 8, value->error_code);
    store_u16(out + 10, value->flags);
    memcpy(out + 12, value->operation_key, 32);
    memcpy(out + 44, value->request_sha256, 32);
    memcpy(out + 76, value->current_checkpoint_sha256, 32);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_operation_error_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_operation_error *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_OPERATION_ERROR_SIZE];
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_OPERATION_ERROR_SIZE
        || load_u16(in) != PLAMEN_BROKER_V2_VERSION)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    value->authority_role = load_u16(in + 2);
    value->member = load_u16(in + 4);
    value->method = load_u16(in + 6);
    value->error_code = load_u16(in + 8);
    value->flags = load_u16(in + 10);
    memcpy(value->operation_key, in + 12, 32);
    memcpy(value->request_sha256, in + 44, 32);
    memcpy(value->current_checkpoint_sha256, in + 76, 32);
    if (plamen_broker_v2_operation_error_encode(value, canonical) != 0
        || !constant_equal(canonical, in, sizeof(canonical))) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_operation_response_matches_request(
    const uint8_t *encoded_request, size_t encoded_request_size,
    const struct plamen_broker_v2_operation_request *request,
    const struct plamen_broker_v2_operation_response *response)
{
    uint8_t digest[32];
    int matches = 0;
    if (encoded_request == NULL || request == NULL || response == NULL
        || encoded_request_size < PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE
        || encoded_request_size > PLAMEN_BROKER_V2_MAX_PAYLOAD)
        return 0;
    if (plamen_broker_v2_sha256(encoded_request, encoded_request_size,
            digest) == 0
        && request->authority_role == response->authority_role
        && request->member == response->member
        && request->method == response->method
        && constant_equal(request->operation_key, response->operation_key, 32)
        && constant_equal(request->prior_checkpoint_sha256,
            response->prior_checkpoint_sha256, 32)
        && constant_equal(digest, response->request_sha256, 32))
        matches = 1;
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return matches;
}

int
plamen_broker_v2_operation_error_matches_request(
    const uint8_t *encoded_request, size_t encoded_request_size,
    const struct plamen_broker_v2_operation_request *request,
    const struct plamen_broker_v2_operation_error *error)
{
    uint8_t digest[32];
    int matches = 0;
    if (encoded_request == NULL || request == NULL || error == NULL
        || encoded_request_size < PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE
        || encoded_request_size > PLAMEN_BROKER_V2_MAX_PAYLOAD)
        return 0;
    if (plamen_broker_v2_sha256(encoded_request, encoded_request_size,
            digest) == 0
        && request->authority_role == error->authority_role
        && request->member == error->member
        && request->method == error->method
        && constant_equal(request->operation_key, error->operation_key, 32)
        && constant_equal(digest, error->request_sha256, 32))
        matches = 1;
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return matches;
}

static int
worker_open_valid(const struct plamen_broker_v2_worker_session_open *value)
{
    return value != NULL
        && value->authority_role == PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER
        && value->member == PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION
        && plamen_broker_v2_authority_method_valid(value->authority_role,
            value->member, value->method, value->flags)
        && required_digest(value->operation_key)
        && required_digest(value->request_sha256)
        && required_digest(value->prior_checkpoint_sha256)
        && required_digest(value->child_session_id)
        && value->control_socket.purpose
            == PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET
        && value->control_socket.target == 0
        && value->control_socket.access_mode == PLAMEN_BROKER_V2_FD_READ_WRITE
        && required_digest(value->control_socket.identity);
}

int
plamen_broker_v2_worker_session_open_encode(
    const struct plamen_broker_v2_worker_session_open *value,
    uint8_t out[PLAMEN_BROKER_V2_WORKER_SESSION_OPEN_SIZE])
{
    if (out == NULL || !worker_open_valid(value))
        return PLAMEN_BROKER_V2_INVALID;
    store_u16(out, PLAMEN_BROKER_V2_VERSION);
    store_u16(out + 2, value->authority_role);
    store_u16(out + 4, value->member);
    store_u16(out + 6, value->method);
    store_u16(out + 8, value->flags);
    store_u16(out + 10, 0);
    memcpy(out + 12, value->operation_key, 32);
    memcpy(out + 44, value->request_sha256, 32);
    memcpy(out + 76, value->prior_checkpoint_sha256, 32);
    memcpy(out + 108, value->child_session_id, 32);
    fd_metadata_store(out + 140, &value->control_socket);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_worker_session_open_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_worker_session_open *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_WORKER_SESSION_OPEN_SIZE];
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_WORKER_SESSION_OPEN_SIZE
        || load_u16(in) != PLAMEN_BROKER_V2_VERSION
        || load_u16(in + 10) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    value->authority_role = load_u16(in + 2);
    value->member = load_u16(in + 4);
    value->method = load_u16(in + 6);
    value->flags = load_u16(in + 8);
    memcpy(value->operation_key, in + 12, 32);
    memcpy(value->request_sha256, in + 44, 32);
    memcpy(value->prior_checkpoint_sha256, in + 76, 32);
    memcpy(value->child_session_id, in + 108, 32);
    fd_metadata_load(in + 140, &value->control_socket);
    if (!worker_open_valid(value)
        || plamen_broker_v2_worker_session_open_encode(value, canonical) != 0
        || !constant_equal(canonical, in, sizeof(canonical))) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

static int
worker_accepted_valid(
    const struct plamen_broker_v2_worker_session_accepted *value)
{
    return value != NULL
        && value->authority_role == PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER
        && value->member == PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION
        && value->method >= PLAMEN_BROKER_V2_METHOD_BACKEND_PREPARE
        && value->method <= PLAMEN_BROKER_V2_METHOD_BACKEND_CLOSE_OPERATION
        && value->status == 1U
        && required_digest(value->request_frame_sha256)
        && required_digest(value->operation_key)
        && required_digest(value->child_session_id)
        && required_digest(value->child_binding_sha256);
}

int
plamen_broker_v2_worker_session_accepted_encode(
    const struct plamen_broker_v2_worker_session_accepted *value,
    uint8_t out[PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED_SIZE])
{
    if (out == NULL || !worker_accepted_valid(value))
        return PLAMEN_BROKER_V2_INVALID;
    store_u16(out, PLAMEN_BROKER_V2_VERSION);
    store_u16(out + 2, value->authority_role);
    store_u16(out + 4, value->member);
    store_u16(out + 6, value->method);
    store_u16(out + 8, value->status);
    store_u16(out + 10, 0);
    memcpy(out + 12, value->request_frame_sha256, 32);
    memcpy(out + 44, value->operation_key, 32);
    memcpy(out + 76, value->child_session_id, 32);
    memcpy(out + 108, value->child_binding_sha256, 32);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_worker_session_accepted_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_worker_session_accepted *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED_SIZE];
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED_SIZE
        || load_u16(in) != PLAMEN_BROKER_V2_VERSION
        || load_u16(in + 10) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    value->authority_role = load_u16(in + 2);
    value->member = load_u16(in + 4);
    value->method = load_u16(in + 6);
    value->status = load_u16(in + 8);
    memcpy(value->request_frame_sha256, in + 12, 32);
    memcpy(value->operation_key, in + 44, 32);
    memcpy(value->child_session_id, in + 76, 32);
    memcpy(value->child_binding_sha256, in + 108, 32);
    if (!worker_accepted_valid(value)
        || plamen_broker_v2_worker_session_accepted_encode(value, canonical) != 0
        || !constant_equal(canonical, in, sizeof(canonical))) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_worker_session_derive_key(const uint8_t parent_key[32],
    const uint8_t parent_session_id[32], const uint8_t operation_key[32],
    const uint8_t child_session_id[32], uint8_t child_key[32])
{
    uint8_t binding[96];
    int status;
    if (!required_digest(parent_key) || !required_digest(parent_session_id)
        || !required_digest(operation_key) || !required_digest(child_session_id)
        || child_key == NULL)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(binding, parent_session_id, 32);
    memcpy(binding + 32, operation_key, 32);
    memcpy(binding + 64, child_session_id, 32);
    status = plamen_broker_v2_hmac_sha256(parent_key,
        PLAMEN_BROKER_V2_WORKER_SESSION_KEY_DOMAIN,
        sizeof(PLAMEN_BROKER_V2_WORKER_SESSION_KEY_DOMAIN),
        binding, sizeof(binding), child_key);
    plamen_broker_v2_secure_zero(binding, sizeof(binding));
    return status;
}

int
plamen_broker_v2_worker_session_derive_binding(
    const uint8_t parent_session_id[32],
    const struct plamen_broker_v2_worker_session_open *value,
    uint8_t child_binding_sha256[32])
{
    struct digest_context context;
    uint8_t integers[8];
    int status = PLAMEN_BROKER_V2_SYSTEM;
    memset(&context, 0, sizeof(context));
    if (!required_digest(parent_session_id) || !worker_open_valid(value)
        || child_binding_sha256 == NULL || digest_init(&context) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    store_u16(integers, value->authority_role);
    store_u16(integers + 2, value->member);
    store_u16(integers + 4, value->method);
    store_u16(integers + 6, value->flags);
    if (digest_update(&context, PLAMEN_BROKER_V2_WORKER_SESSION_BINDING_DOMAIN,
            sizeof(PLAMEN_BROKER_V2_WORKER_SESSION_BINDING_DOMAIN)) != 0
        || digest_update(&context, parent_session_id, 32) != 0
        || digest_update(&context, integers, sizeof(integers)) != 0
        || digest_update(&context, value->operation_key, 32) != 0
        || digest_update(&context, value->request_sha256, 32) != 0
        || digest_update(&context, value->prior_checkpoint_sha256, 32) != 0
        || digest_update(&context, value->child_session_id, 32) != 0
        || digest_update(&context, value->control_socket.identity, 32) != 0
        || digest_final(&context, child_binding_sha256) != 0)
        goto done;
    status = PLAMEN_BROKER_V2_OK;
done:
    if (status != 0) {
        digest_destroy(&context);
        plamen_broker_v2_secure_zero(child_binding_sha256, 32);
    }
    plamen_broker_v2_secure_zero(integers, sizeof(integers));
    return status;
}

static int
guest_bootstrap_checksum(const uint8_t *body, size_t body_size, uint8_t out[32])
{
    struct digest_context context;
    int status = PLAMEN_BROKER_V2_SYSTEM;
    memset(&context, 0, sizeof(context));
    if (body == NULL || out == NULL || digest_init(&context) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    if (digest_update(&context, PLAMEN_BROKER_V2_GUEST_BOOTSTRAP_DIGEST_DOMAIN,
            sizeof(PLAMEN_BROKER_V2_GUEST_BOOTSTRAP_DIGEST_DOMAIN)) == 0
        && digest_update(&context, body, body_size) == 0
        && digest_final(&context, out) == 0)
        status = PLAMEN_BROKER_V2_OK;
    if (status != 0) {
        digest_destroy(&context);
        plamen_broker_v2_secure_zero(out, 32);
    }
    return status;
}

static int
guest_bootstrap_id_valid(const char value[PLAMEN_BROKER_V2_MAX_ID + 1U])
{
    const char *end;
    size_t size;
    if (value == NULL) return 0;
    end = (const char *)memchr(value, '\0', PLAMEN_BROKER_V2_MAX_ID + 1U);
    if (end == NULL) return 0;
    size = (size_t)(end - value);
    return valid_id((const uint8_t *)value, size);
}

static int
guest_bootstrap_required(
    const struct plamen_broker_v2_guest_bootstrap_record *value)
{
    const uint8_t *digests[] = {
        value == NULL ? NULL : value->request_fingerprint,
        value == NULL ? NULL : value->request_projection_sha256,
        value == NULL ? NULL : value->runtime_layout_sha256,
        value == NULL ? NULL : value->image_closure_sha256,
        value == NULL ? NULL : value->backend_executable_identity,
        value == NULL ? NULL : value->backend_profile_identity,
        value == NULL ? NULL : value->credential_identity,
        value == NULL ? NULL : value->egress_policy_identity,
        value == NULL ? NULL : value->egress_admission_identity,
        value == NULL ? NULL : value->network_closure_sha256,
        value == NULL ? NULL : value->proxy_endpoint_sha256,
        value == NULL ? NULL : value->session_id,
        value == NULL ? NULL : value->session_key,
        value == NULL ? NULL : value->one_shot_nonce
    };
    size_t index;
    if (value == NULL || !guest_bootstrap_id_valid(value->request_id)
        || !guest_bootstrap_id_valid(value->attempt_id)
        || !guest_bootstrap_id_valid(value->run_id)
        || !guest_bootstrap_id_valid(value->provider_guest_id))
        return 0;
    for (index = 0; index < sizeof(digests) / sizeof(digests[0]); ++index)
        if (!required_digest(digests[index])) return 0;
    return 1;
}

int
plamen_broker_v2_guest_bootstrap_encode(
    const struct plamen_broker_v2_guest_bootstrap_record *value, uint8_t *out,
    size_t capacity, size_t *size, uint8_t record_sha256[32])
{
    struct plamen_broker_v2_writer writer;
    uint8_t checksum[32];
    size_t body_size, total;
    int status = PLAMEN_BROKER_V2_INVALID;
    if (!guest_bootstrap_required(value) || out == NULL || size == NULL
        || record_sha256 == NULL || capacity < 48U)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, "PLMGBS2\0", 8);
    store_u16(out + 8, PLAMEN_BROKER_V2_VERSION);
    store_u16(out + 10, PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER);
    store_u32(out + 12, 0);
    plamen_broker_v2_writer_init(&writer, out + 16, capacity - 16U - 32U);
    if (plamen_broker_v2_put_id(&writer, value->request_id,
            strlen(value->request_id)) != 0
        || plamen_broker_v2_put_id(&writer, value->attempt_id,
            strlen(value->attempt_id)) != 0
        || plamen_broker_v2_put_id(&writer, value->run_id,
            strlen(value->run_id)) != 0
        || plamen_broker_v2_put_id(&writer, value->provider_guest_id,
            strlen(value->provider_guest_id)) != 0
        || plamen_broker_v2_put_digest(&writer, value->request_fingerprint) != 0
        || plamen_broker_v2_put_digest(&writer,
            value->request_projection_sha256) != 0
        || plamen_broker_v2_put_digest(&writer, value->runtime_layout_sha256) != 0
        || plamen_broker_v2_put_digest(&writer, value->image_closure_sha256) != 0
        || plamen_broker_v2_put_digest(&writer,
            value->backend_executable_identity) != 0
        || plamen_broker_v2_put_digest(&writer,
            value->backend_profile_identity) != 0
        || plamen_broker_v2_put_digest(&writer, value->credential_identity) != 0
        || plamen_broker_v2_put_digest(&writer, value->egress_policy_identity) != 0
        || plamen_broker_v2_put_digest(&writer,
            value->egress_admission_identity) != 0
        || plamen_broker_v2_put_digest(&writer,
            value->network_closure_sha256) != 0
        || plamen_broker_v2_put_digest(&writer,
            value->proxy_endpoint_sha256) != 0
        || plamen_broker_v2_put_digest(&writer, value->session_id) != 0
        || plamen_broker_v2_put_digest(&writer, value->session_key) != 0
        || plamen_broker_v2_put_digest(&writer, value->one_shot_nonce) != 0)
        goto done;
    body_size = 16U + writer.offset; total = body_size + 32U;
    if (total > PLAMEN_BROKER_V2_GUEST_BOOTSTRAP_MAX_SIZE) goto done;
    store_u32(out + 12, (uint32_t)total);
    if (guest_bootstrap_checksum(out, body_size, checksum) != 0) goto done;
    memcpy(out + body_size, checksum, 32);
    if (plamen_broker_v2_sha256(out, total, record_sha256) != 0) goto done;
    *size = total;
    status = PLAMEN_BROKER_V2_OK;
done:
    plamen_broker_v2_secure_zero(checksum, sizeof(checksum));
    if (status != 0) {
        plamen_broker_v2_secure_zero(out, capacity);
        plamen_broker_v2_secure_zero(record_sha256, 32);
        *size = 0;
    }
    return status;
}

int
plamen_broker_v2_guest_bootstrap_decode(const uint8_t *in, size_t size,
    const uint8_t expected_record_sha256[32],
    struct plamen_broker_v2_guest_bootstrap_record *value)
{
    struct plamen_broker_v2_reader reader;
    uint8_t checksum[32], record_sha[32];
    size_t body_size;
    int status = PLAMEN_BROKER_V2_INVALID;
    if (in == NULL || value == NULL || !required_digest(expected_record_sha256)
        || size < 48U || size > PLAMEN_BROKER_V2_GUEST_BOOTSTRAP_MAX_SIZE
        || memcmp(in, "PLMGBS2\0", 8) != 0
        || load_u16(in + 8) != PLAMEN_BROKER_V2_VERSION
        || load_u16(in + 10) != PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER
        || load_u32(in + 12) != size)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    body_size = size - 32U;
    if (plamen_broker_v2_sha256(in, size, record_sha) != 0
        || !constant_equal(record_sha, expected_record_sha256, 32)
        || guest_bootstrap_checksum(in, body_size, checksum) != 0
        || !constant_equal(checksum, in + body_size, 32))
        goto done;
    plamen_broker_v2_reader_init(&reader, in + 16, body_size - 16U);
    if (plamen_broker_v2_get_id(&reader, value->request_id,
            sizeof(value->request_id)) != 0
        || plamen_broker_v2_get_id(&reader, value->attempt_id,
            sizeof(value->attempt_id)) != 0
        || plamen_broker_v2_get_id(&reader, value->run_id,
            sizeof(value->run_id)) != 0
        || plamen_broker_v2_get_id(&reader, value->provider_guest_id,
            sizeof(value->provider_guest_id)) != 0
        || plamen_broker_v2_get_digest(&reader, value->request_fingerprint) != 0
        || plamen_broker_v2_get_digest(&reader,
            value->request_projection_sha256) != 0
        || plamen_broker_v2_get_digest(&reader, value->runtime_layout_sha256) != 0
        || plamen_broker_v2_get_digest(&reader, value->image_closure_sha256) != 0
        || plamen_broker_v2_get_digest(&reader,
            value->backend_executable_identity) != 0
        || plamen_broker_v2_get_digest(&reader,
            value->backend_profile_identity) != 0
        || plamen_broker_v2_get_digest(&reader, value->credential_identity) != 0
        || plamen_broker_v2_get_digest(&reader, value->egress_policy_identity) != 0
        || plamen_broker_v2_get_digest(&reader,
            value->egress_admission_identity) != 0
        || plamen_broker_v2_get_digest(&reader,
            value->network_closure_sha256) != 0
        || plamen_broker_v2_get_digest(&reader,
            value->proxy_endpoint_sha256) != 0
        || plamen_broker_v2_get_digest(&reader, value->session_id) != 0
        || plamen_broker_v2_get_digest(&reader, value->session_key) != 0
        || plamen_broker_v2_get_digest(&reader, value->one_shot_nonce) != 0
        || reader.offset != reader.size
        || !guest_bootstrap_required(value))
        goto done;
    status = PLAMEN_BROKER_V2_OK;
done:
    plamen_broker_v2_secure_zero(checksum, sizeof(checksum));
    plamen_broker_v2_secure_zero(record_sha, sizeof(record_sha));
    if (status != 0) plamen_broker_v2_secure_zero(value, sizeof(*value));
    return status;
}

int
plamen_broker_v2_backend_process_identity_encode(
    const struct plamen_broker_v2_backend_process_identity *value,
    uint8_t out[212])
{
    if (value == NULL || out == NULL || !required_digest(value->operation_key)
        || !required_digest(value->start_request_sha256)
        || !required_digest(value->executable_identity_sha256)
        || !peer_valid(&value->peer)
        || !required_digest(value->native_process_handle_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    store_u16(out, PLAMEN_BROKER_V2_VERSION);
    store_u16(out + 2, PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION);
    store_u32(out + 4, 0);
    memcpy(out + 8, value->operation_key, 32);
    memcpy(out + 40, value->start_request_sha256, 32);
    memcpy(out + 72, value->executable_identity_sha256, 32);
    peer_store(out + 104, &value->peer);
    memcpy(out + 180, value->native_process_handle_sha256, 32);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_backend_process_identity_decode(const uint8_t *in,
    size_t size, struct plamen_broker_v2_backend_process_identity *value)
{
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_BACKEND_PROCESS_IDENTITY_SIZE
        || load_u16(in) != PLAMEN_BROKER_V2_VERSION
        || load_u16(in + 2) != PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION
        || load_u32(in + 4) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->operation_key, in + 8, 32);
    memcpy(value->start_request_sha256, in + 40, 32);
    memcpy(value->executable_identity_sha256, in + 72, 32);
    if (!peer_load(in + 104, &value->peer)) goto invalid_backend_identity;
    memcpy(value->native_process_handle_sha256, in + 180, 32);
    if (!required_digest(value->operation_key)
        || !required_digest(value->start_request_sha256)
        || !required_digest(value->executable_identity_sha256)
        || !required_digest(value->native_process_handle_sha256))
        goto invalid_backend_identity;
    return PLAMEN_BROKER_V2_OK;
invalid_backend_identity:
    plamen_broker_v2_secure_zero(value, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_service_readiness_encode(
    const struct plamen_broker_v2_service_readiness *value, uint8_t out[96])
{
    if (value == NULL || out == NULL
        || !required_digest(value->installed_closure_sha256)
        || !required_digest(value->broker_closure_sha256)
        || !required_digest(value->installation_receipt_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value->installed_closure_sha256, 32);
    memcpy(out + 32, value->broker_closure_sha256, 32);
    memcpy(out + 64, value->installation_receipt_sha256, 32);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_readiness_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_readiness *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_READINESS_SIZE];
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_SERVICE_READINESS_SIZE)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->installed_closure_sha256, in, 32);
    memcpy(value->broker_closure_sha256, in + 32, 32);
    memcpy(value->installation_receipt_sha256, in + 64, 32);
    if (plamen_broker_v2_service_readiness_encode(value, canonical) != 0
        || memcmp(canonical, in, sizeof(canonical)) != 0) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_ready_encode(
    const struct plamen_broker_v2_service_ready *value, uint8_t out[204])
{
    if (value == NULL || out == NULL
        || !required_digest(value->request_envelope_sha256)
        || !peer_valid(&value->service_peer)
        || !required_digest(value->installed_closure_sha256)
        || !required_digest(value->broker_closure_sha256)
        || !required_digest(value->installation_receipt_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value->request_envelope_sha256, 32);
    peer_store(out + 32, &value->service_peer);
    memcpy(out + 108, value->installed_closure_sha256, 32);
    memcpy(out + 140, value->broker_closure_sha256, 32);
    memcpy(out + 172, value->installation_receipt_sha256, 32);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_ready_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_ready *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_READY_SIZE];
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_SERVICE_READY_SIZE)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->request_envelope_sha256, in, 32);
    if (!peer_load(in + 32, &value->service_peer)) goto invalid_ready;
    memcpy(value->installed_closure_sha256, in + 108, 32);
    memcpy(value->broker_closure_sha256, in + 140, 32);
    memcpy(value->installation_receipt_sha256, in + 172, 32);
    if (plamen_broker_v2_service_ready_encode(value, canonical) != 0
        || memcmp(canonical, in, sizeof(canonical)) != 0)
        goto invalid_ready;
    return PLAMEN_BROKER_V2_OK;
invalid_ready:
    plamen_broker_v2_secure_zero(value, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_service_ready_matches_readiness(
    const struct plamen_broker_v2_service_readiness *request,
    const uint8_t request_envelope_sha256[32],
    const struct plamen_broker_v2_service_ready *ready)
{
    return request != NULL && request_envelope_sha256 != NULL && ready != NULL
        && required_digest(request_envelope_sha256)
        && memcmp(request_envelope_sha256,
            ready->request_envelope_sha256, 32) == 0
        && memcmp(request->installed_closure_sha256,
            ready->installed_closure_sha256, 32) == 0
        && memcmp(request->broker_closure_sha256,
            ready->broker_closure_sha256, 32) == 0
        && memcmp(request->installation_receipt_sha256,
            ready->installation_receipt_sha256, 32) == 0;
}

int
plamen_broker_v2_service_registration_descriptors_valid(
    const struct plamen_broker_v2_service_registration *value)
{
    const uint16_t all_slots = (uint16_t)((UINT32_C(1)
        << PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT) - 1U);
    const uint16_t optional = (uint16_t)((UINT16_C(1)
        << PLAMEN_BROKER_V2_RETAINED_DOCS)
        | (UINT16_C(1) << PLAMEN_BROKER_V2_RETAINED_SCOPE));
    const uint16_t resume = (uint16_t)(UINT16_C(1)
        << PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT);
    uint16_t required;
    size_t index;
    if (value == NULL || (value->authority_presence_mask & ~all_slots) != 0)
        return 0;
    required = (uint16_t)(all_slots & ~(optional | resume));
    if ((value->authority_presence_mask & required) != required
        || (all_zero(value->prior_audit_checkpoint_sha256, 32)
            ? (value->authority_presence_mask & resume) != 0
            : (value->authority_presence_mask & resume) == 0))
        return 0;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
            ++index) {
        const struct plamen_broker_v2_fd_metadata *metadata =
            &value->authority_descriptors[index];
        int present = (value->authority_presence_mask
            & (uint16_t)(UINT16_C(1) << index)) != 0;
        if (!present) {
            if (metadata->purpose != 0 || metadata->target != 0
                || metadata->access_mode != 0
                || !all_zero(metadata->identity, 32))
                return 0;
        } else if (metadata->purpose
                != PLAMEN_BROKER_V2_FD_AUTHORITY_CONFIG + index
            || metadata->target != index + 1U
            || metadata->access_mode != PLAMEN_BROKER_V2_FD_READ
            || all_zero(metadata->identity, 32)) {
            return 0;
        }
    }
    return 1;
}

int
plamen_broker_v2_service_registration_fd_count(
    const struct plamen_broker_v2_service_registration *value, uint16_t *out)
{
    uint16_t count = 1U, mask;
    if (out == NULL || !plamen_broker_v2_service_registration_descriptors_valid(
            value))
        return PLAMEN_BROKER_V2_INVALID;
    mask = value->authority_presence_mask;
    while (mask != 0) {
        count = (uint16_t)(count + (mask & 1U));
        mask >>= 1;
    }
    *out = count;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_registration_encode(
    const struct plamen_broker_v2_service_registration *value,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE])
{
    struct plamen_broker_v2_commitment decoded_commitment;
    int commitment_status;
    memset(&decoded_commitment, 0, sizeof(decoded_commitment));
    commitment_status = value == NULL ? PLAMEN_BROKER_V2_INVALID
        : commitment_binding_decode(value->commitment, value->commitment_size,
            value->commitment_sha256, value->audit_request_fingerprint,
            &decoded_commitment);
    if (value == NULL || out == NULL || !required_digest(value->installed_closure_sha256)
        || !required_digest(value->committed_audit_generation_sha256)
        || !required_digest(value->audit_request_fingerprint)
        || !required_digest(value->request_projection_sha256)
        || value->request_projection_size == 0
        || value->request_projection_size > PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX
        || commitment_status != 0
        || !all_zero(value->commitment + value->commitment_size,
            PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE - value->commitment_size)
        || !required_digest(value->python_entrypoint_sha256)
        || !required_digest(value->python_argv_sha256)
        || !required_digest(value->python_environment_sha256)
        || !peer_valid(&value->launcher) || !peer_valid(&value->suspended_child)
        || value->initial_interpreter_slot != 0
        || !initial_authority_role_valid(value->initial_authority_role)
        || !plamen_broker_v2_service_registration_descriptors_valid(value))
        goto invalid_registration_encode;
    memcpy(out, value->installed_closure_sha256, 32);
    memcpy(out + 32, value->committed_audit_generation_sha256, 32);
    memcpy(out + 64, value->audit_request_fingerprint, 32);
    memcpy(out + 96, value->request_projection_sha256, 32);
    store_u32(out + 128, value->request_projection_size);
    memcpy(out + 132, value->commitment_sha256, 32);
    store_u16(out + 164, value->commitment_size);
    memcpy(out + 166, value->commitment,
        PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE);
    memcpy(out + 682, value->python_entrypoint_sha256, 32);
    memcpy(out + 714, value->python_argv_sha256, 32);
    memcpy(out + 746, value->python_environment_sha256, 32);
    peer_store(out + 778, &value->launcher);
    peer_store(out + 854, &value->suspended_child);
    memcpy(out + 930, value->prior_audit_checkpoint_sha256, 32);
    store_u16(out + 962, value->initial_interpreter_slot);
    store_u16(out + 964, value->initial_authority_role);
    store_u16(out + 966, value->authority_presence_mask);
    store_u16(out + 968, 0);
    for (size_t index = 0;
            index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index)
        fd_metadata_store(out + 970U + index * 37U,
            &value->authority_descriptors[index]);
    plamen_broker_v2_secure_zero(&decoded_commitment,
        sizeof(decoded_commitment));
    return PLAMEN_BROKER_V2_OK;
invalid_registration_encode:
    plamen_broker_v2_secure_zero(&decoded_commitment,
        sizeof(decoded_commitment));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_service_registration_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_registration *value)
{
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->installed_closure_sha256, in, 32);
    memcpy(value->committed_audit_generation_sha256, in + 32, 32);
    memcpy(value->audit_request_fingerprint, in + 64, 32);
    memcpy(value->request_projection_sha256, in + 96, 32);
    value->request_projection_size = load_u32(in + 128);
    memcpy(value->commitment_sha256, in + 132, 32);
    value->commitment_size = load_u16(in + 164);
    memcpy(value->commitment, in + 166,
        PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE);
    memcpy(value->python_entrypoint_sha256, in + 682, 32);
    memcpy(value->python_argv_sha256, in + 714, 32);
    memcpy(value->python_environment_sha256, in + 746, 32);
    if (!peer_load(in + 778, &value->launcher)
        || !peer_load(in + 854, &value->suspended_child))
        goto invalid;
    memcpy(value->prior_audit_checkpoint_sha256, in + 930, 32);
    value->initial_interpreter_slot = load_u16(in + 962);
    value->initial_authority_role = load_u16(in + 964);
    value->authority_presence_mask = load_u16(in + 966);
    if (load_u16(in + 968) != 0) goto invalid;
    for (size_t index = 0;
            index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index)
        fd_metadata_load(in + 970U + index * 37U,
            &value->authority_descriptors[index]);
    if (!required_digest(value->installed_closure_sha256)
        || !required_digest(value->committed_audit_generation_sha256)
        || !required_digest(value->audit_request_fingerprint)
        || !required_digest(value->request_projection_sha256)
        || value->request_projection_size == 0
        || value->request_projection_size > PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX
        || !required_digest(value->commitment_sha256)
        || value->commitment_size == 0
        || value->commitment_size > PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE
        || !all_zero(value->commitment + value->commitment_size,
            PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE - value->commitment_size)
        || !required_digest(value->python_entrypoint_sha256)
        || !required_digest(value->python_argv_sha256)
        || !required_digest(value->python_environment_sha256)
        || value->initial_interpreter_slot != 0
        || !initial_authority_role_valid(value->initial_authority_role)
        || !plamen_broker_v2_service_registration_descriptors_valid(value))
        goto invalid;
    {
        struct plamen_broker_v2_commitment decoded_commitment;
        int status = commitment_binding_decode(value->commitment,
            value->commitment_size, value->commitment_sha256,
            value->audit_request_fingerprint, &decoded_commitment);
        plamen_broker_v2_secure_zero(&decoded_commitment,
            sizeof(decoded_commitment));
        if (status != 0) goto invalid;
    }
    return PLAMEN_BROKER_V2_OK;
invalid:
    plamen_broker_v2_secure_zero(value, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_service_registration_ack_encode(
    const struct plamen_broker_v2_service_registration_ack *value,
    uint8_t out[210])
{
    if (value == NULL || out == NULL
        || !required_digest(value->request_envelope_sha256)
        || !required_digest(value->registration_sha256)
        || !required_digest(value->registration_checkpoint_sha256)
        || !required_digest(value->broker_closure_sha256)
        || !peer_valid(&value->suspended_child)
        || value->initial_interpreter_slot != 0
        || !initial_authority_role_valid(value->initial_authority_role)
        || value->issuance_state != 0)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value->request_envelope_sha256, 32);
    memcpy(out + 32, value->registration_sha256, 32);
    memcpy(out + 64, value->registration_checkpoint_sha256, 32);
    memcpy(out + 96, value->broker_closure_sha256, 32);
    peer_store(out + 128, &value->suspended_child);
    store_u16(out + 204, value->initial_interpreter_slot);
    store_u16(out + 206, value->initial_authority_role);
    store_u16(out + 208, value->issuance_state);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_registration_ack_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_registration_ack *value)
{
    if (in == NULL || value == NULL || size != 210)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->request_envelope_sha256, in, 32);
    memcpy(value->registration_sha256, in + 32, 32);
    memcpy(value->registration_checkpoint_sha256, in + 64, 32);
    memcpy(value->broker_closure_sha256, in + 96, 32);
    if (!peer_load(in + 128, &value->suspended_child)) goto invalid_ack;
    value->initial_interpreter_slot = load_u16(in + 204);
    value->initial_authority_role = load_u16(in + 206);
    value->issuance_state = load_u16(in + 208);
    if (!required_digest(value->request_envelope_sha256)
        || !required_digest(value->registration_sha256)
        || !required_digest(value->registration_checkpoint_sha256)
        || !required_digest(value->broker_closure_sha256)
        || value->initial_interpreter_slot != 0
        || !initial_authority_role_valid(value->initial_authority_role)
        || value->issuance_state != 0)
        goto invalid_ack;
    return PLAMEN_BROKER_V2_OK;
invalid_ack:
    plamen_broker_v2_secure_zero(value, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

static void
fd_metadata_store(uint8_t out[37], const struct plamen_broker_v2_fd_metadata *value)
{
    store_u16(out, value->purpose);
    store_u16(out + 2, value->target);
    out[4] = value->access_mode;
    memcpy(out + 5, value->identity, 32);
}

static void
fd_metadata_load(const uint8_t in[37], struct plamen_broker_v2_fd_metadata *value)
{
    memset(value, 0, sizeof(*value));
    value->purpose = load_u16(in);
    value->target = load_u16(in + 2);
    value->access_mode = in[4];
    memcpy(value->identity, in + 5, 32);
}

int
plamen_broker_v2_service_session_lookup_encode(
    const struct plamen_broker_v2_service_session_lookup *value, uint8_t out[96])
{
    if (value == NULL || out == NULL
        || !required_digest(value->extension_closure_sha256)
        || !required_digest(value->interpreter_executable_sha256)
        || all_zero(value->session_id, 32))
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value->extension_closure_sha256, 32);
    memcpy(out + 32, value->interpreter_executable_sha256, 32);
    memcpy(out + 64, value->session_id, 32);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_session_lookup_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_session_lookup *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE];
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->extension_closure_sha256, in, 32);
    memcpy(value->interpreter_executable_sha256, in + 32, 32);
    memcpy(value->session_id, in + 64, 32);
    if (plamen_broker_v2_service_session_lookup_encode(value, canonical) != 0
        || memcmp(canonical, in, sizeof(canonical)) != 0) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_session_challenge_encode(
    const struct plamen_broker_v2_service_session_challenge *value,
    uint8_t out[954])
{
    struct plamen_broker_v2_commitment decoded_commitment;
    int commitment_status;
    memset(&decoded_commitment, 0, sizeof(decoded_commitment));
    commitment_status = value == NULL ? PLAMEN_BROKER_V2_INVALID
        : commitment_binding_decode(value->commitment, value->commitment_size,
            value->commitment_sha256, value->commitment,
            &decoded_commitment);
    if (value == NULL || out == NULL
        || !required_digest(value->request_envelope_sha256)
        || !required_digest(value->registration_sha256)
        || !required_digest(value->committed_audit_generation_sha256)
        || !required_digest(value->request_projection_sha256)
        || value->request_projection_size == 0
        || value->request_projection_size > PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX
        || commitment_status != 0
        || !all_zero(value->commitment + value->commitment_size,
            PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE - value->commitment_size)
        || !required_digest(value->installed_closure_sha256)
        || !required_digest(value->broker_closure_sha256)
        || !required_digest(value->extension_closure_sha256)
        || !required_digest(value->interpreter_executable_sha256)
        || !peer_valid(&value->extension_peer)
        || all_zero(value->session_id, 32)
        || value->initial_interpreter_slot != 0
        || !initial_authority_role_valid(value->initial_authority_role)
        || all_zero(value->challenge_nonce, 32))
        goto invalid_challenge_encode;
    memcpy(out, value->request_envelope_sha256, 32);
    memcpy(out + 32, value->registration_sha256, 32);
    memcpy(out + 64, value->committed_audit_generation_sha256, 32);
    memcpy(out + 96, value->request_projection_sha256, 32);
    store_u32(out + 128, value->request_projection_size);
    memcpy(out + 132, value->commitment_sha256, 32);
    store_u16(out + 164, value->commitment_size);
    memcpy(out + 166, value->commitment,
        PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE);
    memcpy(out + 682, value->installed_closure_sha256, 32);
    memcpy(out + 714, value->broker_closure_sha256, 32);
    memcpy(out + 746, value->extension_closure_sha256, 32);
    memcpy(out + 778, value->interpreter_executable_sha256, 32);
    peer_store(out + 810, &value->extension_peer);
    memcpy(out + 886, value->session_id, 32);
    store_u16(out + 918, value->initial_interpreter_slot);
    store_u16(out + 920, value->initial_authority_role);
    memcpy(out + 922, value->challenge_nonce, 32);
    plamen_broker_v2_secure_zero(&decoded_commitment,
        sizeof(decoded_commitment));
    return PLAMEN_BROKER_V2_OK;
invalid_challenge_encode:
    plamen_broker_v2_secure_zero(&decoded_commitment,
        sizeof(decoded_commitment));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_service_session_challenge_decode(const uint8_t *in,
    size_t size, struct plamen_broker_v2_service_session_challenge *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE];
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->request_envelope_sha256, in, 32);
    memcpy(value->registration_sha256, in + 32, 32);
    memcpy(value->committed_audit_generation_sha256, in + 64, 32);
    memcpy(value->request_projection_sha256, in + 96, 32);
    value->request_projection_size = load_u32(in + 128);
    memcpy(value->commitment_sha256, in + 132, 32);
    value->commitment_size = load_u16(in + 164);
    memcpy(value->commitment, in + 166,
        PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE);
    memcpy(value->installed_closure_sha256, in + 682, 32);
    memcpy(value->broker_closure_sha256, in + 714, 32);
    memcpy(value->extension_closure_sha256, in + 746, 32);
    memcpy(value->interpreter_executable_sha256, in + 778, 32);
    if (!peer_load(in + 810, &value->extension_peer)) goto invalid_challenge;
    memcpy(value->session_id, in + 886, 32);
    value->initial_interpreter_slot = load_u16(in + 918);
    value->initial_authority_role = load_u16(in + 920);
    memcpy(value->challenge_nonce, in + 922, 32);
    if (plamen_broker_v2_service_session_challenge_encode(value, canonical) != 0
        || memcmp(canonical, in, sizeof(canonical)) != 0)
        goto invalid_challenge;
    return PLAMEN_BROKER_V2_OK;
invalid_challenge:
    plamen_broker_v2_secure_zero(value, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

static int
session_descriptors_valid(const struct plamen_broker_v2_fd_metadata values[2])
{
    return values[0].purpose == PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET
        && values[0].target == 0
        && values[0].access_mode == PLAMEN_BROKER_V2_FD_READ_WRITE
        && required_digest(values[0].identity)
        && values[1].purpose == PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ
        && values[1].target == 1
        && values[1].access_mode == PLAMEN_BROKER_V2_FD_READ
        && required_digest(values[1].identity)
        && memcmp(values[0].identity, values[1].identity, 32) != 0;
}

int
plamen_broker_v2_service_session_open_encode(
    const struct plamen_broker_v2_service_session_open *value, uint8_t out[410])
{
    if (value == NULL || out == NULL
        || !required_digest(value->challenge_envelope_sha256)
        || all_zero(value->challenge_nonce, 32)
        || !required_digest(value->commitment_sha256)
        || !required_digest(value->registration_sha256)
        || !required_digest(value->committed_audit_generation_sha256)
        || !required_digest(value->extension_closure_sha256)
        || !required_digest(value->interpreter_executable_sha256)
        || !peer_valid(&value->extension_peer)
        || value->initial_interpreter_slot != 0
        || !initial_authority_role_valid(value->initial_authority_role)
        || all_zero(value->session_id, 32)
        || !session_descriptors_valid(value->descriptors))
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value->challenge_envelope_sha256, 32);
    memcpy(out + 32, value->challenge_nonce, 32);
    memcpy(out + 64, value->commitment_sha256, 32);
    memcpy(out + 96, value->registration_sha256, 32);
    memcpy(out + 128, value->committed_audit_generation_sha256, 32);
    memcpy(out + 160, value->extension_closure_sha256, 32);
    memcpy(out + 192, value->interpreter_executable_sha256, 32);
    peer_store(out + 224, &value->extension_peer);
    store_u16(out + 300, value->initial_interpreter_slot);
    store_u16(out + 302, value->initial_authority_role);
    memcpy(out + 304, value->session_id, 32);
    fd_metadata_store(out + 336, &value->descriptors[0]);
    fd_metadata_store(out + 373, &value->descriptors[1]);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_session_open_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_session_open *value)
{
    if (in == NULL || value == NULL
        || size != PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->challenge_envelope_sha256, in, 32);
    memcpy(value->challenge_nonce, in + 32, 32);
    memcpy(value->commitment_sha256, in + 64, 32);
    memcpy(value->registration_sha256, in + 96, 32);
    memcpy(value->committed_audit_generation_sha256, in + 128, 32);
    memcpy(value->extension_closure_sha256, in + 160, 32);
    memcpy(value->interpreter_executable_sha256, in + 192, 32);
    if (!peer_load(in + 224, &value->extension_peer)) goto invalid_open;
    value->initial_interpreter_slot = load_u16(in + 300);
    value->initial_authority_role = load_u16(in + 302);
    memcpy(value->session_id, in + 304, 32);
    fd_metadata_load(in + 336, &value->descriptors[0]);
    fd_metadata_load(in + 373, &value->descriptors[1]);
    if (!required_digest(value->challenge_envelope_sha256)
        || all_zero(value->challenge_nonce, 32)
        || !required_digest(value->commitment_sha256)
        || !required_digest(value->registration_sha256)
        || !required_digest(value->committed_audit_generation_sha256)
        || !required_digest(value->extension_closure_sha256)
        || !required_digest(value->interpreter_executable_sha256)
        || value->initial_interpreter_slot != 0
        || !initial_authority_role_valid(value->initial_authority_role)
        || all_zero(value->session_id, 32)
        || !session_descriptors_valid(value->descriptors))
        goto invalid_open;
    return PLAMEN_BROKER_V2_OK;
invalid_open:
    plamen_broker_v2_secure_zero(value, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_service_session_ack_encode(
    const struct plamen_broker_v2_service_session_ack *value, uint8_t out[164])
{
    if (value == NULL || out == NULL || !required_digest(value->registration_sha256)
        || !required_digest(value->session_binding_sha256)
        || !required_digest(value->registration_burn_checkpoint_sha256)
        || !required_digest(value->authority_bundle_sha256)
        || all_zero(value->session_id, 32)
        || !initial_authority_role_valid(value->initial_authority_role))
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value->registration_sha256, 32);
    memcpy(out + 32, value->session_binding_sha256, 32);
    memcpy(out + 64, value->registration_burn_checkpoint_sha256, 32);
    memcpy(out + 96, value->authority_bundle_sha256, 32);
    memcpy(out + 128, value->session_id, 32);
    store_u16(out + 160, value->initial_authority_role);
    store_u16(out + 162, 0);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_session_ack_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_session_ack *value)
{
    if (in == NULL || value == NULL || size != 164 || load_u16(in + 162) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(value->registration_sha256, in, 32);
    memcpy(value->session_binding_sha256, in + 32, 32);
    memcpy(value->registration_burn_checkpoint_sha256, in + 64, 32);
    memcpy(value->authority_bundle_sha256, in + 96, 32);
    memcpy(value->session_id, in + 128, 32);
    value->initial_authority_role = load_u16(in + 160);
    if (!required_digest(value->registration_sha256)
        || !required_digest(value->session_binding_sha256)
        || !required_digest(value->registration_burn_checkpoint_sha256)
        || !required_digest(value->authority_bundle_sha256)
        || all_zero(value->session_id, 32)
        || !initial_authority_role_valid(value->initial_authority_role)) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

static int
linux_session_scope_valid(uint16_t scope, uint32_t uid, uint32_t gid)
{
    return (scope == PLAMEN_BROKER_V2_LINUX_SCOPE_OUTER_USER && uid != 0U) ||
        (scope == PLAMEN_BROKER_V2_LINUX_SCOPE_GUEST_ROOT &&
         uid == 0U && gid == 0U);
}

static int
linux_session_authority_valid(uint16_t version, uint16_t scope,
        uint32_t uid, uint32_t gid, const uint8_t receipt[32],
        const uint8_t receipt_binding[32], const uint8_t deployment[32],
        const uint8_t service_bootstrap[32])
{
    return version == PLAMEN_BROKER_V2_LINUX_SESSION_ABI_VERSION &&
        linux_session_scope_valid(scope, uid, gid) &&
        required_digest(receipt) && required_digest(receipt_binding) &&
        required_digest(deployment) && required_digest(service_bootstrap);
}

static void
linux_session_authority_store(uint8_t out[140], uint16_t version,
        uint16_t scope, uint32_t uid, uint32_t gid,
        const uint8_t receipt[32], const uint8_t receipt_binding[32],
        const uint8_t deployment[32], const uint8_t service_bootstrap[32])
{
    store_u16(out, version);
    store_u16(out + 2U, scope);
    store_u32(out + 4U, uid);
    store_u32(out + 8U, gid);
    memcpy(out + 12U, receipt, 32U);
    memcpy(out + 44U, receipt_binding, 32U);
    memcpy(out + 76U, deployment, 32U);
    memcpy(out + 108U, service_bootstrap, 32U);
}

static int
linux_session_authority_load(const uint8_t in[140], uint16_t *version,
        uint16_t *scope, uint32_t *uid, uint32_t *gid, uint8_t receipt[32],
        uint8_t receipt_binding[32], uint8_t deployment[32],
        uint8_t service_bootstrap[32])
{
    *version = load_u16(in);
    *scope = load_u16(in + 2U);
    *uid = load_u32(in + 4U);
    *gid = load_u32(in + 8U);
    memcpy(receipt, in + 12U, 32U);
    memcpy(receipt_binding, in + 44U, 32U);
    memcpy(deployment, in + 76U, 32U);
    memcpy(service_bootstrap, in + 108U, 32U);
    return linux_session_authority_valid(*version, *scope, *uid, *gid,
        receipt, receipt_binding, deployment, service_bootstrap);
}

int
plamen_broker_v2_service_linux_session_lookup_encode(
    const struct plamen_broker_v2_service_linux_session_lookup *value,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP_SIZE])
{
    if (value == NULL || out == NULL || !linux_session_authority_valid(
            value->version, value->scope, value->expected_uid,
            value->expected_gid, value->install_receipt_sha256,
            value->receipt_session_binding_sha256,
            value->native_deployment_receipt_sha256,
            value->service_bootstrap_sha256) ||
            plamen_broker_v2_service_session_lookup_encode(
                &value->base, out + 140U) != PLAMEN_BROKER_V2_OK) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    linux_session_authority_store(out, value->version, value->scope,
        value->expected_uid, value->expected_gid,
        value->install_receipt_sha256,
        value->receipt_session_binding_sha256,
        value->native_deployment_receipt_sha256,
        value->service_bootstrap_sha256);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_linux_session_lookup_decode(
    const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_linux_session_lookup *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP_SIZE];
    if (in == NULL || value == NULL || size != sizeof(canonical))
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    if (!linux_session_authority_load(in, &value->version, &value->scope,
            &value->expected_uid, &value->expected_gid,
            value->install_receipt_sha256,
            value->receipt_session_binding_sha256,
            value->native_deployment_receipt_sha256,
            value->service_bootstrap_sha256) ||
            plamen_broker_v2_service_session_lookup_decode(
                in + 140U, size - 140U, &value->base) !=
                    PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_linux_session_lookup_encode(
                value, canonical) != PLAMEN_BROKER_V2_OK ||
            memcmp(in, canonical, sizeof(canonical)) != 0) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_linux_session_challenge_encode(
    const struct plamen_broker_v2_service_linux_session_challenge *value,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE_SIZE])
{
    if (value == NULL || out == NULL || !linux_session_authority_valid(
            value->version, value->scope, value->expected_uid,
            value->expected_gid, value->install_receipt_sha256,
            value->receipt_session_binding_sha256,
            value->native_deployment_receipt_sha256,
            value->service_bootstrap_sha256) ||
            plamen_broker_v2_service_session_challenge_encode(
                &value->base, out + 140U) != PLAMEN_BROKER_V2_OK) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    linux_session_authority_store(out, value->version, value->scope,
        value->expected_uid, value->expected_gid,
        value->install_receipt_sha256,
        value->receipt_session_binding_sha256,
        value->native_deployment_receipt_sha256,
        value->service_bootstrap_sha256);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_linux_session_challenge_decode(
    const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_linux_session_challenge *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE_SIZE];
    if (in == NULL || value == NULL || size != sizeof(canonical))
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    if (!linux_session_authority_load(in, &value->version, &value->scope,
            &value->expected_uid, &value->expected_gid,
            value->install_receipt_sha256,
            value->receipt_session_binding_sha256,
            value->native_deployment_receipt_sha256,
            value->service_bootstrap_sha256) ||
            plamen_broker_v2_service_session_challenge_decode(
                in + 140U, size - 140U, &value->base) !=
                    PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_linux_session_challenge_encode(
                value, canonical) != PLAMEN_BROKER_V2_OK ||
            memcmp(in, canonical, sizeof(canonical)) != 0) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_linux_session_open_encode(
    const struct plamen_broker_v2_service_linux_session_open *value,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN_SIZE])
{
    if (value == NULL || out == NULL || !linux_session_authority_valid(
            value->version, value->scope, value->expected_uid,
            value->expected_gid, value->install_receipt_sha256,
            value->receipt_session_binding_sha256,
            value->native_deployment_receipt_sha256,
            value->service_bootstrap_sha256) ||
            plamen_broker_v2_service_session_open_encode(
                &value->base, out + 140U) != PLAMEN_BROKER_V2_OK) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    linux_session_authority_store(out, value->version, value->scope,
        value->expected_uid, value->expected_gid,
        value->install_receipt_sha256,
        value->receipt_session_binding_sha256,
        value->native_deployment_receipt_sha256,
        value->service_bootstrap_sha256);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_linux_session_open_decode(
    const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_linux_session_open *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN_SIZE];
    if (in == NULL || value == NULL || size != sizeof(canonical))
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    if (!linux_session_authority_load(in, &value->version, &value->scope,
            &value->expected_uid, &value->expected_gid,
            value->install_receipt_sha256,
            value->receipt_session_binding_sha256,
            value->native_deployment_receipt_sha256,
            value->service_bootstrap_sha256) ||
            plamen_broker_v2_service_session_open_decode(
                in + 140U, size - 140U, &value->base) !=
                    PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_linux_session_open_encode(
                value, canonical) != PLAMEN_BROKER_V2_OK ||
            memcmp(in, canonical, sizeof(canonical)) != 0) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_linux_session_ack_encode(
    const struct plamen_broker_v2_service_linux_session_ack *value,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACK_SIZE])
{
    if (value == NULL || out == NULL ||
            !required_digest(value->request_envelope_sha256) ||
            !required_digest(value->receipt_session_binding_sha256) ||
            !required_digest(value->native_deployment_receipt_sha256) ||
            plamen_broker_v2_service_session_ack_encode(
                &value->base, out + 96U) != PLAMEN_BROKER_V2_OK) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    memcpy(out, value->request_envelope_sha256, 32U);
    memcpy(out + 32U, value->receipt_session_binding_sha256, 32U);
    memcpy(out + 64U, value->native_deployment_receipt_sha256, 32U);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_linux_session_ack_decode(
    const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_linux_session_ack *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACK_SIZE];
    if (in == NULL || value == NULL || size != sizeof(canonical))
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->request_envelope_sha256, in, 32U);
    memcpy(value->receipt_session_binding_sha256, in + 32U, 32U);
    memcpy(value->native_deployment_receipt_sha256, in + 64U, 32U);
    if (plamen_broker_v2_service_session_ack_decode(
            in + 96U, size - 96U, &value->base) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_linux_session_ack_encode(
                value, canonical) != PLAMEN_BROKER_V2_OK ||
            memcmp(in, canonical, sizeof(canonical)) != 0) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_linux_session_challenge_matches_lookup(
    const struct plamen_broker_v2_service_linux_session_lookup *lookup,
    const uint8_t lookup_envelope_sha256[32],
    const struct plamen_broker_v2_service_linux_session_challenge *challenge)
{
    return lookup != NULL && challenge != NULL &&
        lookup_envelope_sha256 != NULL &&
        challenge->version == lookup->version &&
        challenge->scope == lookup->scope &&
        challenge->expected_uid == lookup->expected_uid &&
        challenge->expected_gid == lookup->expected_gid &&
        memcmp(challenge->install_receipt_sha256,
               lookup->install_receipt_sha256, 32) == 0 &&
        memcmp(challenge->receipt_session_binding_sha256,
               lookup->receipt_session_binding_sha256, 32) == 0 &&
        memcmp(challenge->native_deployment_receipt_sha256,
               lookup->native_deployment_receipt_sha256, 32) == 0 &&
        memcmp(challenge->service_bootstrap_sha256,
               lookup->service_bootstrap_sha256, 32) == 0 &&
        plamen_broker_v2_service_session_challenge_matches_lookup(
            &lookup->base, lookup_envelope_sha256, &challenge->base);
}

int
plamen_broker_v2_service_linux_session_open_matches_challenge(
    const struct plamen_broker_v2_service_linux_session_challenge *challenge,
    const uint8_t challenge_envelope_sha256[32],
    const struct plamen_broker_v2_service_linux_session_open *open)
{
    return challenge != NULL && open != NULL &&
        challenge_envelope_sha256 != NULL &&
        open->version == challenge->version && open->scope == challenge->scope &&
        open->expected_uid == challenge->expected_uid &&
        open->expected_gid == challenge->expected_gid &&
        memcmp(open->install_receipt_sha256,
               challenge->install_receipt_sha256, 32) == 0 &&
        memcmp(open->receipt_session_binding_sha256,
               challenge->receipt_session_binding_sha256, 32) == 0 &&
        memcmp(open->native_deployment_receipt_sha256,
               challenge->native_deployment_receipt_sha256, 32) == 0 &&
        memcmp(open->service_bootstrap_sha256,
               challenge->service_bootstrap_sha256, 32) == 0 &&
        plamen_broker_v2_service_session_open_matches_challenge(
            &challenge->base, challenge_envelope_sha256, &open->base);
}

int
plamen_broker_v2_service_linux_session_ack_matches_open(
    const struct plamen_broker_v2_service_linux_session_open *open,
    const uint8_t open_envelope_sha256[32],
    const struct plamen_broker_v2_service_linux_session_ack *ack)
{
    return open != NULL && open_envelope_sha256 != NULL && ack != NULL &&
        required_digest(open_envelope_sha256) &&
        memcmp(ack->request_envelope_sha256,
               open_envelope_sha256, 32) == 0 &&
        memcmp(ack->receipt_session_binding_sha256,
               open->receipt_session_binding_sha256, 32) == 0 &&
        memcmp(ack->native_deployment_receipt_sha256,
               open->native_deployment_receipt_sha256, 32) == 0 &&
        plamen_broker_v2_service_session_ack_matches_open(
            &open->base, &ack->base);
}

static int
specialized_lane_valid(uint16_t lane)
{
    return lane >= PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        && lane <= PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL;
}

int
plamen_broker_v2_service_specialized_session_lookup_encode(
    const struct plamen_broker_v2_service_specialized_session_lookup *value,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP_SIZE])
{
    if (value == NULL || out == NULL
        || value->version != PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION
        || !specialized_lane_valid(value->lane)
        || all_zero(value->parent_session_id, 32)
        || !required_digest(value->registration_sha256)
        || !required_digest(value->authority_bundle_sha256)
        || !required_digest(value->extension_closure_sha256)
        || !required_digest(value->interpreter_executable_sha256)
        || all_zero(value->specialized_session_id, 32))
        return PLAMEN_BROKER_V2_INVALID;
    store_u16(out, value->version);
    store_u16(out + 2U, value->lane);
    memcpy(out + 4U, value->parent_session_id, 32U);
    memcpy(out + 36U, value->registration_sha256, 32U);
    memcpy(out + 68U, value->authority_bundle_sha256, 32U);
    memcpy(out + 100U, value->extension_closure_sha256, 32U);
    memcpy(out + 132U, value->interpreter_executable_sha256, 32U);
    memcpy(out + 164U, value->specialized_session_id, 32U);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_specialized_session_lookup_decode(
    const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_specialized_session_lookup *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP_SIZE];
    if (in == NULL || value == NULL || size != sizeof(canonical))
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    value->version = load_u16(in);
    value->lane = load_u16(in + 2U);
    memcpy(value->parent_session_id, in + 4U, 32U);
    memcpy(value->registration_sha256, in + 36U, 32U);
    memcpy(value->authority_bundle_sha256, in + 68U, 32U);
    memcpy(value->extension_closure_sha256, in + 100U, 32U);
    memcpy(value->interpreter_executable_sha256, in + 132U, 32U);
    memcpy(value->specialized_session_id, in + 164U, 32U);
    if (plamen_broker_v2_service_specialized_session_lookup_encode(
            value, canonical) != PLAMEN_BROKER_V2_OK
        || memcmp(in, canonical, sizeof(canonical)) != 0) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_specialized_session_challenge_encode(
    const struct plamen_broker_v2_service_specialized_session_challenge *value,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE])
{
    if (value == NULL || out == NULL
        || !required_digest(value->request_envelope_sha256)
        || all_zero(value->challenge_nonce, 32)
        || !required_digest(value->broker_closure_sha256)
        || plamen_broker_v2_service_specialized_session_lookup_encode(
            &value->lookup, out + 32U) != PLAMEN_BROKER_V2_OK)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value->request_envelope_sha256, 32U);
    peer_store(out + 228U, &value->extension_peer);
    memcpy(out + 304U, value->challenge_nonce, 32U);
    memcpy(out + 336U, value->broker_closure_sha256, 32U);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_specialized_session_challenge_decode(
    const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_specialized_session_challenge *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE];
    if (in == NULL || value == NULL || size != sizeof(canonical))
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->request_envelope_sha256, in, 32U);
    if (plamen_broker_v2_service_specialized_session_lookup_decode(
            in + 32U,
            PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP_SIZE,
            &value->lookup) != PLAMEN_BROKER_V2_OK
        || !peer_load(in + 228U, &value->extension_peer))
        goto invalid_specialized_challenge;
    memcpy(value->challenge_nonce, in + 304U, 32U);
    memcpy(value->broker_closure_sha256, in + 336U, 32U);
    if (plamen_broker_v2_service_specialized_session_challenge_encode(
            value, canonical) != PLAMEN_BROKER_V2_OK
        || memcmp(in, canonical, sizeof(canonical)) != 0)
        goto invalid_specialized_challenge;
    return PLAMEN_BROKER_V2_OK;
invalid_specialized_challenge:
    plamen_broker_v2_secure_zero(value, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_service_specialized_session_open_encode(
    const struct plamen_broker_v2_service_specialized_session_open *value,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE])
{
    if (value == NULL || out == NULL
        || !required_digest(value->challenge_envelope_sha256)
        || all_zero(value->challenge_nonce, 32)
        || value->version != PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION
        || !specialized_lane_valid(value->lane)
        || all_zero(value->parent_session_id, 32)
        || all_zero(value->specialized_session_id, 32)
        || !session_descriptors_valid(value->descriptors))
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value->challenge_envelope_sha256, 32U);
    memcpy(out + 32U, value->challenge_nonce, 32U);
    store_u16(out + 64U, value->version);
    store_u16(out + 66U, value->lane);
    memcpy(out + 68U, value->parent_session_id, 32U);
    memcpy(out + 100U, value->specialized_session_id, 32U);
    peer_store(out + 132U, &value->extension_peer);
    fd_metadata_store(out + 208U, &value->descriptors[0]);
    fd_metadata_store(out + 245U, &value->descriptors[1]);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_specialized_session_open_decode(
    const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_specialized_session_open *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE];
    if (in == NULL || value == NULL || size != sizeof(canonical))
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->challenge_envelope_sha256, in, 32U);
    memcpy(value->challenge_nonce, in + 32U, 32U);
    value->version = load_u16(in + 64U);
    value->lane = load_u16(in + 66U);
    memcpy(value->parent_session_id, in + 68U, 32U);
    memcpy(value->specialized_session_id, in + 100U, 32U);
    if (!peer_load(in + 132U, &value->extension_peer))
        goto invalid_specialized_open;
    fd_metadata_load(in + 208U, &value->descriptors[0]);
    fd_metadata_load(in + 245U, &value->descriptors[1]);
    if (plamen_broker_v2_service_specialized_session_open_encode(
            value, canonical) != PLAMEN_BROKER_V2_OK
        || memcmp(in, canonical, sizeof(canonical)) != 0)
        goto invalid_specialized_open;
    return PLAMEN_BROKER_V2_OK;
invalid_specialized_open:
    plamen_broker_v2_secure_zero(value, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_service_specialized_session_ack_encode(
    const struct plamen_broker_v2_service_specialized_session_ack *value,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACK_SIZE])
{
    if (value == NULL || out == NULL
        || !required_digest(value->request_envelope_sha256)
        || value->version != PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION
        || !specialized_lane_valid(value->lane)
        || all_zero(value->parent_session_id, 32)
        || all_zero(value->specialized_session_id, 32)
        || !required_digest(value->authority_binding_sha256)
        || !required_digest(value->session_binding_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, value->request_envelope_sha256, 32U);
    store_u16(out + 32U, value->version);
    store_u16(out + 34U, value->lane);
    memcpy(out + 36U, value->parent_session_id, 32U);
    memcpy(out + 68U, value->specialized_session_id, 32U);
    memcpy(out + 100U, value->authority_binding_sha256, 32U);
    memcpy(out + 132U, value->session_binding_sha256, 32U);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_specialized_session_ack_decode(
    const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_specialized_session_ack *value)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACK_SIZE];
    if (in == NULL || value == NULL || size != sizeof(canonical))
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    memcpy(value->request_envelope_sha256, in, 32U);
    value->version = load_u16(in + 32U);
    value->lane = load_u16(in + 34U);
    memcpy(value->parent_session_id, in + 36U, 32U);
    memcpy(value->specialized_session_id, in + 68U, 32U);
    memcpy(value->authority_binding_sha256, in + 100U, 32U);
    memcpy(value->session_binding_sha256, in + 132U, 32U);
    if (plamen_broker_v2_service_specialized_session_ack_encode(
            value, canonical) != PLAMEN_BROKER_V2_OK
        || memcmp(in, canonical, sizeof(canonical)) != 0) {
        plamen_broker_v2_secure_zero(value, sizeof(*value));
        return PLAMEN_BROKER_V2_INVALID;
    }
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_error_encode(
    const struct plamen_broker_v2_service_error *value, uint8_t out[40])
{
    const uint16_t allowed_flags = PLAMEN_BROKER_V2_SERVICE_REGISTRATION_CONSUMED
        | PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED
        | PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED;
    if (value == NULL || out == NULL
        || value->code < PLAMEN_BROKER_V2_SERVICE_ERR_INVALID_ENVELOPE
        || value->code > PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL
        || (value->flags & (uint16_t)~allowed_flags) != 0
        || !(value->failed_message_type == 0
            || value->failed_message_type == PLAMEN_BROKER_V2_SERVICE_READINESS
            || value->failed_message_type == PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
            || value->failed_message_type == PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY
            || value->failed_message_type == PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP
            || value->failed_message_type == PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN
            || value->failed_message_type ==
                PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP
            || value->failed_message_type ==
                PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN
            || value->failed_message_type ==
                PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP
            || value->failed_message_type ==
                PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN)
        || !required_digest(value->request_envelope_sha256))
        return PLAMEN_BROKER_V2_INVALID;
    store_u16(out, value->code);
    store_u16(out + 2, value->flags);
    store_u16(out + 4, value->failed_message_type);
    store_u16(out + 6, 0);
    memcpy(out + 8, value->request_envelope_sha256, 32);
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_service_error_decode(const uint8_t *in, size_t size,
    struct plamen_broker_v2_service_error *value)
{
    if (in == NULL || value == NULL || size != 40 || load_u16(in + 6) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    value->code = load_u16(in);
    value->flags = load_u16(in + 2);
    value->failed_message_type = load_u16(in + 4);
    memcpy(value->request_envelope_sha256, in + 8, 32);
    {
        uint8_t canonical[40];
        if (plamen_broker_v2_service_error_encode(value, canonical) != 0
            || memcmp(canonical, in, 40) != 0) {
            plamen_broker_v2_secure_zero(value, sizeof(*value));
            return PLAMEN_BROKER_V2_INVALID;
        }
    }
    return PLAMEN_BROKER_V2_OK;
}

static int
service_payload_canonical(uint16_t type, const uint8_t *payload, size_t size)
{
    uint8_t canonical[PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE];
    int status = PLAMEN_BROKER_V2_INVALID;
    if (payload == NULL || size > sizeof(canonical)) return 0;
    switch (type) {
    case PLAMEN_BROKER_V2_SERVICE_READINESS: {
        struct plamen_broker_v2_service_readiness value;
        status = plamen_broker_v2_service_readiness_decode(payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_readiness_encode(&value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_READY: {
        struct plamen_broker_v2_service_ready value;
        status = plamen_broker_v2_service_ready_decode(payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_ready_encode(&value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL:
    case PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY: {
        struct plamen_broker_v2_service_registration value;
        status = plamen_broker_v2_service_registration_decode(payload, size, &value);
        if (status == 0
            && ((type == PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
                    && !all_zero(value.prior_audit_checkpoint_sha256, 32))
                || (type == PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY
                    && all_zero(value.prior_audit_checkpoint_sha256, 32))
                || value.launcher.uid != value.suspended_child.uid
                || value.launcher.gid != value.suspended_child.gid))
            status = PLAMEN_BROKER_V2_INVALID;
        if (status == 0)
            status = plamen_broker_v2_service_registration_encode(&value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACCEPTED: {
        struct plamen_broker_v2_service_registration_ack value;
        status = plamen_broker_v2_service_registration_ack_decode(payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_registration_ack_encode(&value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP: {
        struct plamen_broker_v2_service_session_lookup value;
        status = plamen_broker_v2_service_session_lookup_decode(payload, size,
            &value);
        if (status == 0)
            status = plamen_broker_v2_service_session_lookup_encode(&value,
                canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE: {
        struct plamen_broker_v2_service_session_challenge value;
        status = plamen_broker_v2_service_session_challenge_decode(payload, size,
            &value);
        if (status == 0)
            status = plamen_broker_v2_service_session_challenge_encode(&value,
                canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN: {
        struct plamen_broker_v2_service_session_open value;
        status = plamen_broker_v2_service_session_open_decode(payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_session_open_encode(&value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_SESSION_ACCEPTED: {
        struct plamen_broker_v2_service_session_ack value;
        status = plamen_broker_v2_service_session_ack_decode(payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_session_ack_encode(&value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP: {
        struct plamen_broker_v2_service_specialized_session_lookup value;
        status = plamen_broker_v2_service_specialized_session_lookup_decode(
            payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_specialized_session_lookup_encode(
                &value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE: {
        struct plamen_broker_v2_service_specialized_session_challenge value;
        status = plamen_broker_v2_service_specialized_session_challenge_decode(
            payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_specialized_session_challenge_encode(
                &value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN: {
        struct plamen_broker_v2_service_specialized_session_open value;
        status = plamen_broker_v2_service_specialized_session_open_decode(
            payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_specialized_session_open_encode(
                &value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACCEPTED: {
        struct plamen_broker_v2_service_specialized_session_ack value;
        status = plamen_broker_v2_service_specialized_session_ack_decode(
            payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_specialized_session_ack_encode(
                &value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP: {
        struct plamen_broker_v2_service_linux_session_lookup value;
        status = plamen_broker_v2_service_linux_session_lookup_decode(
            payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_linux_session_lookup_encode(
                &value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE: {
        struct plamen_broker_v2_service_linux_session_challenge value;
        status = plamen_broker_v2_service_linux_session_challenge_decode(
            payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_linux_session_challenge_encode(
                &value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN: {
        struct plamen_broker_v2_service_linux_session_open value;
        status = plamen_broker_v2_service_linux_session_open_decode(
            payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_linux_session_open_encode(
                &value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACCEPTED: {
        struct plamen_broker_v2_service_linux_session_ack value;
        status = plamen_broker_v2_service_linux_session_ack_decode(
            payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_linux_session_ack_encode(
                &value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    case PLAMEN_BROKER_V2_SERVICE_ERROR: {
        struct plamen_broker_v2_service_error value;
        status = plamen_broker_v2_service_error_decode(payload, size, &value);
        if (status == 0)
            status = plamen_broker_v2_service_error_encode(&value, canonical);
        plamen_broker_v2_secure_zero(&value, sizeof(value));
        break;
    }
    default:
        return 0;
    }
    return status == 0 && memcmp(canonical, payload, size) == 0;
}

/* ---- Closed retained-config projection composer. ----------------------- */

#define BUILDER_DISCOVERY_MAGIC UINT32_C(0x50424444)
#define BUILDER_RESULT_MAGIC UINT32_C(0x50424452)
#define BUILDER_JSON_MAX_STRING PLAMEN_BROKER_V2_PROJECTION_PATH_MAX

enum builder_json_kind {
    BUILDER_JSON_NULL = 1,
    BUILDER_JSON_BOOL = 2,
    BUILDER_JSON_INTEGER = 3,
    BUILDER_JSON_STRING = 4,
    BUILDER_JSON_ARRAY = 5,
    BUILDER_JSON_OBJECT = 6
};

struct builder_json;

struct builder_json_member {
    char *key;
    struct builder_json *value;
};

struct builder_json {
    enum builder_json_kind kind;
    union {
        int boolean;
        char *text;
        struct {
            struct builder_json **items;
            size_t count;
        } array;
        struct {
            struct builder_json_member *items;
            size_t count;
        } object;
    } value;
};

struct builder_json_parser {
    const uint8_t *data;
    size_t size;
    size_t offset;
    unsigned nodes;
};

struct builder_buffer {
    uint8_t *data;
    size_t size;
    size_t capacity;
    size_t maximum;
};

static void builder_json_destroy(struct builder_json *);

static void
builder_skip_space(struct builder_json_parser *parser)
{
    while (parser->offset < parser->size) {
        uint8_t value = parser->data[parser->offset];
        if (value != ' ' && value != '\n' && value != '\r' && value != '\t')
            break;
        ++parser->offset;
    }
}

static int
builder_take(struct builder_json_parser *parser, uint8_t value)
{
    builder_skip_space(parser);
    if (parser->offset >= parser->size || parser->data[parser->offset] != value)
        return -1;
    ++parser->offset;
    return 0;
}

static int
builder_literal(struct builder_json_parser *parser, const char *literal)
{
    size_t size = strlen(literal);
    builder_skip_space(parser);
    if (parser->size - parser->offset < size
        || memcmp(parser->data + parser->offset, literal, size) != 0)
        return -1;
    parser->offset += size;
    return 0;
}

static int
builder_string(struct builder_json_parser *parser, char **out, size_t maximum,
    int key)
{
    char *value;
    size_t used = 0, capacity = 64U;
    uint8_t ch;
    int high, low;
    if (out == NULL || builder_take(parser, '"') != 0) return -1;
    value = malloc(capacity);
    if (value == NULL) return -1;
    while (parser->offset < parser->size) {
        ch = parser->data[parser->offset++];
        if (ch == '"') {
            if ((key && used == 0) || used > maximum) goto fail;
            value[used] = '\0';
            *out = value;
            return 0;
        }
        if (ch == 0 || ch >= 0x80 || ch < 0x20) goto fail;
        if (ch == '\\') {
            if (parser->offset >= parser->size) goto fail;
            ch = parser->data[parser->offset++];
            switch (ch) {
            case '"': case '\\': case '/': break;
            case 'b': ch = '\b'; break;
            case 'f': ch = '\f'; break;
            case 'n': ch = '\n'; break;
            case 'r': ch = '\r'; break;
            case 't': ch = '\t'; break;
            case 'u':
                if (parser->size - parser->offset < 4U
                    || parser->data[parser->offset] != '0'
                    || parser->data[parser->offset + 1U] != '0')
                    goto fail;
                high = projection_hex_digit(parser->data[parser->offset + 2U]);
                low = projection_hex_digit(parser->data[parser->offset + 3U]);
                if (high < 0 || low < 0) goto fail;
                ch = (uint8_t)((high << 4) | low);
                parser->offset += 4U;
                if (ch == 0 || ch >= 0x20) goto fail;
                break;
            default: goto fail;
            }
        }
        if (key && ch < 0x20) goto fail;
        if (used == maximum) goto fail;
        if (used + 1U == capacity) {
            char *grown;
            capacity *= 2U;
            if (capacity > maximum + 1U) capacity = maximum + 1U;
            grown = realloc(value, capacity);
            if (grown == NULL) goto fail;
            value = grown;
        }
        value[used++] = (char)ch;
    }
fail:
    plamen_broker_v2_secure_zero(value, capacity);
    free(value);
    return -1;
}

static int
builder_member_compare(const void *left, const void *right)
{
    const struct builder_json_member *a = left, *b = right;
    return strcmp(a->key, b->key);
}

static struct builder_json *builder_json_parse_value(
    struct builder_json_parser *, unsigned);

static struct builder_json *
builder_json_parse_array(struct builder_json_parser *parser, unsigned depth)
{
    struct builder_json *node = NULL, *child, **grown;
    if (builder_take(parser, '[') != 0) return NULL;
    node = calloc(1, sizeof(*node));
    if (node == NULL) return NULL;
    node->kind = BUILDER_JSON_ARRAY;
    builder_skip_space(parser);
    if (parser->offset < parser->size && parser->data[parser->offset] == ']') {
        ++parser->offset;
        return node;
    }
    for (;;) {
        child = builder_json_parse_value(parser, depth + 1U);
        if (child == NULL) goto fail;
        grown = realloc(node->value.array.items,
            (node->value.array.count + 1U) * sizeof(*grown));
        if (grown == NULL) { builder_json_destroy(child); goto fail; }
        node->value.array.items = grown;
        node->value.array.items[node->value.array.count++] = child;
        builder_skip_space(parser);
        if (parser->offset < parser->size && parser->data[parser->offset] == ']') {
            ++parser->offset;
            return node;
        }
        if (builder_take(parser, ',') != 0) goto fail;
    }
fail:
    builder_json_destroy(node);
    return NULL;
}

static struct builder_json *
builder_json_parse_object(struct builder_json_parser *parser, unsigned depth)
{
    struct builder_json *node = NULL, *child;
    struct builder_json_member *grown;
    char *key = NULL;
    size_t index;
    if (builder_take(parser, '{') != 0) return NULL;
    node = calloc(1, sizeof(*node));
    if (node == NULL) return NULL;
    node->kind = BUILDER_JSON_OBJECT;
    builder_skip_space(parser);
    if (parser->offset < parser->size && parser->data[parser->offset] == '}') {
        ++parser->offset;
        return node;
    }
    for (;;) {
        if (builder_string(parser, &key, 256U, 1) != 0
            || builder_take(parser, ':') != 0)
            goto fail;
        for (index = 0; index < node->value.object.count; ++index)
            if (strcmp(node->value.object.items[index].key, key) == 0) goto fail;
        child = builder_json_parse_value(parser, depth + 1U);
        if (child == NULL) goto fail;
        grown = realloc(node->value.object.items,
            (node->value.object.count + 1U) * sizeof(*grown));
        if (grown == NULL) { builder_json_destroy(child); goto fail; }
        node->value.object.items = grown;
        grown[node->value.object.count].key = key;
        grown[node->value.object.count].value = child;
        key = NULL;
        ++node->value.object.count;
        builder_skip_space(parser);
        if (parser->offset < parser->size && parser->data[parser->offset] == '}') {
            ++parser->offset;
            qsort(node->value.object.items, node->value.object.count,
                sizeof(*node->value.object.items), builder_member_compare);
            return node;
        }
        if (builder_take(parser, ',') != 0) goto fail;
    }
fail:
    free(key);
    builder_json_destroy(node);
    return NULL;
}

static struct builder_json *
builder_json_parse_value(struct builder_json_parser *parser, unsigned depth)
{
    struct builder_json *node;
    size_t start;
    uint64_t magnitude = 0, limit;
    int negative = 0;
    builder_skip_space(parser);
    if (depth > PROJECTION_CONFIG_MAX_DEPTH
        || ++parser->nodes > PROJECTION_CONFIG_MAX_NODES
        || parser->offset >= parser->size)
        return NULL;
    if (parser->data[parser->offset] == '{')
        return builder_json_parse_object(parser, depth);
    if (parser->data[parser->offset] == '[')
        return builder_json_parse_array(parser, depth);
    node = calloc(1, sizeof(*node));
    if (node == NULL) return NULL;
    if (parser->data[parser->offset] == '"') {
        node->kind = BUILDER_JSON_STRING;
        if (builder_string(parser, &node->value.text,
                BUILDER_JSON_MAX_STRING, 0) == 0)
            return node;
        goto fail;
    }
    if (parser->data[parser->offset] == 't') {
        node->kind = BUILDER_JSON_BOOL; node->value.boolean = 1;
        if (builder_literal(parser, "true") == 0) return node;
        goto fail;
    }
    if (parser->data[parser->offset] == 'f') {
        node->kind = BUILDER_JSON_BOOL;
        if (builder_literal(parser, "false") == 0) return node;
        goto fail;
    }
    if (parser->data[parser->offset] == 'n') {
        node->kind = BUILDER_JSON_NULL;
        if (builder_literal(parser, "null") == 0) return node;
        goto fail;
    }
    start = parser->offset;
    if (parser->data[parser->offset] == '-') {
        negative = 1;
        ++parser->offset;
    }
    if (parser->offset >= parser->size) goto fail;
    if (parser->data[parser->offset] == '0') {
        ++parser->offset;
        if (parser->offset < parser->size
            && parser->data[parser->offset] >= '0'
            && parser->data[parser->offset] <= '9') goto fail;
    } else {
        if (parser->data[parser->offset] < '1'
            || parser->data[parser->offset] > '9') goto fail;
        limit = negative ? UINT64_C(9223372036854775808)
            : UINT64_C(9223372036854775807);
        while (parser->offset < parser->size
            && parser->data[parser->offset] >= '0'
            && parser->data[parser->offset] <= '9') {
            unsigned digit = parser->data[parser->offset++] - '0';
            if (magnitude > (limit - digit) / 10U) goto fail;
            magnitude = magnitude * 10U + digit;
        }
    }
    if ((negative && magnitude == 0) || parser->offset - start > 20U) goto fail;
    node->kind = BUILDER_JSON_INTEGER;
    node->value.text = malloc(parser->offset - start + 1U);
    if (node->value.text == NULL) goto fail;
    memcpy(node->value.text, parser->data + start, parser->offset - start);
    node->value.text[parser->offset - start] = '\0';
    return node;
fail:
    builder_json_destroy(node);
    return NULL;
}

static void
builder_json_destroy(struct builder_json *node)
{
    size_t index;
    if (node == NULL) return;
    if (node->kind == BUILDER_JSON_STRING
        || node->kind == BUILDER_JSON_INTEGER) {
        if (node->value.text != NULL) {
            plamen_broker_v2_secure_zero(node->value.text,
                strlen(node->value.text));
            free(node->value.text);
        }
    } else if (node->kind == BUILDER_JSON_ARRAY) {
        for (index = 0; index < node->value.array.count; ++index)
            builder_json_destroy(node->value.array.items[index]);
        free(node->value.array.items);
    } else if (node->kind == BUILDER_JSON_OBJECT) {
        for (index = 0; index < node->value.object.count; ++index) {
            free(node->value.object.items[index].key);
            builder_json_destroy(node->value.object.items[index].value);
        }
        free(node->value.object.items);
    }
    plamen_broker_v2_secure_zero(node, sizeof(*node));
    free(node);
}

static struct builder_json *
builder_json_parse(const uint8_t *data, size_t size)
{
    struct builder_json_parser parser;
    struct builder_json *node;
    memset(&parser, 0, sizeof(parser));
    parser.data = data; parser.size = size;
    node = builder_json_parse_value(&parser, 0);
    builder_skip_space(&parser);
    if (node == NULL || parser.offset != parser.size) {
        builder_json_destroy(node);
        return NULL;
    }
    return node;
}

static struct builder_json *
builder_object_get(struct builder_json *object, const char *key)
{
    size_t low = 0, high;
    if (object == NULL || object->kind != BUILDER_JSON_OBJECT) return NULL;
    high = object->value.object.count;
    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        int order = strcmp(object->value.object.items[middle].key, key);
        if (order < 0) low = middle + 1U;
        else if (order > 0) high = middle;
        else return object->value.object.items[middle].value;
    }
    return NULL;
}

static int __attribute__((unused))
builder_object_set(struct builder_json *object, const char *key,
    enum builder_json_kind kind, const char *text)
{
    struct builder_json *node = NULL;
    struct builder_json_member *grown;
    size_t index;
    if (object == NULL || object->kind != BUILDER_JSON_OBJECT || key == NULL)
        return -1;
    node = calloc(1, sizeof(*node));
    if (node == NULL) return -1;
    node->kind = kind;
    if (kind == BUILDER_JSON_STRING) {
        node->value.text = strdup(text == NULL ? "" : text);
        if (node->value.text == NULL) { free(node); return -1; }
    }
    for (index = 0; index < object->value.object.count; ++index) {
        if (strcmp(object->value.object.items[index].key, key) == 0) {
            builder_json_destroy(object->value.object.items[index].value);
            object->value.object.items[index].value = node;
            return 0;
        }
    }
    grown = realloc(object->value.object.items,
        (object->value.object.count + 1U) * sizeof(*grown));
    if (grown == NULL) { builder_json_destroy(node); return -1; }
    object->value.object.items = grown;
    grown[object->value.object.count].key = strdup(key);
    if (grown[object->value.object.count].key == NULL) {
        builder_json_destroy(node); return -1;
    }
    grown[object->value.object.count].value = node;
    ++object->value.object.count;
    qsort(object->value.object.items, object->value.object.count,
        sizeof(*object->value.object.items), builder_member_compare);
    return 0;
}

static int
builder_buffer_write(struct builder_buffer *buffer, const void *data, size_t size)
{
    uint8_t *grown;
    size_t capacity;
    if (buffer == NULL || (size != 0 && data == NULL)
        || size > buffer->maximum - buffer->size)
        return -1;
    if (buffer->size + size > buffer->capacity) {
        capacity = buffer->capacity == 0 ? 256U : buffer->capacity;
        while (capacity < buffer->size + size) {
            if (capacity > buffer->maximum / 2U) {
                capacity = buffer->maximum;
                break;
            }
            capacity *= 2U;
        }
        grown = realloc(buffer->data, capacity);
        if (grown == NULL) return -1;
        buffer->data = grown; buffer->capacity = capacity;
    }
    if (size != 0) memcpy(buffer->data + buffer->size, data, size);
    buffer->size += size;
    return 0;
}

static int
builder_buffer_byte(struct builder_buffer *buffer, uint8_t value)
{
    return builder_buffer_write(buffer, &value, 1U);
}

static int
builder_render_string(struct builder_buffer *buffer, const char *value)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *cursor = (const unsigned char *)value;
    if (builder_buffer_byte(buffer, '"') != 0) return -1;
    while (*cursor != 0) {
        uint8_t ch = *cursor++;
        if (ch == '"' || ch == '\\') {
            if (builder_buffer_byte(buffer, '\\') != 0
                || builder_buffer_byte(buffer, ch) != 0) return -1;
        } else if (ch < 0x20) {
            uint8_t escaped[6] = {'\\', 'u', '0', '0',
                (uint8_t)hex[ch >> 4], (uint8_t)hex[ch & 15U]};
            if (builder_buffer_write(buffer, escaped, sizeof(escaped)) != 0)
                return -1;
        } else if (builder_buffer_byte(buffer, ch) != 0) return -1;
    }
    return builder_buffer_byte(buffer, '"');
}

static int __attribute__((unused))
builder_json_render(struct builder_buffer *buffer, const struct builder_json *node)
{
    size_t index;
    if (buffer == NULL || node == NULL) return -1;
    switch (node->kind) {
    case BUILDER_JSON_NULL:
        return builder_buffer_write(buffer, "null", 4U);
    case BUILDER_JSON_BOOL:
        return builder_buffer_write(buffer, node->value.boolean ? "true" : "false",
            node->value.boolean ? 4U : 5U);
    case BUILDER_JSON_INTEGER:
        return builder_buffer_write(buffer, node->value.text,
            strlen(node->value.text));
    case BUILDER_JSON_STRING:
        return builder_render_string(buffer, node->value.text);
    case BUILDER_JSON_ARRAY:
        if (builder_buffer_byte(buffer, '[') != 0) return -1;
        for (index = 0; index < node->value.array.count; ++index) {
            if ((index != 0 && builder_buffer_byte(buffer, ',') != 0)
                || builder_json_render(buffer, node->value.array.items[index]) != 0)
                return -1;
        }
        return builder_buffer_byte(buffer, ']');
    case BUILDER_JSON_OBJECT:
        if (builder_buffer_byte(buffer, '{') != 0) return -1;
        for (index = 0; index < node->value.object.count; ++index) {
            if ((index != 0 && builder_buffer_byte(buffer, ',') != 0)
                || builder_render_string(buffer,
                    node->value.object.items[index].key) != 0
                || builder_buffer_byte(buffer, ':') != 0
                || builder_json_render(buffer,
                    node->value.object.items[index].value) != 0)
                return -1;
        }
        return builder_buffer_byte(buffer, '}');
    default:
        return -1;
    }
}

static int
builder_same_stat(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino
        && left->st_mode == right->st_mode && left->st_uid == right->st_uid
        && left->st_gid == right->st_gid && left->st_size == right->st_size
        && left->st_nlink == right->st_nlink
#ifdef __APPLE__
        && left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec
        && left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec
        && left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec
        && left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec
#else
        && left->st_mtim.tv_sec == right->st_mtim.tv_sec
        && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec
        && left->st_ctim.tv_sec == right->st_ctim.tv_sec
        && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec
#endif
        ;
}

static int
builder_read_regular(int fd, size_t maximum, uint8_t **out, size_t *out_size,
    uint8_t content_sha256[32])
{
    struct stat before, after;
    uint8_t *bytes = NULL, extra;
    size_t offset = 0, size;
    ssize_t amount;
    if (out != NULL) *out = NULL;
    if (out_size != NULL) *out_size = 0;
    if (fd < 0 || out == NULL || out_size == NULL || content_sha256 == NULL
        || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_nlink != 1 || before.st_size <= 0
        || (uint64_t)before.st_size > maximum || fd_access(fd) != PLAMEN_BROKER_V2_FD_READ)
        return PLAMEN_BROKER_V2_FD_INVALID;
    size = (size_t)before.st_size;
    bytes = malloc(size);
    if (bytes == NULL) return PLAMEN_BROKER_V2_NOMEM;
    while (offset < size) {
        amount = pread(fd, bytes + offset, size - offset, (off_t)offset);
        if (amount <= 0) goto invalid;
        offset += (size_t)amount;
    }
    if (pread(fd, &extra, 1U, before.st_size) != 0
        || fstat(fd, &after) != 0 || !builder_same_stat(&before, &after))
        goto invalid;
    if (plamen_broker_v2_sha256(bytes, size, content_sha256) != 0) {
        plamen_broker_v2_secure_zero(bytes, size); free(bytes);
        return PLAMEN_BROKER_V2_SYSTEM;
    }
    *out = bytes; *out_size = size;
    return PLAMEN_BROKER_V2_OK;
invalid:
    plamen_broker_v2_secure_zero(bytes, size); free(bytes);
    return PLAMEN_BROKER_V2_FD_INVALID;
}

static int
builder_path_valid(const char *path)
{
    size_t size;
    if (path == NULL || path[0] != '/' || path[1] == '/'
        || strchr(path, '\\') != NULL || strchr(path, '\n') != NULL
        || strchr(path, '\r') != NULL || strchr(path, '\t') != NULL)
        return 0;
    size = strlen(path);
    return size > 1U && size <= PLAMEN_BROKER_V2_PROJECTION_PATH_MAX
        && path[size - 1U] != '/' && strstr(path, "/./") == NULL
        && strstr(path, "/../") == NULL
        && !(size >= 2U && strcmp(path + size - 2U, "/.") == 0)
        && !(size >= 3U && strcmp(path + size - 3U, "/..") == 0);
}

static int
builder_copy_string_field(struct builder_json *root, const char *name,
    char *out, size_t capacity, int optional, uint8_t *present)
{
    struct builder_json *value = builder_object_get(root, name);
    size_t size;
    if (present != NULL) *present = 0;
    if (value == NULL || value->kind == BUILDER_JSON_NULL
        || (value->kind == BUILDER_JSON_STRING && value->value.text[0] == '\0'))
        return optional ? 0 : -1;
    if (value->kind != BUILDER_JSON_STRING) return -1;
    size = strlen(value->value.text);
    if (size >= capacity) return -1;
    memcpy(out, value->value.text, size + 1U);
    if (present != NULL) *present = 1;
    return 0;
}

void
plamen_broker_v2_projection_discovery_destroy(
    struct plamen_broker_v2_projection_discovery *value)
{
    if (value != NULL && value->ownership_magic == BUILDER_DISCOVERY_MAGIC)
        plamen_broker_v2_secure_zero(value, sizeof(*value));
}

int
plamen_broker_v2_projection_discover_config(uint16_t startup_intent,
    const char *config_path, int config_fd,
    struct plamen_broker_v2_projection_discovery *out)
{
    struct plamen_broker_v2_projection_discovery value;
    struct builder_json *root = NULL, *docs_inputs;
    uint8_t *raw = NULL;
    size_t raw_size = 0, config_path_size, scratch_size;
    int status;
    memset(&value, 0, sizeof(value));
    if (out == NULL) return PLAMEN_BROKER_V2_INVALID;
    memset(out, 0, sizeof(*out));
    if ((startup_intent != PLAMEN_BROKER_V2_STARTUP_START_NEW_RUN
            && startup_intent != PLAMEN_BROKER_V2_STARTUP_RESUME_EXISTING)
        || !builder_path_valid(config_path))
        return PLAMEN_BROKER_V2_INVALID;
    config_path_size = strlen(config_path);
    if (config_path_size < sizeof("/.scratchpad/config.json") - 1U
        || strcmp(config_path + config_path_size
                - (sizeof("/.scratchpad/config.json") - 1U),
            "/.scratchpad/config.json") != 0)
        return PLAMEN_BROKER_V2_INVALID;
    status = builder_read_regular(config_fd, PROJECTION_CONFIG_MAX_SIZE,
        &raw, &raw_size, value.config_content_sha256);
    if (status != 0) goto done;
    if (memchr(raw, '\0', raw_size) != NULL || !valid_utf8(raw, raw_size)) {
        status = PLAMEN_BROKER_V2_INVALID; goto done;
    }
    root = builder_json_parse(raw, raw_size);
    if (root == NULL || root->kind != BUILDER_JSON_OBJECT
        || builder_copy_string_field(root, "project_root", value.project_root,
            sizeof(value.project_root), 0, NULL) != 0
        || builder_copy_string_field(root, "scratchpad", value.scratchpad,
            sizeof(value.scratchpad), 0, NULL) != 0
        || builder_copy_string_field(root, "docs_path", value.docs_path,
            sizeof(value.docs_path), 1, &value.has_docs) != 0
        || builder_copy_string_field(root, "scope_file", value.scope_file,
            sizeof(value.scope_file), 1, &value.has_scope) != 0
        || builder_copy_string_field(root, "pipeline", value.pipeline,
            sizeof(value.pipeline), 0, NULL) != 0
        || builder_copy_string_field(root, "mode", value.mode,
            sizeof(value.mode), 0, NULL) != 0
        || builder_copy_string_field(root, "cli_backend", value.backend,
            sizeof(value.backend), 0, NULL) != 0
        || builder_copy_string_field(root, "language", value.language,
            sizeof(value.language), 0, NULL) != 0
        || !builder_path_valid(value.project_root)
        || !builder_path_valid(value.scratchpad)
        || (value.has_docs && !builder_path_valid(value.docs_path))
        || (value.has_scope && !builder_path_valid(value.scope_file))
        || (strcmp(value.pipeline, "sc") != 0 && strcmp(value.pipeline, "l1") != 0)
        || (strcmp(value.mode, "light") != 0 && strcmp(value.mode, "core") != 0
            && strcmp(value.mode, "thorough") != 0)
        || (strcmp(value.backend, "codex") != 0
            && strcmp(value.backend, "claude") != 0)) {
        status = PLAMEN_BROKER_V2_INVALID; goto done;
    }
    docs_inputs = builder_object_get(root, "docs_inputs");
    if (docs_inputs != NULL && docs_inputs->kind != BUILDER_JSON_NULL) {
        status = PLAMEN_BROKER_V2_UNSUPPORTED; goto done;
    }
    scratch_size = strlen(value.scratchpad);
    if (scratch_size != config_path_size - sizeof("/config.json") + 1U
        || memcmp(value.scratchpad, config_path, scratch_size) != 0
        || value.scratchpad[scratch_size - 1U] == '/'
        || strlen(value.project_root) + sizeof("/.scratchpad")
            != scratch_size + 1U
        || memcmp(value.project_root, value.scratchpad,
            strlen(value.project_root)) != 0
        || strcmp(value.scratchpad + strlen(value.project_root),
            "/.scratchpad") != 0) {
        status = PLAMEN_BROKER_V2_INVALID; goto done;
    }
    if (snprintf(value.resume_checkpoint_path,
            sizeof(value.resume_checkpoint_path), "%s/_v2_checkpoint.json",
            value.scratchpad) < 0
        || strlen(value.resume_checkpoint_path) >= sizeof(value.resume_checkpoint_path)) {
        status = PLAMEN_BROKER_V2_INVALID; goto done;
    }
    if (plamen_broker_v2_fd_identity(config_fd, value.config_identity) != 0) {
        status = PLAMEN_BROKER_V2_FD_INVALID; goto done;
    }
    value.startup_intent = startup_intent;
    memcpy(value.config_path, config_path, config_path_size + 1U);
#ifdef __APPLE__
    strcpy(value.provider_selector, "apple-container-v2");
#else
    strcpy(value.provider_selector, "podman-v2");
#endif
    strcpy(value.backend_profile_selector, value.backend);
    strcpy(value.credential_selector, value.backend);
    strcpy(value.egress_selector, "verified-egress-v2");
    value.ownership_magic = BUILDER_DISCOVERY_MAGIC;
    *out = value;
    status = PLAMEN_BROKER_V2_OK;
done:
    builder_json_destroy(root);
    if (raw != NULL) {
        plamen_broker_v2_secure_zero(raw, raw_size); free(raw);
    }
    if (status != 0) plamen_broker_v2_secure_zero(out, sizeof(*out));
    plamen_broker_v2_secure_zero(&value, sizeof(value));
    return status;
}

static int
builder_hash_regular(int fd, uint64_t maximum, const uint8_t expected[32],
    uint8_t prefix[PLAMEN_BROKER_V2_RUNTIME_MANIFEST_HEADER_SIZE
        + PLAMEN_BROKER_V2_RUNTIME_BINDING_SIZE],
    uint8_t trailer[32], uint64_t *size_out)
{
    struct stat before, after;
    struct digest_context full, body;
    uint8_t buffer[65536], full_sha[32], body_sha[32];
    uint64_t size, offset = 0, body_size;
    ssize_t amount;
    int status = PLAMEN_BROKER_V2_FD_INVALID;
    memset(&full, 0, sizeof(full)); memset(&body, 0, sizeof(body));
    if (fd < 0 || expected == NULL || prefix == NULL || trailer == NULL
        || size_out == NULL || all_zero(expected, 32)
        || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_nlink != 1 || before.st_size < 0
        || (uint64_t)before.st_size > maximum
        || (uint64_t)before.st_size
            < PLAMEN_BROKER_V2_RUNTIME_MANIFEST_HEADER_SIZE
                + PLAMEN_BROKER_V2_RUNTIME_BINDING_SIZE + 32U
        || fd_access(fd) != PLAMEN_BROKER_V2_FD_READ)
        return PLAMEN_BROKER_V2_FD_INVALID;
    size = (uint64_t)before.st_size; body_size = size - 32U;
    if (digest_init(&full) != 0 || digest_init(&body) != 0) {
        status = PLAMEN_BROKER_V2_SYSTEM; goto done;
    }
    while (offset < size) {
        size_t wanted = size - offset > sizeof(buffer)
            ? sizeof(buffer) : (size_t)(size - offset);
        amount = pread(fd, buffer, wanted, (off_t)offset);
        if (amount <= 0 || digest_update(&full, buffer, (size_t)amount) != 0)
            goto done;
        if (offset < body_size) {
            size_t body_amount = (uint64_t)amount > body_size - offset
                ? (size_t)(body_size - offset) : (size_t)amount;
            if (digest_update(&body, buffer, body_amount) != 0) goto done;
        }
        if (offset < PLAMEN_BROKER_V2_RUNTIME_MANIFEST_HEADER_SIZE
                + PLAMEN_BROKER_V2_RUNTIME_BINDING_SIZE) {
            size_t prefix_amount = (uint64_t)amount >
                    PLAMEN_BROKER_V2_RUNTIME_MANIFEST_HEADER_SIZE
                        + PLAMEN_BROKER_V2_RUNTIME_BINDING_SIZE - offset
                ? (size_t)(PLAMEN_BROKER_V2_RUNTIME_MANIFEST_HEADER_SIZE
                    + PLAMEN_BROKER_V2_RUNTIME_BINDING_SIZE - offset)
                : (size_t)amount;
            memcpy(prefix + offset, buffer, prefix_amount);
        }
        if (offset + (uint64_t)amount > body_size) {
            size_t source = offset < body_size ? (size_t)(body_size - offset) : 0;
            size_t destination = offset < body_size ? 0 : (size_t)(offset - body_size);
            memcpy(trailer + destination, buffer + source,
                (size_t)amount - source);
        }
        offset += (uint64_t)amount;
    }
    if (pread(fd, buffer, 1U, (off_t)size) != 0
        || fstat(fd, &after) != 0 || !builder_same_stat(&before, &after))
        goto done;
    if (digest_final(&full, full_sha) != 0 || digest_final(&body, body_sha) != 0) {
        status = PLAMEN_BROKER_V2_SYSTEM; goto done;
    }
    if (!constant_equal(full_sha, expected, 32)
        || !constant_equal(body_sha, trailer, 32))
        goto done;
    *size_out = size;
    status = PLAMEN_BROKER_V2_OK;
done:
    digest_destroy(&full); digest_destroy(&body);
    plamen_broker_v2_secure_zero(buffer, sizeof(buffer));
    plamen_broker_v2_secure_zero(full_sha, sizeof(full_sha));
    plamen_broker_v2_secure_zero(body_sha, sizeof(body_sha));
    return status;
}

static int
builder_content_sha_regular(int fd, uint64_t maximum, int executable,
    uint8_t out[32])
{
    struct stat before, after;
    struct digest_context context;
    uint8_t buffer[65536];
    uint64_t offset, size;
    ssize_t amount;
    int status = PLAMEN_BROKER_V2_FD_INVALID;
    memset(&context, 0, sizeof(context));
    if (fd < 0 || out == NULL || fstat(fd, &before) != 0
        || !S_ISREG(before.st_mode) || before.st_nlink != 1
        || before.st_size <= 0 || (uint64_t)before.st_size > maximum
        || fd_access(fd) != PLAMEN_BROKER_V2_FD_READ
        || (executable && (before.st_mode & 0111) == 0))
        return PLAMEN_BROKER_V2_FD_INVALID;
    size = (uint64_t)before.st_size;
    if (digest_init(&context) != 0) return PLAMEN_BROKER_V2_SYSTEM;
    for (offset = 0; offset < size; offset += (uint64_t)amount) {
        size_t wanted = size - offset > sizeof(buffer)
            ? sizeof(buffer) : (size_t)(size - offset);
        amount = pread(fd, buffer, wanted, (off_t)offset);
        if (amount <= 0
            || digest_update(&context, buffer, (size_t)amount) != 0)
            goto done;
    }
    if (pread(fd, buffer, 1U, (off_t)size) != 0
        || fstat(fd, &after) != 0 || !builder_same_stat(&before, &after))
        goto done;
    if (digest_final(&context, out) != 0) {
        status = PLAMEN_BROKER_V2_SYSTEM;
        goto done;
    }
    status = required_digest(out)
        ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_INVALID;
done:
    digest_destroy(&context);
    plamen_broker_v2_secure_zero(buffer, sizeof(buffer));
    if (status != 0) plamen_broker_v2_secure_zero(out, 32);
    return status;
}

static int
builder_profile_text(const uint8_t *slot, size_t slot_size, uint16_t size,
    char *out, size_t capacity, int component)
{
    size_t index;
    if (slot == NULL || out == NULL || size == 0 || size >= capacity
        || size > slot_size || !all_zero(slot + size, slot_size - size))
        return PLAMEN_BROKER_V2_INVALID;
    for (index = 0; index < size; ++index)
        if (slot[index] < 0x20 || slot[index] > 0x7e
            || slot[index] == '\\' || slot[index] == '\n'
            || slot[index] == '\r' || slot[index] == '\t'
            || (component && slot[index] == '/'))
            return PLAMEN_BROKER_V2_INVALID;
    memcpy(out, slot, size); out[size] = '\0';
    return PLAMEN_BROKER_V2_OK;
}

static int
builder_external_profile(int fd,
    struct plamen_broker_v2_external_authority_facts *facts)
{
    static const uint8_t magic[8] = {'P','L','M','B','P','F','2','\0'};
    uint8_t *bytes = NULL, trailer[32];
    uint8_t profile_sha256[32];
    size_t size = 0;
    char expected_release[257];
    struct stat info;
    int status = PLAMEN_BROKER_V2_INVALID;
    if (facts == NULL || fstat(fd, &info) != 0 || info.st_uid != geteuid()
        || (info.st_mode & 07777) != 0400)
        return PLAMEN_BROKER_V2_FD_INVALID;
    status = builder_read_regular(fd, PLAMEN_BROKER_V2_EXTERNAL_PROFILE_SIZE,
        &bytes, &size, profile_sha256);
    if (status != 0) goto done;
    status = PLAMEN_BROKER_V2_INVALID;
    if (size != PLAMEN_BROKER_V2_EXTERNAL_PROFILE_SIZE
        || memcmp(bytes, magic, sizeof(magic)) != 0
        || load_u16(bytes + 8) != 2U || load_u16(bytes + 10) != 256U
        || load_u32(bytes + 12) != PLAMEN_BROKER_V2_EXTERNAL_PROFILE_SIZE
        || load_u32(bytes + 16) != 1U || !all_zero(bytes + 20, 12)
        || !all_zero(bytes + 182, 74)
        || !all_zero(bytes + 1344,
            PLAMEN_BROKER_V2_EXTERNAL_PROFILE_HASHED_SIZE - 1344U)
        || plamen_broker_v2_sha256(bytes,
            PLAMEN_BROKER_V2_EXTERNAL_PROFILE_HASHED_SIZE, trailer) != 0
        || !constant_equal(trailer,
            bytes + PLAMEN_BROKER_V2_EXTERNAL_PROFILE_HASHED_SIZE, 32))
        goto done;
    memcpy(facts->provider_sha256, bytes + 32, 32);
    memcpy(facts->backend_sha256, bytes + 64, 32);
    memcpy(facts->provider_cdhash, bytes + 96, 32);
    memcpy(facts->backend_cdhash, bytes + 128, 32);
    facts->provider_cdhash_size = load_u16(bytes + 160);
    facts->backend_cdhash_size = load_u16(bytes + 162);
    if (!required_digest(facts->provider_sha256)
        || !required_digest(facts->backend_sha256)
        || (facts->provider_cdhash_size != 20U
            && facts->provider_cdhash_size != 32U)
        || (facts->backend_cdhash_size != 20U
            && facts->backend_cdhash_size != 32U)
        || all_zero(facts->provider_cdhash, facts->provider_cdhash_size)
        || all_zero(facts->backend_cdhash, facts->backend_cdhash_size)
        || !all_zero(facts->provider_cdhash + facts->provider_cdhash_size,
            32U - facts->provider_cdhash_size)
        || !all_zero(facts->backend_cdhash + facts->backend_cdhash_size,
            32U - facts->backend_cdhash_size)
        || builder_profile_text(bytes + 256, 128, load_u16(bytes + 164),
            facts->provider_identifier, sizeof(facts->provider_identifier), 0)
            != 0
        || builder_profile_text(bytes + 384, 128, load_u16(bytes + 166),
            facts->provider_team, sizeof(facts->provider_team), 0) != 0
        || builder_profile_text(bytes + 512, 128, load_u16(bytes + 168),
            facts->provider_version, sizeof(facts->provider_version), 0) != 0
        || builder_profile_text(bytes + 640, 128, load_u16(bytes + 170),
            facts->backend_identifier, sizeof(facts->backend_identifier), 0)
            != 0
        || builder_profile_text(bytes + 768, 128, load_u16(bytes + 172),
            facts->backend_team, sizeof(facts->backend_team), 0) != 0
        || builder_profile_text(bytes + 896, 128, load_u16(bytes + 174),
            facts->backend_version, sizeof(facts->backend_version), 0) != 0
        || builder_profile_text(bytes + 1024, 256, load_u16(bytes + 176),
            facts->backend_release, sizeof(facts->backend_release), 1) != 0
        || builder_profile_text(bytes + 1280, 32, load_u16(bytes + 178),
            facts->backend_selector, sizeof(facts->backend_selector), 1) != 0
        || builder_profile_text(bytes + 1312, 32, load_u16(bytes + 180),
            facts->provider_selector, sizeof(facts->provider_selector), 1) != 0
        || strcmp(facts->provider_identifier, "com.apple.container.cli") != 0
        || strcmp(facts->provider_team, "UPBK2H6LZM") != 0
        || strncmp(facts->provider_version, "container CLI version ", 22) != 0
        || strcmp(facts->backend_identifier, "codex") != 0
        || strcmp(facts->backend_team, "2DC432GLL2") != 0
        || strncmp(facts->backend_version, "codex-cli ", 10) != 0
        || strcmp(facts->backend_selector, "codex") != 0
        || strcmp(facts->provider_selector, "apple-container-v2") != 0
        || snprintf(expected_release, sizeof(expected_release),
            "%s-aarch64-apple-darwin", facts->backend_version + 10)
            >= (int)sizeof(expected_release)
        || strcmp(facts->backend_release, expected_release) != 0)
        goto done;
    memcpy(facts->profile_sha256, profile_sha256, 32);
    status = PLAMEN_BROKER_V2_OK;
done:
    if (bytes != NULL) {
        plamen_broker_v2_secure_zero(bytes, size); free(bytes);
    }
    plamen_broker_v2_secure_zero(trailer, sizeof(trailer));
    plamen_broker_v2_secure_zero(profile_sha256, sizeof(profile_sha256));
    plamen_broker_v2_secure_zero(expected_release, sizeof(expected_release));
    return status;
}

static int
builder_runtime_manifest(int fd, const uint8_t expected[32], int profile_fd,
    const uint8_t profile_sha256[32],
    char image_reference[512], uint8_t image_index[32],
    uint8_t image_manifest[32], uint8_t image_configuration[32],
    uint8_t image_closure[32], uint8_t seccomp[32])
{
    static const uint8_t header_magic[8] = {'P','L','M','R','P','M','2','\0'};
    static const uint8_t binding_magic[8] = {'P','L','M','R','P','B','2','\0'};
    static const uint8_t binding_kat[32] = {
        0xcb,0xec,0x56,0xec,0xf9,0x48,0x5c,0xc1,
        0xca,0x05,0xd2,0xfa,0xa0,0x9e,0xa6,0x15,
        0x75,0xe9,0xde,0xff,0xd7,0x36,0xfd,0x1a,
        0xd8,0xe4,0x11,0xa1,0x86,0x29,0xff,0xbe
    };
    static const char root[] = "lib/plamen/runtime";
    static const char init[] = "/usr/local/libexec/plamen-guest";
    uint8_t prefix[PLAMEN_BROKER_V2_RUNTIME_MANIFEST_HEADER_SIZE
        + PLAMEN_BROKER_V2_RUNTIME_BINDING_SIZE], trailer[32];
    uint8_t row[640];
    const uint8_t *binding;
    struct stat manifest_before, manifest_after, profile_info;
    uint64_t size = 0;
    uint32_t entries, index;
    uint16_t path_size;
    int profile_matches = 0;
    int status = builder_hash_regular(fd,
        PLAMEN_BROKER_V2_RUNTIME_MANIFEST_MAX_SIZE, expected,
        prefix, trailer, &size);
    if (status != 0 || profile_fd < 0 || !required_digest(profile_sha256)
        || fstat(fd, &manifest_before) != 0
        || fstat(profile_fd, &profile_info) != 0
        || !S_ISREG(profile_info.st_mode)
        || profile_info.st_size != PLAMEN_BROKER_V2_EXTERNAL_PROFILE_SIZE)
        goto done;
    binding = prefix + PLAMEN_BROKER_V2_RUNTIME_MANIFEST_HEADER_SIZE;
    entries = load_u32(prefix + 20);
    if (!constant_equal(prefix, header_magic, 8)
        || load_u16(prefix + 8) != 2U
        || load_u16(prefix + 10) != PLAMEN_BROKER_V2_RUNTIME_MANIFEST_HEADER_SIZE
        || load_u32(prefix + 12) != size || load_u32(prefix + 16) != 640U
        || entries == 0 || entries > 8192U
        || load_u32(prefix + 64) != PLAMEN_BROKER_V2_RUNTIME_BINDING_SIZE
        || load_u32(prefix + 68) != PLAMEN_BROKER_V2_RUNTIME_BINDING_DIGEST_COUNT
        || !all_zero(prefix + 72, 24)
        || memcmp(prefix + 160, root, sizeof(root) - 1U) != 0
        || !all_zero(prefix + 160 + sizeof(root) - 1U,
            64U - (sizeof(root) - 1U)) || !all_zero(prefix + 224, 32)
        || !constant_equal(binding, binding_magic, 8)
        || load_u16(binding + 8) != 2U
        || load_u16(binding + 10) != PLAMEN_BROKER_V2_RUNTIME_BINDING_SIZE
        || (load_u16(binding + 12) != 1U && load_u16(binding + 12) != 2U)
        || load_u16(binding + 14) != 2U
        || load_u16(binding + 20) != PLAMEN_BROKER_V2_RUNTIME_BINDING_DIGEST_COUNT
        || load_u16(binding + 22) != 1U || !all_zero(binding + 24, 8)
        || !constant_equal(binding + 32, binding_kat, 32)
        || load_u16(binding + 18) != sizeof(init) - 1U
        || memcmp(binding + 1024, init, sizeof(init) - 1U) != 0
        || !all_zero(binding + 1024 + sizeof(init) - 1U,
            512U - (sizeof(init) - 1U)) || !all_zero(binding + 1536, 512)
        || size != UINT64_C(256) + UINT64_C(2048)
            + UINT64_C(640) * entries + UINT64_C(32)) {
        status = PLAMEN_BROKER_V2_INVALID; goto done;
    }
    for (index = 0; index < entries; ++index) {
        static const char profile_path[] = "profiles/codex-v2.bin";
        off_t offset = (off_t)(PLAMEN_BROKER_V2_RUNTIME_MANIFEST_HEADER_SIZE
            + PLAMEN_BROKER_V2_RUNTIME_BINDING_SIZE + (uint64_t)index * 640U);
        if (pread(fd, row, sizeof(row), offset) != sizeof(row)) {
            status = PLAMEN_BROKER_V2_FD_INVALID; goto done;
        }
        path_size = load_u16(row + 2);
        if (path_size == sizeof(profile_path) - 1U
            && memcmp(row + 56, profile_path, sizeof(profile_path) - 1U) == 0) {
            if (profile_matches != 0 || load_u16(row) != 2U
                || load_u32(row + 4) != 0400U
                || load_u64(row + 8) != (uint64_t)profile_info.st_size
                || load_u32(row + 16) != 1U || load_u16(row + 20) != 2U
                || load_u16(row + 22) != 0U
                || !constant_equal(row + 24, profile_sha256, 32)
                || !all_zero(row + 56 + path_size, 512U - path_size)
                || !all_zero(row + 568, 72)) {
                status = PLAMEN_BROKER_V2_INVALID; goto done;
            }
            profile_matches = 1;
        }
    }
    if (profile_matches != 1 || fstat(fd, &manifest_after) != 0
        || !builder_same_stat(&manifest_before, &manifest_after)) {
        status = PLAMEN_BROKER_V2_AUTH_FAILED; goto done;
    }
    path_size = load_u16(binding + 16);
    if (path_size == 0 || path_size >= 512U
        || !all_zero(binding + 512U + path_size, 512U - path_size)) {
        status = PLAMEN_BROKER_V2_INVALID; goto done;
    }
    for (index = 0; index < path_size; ++index)
        if (binding[512U + index] < 0x21 || binding[512U + index] > 0x7e) {
            status = PLAMEN_BROKER_V2_INVALID; goto done;
        }
    memcpy(image_reference, binding + 512U, path_size);
    image_reference[path_size] = '\0';
    memcpy(image_index, binding + 64U
        + 32U * PLAMEN_BROKER_V2_RUNTIME_OCI_INDEX, 32);
    memcpy(image_manifest, binding + 64U
        + 32U * PLAMEN_BROKER_V2_RUNTIME_OCI_MANIFEST, 32);
    memcpy(image_configuration, binding + 64U
        + 32U * PLAMEN_BROKER_V2_RUNTIME_OCI_CONFIG, 32);
    memcpy(image_closure, binding + 64U
        + 32U * PLAMEN_BROKER_V2_RUNTIME_IMAGE_CLOSURE, 32);
    memcpy(seccomp, binding + 64U
        + 32U * PLAMEN_BROKER_V2_RUNTIME_SECCOMP, 32);
    if (all_zero(image_index, 32) || all_zero(image_manifest, 32)
        || all_zero(image_configuration, 32) || all_zero(image_closure, 32)
        || all_zero(seccomp, 32)) status = PLAMEN_BROKER_V2_INVALID;
done:
    plamen_broker_v2_secure_zero(prefix, sizeof(prefix));
    plamen_broker_v2_secure_zero(trailer, sizeof(trailer));
    plamen_broker_v2_secure_zero(row, sizeof(row));
    return status;
}

static const char *
builder_object_string(struct builder_json *object, const char *key)
{
    struct builder_json *value = builder_object_get(object, key);
    return value != NULL && value->kind == BUILDER_JSON_STRING
        ? value->value.text : NULL;
}

static int
builder_decode_lower_hex32(const char *value, uint8_t out[32])
{
    size_t index;
    if (value == NULL || strlen(value) != 64U || out == NULL)
        return PLAMEN_BROKER_V2_INVALID;
    for (index = 0; index < 32U; ++index) {
        unsigned high, low;
        char first = value[index * 2U], second = value[index * 2U + 1U];
        if (first >= '0' && first <= '9') high = (unsigned)(first - '0');
        else if (first >= 'a' && first <= 'f') high = (unsigned)(first - 'a' + 10);
        else return PLAMEN_BROKER_V2_INVALID;
        if (second >= '0' && second <= '9') low = (unsigned)(second - '0');
        else if (second >= 'a' && second <= 'f') low = (unsigned)(second - 'a' + 10);
        else return PLAMEN_BROKER_V2_INVALID;
        out[index] = (uint8_t)((high << 4) | low);
    }
    return required_digest(out)
        ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_INVALID;
}

static int
builder_exact_json_lf(const uint8_t *bytes, size_t size,
    struct builder_json **object)
{
    struct builder_json *parsed = NULL;
    struct builder_buffer rendered;
    int status = PLAMEN_BROKER_V2_INVALID;
    memset(&rendered, 0, sizeof(rendered)); rendered.maximum = 4096U;
    if (object == NULL || bytes == NULL || size < 3U || size > 4096U
        || bytes[size - 1U] != '\n')
        return PLAMEN_BROKER_V2_INVALID;
    parsed = builder_json_parse(bytes, size - 1U);
    if (parsed == NULL || parsed->kind != BUILDER_JSON_OBJECT
        || builder_json_render(&rendered, parsed) != 0
        || builder_buffer_byte(&rendered, '\n') != 0
        || rendered.size != size || memcmp(rendered.data, bytes, size) != 0)
        goto done;
    *object = parsed; parsed = NULL; status = PLAMEN_BROKER_V2_OK;
done:
    builder_json_destroy(parsed);
    if (rendered.data != NULL) {
        plamen_broker_v2_secure_zero(rendered.data, rendered.capacity);
        free(rendered.data);
    }
    return status;
}

static int
builder_generated_read(int fd, uint8_t **bytes, size_t *size,
    uint8_t sha256[32])
{
    struct stat info;
    if (fd < 0 || fstat(fd, &info) != 0 || info.st_uid != geteuid()
        || (info.st_mode & 07777) != 0400)
        return PLAMEN_BROKER_V2_FD_INVALID;
    return builder_read_regular(fd, 4096U, bytes, size, sha256);
}

static int
builder_egress_policy(int fd, const uint8_t config_sha256[32],
    const uint8_t profile_sha256[32], uint8_t policy_sha256[32],
    uint8_t nonce[32])
{
    struct builder_json *root = NULL;
    uint8_t *bytes = NULL, observed[32], expected[32];
    size_t size = 0;
    const char *backend, *config, *mode, *nonce_text, *profile, *schema;
    int status = builder_generated_read(fd, &bytes, &size, observed);
    if (status != 0) goto done;
    status = builder_exact_json_lf(bytes, size, &root);
    if (status != 0 || root->value.object.count != 6U) goto invalid;
    backend = builder_object_string(root, "backend");
    config = builder_object_string(root, "config_sha256");
    mode = builder_object_string(root, "network_mode");
    nonce_text = builder_object_string(root, "nonce");
    profile = builder_object_string(root, "profile_sha256");
    schema = builder_object_string(root, "schema");
    if (backend == NULL || strcmp(backend, "codex") != 0 || config == NULL
        || mode == NULL || strcmp(mode, "NARROW_TRUSTED_PROXY_ONLY") != 0
        || nonce_text == NULL || profile == NULL || schema == NULL
        || strcmp(schema, "plamen.egress-policy.v2") != 0
        || builder_decode_lower_hex32(config, expected) != 0
        || !constant_equal(expected, config_sha256, 32)
        || builder_decode_lower_hex32(profile, expected) != 0
        || !constant_equal(expected, profile_sha256, 32)
        || builder_decode_lower_hex32(nonce_text, nonce) != 0)
        goto invalid;
    memcpy(policy_sha256, observed, 32);
    status = PLAMEN_BROKER_V2_OK;
    goto done;
invalid:
    status = PLAMEN_BROKER_V2_INVALID;
done:
    builder_json_destroy(root);
    if (bytes != NULL) {
        plamen_broker_v2_secure_zero(bytes, size); free(bytes);
    }
    plamen_broker_v2_secure_zero(observed, sizeof(observed));
    plamen_broker_v2_secure_zero(expected, sizeof(expected));
    if (status != 0) {
        plamen_broker_v2_secure_zero(policy_sha256, 32);
        plamen_broker_v2_secure_zero(nonce, 32);
    }
    return status;
}

static int
builder_egress_admission(int fd, const uint8_t provider_sha256[32],
    const uint8_t backend_sha256[32], const uint8_t policy_sha256[32],
    uint8_t admission_sha256[32])
{
    struct builder_json *root = NULL;
    uint8_t *bytes = NULL, observed[32], expected[32];
    size_t size = 0;
    const char *backend, *policy, *provider, *schema;
    int status = builder_generated_read(fd, &bytes, &size, observed);
    if (status != 0) goto done;
    status = builder_exact_json_lf(bytes, size, &root);
    if (status != 0 || root->value.object.count != 4U) goto invalid;
    backend = builder_object_string(root, "backend_sha256");
    policy = builder_object_string(root, "policy_sha256");
    provider = builder_object_string(root, "provider_sha256");
    schema = builder_object_string(root, "schema");
    if (backend == NULL || policy == NULL || provider == NULL || schema == NULL
        || strcmp(schema, "plamen.egress-admission.v2") != 0
        || builder_decode_lower_hex32(backend, expected) != 0
        || !constant_equal(expected, backend_sha256, 32)
        || builder_decode_lower_hex32(policy, expected) != 0
        || !constant_equal(expected, policy_sha256, 32)
        || builder_decode_lower_hex32(provider, expected) != 0
        || !constant_equal(expected, provider_sha256, 32))
        goto invalid;
    memcpy(admission_sha256, observed, 32);
    status = PLAMEN_BROKER_V2_OK;
    goto done;
invalid:
    status = PLAMEN_BROKER_V2_INVALID;
done:
    builder_json_destroy(root);
    if (bytes != NULL) {
        plamen_broker_v2_secure_zero(bytes, size); free(bytes);
    }
    plamen_broker_v2_secure_zero(observed, sizeof(observed));
    plamen_broker_v2_secure_zero(expected, sizeof(expected));
    if (status != 0) plamen_broker_v2_secure_zero(admission_sha256, 32);
    return status;
}

int
plamen_broker_v2_external_authority_validate(int runtime_manifest_fd,
    const uint8_t expected_runtime_manifest_sha256[32],
    int provider_executable_fd, int backend_executable_fd,
    int backend_profile_fd, int egress_policy_fd, int egress_admission_fd,
    const uint8_t config_content_sha256[32],
    struct plamen_broker_v2_external_authority_facts *facts)
{
    struct plamen_broker_v2_external_authority_facts result;
    uint8_t observed[32], image_index[32], image_manifest[32];
    uint8_t image_configuration[32], image_closure[32], seccomp[32];
    char image_reference[512];
    int status = PLAMEN_BROKER_V2_INVALID;
    if (facts == NULL) return PLAMEN_BROKER_V2_INVALID;
    memset(facts, 0, sizeof(*facts)); memset(&result, 0, sizeof(result));
    memset(image_reference, 0, sizeof(image_reference));
    if (!required_digest(expected_runtime_manifest_sha256)
        || !required_digest(config_content_sha256)
        || builder_external_profile(backend_profile_fd, &result) != 0
        || builder_content_sha_regular(provider_executable_fd,
            UINT64_C(512) * 1024 * 1024, 1, observed) != 0
        || !constant_equal(observed, result.provider_sha256, 32)
        || builder_content_sha_regular(backend_executable_fd,
            UINT64_C(512) * 1024 * 1024, 1, observed) != 0
        || !constant_equal(observed, result.backend_sha256, 32)
        || builder_runtime_manifest(runtime_manifest_fd,
            expected_runtime_manifest_sha256, backend_profile_fd,
            result.profile_sha256, image_reference, image_index,
            image_manifest, image_configuration, image_closure, seccomp) != 0
        || builder_egress_policy(egress_policy_fd, config_content_sha256,
            result.profile_sha256, result.policy_sha256,
            result.policy_nonce) != 0
        || builder_egress_admission(egress_admission_fd,
            result.provider_sha256, result.backend_sha256,
            result.policy_sha256, result.admission_sha256) != 0)
        goto done;
    memcpy(result.runtime_manifest_sha256,
        expected_runtime_manifest_sha256, 32);
    memcpy(result.image_index_sha256, image_index, 32);
    memcpy(result.image_manifest_sha256, image_manifest, 32);
    memcpy(result.image_configuration_sha256, image_configuration, 32);
    memcpy(result.image_closure_sha256, image_closure, 32);
    memcpy(result.seccomp_profile_sha256, seccomp, 32);
    memcpy(result.image_reference, image_reference,
        strlen(image_reference) + 1U);
    *facts = result; status = PLAMEN_BROKER_V2_OK;
done:
    plamen_broker_v2_secure_zero(&result, sizeof(result));
    plamen_broker_v2_secure_zero(observed, sizeof(observed));
    plamen_broker_v2_secure_zero(image_index, sizeof(image_index));
    plamen_broker_v2_secure_zero(image_manifest, sizeof(image_manifest));
    plamen_broker_v2_secure_zero(image_configuration,
        sizeof(image_configuration));
    plamen_broker_v2_secure_zero(image_closure, sizeof(image_closure));
    plamen_broker_v2_secure_zero(seccomp, sizeof(seccomp));
    plamen_broker_v2_secure_zero(image_reference, sizeof(image_reference));
    if (status != 0) plamen_broker_v2_secure_zero(facts, sizeof(*facts));
    return status;
}

static int
builder_digest_join(const char *domain, const uint8_t *const *parts,
    const size_t *sizes, size_t count, uint8_t out[32])
{
    struct digest_context context;
    size_t index;
    int status = PLAMEN_BROKER_V2_SYSTEM;
    memset(&context, 0, sizeof(context));
    if (domain == NULL || parts == NULL || sizes == NULL || out == NULL
        || digest_init(&context) != 0) return PLAMEN_BROKER_V2_INVALID;
    if (digest_update(&context, domain, strlen(domain) + 1U) != 0) goto done;
    for (index = 0; index < count; ++index)
        if ((sizes[index] != 0 && parts[index] == NULL)
            || digest_update(&context, parts[index], sizes[index]) != 0)
            goto done;
    if (digest_final(&context, out) != 0) goto done;
    status = PLAMEN_BROKER_V2_OK;
done:
    if (status != 0) digest_destroy(&context);
    return status;
}

static void
builder_hex(const uint8_t value[32], char out[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32; ++index) {
        out[index * 2U] = digits[value[index] >> 4];
        out[index * 2U + 1U] = digits[value[index] & 15U];
    }
    out[64] = '\0';
}

static int
builder_random_uuid(char out[37])
{
    static const char digits[] = "0123456789abcdef";
    uint8_t raw[16];
    size_t source = 0, target = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t amount;
    if (fd < 0) return PLAMEN_BROKER_V2_SYSTEM;
    while (source < sizeof(raw)) {
        amount = read(fd, raw + source, sizeof(raw) - source);
        if (amount <= 0) {
            close(fd);
            plamen_broker_v2_secure_zero(raw, sizeof(raw));
            return PLAMEN_BROKER_V2_SYSTEM;
        }
        source += (size_t)amount;
    }
    close(fd);
    raw[6] = (uint8_t)((raw[6] & 0x0fU) | 0x40U);
    raw[8] = (uint8_t)((raw[8] & 0x3fU) | 0x80U);
    for (source = 0; source < sizeof(raw); ++source) {
        if (target == 8U || target == 13U || target == 18U || target == 23U)
            out[target++] = '-';
        out[target++] = digits[raw[source] >> 4];
        out[target++] = digits[raw[source] & 15U];
    }
    out[target] = '\0';
    plamen_broker_v2_secure_zero(raw, sizeof(raw));
    return target == 36U ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_SYSTEM;
}

static char *
builder_base64(const uint8_t *bytes, size_t size)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_size = ((size + 2U) / 3U) * 4U, source = 0, target = 0;
    char *out = malloc(output_size + 1U);
    if (out == NULL) return NULL;
    while (source < size) {
        uint32_t value = (uint32_t)bytes[source++] << 16;
        int second = source < size, third;
        if (second) value |= (uint32_t)bytes[source++] << 8;
        third = source < size;
        if (third) value |= bytes[source++];
        out[target++] = table[(value >> 18) & 63U];
        out[target++] = table[(value >> 12) & 63U];
        out[target++] = second ? table[(value >> 6) & 63U] : '=';
        out[target++] = third ? table[value & 63U] : '=';
    }
    out[target] = '\0';
    return out;
}

struct builder_projection_values {
    const struct plamen_broker_v2_projection_discovery *discovery;
    const char *request_id;
    const char *attempt_id;
    const char *run_id;
    const char *request_type;
    const char *config_base64;
    uint8_t source_handle[32];
    uint8_t source_config[32];
    uint8_t startup_receipt[32];
    uint8_t target[32];
    uint8_t runtime[32];
    uint8_t image_manifest[32];
    uint8_t image_closure[32];
    uint8_t docs[32];
    uint8_t scope[32];
    uint8_t seccomp[32];
    uint8_t credential_bundle[32];
    uint8_t credential_isolation[32];
    uint8_t backend_context[32];
    uint8_t backend_admission[32];
    uint8_t egress_policy[32];
    uint8_t egress_admission[32];
    uint8_t provider[32];
    uint8_t export_destination[32];
};

static int
builder_projection_key(struct builder_buffer *out, const char *key, int first)
{
    return (!first && builder_buffer_byte(out, ',') != 0)
        || builder_render_string(out, key) != 0
        || builder_buffer_byte(out, ':') != 0 ? -1 : 0;
}

static int
builder_projection_string_field(struct builder_buffer *out, const char *key,
    const char *value, int first)
{
    return builder_projection_key(out, key, first) != 0
        || builder_render_string(out, value) != 0 ? -1 : 0;
}

static int
builder_projection_digest_field(struct builder_buffer *out, const char *key,
    const uint8_t digest[32], int first, int oci)
{
    char hex[72];
    if (oci) memcpy(hex, "sha256:", 7U);
    builder_hex(digest, hex + (oci ? 7U : 0U));
    return builder_projection_string_field(out, key, hex, first);
}

static int
builder_projection_render(const struct builder_projection_values *value,
    uint8_t **projection, size_t *projection_size)
{
    static const char export_roster[] =
        "[\"project/AUDIT_REPORT.md\",\"scratch/_plamen.log\","
        "\"scratch/_v2_checkpoint.json\"]";
    static const char required_roster[] =
        "[\"project/AUDIT_REPORT.md\",\"scratch/_v2_checkpoint.json\"]";
    static const char failure_roster[] = "[\"scratch/_plamen.log\"]";
    struct builder_buffer out;
    char source_handle[72], source_sha[65];
    int status = PLAMEN_BROKER_V2_NOMEM;
    memset(&out, 0, sizeof(out));
    out.maximum = PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX;
    memcpy(source_handle, "opaque:", 7U);
    builder_hex(value->source_handle, source_handle + 7U);
    builder_hex(value->source_config, source_sha);
    if (builder_buffer_write(&out, "{\"audit_request\":{", 18U) != 0
        || builder_projection_string_field(&out, "attempt_id",
            value->attempt_id, 1) != 0
        || builder_projection_string_field(&out, "backend",
            value->discovery->backend, 0) != 0
        || builder_projection_digest_field(&out, "backend_admission_sha256",
            value->backend_admission, 0, 0) != 0
        || builder_projection_digest_field(&out, "backend_context_sha256",
            value->backend_context, 0, 0) != 0
        || builder_projection_digest_field(&out, "credential_bundle_sha256",
            value->credential_bundle, 0, 0) != 0
        || builder_projection_digest_field(&out, "credential_isolation_sha256",
            value->credential_isolation, 0, 0) != 0
        || builder_projection_digest_field(&out, "docs_sha256", value->docs,
            0, 0) != 0
        || builder_projection_digest_field(&out, "egress_admission_sha256",
            value->egress_admission, 0, 0) != 0
        || builder_projection_digest_field(&out, "egress_policy_sha256",
            value->egress_policy, 0, 0) != 0
        || builder_projection_key(&out, "export_allowlist", 0) != 0
        || builder_buffer_write(&out, export_roster,
            sizeof(export_roster) - 1U) != 0
        || builder_projection_digest_field(&out,
            "export_destination_identity_sha256", value->export_destination,
            0, 0) != 0
        || builder_projection_key(&out, "export_max_total_bytes", 0) != 0
        || builder_buffer_write(&out, "2147483648", 10U) != 0
        || builder_projection_key(&out, "failure_required_artifacts", 0) != 0
        || builder_buffer_write(&out, failure_roster,
            sizeof(failure_roster) - 1U) != 0
        || builder_projection_digest_field(&out, "image_closure_sha256",
            value->image_closure, 0, 0) != 0
        || builder_projection_digest_field(&out, "image_manifest_digest",
            value->image_manifest, 0, 1) != 0
        || builder_projection_string_field(&out, "language",
            value->discovery->language, 0) != 0
        || builder_projection_string_field(&out, "mode",
            value->discovery->mode, 0) != 0
        || builder_projection_string_field(&out, "pipeline",
            value->discovery->pipeline, 0) != 0
        || builder_projection_digest_field(&out, "provider_provenance_sha256",
            value->provider, 0, 0) != 0
        || builder_projection_string_field(&out, "request_id",
            value->request_id, 0) != 0
        || builder_projection_string_field(&out, "request_type",
            value->request_type, 0) != 0
        || builder_projection_key(&out, "required_artifacts", 0) != 0
        || builder_buffer_write(&out, required_roster,
            sizeof(required_roster) - 1U) != 0
        || builder_projection_string_field(&out, "run_id", value->run_id,
            0) != 0
        || builder_projection_digest_field(&out, "runtime_layout_sha256",
            value->runtime, 0, 0) != 0
        || builder_projection_string_field(&out, "schema",
            PLAMEN_BROKER_V2_AUDIT_REQUEST_SCHEMA, 0) != 0
        || builder_projection_digest_field(&out, "scope_sha256", value->scope,
            0, 0) != 0
        || builder_projection_digest_field(&out, "seccomp_profile_sha256",
            value->seccomp, 0, 0) != 0
        || builder_projection_key(&out, "source_config", 0) != 0
        || builder_buffer_write(&out,
            "{\"authenticated\":true,\"canonical_utf8_b64\":",
            sizeof("{\"authenticated\":true,\"canonical_utf8_b64\":") - 1U) != 0
        || builder_render_string(&out, value->config_base64) != 0
        || builder_buffer_write(&out, ",\"retained_source_handle\":",
            sizeof(",\"retained_source_handle\":") - 1U) != 0
        || builder_render_string(&out, source_handle) != 0
        || builder_buffer_write(&out, ",\"sha256\":",
            sizeof(",\"sha256\":") - 1U) != 0
        || builder_render_string(&out, source_sha) != 0
        || builder_buffer_byte(&out, '}') != 0
        || builder_projection_digest_field(&out, "source_config_sha256",
            value->source_config, 0, 0) != 0
        || builder_projection_digest_field(&out,
            "startup_decision_receipt_sha256", value->startup_receipt,
            0, 0) != 0
        || builder_projection_digest_field(&out, "target_identity_sha256",
            value->target, 0, 0) != 0
        || builder_buffer_write(&out, "},\"projection_schema\":",
            sizeof("},\"projection_schema\":") - 1U) != 0
        || builder_render_string(&out,
            PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA) != 0
        || builder_buffer_byte(&out, '}') != 0) {
        goto done;
    }
    *projection = out.data; *projection_size = out.size;
    out.data = NULL; out.size = 0;
    status = PLAMEN_BROKER_V2_OK;
done:
    if (out.data != NULL) {
        plamen_broker_v2_secure_zero(out.data, out.capacity); free(out.data);
    }
    plamen_broker_v2_secure_zero(source_handle, sizeof(source_handle));
    plamen_broker_v2_secure_zero(source_sha, sizeof(source_sha));
    return status;
}

static int
builder_fd_shape(int fd, size_t slot)
{
    struct stat info;
    int directory = slot == PLAMEN_BROKER_V2_RETAINED_TARGET
        || slot == PLAMEN_BROKER_V2_RETAINED_EXPORT;
    int executable = slot == PLAMEN_BROKER_V2_RETAINED_PROVIDER
        || slot == PLAMEN_BROKER_V2_RETAINED_BACKEND;
    if (fd < 0 || fstat(fd, &info) != 0
        || fd_access(fd) != PLAMEN_BROKER_V2_FD_READ
        || (fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0)
        return 0;
    if (directory) return S_ISDIR(info.st_mode);
    if (slot == PLAMEN_BROKER_V2_RETAINED_CREDENTIAL)
        return S_ISREG(info.st_mode) && info.st_nlink == 0;
    if (slot == PLAMEN_BROKER_V2_RETAINED_DOCS)
        return S_ISDIR(info.st_mode)
            || (S_ISREG(info.st_mode) && info.st_nlink == 1);
    return S_ISREG(info.st_mode) && info.st_nlink == 1
        && (!executable || (info.st_mode & 0111) != 0);
}

static int
builder_discovery_equal(
    const struct plamen_broker_v2_projection_discovery *left,
    const struct plamen_broker_v2_projection_discovery *right)
{
    return left != NULL && right != NULL
        && left->ownership_magic == BUILDER_DISCOVERY_MAGIC
        && right->ownership_magic == BUILDER_DISCOVERY_MAGIC
        && memcmp(left, right, sizeof(*left)) == 0;
}

void
plamen_broker_v2_projection_builder_result_destroy(
    struct plamen_broker_v2_projection_builder_result *value)
{
    size_t index;
    if (value == NULL || value->ownership_magic != BUILDER_RESULT_MAGIC) return;
    if (value->guest_config != NULL) {
        plamen_broker_v2_secure_zero(value->guest_config,
            value->guest_config_size);
        free(value->guest_config);
    }
    if (value->request_projection != NULL) {
        plamen_broker_v2_secure_zero(value->request_projection,
            value->request_projection_size);
        free(value->request_projection);
    }
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
            ++index)
        if (value->retained_fds[index] >= 0) close(value->retained_fds[index]);
    plamen_broker_v2_secure_zero(value, sizeof(*value));
}

int
plamen_broker_v2_projection_builder_revalidate(
    const struct plamen_broker_v2_projection_builder_result *value)
{
    struct plamen_broker_v2_commitment commitment;
    uint8_t config_sha[32], projection_sha[32], commitment_sha[32];
    uint8_t encoded[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE], identity[32];
    size_t encoded_size = 0, index;
    int status = PLAMEN_BROKER_V2_INVALID;
    memset(&commitment, 0, sizeof(commitment)); memset(encoded, 0, sizeof(encoded));
    if (value == NULL || value->ownership_magic != BUILDER_RESULT_MAGIC
        || value->guest_config == NULL || value->guest_config_size == 0
        || value->request_projection == NULL || value->request_projection_size == 0
        || value->commitment_size == 0
        || value->commitment_size > sizeof(value->commitment))
        goto done;
    if (plamen_broker_v2_sha256(value->guest_config, value->guest_config_size,
            config_sha) != 0
        || !constant_equal(config_sha, value->guest_config_sha256, 32)
        || plamen_broker_v2_request_projection_derive_exact(
            value->request_projection, value->request_projection_size,
            &commitment, encoded, sizeof(encoded), &encoded_size,
            projection_sha, commitment_sha) != 0
        || !constant_equal(projection_sha, value->request_projection_sha256, 32)
        || !constant_equal(commitment_sha, value->commitment_sha256, 32)
        || encoded_size != value->commitment_size
        || !constant_equal(encoded, value->commitment, encoded_size))
        goto done;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
            ++index) {
        int present = (value->retained_presence_mask
            & (uint16_t)(UINT16_C(1) << index)) != 0;
        if (!present) {
            if (value->retained_fds[index] != -1
                || !all_zero(value->retained_identities[index], 32)) goto done;
        } else if (!builder_fd_shape(value->retained_fds[index], index)
            || plamen_broker_v2_fd_identity(value->retained_fds[index], identity) != 0
            || !constant_equal(identity, value->retained_identities[index], 32)) {
            goto done;
        }
    }
    status = PLAMEN_BROKER_V2_OK;
done:
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    plamen_broker_v2_secure_zero(encoded, sizeof(encoded));
    plamen_broker_v2_secure_zero(config_sha, sizeof(config_sha));
    plamen_broker_v2_secure_zero(projection_sha, sizeof(projection_sha));
    plamen_broker_v2_secure_zero(commitment_sha, sizeof(commitment_sha));
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    return status;
}

int
plamen_broker_v2_projection_registration_roster(
    const struct plamen_broker_v2_projection_builder_result *value,
    struct plamen_broker_v2_service_registration *registration)
{
    size_t index;
    int resume;
    if (value == NULL || registration == NULL
        || plamen_broker_v2_projection_builder_revalidate(value) != 0)
        return PLAMEN_BROKER_V2_INVALID;
    resume = value->startup_intent == PLAMEN_BROKER_V2_STARTUP_RESUME_EXISTING;
    if ((!resume && value->startup_intent
                != PLAMEN_BROKER_V2_STARTUP_START_NEW_RUN)
        || resume != !all_zero(registration->prior_audit_checkpoint_sha256, 32))
        return PLAMEN_BROKER_V2_INVALID;
    registration->authority_presence_mask = value->retained_presence_mask;
    memset(registration->authority_descriptors, 0,
        sizeof(registration->authority_descriptors));
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
            ++index) {
        if ((value->retained_presence_mask
                & (uint16_t)(UINT16_C(1) << index)) == 0) continue;
        registration->authority_descriptors[index].purpose =
            (uint16_t)(PLAMEN_BROKER_V2_FD_AUTHORITY_CONFIG + index);
        registration->authority_descriptors[index].target =
            (uint16_t)(index + 1U);
        registration->authority_descriptors[index].access_mode =
            PLAMEN_BROKER_V2_FD_READ;
        memcpy(registration->authority_descriptors[index].identity,
            value->retained_identities[index], 32);
    }
    return plamen_broker_v2_service_registration_descriptors_valid(registration)
        ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_projection_build_from_retained(
    const struct plamen_broker_v2_projection_builder_inputs *input,
    struct plamen_broker_v2_projection_builder_result *out)
{
    struct plamen_broker_v2_projection_builder_result result;
    struct plamen_broker_v2_projection_discovery observed;
    struct builder_projection_values value;
    struct plamen_broker_v2_external_authority_facts external;
    struct builder_json *config = NULL;
    struct builder_buffer guest;
    uint8_t *raw = NULL, *role5 = NULL;
    size_t raw_size = 0, role5_size = 0, index;
    uint8_t role5_sha[32], runtime_image[32], runtime_closure[32], seccomp[32];
    uint8_t startup_intent_be[2];
    char *config_base64 = NULL;
    int source_fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    int status = PLAMEN_BROKER_V2_INVALID;
    const uint8_t *parts[8]; size_t sizes[8];
    memset(&result, 0, sizeof(result)); memset(&observed, 0, sizeof(observed));
    memset(&value, 0, sizeof(value)); memset(&external, 0, sizeof(external));
    memset(&guest, 0, sizeof(guest));
    memset(source_fds, -1, sizeof(source_fds));
    if (out == NULL) return PLAMEN_BROKER_V2_INVALID;
    memset(out, 0, sizeof(*out));
    result.ownership_magic = BUILDER_RESULT_MAGIC;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++index)
        result.retained_fds[index] = -1;
    if (input == NULL || input->discovery == NULL
        || input->startup_intent != input->discovery->startup_intent
        || input->config_path == NULL
        || strcmp(input->config_path, input->discovery->config_path) != 0
        || all_zero(input->expected_role5_schema_sha256, 32)
        || all_zero(input->expected_runtime_manifest_sha256, 32))
        goto done;
    status = plamen_broker_v2_projection_discover_config(input->startup_intent,
        input->config_path, input->config_fd, &observed);
    if (status != 0 || !builder_discovery_equal(input->discovery, &observed)) {
        if (status == 0) status = PLAMEN_BROKER_V2_AUTH_FAILED;
        goto done;
    }
    if (input->startup_intent == PLAMEN_BROKER_V2_STARTUP_RESUME_EXISTING) {
        /* Native service-journal checkpoint decoder is required before resume. */
        status = PLAMEN_BROKER_V2_UNSUPPORTED; goto done;
    }
    source_fds[0] = input->config_fd;
    source_fds[1] = input->target_root_fd;
    source_fds[2] = input->docs_root_fd;
    source_fds[3] = input->scope_fd;
    source_fds[4] = input->export_root_fd;
    source_fds[5] = input->role5_schema_fd;
    source_fds[6] = input->runtime_manifest_fd;
    source_fds[7] = input->provider_executable_fd;
    source_fds[8] = input->backend_executable_fd;
    source_fds[9] = input->backend_profile_fd;
    source_fds[10] = input->credential_source_fd;
    source_fds[11] = input->egress_policy_fd;
    source_fds[12] = input->egress_admission_fd;
    source_fds[13] = input->resume_checkpoint_fd;
    if ((observed.has_docs != (source_fds[2] >= 0))
        || (observed.has_scope != (source_fds[3] >= 0))
        || source_fds[13] >= 0) {
        status = PLAMEN_BROKER_V2_INVALID; goto done;
    }
    for (index = 0; index < 13U; ++index) {
        if ((index == 2U || index == 3U) && source_fds[index] < 0) continue;
        if (!builder_fd_shape(source_fds[index], index)) {
            status = PLAMEN_BROKER_V2_FD_INVALID; goto done;
        }
        result.retained_presence_mask |= (uint16_t)(UINT16_C(1) << index);
        if (plamen_broker_v2_fd_identity(source_fds[index],
                result.retained_identities[index]) != 0) {
            status = PLAMEN_BROKER_V2_FD_INVALID; goto done;
        }
    }
    if (!constant_equal(result.retained_identities[0], observed.config_identity, 32)) {
        status = PLAMEN_BROKER_V2_AUTH_FAILED; goto done;
    }
    status = builder_read_regular(input->config_fd, PROJECTION_CONFIG_MAX_SIZE,
        &raw, &raw_size, value.source_config);
    if (status != 0 || !constant_equal(value.source_config,
            observed.config_content_sha256, 32)) goto done;
    status = builder_read_regular(input->role5_schema_fd,
        PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX, &role5, &role5_size, role5_sha);
    if (status != 0 || !constant_equal(role5_sha,
            input->expected_role5_schema_sha256, 32)) {
        if (status == 0) status = PLAMEN_BROKER_V2_AUTH_FAILED;
        goto done;
    }
    status = plamen_broker_v2_external_authority_validate(
        input->runtime_manifest_fd, input->expected_runtime_manifest_sha256,
        input->provider_executable_fd, input->backend_executable_fd,
        input->backend_profile_fd, input->egress_policy_fd,
        input->egress_admission_fd, observed.config_content_sha256, &external);
    if (status != 0) goto done;
    memcpy(runtime_image, external.image_manifest_sha256, 32);
    memcpy(runtime_closure, external.image_closure_sha256, 32);
    memcpy(seccomp, external.seccomp_profile_sha256, 32);
    config = builder_json_parse(raw, raw_size);
    if (config == NULL || config->kind != BUILDER_JSON_OBJECT
        || builder_random_uuid(result.request_id) != 0
        || builder_random_uuid(result.attempt_id) != 0
        || builder_random_uuid(result.run_id) != 0
        || builder_object_set(config, "_run_id", BUILDER_JSON_STRING,
            result.run_id) != 0
        || builder_object_set(config, "project_root", BUILDER_JSON_STRING,
            "/workspace/project") != 0
        || builder_object_set(config, "scratchpad", BUILDER_JSON_STRING,
            "/workspace/scratch") != 0
        || builder_object_set(config, "docs_path",
            observed.has_docs ? BUILDER_JSON_STRING : BUILDER_JSON_NULL,
            observed.has_docs ? "/workspace/docs" : NULL) != 0
        || builder_object_set(config, "scope_file",
            observed.has_scope ? BUILDER_JSON_STRING : BUILDER_JSON_NULL,
            observed.has_scope ? "/workspace/scope" : NULL) != 0) {
        status = PLAMEN_BROKER_V2_INVALID; goto done;
    }
    guest.maximum = PROJECTION_CONFIG_MAX_SIZE;
    if (builder_json_render(&guest, config) != 0
        || builder_buffer_byte(&guest, '\n') != 0) {
        status = PLAMEN_BROKER_V2_NOMEM; goto done;
    }
    result.guest_config = guest.data; result.guest_config_size = guest.size;
    guest.data = NULL; guest.size = guest.capacity = 0;
    if (plamen_broker_v2_sha256(result.guest_config, result.guest_config_size,
            result.guest_config_sha256) != 0) {
        status = PLAMEN_BROKER_V2_SYSTEM; goto done;
    }
    config_base64 = builder_base64(result.guest_config, result.guest_config_size);
    if (config_base64 == NULL) { status = PLAMEN_BROKER_V2_NOMEM; goto done; }
    value.discovery = &observed; value.request_id = result.request_id;
    value.attempt_id = result.attempt_id; value.run_id = result.run_id;
    value.request_type = "START_CONFIG"; value.config_base64 = config_base64;
    memcpy(value.source_handle, result.retained_identities[0], 32);
    memcpy(value.source_config, result.guest_config_sha256, 32);
    memcpy(value.target, result.retained_identities[1], 32);
    memcpy(value.runtime, input->expected_runtime_manifest_sha256, 32);
    memcpy(value.image_manifest, runtime_image, 32);
    memcpy(value.image_closure, runtime_closure, 32);
    memcpy(value.seccomp, seccomp, 32);
    memcpy(value.credential_bundle, result.retained_identities[10], 32);
    memcpy(value.egress_policy, result.retained_identities[11], 32);
    memcpy(value.egress_admission, result.retained_identities[12], 32);
    memcpy(value.provider, result.retained_identities[7], 32);
    memcpy(value.export_destination, result.retained_identities[4], 32);
    if (observed.has_docs) memcpy(value.docs, result.retained_identities[2], 32);
    else {
        parts[0] = (const uint8_t *)"ABSENT"; sizes[0] = 6U;
        if (builder_digest_join("PLAMEN-BROKER-V2-DOCS", parts, sizes, 1,
                value.docs) != 0) goto system;
    }
    if (observed.has_scope) memcpy(value.scope, result.retained_identities[3], 32);
    else {
        parts[0] = (const uint8_t *)"ABSENT"; sizes[0] = 6U;
        if (builder_digest_join("PLAMEN-BROKER-V2-SCOPE", parts, sizes, 1,
                value.scope) != 0) goto system;
    }
    parts[0] = result.retained_identities[8]; sizes[0] = 32;
    parts[1] = result.retained_identities[9]; sizes[1] = 32;
    if (builder_digest_join("PLAMEN-BROKER-V2-BACKEND-CONTEXT", parts, sizes, 2,
            value.backend_context) != 0) goto system;
    parts[0] = value.backend_context; sizes[0] = 32;
    parts[1] = value.runtime; sizes[1] = 32;
    parts[2] = role5_sha; sizes[2] = 32;
    if (builder_digest_join("PLAMEN-BROKER-V2-BACKEND-ADMISSION", parts, sizes, 3,
            value.backend_admission) != 0) goto system;
    parts[0] = value.credential_bundle; sizes[0] = 32;
    parts[1] = value.backend_admission; sizes[1] = 32;
    if (builder_digest_join("PLAMEN-BROKER-V2-CREDENTIAL-ISOLATION", parts,
            sizes, 2, value.credential_isolation) != 0) goto system;
    store_u16(startup_intent_be, input->startup_intent);
    parts[0] = startup_intent_be; sizes[0] = 2;
    parts[1] = result.guest_config_sha256; sizes[1] = 32;
    parts[2] = value.target; sizes[2] = 32;
    parts[3] = value.runtime; sizes[3] = 32;
    parts[4] = (const uint8_t *)result.request_id; sizes[4] = strlen(result.request_id);
    parts[5] = (const uint8_t *)result.attempt_id; sizes[5] = strlen(result.attempt_id);
    parts[6] = (const uint8_t *)result.run_id; sizes[6] = strlen(result.run_id);
    if (builder_digest_join("PLAMEN-BROKER-V2-LAUNCH-INTENT", parts, sizes, 7,
            value.startup_receipt) != 0) goto system;
    status = builder_projection_render(&value, &result.request_projection,
        &result.request_projection_size);
    if (status != 0) goto done;
    {
        struct plamen_broker_v2_commitment commitment;
        memset(&commitment, 0, sizeof(commitment));
        status = plamen_broker_v2_request_projection_derive_exact(
            result.request_projection, result.request_projection_size,
            &commitment, result.commitment, sizeof(result.commitment),
            &result.commitment_size, result.request_projection_sha256,
            result.commitment_sha256);
        plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
        if (status != 0) goto done;
    }
    result.startup_intent = input->startup_intent;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
            ++index) {
        if ((result.retained_presence_mask
                & (uint16_t)(UINT16_C(1) << index)) == 0) continue;
        result.retained_fds[index] = fcntl(source_fds[index], F_DUPFD_CLOEXEC, 0);
        if (result.retained_fds[index] < 0) {
            status = PLAMEN_BROKER_V2_SYSTEM; goto done;
        }
    }
    status = plamen_broker_v2_projection_builder_revalidate(&result);
    if (status != 0) goto done;
    *out = result;
    memset(&result, 0, sizeof(result));
    status = PLAMEN_BROKER_V2_OK;
    goto done;
system:
    status = PLAMEN_BROKER_V2_SYSTEM;
done:
    plamen_broker_v2_projection_discovery_destroy(&observed);
    builder_json_destroy(config);
    if (raw != NULL) { plamen_broker_v2_secure_zero(raw, raw_size); free(raw); }
    if (role5 != NULL) {
        plamen_broker_v2_secure_zero(role5, role5_size); free(role5);
    }
    if (config_base64 != NULL) {
        plamen_broker_v2_secure_zero(config_base64, strlen(config_base64));
        free(config_base64);
    }
    if (guest.data != NULL) {
        plamen_broker_v2_secure_zero(guest.data, guest.capacity); free(guest.data);
    }
    if (result.ownership_magic == BUILDER_RESULT_MAGIC)
        plamen_broker_v2_projection_builder_result_destroy(&result);
    plamen_broker_v2_secure_zero(&value, sizeof(value));
    plamen_broker_v2_secure_zero(&external, sizeof(external));
    plamen_broker_v2_secure_zero(role5_sha, sizeof(role5_sha));
    plamen_broker_v2_secure_zero(runtime_image, sizeof(runtime_image));
    plamen_broker_v2_secure_zero(runtime_closure, sizeof(runtime_closure));
    plamen_broker_v2_secure_zero(seccomp, sizeof(seccomp));
    return status;
}

static int
specialized_digest_zero(const uint8_t value[32])
{
    uint8_t combined = 0;
    size_t index;
    for (index = 0; index < 32U; ++index) combined |= value[index];
    return combined == 0;
}

static int
specialized_payload_canonical(const uint8_t *payload, size_t size,
    uint16_t lane, uint16_t method, int response)
{
    struct builder_json *parsed = NULL;
    struct builder_buffer rendered;
    size_t json_size = size;
    int valid = 0;
    memset(&rendered, 0, sizeof(rendered));
    if (payload == NULL || size == 0U
        || size > PLAMEN_BROKER_V2_SPECIALIZED_PAYLOAD_MAX)
        return 0;
    if (response && lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER
        && (method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE
            || method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY)) {
        if (size == 1U || payload[size - 1U] != '\n'
            || payload[size - 2U] == '\n') return 0;
        --json_size;
    } else if (payload[size - 1U] == '\n') {
        if (response || size == 1U || payload[size - 2U] == '\n') return 0;
        --json_size;
    }
    parsed = builder_json_parse(payload, json_size);
    rendered.maximum = PLAMEN_BROKER_V2_SPECIALIZED_PAYLOAD_MAX;
    if (parsed != NULL && parsed->kind == BUILDER_JSON_OBJECT
        && builder_json_render(&rendered, parsed) == 0
        && rendered.size == json_size
        && memcmp(rendered.data, payload, json_size) == 0)
        valid = 1;
    builder_json_destroy(parsed);
    if (rendered.data != NULL) {
        plamen_broker_v2_secure_zero(rendered.data, rendered.capacity);
        free(rendered.data);
    }
    return valid;
}

static int
specialized_method_lane(uint16_t lane, uint16_t method)
{
    switch (lane) {
    case PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER:
        return method >= PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE
            && method <= PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_RUNTIME_IDENTITY;
    case PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM:
        return method >= PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_RUNTIME_IDENTITY
            && method <= PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PROJECT;
    case PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION:
        return method >= PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
            && method <= PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_PROJECT;
    case PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL:
        return method >= PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_RUNTIME_IDENTITY
            && method <= PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE;
    default:
        return 0;
    }
}

static int
specialized_capability_shape(uint16_t method, const uint8_t capability[32])
{
    int initial = method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE
        || method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_RUNTIME_IDENTITY
        || method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_RUNTIME_IDENTITY
        || method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
        || method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER
        || method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_RUNTIME_IDENTITY
        || method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE
        || method == PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT;
    return specialized_digest_zero(capability) == initial;
}

static int
specialized_descriptor_shape(
    const struct plamen_broker_v2_specialized_request *value)
{
    static const uint16_t projection_purposes[4] = {
        PLAMEN_BROKER_V2_FD_PROJECTION_PROJECT,
        PLAMEN_BROKER_V2_FD_PROJECTION_SCRATCH,
        PLAMEN_BROKER_V2_FD_PROJECTION_STATE,
        PLAMEN_BROKER_V2_FD_PROJECTION_MODULES
    };
    static const uint16_t js_purposes[4] = {
        PLAMEN_BROKER_V2_FD_JS_SOURCE,
        PLAMEN_BROKER_V2_FD_JS_SCRATCH,
        PLAMEN_BROKER_V2_FD_JS_STATE,
        PLAMEN_BROKER_V2_FD_JS_ARCHIVE_ROOT
    };
    static const uint16_t snapshot_purposes[4] = {
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE,
        PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT
    };
    static const uint16_t managed_purposes[5] = {
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_POLICY,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_PROJECT,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_CACHE,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_GENERATIONS,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_ACQUISITION_RECEIPT
    };
    size_t index;
    if (value == NULL || value->fd_count > PLAMEN_BROKER_V2_MAX_FDS)
        return 0;
    if (value->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE ||
            value->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY) {
        if (value->fd_count != 4U) return 0;
        for (index = 0; index < 4U; ++index)
            if (value->descriptors[index].purpose != js_purposes[index])
                return 0;
    } else if (value->method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT) {
        if (value->fd_count != 4U) return 0;
        for (index = 0; index < 4U; ++index)
            if (value->descriptors[index].purpose != projection_purposes[index])
                return 0;
    } else if (value->method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE
            || value->method == PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT) {
        if (value->fd_count != 4U) return 0;
        for (index = 0; index < 4U; ++index)
            if (value->descriptors[index].purpose != snapshot_purposes[index])
                return 0;
    } else if (value->method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE) {
        if (value->fd_count != 5U) return 0;
        for (index = 0; index < 5U; ++index)
            if (value->descriptors[index].purpose != managed_purposes[index])
                return 0;
    } else if (value->fd_count != 0U) return 0;
    for (index = 0; index < value->fd_count; ++index) {
        uint8_t access = PLAMEN_BROKER_V2_FD_READ;
        uint16_t purpose = value->descriptors[index].purpose;
        if (value->descriptors[index].target != (uint16_t)(index + 1U)) return 0;
        if (purpose == PLAMEN_BROKER_V2_FD_JS_SCRATCH
            || purpose == PLAMEN_BROKER_V2_FD_JS_STATE
            || purpose == PLAMEN_BROKER_V2_FD_PROJECTION_SCRATCH
            || purpose == PLAMEN_BROKER_V2_FD_PROJECTION_STATE
            || purpose == PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH
            || purpose == PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE
            || purpose == PLAMEN_BROKER_V2_FD_MANAGED_EVM_CACHE
            || purpose == PLAMEN_BROKER_V2_FD_MANAGED_EVM_GENERATIONS)
            access = PLAMEN_BROKER_V2_FD_READ_WRITE;
        if (value->descriptors[index].access_mode != access) return 0;
    }
    return 1;
}

static int
specialized_response_capability_shape(uint16_t method,
    const uint8_t capability[32])
{
    int issued = method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE
        || method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY
        || method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE
        || method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
        || method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER
        || method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE
        || method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE;
    return specialized_digest_zero(capability) != issued;
}

static uint16_t
specialized_response_disposition(uint16_t method)
{
    if (method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY)
        return PLAMEN_BROKER_V2_SPECIALIZED_REPLAYED;
    if (method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER)
        return PLAMEN_BROKER_V2_SPECIALIZED_RECOVERED;
    if (method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE
        || method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE
        || method == PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE
        || method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT
        || method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE
        || method == PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE)
        return PLAMEN_BROKER_V2_SPECIALIZED_ISSUED;
    return PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED;
}

int
plamen_broker_v2_specialized_request_encode(
    const struct plamen_broker_v2_specialized_request *value,
    uint8_t *out, size_t capacity, size_t *out_size)
{
    uint8_t digest[32];
    size_t metadata_size, total, index, offset;
    if (out_size != NULL) *out_size = 0;
    if (value == NULL || out == NULL || out_size == NULL
        || !specialized_method_lane(value->lane, value->method)
        || (value->flags & ~PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER) != 0
        || ((value->flags & PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER) != 0
            && value->method != PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY
            && value->method != PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER)
        || ((value->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY
             || value->method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER)
            && (value->flags & PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER) == 0)
        || !specialized_capability_shape(value->method, value->capability_id)
        || specialized_digest_zero(value->operation_nonce)
        || specialized_digest_zero(value->authority_binding_sha256)
        || !specialized_descriptor_shape(value)
        || !specialized_payload_canonical(value->payload,
            value->payload_size, value->lane, value->method, 0))
        return PLAMEN_BROKER_V2_INVALID;
    metadata_size = (size_t)value->fd_count
        * PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE;
    if (metadata_size > SIZE_MAX - PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE
        || value->payload_size > SIZE_MAX
            - PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE - metadata_size)
        return PLAMEN_BROKER_V2_INVALID;
    total = PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE
        + metadata_size + value->payload_size;
    if (total > capacity) return PLAMEN_BROKER_V2_INVALID;
    memset(out, 0, total);
    store_u16(out, PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION);
    store_u16(out + 2U, value->lane);
    store_u16(out + 4U, value->method);
    store_u16(out + 6U, value->flags);
    memcpy(out + 8U, value->capability_id, 32U);
    memcpy(out + 40U, value->operation_nonce, 32U);
    memcpy(out + 72U, value->authority_binding_sha256, 32U);
    store_u16(out + 104U, value->fd_count);
    store_u16(out + 106U, 0U);
    store_u32(out + 108U, value->payload_size);
    if (plamen_broker_v2_sha256(value->payload, value->payload_size,
            digest) != PLAMEN_BROKER_V2_OK)
        return PLAMEN_BROKER_V2_INVALID;
    memcpy(out + 112U, digest, 32U);
    offset = PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE;
    for (index = 0; index < value->fd_count; ++index) {
        const struct plamen_broker_v2_fd_metadata *metadata =
            &value->descriptors[index];
        store_u16(out + offset, metadata->purpose);
        store_u16(out + offset + 2U, metadata->target);
        out[offset + 4U] = metadata->access_mode;
        memcpy(out + offset + 5U, metadata->identity, 32U);
        offset += PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE;
    }
    memcpy(out + offset, value->payload, value->payload_size);
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    *out_size = total;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_specialized_request_decode_exact(const uint8_t *data,
    size_t size, struct plamen_broker_v2_specialized_request *value)
{
    uint8_t digest[32];
    size_t metadata_size, expected, index, offset;
    if (value == NULL) return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    if (data == NULL
        || size < PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE
        || load_u16(data) != PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION
        || load_u16(data + 106U) != 0U)
        return PLAMEN_BROKER_V2_INVALID;
    value->lane = load_u16(data + 2U);
    value->method = load_u16(data + 4U);
    value->flags = load_u16(data + 6U);
    memcpy(value->capability_id, data + 8U, 32U);
    memcpy(value->operation_nonce, data + 40U, 32U);
    memcpy(value->authority_binding_sha256, data + 72U, 32U);
    value->fd_count = load_u16(data + 104U);
    value->payload_size = load_u32(data + 108U);
    if (value->fd_count > PLAMEN_BROKER_V2_MAX_FDS)
        goto invalid;
    metadata_size = (size_t)value->fd_count
        * PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE;
    expected = PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE
        + metadata_size + value->payload_size;
    if (expected != size) goto invalid;
    offset = PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE;
    for (index = 0; index < value->fd_count; ++index) {
        value->descriptors[index].purpose = load_u16(data + offset);
        value->descriptors[index].target = load_u16(data + offset + 2U);
        value->descriptors[index].access_mode = data[offset + 4U];
        memcpy(value->descriptors[index].identity, data + offset + 5U, 32U);
        offset += PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE;
    }
    value->payload = data + offset;
    if (!specialized_method_lane(value->lane, value->method)
        || (value->flags & ~PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER) != 0
        || ((value->flags & PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER) != 0
            && value->method != PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY
            && value->method != PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER)
        || ((value->method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY
             || value->method == PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER)
            && (value->flags & PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER) == 0)
        || !specialized_capability_shape(value->method, value->capability_id)
        || specialized_digest_zero(value->operation_nonce)
        || specialized_digest_zero(value->authority_binding_sha256)
        || !specialized_descriptor_shape(value)
        || !specialized_payload_canonical(value->payload,
            value->payload_size, value->lane, value->method, 0)
        || plamen_broker_v2_sha256(value->payload, value->payload_size,
            digest) != PLAMEN_BROKER_V2_OK
        || !constant_equal(digest, data + 112U, 32U))
        goto invalid;
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return PLAMEN_BROKER_V2_OK;
invalid:
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    memset(value, 0, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_specialized_response_encode(
    const struct plamen_broker_v2_specialized_response *value,
    uint8_t *out, size_t capacity, size_t *out_size)
{
    size_t total;
    uint8_t terminal_sha[32];
    if (out_size != NULL) *out_size = 0;
    if (value == NULL || out == NULL || out_size == NULL
        || !specialized_method_lane(value->lane, value->method)
        || value->disposition !=
            specialized_response_disposition(value->method)
        || value->status != 0U
        || !specialized_response_capability_shape(value->method,
            value->capability_id)
        || specialized_digest_zero(value->operation_nonce)
        || specialized_digest_zero(value->request_sha256)
        || !specialized_payload_canonical(value->payload,
            value->payload_size, value->lane, value->method, 1))
        return PLAMEN_BROKER_V2_INVALID;
    total = PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE
        + value->payload_size;
    if (total > capacity) return PLAMEN_BROKER_V2_INVALID;
    if (plamen_broker_v2_sha256(value->payload, value->payload_size,
            terminal_sha) != PLAMEN_BROKER_V2_OK
        || !constant_equal(terminal_sha, value->terminal_sha256, 32U)) {
        plamen_broker_v2_secure_zero(terminal_sha, sizeof(terminal_sha));
        return PLAMEN_BROKER_V2_INVALID;
    }
    memset(out, 0, total);
    store_u16(out, PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION);
    store_u16(out + 2U, value->lane);
    store_u16(out + 4U, value->method);
    store_u16(out + 6U, value->disposition);
    store_u16(out + 8U, value->status);
    store_u16(out + 10U, 0U);
    memcpy(out + 12U, value->capability_id, 32U);
    memcpy(out + 44U, value->operation_nonce, 32U);
    memcpy(out + 76U, value->request_sha256, 32U);
    memcpy(out + 108U, value->terminal_sha256, 32U);
    store_u32(out + 140U, value->payload_size);
    memcpy(out + PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE,
        value->payload, value->payload_size);
    plamen_broker_v2_secure_zero(terminal_sha, sizeof(terminal_sha));
    *out_size = total;
    return PLAMEN_BROKER_V2_OK;
}

int
plamen_broker_v2_specialized_response_decode_exact(const uint8_t *data,
    size_t size, struct plamen_broker_v2_specialized_response *value)
{
    uint8_t terminal_sha[32];
    size_t expected;
    if (value == NULL) return PLAMEN_BROKER_V2_INVALID;
    memset(value, 0, sizeof(*value));
    if (data == NULL
        || size < PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE
        || load_u16(data) != PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION
        || load_u16(data + 10U) != 0U)
        return PLAMEN_BROKER_V2_INVALID;
    value->lane = load_u16(data + 2U);
    value->method = load_u16(data + 4U);
    value->disposition = load_u16(data + 6U);
    value->status = load_u16(data + 8U);
    memcpy(value->capability_id, data + 12U, 32U);
    memcpy(value->operation_nonce, data + 44U, 32U);
    memcpy(value->request_sha256, data + 76U, 32U);
    memcpy(value->terminal_sha256, data + 108U, 32U);
    value->payload_size = load_u32(data + 140U);
    expected = PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE
        + value->payload_size;
    if (expected != size
        || !specialized_method_lane(value->lane, value->method)
        || value->disposition !=
            specialized_response_disposition(value->method)
        || value->status != 0U
        || !specialized_response_capability_shape(value->method,
            value->capability_id)
        || specialized_digest_zero(value->operation_nonce)
        || specialized_digest_zero(value->request_sha256))
        goto invalid_response;
    value->payload = data + PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE;
    if (!specialized_payload_canonical(value->payload,
            value->payload_size, value->lane, value->method, 1)
        || plamen_broker_v2_sha256(value->payload, value->payload_size,
            terminal_sha) != PLAMEN_BROKER_V2_OK
        || !constant_equal(terminal_sha, value->terminal_sha256, 32U))
        goto invalid_response;
    plamen_broker_v2_secure_zero(terminal_sha, sizeof(terminal_sha));
    return PLAMEN_BROKER_V2_OK;
invalid_response:
    plamen_broker_v2_secure_zero(terminal_sha, sizeof(terminal_sha));
    memset(value, 0, sizeof(*value));
    return PLAMEN_BROKER_V2_INVALID;
}

int
plamen_broker_v2_specialized_request_validate_fds(
    const struct plamen_broker_v2_specialized_request *value,
    int *fds, size_t fd_count)
{
    if (!specialized_descriptor_shape(value)
        || fd_count != value->fd_count
        || (fd_count != 0U && fds == NULL))
        return PLAMEN_BROKER_V2_INVALID;
    return plamen_broker_v2_validate_received_fds(
        fds, fd_count, value->descriptors, value->fd_count);
}

#ifdef __linux__

#define PLAMEN_LINUX_CLIENT_PROC_TEXT_MAX 16384U
#define PLAMEN_LINUX_CLIENT_BOOT_ID_SIZE 36U

static int
linux_client_pidfd_open(pid_t pid)
{
#ifdef SYS_pidfd_open
    int descriptor = (int)syscall(SYS_pidfd_open, pid, 0U);
    int flags;
    if (descriptor < 0 ||
            (flags = fcntl(descriptor, F_GETFD)) < 0 ||
            fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) != 0) {
        if (descriptor >= 0) (void)close(descriptor);
        return -1;
    }
    return descriptor;
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

static int
linux_client_pidfd_alive(int descriptor)
{
    struct pollfd item;
    int result;
    memset(&item, 0, sizeof(item));
    item.fd = descriptor;
    item.events = POLLIN;
    do {
        result = poll(&item, 1, 0);
    } while (result < 0 && errno == EINTR);
    return result == 0 && item.revents == 0 ? 0 : -1;
}

static int
linux_client_read_at(int directory, const char *name, uint8_t *output,
                     size_t capacity, size_t *size)
{
    int descriptor = -1, result = -1;
    size_t offset = 0;
    ssize_t amount;
    if (directory < 0 || name == NULL || output == NULL || capacity == 0 ||
            size == NULL) {
        return -1;
    }
    *size = 0;
    descriptor = openat(directory, name,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return -1;
    for (;;) {
        if (offset == capacity) goto done;
        do {
            amount = read(descriptor, output + offset, capacity - offset);
        } while (amount < 0 && errno == EINTR);
        if (amount < 0) goto done;
        if (amount == 0) break;
        offset += (size_t)amount;
    }
    *size = offset;
    result = 0;
done:
    (void)close(descriptor);
    return result;
}

static int
linux_client_decimal_fields(const char *start, const char *end,
                            uint64_t values[4])
{
    const char *cursor = start;
    unsigned index;
    for (index = 0; index < 4; index++) {
        char *after;
        unsigned long long value;
        while (cursor < end && (*cursor == ' ' || *cursor == '\t')) cursor++;
        if (cursor == end || *cursor < '0' || *cursor > '9') return -1;
        errno = 0;
        value = strtoull(cursor, &after, 10);
        if (errno != 0 || after == cursor || after > end) return -1;
        values[index] = (uint64_t)value;
        cursor = after;
    }
    while (cursor < end && (*cursor == ' ' || *cursor == '\t')) cursor++;
    return cursor == end ? 0 : -1;
}

static int
linux_client_status_ids(int process_directory,
                        const struct ucred *credential)
{
    uint8_t raw[PLAMEN_LINUX_CLIENT_PROC_TEXT_MAX];
    size_t size = 0, offset = 0;
    int uid_seen = 0, gid_seen = 0;
    if (credential == NULL ||
            linux_client_read_at(process_directory, "status", raw,
                                 sizeof(raw), &size) != 0 ||
            size == sizeof(raw)) {
        return -1;
    }
    while (offset < size) {
        size_t end = offset;
        uint64_t fields[4];
        while (end < size && raw[end] != '\n') end++;
        if (end - offset >= 4 && memcmp(raw + offset, "Uid:", 4) == 0) {
            if (uid_seen || linux_client_decimal_fields(
                    (const char *)raw + offset + 4,
                    (const char *)raw + end, fields) != 0 ||
                    fields[0] != (uint64_t)credential->uid ||
                    fields[1] != fields[0] || fields[2] != fields[0] ||
                    fields[3] != fields[0]) {
                return -1;
            }
            uid_seen = 1;
        } else if (end - offset >= 4 &&
                   memcmp(raw + offset, "Gid:", 4) == 0) {
            if (gid_seen || linux_client_decimal_fields(
                    (const char *)raw + offset + 4,
                    (const char *)raw + end, fields) != 0 ||
                    fields[0] != (uint64_t)credential->gid ||
                    fields[1] != fields[0] || fields[2] != fields[0] ||
                    fields[3] != fields[0]) {
                return -1;
            }
            gid_seen = 1;
        }
        offset = end < size ? end + 1 : end;
    }
    return uid_seen && gid_seen ? 0 : -1;
}

static int
linux_client_start_ticks(int process_directory, pid_t expected_pid,
                         uint64_t *start_ticks)
{
    uint8_t raw[PLAMEN_LINUX_CLIENT_PROC_TEXT_MAX];
    char *cursor, *end, *close_paren, *after;
    size_t size = 0;
    long parsed_pid;
    unsigned field;
    if (start_ticks == NULL || linux_client_read_at(
            process_directory, "stat", raw, sizeof(raw) - 1, &size) != 0 ||
            size == 0 || size == sizeof(raw) - 1) {
        return -1;
    }
    raw[size] = '\0';
    cursor = (char *)raw;
    errno = 0;
    parsed_pid = strtol(cursor, &after, 10);
    if (errno != 0 || parsed_pid != (long)expected_pid || after == cursor ||
            *after != ' ') {
        return -1;
    }
    close_paren = strrchr(after + 1, ')');
    if (close_paren == NULL || close_paren[1] != ' ' ||
            close_paren[2] == '\0' || close_paren[3] != ' ') {
        return -1;
    }
    cursor = close_paren + 4;
    end = (char *)raw + size;
    for (field = 4; field <= 22; field++) {
        unsigned long long value;
        while (cursor < end && *cursor == ' ') cursor++;
        if (cursor == end) return -1;
        errno = 0;
        value = strtoull(cursor, &after, 10);
        if (errno != 0 || after == cursor || after > end ||
                (after < end && *after != ' ' && *after != '\n')) {
            return -1;
        }
        if (field == 22) {
            if (value == 0) return -1;
            *start_ticks = (uint64_t)value;
            return 0;
        }
        cursor = after;
    }
    return -1;
}

static int
linux_client_boot_digest(int proc_root, uint8_t digest[32])
{
    uint8_t raw[PLAMEN_LINUX_CLIENT_BOOT_ID_SIZE + 2];
    size_t size = 0, index;
    if (linux_client_read_at(proc_root, "sys/kernel/random/boot_id", raw,
            sizeof(raw), &size) != 0 ||
            size != PLAMEN_LINUX_CLIENT_BOOT_ID_SIZE + 1 ||
            raw[PLAMEN_LINUX_CLIENT_BOOT_ID_SIZE] != '\n') {
        return -1;
    }
    for (index = 0; index < PLAMEN_LINUX_CLIENT_BOOT_ID_SIZE; index++) {
        int hyphen = index == 8 || index == 13 || index == 18 || index == 23;
        if (hyphen ? raw[index] != '-' :
                !((raw[index] >= '0' && raw[index] <= '9') ||
                  (raw[index] >= 'a' && raw[index] <= 'f'))) {
            return -1;
        }
    }
    return plamen_broker_v2_sha256(raw, PLAMEN_LINUX_CLIENT_BOOT_ID_SIZE,
                                   digest) == PLAMEN_BROKER_V2_OK ? 0 : -1;
}

static int
linux_client_peer_admit(int socket_fd, uint64_t expected_uid,
        const uint8_t expected_executable_identity[32],
        struct plamen_broker_v2_peer_identity *identity, int *pidfd_out)
{
    struct plamen_broker_v2_peer_identity candidate;
    struct statfs filesystem;
    struct stat executable_info;
    struct ucred first, second;
    socklen_t credential_size;
    char process_name[32];
    uint8_t executable_identity[32], second_boot[32];
    uint64_t second_start = 0;
    long ticks;
    int proc_root = -1, process_directory = -1, executable = -1, pidfd = -1;
    int result = PLAMEN_BROKER_V2_AUTH_FAILED;
    if (identity != NULL) memset(identity, 0, sizeof(*identity));
    if (pidfd_out != NULL) *pidfd_out = -1;
    memset(&candidate, 0, sizeof(candidate));
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    memset(executable_identity, 0, sizeof(executable_identity));
    memset(second_boot, 0, sizeof(second_boot));
    if (socket_fd < 0 || expected_uid != (uint64_t)geteuid() ||
            expected_executable_identity == NULL || identity == NULL ||
            pidfd_out == NULL) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    credential_size = sizeof(first);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &first,
            &credential_size) != 0 || credential_size != sizeof(first) ||
            first.pid <= 1 || (uint64_t)first.uid != expected_uid) {
        goto done;
    }
    if (snprintf(process_name, sizeof(process_name), "%ld",
                 (long)first.pid) <= 0) {
        goto done;
    }
    proc_root = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (proc_root < 0 || fstatfs(proc_root, &filesystem) != 0 ||
            (unsigned long)filesystem.f_type !=
                (unsigned long)PROC_SUPER_MAGIC) {
        goto done;
    }
    process_directory = openat(proc_root, process_name,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (process_directory < 0 ||
            linux_client_status_ids(process_directory, &first) != 0 ||
            linux_client_start_ticks(process_directory, first.pid,
                                     &candidate.birth_primary) != 0 ||
            linux_client_boot_digest(proc_root,
                                     candidate.boot_id_sha256) != 0) {
        goto done;
    }
    ticks = sysconf(_SC_CLK_TCK);
    if (ticks <= 0) goto done;
    candidate.pid = (uint64_t)first.pid;
    candidate.uid = (uint64_t)first.uid;
    candidate.gid = (uint64_t)first.gid;
    candidate.birth_kind = PLAMEN_BROKER_V2_BIRTH_LINUX_BOOT_TICKS;
    candidate.birth_secondary = (uint64_t)ticks;
    pidfd = linux_client_pidfd_open(first.pid);
    if (pidfd < 0 || linux_client_pidfd_alive(pidfd) != 0) goto done;
    executable = openat(process_directory, "exe", O_RDONLY | O_CLOEXEC);
    if (executable < 0 || fstat(executable, &executable_info) != 0 ||
            !S_ISREG(executable_info.st_mode) ||
            (executable_info.st_mode & 0111) == 0 ||
            plamen_broker_v2_fd_identity(executable,
                executable_identity) != PLAMEN_BROKER_V2_OK ||
            !constant_equal(executable_identity,
                            expected_executable_identity, 32)) {
        goto done;
    }
    credential_size = sizeof(second);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &second,
            &credential_size) != 0 || credential_size != sizeof(second) ||
            second.pid != first.pid || second.uid != first.uid ||
            second.gid != first.gid ||
            linux_client_status_ids(process_directory, &second) != 0 ||
            linux_client_start_ticks(process_directory, second.pid,
                                     &second_start) != 0 ||
            second_start != candidate.birth_primary ||
            linux_client_boot_digest(proc_root, second_boot) != 0 ||
            !constant_equal(second_boot, candidate.boot_id_sha256, 32) ||
            linux_client_pidfd_alive(pidfd) != 0) {
        goto done;
    }
    *identity = candidate;
    *pidfd_out = pidfd;
    pidfd = -1;
    result = PLAMEN_BROKER_V2_OK;
done:
    if (pidfd >= 0) (void)close(pidfd);
    if (executable >= 0) (void)close(executable);
    if (process_directory >= 0) (void)close(process_directory);
    if (proc_root >= 0) (void)close(proc_root);
    plamen_broker_v2_secure_zero(executable_identity,
                                 sizeof(executable_identity));
    plamen_broker_v2_secure_zero(second_boot, sizeof(second_boot));
    if (result != PLAMEN_BROKER_V2_OK) {
        memset(identity, 0, sizeof(*identity));
        *pidfd_out = -1;
    }
    return result;
}

static int
linux_client_socket_path(uint16_t scope, uint64_t expected_uid,
                         char output[sizeof(((struct sockaddr_un *)0)->sun_path)])
{
    int written;
    if (expected_uid != (uint64_t)geteuid()) return -1;
    if (scope == PLAMEN_BROKER_V2_LINUX_SCOPE_GUEST_ROOT) {
        if (expected_uid != 0) return -1;
        written = snprintf(output, sizeof(((struct sockaddr_un *)0)->sun_path),
                           "%s", PLAMEN_BROKER_V2_LINUX_GUEST_SOCKET);
    } else if (scope == PLAMEN_BROKER_V2_LINUX_SCOPE_OUTER_USER) {
        written = snprintf(output, sizeof(((struct sockaddr_un *)0)->sun_path),
                           PLAMEN_BROKER_V2_LINUX_USER_SOCKET_FORMAT,
                           (unsigned long long)expected_uid);
    } else {
        return -1;
    }
    return written > 0 &&
        (size_t)written < sizeof(((struct sockaddr_un *)0)->sun_path) ? 0 : -1;
}

int
plamen_broker_v2_linux_current_peer(
    uint64_t expected_uid,
    const uint8_t expected_interpreter_executable_identity[32],
    struct plamen_broker_v2_peer_identity *current_peer)
{
    int sockets[2] = {-1, -1}, pidfd = -1;
    int result = PLAMEN_BROKER_V2_AUTH_FAILED;
    if (current_peer != NULL) memset(current_peer, 0, sizeof(*current_peer));
    if (expected_interpreter_executable_identity == NULL ||
            current_peer == NULL || expected_uid != (uint64_t)geteuid()) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
        return PLAMEN_BROKER_V2_SYSTEM;
    }
    result = linux_client_peer_admit(sockets[0], expected_uid,
        expected_interpreter_executable_identity, current_peer, &pidfd);
    if (result == PLAMEN_BROKER_V2_OK &&
            linux_client_pidfd_alive(pidfd) != 0) {
        memset(current_peer, 0, sizeof(*current_peer));
        result = PLAMEN_BROKER_V2_AUTH_FAILED;
    }
    if (pidfd >= 0) (void)close(pidfd);
    (void)close(sockets[0]);
    (void)close(sockets[1]);
    return result;
}

static int
linux_client_path_admit(const char *path, uint64_t expected_uid)
{
    struct stat socket_info, directory_info;
    char directory[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char *separator;
    size_t size;
    if (path == NULL || path[0] != '/' ||
            (size = strlen(path)) >= sizeof(directory)) {
        return -1;
    }
    memcpy(directory, path, size + 1);
    separator = strrchr(directory, '/');
    if (separator == NULL || separator == directory) return -1;
    *separator = '\0';
    if (lstat(directory, &directory_info) != 0 ||
            !S_ISDIR(directory_info.st_mode) ||
            (uint64_t)directory_info.st_uid != expected_uid ||
            (directory_info.st_mode & 0777) != 0700 ||
            lstat(path, &socket_info) != 0 ||
            !S_ISSOCK(socket_info.st_mode) ||
            (uint64_t)socket_info.st_uid != expected_uid) {
        return -1;
    }
    return 0;
}

static int
linux_client_connect(uint16_t scope, uint64_t expected_uid,
                     int *socket_out)
{
    struct sockaddr_un address;
    struct pollfd item;
    socklen_t address_size;
    int descriptor = -1, flags, error = 0, result;
    socklen_t error_size = sizeof(error);
    if (socket_out == NULL) return PLAMEN_BROKER_V2_INVALID;
    *socket_out = -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (linux_client_socket_path(scope, expected_uid,
            address.sun_path) != 0 ||
            linux_client_path_admit(address.sun_path, expected_uid) != 0) {
        return PLAMEN_BROKER_V2_AUTH_FAILED;
    }
    descriptor = socket(AF_UNIX,
        SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (descriptor < 0) return PLAMEN_BROKER_V2_SYSTEM;
    address_size = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                               strlen(address.sun_path) + 1U);
    result = connect(descriptor, (struct sockaddr *)&address, address_size);
    if (result != 0 && errno == EINPROGRESS) {
        memset(&item, 0, sizeof(item));
        item.fd = descriptor;
        item.events = POLLOUT;
        do {
            result = poll(&item, 1,
                          (int)PLAMEN_BROKER_V2_SESSION_CHALLENGE_TIMEOUT_MS);
        } while (result < 0 && errno == EINTR);
        if (result != 1 || (item.revents & POLLOUT) == 0 ||
                (item.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
                getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error,
                           &error_size) != 0 || error_size != sizeof(error) ||
                error != 0) {
            if (error != 0) errno = error;
            (void)close(descriptor);
            return PLAMEN_BROKER_V2_SYSTEM;
        }
    } else if (result != 0) {
        (void)close(descriptor);
        return PLAMEN_BROKER_V2_SYSTEM;
    }
    flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK) != 0) {
        (void)close(descriptor);
        return PLAMEN_BROKER_V2_SYSTEM;
    }
    *socket_out = descriptor;
    return PLAMEN_BROKER_V2_OK;
}

static int
linux_client_send_borrowed(int socket_fd, const uint8_t *envelope,
        size_t envelope_size, const int *fds, size_t fd_count)
{
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(int) *
                                 PLAMEN_BROKER_V2_SERVICE_MAX_FDS)];
    } control;
    struct msghdr message;
    struct iovec vector;
    struct cmsghdr *header;
    ssize_t amount;
    size_t index;
    if (socket_fd < 0 || envelope == NULL ||
            envelope_size < PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE ||
            envelope_size > PLAMEN_BROKER_V2_LINUX_SERVICE_PACKET_MAX ||
            fd_count > PLAMEN_BROKER_V2_SERVICE_MAX_FDS ||
            (fd_count != 0 && fds == NULL)) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    for (index = 0; index < fd_count; index++) {
        if (fds[index] < 0) return PLAMEN_BROKER_V2_FD_INVALID;
    }
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    vector.iov_base = (void *)(uintptr_t)envelope;
    vector.iov_len = envelope_size;
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    if (fd_count != 0) {
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * fd_count);
        header = CMSG_FIRSTHDR(&message);
        if (header == NULL) return PLAMEN_BROKER_V2_SYSTEM;
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);
        memcpy(CMSG_DATA(header), fds, sizeof(int) * fd_count);
    }
    do {
        amount = sendmsg(socket_fd, &message, MSG_NOSIGNAL);
    } while (amount < 0 && errno == EINTR);
    return amount == (ssize_t)envelope_size ?
        PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_SYSTEM;
}

static int
linux_client_receive_no_fds(int socket_fd, uint8_t local_role,
        const struct plamen_broker_v2_peer_identity *expected_peer,
        uint8_t **envelope, size_t *envelope_size,
        struct plamen_broker_v2_service_envelope_view *view)
{
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(struct ucred)) +
                      CMSG_SPACE(sizeof(int) *
                          (PLAMEN_BROKER_V2_SERVICE_MAX_FDS + 1U))];
    } control;
    uint8_t packet[PLAMEN_BROKER_V2_LINUX_SERVICE_PACKET_MAX + 1U];
    struct msghdr message;
    struct iovec vector;
    struct cmsghdr *header;
    struct ucred socket_credential, packet_credential;
    struct pollfd item;
    socklen_t credential_size = sizeof(socket_credential);
    int passcred = 1, credential_seen = 0, rights_seen = 0;
    int received[PLAMEN_BROKER_V2_SERVICE_MAX_FDS + 1U];
    size_t received_count = 0, received_index;
    ssize_t amount, trailing;
    int result = PLAMEN_BROKER_V2_AUTH_FAILED;
    if (envelope == NULL || envelope_size == NULL || view == NULL ||
            expected_peer == NULL) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    *envelope = NULL;
    *envelope_size = 0;
    memset(view, 0, sizeof(*view));
    memset(&socket_credential, 0, sizeof(socket_credential));
    memset(&packet_credential, 0, sizeof(packet_credential));
    for (received_index = 0;
            received_index < PLAMEN_BROKER_V2_SERVICE_MAX_FDS + 1U;
            received_index++) {
        received[received_index] = -1;
    }
    if (setsockopt(socket_fd, SOL_SOCKET, SO_PASSCRED, &passcred,
            sizeof(passcred)) != 0 ||
            getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED,
            &socket_credential, &credential_size) != 0 ||
            credential_size != sizeof(socket_credential) ||
            (uint64_t)socket_credential.pid != expected_peer->pid ||
            (uint64_t)socket_credential.uid != expected_peer->uid ||
            (uint64_t)socket_credential.gid != expected_peer->gid) {
        return PLAMEN_BROKER_V2_AUTH_FAILED;
    }
    memset(&item, 0, sizeof(item));
    item.fd = socket_fd;
    item.events = POLLIN;
    do {
        result = poll(&item, 1,
                      (int)PLAMEN_BROKER_V2_SESSION_CHALLENGE_TIMEOUT_MS);
    } while (result < 0 && errno == EINTR);
    if (result != 1 || (item.revents & POLLIN) == 0 ||
            (item.revents & (POLLERR | POLLNVAL)) != 0) {
        return PLAMEN_BROKER_V2_SYSTEM;
    }
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    vector.iov_base = packet;
    vector.iov_len = sizeof(packet);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    do {
        amount = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC | MSG_TRUNC);
    } while (amount < 0 && errno == EINTR);
    if (amount < (ssize_t)PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE ||
            amount > (ssize_t)PLAMEN_BROKER_V2_LINUX_SERVICE_PACKET_MAX) {
        goto done;
    }
    for (header = CMSG_FIRSTHDR(&message); header != NULL;
            header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_len < CMSG_LEN(0) ||
                header->cmsg_level != SOL_SOCKET) {
            goto done;
        }
        if (header->cmsg_type == SCM_CREDENTIALS) {
            if (credential_seen ||
                    header->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
                goto done;
            }
            memcpy(&packet_credential, CMSG_DATA(header),
                   sizeof(packet_credential));
            credential_seen = 1;
        } else if (header->cmsg_type == SCM_RIGHTS) {
            size_t bytes, count;
            rights_seen = 1;
            bytes = header->cmsg_len - CMSG_LEN(0);
            if (bytes == 0 || bytes % sizeof(int) != 0) goto done;
            count = bytes / sizeof(int);
            if (count > PLAMEN_BROKER_V2_SERVICE_MAX_FDS + 1U) goto done;
            memcpy(received, CMSG_DATA(header), bytes);
            received_count = count;
        } else {
            goto done;
        }
    }
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
            !credential_seen || rights_seen ||
            packet_credential.pid != socket_credential.pid ||
            packet_credential.uid != socket_credential.uid ||
            packet_credential.gid != socket_credential.gid) {
        goto done;
    }
    do {
        trailing = recv(socket_fd, packet, 1, MSG_PEEK | MSG_DONTWAIT);
    } while (trailing < 0 && errno == EINTR);
    if (trailing > 0 || (trailing < 0 && errno != EAGAIN &&
                         errno != EWOULDBLOCK)) {
        goto done;
    }
    *envelope = malloc((size_t)amount);
    if (*envelope == NULL) {
        result = PLAMEN_BROKER_V2_NOMEM;
        goto done;
    }
    memcpy(*envelope, packet, (size_t)amount);
    if (plamen_broker_v2_service_envelope_accept(local_role, *envelope,
            (size_t)amount, 0, view) != PLAMEN_BROKER_V2_OK) {
        goto done;
    }
    *envelope_size = (size_t)amount;
    result = PLAMEN_BROKER_V2_OK;
done:
    for (received_index = 0; received_index < received_count;
            received_index++) {
        if (received[received_index] >= 0) (void)close(received[received_index]);
    }
    plamen_broker_v2_secure_zero(packet, sizeof(packet));
    if (result != PLAMEN_BROKER_V2_OK) {
        if (*envelope != NULL) {
            plamen_broker_v2_secure_zero(*envelope, (size_t)(amount > 0 ? amount : 0));
            free(*envelope);
            *envelope = NULL;
        }
        *envelope_size = 0;
        memset(view, 0, sizeof(*view));
    }
    return result;
}

int
plamen_broker_v2_linux_client_exchange(
    uint16_t scope, uint64_t expected_uid,
    const uint8_t expected_executable_identity[32],
    const uint8_t *request_envelope, size_t request_envelope_size,
    const int *request_fds, size_t request_fd_count, uint8_t local_role,
    uint8_t **response_envelope, size_t *response_envelope_size,
    struct plamen_broker_v2_service_envelope_view *response_view,
    struct plamen_broker_v2_peer_identity *service_peer)
{
    struct plamen_broker_v2_peer_identity first, second;
    struct plamen_broker_v2_service_envelope_view request_view;
    int socket_fd = -1, first_pidfd = -1, second_pidfd = -1;
    int result;
    if (response_envelope != NULL) *response_envelope = NULL;
    if (response_envelope_size != NULL) *response_envelope_size = 0;
    if (response_view != NULL) memset(response_view, 0, sizeof(*response_view));
    if (service_peer != NULL) memset(service_peer, 0, sizeof(*service_peer));
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    memset(&request_view, 0, sizeof(request_view));
    if (expected_executable_identity == NULL || request_envelope == NULL ||
            response_envelope == NULL || response_envelope_size == NULL ||
            response_view == NULL || service_peer == NULL ||
            request_fd_count > PLAMEN_BROKER_V2_SERVICE_MAX_FDS ||
            local_role != PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION ||
            plamen_broker_v2_service_envelope_accept(
                PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER,
                request_envelope, request_envelope_size, request_fd_count,
                &request_view) != PLAMEN_BROKER_V2_OK) {
        return PLAMEN_BROKER_V2_INVALID;
    }
    result = linux_client_connect(scope, expected_uid, &socket_fd);
    if (result != PLAMEN_BROKER_V2_OK) goto done;
    result = linux_client_peer_admit(socket_fd, expected_uid,
        expected_executable_identity, &first, &first_pidfd);
    if (result != PLAMEN_BROKER_V2_OK) goto done;
    result = linux_client_send_borrowed(socket_fd, request_envelope,
        request_envelope_size, request_fds, request_fd_count);
    if (result != PLAMEN_BROKER_V2_OK) goto done;
    result = linux_client_receive_no_fds(socket_fd, local_role, &first,
        response_envelope, response_envelope_size, response_view);
    if (result != PLAMEN_BROKER_V2_OK) goto done;
    result = linux_client_peer_admit(socket_fd, expected_uid,
        expected_executable_identity, &second, &second_pidfd);
    if (result != PLAMEN_BROKER_V2_OK ||
            memcmp(&first, &second, sizeof(first)) != 0 ||
            linux_client_pidfd_alive(first_pidfd) != 0 ||
            linux_client_pidfd_alive(second_pidfd) != 0) {
        result = PLAMEN_BROKER_V2_AUTH_FAILED;
        goto done;
    }
    *service_peer = first;
    result = PLAMEN_BROKER_V2_OK;
done:
    if (second_pidfd >= 0) (void)close(second_pidfd);
    if (first_pidfd >= 0) (void)close(first_pidfd);
    if (socket_fd >= 0) (void)close(socket_fd);
    if (result != PLAMEN_BROKER_V2_OK) {
        if (*response_envelope != NULL) {
            plamen_broker_v2_secure_zero(*response_envelope,
                                         *response_envelope_size);
            free(*response_envelope);
            *response_envelope = NULL;
        }
        *response_envelope_size = 0;
        memset(response_view, 0, sizeof(*response_view));
        memset(service_peer, 0, sizeof(*service_peer));
    }
    plamen_broker_v2_secure_zero(&first, sizeof(first));
    plamen_broker_v2_secure_zero(&second, sizeof(second));
    plamen_broker_v2_secure_zero(&request_view, sizeof(request_view));
    return result;
}

#endif /* __linux__ */
