#ifndef PLAMEN_BROKER_V2_TEST_ONLY
#error "broker_v2_test_peer.c is a separately compiled TEST_ONLY peer"
#endif

#ifdef __linux__
#define _GNU_SOURCE 1
#endif
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "../include/plamen_broker_v2.h"
#include "../posix/plamen_broker_v2_journal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/memfd.h>
#include <sys/mman.h>
#endif

#ifndef O_NOFOLLOW
#error "TEST_ONLY broker peer requires O_NOFOLLOW"
#endif
#ifndef O_CLOEXEC
#error "TEST_ONLY broker peer requires O_CLOEXEC"
#endif

#define CHECK(value) do { if (!(value)) return __LINE__; } while (0)

static void
fill(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static int
make_commitment(uint8_t fingerprint_value, uint8_t *encoded, size_t *size,
    uint8_t sha256[32], struct plamen_broker_v2_commitment *value)
{
    struct plamen_broker_v2_writer writer;
    memset(value, 0, sizeof(*value));
    fill(value->request_fingerprint, fingerprint_value);
    strcpy(value->attempt_id, "attempt-1");
    strcpy(value->run_identity, "run-1");
    fill(value->config_sha256, 2);
    fill(value->runtime_closure_sha256, 3);
    fill(value->image_closure_sha256, 4);
    fill(value->provider_provenance_sha256, 5);
    fill(value->backend_admission_sha256, 6);
    fill(value->credential_isolation_sha256, 7);
    fill(value->egress_admission_sha256, 8);
    plamen_broker_v2_writer_init(&writer, encoded,
        PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE);
    if (plamen_broker_v2_encode_commitment(&writer, value) != 0
        || plamen_broker_v2_sha256(encoded, writer.offset, sha256) != 0)
        return -1;
    *size = writer.offset;
    return 0;
}

static const uint8_t valid_projection[] =
    "{\"audit_request\":{\"attempt_id\":\"attempt-1\",\"backend\":\"codex\",\"backend_admission_sha256\":\"6666666"
    "666666666666666666666666666666666666666666666666666666666\",\"backend_context_sha256\":\"bbbbbbbbbbb"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"credential_bundle_sha256\":\"ccccccccccccc"
    "ccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"credential_isolation_sha256\":\"777777777777"
    "7777777777777777777777777777777777777777777777777777\",\"docs_sha256\":\"ddddddddddddddddddddddddddd"
    "ddddddddddddddddddddddddddddddddddddd\",\"egress_admission_sha256\":\"888888888888888888888888888888"
    "8888888888888888888888888888888888\",\"egress_policy_sha256\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    "eeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"export_allowlist\":[\"project/AUDIT_REPORT.md\",\"scratch/_plamen.log"
    "\",\"scratch/_v2_checkpoint.json\"],\"export_destination_identity_sha256\":\"fffffffffffffffffffffffff"
    "fffffffffffffffffffffffffffffffffffffff\",\"export_max_total_bytes\":2147483648,\"failure_required_a"
    "rtifacts\":[\"scratch/_plamen.log\"],\"image_closure_sha256\":\"44444444444444444444444444444444444444"
    "44444444444444444444444444\",\"image_manifest_digest\":\"sha256:999999999999999999999999999999999999"
    "9999999999999999999999999999\",\"language\":\"evm\",\"mode\":\"core\",\"pipeline\":\"sc\",\"provider_provenanc"
    "e_sha256\":\"5555555555555555555555555555555555555555555555555555555555555555\",\"request_id\":\"reque"
    "st-1\",\"request_type\":\"SC_NEW\",\"required_artifacts\":[\"project/AUDIT_REPORT.md\",\"scratch/_v2_check"
    "point.json\"],\"run_id\":\"run-1\",\"runtime_layout_sha256\":\"33333333333333333333333333333333333333333"
    "33333333333333333333333\",\"schema\":\"plamen.posix_audit_supervisor.v1\",\"scope_sha256\":\"11111111111"
    "11111111111111111111111111111111111111111111111111111\",\"seccomp_profile_sha256\":\"222222222222222"
    "2222222222222222222222222222222222222222222222222\",\"source_config\":{\"authenticated\":true,\"canoni"
    "cal_utf8_b64\":\"eyJfcnVuX2lkIjoicnVuLTEiLCJjbGlfYmFja2VuZCI6ImNvZGV4IiwibGFuZ3VhZ2UiOiJldm0iLCJtb"
    "2RlIjoiY29yZSIsInBpcGVsaW5lIjoic2MiLCJwcm9qZWN0X3Jvb3QiOiIvd29ya3NwYWNlL3Byb2plY3QiLCJzY3JhdGNoc"
    "GFkIjoiL3dvcmtzcGFjZS9zY3JhdGNoIn0K\",\"retained_source_handle\":\"opaque:aaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"sha256\":\"201e8183f9df23e133f2b8bca392eec769e13525a6d38a"
    "b4c3231d63e33a7e83\"},\"source_config_sha256\":\"201e8183f9df23e133f2b8bca392eec769e13525a6d38ab4c32"
    "31d63e33a7e83\",\"startup_decision_receipt_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaa\",\"target_identity_sha256\":\"00000000000000000000000000000000000000000000000000"
    "00000000000000\"},\"projection_schema\":\"plamen.native_audit_request_projection.v1\"}";

static int
hex_equal(const uint8_t *actual, const char *expected)
{
    static const char digits[] = "0123456789abcdef";
    unsigned index;
    for (index = 0; index < 32; ++index) {
        if (digits[actual[index] >> 4] != expected[index * 2]
            || digits[actual[index] & 15] != expected[index * 2 + 1])
            return 0;
    }
    return expected[64] == '\0';
}

static int
test_crypto(void)
{
    uint8_t digest[32], hmac[32], key[32];
    unsigned index;
    for (index = 0; index < 32; ++index) key[index] = (uint8_t)index;
    CHECK(plamen_broker_v2_sha256("abc", 3, digest) == 0);
    CHECK(hex_equal(digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK(plamen_broker_v2_hmac_sha256(key, "abc", 3, "def", 3, hmac) == 0);
    CHECK(hex_equal(hmac,
        "2867d85143fa9948833a5ec6f3c7d31068cc5a9ba587e08b1e8ad88e1a30acb3"));
    return 0;
}

static int
test_payloads(void)
{
    uint8_t bytes[1024], digest[32], projection_sha[32], commitment_sha[32];
    uint8_t commitment_bytes[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    uint8_t *projection_copy = NULL;
    size_t commitment_size = 0;
    struct plamen_broker_v2_writer writer;
    struct plamen_broker_v2_reader reader;
    struct plamen_broker_v2_commitment in, out;
    const uint8_t bad_overlong[] = {0xc0, 0x80};
    int boolean;
    memset(&in, 0, sizeof(in));
    fill(in.request_fingerprint, 1);
    strcpy(in.attempt_id, "attempt-1");
    strcpy(in.run_identity, "run:1");
    fill(in.config_sha256, 2);
    fill(in.runtime_closure_sha256, 3);
    fill(in.image_closure_sha256, 4);
    fill(in.provider_provenance_sha256, 5);
    fill(in.backend_admission_sha256, 6);
    fill(in.credential_isolation_sha256, 7);
    fill(in.egress_admission_sha256, 8);
    plamen_broker_v2_writer_init(&writer, bytes, sizeof(bytes));
    CHECK(plamen_broker_v2_encode_commitment(&writer, &in) == 0);
    CHECK(plamen_broker_v2_decode_commitment_exact(bytes, writer.offset, &out) == 0);
    CHECK(memcmp(in.request_fingerprint, out.request_fingerprint, 32) == 0);
    CHECK(strcmp(in.attempt_id, out.attempt_id) == 0);
    CHECK(strcmp(in.run_identity, out.run_identity) == 0);
    bytes[writer.offset] = 0;
    CHECK(plamen_broker_v2_decode_commitment_exact(bytes, writer.offset + 1, &out)
        == PLAMEN_BROKER_V2_INVALID);
    plamen_broker_v2_writer_init(&writer, bytes, sizeof(bytes));
    CHECK(plamen_broker_v2_put_text(&writer, bad_overlong,
        sizeof(bad_overlong)) == PLAMEN_BROKER_V2_INVALID);
    bytes[0] = 2;
    plamen_broker_v2_reader_init(&reader, bytes, 1);
    CHECK(plamen_broker_v2_get_bool(&reader, &boolean) == PLAMEN_BROKER_V2_INVALID);
    fill(digest, 9);
    plamen_broker_v2_writer_init(&writer, bytes, sizeof(bytes));
    CHECK(plamen_broker_v2_put_u8(&writer, 1) == 0);
    CHECK(plamen_broker_v2_put_u16(&writer, 0x0203) == 0);
    CHECK(plamen_broker_v2_put_u32(&writer, 0x04050607) == 0);
    CHECK(plamen_broker_v2_put_u64(&writer, UINT64_C(0x08090a0b0c0d0e0f)) == 0);
    CHECK(plamen_broker_v2_put_digest(&writer, digest) == 0);
    CHECK(bytes[0] == 1 && bytes[1] == 2 && bytes[2] == 3 && bytes[3] == 4
        && bytes[4] == 5 && bytes[5] == 6 && bytes[6] == 7);
    memset(commitment_bytes, 0, sizeof(commitment_bytes));
    CHECK(plamen_broker_v2_request_projection_derive_exact(valid_projection,
        sizeof(valid_projection) - 1U, &out, commitment_bytes,
        sizeof(commitment_bytes), &commitment_size, projection_sha,
        commitment_sha) == 0);
    CHECK(commitment_size > 0
        && hex_equal(projection_sha,
            "8041df45ffa5e711921c9d30f742334b65e36f668bf8a004e31e26ab3f870f92")
        && hex_equal(out.request_fingerprint,
            "fa9d6c7ecb3fe1795f42119865cc24f23e702d3fb91401a21720f1776b067a37")
        && strcmp(out.attempt_id, "attempt-1") == 0
        && strcmp(out.run_identity, "run-1") == 0
        && hex_equal(out.config_sha256,
            "201e8183f9df23e133f2b8bca392eec769e13525a6d38ab4c3231d63e33a7e83"));
    CHECK(plamen_broker_v2_request_projection_validate_exact(valid_projection,
        sizeof(valid_projection) - 1U, projection_sha, commitment_bytes,
        commitment_size, commitment_sha, &out) == 0);
    commitment_bytes[commitment_size - 1U] ^= 1U;
    CHECK(plamen_broker_v2_request_projection_validate_exact(valid_projection,
        sizeof(valid_projection) - 1U, projection_sha, commitment_bytes,
        commitment_size, commitment_sha, &out) == PLAMEN_BROKER_V2_AUTH_FAILED);
    commitment_bytes[commitment_size - 1U] ^= 1U;
    projection_copy = malloc(sizeof(valid_projection));
    CHECK(projection_copy != NULL);
    memcpy(projection_copy, valid_projection, sizeof(valid_projection));
    {
        uint8_t *field = (uint8_t *)strstr((char *)projection_copy,
            "\"source_config_sha256\":\"");
        CHECK(field != NULL);
        field += strlen("\"source_config_sha256\":\"");
        field[0] = field[0] == '2' ? '3' : '2';
    }
    CHECK(plamen_broker_v2_request_projection_derive_exact(projection_copy,
        sizeof(valid_projection) - 1U, &out, commitment_bytes,
        sizeof(commitment_bytes), &commitment_size, projection_sha,
        commitment_sha) == PLAMEN_BROKER_V2_INVALID);
    free(projection_copy);
    return 0;
}

static int
test_output_protocol(void)
{
    static const uint8_t chunk[] = "chunk-data";
    struct plamen_broker_v2_commitment commitment;
    struct plamen_broker_v2_output_read read_value, decoded_read;
    struct plamen_broker_v2_output_chunk chunk_value, decoded_chunk;
    struct plamen_broker_v2_service_session_challenge challenge;
    struct plamen_broker_v2_service_session_ack ack;
    struct plamen_broker_v2_authority_bundle_binding bundle, decoded_bundle;
    struct plamen_broker_v2_operation_request operation_request,
        decoded_operation_request;
    struct plamen_broker_v2_operation_response operation_response,
        decoded_operation_response;
    struct plamen_broker_v2_operation_error operation_error,
        decoded_operation_error;
    uint8_t commitment_bytes[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    uint8_t projection_sha256[32], commitment_sha256[32], operation_key[32];
    uint8_t rpc_operation_key[32], wrong_rpc_key[32], member_capability_id[32];
    uint8_t operation_nonce[32], spec_sha256[32], launch_sha256[32];
    uint8_t prior_checkpoint[32], read_bytes[PLAMEN_BROKER_V2_OUTPUT_READ_SIZE];
    uint8_t chunk_bytes[PLAMEN_BROKER_V2_OUTPUT_CHUNK_PREFIX_SIZE
        + sizeof(chunk) - 1U];
    uint8_t bundle_bytes[PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE];
    uint8_t operation_request_bytes[PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE
        + sizeof(chunk) - 1U];
    uint8_t operation_response_bytes[
        PLAMEN_BROKER_V2_OPERATION_RESPONSE_PREFIX_SIZE + sizeof(chunk) - 1U];
    uint8_t operation_error_bytes[PLAMEN_BROKER_V2_OPERATION_ERROR_SIZE];
    size_t commitment_size = 0, chunk_size = 0, bundle_size = 0;
    size_t operation_request_size = 0, operation_response_size = 0;
    uint32_t service_deadline = 0, client_deadline = 0;
    unsigned index;

    CHECK(plamen_broker_v2_request_projection_derive_exact(valid_projection,
        sizeof(valid_projection) - 1U, &commitment, commitment_bytes,
        sizeof(commitment_bytes), &commitment_size, projection_sha256,
        commitment_sha256) == 0);
    CHECK(commitment_size == 274U);
    fill(operation_nonce, 9); fill(spec_sha256, 10); fill(launch_sha256, 11);
    fill(prior_checkpoint, 12);
    CHECK(plamen_broker_v2_derive_operation_key(&commitment,
        PLAMEN_BROKER_V2_BACKEND_OPERATION_OUTPUT_STDOUT, operation_nonce,
        spec_sha256, launch_sha256, prior_checkpoint, operation_key) == 0);
    CHECK(hex_equal(operation_key,
        "65442b742e4058ea674fadf155f220476638919b0462b691417e0c6d1ba4330f"));
    memset(operation_nonce, 0, sizeof(operation_nonce));
    CHECK(plamen_broker_v2_derive_operation_key(&commitment,
        PLAMEN_BROKER_V2_BACKEND_OPERATION_OUTPUT_STDOUT, operation_nonce,
        spec_sha256, launch_sha256, prior_checkpoint, operation_key)
        == PLAMEN_BROKER_V2_INVALID);
    fill(operation_nonce, 9);

    memset(&read_value, 0, sizeof(read_value));
    memcpy(read_value.operation_key, operation_key, 32);
    fill(read_value.exited_receipt_sha256, 13);
    read_value.stream = PLAMEN_BROKER_V2_OUTPUT_STDOUT;
    read_value.offset = 0;
    read_value.max_bytes = PLAMEN_BROKER_V2_OUTPUT_CHUNK_MAX;
    CHECK(plamen_broker_v2_output_read_encode(&read_value, read_bytes) == 0);
    CHECK(plamen_broker_v2_output_read_decode(read_bytes, sizeof(read_bytes),
        &decoded_read) == 0);
    CHECK(memcmp(&read_value, &decoded_read, sizeof(read_value)) == 0);
    CHECK(plamen_broker_v2_output_read_decode(read_bytes,
        sizeof(read_bytes) - 1U, &decoded_read) == PLAMEN_BROKER_V2_INVALID);
    read_bytes[1] = PLAMEN_BROKER_V2_VERSION + 1U;
    CHECK(plamen_broker_v2_output_read_decode(read_bytes, sizeof(read_bytes),
        &decoded_read) == PLAMEN_BROKER_V2_INVALID);
    read_bytes[0] = 0; read_bytes[1] = PLAMEN_BROKER_V2_VERSION;
    read_value.max_bytes = 0;
    CHECK(plamen_broker_v2_output_read_encode(&read_value, read_bytes)
        == PLAMEN_BROKER_V2_INVALID);
    read_value.max_bytes = PLAMEN_BROKER_V2_OUTPUT_CHUNK_MAX + 1U;
    CHECK(plamen_broker_v2_output_read_encode(&read_value, read_bytes)
        == PLAMEN_BROKER_V2_INVALID);

    memset(&chunk_value, 0, sizeof(chunk_value));
    memcpy(chunk_value.operation_key, operation_key, 32);
    fill(chunk_value.request_sha256, 14);
    fill(chunk_value.exited_receipt_sha256, 13);
    chunk_value.stream = PLAMEN_BROKER_V2_OUTPUT_STDOUT;
    chunk_value.offset = 0;
    chunk_value.length = (uint32_t)(sizeof(chunk) - 1U);
    chunk_value.eof = 1;
    CHECK(plamen_broker_v2_sha256(chunk, sizeof(chunk) - 1U,
        chunk_value.chunk_sha256) == 0);
    memcpy(chunk_value.full_stream_sha256, chunk_value.chunk_sha256, 32);
    chunk_value.full_stream_size = sizeof(chunk) - 1U;
    chunk_value.chunk = chunk;
    CHECK(plamen_broker_v2_output_chunk_encode(&chunk_value, chunk_bytes,
        sizeof(chunk_bytes), &chunk_size) == 0
        && chunk_size == sizeof(chunk_bytes));
    CHECK(plamen_broker_v2_output_chunk_decode(chunk_bytes, chunk_size,
        &decoded_chunk) == 0
        && decoded_chunk.length == sizeof(chunk) - 1U
        && decoded_chunk.eof == 1
        && memcmp(decoded_chunk.chunk, chunk, sizeof(chunk) - 1U) == 0);
    CHECK(plamen_broker_v2_output_chunk_decode(chunk_bytes, chunk_size - 1U,
        &decoded_chunk) == PLAMEN_BROKER_V2_INVALID);
    chunk_bytes[chunk_size - 1U] ^= 1U;
    CHECK(plamen_broker_v2_output_chunk_decode(chunk_bytes, chunk_size,
        &decoded_chunk) == PLAMEN_BROKER_V2_INVALID);
    chunk_bytes[chunk_size - 1U] ^= 1U;
    chunk_bytes[107] = 0; chunk_bytes[108] = 0;
    chunk_bytes[109] = 0; chunk_bytes[110] = 1;
    CHECK(plamen_broker_v2_output_chunk_decode(chunk_bytes, chunk_size,
        &decoded_chunk) == PLAMEN_BROKER_V2_INVALID);

    memset(&challenge, 0, sizeof(challenge));
    memcpy(challenge.commitment, commitment_bytes, commitment_size);
    challenge.commitment_size = (uint16_t)commitment_size;
    memcpy(challenge.commitment_sha256, commitment_sha256, 32);
    CHECK(plamen_broker_v2_auth_consume_matches_challenge(&challenge,
        commitment_bytes, commitment_size, &commitment) == 0);
    commitment_bytes[commitment_size - 1U] ^= 1U;
    CHECK(plamen_broker_v2_auth_consume_matches_challenge(&challenge,
        commitment_bytes, commitment_size, &commitment)
        == PLAMEN_BROKER_V2_AUTH_FAILED);
    commitment_bytes[commitment_size - 1U] ^= 1U;

    memset(&bundle, 0, sizeof(bundle));
    bundle.role = PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    bundle.member_count = PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT;
    fill(bundle.registration_sha256, 15);
    fill(bundle.issuance_checkpoint_sha256, 16);
    for (index = 0; index < bundle.member_count; ++index)
        fill(bundle.member_sha256[index], (uint8_t)(17U + index));
    CHECK(plamen_broker_v2_authority_bundle_binding_encode(&bundle,
        bundle_bytes, sizeof(bundle_bytes), &bundle_size) == 0);
    memset(&ack, 0, sizeof(ack));
    memcpy(ack.registration_sha256, bundle.registration_sha256, 32);
    memcpy(ack.registration_burn_checkpoint_sha256,
        bundle.issuance_checkpoint_sha256, 32);
    ack.initial_authority_role = bundle.role;
    CHECK(plamen_broker_v2_sha256(bundle_bytes, bundle_size,
        ack.authority_bundle_sha256) == 0);
    CHECK(plamen_broker_v2_auth_accepted_matches_session_ack(&ack,
        bundle_bytes, bundle_size, &decoded_bundle) == 0
        && memcmp(&decoded_bundle, &bundle, sizeof(bundle)) == 0);
    ack.authority_bundle_sha256[0] ^= 1U;
    CHECK(plamen_broker_v2_auth_accepted_matches_session_ack(&ack,
        bundle_bytes, bundle_size, &decoded_bundle)
        == PLAMEN_BROKER_V2_AUTH_FAILED);

    CHECK(plamen_broker_v2_request_projection_derive_exact(valid_projection,
        sizeof(valid_projection) - 1U, &commitment, commitment_bytes,
        sizeof(commitment_bytes), &commitment_size, projection_sha256,
        commitment_sha256) == 0);

    memset(&operation_request, 0, sizeof(operation_request));
    operation_request.authority_role = PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER;
    operation_request.member = PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION;
    operation_request.method =
        PLAMEN_BROKER_V2_METHOD_BACKEND_READ_OUTPUT_OR_RECOVER;
    operation_request.flags = PLAMEN_BROKER_V2_OPERATION_RECOVER;
    fill(member_capability_id, 29);
    memcpy(operation_request.request_fingerprint,
        commitment.request_fingerprint, 32);
    fill(operation_request.prior_checkpoint_sha256, 27);
    operation_request.payload = chunk;
    operation_request.payload_size = sizeof(chunk) - 1U;
    CHECK(plamen_broker_v2_sha256(chunk, sizeof(chunk) - 1U,
        operation_request.payload_sha256) == 0);
    CHECK(plamen_broker_v2_derive_rpc_operation_key(&commitment,
        member_capability_id, operation_request.authority_role,
        operation_request.member,
        operation_request.method, operation_request.payload_sha256,
        operation_request.prior_checkpoint_sha256, rpc_operation_key) == 0);
    CHECK(hex_equal(rpc_operation_key,
            "d7e8ed4011505947f1fdf1913dea73f1f9fd12dc5b5c99d9d03915a1bf0753fc"));
    member_capability_id[0] ^= 1U;
    CHECK(plamen_broker_v2_derive_rpc_operation_key(&commitment,
        member_capability_id, operation_request.authority_role,
        operation_request.member, operation_request.method,
        operation_request.payload_sha256,
        operation_request.prior_checkpoint_sha256, wrong_rpc_key) == 0
        && memcmp(wrong_rpc_key, rpc_operation_key, 32) != 0);
    member_capability_id[0] ^= 1U;
    CHECK(plamen_broker_v2_derive_rpc_operation_key(&commitment,
        member_capability_id, operation_request.authority_role, 2,
        operation_request.method, operation_request.payload_sha256,
        operation_request.prior_checkpoint_sha256, wrong_rpc_key)
        == PLAMEN_BROKER_V2_INVALID);
    CHECK(plamen_broker_v2_derive_rpc_operation_key(&commitment,
        member_capability_id, operation_request.authority_role,
        operation_request.member, PLAMEN_BROKER_V2_METHOD_BACKEND_WAIT_OR_RECOVER,
        operation_request.payload_sha256,
        operation_request.prior_checkpoint_sha256, wrong_rpc_key) == 0
        && memcmp(wrong_rpc_key, rpc_operation_key, 32) != 0);
    memcpy(operation_request.operation_key, rpc_operation_key, 32);
    CHECK(plamen_broker_v2_operation_request_encode(&operation_request,
        operation_request_bytes, sizeof(operation_request_bytes),
        &operation_request_size) == 0
        && operation_request_size == sizeof(operation_request_bytes));
    CHECK(plamen_broker_v2_operation_request_decode(operation_request_bytes,
        operation_request_size, &decoded_operation_request) == 0
        && decoded_operation_request.method == operation_request.method
        && decoded_operation_request.flags == operation_request.flags
        && decoded_operation_request.payload_size == sizeof(chunk) - 1U
        && memcmp(decoded_operation_request.payload, chunk,
            sizeof(chunk) - 1U) == 0);
    operation_request_bytes[operation_request_size - 1U] ^= 1U;
    CHECK(plamen_broker_v2_operation_request_decode(operation_request_bytes,
        operation_request_size, &decoded_operation_request)
        == PLAMEN_BROKER_V2_INVALID);
    operation_request_bytes[operation_request_size - 1U] ^= 1U;
    CHECK(!plamen_broker_v2_authority_method_valid(
        PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR,
        PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE,
        PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND, 0));
    CHECK(!plamen_broker_v2_authority_method_valid(
        PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER,
        PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION,
        PLAMEN_BROKER_V2_METHOD_BACKEND_PREPARE,
        PLAMEN_BROKER_V2_OPERATION_RECOVER));
    CHECK(plamen_broker_v2_authority_method_deadline(
        PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER,
        PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION,
        PLAMEN_BROKER_V2_METHOD_BACKEND_WAIT_OR_RECOVER,
        &service_deadline, &client_deadline) == 0
        && service_deadline == PLAMEN_BROKER_V2_RPC_WAIT_DEADLINE_SECONDS
        && client_deadline == PLAMEN_BROKER_V2_RPC_WAIT_DEADLINE_SECONDS
            + PLAMEN_BROKER_V2_RPC_CLIENT_GRACE_SECONDS);

    memset(&operation_response, 0, sizeof(operation_response));
    operation_response.authority_role = operation_request.authority_role;
    operation_response.member = operation_request.member;
    operation_response.method = operation_request.method;
    operation_response.disposition = PLAMEN_BROKER_V2_OPERATION_RECOVERED;
    operation_response.state = PLAMEN_BROKER_V2_OPERATION_STATE_COMMITTED;
    memcpy(operation_response.operation_key, rpc_operation_key, 32);
    CHECK(plamen_broker_v2_sha256(operation_request_bytes,
        operation_request_size, operation_response.request_sha256) == 0);
    memcpy(operation_response.prior_checkpoint_sha256,
        operation_request.prior_checkpoint_sha256, 32);
    fill(operation_response.next_checkpoint_sha256, 28);
    operation_response.payload = chunk;
    operation_response.payload_size = sizeof(chunk) - 1U;
    CHECK(plamen_broker_v2_sha256(chunk, sizeof(chunk) - 1U,
        operation_response.payload_sha256) == 0);
    CHECK(plamen_broker_v2_operation_response_encode(&operation_response,
        operation_response_bytes, sizeof(operation_response_bytes),
        &operation_response_size) == 0
        && operation_response_size == sizeof(operation_response_bytes));
    CHECK(plamen_broker_v2_operation_response_decode(operation_response_bytes,
        operation_response_size, &decoded_operation_response) == 0
        && decoded_operation_response.disposition
            == PLAMEN_BROKER_V2_OPERATION_RECOVERED
        && decoded_operation_response.state
            == PLAMEN_BROKER_V2_OPERATION_STATE_COMMITTED
        && memcmp(decoded_operation_response.payload, chunk,
            sizeof(chunk) - 1U) == 0);
    CHECK(plamen_broker_v2_operation_response_matches_request(
        operation_request_bytes, operation_request_size, &operation_request,
        &decoded_operation_response));
    operation_response_bytes[operation_response_size - 1U] ^= 1U;
    CHECK(plamen_broker_v2_operation_response_decode(operation_response_bytes,
        operation_response_size, &decoded_operation_response)
        == PLAMEN_BROKER_V2_INVALID);
    operation_response_bytes[operation_response_size - 1U] ^= 1U;

    memset(&operation_error, 0, sizeof(operation_error));
    operation_error.authority_role = operation_request.authority_role;
    operation_error.member = operation_request.member;
    operation_error.method = operation_request.method;
    operation_error.error_code = PLAMEN_BROKER_V2_SERVICE_ERR_DURABILITY;
    operation_error.flags = PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED;
    memcpy(operation_error.operation_key, rpc_operation_key, 32);
    memcpy(operation_error.request_sha256, operation_response.request_sha256, 32);
    memcpy(operation_error.current_checkpoint_sha256,
        operation_request.prior_checkpoint_sha256, 32);
    CHECK(plamen_broker_v2_operation_error_encode(&operation_error,
        operation_error_bytes) == 0);
    CHECK(plamen_broker_v2_operation_error_decode(operation_error_bytes,
        sizeof(operation_error_bytes), &decoded_operation_error) == 0
        && decoded_operation_error.error_code
            == PLAMEN_BROKER_V2_SERVICE_ERR_DURABILITY);
    CHECK(plamen_broker_v2_operation_error_matches_request(
        operation_request_bytes, operation_request_size, &operation_request,
        &decoded_operation_error));
    operation_error_bytes[10] = 0xff;
    CHECK(plamen_broker_v2_operation_error_decode(operation_error_bytes,
        sizeof(operation_error_bytes), &decoded_operation_error)
        == PLAMEN_BROKER_V2_INVALID);
    return 0;
}

static int
make_sessions(struct plamen_broker_v2_session *broker,
    struct plamen_broker_v2_session *extension, uint8_t key[32], uint8_t id[32])
{
    unsigned index;
    for (index = 0; index < 32; ++index) {
        key[index] = (uint8_t)(index + 1);
        id[index] = (uint8_t)(0xa0 + index);
    }
    CHECK(plamen_broker_v2_session_init(broker, PLAMEN_BROKER_V2_ROLE_BROKER,
        key, id) == 0);
    CHECK(plamen_broker_v2_session_init(extension, PLAMEN_BROKER_V2_ROLE_EXTENSION,
        key, id) == 0);
    return 0;
}

static int
test_protocol(void)
{
    struct plamen_broker_v2_session broker, extension, receiver;
    struct plamen_broker_v2_frame_view view;
    uint8_t key[32], id[32], other_id[32], zero[32] = {0}, nonce[32];
    uint8_t *hello = NULL, *projection_request = NULL, *projection_reply = NULL;
    uint8_t *request = NULL, *reply = NULL, *copy = NULL;
    size_t hello_size = 0, projection_request_size = 0;
    size_t projection_reply_size = 0, request_size = 0, reply_size = 0;
    const uint8_t payload[] = {1, 2, 3, 4};
    CHECK(make_sessions(&broker, &extension, key, id) == 0);
    fill(nonce, 0x55);
    CHECK(plamen_broker_v2_frame_build(&broker, PLAMEN_BROKER_V2_HELLO,
        zero, NULL, 0, 0, &hello, &hello_size) == 0);
    CHECK(hello_size == PLAMEN_BROKER_V2_HEADER_SIZE);
    CHECK(memcmp(hello, "PLMBRK2\0", 8) == 0 && hello[8] == 0 && hello[9] == 2);
    CHECK(plamen_broker_v2_frame_accept(&extension, hello, hello_size, 0, &view) == 0);
    CHECK(view.type == PLAMEN_BROKER_V2_HELLO && view.sequence == 0);
    CHECK(plamen_broker_v2_frame_build(&extension,
        PLAMEN_BROKER_V2_REQUEST_PROJECTION, zero, NULL, 0, 0,
        &projection_request, &projection_request_size) == 0);
    CHECK(plamen_broker_v2_frame_accept(&broker, projection_request,
        projection_request_size, 0, &view) == 0 && view.sequence == 1);
    CHECK(plamen_broker_v2_frame_build(&broker,
        PLAMEN_BROKER_V2_REQUEST_PROJECTED, zero, valid_projection,
        sizeof(valid_projection) - 1U, 0, &projection_reply,
        &projection_reply_size) == 0);
    CHECK(plamen_broker_v2_frame_accept(&extension, projection_reply,
        projection_reply_size, 0, &view) == 0 && view.sequence == 2);
    CHECK(plamen_broker_v2_frame_build(&extension,
        PLAMEN_BROKER_V2_AUTH_CONSUME, zero, payload, sizeof(payload), 0,
        &request, &request_size) == 0);
    CHECK(plamen_broker_v2_frame_accept(&broker, request, request_size, 0, &view) == 0);
    CHECK(view.sequence == 3 && view.payload_size == sizeof(payload));
    CHECK(plamen_broker_v2_frame_build(&broker,
        PLAMEN_BROKER_V2_AUTH_ACCEPTED, zero, payload, sizeof(payload), 0,
        &reply, &reply_size) == 0);
    CHECK(plamen_broker_v2_frame_accept(&extension, reply, reply_size, 0, &view) == 0);
    CHECK(view.sequence == 4 && extension.authenticated);

    /* A replay is terminal for that session. */
    CHECK(plamen_broker_v2_frame_accept(&broker, request, request_size, 0, &view)
        == PLAMEN_BROKER_V2_REPLAY);
    CHECK(plamen_broker_v2_frame_accept(&broker, request, request_size, 0, &view)
        == PLAMEN_BROKER_V2_BURNED);

    /* Every malformed case gets a fresh receiver and must burn it. */
    CHECK(plamen_broker_v2_session_init(&receiver, PLAMEN_BROKER_V2_ROLE_EXTENSION,
        key, id) == 0);
    CHECK(plamen_broker_v2_frame_accept(&receiver, hello, hello_size - 1, 0, &view)
        != 0 && receiver.burned);
    CHECK(plamen_broker_v2_session_init(&receiver, PLAMEN_BROKER_V2_ROLE_EXTENSION,
        key, id) == 0);
    copy = malloc(hello_size + 1); CHECK(copy != NULL);
    memcpy(copy, hello, hello_size); copy[hello_size] = 0;
    CHECK(plamen_broker_v2_frame_accept(&receiver, copy, hello_size + 1, 0, &view)
        != 0 && receiver.burned); free(copy); copy = NULL;
    CHECK(plamen_broker_v2_session_init(&receiver, PLAMEN_BROKER_V2_ROLE_EXTENSION,
        key, id) == 0);
    copy = malloc(hello_size); CHECK(copy != NULL); memcpy(copy, hello, hello_size);
    copy[12] ^= 1;
    CHECK(plamen_broker_v2_frame_accept(&receiver, copy, hello_size, 0, &view)
        != 0 && receiver.burned); free(copy); copy = NULL;
    CHECK(plamen_broker_v2_session_init(&receiver, PLAMEN_BROKER_V2_ROLE_EXTENSION,
        key, id) == 0);
    copy = malloc(hello_size); CHECK(copy != NULL); memcpy(copy, hello, hello_size);
    copy[164] ^= 1;
    CHECK(plamen_broker_v2_frame_accept(&receiver, copy, hello_size, 0, &view)
        == PLAMEN_BROKER_V2_AUTH_FAILED && receiver.burned); free(copy); copy = NULL;
    memcpy(other_id, id, 32); other_id[0] ^= 1;
    CHECK(plamen_broker_v2_session_init(&receiver, PLAMEN_BROKER_V2_ROLE_EXTENSION,
        key, other_id) == 0);
    CHECK(plamen_broker_v2_frame_accept(&receiver, hello, hello_size, 0, &view)
        != 0 && receiver.burned);

    /* Claimed and received descriptor counts are exact. */
    CHECK(plamen_broker_v2_session_init(&receiver, PLAMEN_BROKER_V2_ROLE_EXTENSION,
        key, id) == 0);
    CHECK(plamen_broker_v2_frame_accept(&receiver, hello, hello_size, 1, &view)
        != 0 && receiver.burned);

    free(hello); free(projection_request); free(projection_reply);
    free(request); free(reply);
    plamen_broker_v2_session_burn(&extension);
    CHECK(extension.burned && !memcmp(extension.key, zero, 32));
    return 0;
}

static int
write_bytes(int fd, const void *data, size_t size)
{
    return write(fd, data, size) == (ssize_t)size ? 0 : -1;
}

static int
test_fds(void)
{
    char first[] = "/tmp/plamen-v2-fd-a.XXXXXX";
    char second[] = "/tmp/plamen-v2-fd-b.XXXXXX";
    int seed_a = -1, seed_b = -1, fds[2] = {-1, -1}, alias[2] = {-1, -1};
    int service_fds[2] = {-1, -1}, peer_socket = -1, key_pipe_write = -1;
    struct plamen_broker_v2_fd_metadata metadata[2];
    int result = __LINE__;
    seed_a = mkstemp(first); seed_b = mkstemp(second);
    if (seed_a < 0 || seed_b < 0 || write_bytes(seed_a, "alpha", 5) != 0
        || write_bytes(seed_b, "beta", 4) != 0) goto done;
    close(seed_a); seed_a = -1; close(seed_b); seed_b = -1;
    if (chmod(first, 0700) != 0) goto done;
    fds[0] = open(first, O_RDONLY); fds[1] = open(second, O_RDONLY);
    if (fds[0] < 0 || fds[1] < 0) goto done;
    memset(metadata, 0, sizeof(metadata));
    metadata[0].purpose = PLAMEN_BROKER_V2_FD_APPLE_CLI_EXECUTABLE;
    metadata[0].target = 10; metadata[0].access_mode = PLAMEN_BROKER_V2_FD_READ;
    metadata[1].purpose = PLAMEN_BROKER_V2_FD_STDIN_PROMPT;
    metadata[1].target = 11; metadata[1].access_mode = PLAMEN_BROKER_V2_FD_READ;
    if (plamen_broker_v2_fd_identity(fds[0], metadata[0].identity) != 0
        || plamen_broker_v2_fd_identity(fds[1], metadata[1].identity) != 0
        || plamen_broker_v2_validate_received_fds(fds, 2, metadata, 2) != 0
        || !(fcntl(fds[0], F_GETFD) & FD_CLOEXEC)
        || !(fcntl(fds[1], F_GETFD) & FD_CLOEXEC)) goto done;
    close(fds[0]); fds[0] = -1; close(fds[1]); fds[1] = -1;

    alias[0] = open(first, O_RDONLY); alias[1] = dup(alias[0]);
    if (alias[0] < 0 || alias[1] < 0) goto done;
    if (plamen_broker_v2_fd_identity(alias[0], metadata[0].identity) != 0) goto done;
    memcpy(metadata[1].identity, metadata[0].identity, 32);
    if (plamen_broker_v2_validate_received_fds(alias, 2, metadata, 2)
        != PLAMEN_BROKER_V2_FD_INVALID || alias[0] != -1 || alias[1] != -1)
        goto done;

    fds[0] = open(first, O_RDONLY);
    if (fds[0] < 0 || plamen_broker_v2_fd_identity(fds[0], metadata[0].identity) != 0)
        goto done;
    metadata[0].access_mode = PLAMEN_BROKER_V2_FD_WRITE;
    if (plamen_broker_v2_validate_received_fds(fds, 1, metadata, 1)
        != PLAMEN_BROKER_V2_FD_INVALID || fds[0] != -1) goto done;

    {
        int sockets[2], pipe_fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
            goto done;
        service_fds[0] = sockets[0]; peer_socket = sockets[1];
        if (pipe(pipe_fds) != 0) goto done;
        service_fds[1] = pipe_fds[0]; key_pipe_write = pipe_fds[1];
        memset(metadata, 0, sizeof(metadata));
        metadata[0].purpose = PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET;
        metadata[0].target = 0;
        metadata[0].access_mode = PLAMEN_BROKER_V2_FD_READ_WRITE;
        metadata[1].purpose = PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ;
        metadata[1].target = 1;
        metadata[1].access_mode = PLAMEN_BROKER_V2_FD_READ;
        if (plamen_broker_v2_fd_identity(service_fds[0], metadata[0].identity) != 0
            || plamen_broker_v2_fd_identity(service_fds[1], metadata[1].identity) != 0
            || plamen_broker_v2_validate_received_fds(service_fds, 2,
                metadata, 2) != 0
            || !(fcntl(service_fds[0], F_GETFD) & FD_CLOEXEC)
            || !(fcntl(service_fds[1], F_GETFD) & FD_CLOEXEC))
            goto done;
        close(service_fds[0]); service_fds[0] = -1;
        close(service_fds[1]); service_fds[1] = -1;
        close(peer_socket); peer_socket = -1;
        close(key_pipe_write); key_pipe_write = -1;

        fds[0] = open(first, O_RDONLY);
        if (fds[0] < 0
            || plamen_broker_v2_fd_identity(fds[0], metadata[0].identity) != 0
            || plamen_broker_v2_validate_received_fds(fds, 1, metadata, 1)
                != PLAMEN_BROKER_V2_FD_INVALID
            || fds[0] != -1)
            goto done;
    }
    result = 0;
done:
    if (seed_a >= 0) close(seed_a);
    if (seed_b >= 0) close(seed_b);
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    if (alias[0] >= 0) close(alias[0]);
    if (alias[1] >= 0) close(alias[1]);
    if (service_fds[0] >= 0) close(service_fds[0]);
    if (service_fds[1] >= 0) close(service_fds[1]);
    if (peer_socket >= 0) close(peer_socket);
    if (key_pipe_write >= 0) close(key_pipe_write);
    unlink(first); unlink(second);
    return result;
}

static void
darwin_peer(struct plamen_broker_v2_peer_identity *peer, uint64_t pid)
{
    memset(peer, 0, sizeof(*peer));
    peer->pid = pid;
    peer->uid = 501;
    peer->gid = 20;
    peer->birth_kind = PLAMEN_BROKER_V2_BIRTH_DARWIN_EPOCH;
    peer->birth_primary = UINT64_C(1700000000);
    peer->birth_secondary = 123456000;
}

static uint16_t
registration_authority_roster(struct plamen_broker_v2_service_registration *value,
    int docs, int scope, int recovery)
{
    size_t index;
    uint16_t count = 1;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
            ++index) {
        int present = !((index == PLAMEN_BROKER_V2_RETAINED_DOCS && !docs)
            || (index == PLAMEN_BROKER_V2_RETAINED_SCOPE && !scope)
            || (index == PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT
                && !recovery));
        if (!present) continue;
        value->authority_presence_mask |= (uint16_t)(UINT16_C(1) << index);
        value->authority_descriptors[index].purpose =
            (uint16_t)(PLAMEN_BROKER_V2_FD_AUTHORITY_CONFIG + index);
        value->authority_descriptors[index].target = (uint16_t)(index + 1U);
        value->authority_descriptors[index].access_mode = PLAMEN_BROKER_V2_FD_READ;
        fill(value->authority_descriptors[index].identity,
            (uint8_t)(0x40U + index));
        ++count;
    }
    return count;
}

static int
test_service_bootstrap(void)
{
    struct plamen_broker_v2_service_readiness readiness, decoded_readiness;
    struct plamen_broker_v2_service_ready ready, decoded_ready;
    struct plamen_broker_v2_service_registration registration, decoded;
    struct plamen_broker_v2_service_registration_ack registration_ack;
    struct plamen_broker_v2_service_session_lookup lookup, decoded_lookup;
    struct plamen_broker_v2_service_session_challenge challenge,
        decoded_challenge;
    struct plamen_broker_v2_service_session_open session_open, decoded_open;
    struct plamen_broker_v2_service_session_ack session_ack;
    struct plamen_broker_v2_service_error error, decoded_error;
    struct plamen_broker_v2_service_envelope_view view;
    uint8_t readiness_bytes[PLAMEN_BROKER_V2_SERVICE_READINESS_SIZE];
    uint8_t ready_bytes[PLAMEN_BROKER_V2_SERVICE_READY_SIZE];
    uint8_t registration_bytes[PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE];
    uint8_t registration_ack_bytes[PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACK_SIZE];
    uint8_t lookup_bytes[PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE];
    uint8_t challenge_bytes[PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE];
    uint8_t session_open_bytes[PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE];
    uint8_t session_ack_bytes[PLAMEN_BROKER_V2_SERVICE_SESSION_ACK_SIZE];
    uint8_t error_bytes[PLAMEN_BROKER_V2_SERVICE_ERROR_SIZE];
    uint8_t transaction[32], invocation[32], *envelope = NULL, *forged = NULL;
    uint8_t readiness_envelope_sha256[32], lookup_envelope_sha256[32];
    uint8_t challenge_envelope_sha256[32];
    uint8_t commitment_encoded[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    uint8_t commitment_sha256[32];
    struct plamen_broker_v2_commitment commitment_value;
    size_t envelope_size = 0, commitment_size = 0;
    fill(transaction, 0x71); fill(invocation, 0x72);

    memset(&readiness, 0, sizeof(readiness));
    fill(readiness.installed_closure_sha256, 0xa1);
    fill(readiness.broker_closure_sha256, 0xa2);
    fill(readiness.installation_receipt_sha256, 0xa3);
    CHECK(plamen_broker_v2_service_readiness_encode(&readiness,
        readiness_bytes) == 0);
    CHECK(plamen_broker_v2_service_readiness_decode(readiness_bytes,
        sizeof(readiness_bytes), &decoded_readiness) == 0);
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER,
        PLAMEN_BROKER_V2_SERVICE_READINESS, transaction, invocation,
        readiness_bytes, sizeof(readiness_bytes), 0, &envelope,
        &envelope_size) == 0);
    CHECK(plamen_broker_v2_sha256(envelope, envelope_size,
        readiness_envelope_sha256) == 0);
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, envelope, envelope_size, 0,
        &view) == 0);
    free(envelope); envelope = NULL;
    memset(&ready, 0, sizeof(ready));
    memcpy(ready.request_envelope_sha256, readiness_envelope_sha256, 32);
    darwin_peer(&ready.service_peer, 99);
    memcpy(ready.installed_closure_sha256,
        readiness.installed_closure_sha256, 32);
    memcpy(ready.broker_closure_sha256, readiness.broker_closure_sha256, 32);
    memcpy(ready.installation_receipt_sha256,
        readiness.installation_receipt_sha256, 32);
    CHECK(plamen_broker_v2_service_ready_encode(&ready, ready_bytes) == 0);
    CHECK(plamen_broker_v2_service_ready_decode(ready_bytes,
        sizeof(ready_bytes), &decoded_ready) == 0);
    CHECK(plamen_broker_v2_service_ready_matches_readiness(&readiness,
        readiness_envelope_sha256, &decoded_ready));
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER,
        PLAMEN_BROKER_V2_SERVICE_READY, transaction, invocation,
        ready_bytes, sizeof(ready_bytes), 0, &envelope, &envelope_size) == 0);
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER, envelope, envelope_size, 0,
        &view) == 0);
    free(envelope); envelope = NULL;

    CHECK(make_commitment(3, commitment_encoded, &commitment_size,
        commitment_sha256, &commitment_value) == 0);
    memset(&registration, 0, sizeof(registration));
    fill(registration.installed_closure_sha256, 1);
    fill(registration.committed_audit_generation_sha256, 2);
    memcpy(registration.audit_request_fingerprint,
        commitment_value.request_fingerprint, 32);
    fill(registration.request_projection_sha256, 0x33);
    registration.request_projection_size = 4096;
    memcpy(registration.commitment_sha256, commitment_sha256, 32);
    registration.commitment_size = (uint16_t)commitment_size;
    memcpy(registration.commitment, commitment_encoded, commitment_size);
    fill(registration.python_entrypoint_sha256, 4);
    fill(registration.python_argv_sha256, 5);
    fill(registration.python_environment_sha256, 6);
    darwin_peer(&registration.launcher, 100);
    darwin_peer(&registration.suspended_child, 101);
    registration.initial_authority_role =
        PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    CHECK(registration_authority_roster(&registration, 1, 1, 0) == 14);
    CHECK(plamen_broker_v2_service_registration_encode(&registration,
        registration_bytes) == 0);
    CHECK(plamen_broker_v2_service_registration_decode(registration_bytes,
        sizeof(registration_bytes), &decoded) == 0);
    CHECK(decoded.suspended_child.pid == 101);
    decoded.initial_authority_role =
        PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION;
    CHECK(plamen_broker_v2_service_registration_encode(&decoded,
        registration_bytes) == PLAMEN_BROKER_V2_INVALID);
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER,
        PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL, transaction, invocation,
        registration_bytes, sizeof(registration_bytes), 14, &envelope,
        &envelope_size) == 0);
    CHECK(envelope_size == 124 + sizeof(registration_bytes));
    CHECK(memcmp(envelope, "PLMSVC2\0", 8) == 0);
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, envelope, envelope_size, 14,
        &view) == 0);
    CHECK(view.type == PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
        && view.payload_size == sizeof(registration_bytes));
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION, envelope, envelope_size, 14,
        &view) == PLAMEN_BROKER_V2_INVALID);
    forged = malloc(envelope_size + 1); CHECK(forged != NULL);
    memcpy(forged, envelope, envelope_size); forged[envelope_size] = 0;
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, forged, envelope_size + 1, 14,
        &view) == PLAMEN_BROKER_V2_INVALID);
    free(forged); forged = NULL; free(envelope); envelope = NULL;
    /* Initial and recovery registrations have disjoint prior-checkpoint shape. */
    fill(registration.prior_audit_checkpoint_sha256, 9);
    registration.authority_presence_mask |= (uint16_t)(UINT16_C(1)
        << PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT);
    registration.authority_descriptors[PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT].purpose =
        PLAMEN_BROKER_V2_FD_AUTHORITY_RESUME_CHECKPOINT;
    registration.authority_descriptors[PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT].target = 14;
    registration.authority_descriptors[PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT].access_mode =
        PLAMEN_BROKER_V2_FD_READ;
    fill(registration.authority_descriptors[PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT].identity,
        0x4d);
    CHECK(plamen_broker_v2_service_registration_encode(&registration,
        registration_bytes) == 0);
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER,
        PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL, transaction, invocation,
        registration_bytes, sizeof(registration_bytes), 15, &envelope,
        &envelope_size) == PLAMEN_BROKER_V2_INVALID);
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER,
        PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY, transaction, invocation,
        registration_bytes, sizeof(registration_bytes), 15, &envelope,
        &envelope_size) == 0);
    free(envelope); envelope = NULL;

    memset(&registration_ack, 0, sizeof(registration_ack));
    fill(registration_ack.request_envelope_sha256, 11);
    fill(registration_ack.registration_sha256, 12);
    fill(registration_ack.registration_checkpoint_sha256, 13);
    fill(registration_ack.broker_closure_sha256, 14);
    darwin_peer(&registration_ack.suspended_child, 101);
    registration_ack.initial_authority_role =
        PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    CHECK(plamen_broker_v2_service_registration_ack_encode(&registration_ack,
        registration_ack_bytes) == 0);
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER,
        PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACCEPTED, transaction, invocation,
        registration_ack_bytes, sizeof(registration_ack_bytes), 0, &envelope,
        &envelope_size) == 0);
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER, envelope, envelope_size, 0,
        &view) == 0);
    free(envelope); envelope = NULL;

    memset(&lookup, 0, sizeof(lookup));
    fill(lookup.extension_closure_sha256, 15);
    fill(lookup.interpreter_executable_sha256, 16);
    fill(lookup.session_id, 17);
    CHECK(plamen_broker_v2_service_session_lookup_encode(&lookup,
        lookup_bytes) == 0);
    CHECK(plamen_broker_v2_service_session_lookup_decode(lookup_bytes,
        sizeof(lookup_bytes), &decoded_lookup) == 0);
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
        PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP, transaction, invocation,
        lookup_bytes, sizeof(lookup_bytes), 0, &envelope, &envelope_size) == 0);
    CHECK(plamen_broker_v2_sha256(envelope, envelope_size,
        lookup_envelope_sha256) == 0);
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, envelope, envelope_size, 0,
        &view) == 0);
    free(envelope); envelope = NULL;

    memset(&challenge, 0, sizeof(challenge));
    memcpy(challenge.request_envelope_sha256, lookup_envelope_sha256, 32);
    fill(challenge.registration_sha256, 12);
    fill(challenge.committed_audit_generation_sha256, 2);
    fill(challenge.request_projection_sha256, 0x33);
    challenge.request_projection_size = 4096;
    memcpy(challenge.commitment_sha256, commitment_sha256, 32);
    challenge.commitment_size = (uint16_t)commitment_size;
    memcpy(challenge.commitment, commitment_encoded, commitment_size);
    fill(challenge.installed_closure_sha256, 1);
    fill(challenge.broker_closure_sha256, 14);
    fill(challenge.extension_closure_sha256, 15);
    fill(challenge.interpreter_executable_sha256, 16);
    darwin_peer(&challenge.extension_peer, 101);
    fill(challenge.session_id, 17);
    challenge.initial_authority_role =
        PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    fill(challenge.challenge_nonce, 0x73);
    CHECK(plamen_broker_v2_service_session_challenge_encode(&challenge,
        challenge_bytes) == 0);
    CHECK(plamen_broker_v2_service_session_challenge_decode(challenge_bytes,
        sizeof(challenge_bytes), &decoded_challenge) == 0);
    CHECK(plamen_broker_v2_service_session_challenge_matches_lookup(&lookup,
        lookup_envelope_sha256, &decoded_challenge));
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER,
        PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE, transaction, invocation,
        challenge_bytes, sizeof(challenge_bytes), 0, &envelope,
        &envelope_size) == 0);
    CHECK(plamen_broker_v2_sha256(envelope, envelope_size,
        challenge_envelope_sha256) == 0);
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION, envelope, envelope_size, 0,
        &view) == 0);
    free(envelope); envelope = NULL;

    memset(&session_open, 0, sizeof(session_open));
    memcpy(session_open.challenge_envelope_sha256,
        challenge_envelope_sha256, 32);
    memcpy(session_open.challenge_nonce, challenge.challenge_nonce, 32);
    memcpy(session_open.commitment_sha256, commitment_sha256, 32);
    fill(session_open.registration_sha256, 12);
    fill(session_open.committed_audit_generation_sha256, 2);
    fill(session_open.extension_closure_sha256, 15);
    fill(session_open.interpreter_executable_sha256, 16);
    darwin_peer(&session_open.extension_peer, 101);
    session_open.initial_authority_role =
        PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    fill(session_open.session_id, 17);
    session_open.descriptors[0].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET;
    session_open.descriptors[0].target = 0;
    session_open.descriptors[0].access_mode = PLAMEN_BROKER_V2_FD_READ_WRITE;
    fill(session_open.descriptors[0].identity, 18);
    session_open.descriptors[1].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ;
    session_open.descriptors[1].target = 1;
    session_open.descriptors[1].access_mode = PLAMEN_BROKER_V2_FD_READ;
    fill(session_open.descriptors[1].identity, 19);
    CHECK(plamen_broker_v2_service_session_open_encode(&session_open,
        session_open_bytes) == 0);
    CHECK(plamen_broker_v2_service_session_open_decode(session_open_bytes,
        sizeof(session_open_bytes), &decoded_open) == 0);
    CHECK(plamen_broker_v2_service_session_open_matches_challenge(&challenge,
        challenge_envelope_sha256, &decoded_open));
    CHECK(decoded_open.extension_peer.pid == 101);
    CHECK(plamen_broker_v2_service_session_open_matches_registration(
        &registration_ack, &decoded_open));
    decoded_open.initial_authority_role =
        PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION;
    CHECK(!plamen_broker_v2_service_session_open_matches_registration(
        &registration_ack, &decoded_open));
    decoded_open.initial_authority_role =
        PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
        PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN, transaction, invocation,
        session_open_bytes, sizeof(session_open_bytes), 2, &envelope,
        &envelope_size) == 0);
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, envelope, envelope_size, 2,
        &view) == 0);
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, envelope, envelope_size, 1,
        &view) == PLAMEN_BROKER_V2_INVALID);
    free(envelope); envelope = NULL;

    memset(&session_ack, 0, sizeof(session_ack));
    fill(session_ack.registration_sha256, 12);
    fill(session_ack.session_binding_sha256, 20);
    fill(session_ack.registration_burn_checkpoint_sha256, 21);
    fill(session_ack.authority_bundle_sha256, 22);
    fill(session_ack.session_id, 17);
    session_ack.initial_authority_role =
        PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    CHECK(plamen_broker_v2_service_session_ack_encode(&session_ack,
        session_ack_bytes) == 0);
    CHECK(plamen_broker_v2_service_session_ack_matches_open(
        &session_open, &session_ack));
    session_ack.initial_authority_role =
        PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION;
    CHECK(!plamen_broker_v2_service_session_ack_matches_open(
        &session_open, &session_ack));
    session_ack.initial_authority_role =
        PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER,
        PLAMEN_BROKER_V2_SERVICE_SESSION_ACCEPTED, transaction, invocation,
        session_ack_bytes, sizeof(session_ack_bytes), 0, &envelope,
        &envelope_size) == 0);
    CHECK(plamen_broker_v2_service_envelope_accept(
        PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION, envelope, envelope_size, 0,
        &view) == 0);
    free(envelope); envelope = NULL;

    memset(&error, 0, sizeof(error));
    error.code = PLAMEN_BROKER_V2_SERVICE_ERR_DURABILITY;
    error.flags = PLAMEN_BROKER_V2_SERVICE_REGISTRATION_CONSUMED
        | PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED;
    error.failed_message_type = PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN;
    fill(error.request_envelope_sha256, 23);
    CHECK(plamen_broker_v2_service_error_encode(&error, error_bytes) == 0);
    CHECK(plamen_broker_v2_service_error_decode(error_bytes,
        sizeof(error_bytes), &decoded_error) == 0);
    CHECK(decoded_error.code == error.code && decoded_error.flags == error.flags);
    CHECK(plamen_broker_v2_initial_authority_allows_frame(
        PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR,
        PLAMEN_BROKER_V2_CLI_PREPARE));
    CHECK(!plamen_broker_v2_initial_authority_allows_frame(
        PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION,
        PLAMEN_BROKER_V2_CLI_PREPARE));
    CHECK(!plamen_broker_v2_initial_authority_allows_frame(
        PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION,
        PLAMEN_BROKER_V2_AUTH_CONSUME));
    CHECK(!plamen_broker_v2_initial_authority_allows_frame(
        PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION,
        PLAMEN_BROKER_V2_START_PREPARE));
    CHECK(plamen_broker_v2_initial_authority_allows_frame(
        PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER,
        PLAMEN_BROKER_V2_START_PREPARE));
    CHECK(!plamen_broker_v2_initial_authority_allows_frame(
        PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER,
        PLAMEN_BROKER_V2_CLI_PREPARE));
    return 0;
}

static int
test_role_bindings(void)
{
    struct plamen_broker_v2_authority_bundle_binding bundle, decoded_bundle;
    struct plamen_broker_v2_backend_process_identity backend, decoded_backend;
    struct plamen_broker_v2_worker_session_open worker, decoded_worker;
    struct plamen_broker_v2_worker_session_accepted accepted, decoded_accepted;
    struct plamen_broker_v2_guest_bootstrap_record bootstrap, decoded_bootstrap;
    uint8_t bytes[PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE];
    uint8_t backend_bytes[PLAMEN_BROKER_V2_BACKEND_PROCESS_IDENTITY_SIZE];
    uint8_t worker_bytes[PLAMEN_BROKER_V2_WORKER_SESSION_OPEN_SIZE];
    uint8_t accepted_bytes[PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED_SIZE];
    uint8_t bootstrap_bytes[PLAMEN_BROKER_V2_GUEST_BOOTSTRAP_MAX_SIZE];
    uint8_t bootstrap_sha256[32];
    uint8_t parent_key[32], parent_session[32], child_key[32], changed_key[32];
    int control[2] = {-1, -1};
    size_t size = 0;
    unsigned index;
    memset(&bundle, 0, sizeof(bundle));
    bundle.role = PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    bundle.member_count = PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT;
    fill(bundle.registration_sha256, 1);
    fill(bundle.issuance_checkpoint_sha256, 2);
    for (index = 0; index < bundle.member_count; ++index)
        fill(bundle.member_sha256[index], (uint8_t)(10 + index));
    CHECK(plamen_broker_v2_authority_bundle_binding_encode(&bundle, bytes,
        sizeof(bytes), &size) == 0
        && size == PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE);
    CHECK(plamen_broker_v2_authority_bundle_binding_decode(bytes, size,
        &decoded_bundle) == 0
        && decoded_bundle.role == PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR
        && decoded_bundle.member_count
            == PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT
        && memcmp(&decoded_bundle, &bundle, sizeof(bundle)) == 0);

    memset(&bundle, 0, sizeof(bundle));
    bundle.role = PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER;
    bundle.member_count = PLAMEN_BROKER_V2_GUEST_AUTHORITY_MEMBER_COUNT;
    fill(bundle.registration_sha256, 30);
    fill(bundle.issuance_checkpoint_sha256, 31);
    fill(bundle.member_sha256[0], 32);
    CHECK(plamen_broker_v2_authority_bundle_binding_encode(&bundle, bytes,
        sizeof(bytes), &size) == 0
        && size == PLAMEN_BROKER_V2_GUEST_AUTHORITY_BUNDLE_SIZE);
    CHECK(plamen_broker_v2_authority_bundle_binding_decode(bytes, size,
        &decoded_bundle) == 0
        && memcmp(&decoded_bundle, &bundle, sizeof(bundle)) == 0);
    bundle.role = PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION;
    CHECK(plamen_broker_v2_authority_bundle_binding_encode(&bundle, bytes,
        sizeof(bytes), &size) == PLAMEN_BROKER_V2_INVALID);

    memset(&backend, 0, sizeof(backend));
    fill(backend.operation_key, 40);
    fill(backend.start_request_sha256, 41);
    fill(backend.executable_identity_sha256, 42);
    darwin_peer(&backend.peer, 202);
    fill(backend.native_process_handle_sha256, 43);
    CHECK(plamen_broker_v2_backend_process_identity_encode(&backend,
        backend_bytes) == 0);
    CHECK(plamen_broker_v2_backend_process_identity_decode(backend_bytes,
        sizeof(backend_bytes), &decoded_backend) == 0
        && memcmp(&decoded_backend, &backend, sizeof(backend)) == 0);
    backend_bytes[2] = 0;
    backend_bytes[3] = PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER;
    CHECK(plamen_broker_v2_backend_process_identity_decode(backend_bytes,
        sizeof(backend_bytes), &decoded_backend) == PLAMEN_BROKER_V2_INVALID);

    memset(&worker, 0, sizeof(worker));
    worker.authority_role = PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER;
    worker.member = PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION;
    worker.method = PLAMEN_BROKER_V2_METHOD_BACKEND_WAIT_OR_RECOVER;
    worker.flags = PLAMEN_BROKER_V2_OPERATION_RECOVER;
    fill(worker.operation_key, 50); fill(worker.request_sha256, 51);
    fill(worker.prior_checkpoint_sha256, 52); fill(worker.child_session_id, 53);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, control) == 0);
    worker.control_socket.purpose = PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET;
    worker.control_socket.target = 0;
    worker.control_socket.access_mode = PLAMEN_BROKER_V2_FD_READ_WRITE;
    CHECK(plamen_broker_v2_fd_identity(control[1],
        worker.control_socket.identity) == 0);
    CHECK(plamen_broker_v2_worker_session_open_encode(&worker, worker_bytes) == 0
        && plamen_broker_v2_worker_session_open_decode(worker_bytes,
            sizeof(worker_bytes), &decoded_worker) == 0
        && memcmp(&worker, &decoded_worker, sizeof(worker)) == 0);
    fill(parent_key, 54); fill(parent_session, 55);
    CHECK(plamen_broker_v2_worker_session_derive_key(parent_key, parent_session,
        worker.operation_key, worker.child_session_id, child_key) == 0);
    worker.operation_key[0] ^= 1U;
    CHECK(plamen_broker_v2_worker_session_derive_key(parent_key, parent_session,
        worker.operation_key, worker.child_session_id, changed_key) == 0
        && memcmp(child_key, changed_key, 32) != 0);
    worker.operation_key[0] ^= 1U;
    memset(&accepted, 0, sizeof(accepted));
    accepted.authority_role = worker.authority_role;
    accepted.member = worker.member; accepted.method = worker.method;
    accepted.status = 1; fill(accepted.request_frame_sha256, 56);
    memcpy(accepted.operation_key, worker.operation_key, 32);
    memcpy(accepted.child_session_id, worker.child_session_id, 32);
    CHECK(plamen_broker_v2_worker_session_derive_binding(parent_session, &worker,
        accepted.child_binding_sha256) == 0
        && plamen_broker_v2_worker_session_accepted_encode(&accepted,
            accepted_bytes) == 0
        && plamen_broker_v2_worker_session_accepted_decode(accepted_bytes,
            sizeof(accepted_bytes), &decoded_accepted) == 0
        && memcmp(&accepted, &decoded_accepted, sizeof(accepted)) == 0);
    accepted_bytes[10] = 1;
    CHECK(plamen_broker_v2_worker_session_accepted_decode(accepted_bytes,
        sizeof(accepted_bytes), &decoded_accepted) == PLAMEN_BROKER_V2_INVALID);

    memset(&bootstrap, 0, sizeof(bootstrap));
    memcpy(bootstrap.request_id, "request-1", sizeof("request-1"));
    memcpy(bootstrap.attempt_id, "attempt-1", sizeof("attempt-1"));
    memcpy(bootstrap.run_id, "run-1", sizeof("run-1"));
    memcpy(bootstrap.provider_guest_id, "plamen-attempt-1",
        sizeof("plamen-attempt-1"));
    fill(bootstrap.request_fingerprint, 60);
    fill(bootstrap.request_projection_sha256, 61);
    fill(bootstrap.runtime_layout_sha256, 62);
    fill(bootstrap.image_closure_sha256, 63);
    fill(bootstrap.backend_executable_identity, 64);
    fill(bootstrap.backend_profile_identity, 65);
    fill(bootstrap.credential_identity, 66);
    fill(bootstrap.egress_policy_identity, 67);
    fill(bootstrap.egress_admission_identity, 68);
    fill(bootstrap.network_closure_sha256, 69);
    fill(bootstrap.proxy_endpoint_sha256, 70);
    fill(bootstrap.session_id, 71);
    fill(bootstrap.session_key, 72);
    fill(bootstrap.one_shot_nonce, 73);
    size = 0;
    CHECK(plamen_broker_v2_guest_bootstrap_encode(&bootstrap,
        bootstrap_bytes, sizeof(bootstrap_bytes), &size,
        bootstrap_sha256) == 0);
    CHECK(size <= PLAMEN_BROKER_V2_GUEST_BOOTSTRAP_MAX_SIZE);
    CHECK(plamen_broker_v2_guest_bootstrap_decode(bootstrap_bytes, size,
        bootstrap_sha256, &decoded_bootstrap) == 0);
    CHECK(memcmp(&bootstrap, &decoded_bootstrap, sizeof(bootstrap)) == 0);
    bootstrap_bytes[24] ^= 1U;
    CHECK(plamen_broker_v2_guest_bootstrap_decode(bootstrap_bytes, size,
        bootstrap_sha256, &decoded_bootstrap) == PLAMEN_BROKER_V2_INVALID);
    bootstrap_bytes[24] ^= 1U;
    bootstrap_sha256[0] ^= 1U;
    CHECK(plamen_broker_v2_guest_bootstrap_decode(bootstrap_bytes, size,
        bootstrap_sha256, &decoded_bootstrap) == PLAMEN_BROKER_V2_INVALID);
    plamen_broker_v2_secure_zero(&decoded_bootstrap,
        sizeof(decoded_bootstrap));
    close(control[0]); close(control[1]);
    return 0;
}

static int
open_parent(const char *path)
{
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

static int
append_state(struct plamen_broker_v2_journal *journal, uint16_t state,
    uint8_t key_value, uint8_t request_value, const uint8_t previous[32],
    const char *payload, uint8_t checkpoint[32])
{
    uint8_t key[32], request[32];
    fill(key, key_value); fill(request, request_value);
    return plamen_broker_v2_journal_append(journal, state, key, request, previous,
        (const uint8_t *)payload, (uint32_t)strlen(payload), checkpoint);
}

struct replay_count { unsigned count; uint8_t last[32]; };
static int
count_visitor(const struct plamen_broker_v2_journal_record *record, void *opaque)
{
    struct replay_count *count = opaque;
    ++count->count;
    memcpy(count->last, record->checkpoint_sha256, 32);
    return 0;
}

static int
journal_lifecycle(const char *root, const char *id)
{
    int parent = -1, result = __LINE__;
    struct plamen_broker_v2_journal *journal = NULL;
    struct plamen_broker_v2_journal_record head;
    struct replay_count count = {0};
    uint8_t zero[32] = {0}, c1[32], c2[32], c3[32], c4[32], c5[32], c6[32];
    uint8_t *recovered = NULL, key[32], request[32], recovered_checkpoint[32];
    uint32_t recovered_size = 0;
    parent = open_parent(root); if (parent < 0) goto done;
    if (plamen_broker_v2_journal_open(parent, id, &journal) != 0) goto done;
    if (append_state(journal, PLAMEN_BROKER_V2_JOURNAL_PREPARED, 1, 2,
            zero, "prepared", c1) != 0
        || append_state(journal, PLAMEN_BROKER_V2_JOURNAL_STARTED, 1, 2,
            c1, "started", c2) != 0
        || append_state(journal, PLAMEN_BROKER_V2_JOURNAL_WAIT_PREPARED, 3, 4,
            c2, "wait-prepared", c3) != 0
        || append_state(journal, PLAMEN_BROKER_V2_JOURNAL_EXITED, 3, 4,
            c3, "exact-exit", c4) != 0
        || append_state(journal, PLAMEN_BROKER_V2_JOURNAL_REVOKE_PREPARED, 5, 6,
            c4, "revoke-prepared", c5) != 0
        || append_state(journal, PLAMEN_BROKER_V2_JOURNAL_REVOKED, 5, 6,
            c5, "revoked", c6) != 0) goto done;
    /* ACK loss: the exact terminal record replays byte-identically. */
    {
        uint8_t again[32];
        if (append_state(journal, PLAMEN_BROKER_V2_JOURNAL_REVOKED, 5, 6,
                c5, "revoked", again) != 0 || memcmp(again, c6, 32) != 0)
            goto done;
    }
    if (plamen_broker_v2_journal_replay(journal, count_visitor, &count, &head) != 0
        || count.count != 6 || head.sequence != 6 || head.state != 6
        || memcmp(head.checkpoint_sha256, c6, 32) != 0
        || memcmp(count.last, c6, 32) != 0) goto done;
    fill(key, 3); fill(request, 4);
    if (plamen_broker_v2_journal_recover(journal,
            PLAMEN_BROKER_V2_JOURNAL_EXITED, key, request, &recovered,
            &recovered_size, recovered_checkpoint) != 0
        || recovered_size != strlen("exact-exit")
        || memcmp(recovered, "exact-exit", recovered_size) != 0
        || memcmp(recovered_checkpoint, c4, 32) != 0) goto done;
    result = 0;
done:
    if (recovered != NULL) { plamen_broker_v2_secure_zero(recovered, recovered_size); free(recovered); }
    plamen_broker_v2_journal_close(journal);
    if (parent >= 0) close(parent);
    return result;
}

static int
journal_prepared(const char *root, const char *id, const char *payload)
{
    int parent = open_parent(root), result;
    struct plamen_broker_v2_journal *journal = NULL;
    uint8_t zero[32] = {0}, checkpoint[32];
    if (parent < 0) return __LINE__;
    result = plamen_broker_v2_journal_open(parent, id, &journal);
    if (result == 0)
        result = append_state(journal, PLAMEN_BROKER_V2_JOURNAL_PREPARED,
            1, 2, zero, payload, checkpoint);
    plamen_broker_v2_journal_close(journal); close(parent);
    if (result == 0) return 0;
    if (result == PLAMEN_BROKER_V2_CONFLICT) return 3;
    return 4;
}

static int
journal_replay_only(const char *root, const char *id)
{
    int parent = open_parent(root), result;
    struct plamen_broker_v2_journal *journal = NULL;
    struct plamen_broker_v2_journal_record head;
    if (parent < 0) return 4;
    result = plamen_broker_v2_journal_open(parent, id, &journal);
    if (result == 0) result = plamen_broker_v2_journal_replay(journal,
        NULL, NULL, &head);
    plamen_broker_v2_journal_close(journal); close(parent);
    return result == PLAMEN_BROKER_V2_CORRUPT ? 10 : result == 0 ? 0 : 4;
}

#ifdef __linux__
static int
linux_service_pair(int pair[2])
{
    int enabled = 1;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0)
        return -1;
    if (setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED, &enabled,
            sizeof(enabled)) != 0) {
        close(pair[0]); close(pair[1]); pair[0] = pair[1] = -1;
        return -1;
    }
    return 0;
}

static void
linux_test_peer(struct plamen_broker_v2_peer_identity *peer)
{
    memset(peer, 0, sizeof(*peer));
    peer->pid = (uint64_t)getpid();
    peer->uid = (uint64_t)geteuid();
    peer->gid = (uint64_t)getegid();
    peer->birth_kind = PLAMEN_BROKER_V2_BIRTH_LINUX_BOOT_TICKS;
    peer->birth_primary = 1;
    peer->birth_secondary = 100;
    fill(peer->boot_id_sha256, 0x45);
}

static int
linux_projection_fd(const uint8_t *projection, size_t size)
{
    char path[64];
    int writable = -1, readonly = -1;
    ssize_t amount;
    writable = memfd_create("plamen-projection-test",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (writable < 0) return -1;
    do { amount = write(writable, projection, size); }
    while (amount < 0 && errno == EINTR);
    if (amount != (ssize_t)size
        || fcntl(writable, F_ADD_SEALS,
            F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0
        || snprintf(path, sizeof(path), "/proc/self/fd/%d", writable) <= 0) {
        close(writable); return -1;
    }
    readonly = open(path, O_RDONLY | O_CLOEXEC);
    close(writable);
    return readonly;
}

static int
test_linux_service_transport(void)
{
    static const uint8_t projection[] =
        "{\"audit_request\":{},\"projection_schema\":"
        "\"plamen.native_audit_request_projection.v1\"}";
    struct plamen_broker_v2_peer_identity admitted;
    struct plamen_broker_v2_service_envelope_view view;
    struct plamen_broker_v2_service_readiness readiness;
    struct plamen_broker_v2_service_registration registration;
    struct plamen_broker_v2_service_session_open session_request;
    struct plamen_broker_v2_commitment commitment_value;
    uint8_t expected[32], wrong[32], payload[PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE];
    uint8_t transaction[32], invocation[32], *out = NULL, *received = NULL;
    uint8_t commitment_encoded[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    uint8_t commitment_sha256[32];
    size_t out_size = 0, received_size = 0, received_count = 0,
        commitment_size = 0;
    int pair[2] = {-1, -1}, control[2] = {-1, -1}, key_pipe[2] = {-1, -1};
    int sent[PLAMEN_BROKER_V2_SERVICE_MAX_FDS] = {-1, -1};
    int received_fds[PLAMEN_BROKER_V2_SERVICE_MAX_FDS] = {-1, -1};
    int executable = -1, projection_fd = -1, pidfd = -1;
    executable = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    CHECK(executable >= 0
        && plamen_broker_v2_fd_identity(executable, expected) == 0);
    close(executable); executable = -1;
    CHECK(linux_service_pair(pair) == 0);
    CHECK(plamen_broker_v2_linux_peer_admit(pair[1], expected, &admitted,
        &pidfd) == 0);
    CHECK(admitted.pid == (uint64_t)getpid() && admitted.uid == (uint64_t)geteuid()
        && admitted.gid == (uint64_t)getegid() && pidfd >= 0);
    close(pidfd); pidfd = -1;
    memcpy(wrong, expected, 32); wrong[0] ^= 1;
    CHECK(plamen_broker_v2_linux_peer_admit(pair[1], wrong, &admitted,
        &pidfd) == PLAMEN_BROKER_V2_AUTH_FAILED && pidfd == -1
        && admitted.pid == 0);
    close(pair[0]); close(pair[1]); pair[0] = pair[1] = -1;

    fill(transaction, 0x81); fill(invocation, 0x82);
    memset(&readiness, 0, sizeof(readiness));
    fill(readiness.installed_closure_sha256, 1);
    fill(readiness.broker_closure_sha256, 2);
    fill(readiness.installation_receipt_sha256, 3);
    CHECK(plamen_broker_v2_service_readiness_encode(&readiness, payload) == 0);
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER,
        PLAMEN_BROKER_V2_SERVICE_READINESS, transaction, invocation, payload,
        PLAMEN_BROKER_V2_SERVICE_READINESS_SIZE, 0, &out, &out_size) == 0);
    CHECK(linux_service_pair(pair) == 0);
    CHECK(plamen_broker_v2_linux_service_send_owned(pair[0], out, out_size,
        sent, 0) == 0);
    CHECK(plamen_broker_v2_linux_service_receive(pair[1],
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, &received, &received_size,
        received_fds, &received_count, &view) == 0
        && view.type == PLAMEN_BROKER_V2_SERVICE_READINESS
        && received_count == 0 && received_size == out_size);
    free(out); out = NULL; free(received); received = NULL;
    close(pair[0]); close(pair[1]); pair[0] = pair[1] = -1;

    CHECK(make_commitment(6, commitment_encoded, &commitment_size,
        commitment_sha256, &commitment_value) == 0);
    memset(&registration, 0, sizeof(registration));
    fill(registration.installed_closure_sha256, 4);
    fill(registration.committed_audit_generation_sha256, 5);
    memcpy(registration.audit_request_fingerprint,
        commitment_value.request_fingerprint, 32);
    CHECK(plamen_broker_v2_sha256(projection, sizeof(projection) - 1,
        registration.request_projection_sha256) == 0);
    registration.request_projection_size = sizeof(projection) - 1;
    memcpy(registration.commitment_sha256, commitment_sha256, 32);
    registration.commitment_size = (uint16_t)commitment_size;
    memcpy(registration.commitment, commitment_encoded, commitment_size);
    fill(registration.python_entrypoint_sha256, 7);
    fill(registration.python_argv_sha256, 8);
    fill(registration.python_environment_sha256, 9);
    linux_test_peer(&registration.launcher);
    linux_test_peer(&registration.suspended_child);
    registration.suspended_child.pid++;
    registration.initial_authority_role = PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER;
    CHECK(plamen_broker_v2_service_registration_encode(&registration,
        payload) == 0);
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER,
        PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL, transaction, invocation,
        payload, sizeof(payload), 1, &out, &out_size) == 0);
    projection_fd = linux_projection_fd(projection, sizeof(projection) - 1);
    CHECK(projection_fd >= 0 && linux_service_pair(pair) == 0);
    sent[0] = projection_fd; projection_fd = -1;
    CHECK(plamen_broker_v2_linux_service_send_owned(pair[0], out, out_size,
        sent, 1) == 0 && sent[0] == -1);
    CHECK(plamen_broker_v2_linux_service_receive(pair[1],
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, &received, &received_size,
        received_fds, &received_count, &view) == 0
        && received_count == 1);
    plamen_broker_v2_close_fds(received_fds, received_count);
    free(out); out = NULL; free(received); received = NULL;
    close(pair[0]); close(pair[1]); pair[0] = pair[1] = -1;

    memset(&session_request, 0, sizeof(session_request));
    fill(session_request.challenge_envelope_sha256, 10);
    fill(session_request.challenge_nonce, 11);
    memcpy(session_request.commitment_sha256, commitment_sha256, 32);
    fill(session_request.registration_sha256, 12);
    fill(session_request.committed_audit_generation_sha256, 13);
    fill(session_request.extension_closure_sha256, 14);
    fill(session_request.interpreter_executable_sha256, 15);
    linux_test_peer(&session_request.extension_peer);
    session_request.initial_authority_role =
        PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER;
    fill(session_request.session_id, 16);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, control) == 0
        && pipe2(key_pipe, O_CLOEXEC) == 0);
    session_request.descriptors[0].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET;
    session_request.descriptors[0].target = 0;
    session_request.descriptors[0].access_mode =
        PLAMEN_BROKER_V2_FD_READ_WRITE;
    CHECK(plamen_broker_v2_fd_identity(control[1],
        session_request.descriptors[0].identity) == 0);
    session_request.descriptors[1].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ;
    session_request.descriptors[1].target = 1;
    session_request.descriptors[1].access_mode = PLAMEN_BROKER_V2_FD_READ;
    CHECK(plamen_broker_v2_fd_identity(key_pipe[0],
        session_request.descriptors[1].identity) == 0);
    CHECK(plamen_broker_v2_service_session_open_encode(&session_request,
        payload) == 0);
    CHECK(plamen_broker_v2_service_envelope_build(
        PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
        PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN, transaction, invocation, payload,
        PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE, 2, &out, &out_size) == 0);
    CHECK(linux_service_pair(pair) == 0);
    sent[0] = control[1]; control[1] = -1;
    sent[1] = key_pipe[0]; key_pipe[0] = -1;
    CHECK(plamen_broker_v2_linux_service_send_owned(pair[0], out, out_size,
        sent, 2) == 0 && sent[0] == -1 && sent[1] == -1);
    CHECK(plamen_broker_v2_linux_service_receive(pair[1],
        PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, &received, &received_size,
        received_fds, &received_count, &view) == 0
        && received_count == 2);
    plamen_broker_v2_close_fds(received_fds, received_count);
    free(out); free(received);
    close(pair[0]); close(pair[1]); close(control[0]); close(key_pipe[1]);
    return 0;
}
#endif

static int
decode_hex_digest(const char *text, uint8_t out[32])
{
    size_t index;
    if (text == NULL || strlen(text) != 64U) return -1;
    for (index = 0; index < 32U; ++index) {
        unsigned high, low;
        char first = text[index * 2U], second = text[index * 2U + 1U];
        if (first >= '0' && first <= '9') high = (unsigned)(first - '0');
        else if (first >= 'a' && first <= 'f') high = (unsigned)(first - 'a' + 10);
        else return -1;
        if (second >= '0' && second <= '9') low = (unsigned)(second - '0');
        else if (second >= 'a' && second <= 'f') low = (unsigned)(second - 'a' + 10);
        else return -1;
        out[index] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int
bytes_contains(const uint8_t *data, size_t size, const char *wanted)
{
    size_t index, wanted_size = strlen(wanted);
    if (wanted_size > size) return 0;
    for (index = 0; index <= size - wanted_size; ++index)
        if (memcmp(data + index, wanted, wanted_size) == 0) return 1;
    return 0;
}

static int
projection_builder_cli(int argc, char **argv)
{
    struct plamen_broker_v2_projection_discovery discovery;
    struct plamen_broker_v2_projection_builder_inputs input;
    struct plamen_broker_v2_projection_builder_result result;
    struct plamen_broker_v2_service_registration registration;
    int fds[12], status = 1;
    size_t index;
    uint16_t registration_fd_count = 0;
    if (argc != 16) return 64;
    memset(&discovery, 0, sizeof(discovery));
    memset(&input, 0, sizeof(input));
    memset(&result, 0, sizeof(result));
    memset(&registration, 0, sizeof(registration));
    for (index = 0; index < sizeof(fds) / sizeof(fds[0]); ++index) fds[index] = -1;
    fds[0] = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    fds[1] = open(argv[3], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY);
    fds[2] = open(argv[4], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    fds[3] = open(argv[5], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY);
    for (index = 4; index < sizeof(fds) / sizeof(fds[0]); ++index)
        fds[index] = open(argv[index + 2U], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    for (index = 0; index < sizeof(fds) / sizeof(fds[0]); ++index)
        if (fds[index] < 0) goto done;
    if (decode_hex_digest(argv[14], input.expected_role5_schema_sha256) != 0
        || decode_hex_digest(argv[15], input.expected_runtime_manifest_sha256) != 0
        || plamen_broker_v2_projection_discover_config(
            PLAMEN_BROKER_V2_STARTUP_START_NEW_RUN, argv[2], fds[0],
            &discovery) != 0)
        goto done;
    input.startup_intent = PLAMEN_BROKER_V2_STARTUP_START_NEW_RUN;
    input.config_path = argv[2]; input.config_fd = fds[0];
    input.discovery = &discovery;
    input.target_root_fd = fds[1]; input.docs_root_fd = fds[2];
    input.scope_fd = -1; input.export_root_fd = fds[3];
    input.role5_schema_fd = fds[4]; input.runtime_manifest_fd = fds[5];
    input.provider_executable_fd = fds[6]; input.backend_executable_fd = fds[7];
    input.backend_profile_fd = fds[8]; input.credential_source_fd = fds[9];
    input.egress_policy_fd = fds[10]; input.egress_admission_fd = fds[11];
    input.resume_checkpoint_fd = -1;
    if (plamen_broker_v2_projection_build_from_retained(&input, &result) != 0
        || plamen_broker_v2_projection_builder_revalidate(&result) != 0
        || !bytes_contains(result.guest_config, result.guest_config_size,
            "\"project_root\":\"/workspace/project\"")
        || !bytes_contains(result.guest_config, result.guest_config_size,
            "\"docs_path\":\"/workspace/docs\"")
        || !bytes_contains(result.request_projection,
            result.request_projection_size,
            "\"projection_schema\":\"plamen.native_audit_request_projection.v1\"")
        || plamen_broker_v2_projection_registration_roster(&result,
            &registration) != 0
        || plamen_broker_v2_service_registration_fd_count(&registration,
            &registration_fd_count) != 0
        || registration_fd_count != 13U)
        goto done;
    status = 0;
done:
    plamen_broker_v2_projection_builder_result_destroy(&result);
    plamen_broker_v2_projection_discovery_destroy(&discovery);
    for (index = 0; index < sizeof(fds) / sizeof(fds[0]); ++index)
        if (fds[index] >= 0) close(fds[index]);
    return status;
}

int
main(int argc, char **argv)
{
    int result;
    if (argc == 2 && strcmp(argv[1], "selftest") == 0) {
        if ((result = test_crypto()) != 0 || (result = test_payloads()) != 0
            || (result = test_output_protocol()) != 0
            || (result = test_protocol()) != 0 || (result = test_fds()) != 0
            || (result = test_service_bootstrap()) != 0
            || (result = test_role_bindings()) != 0
#ifdef __linux__
            || (result = test_linux_service_transport()) != 0
#endif
            ) {
            fprintf(stderr, "TEST_ONLY core failure at %d\n", result);
            return 1;
        }
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "journal-lifecycle") == 0)
        return journal_lifecycle(argv[2], argv[3]) == 0 ? 0 : 1;
    if (argc == 5 && strcmp(argv[1], "journal-prepared") == 0)
        return journal_prepared(argv[2], argv[3], argv[4]);
    if (argc == 4 && strcmp(argv[1], "journal-replay") == 0)
        return journal_replay_only(argv[2], argv[3]);
    if (argc >= 2 && strcmp(argv[1], "projection-builder") == 0)
        return projection_builder_cli(argc, argv);
    return 64;
}
