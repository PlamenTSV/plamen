#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "../include/plamen_broker_v2.h"
#include "../darwin/plamen_broker_v2_workspace_effects.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(value) do { if (!(value)) return __LINE__; } while (0)

static void
put_u16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8); out[1] = (uint8_t)value;
}

static void
put_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24); out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8); out[3] = (uint8_t)value;
}

static void
put_u64(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)(value >> 56); out[1] = (uint8_t)(value >> 48);
    out[2] = (uint8_t)(value >> 40); out[3] = (uint8_t)(value >> 32);
    out[4] = (uint8_t)(value >> 24); out[5] = (uint8_t)(value >> 16);
    out[6] = (uint8_t)(value >> 8); out[7] = (uint8_t)value;
}

static void
hex_digest(const uint8_t digest[32], char out[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32U; ++index) {
        out[index * 2U] = digits[digest[index] >> 4];
        out[index * 2U + 1U] = digits[digest[index] & 15U];
    }
    out[64] = '\0';
}

static int
write_file(const char *path, const void *bytes, size_t size, mode_t mode)
{
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    ssize_t amount;
    if (descriptor < 0) return -1;
    amount = write(descriptor, bytes, size);
    if (amount != (ssize_t)size || fsync(descriptor) != 0
        || close(descriptor) != 0)
        return -1;
    return 0;
}

static int
make_profile(const char *path, const void *provider, size_t provider_size,
    const void *backend, size_t backend_size, uint8_t sha[32])
{
    static const struct {
        size_t offset;
        const char *value;
    } fields[] = {
        {256U, "com.apple.container.cli"},
        {384U, "UPBK2H6LZM"},
        {512U, "container CLI version 1.3.1"},
        {640U, "codex"},
        {768U, "2DC432GLL2"},
        {896U, "codex-cli 0.153.4"},
        {1024U, "0.153.4-aarch64-apple-darwin"},
        {1280U, "codex"},
        {1312U, "apple-container-v2"}
    };
    uint8_t bytes[2048], digest[32];
    size_t index;
    memset(bytes, 0, sizeof(bytes));
    memcpy(bytes, "PLMBPF2\0", 8);
    put_u16(bytes + 8, 2); put_u16(bytes + 10, 256);
    put_u32(bytes + 12, (uint32_t)sizeof(bytes)); put_u32(bytes + 16, 1);
    if (plamen_broker_v2_sha256(provider, provider_size, bytes + 32) != 0
        || plamen_broker_v2_sha256(backend, backend_size, bytes + 64) != 0)
        return -1;
    memset(bytes + 96, 'p', 20); memset(bytes + 128, 'b', 20);
    put_u16(bytes + 160, 20); put_u16(bytes + 162, 20);
    for (index = 0; index < sizeof(fields) / sizeof(fields[0]); ++index) {
        size_t size = strlen(fields[index].value);
        put_u16(bytes + 164U + index * 2U, (uint16_t)size);
        memcpy(bytes + fields[index].offset, fields[index].value, size);
    }
    if (plamen_broker_v2_sha256(bytes, 2016U, digest) != 0) return -1;
    memcpy(bytes + 2016U, digest, sizeof(digest));
    if (plamen_broker_v2_sha256(bytes, sizeof(bytes), sha) != 0
        || write_file(path, bytes, sizeof(bytes), 0400) != 0)
        return -1;
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return 0;
}

static int
make_runtime(const char *path, const uint8_t profile_sha[32], uint8_t sha[32])
{
    const size_t body_size = 256U + 2048U + 640U;
    const size_t total_size = body_size + 32U;
    const char image[] = "registry.invalid/plamen@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char init[] = "/usr/local/libexec/plamen-guest";
    uint8_t *bytes = calloc(1, total_size);
    uint8_t digest[32];
    size_t index;
    int status = -1;
    if (bytes == NULL) return -1;
    memcpy(bytes, "PLMRPM2\0", 8);
    put_u16(bytes + 8, 2); put_u16(bytes + 10, 256);
    put_u32(bytes + 12, (uint32_t)total_size);
    put_u32(bytes + 16, 640); put_u32(bytes + 20, 1);
    put_u32(bytes + 64, 2048); put_u32(bytes + 68, 14);
    memcpy(bytes + 160, "lib/plamen/runtime", 18);
    memcpy(bytes + 256, "PLMRPB2\0", 8);
    put_u16(bytes + 264, 2); put_u16(bytes + 266, 2048);
    put_u16(bytes + 268, 1); put_u16(bytes + 270, 2);
    put_u16(bytes + 272, (uint16_t)(sizeof(image) - 1U));
    put_u16(bytes + 274, (uint16_t)(sizeof(init) - 1U));
    put_u16(bytes + 276, 14); put_u16(bytes + 278, 1);
    {
        static const uint8_t kat[32] = {
            0xcb,0xec,0x56,0xec,0xf9,0x48,0x5c,0xc1,
            0xca,0x05,0xd2,0xfa,0xa0,0x9e,0xa6,0x15,
            0x75,0xe9,0xde,0xff,0xd7,0x36,0xfd,0x1a,
            0xd8,0xe4,0x11,0xa1,0x86,0x29,0xff,0xbe
        };
        memcpy(bytes + 288, kat, 32);
    }
    for (index = 0; index < 14U; ++index) {
        char value[32];
        int count = snprintf(value, sizeof(value), "role8-binding-%zu", index);
        if (count <= 0 || plamen_broker_v2_sha256(value, (size_t)count,
                bytes + 320U + index * 32U) != 0)
            goto done;
    }
    memcpy(bytes + 768, image, sizeof(image) - 1U);
    memcpy(bytes + 1280, init, sizeof(init) - 1U);
    put_u16(bytes + 2304, 2); put_u16(bytes + 2306, 21);
    put_u32(bytes + 2308, 0400); put_u64(bytes + 2312, 2048);
    put_u32(bytes + 2320, 1); put_u16(bytes + 2324, 2);
    put_u16(bytes + 2326, 0); memcpy(bytes + 2328, profile_sha, 32);
    memcpy(bytes + 2360, "profiles/codex-v2.bin", 21);
    if (plamen_broker_v2_sha256(bytes, body_size, digest) != 0) goto done;
    memcpy(bytes + body_size, digest, 32);
    if (plamen_broker_v2_sha256(bytes, total_size, sha) != 0
        || write_file(path, bytes, total_size, 0600) != 0)
        goto done;
    status = 0;
done:
    plamen_broker_v2_secure_zero(bytes, total_size); free(bytes);
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    return status;
}

static int
open_read(const char *path, int directory)
{
    return open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW
        | (directory ? O_DIRECTORY : 0));
}

static int
derive_guest_commitment(const uint8_t *config, size_t config_size,
    const char *sha, const char *source_handle, uint8_t output[32])
{
    static const char digits[] = "0123456789abcdef";
    const char *prefix = "{\"canonical_bytes\":{\"$bytes_hex\":\"";
    const char *middle = "\"},\"config_sha256\":\"";
    const char *next = "\",\"retained_source_handle\":\"";
    const char *suffix = "\"}\n";
    size_t size = strlen(prefix) + config_size * 2U + strlen(middle) + 64U
        + strlen(next) + 71U + strlen(suffix), offset = 0, index;
    uint8_t *value = malloc(size);
    if (value == NULL) return -1;
#define APPEND(text) do { size_t n = strlen(text); memcpy(value + offset, text, n); offset += n; } while (0)
    APPEND(prefix);
    for (index = 0; index < config_size; ++index) {
        value[offset++] = (uint8_t)digits[config[index] >> 4];
        value[offset++] = (uint8_t)digits[config[index] & 15U];
    }
    APPEND(middle); APPEND(sha); APPEND(next); APPEND(source_handle); APPEND(suffix);
#undef APPEND
    if (offset != size || plamen_broker_v2_sha256(value, size, output) != 0) {
        free(value); return -1;
    }
    free(value); return 0;
}

static int
exercise(const char *root)
{
    struct plamen_broker_v2_projection_discovery discovery;
    struct plamen_broker_v2_projection_builder_inputs input;
    struct plamen_broker_v2_projection_builder_result built;
    struct plamen_broker_v2_service_registration registration;
    struct plamen_broker_v2_commitment commitment;
    struct plamen_broker_v2_workspace_effects_open workspace_open;
    struct plamen_broker_v2_workspace_effects_context *workspace = NULL;
    struct plamen_broker_v2_operations_effect_request request;
    struct plamen_broker_v2_operations_effect_result result;
    struct plamen_broker_v2_operations_argument arguments[7];
    char project[PATH_MAX], target[PATH_MAX], scratch[PATH_MAX];
    char config_path[PATH_MAX], docs[PATH_MAX], export_path[PATH_MAX];
    char state[PATH_MAX], generation[PATH_MAX], generation_lib[PATH_MAX];
    char generation_plamen[PATH_MAX], generation_runtime[PATH_MAX];
    char generation_scripts[PATH_MAX], file_path[PATH_MAX], inputs[8][PATH_MAX];
    char config[PATH_MAX * 4U], source_sha[65], source_handle[72];
    uint8_t role5_sha[32], runtime_sha[32], guest_commitment[32];
    uint8_t config_sha[32], profile_sha[32], policy_sha[32];
    uint8_t target_receipt[32], layout_receipt[32], config_receipt[32];
    uint8_t precreate_recensus_commitment[32];
    uint8_t precreate_provider_mounts_sha256[32];
    uint8_t allowed_delta_sha256[32];
    uint8_t *precreate_recensus = NULL;
    size_t precreate_recensus_size = 0;
    uint8_t encoded[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    size_t encoded_size = 0, index;
    int fds[12], state_fd = -1, generation_fd = -1;
    int merged_fd, config_fd, status = 1;
    const char *names[] = { "role5", "runtime", "provider", "backend",
        "profile", "credential", "egress-policy", "egress-admission" };
    static const char provider[] = "provider executable";
    static const char backend[] = "backend executable";
    memset(&discovery, 0, sizeof(discovery)); memset(&input, 0, sizeof(input));
    memset(&built, 0, sizeof(built)); memset(&registration, 0, sizeof(registration));
    memset(&commitment, 0, sizeof(commitment)); memset(&workspace_open, 0, sizeof(workspace_open));
    for (index = 0; index < 12U; ++index) fds[index] = -1;
    CHECK(snprintf(project, sizeof(project), "%s/project", root) > 0);
    CHECK(snprintf(target, sizeof(target), "%s/code", project) > 0);
    CHECK(snprintf(scratch, sizeof(scratch), "%s/.scratchpad", project) > 0);
    CHECK(snprintf(config_path, sizeof(config_path), "%s/config.json", scratch) > 0);
    CHECK(snprintf(docs, sizeof(docs), "%s/docs", root) > 0);
    CHECK(snprintf(export_path, sizeof(export_path), "%s/export", root) > 0);
    CHECK(snprintf(state, sizeof(state), "%s/state", root) > 0);
    CHECK(snprintf(generation, sizeof(generation), "%s/generation", root) > 0);
    CHECK(snprintf(generation_lib, sizeof(generation_lib), "%s/lib", generation) > 0);
    CHECK(snprintf(generation_plamen, sizeof(generation_plamen), "%s/plamen",
        generation_lib) > 0);
    CHECK(snprintf(generation_runtime, sizeof(generation_runtime), "%s/runtime",
        generation_plamen) > 0);
    CHECK(snprintf(generation_scripts, sizeof(generation_scripts), "%s/scripts",
        generation_runtime) > 0);
    CHECK(mkdir(project, 0700) == 0 && mkdir(target, 0700) == 0
        && mkdir(scratch, 0700) == 0 && mkdir(docs, 0700) == 0
        && mkdir(export_path, 0700) == 0 && mkdir(state, 0700) == 0
        && mkdir(generation, 0700) == 0 && mkdir(generation_lib, 0700) == 0
        && mkdir(generation_plamen, 0700) == 0
        && mkdir(generation_runtime, 0700) == 0
        && mkdir(generation_scripts, 0700) == 0);
    CHECK(snprintf(file_path, sizeof(file_path), "%s/plamen_driver.py",
        generation_scripts) > 0);
    CHECK(write_file(file_path, "# native retained driver\n", 25, 0500) == 0);
    CHECK(snprintf(file_path, sizeof(file_path), "%s/Main.sol", target) > 0);
    CHECK(write_file(file_path, "contract Main {}\n", 17, 0600) == 0);
    CHECK(snprintf(file_path, sizeof(file_path), "%s/README.md", docs) > 0);
    CHECK(write_file(file_path, "# docs\n", 7, 0600) == 0);
    CHECK(snprintf(config, sizeof(config),
        "{\"project_root\":\"%s\",\"scratchpad\":\"%s\",\"docs_path\":\"%s\",\"scope_file\":null,\"pipeline\":\"sc\",\"mode\":\"core\",\"cli_backend\":\"codex\",\"language\":\"evm\",\"docs_inputs\":null}\n",
        project, scratch, docs) > 0);
    CHECK(write_file(config_path, config, strlen(config), 0600) == 0);
    for (index = 0; index < 8U; ++index) {
        CHECK(snprintf(inputs[index], sizeof(inputs[index]), "%s/%s", root,
            names[index]) > 0);
    }
    CHECK(write_file(inputs[0], names[0], strlen(names[0]), 0600) == 0);
    CHECK(write_file(inputs[2], provider, sizeof(provider) - 1U, 0700) == 0);
    CHECK(write_file(inputs[3], backend, sizeof(backend) - 1U, 0700) == 0);
    CHECK(make_profile(inputs[4], provider, sizeof(provider) - 1U,
        backend, sizeof(backend) - 1U, profile_sha) == 0);
    CHECK(make_runtime(inputs[1], profile_sha, runtime_sha) == 0);
    CHECK(write_file(inputs[5], names[5], strlen(names[5]), 0600) == 0);
    CHECK(plamen_broker_v2_sha256(config, strlen(config), config_sha) == 0);
    {
        char config_hex[65], profile_hex[65], policy_hex[65];
        char provider_hex[65], backend_hex[65], policy[512], admission[512];
        uint8_t digest[32];
        int count;
        hex_digest(config_sha, config_hex); hex_digest(profile_sha, profile_hex);
        count = snprintf(policy, sizeof(policy),
            "{\"backend\":\"codex\",\"config_sha256\":\"%s\","
            "\"network_mode\":\"NARROW_TRUSTED_PROXY_ONLY\","
            "\"nonce\":\"abababababababababababababababababababababababababababababababab\","
            "\"profile_sha256\":\"%s\",\"schema\":\"plamen.egress-policy.v2\"}\n",
            config_hex, profile_hex);
        CHECK(count > 0 && (size_t)count < sizeof(policy));
        CHECK(plamen_broker_v2_sha256(policy, (size_t)count, policy_sha) == 0);
        CHECK(write_file(inputs[6], policy, (size_t)count, 0400) == 0);
        hex_digest(policy_sha, policy_hex);
        CHECK(plamen_broker_v2_sha256(provider, sizeof(provider) - 1U,
            digest) == 0); hex_digest(digest, provider_hex);
        CHECK(plamen_broker_v2_sha256(backend, sizeof(backend) - 1U,
            digest) == 0); hex_digest(digest, backend_hex);
        count = snprintf(admission, sizeof(admission),
            "{\"backend_sha256\":\"%s\",\"policy_sha256\":\"%s\","
            "\"provider_sha256\":\"%s\",\"schema\":\"plamen.egress-admission.v2\"}\n",
            backend_hex, policy_hex, provider_hex);
        CHECK(count > 0 && (size_t)count < sizeof(admission));
        CHECK(write_file(inputs[7], admission, (size_t)count, 0400) == 0);
        plamen_broker_v2_secure_zero(digest, sizeof(digest));
    }
    CHECK(plamen_broker_v2_sha256(names[0], strlen(names[0]), role5_sha) == 0);
    fds[0] = open_read(config_path, 0); fds[1] = open_read(target, 1);
    fds[2] = open_read(docs, 1); fds[3] = open_read(export_path, 1);
    for (index = 4; index < 12U; ++index)
        fds[index] = open_read(inputs[index - 4U], 0);
    for (index = 0; index < 12U; ++index) CHECK(fds[index] >= 0);
    /* Credential custody is anonymous and cannot be reopened by path. */
    CHECK(unlink(inputs[5]) == 0);
    CHECK(plamen_broker_v2_projection_discover_config(
        PLAMEN_BROKER_V2_STARTUP_START_NEW_RUN, config_path, fds[0],
        &discovery) == 0);
    input.startup_intent = PLAMEN_BROKER_V2_STARTUP_START_NEW_RUN;
    input.config_path = config_path; input.config_fd = fds[0];
    input.discovery = &discovery; input.target_root_fd = fds[1];
    input.docs_root_fd = fds[2]; input.scope_fd = -1;
    input.export_root_fd = fds[3]; input.role5_schema_fd = fds[4];
    input.runtime_manifest_fd = fds[5]; input.provider_executable_fd = fds[6];
    input.backend_executable_fd = fds[7]; input.backend_profile_fd = fds[8];
    input.credential_source_fd = fds[9]; input.egress_policy_fd = fds[10];
    input.egress_admission_fd = fds[11]; input.resume_checkpoint_fd = -1;
    memcpy(input.expected_role5_schema_sha256, role5_sha, 32);
    memcpy(input.expected_runtime_manifest_sha256, runtime_sha, 32);
    CHECK(plamen_broker_v2_projection_build_from_retained(&input, &built) == 0);
    CHECK(plamen_broker_v2_projection_registration_roster(&built,
        &registration) == 0);
    memcpy(registration.request_projection_sha256,
        built.request_projection_sha256, 32);
    registration.request_projection_size = (uint32_t)built.request_projection_size;
    memcpy(registration.commitment, built.commitment, built.commitment_size);
    registration.commitment_size = (uint16_t)built.commitment_size;
    memcpy(registration.commitment_sha256, built.commitment_sha256, 32);
    CHECK(plamen_broker_v2_request_projection_derive_exact(
        built.request_projection, built.request_projection_size, &commitment,
        encoded, sizeof(encoded), &encoded_size, registration.request_projection_sha256,
        registration.commitment_sha256) == 0);
    memcpy(registration.audit_request_fingerprint,
        commitment.request_fingerprint, 32);
    state_fd = open_read(state, 1); CHECK(state_fd >= 0);
    generation_fd = open_read(generation, 1); CHECK(generation_fd >= 0);
    workspace_open.version = PLAMEN_BROKER_V2_WORKSPACE_EFFECTS_VERSION;
    workspace_open.registration = &registration;
    workspace_open.request_projection = built.request_projection;
    workspace_open.request_projection_size = built.request_projection_size;
    workspace_open.state_parent_fd = state_fd;
    workspace_open.generation_fd = generation_fd;
    workspace_open.authority_fds = built.retained_fds;
    workspace_open.authority_fd_count = PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
    CHECK(plamen_broker_v2_workspace_effects_create(&workspace_open,
        &workspace) == 0);
    memset(&request, 0, sizeof(request)); memset(arguments, 0, sizeof(arguments));
    request.version = PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION;
    request.member = PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE;
    request.method = PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET;
    request.argument_count = 1; request.arguments = arguments;
    memset(request.operation_key, 0x11, 32);
    CHECK(plamen_broker_v2_workspace_effects_execute(workspace, &request,
        &result) == 1);
    memcpy(arguments[1].commitment_sha256, result.result_commitment_sha256, 32);
    memcpy(target_receipt, result.result_commitment_sha256, 32);
    plamen_broker_v2_workspace_effects_dispose_result(&result);
    request.method = PLAMEN_BROKER_V2_METHOD_WORKSPACE_PREPARE_LAYOUT;
    request.argument_count = 3;
    arguments[1].name = "target"; memset(request.operation_key, 0x22, 32);
    CHECK(plamen_broker_v2_workspace_effects_execute(workspace, &request,
        &result) == 1 && result.effect_applied == 1);
    memcpy(arguments[1].commitment_sha256, result.result_commitment_sha256, 32);
    memcpy(layout_receipt, result.result_commitment_sha256, 32);
    plamen_broker_v2_workspace_effects_dispose_result(&result);
    merged_fd = plamen_broker_v2_workspace_effects_borrow_fd(workspace,
        PLAMEN_BROKER_V2_WORKSPACE_MERGED); CHECK(merged_fd >= 0);
    config_fd = openat(merged_fd, "Main.sol", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(config_fd >= 0); close(config_fd);
    {
        static const char digits[] = "0123456789abcdef";
        for (index = 0; index < 32U; ++index) {
            source_sha[index * 2U] = digits[built.guest_config_sha256[index] >> 4];
            source_sha[index * 2U + 1U] = digits[built.guest_config_sha256[index] & 15U];
            source_handle[7U + index * 2U] = digits[built.retained_identities[0][index] >> 4];
            source_handle[8U + index * 2U] = digits[built.retained_identities[0][index] & 15U];
        }
        source_sha[64] = '\0'; memcpy(source_handle, "opaque:", 7); source_handle[71] = '\0';
    }
    CHECK(derive_guest_commitment(built.guest_config, built.guest_config_size,
        source_sha, source_handle, guest_commitment) == 0);
    memcpy(arguments[2].commitment_sha256, guest_commitment, 32);
    request.method = PLAMEN_BROKER_V2_METHOD_WORKSPACE_WRITE_GUEST_CONFIG;
    request.argument_count = 4; memset(request.operation_key, 0x33, 32);
    CHECK(plamen_broker_v2_workspace_effects_execute(workspace, &request,
        &result) == 1 && result.effect_applied == 1);
    memcpy(config_receipt, result.result_commitment_sha256, 32);
    plamen_broker_v2_workspace_effects_dispose_result(&result);
    config_fd = openat(plamen_broker_v2_workspace_effects_borrow_fd(workspace,
        PLAMEN_BROKER_V2_WORKSPACE_CONTROL), "config.json",
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(config_fd >= 0); close(config_fd);
    CHECK(plamen_broker_v2_workspace_effects_revalidate(workspace) == 0);
    memset(arguments, 0, sizeof(arguments));
    memcpy(arguments[1].commitment_sha256, target_receipt, 32);
    memcpy(arguments[2].commitment_sha256, layout_receipt, 32);
    memset(arguments[3].commitment_sha256, 0x91, 32);
    memset(arguments[4].commitment_sha256, 0x92, 32);
    memcpy(arguments[5].commitment_sha256, config_receipt, 32);
    arguments[6].scalar = "PRE_CREATE";
    arguments[6].scalar_size = strlen(arguments[6].scalar);
    request.method = PLAMEN_BROKER_V2_METHOD_WORKSPACE_RECENSUS_LAYOUT;
    request.argument_count = 7U;
    CHECK(plamen_broker_v2_workspace_effects_execute(workspace, &request,
        &result) == 1 && result.effect_applied == 0);
    {
        const uint8_t *recensus = NULL;
        size_t recensus_size = 0;
        uint8_t recensus_commitment[32];
        CHECK(plamen_broker_v2_workspace_effects_borrow_recensus(
            workspace, "PRE_CREATE", &recensus, &recensus_size,
            recensus_commitment) == 0);
        CHECK(recensus != NULL && recensus_size == result.canonical_result_size
            && memcmp(recensus, result.canonical_result, recensus_size) == 0
            && memcmp(recensus_commitment,
                result.result_commitment_sha256, 32) == 0);
        precreate_recensus = malloc(recensus_size);
        CHECK(precreate_recensus != NULL);
        memcpy(precreate_recensus, recensus, recensus_size);
        precreate_recensus_size = recensus_size;
        memcpy(precreate_recensus_commitment, recensus_commitment, 32);
        CHECK(plamen_broker_v2_workspace_effects_provider_mounts_sha256(
            workspace, "PRE_CREATE",
            precreate_provider_mounts_sha256) == 0);
    }
    plamen_broker_v2_workspace_effects_dispose_result(&result);
    {
        static const uint16_t mounts[10] = {
            PLAMEN_BROKER_V2_WORKSPACE_MERGED,
            PLAMEN_BROKER_V2_WORKSPACE_SCRATCH,
            PLAMEN_BROKER_V2_WORKSPACE_STATE,
            PLAMEN_BROKER_V2_WORKSPACE_CONTROL,
            PLAMEN_BROKER_V2_WORKSPACE_SECCOMP,
            PLAMEN_BROKER_V2_WORKSPACE_CREDENTIALS,
            PLAMEN_BROKER_V2_WORKSPACE_BACKEND,
            PLAMEN_BROKER_V2_WORKSPACE_RUNTIME,
            PLAMEN_BROKER_V2_WORKSPACE_DOCS,
            PLAMEN_BROKER_V2_WORKSPACE_SCOPE
        };
        struct plamen_broker_v2_workspace_mount_view view;
        for (index = 0; index < 10U; ++index) {
            CHECK(plamen_broker_v2_workspace_effects_borrow_mount(
                workspace, mounts[index], &view) == 0);
            CHECK(view.version == PLAMEN_BROKER_V2_WORKSPACE_EFFECTS_VERSION
                && view.purpose == mounts[index] && view.source_fd >= 0
                && view.source_path[0] == '/');
            CHECK(view.read_only == (index == 1U || index == 2U ? 0U : 1U));
        }
    }
    memset(request.operation_key, 0x40, 32);
    CHECK(plamen_broker_v2_workspace_effects_capture_recensus(
        workspace, "POST_CREATE", request.operation_key, &result) == 0);
    plamen_broker_v2_workspace_effects_dispose_result(&result);
    CHECK(plamen_broker_v2_workspace_effects_allowed_delta_sha256(
        workspace, allowed_delta_sha256) == 0);
    /* A fresh service context must adopt the durable recensus exactly. */
    plamen_broker_v2_workspace_effects_destroy(workspace); workspace = NULL;
    CHECK(plamen_broker_v2_workspace_effects_create(&workspace_open,
        &workspace) == 0);
    memset(arguments, 0, sizeof(arguments));
    request.method = PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET;
    request.argument_count = 1U; memset(request.operation_key, 0x41, 32);
    CHECK(plamen_broker_v2_workspace_effects_execute(workspace, &request,
        &result) == 1);
    plamen_broker_v2_workspace_effects_dispose_result(&result);
    arguments[1].name = "target";
    memcpy(arguments[1].commitment_sha256, target_receipt, 32);
    request.method = PLAMEN_BROKER_V2_METHOD_WORKSPACE_PREPARE_LAYOUT;
    request.argument_count = 3U; memset(request.operation_key, 0x42, 32);
    CHECK(plamen_broker_v2_workspace_effects_execute(workspace, &request,
        &result) == 1);
    CHECK(memcmp(result.result_commitment_sha256, layout_receipt, 32) == 0);
    plamen_broker_v2_workspace_effects_dispose_result(&result);
    memset(arguments, 0, sizeof(arguments));
    memcpy(arguments[1].commitment_sha256, layout_receipt, 32);
    memcpy(arguments[2].commitment_sha256, guest_commitment, 32);
    request.method = PLAMEN_BROKER_V2_METHOD_WORKSPACE_WRITE_GUEST_CONFIG;
    request.argument_count = 4U; memset(request.operation_key, 0x43, 32);
    CHECK(plamen_broker_v2_workspace_effects_execute(workspace, &request,
        &result) == 1);
    CHECK(memcmp(result.result_commitment_sha256, config_receipt, 32) == 0);
    plamen_broker_v2_workspace_effects_dispose_result(&result);
    {
        const uint8_t *recensus = NULL;
        size_t recensus_size = 0;
        uint8_t recensus_commitment[32];
        CHECK(plamen_broker_v2_workspace_effects_borrow_recensus(
            workspace, "PRE_CREATE", &recensus, &recensus_size,
            recensus_commitment) == 0);
        CHECK(recensus_size == precreate_recensus_size
            && memcmp(recensus, precreate_recensus, recensus_size) == 0
            && memcmp(recensus_commitment,
                precreate_recensus_commitment, 32) == 0);
        {
            uint8_t provider_mounts_sha256[32];
            CHECK(plamen_broker_v2_workspace_effects_provider_mounts_sha256(
                workspace, "PRE_CREATE", provider_mounts_sha256) == 0
                && memcmp(provider_mounts_sha256,
                    precreate_provider_mounts_sha256, 32) == 0);
        }
        {
            uint8_t recovered_delta_sha256[32];
            CHECK(plamen_broker_v2_workspace_effects_allowed_delta_sha256(
                workspace, recovered_delta_sha256) == 0
                && memcmp(recovered_delta_sha256,
                    allowed_delta_sha256, 32) == 0);
        }
    }
    status = 0;
    plamen_broker_v2_workspace_effects_destroy(workspace); workspace = NULL;
    close(state_fd); state_fd = -1;
    close(generation_fd); generation_fd = -1;
    plamen_broker_v2_projection_builder_result_destroy(&built);
    plamen_broker_v2_projection_discovery_destroy(&discovery);
    for (index = 0; index < 12U; ++index) if (fds[index] >= 0) close(fds[index]);
    if (precreate_recensus != NULL) {
        plamen_broker_v2_secure_zero(precreate_recensus,
            precreate_recensus_size);
        free(precreate_recensus);
    }
    return status;
}

int
main(int argc, char **argv)
{
    if (argc != 2) return 64;
    return exercise(argv[1]);
}
