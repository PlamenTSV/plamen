#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_native_install_coordinator_v2.h"
#include "plamen_native_code_identity_v2.h"
#include "plamen_native_image_member_receipt_v2.h"
#include "plamen_native_source_bootstrap_coordinator_v1.h"
#include "../posix/plamen_native_builder_v2.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifdef PLAMEN_NATIVE_INSTALL_COORDINATOR_V2_MAIN
static int
parse_inherited_fd(const char *value)
{
    char *end = NULL;
    long number;
    if (value == NULL || value[0] == '\0') { errno = EINVAL; return -1; }
    errno = 0; number = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || number < 3
        || number > 1048576L || fcntl((int)number, F_GETFD) < 0
        || fcntl((int)number, F_SETFD, FD_CLOEXEC) != 0) {
        errno = EINVAL; return -1;
    }
    return (int)number;
}

static void
coordinator_cli_diagnostic(void)
{
    static const char message[] = "Plamen Darwin native install denied.\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1U);
}

static int
decode_hex_cli(const char *value, uint8_t *output, size_t output_capacity,
    size_t minimum_size, size_t maximum_size, uint16_t *decoded_size)
{
    size_t input_size, index, byte_count;
    if (value == NULL || output == NULL || minimum_size > maximum_size
            || maximum_size > output_capacity)
        return -1;
    input_size = strlen(value);
    if ((input_size & 1U) != 0U)
        return -1;
    byte_count = input_size / 2U;
    if (byte_count < minimum_size || byte_count > maximum_size)
        return -1;
    memset(output, 0, output_capacity);
    for (index = 0U; index < byte_count; ++index) {
        unsigned char high = (unsigned char)value[index * 2U];
        unsigned char low = (unsigned char)value[index * 2U + 1U];
        unsigned char high_value, low_value;
        if (!((high >= '0' && high <= '9')
                    || (high >= 'a' && high <= 'f'))
                || !((low >= '0' && low <= '9')
                    || (low >= 'a' && low <= 'f')))
            return -1;
        high_value = (unsigned char)(high <= '9'
            ? high - '0' : high - 'a' + 10U);
        low_value = (unsigned char)(low <= '9'
            ? low - '0' : low - 'a' + 10U);
        output[index] = (uint8_t)((high_value << 4U) | low_value);
    }
    if (decoded_size != NULL)
        *decoded_size = (uint16_t)byte_count;
    return 0;
}

static int
parse_u16_cli(const char *value, uint16_t *output)
{
    char *end = NULL;
    unsigned long number;
    if (value == NULL || value[0] == '\0' || output == NULL)
        return -1;
    errno = 0;
    number = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0'
            || number == 0UL || number > UINT16_MAX)
        return -1;
    *output = (uint16_t)number;
    return 0;
}

static int
specialized_stage_name_exact(const char *value)
{
    static const char prefix[] = "generation-stage-v2-";
    static const char attempt[] = ".attempt-";
    size_t index, offset = sizeof(prefix) - 1U;
    unsigned int ordinal;
    if (value == NULL || strncmp(value, prefix, offset) != 0)
        return 0;
    for (index = 0U; index < 64U; ++index) {
        char byte = value[offset + index];
        if (!((byte >= '0' && byte <= '9')
                || (byte >= 'a' && byte <= 'f')))
            return 0;
    }
    offset += 64U;
    if (value[offset] == '\0')
        return 1;
    if (strncmp(value + offset, attempt, sizeof(attempt) - 1U) != 0)
        return 0;
    offset += sizeof(attempt) - 1U;
    if (strlen(value + offset) != 4U
            || value[offset] != '0' || value[offset + 1U] != '0'
            || value[offset + 2U] < '0' || value[offset + 2U] > '9'
            || value[offset + 3U] < '0' || value[offset + 3U] > '9')
        return 0;
    ordinal = (unsigned int)(value[offset + 2U] - '0') * 10U
        + (unsigned int)(value[offset + 3U] - '0');
    return ordinal >= 2U && ordinal <= 32U;
}

/*
 * One-process production handoff.  The caller supplies only retained source
 * and empty output descriptors plus exact signed-member observations.  This
 * process keeps all descriptors live while native code derives and checks the
 * generation ID, renders both launchd plists, stages all ten generation
 * artifacts, encodes the receipt, and enters the atomic publisher.
 *
 * Production argv: command, root-fd, stage-parent-fd, runtime-root-fd,
 * receipt-output-fd,
 * broker-plist-output-fd, custody-plist-output-fd, install-root, stage-name,
 * projection-sha256, protocol-sha256, python-micro,
 * target-arch, image-reference, init-reference, fourteen runtime-binding
 * digests, ten source-member-fds (role 8 is an empty manifest output),
 * five ad-hoc CDHashes, Python identifier, Python team ("-" means empty),
 * Python CDHash.  The legacy test ABI inserts an expected-generation-hex
 * after stage-name; production derives that value from retained descriptors.
 */
typedef int (*plamen_prepare_publish_effect_v2)(
    const struct plamen_native_install_request_v2 *,
    struct plamen_native_install_result_v2 *);

static int read_receipt(int fd, uid_t owner,
    struct plamen_install_receipt *receipt);

static int
validate_source_bootstrap_receipt_for_install(void *context, int receipt_fd,
    uid_t owner_uid, uint8_t acquisition_roster_sha256[32],
    uint8_t producer_verifier_key_sha256[32],
    uint8_t installed_authority_roster_sha256[32])
{
    struct plamen_source_bootstrap_receipt_v1 receipt;
    const uint8_t *expected_installed_authority_roster_sha256 = context;
    memset(&receipt, 0, sizeof(receipt));
    if (expected_installed_authority_roster_sha256 == NULL
        || receipt_fd < 0 || acquisition_roster_sha256 == NULL
        || producer_verifier_key_sha256 == NULL
        || installed_authority_roster_sha256 == NULL
        || plamen_source_bootstrap_receipt_read_fd_v1(
            receipt_fd, owner_uid, &receipt) != 0)
        return -1;
    memcpy(acquisition_roster_sha256,
        receipt.acquisition_roster_sha256, 32U);
    memcpy(producer_verifier_key_sha256,
        receipt.producer_verifier_key.sha256, 32U);
    if (plamen_source_bootstrap_installed_authority_roster_sha256_v1(
            &receipt, installed_authority_roster_sha256) != 0
        || memcmp(installed_authority_roster_sha256,
            expected_installed_authority_roster_sha256, 32U) != 0) {
        memset(&receipt, 0, sizeof(receipt));
        return -1;
    }
    memset(&receipt, 0, sizeof(receipt));
    return 0;
}

static int
prepare_publish_fds_cli_with_effect(int argc, char **argv,
    plamen_prepare_publish_effect_v2 publish_effect)
{
    static const char *const fixed_identifiers[5] = {
        "com.plamen.audit.launcher.v2",
        "com.plamen.audit.broker.v2",
        "com.plamen.audit.native-supervisor.v2",
        "com.plamen.audit.installer.v2",
        "com.plamen.audit.source-bootstrap.v1"
    };
    struct plamen_native_generation_deployment_stage_request_v2 stage;
    struct plamen_native_generation_deployment_stage_result_v2 staged;
    struct plamen_darwin_install_receipt_request_v2 receipt_request;
    struct plamen_darwin_install_receipt_result_v2 receipt_result;
    struct plamen_native_install_request_v2 install_request;
    struct plamen_native_install_result_v2 install_result;
    struct plamen_runtime_package_bindings_v2 runtime_bindings;
    struct plamen_runtime_package_manifest_result_v2 runtime_manifest;
    struct plamen_image_member_receipt_v2_encode_bindings image_bindings;
    struct plamen_image_member_receipt_v2_expected expected_image;
    struct plamen_image_member_receipt_v2 decoded_image;
    struct plamen_install_receipt stored_receipt;
    uint8_t expected_generation[32];
    uint8_t intrinsic_roster_sha256[32];
    uint8_t image_roster_sha256[32];
    uint8_t image_receipt_sha256[32];
    uint8_t installed_authority_roster_sha256[32];
    char generation_hex[65];
    char generation_path[PATH_MAX + 1U];
    char service_path[PATH_MAX + 1U];
    char broker_plist_path[PATH_MAX + 1U];
    char custody_plist_path[PATH_MAX + 1U];
    const char *python_team;
    const char *generation_id_hex;
    size_t index;
    size_t shift, identity_offset;
    int generation_path_size, service_path_size;
    int broker_plist_path_size, custody_plist_path_size;
    int install_root_fd, stage_parent_fd, runtime_root_fd;
    int receipt_output_fd, broker_output_fd, custody_output_fd;
    int derive_generation, specialized_generation, resume_specialized;
    int source_bootstrap_generation;
    int retained_publish;
    int image_rows_fd = -1, image_receipt_output_fd = -1;
    int source_bootstrap_receipt_fd = -1, producer_verifier_key_fd = -1;
    int generations_fd = -1;
    int stage_probe_fd = -1;
    int saved_errno = 0;
    int result = -1;

    memset(&stage, 0, sizeof(stage));
    memset(&staged, 0, sizeof(staged));
    memset(&receipt_request, 0, sizeof(receipt_request));
    memset(&receipt_result, 0, sizeof(receipt_result));
    memset(&install_request, 0, sizeof(install_request));
    memset(&install_result, 0, sizeof(install_result));
    memset(&runtime_bindings, 0, sizeof(runtime_bindings));
    memset(&runtime_manifest, 0, sizeof(runtime_manifest));
    memset(&image_bindings, 0, sizeof(image_bindings));
    memset(&expected_image, 0, sizeof(expected_image));
    memset(&decoded_image, 0, sizeof(decoded_image));
    memset(&stored_receipt, 0, sizeof(stored_receipt));
    memset(expected_generation, 0, sizeof(expected_generation));
    memset(intrinsic_roster_sha256, 0, sizeof(intrinsic_roster_sha256));
    memset(image_roster_sha256, 0, sizeof(image_roster_sha256));
    memset(image_receipt_sha256, 0, sizeof(image_receipt_sha256));
    memset(installed_authority_roster_sha256, 0,
        sizeof(installed_authority_roster_sha256));
    memset(generation_hex, 0, sizeof(generation_hex));
    staged.generation.generation_root_fd = -1;
    staged.generation.runtime_root_fd = -1;
    staged.generation.specialized_authority_fd = -1;
    staged.generation.source_bootstrap_authority_fd = -1;
    staged.broker_launchd_plist_fd = -1;
    staged.custody_launchd_plist_fd = -1;
    for (index = 0U; index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT;
            ++index) {
        stage.generation.member_source_fds[index] = -1;
        staged.generation.generation_member_fds[index] = -1;
        install_request.generation_member_fds[index] = -1;
    }
    resume_specialized = (argc == 52 && strcmp(argv[1],
        "resume-publish-specialized-derived-fds") == 0)
        || (argc == 54 && strcmp(argv[1],
            "resume-publish-specialized-source-bootstrap-derived-fds") == 0);
    source_bootstrap_generation = (argc == 50 && (
            strcmp(argv[1],
                "prepare-publish-source-bootstrap-derived-fds") == 0
            || strcmp(argv[1],
                "prepare-publish-retained-source-bootstrap-derived-fds") == 0))
        || (argc == 54 && (
            strcmp(argv[1],
                "prepare-publish-specialized-source-bootstrap-derived-fds") == 0
            || strcmp(argv[1],
                "prepare-publish-retained-specialized-source-bootstrap-derived-fds") == 0
            || strcmp(argv[1],
                "resume-publish-specialized-source-bootstrap-derived-fds") == 0));
    specialized_generation = resume_specialized || (argc == 52
        && strcmp(argv[1],
            "prepare-publish-specialized-derived-fds") == 0)
        || (argc == 52 && strcmp(argv[1],
            "prepare-publish-retained-specialized-derived-fds") == 0)
        || (source_bootstrap_generation && argc == 54);
    retained_publish = (argc == 48 && strcmp(argv[1],
        "prepare-publish-retained-derived-fds") == 0)
        || (argc == 52 && strcmp(argv[1],
            "prepare-publish-retained-specialized-derived-fds") == 0)
        || (argc == 50 && strcmp(argv[1],
            "prepare-publish-retained-source-bootstrap-derived-fds") == 0)
        || (argc == 54 && strcmp(argv[1],
            "prepare-publish-retained-specialized-source-bootstrap-derived-fds") == 0);
    derive_generation = specialized_generation || source_bootstrap_generation
        || retained_publish ||
        (argc == 48
        && strcmp(argv[1], "prepare-publish-derived-fds") == 0);
    if (publish_effect == NULL
            || (specialized_generation && !specialized_stage_name_exact(argv[9]))
            || (!derive_generation
            && (argc != 49 || strcmp(argv[1], "prepare-publish-fds") != 0)))
        goto done;
    shift = derive_generation ? 0U : 1U;
    identity_offset = (specialized_generation ? 44U : 40U + shift)
        + (source_bootstrap_generation ? 2U : 0U);
    install_root_fd = parse_inherited_fd(argv[2]);
    stage_parent_fd = parse_inherited_fd(argv[3]);
    runtime_root_fd = parse_inherited_fd(argv[4]);
    receipt_output_fd = parse_inherited_fd(argv[5]);
    broker_output_fd = parse_inherited_fd(argv[6]);
    custody_output_fd = parse_inherited_fd(argv[7]);
    if (install_root_fd < 0 || stage_parent_fd < 0 || runtime_root_fd < 0
            || receipt_output_fd < 0 || broker_output_fd < 0
            || custody_output_fd < 0
            || (!derive_generation && decode_hex_cli(argv[10],
                expected_generation, sizeof(expected_generation),
                32U, 32U, NULL) != 0)
            || decode_hex_cli(argv[10U + shift],
                receipt_request.projection_schema_sha256,
                sizeof(receipt_request.projection_schema_sha256),
                32U, 32U, NULL) != 0
            || decode_hex_cli(argv[11U + shift],
                receipt_request.protocol_schema_sha256,
                sizeof(receipt_request.protocol_schema_sha256),
                32U, 32U, NULL) != 0
            || parse_u16_cli(argv[12U + shift],
                &receipt_request.python_micro) != 0)
        goto done;
    if (strcmp(argv[13U + shift], "arm64") != 0)
        goto done;
    runtime_bindings.target_arch = PLAMEN_RUNTIME_PACKAGE_TARGET_ARCH_ARM64_V2;
    runtime_bindings.oci_image_reference = argv[14U + shift];
    runtime_bindings.oci_image_reference_size = strlen(argv[14U + shift]);
    runtime_bindings.oci_init_reference = argv[15U + shift];
    runtime_bindings.oci_init_reference_size = strlen(argv[15U + shift]);
    for (index = 0U;
            index < PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_COUNT;
            ++index)
        if (decode_hex_cli(argv[16U + shift + index],
                runtime_bindings.digests[index],
                sizeof(runtime_bindings.digests[index]),
                32U, 32U, NULL) != 0)
            goto done;
    for (index = 0U; index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT;
            ++index) {
        stage.generation.member_source_fds[index] =
            parse_inherited_fd(argv[30U + shift + index]);
        if (stage.generation.member_source_fds[index] < 0)
            goto done;
    }
    if (specialized_generation) {
        image_rows_fd = parse_inherited_fd(argv[40]);
        image_receipt_output_fd = parse_inherited_fd(argv[41]);
        if (image_rows_fd < 0 || image_receipt_output_fd < 0
                || decode_hex_cli(argv[42],
                    runtime_bindings.specialized_policy_self_sha256,
                    32U, 32U, 32U, NULL) != 0
                || decode_hex_cli(argv[43],
                    runtime_bindings.specialized_policy_bytes_sha256,
                    32U, 32U, 32U, NULL) != 0
                || plamen_image_member_rows_v2_validate_fd(image_rows_fd,
                    image_roster_sha256) != 0)
            goto done;
        runtime_bindings.specialized_present = 1U;
        runtime_bindings.specialized_member_receipt_path =
            PLAMEN_RUNTIME_PACKAGE_SPECIALIZED_RECEIPT_PATH_V2;
        runtime_bindings.specialized_member_receipt_path_size = strlen(
            PLAMEN_RUNTIME_PACKAGE_SPECIALIZED_RECEIPT_PATH_V2);
        memcpy(runtime_bindings.specialized_roster_sha256,
            image_roster_sha256, 32U);
    }
    if (source_bootstrap_generation) {
        size_t source_offset = specialized_generation ? 44U : 40U + shift;
        source_bootstrap_receipt_fd = parse_inherited_fd(argv[source_offset]);
        producer_verifier_key_fd = parse_inherited_fd(argv[source_offset + 1U]);
        if (source_bootstrap_receipt_fd < 0 || producer_verifier_key_fd < 0)
            goto done;
    }
    if ((!resume_specialized
            && plamen_runtime_package_manifest_render_v2(runtime_root_fd,
                &runtime_bindings, stage.generation.member_source_fds[7],
                getuid(), &runtime_manifest) != 0)
            || (resume_specialized
                && plamen_runtime_package_manifest_revalidate_v2(
                    runtime_root_fd, stage.generation.member_source_fds[7],
                    getuid(), &runtime_manifest) != 0)
            || plamen_intrinsic_generation_id_from_sources_v2(
                runtime_root_fd, stage.generation.member_source_fds,
                getuid(), expected_generation,
                intrinsic_roster_sha256) != 0)
        goto done;
    if (specialized_generation) {
        memcpy(image_bindings.oci_manifest_sha256,
            runtime_bindings.digests[PLAMEN_RUNTIME_PACKAGE_IMAGE_MANIFEST_V2],
            32U);
        memcpy(image_bindings.runtime_package_manifest_sha256,
            runtime_manifest.manifest_sha256, 32U);
        memcpy(image_bindings.image_closure_sha256,
            runtime_bindings.digests[PLAMEN_RUNTIME_PACKAGE_IMAGE_CLOSURE_V2],
            32U);
        memcpy(image_bindings.closure_census_sha256,
            runtime_bindings.digests[PLAMEN_RUNTIME_PACKAGE_CLOSURE_CENSUS_V2],
            32U);
        memcpy(image_bindings.materialization_receipt_sha256,
            runtime_bindings.digests[
                PLAMEN_RUNTIME_PACKAGE_MATERIALIZATION_RECEIPT_V2], 32U);
        memcpy(image_bindings.policy_sha256,
            runtime_bindings.specialized_policy_self_sha256, 32U);
        memcpy(expected_image.oci_manifest_sha256,
            image_bindings.oci_manifest_sha256, 32U);
        memcpy(expected_image.runtime_package_manifest_sha256,
            image_bindings.runtime_package_manifest_sha256, 32U);
        memcpy(expected_image.image_closure_sha256,
            image_bindings.image_closure_sha256, 32U);
        memcpy(expected_image.closure_census_sha256,
            image_bindings.closure_census_sha256, 32U);
        memcpy(expected_image.materialization_receipt_sha256,
            image_bindings.materialization_receipt_sha256, 32U);
        memcpy(expected_image.roster_sha256, image_roster_sha256, 32U);
        memcpy(expected_image.policy_sha256,
            image_bindings.policy_sha256, 32U);
        if ((!resume_specialized
                && plamen_image_member_receipt_v2_encode_rows_fd(
                    image_rows_fd, image_receipt_output_fd, getuid(),
                    &image_bindings, image_roster_sha256,
                    image_receipt_sha256) != 0)
            || (resume_specialized
                && plamen_image_member_receipt_v2_read_fd(
                    image_receipt_output_fd, &expected_image,
                    &decoded_image, image_receipt_sha256) != 0))
            goto done;
    }
    if (derive_generation) {
        static const char digits[] = "0123456789abcdef";
        for (index = 0U; index < 32U; ++index) {
            generation_hex[index * 2U] =
                digits[expected_generation[index] >> 4U];
            generation_hex[index * 2U + 1U] =
                digits[expected_generation[index] & 15U];
        }
        generation_id_hex = generation_hex;
    } else {
        uint8_t supplied_generation[32];
        memset(supplied_generation, 0, sizeof(supplied_generation));
        if (decode_hex_cli(argv[10], supplied_generation,
                sizeof(supplied_generation), 32U, 32U, NULL) != 0
                || memcmp(supplied_generation, expected_generation,
                    sizeof(expected_generation)) != 0) {
            memset(supplied_generation, 0, sizeof(supplied_generation));
            goto done;
        }
        memset(supplied_generation, 0, sizeof(supplied_generation));
        generation_id_hex = argv[10];
    }
    generation_path_size = snprintf(generation_path, sizeof(generation_path),
        "%s/generations/%s", argv[8], generation_id_hex);
    service_path_size = snprintf(service_path, sizeof(service_path),
                "%s/lib/plamen/plamen-audit-broker-v2",
                generation_path);
    broker_plist_path_size = snprintf(
        broker_plist_path, sizeof(broker_plist_path),
                "%s/Library/LaunchAgents/%s", generation_path,
                "com.plamen.audit.broker.v2.plist");
    custody_plist_path_size = snprintf(
        custody_plist_path, sizeof(custody_plist_path),
                "%s/Library/LaunchAgents/%s", generation_path,
                "com.plamen.audit.process-custody.v2.plist");
    if (generation_path_size < 0
            || (size_t)generation_path_size >= sizeof(generation_path)
            || service_path_size < 0
            || (size_t)service_path_size >= sizeof(service_path)
            || broker_plist_path_size < 0
            || (size_t)broker_plist_path_size >= sizeof(broker_plist_path)
            || custody_plist_path_size < 0
            || (size_t)custody_plist_path_size >= sizeof(custody_plist_path))
        goto done;
    if (!resume_specialized) {
    if (plamen_native_launchd_render_plist_v2(broker_output_fd,
            service_path, PLAMEN_LAUNCHD_ROLE_BROKER_V2) != 0
            || plamen_native_launchd_render_plist_v2(custody_output_fd,
                service_path, PLAMEN_LAUNCHD_ROLE_CUSTODY_V2) != 0)
        goto done;
    stage.generation.staging_parent_fd = stage_parent_fd;
    stage.generation.runtime_root_source_fd = runtime_root_fd;
    stage.generation.staged_generation_name = argv[9];
    stage.generation.owner_uid = getuid();
    stage.generation.specialized_present = specialized_generation ? 1U : 0U;
    stage.generation.specialized_authority_source_fd =
        image_receipt_output_fd;
    stage.generation.source_bootstrap_present =
        source_bootstrap_generation ? 1U : 0U;
    stage.generation.source_bootstrap_authority_source_fd =
        source_bootstrap_receipt_fd;
    stage.broker_launchd_plist_fd = broker_output_fd;
    stage.custody_launchd_plist_fd = custody_output_fd;
    stage_probe_fd = openat(stage_parent_fd, argv[9],
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (stage_probe_fd >= 0) {
        (void)close(stage_probe_fd);
        stage_probe_fd = -1;
        if (plamen_native_generation_deployment_stage_revalidate_v2(
                &stage, &staged) != 0) {
            struct stat receipt_state;
            if (fstat(receipt_output_fd, &receipt_state) == 0
                    && S_ISREG(receipt_state.st_mode)
                    && receipt_state.st_size == 0)
                errno = EINPROGRESS;
            goto done;
        }
    } else {
        if (errno != ENOENT
                || plamen_native_generation_deployment_stage_v2(
                    &stage, &staged) != 0)
            goto done;
    }
    if (memcmp(staged.generation.generation_id,
            expected_generation, sizeof(expected_generation)) != 0)
        goto done;
    } else {
        staged.generation.generation_root_fd = openat(stage_parent_fd,
            argv[9], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (staged.generation.generation_root_fd < 0 && errno == ENOENT) {
            generations_fd = openat(install_root_fd, "generations",
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (generations_fd >= 0)
                staged.generation.generation_root_fd = openat(generations_fd,
                    generation_id_hex,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
        if (staged.generation.generation_root_fd < 0
                || read_receipt(receipt_output_fd, getuid(),
                    &stored_receipt) != 0
                || memcmp(stored_receipt.generation_id_sha256,
                    expected_generation, 32U) != 0
                || memcmp(stored_receipt.projection_schema_sha256,
                    receipt_request.projection_schema_sha256, 32U) != 0
                || memcmp(stored_receipt.protocol_schema_sha256,
                    receipt_request.protocol_schema_sha256, 32U) != 0
                || stored_receipt.python_micro
                    != receipt_request.python_micro
                || stored_receipt.specialized_present != 1U
                || stored_receipt.source_bootstrap_present
                    != (source_bootstrap_generation ? 1U : 0U)
                || memcmp(stored_receipt.specialized_authority
                        .runtime_package_manifest_sha256,
                    runtime_manifest.manifest_sha256, 32U) != 0)
            goto done;
        for (index = 0U; index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT;
                ++index)
            if (plamen_install_receipt_open_member(
                    staged.generation.generation_root_fd,
                    &stored_receipt.members[index],
                    &staged.generation.generation_member_fds[index]) != 0)
                goto done;
        if (plamen_install_receipt_open_specialized_authority(
                staged.generation.generation_root_fd, &stored_receipt,
                &staged.generation.specialized_authority_fd) != 0)
            goto done;
        if (source_bootstrap_generation
            && plamen_install_receipt_open_source_bootstrap_authority(
                staged.generation.generation_root_fd, &stored_receipt,
                &staged.generation.source_bootstrap_authority_fd) != 0)
            goto done;
    }

    if (source_bootstrap_generation
            && plamen_source_bootstrap_staged_authority_validate_v1(
                staged.generation.generation_root_fd,
                staged.generation.source_bootstrap_authority_fd,
                getuid(), installed_authority_roster_sha256) != 0)
        goto done;

    receipt_request.generation_absolute_path = generation_path;
    receipt_request.generation_absolute_path_size = strlen(generation_path);
    receipt_request.broker_launchd_plist.fd = staged.broker_launchd_plist_fd;
    receipt_request.broker_launchd_plist.absolute_path = broker_plist_path;
    receipt_request.broker_launchd_plist.absolute_path_size =
        strlen(broker_plist_path);
    receipt_request.custody_launchd_plist.fd = staged.custody_launchd_plist_fd;
    receipt_request.custody_launchd_plist.absolute_path = custody_plist_path;
    receipt_request.custody_launchd_plist.absolute_path_size =
        strlen(custody_plist_path);
    if (specialized_generation) {
        receipt_request.specialized_present = 1U;
        receipt_request.specialized_member_receipt_fd =
            staged.generation.specialized_authority_fd;
    }
    if (source_bootstrap_generation) {
        receipt_request.source_bootstrap_present = 1U;
        receipt_request.source_bootstrap_receipt_fd =
            staged.generation.source_bootstrap_authority_fd;
        receipt_request.source_bootstrap_producer_verifier_key_fd =
            producer_verifier_key_fd;
        receipt_request.source_bootstrap_receipt_validate =
            validate_source_bootstrap_receipt_for_install;
        receipt_request.source_bootstrap_receipt_context =
            installed_authority_roster_sha256;
    }
    for (index = 0U; index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT;
            ++index) {
        struct plamen_darwin_code_identity_v2 *identity =
            &receipt_request.members[index].code_identity;
        receipt_request.members[index].fd =
            staged.generation.generation_member_fds[index];
        identity->signing_identifier = "";
        identity->team_identifier = "";
        if (index < 3U || index == 8U || index == 9U) {
            size_t fixed_index = index == 8U ? 3U : index == 9U ? 4U : index;
            identity->signing_identifier = fixed_identifiers[fixed_index];
            identity->signing_identifier_size =
                strlen(fixed_identifiers[fixed_index]);
            if (decode_hex_cli(argv[identity_offset + fixed_index],
                    identity->cdhash,
                    sizeof(identity->cdhash), 20U, 32U,
                    &identity->cdhash_size) != 0)
                goto done;
        }
    }
    python_team = strcmp(argv[identity_offset + 6U], "-") == 0
        ? "" : argv[identity_offset + 6U];
    receipt_request.members[5].code_identity.signing_identifier =
        argv[identity_offset + 5U];
    receipt_request.members[5].code_identity.signing_identifier_size =
        strlen(argv[identity_offset + 5U]);
    receipt_request.members[5].code_identity.team_identifier = python_team;
    receipt_request.members[5].code_identity.team_identifier_size =
        strlen(python_team);
    if (decode_hex_cli(argv[identity_offset + 7U],
            receipt_request.members[5].code_identity.cdhash,
            sizeof(receipt_request.members[5].code_identity.cdhash),
            20U, 32U,
            &receipt_request.members[5].code_identity.cdhash_size) != 0)
        goto done;
    if (!resume_specialized) {
        if (plamen_darwin_install_receipt_encode_v2(&receipt_request,
                receipt_output_fd, getuid(), &receipt_result) != 0
                || memcmp(receipt_result.generation_id, expected_generation,
                    sizeof(expected_generation)) != 0)
            goto done;
    } else {
        if (strcmp(stored_receipt.generation_path, generation_path) != 0
                || strcmp(stored_receipt.broker_launchd_plist.path,
                    broker_plist_path) != 0
                || strcmp(stored_receipt.custody_launchd_plist.path,
                    custody_plist_path) != 0)
            goto done;
        for (index = 0U; index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT;
                ++index) {
            const struct plamen_darwin_code_identity_v2 *identity =
                &receipt_request.members[index].code_identity;
            const struct plamen_install_receipt_member *stored =
                &stored_receipt.members[index];
            if (strcmp(stored->signing_identifier,
                    identity->signing_identifier) != 0
                    || strcmp(stored->team_identifier,
                        identity->team_identifier) != 0
                    || stored->cdhash_size != identity->cdhash_size
                    || memcmp(stored->cdhash, identity->cdhash,
                        identity->cdhash_size) != 0)
                goto done;
        }
    }
    install_request.install_root_fd = install_root_fd;
    install_request.staging_parent_fd = stage_parent_fd;
    install_request.receipt_fd = receipt_output_fd;
    install_request.install_root_absolute = argv[8];
    install_request.staged_generation_name = argv[9];
    install_request.generation_id_hex = generation_id_hex;
    install_request.owner_uid = getuid();
    install_request.require_specialized_authority =
        specialized_generation ? 1U : 0U;
    install_request.specialized_authority_fd =
        staged.generation.specialized_authority_fd;
    install_request.require_source_bootstrap_authority =
        source_bootstrap_generation ? 1U : 0U;
    install_request.source_bootstrap_authority_fd =
        staged.generation.source_bootstrap_authority_fd;
    install_request.retain_postcommit_rollback = retained_publish;
    for (index = 0U; index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT;
            ++index)
        install_request.generation_member_fds[index] =
            staged.generation.generation_member_fds[index];
    if (publish_effect(&install_request, &install_result) != 0)
        goto done;
    result = 0;
done:
    saved_errno = result == 0 ? 0 : (errno == 0 ? EINVAL : errno);
    if (generations_fd >= 0) close(generations_fd);
    if (stage_probe_fd >= 0) close(stage_probe_fd);
    plamen_native_generation_deployment_stage_result_dispose_v2(&staged);
    memset(&receipt_request, 0, sizeof(receipt_request));
    memset(&receipt_result, 0, sizeof(receipt_result));
    memset(&install_request, 0, sizeof(install_request));
    memset(&install_result, 0, sizeof(install_result));
    memset(&runtime_bindings, 0, sizeof(runtime_bindings));
    memset(&runtime_manifest, 0, sizeof(runtime_manifest));
    memset(expected_generation, 0, sizeof(expected_generation));
    memset(intrinsic_roster_sha256, 0, sizeof(intrinsic_roster_sha256));
    memset(installed_authority_roster_sha256, 0,
        sizeof(installed_authority_roster_sha256));
    memset(generation_hex, 0, sizeof(generation_hex));
    memset(generation_path, 0, sizeof(generation_path));
    memset(service_path, 0, sizeof(service_path));
    memset(broker_plist_path, 0, sizeof(broker_plist_path));
    memset(custody_plist_path, 0, sizeof(custody_plist_path));
    if (result != 0)
        errno = saved_errno;
    return result;
}

static int
prepare_publish_fds_cli(int argc, char **argv)
{
    return prepare_publish_fds_cli_with_effect(argc, argv,
        plamen_native_darwin_install_publish_v2);
}
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define ACTIVE_RECEIPT "native-install-receipt-v2.bin"
#define ROLLBACK_RECEIPT ".native-install-receipt-v2.rollback-v2"
#define BROKER_PLIST "com.plamen.audit.broker.v2.plist"
#define CUSTODY_PLIST "com.plamen.audit.process-custody.v2.plist"
#define DEPLOYMENT_RECEIPT "native-deployment-receipt-v2.bin"
#define DEPLOYMENT_RECEIPT_NEXT ".native-deployment-receipt-v2.next-v2"
#define DEPLOYMENT_STATE_MAGIC UINT32_C(0x504c4d00)
#define DEPLOYMENT_STATE_PRIOR_LOADED UINT32_C(1)

struct coordinator_context {
    int root_fd;
    const char *root_path;
    uid_t owner;
    struct plamen_native_launchd_transaction_v2 transaction;
    struct plamen_native_install_deployment_v2 launchd;
    struct plamen_native_install_deployment_v2 wrapper;
    struct plamen_install_receipt replacement_receipt;
    struct plamen_install_receipt prior_receipt;
    int replacement_generation_fd;
    int replacement_broker_plist_fd;
    int replacement_custody_plist_fd;
    int prior_generation_fd;
    int prior_broker_plist_fd;
    int prior_custody_plist_fd;
};

static int open_child_directory(int, const char *);

static int
duplicate_cloexec(int fd)
{
#ifdef F_DUPFD_CLOEXEC
    return fcntl(fd, F_DUPFD_CLOEXEC, 3);
#else
    int copy = fcntl(fd, F_DUPFD, 3);
    if (copy >= 0 && fcntl(copy, F_SETFD, FD_CLOEXEC) != 0) {
        int saved = errno; close(copy); errno = saved; return -1;
    }
    return copy;
#endif
}

static int
read_receipt(int fd, uid_t owner,
    struct plamen_install_receipt *receipt)
{
    uint8_t bytes[PLAMEN_INSTALL_RECEIPT_SIZE];
    struct stat before, after;
    size_t offset = 0;
    int result = -1;
    memset(bytes, 0, sizeof(bytes));
    if (fd < 0 || receipt == NULL || fstat(fd, &before) != 0
        || !S_ISREG(before.st_mode)
        || before.st_size != (off_t)sizeof(bytes)
        || before.st_uid != owner
        || (before.st_mode & 07777) != 0400)
        goto done;
    while (offset < sizeof(bytes)) {
        ssize_t amount = pread(fd, bytes + offset, sizeof(bytes) - offset,
            (off_t)offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    if (fstat(fd, &after) != 0 || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid || before.st_gid != after.st_gid
        || before.st_nlink != after.st_nlink || before.st_size != after.st_size
        || plamen_install_receipt_decode_exact(bytes, sizeof(bytes), receipt)
            != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        memset(bytes, 0, sizeof(bytes));
        if (result != 0) errno = saved;
        return result;
    }
}

static int
persist_deployment_receipt_for(struct coordinator_context *context,
    const struct plamen_install_receipt *target,
    const struct plamen_install_receipt *admissible_other)
{
    uint8_t bytes[PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_SIZE];
    int share = -1, plamen = -1, output = -1, retained = -1;
    int stable = -1, named = -1, result = -1;
    int stable_is_target = 0;
    struct stat information, retained_information, named_information;
    memset(bytes, 0, sizeof(bytes));
    if (context == NULL || target == NULL
        || plamen_native_darwin_deployment_receipt_bytes_v2(
            target, bytes) != 0
        || (share = open_child_directory(context->root_fd, "share")) < 0
        || (plamen = open_child_directory(share, "plamen")) < 0)
        goto done;
    output = openat(plamen, DEPLOYMENT_RECEIPT_NEXT,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output >= 0) {
        size_t offset = 0;
        while (offset < sizeof(bytes)) {
            ssize_t amount = pwrite(output, bytes + offset,
                sizeof(bytes) - offset, (off_t)offset);
            if (amount < 0 && errno == EINTR) continue;
            if (amount <= 0) goto done;
            offset += (size_t)amount;
        }
        if (ftruncate(output, (off_t)sizeof(bytes)) != 0
            || fsync(output) != 0 || fchmod(output, 0400) != 0
            || fsync(output) != 0
            || (retained = openat(plamen, DEPLOYMENT_RECEIPT_NEXT,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
            || fstat(output, &information) != 0
            || fstat(retained, &retained_information) != 0
            || information.st_dev != retained_information.st_dev
            || information.st_ino != retained_information.st_ino)
            goto done;
        close(output); output = retained; retained = -1;
    } else if (errno == EEXIST) {
        output = openat(plamen, DEPLOYMENT_RECEIPT_NEXT,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (output < 0 || plamen_native_darwin_deployment_receipt_validate_v2(
                output, target) != 0)
            goto done;
    } else {
        goto done;
    }
    if (plamen_native_darwin_deployment_receipt_validate_v2(output,
            target) != 0)
        goto done;
    /* Never replace an unrelated managed-root entry.  Across committed
     * recovery the stable record may be either the prior or replacement
     * byte-exact record, and no other state is admissible. */
    stable = openat(plamen, DEPLOYMENT_RECEIPT,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (stable >= 0) {
        if (plamen_native_darwin_deployment_receipt_validate_v2(stable,
                target) == 0) {
            stable_is_target = 1;
        } else if (admissible_other == NULL
                || plamen_native_darwin_deployment_receipt_validate_v2(
                    stable, admissible_other) != 0) {
                goto done;
        }
        close(stable); stable = -1;
    } else if (errno != ENOENT) {
        goto done;
    }
    /* A committed replay must preserve the already-published terminal vnode.
     * Retire only the byte-identical private candidate after both records have
     * independently validated; never churn stable authority on recovery. */
    if (stable_is_target) {
        if (unlinkat(plamen, DEPLOYMENT_RECEIPT_NEXT, 0) != 0
            || fsync(plamen) != 0)
            goto done;
        result = 0;
        goto done;
    }
    if (fstat(output, &information) != 0 || !S_ISREG(information.st_mode)
        || information.st_uid != context->owner || information.st_nlink != 1
        || (information.st_mode & 07777) != 0400
        || renameat(plamen, DEPLOYMENT_RECEIPT_NEXT,
            plamen, DEPLOYMENT_RECEIPT) != 0 || fsync(plamen) != 0
        || (named = openat(plamen, DEPLOYMENT_RECEIPT,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || fstat(named, &named_information) != 0
        || named_information.st_dev != information.st_dev
        || named_information.st_ino != information.st_ino
        || plamen_native_darwin_deployment_receipt_validate_v2(named,
            target) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        if (stable >= 0) close(stable);
        if (retained >= 0) close(retained);
        if (named >= 0) close(named); if (output >= 0) close(output);
        if (plamen >= 0) close(plamen); if (share >= 0) close(share);
        memset(bytes, 0, sizeof(bytes)); if (result != 0) errno = saved;
        return result;
    }
}

static int
persist_deployment_receipt(struct coordinator_context *context)
{
    return persist_deployment_receipt_for(context,
        context == NULL ? NULL : context->transaction.replacement.receipt,
        context != NULL && context->transaction.prior_present
            ? context->transaction.prior.receipt : NULL);
}

static int
restore_deployment_receipt(struct coordinator_context *context)
{
    int share = -1, plamen = -1, stable = -1, result = -1;
    if (context == NULL || context->transaction.replacement.receipt == NULL
        || (share = open_child_directory(context->root_fd, "share")) < 0
        || (plamen = open_child_directory(share, "plamen")) < 0)
        goto done;
    if (context->transaction.prior_present) {
        result = persist_deployment_receipt_for(context,
            context->transaction.prior.receipt,
            context->transaction.replacement.receipt);
        goto done;
    }
    /* An absent predecessor is restored only from the exact replacement
     * terminal receipt.  A missing receipt is the idempotent completed state;
     * every foreign or malformed vnode is rejected before unlink. */
    stable = openat(plamen, DEPLOYMENT_RECEIPT,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (stable < 0) {
        if (errno == ENOENT)
            result = 0;
        goto done;
    }
    if (plamen_native_darwin_deployment_receipt_validate_v2(stable,
            context->transaction.replacement.receipt) != 0)
        goto done;
    close(stable); stable = -1;
    if (unlinkat(plamen, DEPLOYMENT_RECEIPT, 0) != 0
        || fsync(plamen) != 0)
        goto done;
    stable = openat(plamen, DEPLOYMENT_RECEIPT,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (stable >= 0 || errno != ENOENT)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        if (stable >= 0) close(stable);
        if (plamen >= 0) close(plamen);
        if (share >= 0) close(share);
        if (result != 0) errno = saved;
        return result;
    }
}

static void
digest_hex(const uint8_t digest[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32U; ++index) {
        output[index * 2U] = digits[digest[index] >> 4];
        output[index * 2U + 1U] = digits[digest[index] & 15U];
    }
    output[64] = '\0';
}

static int
open_child_directory(int parent, const char *name)
{
    return openat(parent, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

static int
directory_entries_exact(int directory_fd, const char *const *names,
    size_t name_count)
{
    DIR *directory = NULL;
    struct dirent *entry;
    uint64_t seen = 0;
    int iteration = -1, result = -1;
    size_t index;
    if (name_count == 0 || name_count > 63U
        || (iteration = duplicate_cloexec(directory_fd)) < 0
        || (directory = fdopendir(iteration)) == NULL)
        goto done;
    iteration = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0
            || strcmp(entry->d_name, "..") == 0)
            continue;
        for (index = 0; index < name_count; ++index)
            if (strcmp(entry->d_name, names[index]) == 0)
                break;
        if (index == name_count || (seen & (UINT64_C(1) << index)) != 0)
            goto done;
        seen |= UINT64_C(1) << index;
    }
    if (errno != 0 || seen != ((UINT64_C(1) << name_count) - 1U))
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (directory != NULL) closedir(directory);
        else if (iteration >= 0) close(iteration);
        if (result != 0) errno = saved;
        return result;
    }
}

static int
validate_generation_layout(int generation_fd)
{
    static const char *const root_names[] = {
        "Library", "bin", "lib", "libexec", "share"
    };
    static const char *const bin_names[] = {
        "plamen-native-launcher", "python3.12"
    };
    static const char *const lib_names[] = { "plamen" };
    static const char *const plamen_lib_names[] = {
        "_plamen_native_supervisor.cpython-312-darwin.so",
        "plamen-audit-broker-v2", "runtime"
    };
    static const char *const share_names[] = { "plamen" };
    static const char *const plamen_share_names[] = {
        "native-supervisor-schema-v2.json", "plamen_broker_v2.h",
        "runtime-package-manifest-v2.bin"
    };
    static const char *const library_names[] = { "LaunchAgents" };
    static const char *const libexec_names[] = {
        "plamen-native-installer-v2",
        "plamen-native-source-bootstrap-coordinator-v1"
    };
    static const char *const launch_agents_names[] = {
        BROKER_PLIST, CUSTODY_PLIST
    };
    int bin = -1, lib = -1, libexec = -1, plamen_lib = -1, share = -1;
    int plamen_share = -1, library = -1, agents = -1, result = -1;
    if (directory_entries_exact(generation_fd, root_names,
            sizeof(root_names) / sizeof(root_names[0])) != 0
        || (bin = open_child_directory(generation_fd, "bin")) < 0
        || directory_entries_exact(bin, bin_names,
            sizeof(bin_names) / sizeof(bin_names[0])) != 0
        || (lib = open_child_directory(generation_fd, "lib")) < 0
        || directory_entries_exact(lib, lib_names,
            sizeof(lib_names) / sizeof(lib_names[0])) != 0
        || (plamen_lib = open_child_directory(lib, "plamen")) < 0
        || directory_entries_exact(plamen_lib, plamen_lib_names,
            sizeof(plamen_lib_names) / sizeof(plamen_lib_names[0])) != 0
        || (libexec = open_child_directory(generation_fd, "libexec")) < 0
        || directory_entries_exact(libexec, libexec_names,
            sizeof(libexec_names) / sizeof(libexec_names[0])) != 0
        || (share = open_child_directory(generation_fd, "share")) < 0
        || directory_entries_exact(share, share_names,
            sizeof(share_names) / sizeof(share_names[0])) != 0
        || (plamen_share = open_child_directory(share, "plamen")) < 0
        || directory_entries_exact(plamen_share, plamen_share_names,
            sizeof(plamen_share_names) / sizeof(plamen_share_names[0])) != 0
        || (library = open_child_directory(generation_fd, "Library")) < 0
        || directory_entries_exact(library, library_names,
            sizeof(library_names) / sizeof(library_names[0])) != 0
        || (agents = open_child_directory(library, "LaunchAgents")) < 0
        || directory_entries_exact(agents, launch_agents_names,
            sizeof(launch_agents_names) / sizeof(launch_agents_names[0])) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (agents >= 0) close(agents); if (library >= 0) close(library);
        if (plamen_share >= 0) close(plamen_share);
        if (share >= 0) close(share); if (plamen_lib >= 0) close(plamen_lib);
        if (libexec >= 0) close(libexec);
        if (lib >= 0) close(lib); if (bin >= 0) close(bin);
        if (result != 0) errno = saved;
        return result;
    }
}

static int
validate_runtime_package(int generation_fd, uid_t owner)
{
    struct plamen_runtime_package_manifest_result_v2 observed;
    int lib = -1, plamen_lib = -1, runtime = -1;
    int share = -1, plamen_share = -1, manifest = -1, result = -1;
    memset(&observed, 0, sizeof(observed));
    if ((lib = open_child_directory(generation_fd, "lib")) < 0
        || (plamen_lib = open_child_directory(lib, "plamen")) < 0
        || (runtime = open_child_directory(plamen_lib, "runtime")) < 0
        || (share = open_child_directory(generation_fd, "share")) < 0
        || (plamen_share = open_child_directory(share, "plamen")) < 0
        || (manifest = openat(plamen_share,
            "runtime-package-manifest-v2.bin",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || plamen_runtime_package_manifest_revalidate_v2(runtime, manifest,
            owner, &observed) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (manifest >= 0) close(manifest);
        if (plamen_share >= 0) close(plamen_share);
        if (share >= 0) close(share);
        if (runtime >= 0) close(runtime);
        if (plamen_lib >= 0) close(plamen_lib);
        if (lib >= 0) close(lib);
        memset(&observed, 0, sizeof(observed));
        if (result != 0) errno = saved;
        return result;
    }
}

static int
open_generation_from_receipt(struct coordinator_context *context,
    const struct plamen_install_receipt *receipt, int *generation_fd)
{
    char hex[65], expected[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1U];
    int generations = -1, generation = -1;
    digest_hex(receipt->generation_id_sha256, hex);
    if (snprintf(expected, sizeof(expected), "%s/generations/%s",
            context->root_path, hex) >= (int)sizeof(expected)
        || strcmp(expected, receipt->generation_path) != 0)
        goto done;
    generations = open_child_directory(context->root_fd, "generations");
    if (generations < 0)
        goto done;
    generation = open_child_directory(generations, hex);
    if (generation < 0)
        goto done;
    *generation_fd = generation; generation = -1;
done:
    {
        int saved = *generation_fd >= 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (generation >= 0) close(generation);
        if (generations >= 0) close(generations);
        memset(hex, 0, sizeof(hex)); memset(expected, 0, sizeof(expected));
        if (*generation_fd < 0) errno = saved;
        return *generation_fd >= 0 ? 0 : -1;
    }
}

static int
open_plists(int generation_fd, int *broker_fd, int *custody_fd)
{
    int library = -1, agents = -1, broker = -1, custody = -1;
    library = open_child_directory(generation_fd, "Library");
    if (library < 0 || (agents = open_child_directory(library,
            "LaunchAgents")) < 0
        || (broker = openat(agents, BROKER_PLIST,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || (custody = openat(agents, CUSTODY_PLIST,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0)
        goto done;
    *broker_fd = broker; broker = -1;
    *custody_fd = custody; custody = -1;
done:
    {
        int result = *broker_fd >= 0 && *custody_fd >= 0 ? 0 : -1;
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (custody >= 0) close(custody); if (broker >= 0) close(broker);
        if (agents >= 0) close(agents); if (library >= 0) close(library);
        if (result != 0) errno = saved;
        return result;
    }
}

static int
open_receipt_named(struct coordinator_context *context, const char *name,
    struct plamen_install_receipt *receipt, int *receipt_fd)
{
    int share = -1, plamen = -1, opened = -1;
    share = open_child_directory(context->root_fd, "share");
    if (share < 0 || (plamen = open_child_directory(share, "plamen")) < 0
        || (opened = openat(plamen, name,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || read_receipt(opened, context->owner, receipt) != 0)
        goto done;
    *receipt_fd = opened; opened = -1;
done:
    {
        int result = *receipt_fd >= 0 ? 0 : -1;
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (opened >= 0) close(opened); if (plamen >= 0) close(plamen);
        if (share >= 0) close(share);
        if (result != 0) errno = saved;
        return result;
    }
}

static void
close_closures(struct coordinator_context *context)
{
    int *descriptors[] = {
        &context->replacement_generation_fd,
        &context->replacement_broker_plist_fd,
        &context->replacement_custody_plist_fd,
        &context->prior_generation_fd,
        &context->prior_broker_plist_fd,
        &context->prior_custody_plist_fd,
    };
    size_t index;
    for (index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]);
            ++index) {
        if (*descriptors[index] >= 0) close(*descriptors[index]);
        *descriptors[index] = -1;
    }
    memset(&context->replacement_receipt, 0,
        sizeof(context->replacement_receipt));
    memset(&context->prior_receipt, 0, sizeof(context->prior_receipt));
    memset(&context->transaction.replacement, 0,
        sizeof(context->transaction.replacement));
    memset(&context->transaction.prior, 0,
        sizeof(context->transaction.prior));
    context->transaction.prior_present = 0;
}

static void
bind_transaction_closures(struct coordinator_context *context,
    int prior_present)
{
    context->transaction.replacement.receipt =
        &context->replacement_receipt;
    context->transaction.replacement.generation_fd =
        context->replacement_generation_fd;
    context->transaction.replacement.broker_plist_fd =
        context->replacement_broker_plist_fd;
    context->transaction.replacement.custody_plist_fd =
        context->replacement_custody_plist_fd;
    context->transaction.prior_present = prior_present;
    if (prior_present) {
        context->transaction.prior.receipt = &context->prior_receipt;
        context->transaction.prior.generation_fd = context->prior_generation_fd;
        context->transaction.prior.broker_plist_fd =
            context->prior_broker_plist_fd;
        context->transaction.prior.custody_plist_fd =
            context->prior_custody_plist_fd;
    }
}

static int
load_named_closure(struct coordinator_context *context, const char *receipt_name,
    struct plamen_install_receipt *receipt, int *generation_fd,
    int *broker_fd, int *custody_fd)
{
    int receipt_fd = -1;
    if (open_receipt_named(context, receipt_name, receipt, &receipt_fd) != 0
        || open_generation_from_receipt(context, receipt, generation_fd) != 0
        || open_plists(*generation_fd, broker_fd, custody_fd) != 0
        || plamen_native_darwin_validate_signed_closure_v2(receipt,
            *generation_fd) != 0
        || validate_runtime_package(*generation_fd, context->owner) != 0
        || plamen_native_launchd_validate_deployment_v2(receipt,
            *generation_fd, *broker_fd, *custody_fd) != 0) {
        int saved = errno == 0 ? EPERM : errno;
        if (receipt_fd >= 0) close(receipt_fd);
        errno = saved; return -1;
    }
    close(receipt_fd);
    return 0;
}

static int
coordinator_bind_recovery(void *opaque, uint32_t state,
    const uint8_t generation_id[32], int marker_prior_present)
{
    struct coordinator_context *context = opaque;
    int prior_present;
    if (context == NULL
        || (state & ~DEPLOYMENT_STATE_PRIOR_LOADED) != DEPLOYMENT_STATE_MAGIC) {
        errno = ENOTRECOVERABLE; return -1;
    }
    prior_present = (state & DEPLOYMENT_STATE_PRIOR_LOADED) != 0;
    if (prior_present != marker_prior_present) {
        errno = ENOTRECOVERABLE; return -1;
    }
    close_closures(context);
    if (load_named_closure(context, ACTIVE_RECEIPT,
            &context->replacement_receipt,
            &context->replacement_generation_fd,
            &context->replacement_broker_plist_fd,
            &context->replacement_custody_plist_fd) != 0
        || (prior_present && load_named_closure(context, ROLLBACK_RECEIPT,
            &context->prior_receipt, &context->prior_generation_fd,
            &context->prior_broker_plist_fd,
            &context->prior_custody_plist_fd) != 0)
        || memcmp(context->replacement_receipt.generation_id_sha256,
            generation_id, 32U) != 0) {
        errno = ENOTRECOVERABLE;
        return -1;
    }
    bind_transaction_closures(context, prior_present);
    return 0;
}

static int wrapper_prepare(void *p, uint32_t *s)
{
    struct coordinator_context *c = p;
    return validate_generation_layout(
            c->transaction.replacement.generation_fd) == 0
        && validate_runtime_package(
            c->transaction.replacement.generation_fd, c->owner) == 0
        && plamen_native_darwin_validate_signed_closure_v2(
            c->transaction.replacement.receipt,
            c->transaction.replacement.generation_fd) == 0
        ? c->launchd.prepare(c->launchd.context, s) : -1;
}
static int wrapper_activate(void *p, uint32_t s)
{ struct coordinator_context *c = p; return c->launchd.activate(c->launchd.context, s); }
static int wrapper_rollback(void *p, uint32_t s)
{ struct coordinator_context *c = p; return c->launchd.rollback(c->launchd.context, s); }
static int wrapper_restore(void *p, uint32_t s)
{
    struct coordinator_context *c = p;
    return c->launchd.restore(c->launchd.context, s) == 0
        && restore_deployment_receipt(c) == 0 ? 0 : -1;
}
static int wrapper_commit(void *p, uint32_t s)
{
    struct coordinator_context *c = p;
    return c->launchd.commit(c->launchd.context, s) == 0
        && persist_deployment_receipt(c) == 0 ? 0 : -1;
}

static int
context_init(struct coordinator_context *context, int root_fd,
    const char *root_path, uid_t owner,
    const struct plamen_native_launchd_effects_v2 *effects)
{
    memset(context, 0, sizeof(*context));
    context->root_fd = duplicate_cloexec(root_fd);
    context->root_path = root_path; context->owner = owner;
    context->replacement_generation_fd = -1;
    context->replacement_broker_plist_fd = -1;
    context->replacement_custody_plist_fd = -1;
    context->prior_generation_fd = -1;
    context->prior_broker_plist_fd = -1;
    context->prior_custody_plist_fd = -1;
    context->transaction.owner_uid = owner;
    if (context->root_fd < 0)
        return -1;
    if (effects == NULL) {
        if (plamen_native_launchd_production_effects_v2(
                &context->transaction) != 0)
            goto invalid;
    } else {
        context->transaction.effects = *effects;
    }
    if (plamen_native_launchd_deployment_hooks_v2(&context->transaction,
            &context->launchd) != 0)
        goto invalid;
    context->wrapper.context = context;
    context->wrapper.bind_recovery = coordinator_bind_recovery;
    context->wrapper.prepare = wrapper_prepare;
    context->wrapper.activate = wrapper_activate;
    context->wrapper.rollback = wrapper_rollback;
    context->wrapper.restore = wrapper_restore;
    context->wrapper.commit = wrapper_commit;
    return 0;
invalid:
    {
        int saved = errno == 0 ? EIO : errno;
        if (context->root_fd >= 0) close(context->root_fd);
        memset(context, 0, sizeof(*context));
        errno = saved;
        return -1;
    }
}

static void
context_dispose(struct coordinator_context *context)
{
    close_closures(context);
    if (context->root_fd >= 0) close(context->root_fd);
    memset(context, 0, sizeof(*context));
}

static int
recover_internal(int root_fd, const char *root_path, uid_t owner,
    const struct plamen_native_launchd_effects_v2 *effects, int *recovered)
{
    struct coordinator_context context;
    int result;
    if (context_init(&context, root_fd, root_path, owner, effects) != 0)
        return -1;
    result = plamen_native_installer_recover_with_deployment_v2(root_fd,
        root_path, owner, &context.wrapper, recovered);
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        context_dispose(&context); if (result != 0) errno = saved;
    }
    return result;
}

static int
load_active_prior(struct coordinator_context *context)
{
    int receipt_fd = -1;
    if (open_receipt_named(context, ACTIVE_RECEIPT,
            &context->prior_receipt, &receipt_fd) != 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    close(receipt_fd);
    if (open_generation_from_receipt(context, &context->prior_receipt,
            &context->prior_generation_fd) != 0
        || open_plists(context->prior_generation_fd,
            &context->prior_broker_plist_fd,
            &context->prior_custody_plist_fd) != 0
        || plamen_native_darwin_validate_signed_closure_v2(
            &context->prior_receipt, context->prior_generation_fd) != 0
        || validate_runtime_package(context->prior_generation_fd,
            context->owner) != 0
        || plamen_native_launchd_validate_deployment_v2(
            &context->prior_receipt, context->prior_generation_fd,
            context->prior_broker_plist_fd,
            context->prior_custody_plist_fd) != 0)
        return -1;
    return 1;
}

static int
validate_terminal_deployment_receipt(struct coordinator_context *context,
    const struct plamen_install_receipt *receipt)
{
    int share = -1, plamen = -1, retained = -1, result = -1;
    if (context == NULL || receipt == NULL
        || (share = open_child_directory(context->root_fd, "share")) < 0
        || (plamen = open_child_directory(share, "plamen")) < 0
        || (retained = openat(plamen, DEPLOYMENT_RECEIPT,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || plamen_native_darwin_deployment_receipt_validate_v2(
            retained, receipt) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (retained >= 0) close(retained);
        if (plamen >= 0) close(plamen);
        if (share >= 0) close(share);
        if (result != 0) errno = saved;
        return result;
    }
}

static int
validate_installed_internal(int root_fd, const char *root_path, uid_t owner,
    int expected_receipt_fd,
    const struct plamen_native_launchd_effects_v2 *effects)
{
    struct coordinator_context context;
    struct plamen_install_receipt expected;
    int loaded = -1, result = -1;
    memset(&expected, 0, sizeof(expected));
    if (plamen_native_installer_validate_installed_v2(root_fd, root_path,
            owner, expected_receipt_fd) != 0
        || read_receipt(expected_receipt_fd, owner, &expected) != 0
        || context_init(&context, root_fd, root_path, owner, effects) != 0)
        return -1;
    loaded = load_active_prior(&context);
    if (loaded != 1
        || memcmp(expected.generation_id_sha256,
            context.prior_receipt.generation_id_sha256, 32U) != 0
        || memcmp(expected.receipt_sha256,
            context.prior_receipt.receipt_sha256, 32U) != 0
        || validate_terminal_deployment_receipt(
            &context, &context.prior_receipt) != 0)
        goto done;
    /* Rebind the authenticated active closure as the launchd replacement so
     * the ordinary commit validator proves both jobs loaded and receipt-bound
     * readiness without performing a deployment effect. */
    context.transaction.replacement.receipt = &context.prior_receipt;
    context.transaction.replacement.generation_fd =
        context.prior_generation_fd;
    context.transaction.replacement.broker_plist_fd =
        context.prior_broker_plist_fd;
    context.transaction.replacement.custody_plist_fd =
        context.prior_custody_plist_fd;
    if (context.launchd.commit(context.launchd.context,
            DEPLOYMENT_STATE_MAGIC) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        context_dispose(&context);
        memset(&expected, 0, sizeof(expected));
        if (result != 0) errno = saved;
        return result;
    }
}

static int
validate_absent_deployment(struct coordinator_context *context)
{
    int share = -1, plamen = -1, receipt = -1;
    int broker_status = -1, custody_status = -1, result = -1;
    if (context == NULL || context->transaction.effects.run == NULL
        || (share = open_child_directory(context->root_fd, "share")) < 0
        || (plamen = open_child_directory(share, "plamen")) < 0)
        goto done;
    receipt = openat(plamen, DEPLOYMENT_RECEIPT,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (receipt >= 0 || errno != ENOENT)
        goto done;
    if (context->transaction.effects.run(
            context->transaction.effects.context, context->owner,
            PLAMEN_LAUNCHD_ROLE_BROKER_V2, PLAMEN_LAUNCHD_PRINT_V2,
            NULL, &broker_status) != 0
        || context->transaction.effects.run(
            context->transaction.effects.context, context->owner,
            PLAMEN_LAUNCHD_ROLE_CUSTODY_V2, PLAMEN_LAUNCHD_PRINT_V2,
            NULL, &custody_status) != 0
        || broker_status != 113 || custody_status != 113)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (receipt >= 0) close(receipt);
        if (plamen >= 0) close(plamen);
        if (share >= 0) close(share);
        if (result != 0) errno = saved;
        return result;
    }
}

static int
finalize_committed_internal(int root_fd, const char *root_path, uid_t owner,
    int expected_successor_receipt_fd,
    const struct plamen_native_launchd_effects_v2 *effects)
{
    struct coordinator_context context;
    int result;
    if (context_init(&context, root_fd, root_path, owner, effects) != 0)
        return -1;
    result = plamen_native_installer_finalize_committed_v2(root_fd,
        root_path, owner, expected_successor_receipt_fd, &context.wrapper);
    if (result == 0)
        result = validate_installed_internal(root_fd, root_path, owner,
            expected_successor_receipt_fd, effects);
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        context_dispose(&context);
        if (result != 0) errno = saved;
    }
    return result;
}

static int
rollback_committed_internal(int root_fd, const char *root_path, uid_t owner,
    int expected_successor_receipt_fd, int expected_prior_receipt_fd,
    int expected_prior_present,
    const struct plamen_native_launchd_effects_v2 *effects)
{
    struct coordinator_context context;
    int result;
    if (context_init(&context, root_fd, root_path, owner, effects) != 0)
        return -1;
    result = plamen_native_installer_rollback_committed_v2(root_fd,
        root_path, owner, expected_successor_receipt_fd,
        expected_prior_receipt_fd, expected_prior_present, &context.wrapper);
    if (result == 0) {
        if (expected_prior_present)
            result = validate_installed_internal(root_fd, root_path, owner,
                expected_prior_receipt_fd, effects);
        else
            result = validate_absent_deployment(&context);
    }
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        context_dispose(&context);
        if (result != 0) errno = saved;
    }
    return result;
}

static int
publish_internal(const struct plamen_native_install_request_v2 *request,
    const struct plamen_native_launchd_effects_v2 *effects,
    struct plamen_native_install_result_v2 *result)
{
    struct coordinator_context context;
    struct plamen_native_install_request_v2 bound;
    int recovered = 0, prior_present, generation = -1;
    int broker = -1, custody = -1, completed = 0;
    if (request == NULL || request->deployment != NULL) {
        errno = EINVAL; return -1;
    }
    if (recover_internal(request->install_root_fd,
            request->install_root_absolute, request->owner_uid, effects,
            &recovered) != 0
        || context_init(&context, request->install_root_fd,
            request->install_root_absolute, request->owner_uid, effects) != 0)
        return -1;
    generation = openat(request->staging_parent_fd,
        request->staged_generation_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (generation < 0 && errno == ENOENT) {
        int generations = open_child_directory(request->install_root_fd,
            "generations");
        if (generations >= 0) {
            generation = openat(generations, request->generation_id_hex,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            close(generations);
        }
    }
    if (generation < 0
        || open_plists(generation, &broker, &custody) != 0
        || read_receipt(request->receipt_fd, request->owner_uid,
            &context.replacement_receipt) != 0)
        goto done;
    context.replacement_generation_fd = generation; generation = -1;
    context.replacement_broker_plist_fd = broker; broker = -1;
    context.replacement_custody_plist_fd = custody; custody = -1;
    prior_present = load_active_prior(&context);
    if (prior_present < 0) goto done;
    bind_transaction_closures(&context, prior_present);
    bound = *request; bound.deployment = &context.wrapper;
    if (plamen_native_installer_publish_v2(&bound, result) != 0)
        goto done;
    if (result != NULL && recovered)
        result->recovered_prior_transaction = 1;
    completed = 1;
done:
    {
        int saved = completed ? 0 : (errno == 0 ? EIO : errno);
        if (custody >= 0) close(custody); if (broker >= 0) close(broker);
        if (generation >= 0) close(generation);
        context_dispose(&context); if (!completed) errno = saved;
        return completed ? 0 : -1;
    }
}

int
plamen_native_darwin_install_publish_v2(
    const struct plamen_native_install_request_v2 *request,
    struct plamen_native_install_result_v2 *result)
{
    return publish_internal(request, NULL, result);
}

int
plamen_native_darwin_install_recover_v2(int root_fd,
    const char *root_path, uid_t owner, int *recovered)
{
    return recover_internal(root_fd, root_path, owner, NULL, recovered);
}

int
plamen_native_darwin_install_validate_installed_v2(int root_fd,
    const char *root_path, uid_t owner, int expected_receipt_fd)
{
    return validate_installed_internal(root_fd, root_path, owner,
        expected_receipt_fd, NULL);
}

int
plamen_native_darwin_install_finalize_committed_v2(int root_fd,
    const char *root_path, uid_t owner, int expected_successor_receipt_fd)
{
    return finalize_committed_internal(root_fd, root_path, owner,
        expected_successor_receipt_fd, NULL);
}

int
plamen_native_darwin_install_rollback_committed_v2(int root_fd,
    const char *root_path, uid_t owner, int expected_successor_receipt_fd,
    int expected_prior_receipt_fd, int expected_prior_present)
{
    return rollback_committed_internal(root_fd, root_path, owner,
        expected_successor_receipt_fd, expected_prior_receipt_fd,
        expected_prior_present, NULL);
}

#ifdef PLAMEN_NATIVE_INSTALL_COORDINATOR_V2_TESTING
int
plamen_native_darwin_install_publish_with_effects_v2(
    const struct plamen_native_install_request_v2 *request,
    const struct plamen_native_launchd_effects_v2 *effects,
    struct plamen_native_install_result_v2 *result)
{
    if (effects == NULL || effects->run == NULL || effects->ready == NULL) {
        errno = EINVAL; return -1;
    }
    return publish_internal(request, effects, result);
}

int
plamen_native_darwin_install_recover_with_effects_v2(int root_fd,
    const char *root_path, uid_t owner,
    const struct plamen_native_launchd_effects_v2 *effects, int *recovered)
{
    if (effects == NULL || effects->run == NULL || effects->ready == NULL) {
        errno = EINVAL; return -1;
    }
    return recover_internal(root_fd, root_path, owner, effects, recovered);
}

int
plamen_native_darwin_install_validate_installed_with_effects_v2(int root_fd,
    const char *root_path, uid_t owner, int expected_receipt_fd,
    const struct plamen_native_launchd_effects_v2 *effects)
{
    if (effects == NULL || effects->run == NULL || effects->ready == NULL) {
        errno = EINVAL; return -1;
    }
    return validate_installed_internal(root_fd, root_path, owner,
        expected_receipt_fd, effects);
}

int
plamen_native_darwin_install_finalize_committed_with_effects_v2(int root_fd,
    const char *root_path, uid_t owner, int expected_successor_receipt_fd,
    const struct plamen_native_launchd_effects_v2 *effects)
{
    if (effects == NULL || effects->run == NULL || effects->ready == NULL) {
        errno = EINVAL; return -1;
    }
    return finalize_committed_internal(root_fd, root_path, owner,
        expected_successor_receipt_fd, effects);
}

int
plamen_native_darwin_install_rollback_committed_with_effects_v2(int root_fd,
    const char *root_path, uid_t owner, int expected_successor_receipt_fd,
    int expected_prior_receipt_fd, int expected_prior_present,
    const struct plamen_native_launchd_effects_v2 *effects)
{
    if (effects == NULL || effects->run == NULL || effects->ready == NULL) {
        errno = EINVAL; return -1;
    }
    return rollback_committed_internal(root_fd, root_path, owner,
        expected_successor_receipt_fd, expected_prior_receipt_fd,
        expected_prior_present, effects);
}
#endif

#ifdef PLAMEN_NATIVE_INSTALL_COORDINATOR_V2_MAIN
int
main(int argc, char **argv)
{
    static const char capabilities[] =
        "PLAMEN_NATIVE_INSTALL_COORDINATOR_V2 specialized-derived-v1 "
        "source-bootstrap-derived-v1\n";
    struct plamen_native_install_request_v2 request;
    struct plamen_native_install_result_v2 result;
    struct plamen_install_receipt receipt;
    int root = -1, stage_parent = -1, receipt_fd = -1, generation = -1;
    int prior_receipt_fd = -1;
    int recovered = 0, status = 75;
    size_t index;
    memset(&request, 0, sizeof(request)); memset(&result, 0, sizeof(result));
    memset(&receipt, 0, sizeof(receipt));
    for (index = 0; index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT; ++index)
        request.generation_member_fds[index] = -1;
    if (argc == 2 && strcmp(argv[1], "capabilities-v2") == 0) {
        if (write(STDOUT_FILENO, capabilities,
                sizeof(capabilities) - 1U) == (ssize_t)(sizeof(capabilities) - 1U))
            status = 0;
        goto done;
    }
    if (argc > 1 && (strcmp(argv[1], "prepare-publish-fds") == 0
            || strcmp(argv[1], "prepare-publish-derived-fds") == 0
            || strcmp(argv[1], "prepare-publish-retained-derived-fds") == 0
            || strcmp(argv[1],
                "prepare-publish-source-bootstrap-derived-fds") == 0
            || strcmp(argv[1],
                "prepare-publish-retained-source-bootstrap-derived-fds") == 0
            || strcmp(argv[1],
                "prepare-publish-specialized-derived-fds") == 0
            || strcmp(argv[1],
                "prepare-publish-retained-specialized-derived-fds") == 0
            || strcmp(argv[1],
                "prepare-publish-specialized-source-bootstrap-derived-fds") == 0
            || strcmp(argv[1],
                "prepare-publish-retained-specialized-source-bootstrap-derived-fds") == 0
            || strcmp(argv[1],
                "resume-publish-specialized-derived-fds") == 0
            || strcmp(argv[1],
                "resume-publish-specialized-source-bootstrap-derived-fds") == 0)) {
        if (prepare_publish_fds_cli(argc, argv) == 0)
            status = 0;
        else
            status = errno == EINPROGRESS ? 76 : 75;
        goto done;
    }
    if (argc == 5 && strcmp(argv[1], "validate-installed-fd") == 0) {
        root = parse_inherited_fd(argv[2]);
        receipt_fd = parse_inherited_fd(argv[3]);
        if (root >= 0 && receipt_fd >= 0
            && plamen_native_darwin_install_validate_installed_v2(root,
                argv[4], getuid(), receipt_fd) == 0)
            status = 0;
        goto done;
    }
    if (argc == 5 && strcmp(argv[1], "finalize-committed-fds") == 0) {
        root = parse_inherited_fd(argv[2]);
        receipt_fd = parse_inherited_fd(argv[3]);
        if (root >= 0 && receipt_fd >= 0
            && plamen_native_darwin_install_finalize_committed_v2(root,
                argv[4], getuid(), receipt_fd) == 0)
            status = 0;
        goto done;
    }
    if (argc == 6 && strcmp(argv[1], "rollback-committed-fds") == 0) {
        root = parse_inherited_fd(argv[2]);
        receipt_fd = parse_inherited_fd(argv[3]);
        if (strcmp(argv[4], "-") != 0)
            prior_receipt_fd = parse_inherited_fd(argv[4]);
        if (root >= 0 && receipt_fd >= 0
            && (strcmp(argv[4], "-") == 0 || prior_receipt_fd >= 0)
            && plamen_native_darwin_install_rollback_committed_v2(root,
                argv[5], getuid(), receipt_fd, prior_receipt_fd,
                strcmp(argv[4], "-") != 0) == 0)
            status = 0;
        goto done;
    }
    if (argc == 4 && strcmp(argv[1], "recover-fd") == 0) {
        root = parse_inherited_fd(argv[2]);
        if (root >= 0 && plamen_native_darwin_install_recover_v2(root,
                argv[3], getuid(), &recovered) == 0)
            status = 0;
        goto done;
    }
    if (argc != 8 || (strcmp(argv[1], "publish-fds") != 0
            && strcmp(argv[1], "publish-retained-fds") != 0))
        goto done;
    root = parse_inherited_fd(argv[2]);
    stage_parent = parse_inherited_fd(argv[3]);
    receipt_fd = parse_inherited_fd(argv[4]);
    if (root < 0 || stage_parent < 0 || receipt_fd < 0
        || read_receipt(receipt_fd, getuid(), &receipt) != 0)
        goto done;
    generation = openat(stage_parent, argv[6],
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (generation < 0) {
        int generations = open_child_directory(root, "generations");
        if (generations >= 0) {
            generation = openat(generations, argv[7],
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            close(generations);
        }
    }
    if (generation < 0)
        goto done;
    for (index = 0; index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT;
            ++index) {
        if (plamen_install_receipt_open_member(generation,
                &receipt.members[index],
                &request.generation_member_fds[index]) != 0)
            goto done;
    }
    request.install_root_fd = root;
    request.staging_parent_fd = stage_parent;
    request.receipt_fd = receipt_fd;
    request.install_root_absolute = argv[5];
    request.staged_generation_name = argv[6];
    request.generation_id_hex = argv[7];
    request.owner_uid = getuid();
    request.retain_postcommit_rollback =
        strcmp(argv[1], "publish-retained-fds") == 0;
    if (plamen_native_darwin_install_publish_v2(&request, &result) == 0)
        status = 0;
done:
    for (index = 0; index < PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT; ++index)
        if (request.generation_member_fds[index] >= 0)
            close(request.generation_member_fds[index]);
    if (generation >= 0) close(generation);
    memset(&receipt, 0, sizeof(receipt)); memset(&request, 0, sizeof(request));
    if (status != 0 && status != 76) coordinator_cli_diagnostic();
    return status;
}
#endif
