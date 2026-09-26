#ifndef PLAMEN_NATIVE_BUILDER_V2_H
#define PLAMEN_NATIVE_BUILDER_V2_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_VERSION 2U
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE 256U
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE 2048U
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE 640U
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_TRAILER_SIZE 32U
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_COUNT 14U
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES 8192U
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES 512U
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH 64U
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES (64ULL * 1024ULL * 1024ULL)
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_MAX_TOTAL_BYTES (512ULL * 1024ULL * 1024ULL)
#define PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_REFERENCE_BYTES 512U
#define PLAMEN_RUNTIME_PACKAGE_SPECIALIZED_AUTHORITY_V2_SIZE 256U
#define PLAMEN_RUNTIME_PACKAGE_SPECIALIZED_RECEIPT_PATH_V2 \
    "share/plamen/image-member-receipt-v2.bin"
#define PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2 10U
#define PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2 32U
#define PLAMEN_INTRINSIC_GENERATION_MAX_PATH_BYTES_V2 255U
#define PLAMEN_DARWIN_INSTALL_RECEIPT_SIZE_V2 16384U
#define PLAMEN_DARWIN_INSTALL_RECEIPT_HASHED_SIZE_V2 16352U
#define PLAMEN_DARWIN_INSTALL_RECEIPT_SIGNING_ID_MAX_V2 128U
#define PLAMEN_DARWIN_INSTALL_RECEIPT_TEAM_ID_MAX_V2 128U
#define PLAMEN_DARWIN_INSTALL_RECEIPT_CDHASH_MAX_V2 32U

enum plamen_runtime_package_target_arch_v2 {
    PLAMEN_RUNTIME_PACKAGE_TARGET_ARCH_ARM64_V2 = 1,
    PLAMEN_RUNTIME_PACKAGE_TARGET_ARCH_AMD64_V2 = 2
};

enum plamen_runtime_package_digest_v2 {
    PLAMEN_RUNTIME_PACKAGE_OCI_INDEX_V2 = 0,
    PLAMEN_RUNTIME_PACKAGE_IMAGE_MANIFEST_V2 = 1,
    PLAMEN_RUNTIME_PACKAGE_OCI_CONFIG_V2 = 2,
    PLAMEN_RUNTIME_PACKAGE_IMAGE_CLOSURE_V2 = 3,
    PLAMEN_RUNTIME_PACKAGE_APPLE_CONTAINER_CONFIGURATION_V2 = 4,
    PLAMEN_RUNTIME_PACKAGE_SECCOMP_PROFILE_V2 = 5,
    PLAMEN_RUNTIME_PACKAGE_BAKED_TOOLCHAIN_CLOSURE_V2 = 6,
    PLAMEN_RUNTIME_PACKAGE_OCI_LOCK_V2 = 7,
    PLAMEN_RUNTIME_PACKAGE_MATERIALIZATION_RECEIPT_V2 = 8,
    PLAMEN_RUNTIME_PACKAGE_ROOTFS_ARCHIVE_V2 = 9,
    PLAMEN_RUNTIME_PACKAGE_ROOTFS_DIFF_ID_V2 = 10,
    PLAMEN_RUNTIME_PACKAGE_CLOSURE_CENSUS_V2 = 11,
    PLAMEN_RUNTIME_PACKAGE_SBOM_V2 = 12,
    PLAMEN_RUNTIME_PACKAGE_PROVENANCE_V2 = 13
};

struct plamen_runtime_package_bindings_v2 {
    uint16_t target_arch;
    const char *oci_image_reference;
    size_t oci_image_reference_size;
    const char *oci_init_reference;
    size_t oci_init_reference_size;
    uint8_t digests[PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_COUNT][32];
    uint16_t specialized_present;
    const char *specialized_member_receipt_path;
    size_t specialized_member_receipt_path_size;
    uint8_t specialized_roster_sha256[32];
    uint8_t specialized_policy_self_sha256[32];
    uint8_t specialized_policy_bytes_sha256[32];
};

struct plamen_runtime_package_manifest_result_v2 {
    uint32_t entry_count;
    uint32_t directory_count;
    uint32_t file_count;
    uint64_t total_file_bytes;
    uint64_t manifest_size;
    uint8_t census_sha256[32];
    uint8_t tree_sha256[32];
    uint8_t manifest_sha256[32];
};

struct plamen_intrinsic_generation_member_v2 {
    uint16_t role;
    const char *relative_path;
    size_t relative_path_size;
    uint32_t mode;
    uint64_t size;
    uint8_t sha256[PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2];
};

struct plamen_darwin_code_identity_v2 {
    const char *signing_identifier;
    size_t signing_identifier_size;
    const char *team_identifier;
    size_t team_identifier_size;
    uint8_t cdhash[PLAMEN_DARWIN_INSTALL_RECEIPT_CDHASH_MAX_V2];
    uint16_t cdhash_size;
};

struct plamen_darwin_install_member_input_v2 {
    int fd;
    struct plamen_darwin_code_identity_v2 code_identity;
};

struct plamen_darwin_launchd_plist_input_v2 {
    int fd;
    const char *absolute_path;
    size_t absolute_path_size;
};

struct plamen_darwin_install_receipt_request_v2 {
    uint8_t projection_schema_sha256[32];
    uint8_t protocol_schema_sha256[32];
    uint16_t python_micro;
    const char *generation_absolute_path;
    size_t generation_absolute_path_size;
    struct plamen_darwin_launchd_plist_input_v2 broker_launchd_plist;
    struct plamen_darwin_launchd_plist_input_v2 custody_launchd_plist;
    struct plamen_darwin_install_member_input_v2
        members[PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2];
    uint16_t specialized_present;
    int specialized_member_receipt_fd;
    uint16_t source_bootstrap_present;
    int source_bootstrap_receipt_fd;
    /* Retained trusted key from the install-generation authority. */
    int source_bootstrap_producer_verifier_key_fd;
    void *source_bootstrap_receipt_context;
    /* Fixed native decoder; production never accepts a Python callback. */
    int (*source_bootstrap_receipt_validate)(void *context, int receipt_fd,
        uid_t owner_uid, uint8_t acquisition_roster_sha256[32],
        uint8_t producer_verifier_key_sha256[32],
        uint8_t installed_authority_roster_sha256[32]);
};

struct plamen_darwin_install_receipt_result_v2 {
    uint8_t generation_id[32];
    uint8_t intrinsic_roster_sha256[32];
    uint8_t install_precommit_sha256[32];
    uint8_t receipt_hashed_prefix_sha256[32];
    uint8_t full_receipt_sha256[32];
};

struct plamen_native_generation_stage_request_v2 {
    int staging_parent_fd;
    const char *staged_generation_name;
    uid_t owner_uid;
    /* Exact receipt role order.  Role 7 must be inside runtime_root_source_fd. */
    int member_source_fds[PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2];
    int runtime_root_source_fd;
    uint16_t specialized_present;
    int specialized_authority_source_fd;
    uint16_t source_bootstrap_present;
    int source_bootstrap_authority_source_fd;
};

struct plamen_native_generation_stage_result_v2 {
    int generation_root_fd;
    int runtime_root_fd;
    /* Exact receipt role order; every descriptor names the staged copy. */
    int generation_member_fds[PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2];
    int specialized_authority_fd;
    int source_bootstrap_authority_fd;
    uint8_t generation_id[PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2];
    uint8_t intrinsic_roster_sha256[
        PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2];
};

struct plamen_native_generation_deployment_stage_request_v2 {
    struct plamen_native_generation_stage_request_v2 generation;
    int broker_launchd_plist_fd;
    int custody_launchd_plist_fd;
};

struct plamen_native_generation_deployment_stage_result_v2 {
    struct plamen_native_generation_stage_result_v2 generation;
    int broker_launchd_plist_fd;
    int custody_launchd_plist_fd;
};

/*
 * Derive the acyclic generation ID from the exact ten receipt-order
 * members.  Deployment plist and receipt identities cannot be supplied here.
 */
int plamen_intrinsic_generation_id_v2(
    const struct plamen_intrinsic_generation_member_v2
        members[PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2],
    uint8_t generation_id[PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2]);

int plamen_intrinsic_generation_id_and_roster_v2(
    const struct plamen_intrinsic_generation_member_v2
        members[PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2],
    uint8_t generation_id[PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2],
    uint8_t intrinsic_roster_sha256[
        PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2]);

/*
 * Derive the intrinsic ID from the exact retained pre-stage sources.  Role 7
 * must be the same vnode as scripts/posix_audit_entrypoint.py below the
 * retained runtime root, and role 8 must revalidate that complete runtime.
 * The generation stager repeats the derivation from its private copies.
 */
int plamen_intrinsic_generation_id_from_sources_v2(
    int runtime_root_source_fd,
    const int member_source_fds[
        PLAMEN_INTRINSIC_GENERATION_MEMBER_COUNT_V2],
    uid_t owner_uid,
    uint8_t generation_id[PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2],
    uint8_t intrinsic_roster_sha256[
        PLAMEN_INTRINSIC_GENERATION_SHA256_SIZE_V2]);

/*
 * Materialize one private generation candidate from retained descriptors.
 * The staging parent and source descriptors are caller-owned.  On success the
 * result owns a retained 0700 generation-root FD, a retained 0500 runtime-root
 * FD, and ten retained member FDs; dispose closes only those returned FDs.
 * Every descendant directory is 0500 and every member has its receipt mode.
 * No receipt, launchd asset, stable path, or install state is published here.
 */
int plamen_native_generation_stage_v2(
    const struct plamen_native_generation_stage_request_v2 *request,
    struct plamen_native_generation_stage_result_v2 *result);

void plamen_native_generation_stage_result_dispose_v2(
    struct plamen_native_generation_stage_result_v2 *result);

/*
 * Extend the intrinsic ten-member stage with the two deployment-only
 * launchd plists.  The plist bytes are excluded from the intrinsic generation
 * ID, but are copied under Library/LaunchAgents, retained, and subsequently
 * bound by the install receipt before any publication effect.
 */
int plamen_native_generation_deployment_stage_v2(
    const struct plamen_native_generation_deployment_stage_request_v2 *,
    struct plamen_native_generation_deployment_stage_result_v2 *);

/*
 * Reopen a fully materialized private deployment stage and prove its exact
 * fixed census and bytes against the still-retained stage request.  This
 * never creates, removes, chmods, or publishes a path.
 */
int plamen_native_generation_deployment_stage_revalidate_v2(
    const struct plamen_native_generation_deployment_stage_request_v2 *,
    struct plamen_native_generation_deployment_stage_result_v2 *);

void plamen_native_generation_deployment_stage_result_dispose_v2(
    struct plamen_native_generation_deployment_stage_result_v2 *);

/*
 * Serialize the Darwin/arm64 CPython-3.12 receipt from retained artifact and
 * plist descriptors.  This derives both intrinsic digests, exact vnodes and
 * the precommit checkpoint; it never publishes install state.
 */
int plamen_darwin_install_receipt_encode_v2(
    const struct plamen_darwin_install_receipt_request_v2 *request,
    int output_fd,
    uid_t owner_uid,
    struct plamen_darwin_install_receipt_result_v2 *result);

/*
 * Render role 8 from an already-retained runtime-root descriptor.  output_fd
 * must be a caller-owned empty regular file opened read/write with nlink==1.
 * The function performs a before/after descriptor-relative census, writes the
 * exact binary ABI, fsyncs it, changes its mode to 0400, and leaves both input
 * descriptors owned by the caller.  It never installs or publishes anything.
 */
int plamen_runtime_package_manifest_render_v2(
    int runtime_root_fd,
    const struct plamen_runtime_package_bindings_v2 *bindings,
    int output_fd,
    uid_t owner_uid,
    struct plamen_runtime_package_manifest_result_v2 *result);

/* Strictly validate already-rendered bytes and optionally return its census. */
int plamen_runtime_package_manifest_decode_exact_v2(
    const uint8_t *bytes,
    size_t size,
    struct plamen_runtime_package_manifest_result_v2 *result);

/*
 * Strictly validate the complete role-8 manifest and return its fixed binding
 * block.  The two reference pointers in bindings_out borrow storage from
 * bytes and remain valid only while the caller keeps bytes alive and
 * unchanged.  Digest arrays and scalar fields are copied into bindings_out.
 */
int plamen_runtime_package_manifest_decode_bindings_exact_v2(
    const uint8_t *bytes,
    size_t size,
    struct plamen_runtime_package_manifest_result_v2 *result,
    struct plamen_runtime_package_bindings_v2 *bindings_out);

/*
 * Re-census runtime_root_fd, re-render in memory, and compare every byte with
 * manifest_fd.  Both descriptors remain caller-owned and retained.
 */
int plamen_runtime_package_manifest_revalidate_v2(
    int runtime_root_fd,
    int manifest_fd,
    uid_t owner_uid,
    struct plamen_runtime_package_manifest_result_v2 *result);

#ifdef __cplusplus
}
#endif

#endif
