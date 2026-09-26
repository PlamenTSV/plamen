#ifndef PLAMEN_NATIVE_SOURCE_BOOTSTRAP_COORDINATOR_V1_H
#define PLAMEN_NATIVE_SOURCE_BOOTSTRAP_COORDINATOR_V1_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_VERSION 1U
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT 11U
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT 5U
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT 24U
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE 8192U
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_HEADER_SIZE 512U
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROW_SIZE 384U
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_ROW_SIZE 128U
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_SIZE 32U
#define PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_MEMBER_COUNT 33U
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_RELATIVE_PATH \
    "share/plamen/native-source-bootstrap-coordinator-receipt-v1.bin"
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_EXECUTABLE_RELATIVE_PATH \
    "libexec/plamen-native-source-bootstrap-coordinator-v1"
#define PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SIGNING_IDENTIFIER \
    "com.plamen.audit.source-bootstrap.v1"

enum plamen_source_bootstrap_role_v1 {
    PLAMEN_SOURCE_BOOTSTRAP_BASE_ROOTFS_V1 = 0,
    PLAMEN_SOURCE_BOOTSTRAP_DEBIAN_PACKAGE_STATE_V1 = 1,
    PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_GUEST_V1 = 2,
    PLAMEN_SOURCE_BOOTSTRAP_CPYTHON_V1 = 3,
    PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_PACKAGE_V1 = 4,
    PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1 = 5,
    PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1 = 6,
    PLAMEN_SOURCE_BOOTSTRAP_FOUNDRY_V1 = 7,
    PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1 = 8,
    PLAMEN_SOURCE_BOOTSTRAP_SOLC_AMD64_V1 = 9,
    PLAMEN_SOURCE_BOOTSTRAP_AMD64_COMPAT_V1 = 10
};

enum plamen_source_bootstrap_output_role_v1 {
    PLAMEN_SOURCE_BOOTSTRAP_RUNTIME_ARCHIVE_V1 = 0,
    PLAMEN_SOURCE_BOOTSTRAP_MATERIALIZATION_OBSERVATION_V1 = 1,
    PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_CENSUS_V1 = 2,
    PLAMEN_SOURCE_BOOTSTRAP_SBOM_V1 = 3,
    PLAMEN_SOURCE_BOOTSTRAP_PROVENANCE_V1 = 4
};

enum plamen_source_bootstrap_installed_member_kind_v1 {
    PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PAYLOAD_V1 = 0,
    PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PRODUCER_RECEIPT_V1 = 1,
    PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_SOURCE_MANIFEST_V1 = 2
};

enum plamen_source_bootstrap_identity_mode_v1 {
    PLAMEN_SOURCE_BOOTSTRAP_STATIC_PAYLOAD_V1 = 1,
    PLAMEN_SOURCE_BOOTSTRAP_LATEST_BACKEND_RECEIPT_V1 = 2,
    PLAMEN_SOURCE_BOOTSTRAP_FROZEN_SOURCE_PROJECTION_V1 = 3
};

/* Stable, network-byte-order receipt projection of one retained regular FD. */
struct plamen_source_bootstrap_fd_identity_v1 {
    uint64_t device;
    uint64_t inode;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t links;
    uint64_t size;
    int64_t mtime_seconds;
    uint32_t mtime_nanoseconds;
    int64_t ctime_seconds;
    uint32_t ctime_nanoseconds;
    uint8_t sha256[32];
};

struct plamen_source_bootstrap_input_v1 {
    int payload_fd;
    int producer_receipt_fd;
    int source_manifest_fd;
    uint16_t identity_mode;
    uint16_t reserved;
    uint64_t expected_payload_size;
    uint8_t expected_payload_sha256[32];
    uint64_t expected_producer_receipt_size;
    uint8_t expected_producer_receipt_sha256[32];
    uint64_t expected_source_manifest_size;
    uint8_t expected_source_manifest_sha256[32];
    uint8_t policy_sha256[32];
};

struct plamen_source_bootstrap_policy_authority_v1 {
    void *context;
    /*
     * Production wires a coordinator-internal implementation backed by the
     * frozen signed/compiled release policy.  It must authenticate the
     * producer receipt semantics and the complete expected/observed tuple;
     * there is deliberately no CLI or Python callback selection surface.
     */
    int (*authenticate_source)(void *context, uint16_t role,
        int retained_producer_receipt_fd,
        const struct plamen_source_bootstrap_input_v1 *expected,
        const struct plamen_source_bootstrap_fd_identity_v1 *payload,
        const struct plamen_source_bootstrap_fd_identity_v1 *producer_receipt,
        const struct plamen_source_bootstrap_fd_identity_v1 *source_manifest);
    /* Authenticate the signed operation-4 executable against the same policy. */
    int (*authenticate_operation4)(void *context,
        const uint8_t executable_sha256[32]);
};

struct plamen_source_bootstrap_operation4_v1 {
    void *context;
    /*
     * All input descriptors are coordinator-owned O_RDONLY|CLOEXEC
     * duplicates.  Output and scratch descriptors are coordinator-owned
     * O_RDWR|CLOEXEC duplicates of empty caller-owned files.  The callback
     * must execute the authenticated operation-4 helper and return one
     * O_RDONLY|CLOEXEC terminal-receipt descriptor in terminal_receipt_fd.
     * The coordinator never invokes a shell or performs network access.
     */
    int (*invoke)(void *context, int composition_manifest_fd,
        const int payload_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT],
        const int source_manifest_fds[
            PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT],
        int output_writer_fds[
            PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT],
        int scratch_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT],
        int *terminal_receipt_fd);
    /*
     * Re-authenticate the terminal receipt after the coordinator has closed
     * every output writer, and bind its five output commitments to the final
     * read-only descriptor census.  Production supplies the helper's MACed
     * terminal decoder; a generic caller cannot self-assert this join.
     */
    int (*rejoin_terminal_outputs)(void *context, int terminal_receipt_fd,
        const struct plamen_source_bootstrap_fd_identity_v1
            outputs[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT]);
    /* SHA-256 of the already-authenticated signed operation-4 executable. */
    uint8_t executable_sha256[32];
};

struct plamen_source_bootstrap_issue_request_v1 {
    uid_t owner_uid;
    /* Exact 32-byte install-generation Ed25519 producer-verifier public key. */
    int producer_verifier_key_fd;
    int composition_manifest_fd;
    struct plamen_source_bootstrap_input_v1
        inputs[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT];
    /*
     * Each output writer/reader pair names the same initially-empty,
     * already-unlinked private-store vnode.  The native producer creates and
     * unlinks these stores before descriptor transfer; no pathname is ever an
     * output authority.  The receipt pair remains a linked staging member.
     * issue_v1 consumes and closes every writer and scratch descriptor on
     * every return path; readers and all source descriptors remain caller-owned.
     */
    int output_writer_fds[
        PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT];
    int output_reader_fds[
        PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT];
    int scratch_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT];
    int receipt_writer_fd;
    /* Same initially-empty vnode as receipt_writer_fd, opened O_RDONLY. */
    int receipt_reader_fd;
    struct plamen_source_bootstrap_policy_authority_v1 policy_authority;
    struct plamen_source_bootstrap_operation4_v1 operation4;
};

struct plamen_source_bootstrap_receipt_row_v1 {
    uint16_t ordinal;
    char role[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_SIZE + 1U];
    struct plamen_source_bootstrap_fd_identity_v1 payload;
    struct plamen_source_bootstrap_fd_identity_v1 producer_receipt;
    uint8_t policy_sha256[32];
    struct plamen_source_bootstrap_fd_identity_v1 source_manifest;
};

struct plamen_source_bootstrap_receipt_v1 {
    uint8_t acquisition_roster_sha256[32];
    struct plamen_source_bootstrap_fd_identity_v1 composition_manifest;
    uint8_t operation4_executable_sha256[32];
    struct plamen_source_bootstrap_fd_identity_v1 operation4_terminal_receipt;
    uint8_t output_roster_sha256[32];
    struct plamen_source_bootstrap_fd_identity_v1 producer_verifier_key;
    struct plamen_source_bootstrap_receipt_row_v1
        rows[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT];
    struct plamen_source_bootstrap_fd_identity_v1
        outputs[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT];
    uint8_t receipt_sha256[32];
};

/* Opaque live authority; it owns only duplicated descriptors. */
struct plamen_source_bootstrap_authority_v1;
struct plamen_source_bootstrap_installed_authority_v1;

struct plamen_source_bootstrap_projection_v1 {
    uint16_t ordinal;
    char role[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_SIZE + 1U];
    int payload_fd;
    int producer_receipt_fd;
    int source_manifest_fd;
    int coordinator_receipt_fd;
    struct plamen_source_bootstrap_fd_identity_v1 payload;
    struct plamen_source_bootstrap_fd_identity_v1 producer_receipt;
    struct plamen_source_bootstrap_fd_identity_v1 source_manifest;
    uint8_t policy_sha256[32];
    uint8_t producer_verifier_key_sha256[32];
    uint8_t acquisition_roster_sha256[32];
    uint8_t coordinator_receipt_sha256[32];
};

/* Values copied only from an authenticated terminal install receipt. */
struct plamen_source_bootstrap_installed_binding_v1 {
    uint64_t receipt_size;
    uint8_t receipt_sha256[32];
    uint8_t acquisition_roster_sha256[32];
    uint8_t producer_verifier_key_sha256[32];
    /* Complete installed 11 x (payload, producer receipt, manifest) roster. */
    uint8_t installed_authority_roster_sha256[32];
    uint8_t coordinator_member_identity_sha256[32];
    uint8_t coordinator_code_identity_sha256[32];
};

/* Audit-time role projection: exact retained role descriptors and receipt. */
struct plamen_source_bootstrap_installed_projection_v1 {
    uint16_t ordinal;
    char role[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_SIZE + 1U];
    int payload_fd;
    int producer_receipt_fd;
    int source_manifest_fd;
    int coordinator_receipt_fd;
    struct plamen_source_bootstrap_receipt_row_v1 row;
    uint8_t coordinator_receipt_sha256[32];
    uint8_t acquisition_roster_sha256[32];
    uint8_t producer_verifier_key_sha256[32];
    uint8_t installed_authority_roster_sha256[32];
    uint8_t coordinator_member_identity_sha256[32];
    uint8_t coordinator_code_identity_sha256[32];
};

/*
 * Admit and retain the complete fixed source roster, execute operation 4,
 * recensus every retained input/output, publish the fixed receipt, and return
 * an opaque authority.  Input/read-only descriptors remain caller-owned;
 * output writers, scratch writers, and the receipt writer are consumed and
 * invalidated on every return path as documented by the request structure.
 */
int plamen_source_bootstrap_coordinator_issue_v1(
    struct plamen_source_bootstrap_issue_request_v1 *request,
    struct plamen_source_bootstrap_authority_v1 **authority,
    struct plamen_source_bootstrap_receipt_v1 *receipt);

/* Strict fixed-size receipt decoder and retained-FD reader. */
int plamen_source_bootstrap_receipt_decode_exact_v1(const uint8_t *bytes,
    size_t size, struct plamen_source_bootstrap_receipt_v1 *receipt);
int plamen_source_bootstrap_receipt_read_fd_v1(int fd, uid_t owner_uid,
    struct plamen_source_bootstrap_receipt_v1 *receipt);

/* Fixed native-only installed-member naming and complete 33-member roster. */
const char *plamen_source_bootstrap_installed_member_relative_path_v1(
    uint16_t role, uint16_t kind);
int plamen_source_bootstrap_installed_authority_roster_sha256_v1(
    const struct plamen_source_bootstrap_receipt_v1 *receipt,
    uint8_t roster_sha256[32]);

/*
 * Prepublication admission for a private staged generation.  The retained
 * generation root must already contain the fixed coordinator receipt and the
 * exact 33 final companion leaves.  This performs descriptor-relative,
 * no-follow opens, rejects missing/extra/substituted leaves and writable
 * aliases, rejoins every full identity to the coordinator receipt, and emits
 * the only roster digest suitable for the terminal install receipt.
 */
int plamen_source_bootstrap_staged_authority_validate_v1(
    int generation_root_fd, int coordinator_receipt_fd, uid_t owner_uid,
    uint8_t installed_authority_roster_sha256[32]);

/* Duplicate a single role's descriptor-bound authority; never returns paths. */
int plamen_source_bootstrap_authority_project_role_v1(
    const struct plamen_source_bootstrap_authority_v1 *authority,
    uint16_t role, struct plamen_source_bootstrap_projection_v1 *projection);
void plamen_source_bootstrap_projection_dispose_v1(
    struct plamen_source_bootstrap_projection_v1 *projection);
void plamen_source_bootstrap_authority_dispose_v1(
    struct plamen_source_bootstrap_authority_v1 *authority);

/*
 * Re-admit the installed receipt without any setup-time source descriptor.
 * `binding` must be copied by the native runtime bootstrap from its already
 * authenticated terminal install receipt; this function verifies every value
 * it can derive from the retained receipt and stores no pathname.  Projection
 * accepts only descriptor-relative installed members whose complete identities
 * still equal the setup receipt row; copies or hash-only substitutes fail.
 */
int plamen_source_bootstrap_installed_readmit_v1(int receipt_fd,
    uid_t owner_uid,
    const struct plamen_source_bootstrap_installed_binding_v1 *binding,
    struct plamen_source_bootstrap_installed_authority_v1 **authority);
int plamen_source_bootstrap_installed_project_role_v1(
    const struct plamen_source_bootstrap_installed_authority_v1 *authority,
    uint16_t role, int installed_payload_fd,
    int installed_producer_receipt_fd, int installed_source_manifest_fd,
    struct plamen_source_bootstrap_installed_projection_v1 *projection);
void plamen_source_bootstrap_installed_projection_dispose_v1(
    struct plamen_source_bootstrap_installed_projection_v1 *projection);
void plamen_source_bootstrap_installed_authority_dispose_v1(
    struct plamen_source_bootstrap_installed_authority_v1 *authority);

#ifdef __cplusplus
}
#endif

#endif
