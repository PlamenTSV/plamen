#ifndef PLAMEN_BROKER_V2_ARTIFACT_EXPORT_H
#define PLAMEN_BROKER_V2_ARTIFACT_EXPORT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION 1U
#define PLAMEN_BROKER_V2_ARTIFACT_DIGEST_SIZE 32U
#define PLAMEN_BROKER_V2_ARTIFACT_ID_MAX 128U
#define PLAMEN_BROKER_V2_ARTIFACT_HANDLE_MAX 72U
#define PLAMEN_BROKER_V2_ARTIFACT_PATH_MAX 1024U
#define PLAMEN_BROKER_V2_ARTIFACT_FILES_MAX 4096U
#define PLAMEN_BROKER_V2_ARTIFACT_REPORT_MAX \
    (UINT64_C(256) * UINT64_C(1024) * UINT64_C(1024))

#define PLAMEN_BROKER_V2_ARTIFACT_PHYSICAL_REPORT "AUDIT_REPORT.md"
#define PLAMEN_BROKER_V2_ARTIFACT_LOGICAL_REPORT \
    "project/AUDIT_REPORT.md"
#define PLAMEN_BROKER_V2_ARTIFACT_TARGET_REPORT "AUDIT_REPORT.md"

enum plamen_broker_v2_artifact_status {
    PLAMEN_BROKER_V2_ARTIFACT_ERROR = -1,
    PLAMEN_BROKER_V2_ARTIFACT_SUPPRESSED = 0,
    PLAMEN_BROKER_V2_ARTIFACT_COMPLETE = 1
};

/*
 * All descriptors and strings are borrowed.  No function consumes or closes
 * them. scratch_fd is the authenticated scratch directory containing the
 * physical AUDIT_REPORT.md; target_fd is the authenticated publication root.
 * The audited project/source descriptor is deliberately not part of this ABI.
 */
struct plamen_broker_v2_artifact_session {
    uint32_t version;
    int scratch_fd;
    int target_fd;
    const char *attempt_id;
    const char *run_id;
    const char *census_handle;
    const char *destination_handle;
    const uint8_t *terminal_sha256;
    const uint8_t *destination_identity_sha256;
    /* Authenticated target census before publication. */
    const uint8_t *source_content_sha256;
    const struct plamen_broker_v2_artifact_spec *artifacts;
    size_t artifact_count;
    uint64_t export_max_total_bytes;
    uint8_t driver_exit_code;
    uint8_t terminal_authenticated;
    uint8_t extinction_proven;
    uint8_t driver_terminal_proven;
};

/*
 * The caller instantiates this exact sorted allowlist from the authenticated
 * request. parent_fd is retained authority; physical_path is descriptor-
 * relative. project/AUDIT_REPORT.md must map to scratch/AUDIT_REPORT.md.
 */
struct plamen_broker_v2_artifact_spec {
    int parent_fd;
    const char *physical_path;
    const char *logical_path;
    uint8_t required_on_success;
    uint8_t required_on_failure;
};

struct plamen_broker_v2_artifact_entry {
    const char *relative_path;
    uint64_t size;
    uint8_t sha256[PLAMEN_BROKER_V2_ARTIFACT_DIGEST_SIZE];
    uint64_t device;
    uint64_t inode;
    uint64_t change_token;
    size_t spec_index;
};

struct plamen_broker_v2_artifact_disposition {
    const char *relative_path;
    uint8_t entry_sha256[PLAMEN_BROKER_V2_ARTIFACT_DIGEST_SIZE];
};

/* Exact immutable lease over physical scratch/AUDIT_REPORT.md. */
struct plamen_broker_v2_artifact_census {
    uint32_t version;
    uint8_t status;
    uint64_t report_size;
    uint8_t report_sha256[PLAMEN_BROKER_V2_ARTIFACT_DIGEST_SIZE];
    uint8_t census_sha256[PLAMEN_BROKER_V2_ARTIFACT_DIGEST_SIZE];
    struct plamen_broker_v2_artifact_entry *entries;
    size_t entry_count;
    struct plamen_broker_v2_artifact_disposition *dispositions;
    size_t disposition_count;
    uint64_t total_bytes;
};

/*
 * Replacement is fail closed by default.  An authorized replacement must
 * carry the exact digest of the existing ordinary single-link target slot.
 * That precondition is checked immediately before the atomic rename.
 */
struct plamen_broker_v2_artifact_publication {
    uint32_t version;
    uint8_t authorize_replace;
    const uint8_t *expected_existing_sha256;
};

struct plamen_broker_v2_artifact_export_receipt {
    uint32_t version;
    uint8_t status;
    uint8_t complete;
    uint64_t exported_count;
    uint64_t exported_bytes;
    uint8_t report_sha256[PLAMEN_BROKER_V2_ARTIFACT_DIGEST_SIZE];
    uint8_t census_sha256[PLAMEN_BROKER_V2_ARTIFACT_DIGEST_SIZE];
    uint8_t manifest_sha256[PLAMEN_BROKER_V2_ARTIFACT_DIGEST_SIZE];
    uint8_t export_sha256[PLAMEN_BROKER_V2_ARTIFACT_DIGEST_SIZE];
    uint8_t postpublication_sha256[PLAMEN_BROKER_V2_ARTIFACT_DIGEST_SIZE];
};

/*
 * A failed/nonzero driver deterministically returns SUPPRESSED and never opens
 * or creates the target slot.  COMPLETE is possible only after all three
 * authenticated terminal predicates are true and the scratch lease is exact.
 */
int plamen_broker_v2_artifact_census_report(
    const struct plamen_broker_v2_artifact_session *,
    struct plamen_broker_v2_artifact_census *);

int plamen_broker_v2_artifact_publish_report(
    const struct plamen_broker_v2_artifact_session *,
    const struct plamen_broker_v2_artifact_census *,
    const struct plamen_broker_v2_artifact_publication *,
    struct plamen_broker_v2_artifact_export_receipt *);

/*
 * Crash recovery for the narrow window after the target report was durably
 * published but before its deterministic receipt was retained.  The caller
 * must separately prove that its durable PREPARE observed an absent target;
 * this function grants no publication or replacement authority.  It performs
 * no filesystem mutation: it recensuses the complete retained source lease
 * and the already-present target, then reconstructs the byte-identical
 * COMPLETE receipt in receipt_out.  Any drift, alias, symlink, hardlink,
 * missing source, or malformed census fails closed.
 */
int plamen_broker_v2_artifact_reopen_publication(
    const struct plamen_broker_v2_artifact_session *,
    const struct plamen_broker_v2_artifact_census *,
    struct plamen_broker_v2_artifact_export_receipt *receipt_out);

/* Observation-only validation for a COMPLETE receipt retained before crash. */
int plamen_broker_v2_artifact_validate_publication_receipt(
    const struct plamen_broker_v2_artifact_session *,
    const struct plamen_broker_v2_artifact_census *,
    const struct plamen_broker_v2_artifact_export_receipt *expected_receipt);

void plamen_broker_v2_artifact_census_dispose(
    struct plamen_broker_v2_artifact_census *);

/*
 * All receipt digests are byte-for-byte Python ``canonical_sha256`` values:
 * ASCII JSON, recursively sorted object keys, compact separators, lowercase
 * hex, and one trailing LF.  The census has one exact ArtifactEntry and one
 * PRESENT ArtifactDisposition for project/AUDIT_REPORT.md.  The manifest has
 * the frozen nested report_publication object (including guest staging path),
 * export_sha256 has the frozen ExportReceipt preimage, and postpublication is
 * canonical_sha256({source_content_sha256, published_artifact}).
 */

#ifdef __cplusplus
}
#endif

#endif
