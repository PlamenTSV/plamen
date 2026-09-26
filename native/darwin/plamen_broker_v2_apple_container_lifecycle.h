#ifndef PLAMEN_BROKER_V2_APPLE_CONTAINER_LIFECYCLE_H
#define PLAMEN_BROKER_V2_APPLE_CONTAINER_LIFECYCLE_H

#include "plamen_broker_v2_apple_container.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_VERSION 1U
#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_DYNAMIC_VERSION 2U
#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_VERSION 1U
#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_START_RECEIPT_DYNAMIC_VERSION 2U
#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_TERMINAL_RECEIPT_VERSION 2U
#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT 10U
#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX 12U
#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_ARGUMENT_COUNT_MAX 9U
#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX 1024U
#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_RETAIN_MAX (2U * 1024U * 1024U)
#define PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OBSERVED_MAX (16U * 1024U * 1024U)

enum plamen_broker_v2_apple_lifecycle_status {
    PLAMEN_BROKER_V2_APPLE_LIFECYCLE_OK = 0,
    PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REJECTED = 1,
    PLAMEN_BROKER_V2_APPLE_LIFECYCLE_AMBIGUOUS = 2,
    PLAMEN_BROKER_V2_APPLE_LIFECYCLE_REVOKED = 3,
    PLAMEN_BROKER_V2_APPLE_LIFECYCLE_INTERNAL_ERROR = 4
};

enum plamen_broker_v2_apple_lifecycle_dynamic_identity_kind {
    PLAMEN_BROKER_V2_APPLE_DYNAMIC_IDENTITY_NONE = 0,
    PLAMEN_BROKER_V2_APPLE_DYNAMIC_IDENTITY_APPLE_CODEDIRECTORY_CDHASH = 1
};

struct plamen_broker_v2_apple_lifecycle_mount {
    int source_fd;
    const char *source_path;
    const char *target_path;
    uint8_t expected_identity_sha256[32];
    uint8_t readonly;
};

struct plamen_broker_v2_apple_lifecycle_commitments {
    uint8_t spec_sha256[32];
    uint8_t launch_request_sha256[32];
    uint8_t driver_argv_sha256[32];
    uint8_t driver_environment_sha256[32];
    uint8_t driver_cwd_sha256[32];
    uint8_t driver_stdin_sha256[32];
    uint8_t pass_fd_roster_sha256[32];
    uint8_t mount_roster_sha256[32];
    uint8_t create_argv_sha256[32];
};

struct plamen_broker_v2_apple_lifecycle_spec {
    uint32_t version;
    int cli_fd;
    const char *cli_path;
    int cwd_fd;
    int stdin_fd;
    int state_directory_fd;
    const struct plamen_broker_v2_apple_container_admission_receipt *admission;
    const char *container_id;
    const char *runtime_image_reference;
    const char *working_directory;
    const char *entrypoint;
    const char *const *arguments;
    size_t argument_count;
    uint32_t cpus;
    uint64_t memory_bytes;
    uint32_t uid;
    uint32_t gid;
    uint32_t create_timeout_seconds;
    uint32_t driver_timeout_seconds;
    uint32_t stop_grace_seconds;
    uint8_t rosetta_required;
    uint8_t spec_sha256[32];
    uint8_t launch_request_sha256[32];
    uint8_t launch_policy_sha256[32];
    uint8_t driver_argv_sha256[32];
    uint8_t driver_environment_sha256[32];
    uint8_t driver_cwd_sha256[32];
    uint8_t driver_stdin_sha256[32];
    uint8_t pass_fd_roster_sha256[32];
    uint8_t create_operation_key[32];
    uint8_t start_operation_nonce[32];
    uint8_t wait_operation_nonce[32];
    uint8_t revoke_operation_nonce[32];
    struct plamen_broker_v2_apple_lifecycle_mount
        mounts[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_MOUNT_COUNT_MAX];
    /*
     * Version 1 never reads these append-only fields and preserves the fixed
     * ten-mount audit-driver ABI.  Version 2 is reserved for authenticated,
     * broker-owned specialized workers.  Its mounts remain exact directory
     * capabilities: absolute unique/non-overlapping targets,
     * descriptor/path identity equality, and an explicit RO bit.
     */
    size_t mount_count;
    uint8_t dynamic_mounts;
};

struct plamen_broker_v2_apple_lifecycle_create_receipt {
    uint32_t version;
    uint32_t status;
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    uint8_t request_fingerprint_sha256[32];
    uint8_t provider_provenance_sha256[32];
    uint8_t image_closure_sha256[32];
    uint8_t spec_sha256[32];
    uint8_t mount_roster_sha256[32];
    uint8_t create_argv_sha256[32];
    uint8_t create_stdout_sha256[32];
    uint8_t create_stderr_sha256[32];
    uint8_t stopped_observation_sha256[32];
    uint8_t rootfs_readonly;
    uint8_t use_init;
    uint8_t network_attachment_count;
    uint8_t dns_disabled;
    uint8_t control_process_reaped;
    uint8_t control_process_group_extinct;
    uint8_t receipt_sha256[32];
};

struct plamen_broker_v2_apple_lifecycle_start_receipt {
    uint32_t version;
    uint32_t status;
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    uint8_t request_fingerprint_sha256[32];
    uint8_t spec_sha256[32];
    uint8_t launch_request_sha256[32];
    uint8_t start_operation_nonce[32];
    uint8_t start_argv_sha256[32];
    uint8_t native_process_handle_sha256[32];
    int32_t native_process_id;
    uint64_t start_monotonic_ms;
    uint8_t prepared_record_sha256[32];
    uint8_t custody_process_spec_sha256[32];
    uint8_t custody_prepared_checkpoint_sha256[32];
    uint8_t custody_started_checkpoint_sha256[32];
    uint8_t receipt_sha256[32];
    /*
     * Append-only version-2 projection of the actual post-spawn signing
     * observation.  This is deliberately distinct from the native process
     * handle digest.  Version 1 requires all three fields to be zero.
     */
    uint32_t post_spawn_dynamic_identity_kind;
    uint32_t post_spawn_dynamic_identity_size;
    uint8_t post_spawn_dynamic_identity_sha256[32];
};

struct plamen_broker_v2_apple_lifecycle_terminal_receipt {
    uint32_t version;
    uint32_t status;
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    uint8_t request_fingerprint_sha256[32];
    uint8_t spec_sha256[32];
    uint8_t launch_request_sha256[32];
    uint8_t start_operation_nonce[32];
    uint8_t wait_operation_nonce[32];
    uint8_t revoke_operation_nonce[32];
    uint8_t native_process_handle_sha256[32];
    int32_t native_process_id;
    int32_t exit_code;
    uint64_t start_monotonic_ms;
    uint64_t end_monotonic_ms;
    uint64_t stdout_observed_bytes;
    uint64_t stderr_observed_bytes;
    uint32_t stdout_retained_bytes;
    uint32_t stderr_retained_bytes;
    uint8_t stdout_sha256[32];
    uint8_t stderr_sha256[32];
    uint8_t stdout_retained_sha256[32];
    uint8_t stderr_retained_sha256[32];
    uint8_t native_process_extinction_sha256[32];
    uint8_t cleanup_sha256[32];
    uint8_t descendants_extinct;
    uint8_t guest_process_extinct;
    uint8_t backend_egress_revoked;
    uint8_t stdout_truncated;
    uint8_t stderr_truncated;
    uint8_t terminal_durable;
    uint8_t deleted;
    /*
     * A reaped `container start --attach` process is only host control-plane
     * evidence.  It does not prove that the guest process population or the
     * per-container VM is extinct.  Version 2 binds the mandatory, exact
     * post-wait `container stop` transaction.  Apple Container's stop path
     * kills the remaining guest population, unmounts/syncs the guest, and
     * completes only after the backing VM stop.  The independently parsed
     * stopped observation then proves the provider's terminal projection.
     */
    uint8_t stop_argv_sha256[32];
    uint8_t stop_stdout_sha256[32];
    uint8_t stop_stderr_sha256[32];
    uint8_t stopped_observation_sha256[32];
    uint8_t guest_population_extinction_sha256[32];
    uint8_t stop_control_process_reaped;
    uint8_t stop_control_process_group_extinct;
    uint8_t guest_population_zero;
    uint8_t container_vm_stopped;
    uint8_t receipt_sha256[32];
    uint8_t *stdout_retained;
    uint8_t *stderr_retained;
};

struct plamen_broker_v2_apple_lifecycle_delete_receipt {
    uint32_t version;
    uint32_t status;
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    uint8_t request_fingerprint_sha256[32];
    uint8_t spec_sha256[32];
    uint8_t terminal_receipt_sha256[32];
    uint8_t cleanup_sha256[32];
    uint8_t absence_sha256[32];
    uint8_t descendants_extinct;
    uint8_t guest_process_extinct;
    uint8_t backend_egress_revoked;
    uint8_t absent;
    uint8_t receipt_sha256[32];
};

struct plamen_broker_v2_apple_lifecycle;
struct plamen_broker_v2_process_custody_client;
struct plamen_broker_v2_process_start_identity;

/* Derives every execution commitment from the exact retained inputs. */
int plamen_broker_v2_apple_lifecycle_derive_commitments(
    const struct plamen_broker_v2_apple_lifecycle_spec *,
    struct plamen_broker_v2_apple_lifecycle_commitments *);

int plamen_broker_v2_apple_lifecycle_create(
    const struct plamen_broker_v2_apple_lifecycle_spec *,
    struct plamen_broker_v2_apple_lifecycle_create_receipt *,
    struct plamen_broker_v2_apple_lifecycle **);

/*
 * Process custody is service authority, not part of the guest specification.
 * The client is borrowed for the lifetime of the lifecycle object.  The claim
 * owner is the authenticated authority-bundle binding and is copied into the
 * lifecycle object before any START mutation can be attempted.
 */
int plamen_broker_v2_apple_lifecycle_bind_process_custody(
    struct plamen_broker_v2_apple_lifecycle *,
    struct plamen_broker_v2_process_custody_client *, const uint8_t [32]);

/*
 * Reopens only from exact durable records plus the original retained
 * descriptor/path topology.  A stopped reopen re-observes the provider guest;
 * a started reopen also adopts the durable native process from the custody
 * daemon.  Neither API derives authority from ambient container names.
 */
int plamen_broker_v2_apple_lifecycle_reopen_created(
    const struct plamen_broker_v2_apple_lifecycle_spec *,
    struct plamen_broker_v2_process_custody_client *, const uint8_t [32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *,
    struct plamen_broker_v2_apple_lifecycle **);
int plamen_broker_v2_apple_lifecycle_reopen_started(
    const struct plamen_broker_v2_apple_lifecycle_spec *,
    struct plamen_broker_v2_process_custody_client *, const uint8_t [32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *,
    struct plamen_broker_v2_apple_lifecycle **);
int plamen_broker_v2_apple_lifecycle_reopen_terminal(
    const struct plamen_broker_v2_apple_lifecycle_spec *,
    struct plamen_broker_v2_process_custody_client *, const uint8_t [32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *,
    struct plamen_broker_v2_apple_lifecycle **);
int plamen_broker_v2_apple_lifecycle_reopen_deleted(
    const struct plamen_broker_v2_apple_lifecycle_spec *,
    struct plamen_broker_v2_process_custody_client *, const uint8_t [32],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *,
    struct plamen_broker_v2_apple_lifecycle_delete_receipt *,
    struct plamen_broker_v2_apple_lifecycle **);
int plamen_broker_v2_apple_lifecycle_start(
    struct plamen_broker_v2_apple_lifecycle *,
    struct plamen_broker_v2_apple_lifecycle_start_receipt *);
int plamen_broker_v2_apple_lifecycle_wait(
    struct plamen_broker_v2_apple_lifecycle *,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *);
int plamen_broker_v2_apple_lifecycle_revoke_delete(
    struct plamen_broker_v2_apple_lifecycle *,
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *,
    struct plamen_broker_v2_apple_lifecycle_delete_receipt *);
int plamen_broker_v2_apple_lifecycle_delete(
    struct plamen_broker_v2_apple_lifecycle *,
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *,
    struct plamen_broker_v2_apple_lifecycle_delete_receipt *);
int plamen_broker_v2_apple_lifecycle_create_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *);
int plamen_broker_v2_apple_lifecycle_start_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *);
int plamen_broker_v2_apple_lifecycle_start_receipt_dynamic_identity_validate(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *);
int plamen_broker_v2_apple_lifecycle_terminal_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_terminal_receipt *);
int plamen_broker_v2_apple_lifecycle_delete_receipt_validate(
    const struct plamen_broker_v2_apple_lifecycle_delete_receipt *);
void plamen_broker_v2_apple_lifecycle_terminal_dispose(
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *);
int plamen_broker_v2_apple_lifecycle_close(
    struct plamen_broker_v2_apple_lifecycle *);
/* Drops only this service session's retained descriptors; provider/custody live. */
int plamen_broker_v2_apple_lifecycle_detach(
    struct plamen_broker_v2_apple_lifecycle *);

#ifdef PLAMEN_BROKER_V2_APPLE_CONTAINER_TEST_ONLY
int plamen_broker_v2_apple_lifecycle_test_create_argv(
    const struct plamen_broker_v2_apple_lifecycle_spec *, char *, size_t);
int plamen_broker_v2_apple_lifecycle_test_validate_spec(
    const struct plamen_broker_v2_apple_lifecycle_spec *);
int plamen_broker_v2_apple_lifecycle_test_validate_inspect(
    const uint8_t *, size_t,
    const struct plamen_broker_v2_apple_lifecycle_spec *, const char *,
    uint8_t [32]);
int plamen_broker_v2_apple_lifecycle_test_exact_id_output(
    const uint8_t *, size_t, const char *);
int plamen_broker_v2_apple_lifecycle_test_list_proves_absent(
    const uint8_t *, size_t, const char *);
int plamen_broker_v2_apple_lifecycle_test_encode_create_receipt(
    const struct plamen_broker_v2_apple_lifecycle_create_receipt *,
    uint8_t [512]);
int plamen_broker_v2_apple_lifecycle_test_decode_create_receipt(
    const uint8_t [512],
    struct plamen_broker_v2_apple_lifecycle_create_receipt *);
int plamen_broker_v2_apple_lifecycle_test_encode_start_receipt(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *,
    uint8_t [512]);
int plamen_broker_v2_apple_lifecycle_test_decode_start_receipt(
    const uint8_t [512],
    struct plamen_broker_v2_apple_lifecycle_start_receipt *);
int plamen_broker_v2_apple_lifecycle_test_encode_terminal_receipt(
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *,
    uint8_t [768]);
int plamen_broker_v2_apple_lifecycle_test_decode_terminal_receipt(
    const uint8_t [768],
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt *);
int plamen_broker_v2_apple_lifecycle_test_bind_start_dynamic_identity(
    struct plamen_broker_v2_apple_lifecycle_start_receipt *,
    const struct plamen_broker_v2_process_start_identity *);
int plamen_broker_v2_apple_lifecycle_test_start_dynamic_identity_matches(
    const struct plamen_broker_v2_apple_lifecycle_start_receipt *,
    const struct plamen_broker_v2_process_start_identity *);
#endif

#ifdef __cplusplus
}
#endif

#endif
