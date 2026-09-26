#ifndef PLAMEN_BROKER_V2_EFFECTS_H
#define PLAMEN_BROKER_V2_EFFECTS_H

#include "plamen_broker_v2_operations.h"
#include "plamen_broker_v2_apple_container.h"
#include "plamen_broker_v2_apple_container_lifecycle.h"
#include "plamen_broker_v2_specialized_runtime_effects_handoff.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_EFFECTS_VERSION 1U
#define PLAMEN_BROKER_V2_SPECIALIZED_WORKER_VERSION 1U

struct plamen_broker_v2_effects_context;
struct plamen_broker_v2_process_custody_client;
struct plamen_broker_v2_specialized_request;

/*
 * authority_fds is an indexed PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT
 * array.  A present bit requires a descriptor in the corresponding slot and
 * an absent bit requires -1.  Creation is an atomic ownership transfer: on
 * success every present entry is changed to -1 and is owned by the returned
 * context; on failure no entry is consumed or closed.
 *
 * state_parent_fd is a service-owned, private directory. cancellation_fd is
 * the authenticated session stream.  Both are borrowed and duplicated with
 * CLOEXEC.  Neither descriptor, nor the retained credential descriptor, is
 * ever inherited by a provider/backend child.
 */
struct plamen_broker_v2_effects_open {
    uint32_t version;
    const struct plamen_broker_v2_service_registration *registration;
    const uint8_t *request_projection;
    size_t request_projection_size;
    uint8_t authority_binding_sha256[32];
    int state_parent_fd;
    /* Borrowed authenticated installed-generation root. */
    int generation_fd;
    /* Borrowed signed role-8 and specialized companion authority. */
    int runtime_manifest_fd;
    const struct plamen_install_receipt_member *runtime_manifest_member;
    int image_member_receipt_fd;
    const struct plamen_install_receipt_specialized_authority
        *specialized_runtime_auxiliary;
    /* Borrowed process-owned custody authority; never closed by effects. */
    struct plamen_broker_v2_process_custody_client *custody_client;
    int cancellation_fd;
    int *authority_fds;
    size_t authority_fd_count;
};

int plamen_broker_v2_effects_create(
    struct plamen_broker_v2_effects_open *,
    struct plamen_broker_v2_effects_context **);

const struct plamen_broker_v2_operations_effects *
plamen_broker_v2_effects_operations(
    struct plamen_broker_v2_effects_context *);

/*
 * Authenticated specialized-session boundary.  request_wire is the exact
 * canonical specialized request encoded and authenticated by the service.
 * On success terminal is malloc-owned canonical JSON without a trailing LF;
 * the service securely releases it after journaling the response.
 */
int plamen_broker_v2_effects_dispatch_specialized(
    struct plamen_broker_v2_effects_context *,
    const struct plamen_broker_v2_specialized_request *,
    const uint8_t *request_wire, size_t request_wire_size,
    const uint8_t request_sha256[32], const uint8_t session_key[32],
    int *fds, size_t fd_count,
    uint8_t **terminal, size_t *terminal_size);

/*
 * C-only dynamic worker launch seam.  It is callable only while the owning
 * effects dispatcher holds the authenticated context lock; it is not a wire
 * or Python authority.  Every bind is an exact directory descriptor/path
 * pair and Apple Container remains rootfs-RO, cap-drop ALL, init-enabled,
 * network none and DNS-disabled.  stdin_bytes are delivered only to the
 * attached worker; stdout must be one complete canonical no-LF terminal.
 */
struct plamen_broker_v2_specialized_worker_request {
    uint32_t version;
    uint16_t lane;
    uint16_t method;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t effects_context_sha256[32];
    uint8_t launch_policy_sha256[32];
    uint8_t terminal_hmac_key[32];
    const char *working_directory;
    const char *entrypoint;
    const char *const *arguments;
    size_t argument_count;
    const struct plamen_broker_v2_apple_lifecycle_mount *mounts;
    size_t mount_count;
    int stdin_fd;
    uint32_t cpus;
    uint64_t memory_bytes;
    uint32_t timeout_seconds;
};

struct plamen_broker_v2_specialized_worker_result {
    uint32_t version;
    struct plamen_broker_v2_apple_lifecycle_create_receipt created;
    struct plamen_broker_v2_apple_lifecycle_start_receipt started;
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt exited;
    struct plamen_broker_v2_apple_lifecycle_delete_receipt deleted;
    uint8_t lifecycle_receipt_sha256[32];
    uint8_t guest_terminal_sha256[32];
    uint8_t guest_terminal_hmac_sha256[32];
    uint8_t network_denied;
    uint8_t population_zero;
    uint8_t cleanup_complete;
    uint8_t *guest_terminal;
    size_t guest_terminal_size;
};

int plamen_broker_v2_effects_run_specialized_worker_locked(
    struct plamen_broker_v2_effects_context *,
    const struct plamen_broker_v2_specialized_worker_request *,
    struct plamen_broker_v2_specialized_worker_result *);
void plamen_broker_v2_effects_dispose_specialized_worker_result(
    struct plamen_broker_v2_specialized_worker_result *);

/*
 * C-only admission handoff.  It is intentionally absent from the broker wire
 * method table: Slice 1 may retain and expose read-only admission evidence but
 * cannot grant provider lifecycle authority.  The caller supplies a receipt
 * already produced by plamen_broker_v2_apple_container_admit().
 */
int plamen_broker_v2_effects_retain_provider_admission(
    struct plamen_broker_v2_effects_context *,
    const struct plamen_broker_v2_apple_container_admission_receipt *);

int plamen_broker_v2_effects_copy_provider_admission(
    struct plamen_broker_v2_effects_context *,
    struct plamen_broker_v2_apple_container_admission_receipt *);

/* Extinguishes and reaps any owned process before releasing native custody. */
void plamen_broker_v2_effects_destroy(
    struct plamen_broker_v2_effects_context *);

#ifdef __cplusplus
}
#endif

#endif
