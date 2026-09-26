#ifndef PLAMEN_BROKER_V2_WORKSPACE_EFFECTS_H
#define PLAMEN_BROKER_V2_WORKSPACE_EFFECTS_H

#include "plamen_broker_v2_operations.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_WORKSPACE_EFFECTS_VERSION 1U
#define PLAMEN_BROKER_V2_WORKSPACE_MOUNT_PATH_MAX 4096U

struct plamen_broker_v2_workspace_effects_context;

/*
 * Every descriptor is borrowed.  create duplicates the descriptors it needs
 * with CLOEXEC and never consumes, closes, or changes the caller's entries.
 * state_parent_fd must name a service-private (owner-only) directory.
 */
struct plamen_broker_v2_workspace_effects_open {
    uint32_t version;
    const struct plamen_broker_v2_service_registration *registration;
    const uint8_t *request_projection;
    size_t request_projection_size;
    int state_parent_fd;
    /* Authenticated installed-generation root retained by the broker. */
    int generation_fd;
    const int *authority_fds;
    size_t authority_fd_count;
};

int plamen_broker_v2_workspace_effects_create(
    const struct plamen_broker_v2_workspace_effects_open *,
    struct plamen_broker_v2_workspace_effects_context **);

int plamen_broker_v2_workspace_effects_revalidate(
    struct plamen_broker_v2_workspace_effects_context *);

/*
 * Returns 1 when a workspace request was handled, 0 for a different member,
 * and -1 for a fail-closed error.  Successful results own canonical_result;
 * dispose_result releases it.  Mutating success is returned only after the
 * corresponding descriptor-relative receipt has been fsync'd and renamed.
 */
int plamen_broker_v2_workspace_effects_execute(
    struct plamen_broker_v2_workspace_effects_context *,
    const struct plamen_broker_v2_operations_effect_request *,
    struct plamen_broker_v2_operations_effect_result *);

void plamen_broker_v2_workspace_effects_dispose_result(
    struct plamen_broker_v2_operations_effect_result *);

/* Borrowed internal descriptors.  Callers must dup before retaining them. */
enum plamen_broker_v2_workspace_effects_descriptor {
    PLAMEN_BROKER_V2_WORKSPACE_LAYOUT_ROOT = 1,
    PLAMEN_BROKER_V2_WORKSPACE_MERGED = 2,
    PLAMEN_BROKER_V2_WORKSPACE_SCRATCH = 3,
    PLAMEN_BROKER_V2_WORKSPACE_STATE = 4,
    PLAMEN_BROKER_V2_WORKSPACE_CONTROL = 5,
    PLAMEN_BROKER_V2_WORKSPACE_EXPORT = 6,
    PLAMEN_BROKER_V2_WORKSPACE_TARGET = 7,
    PLAMEN_BROKER_V2_WORKSPACE_DOCS = 8,
    PLAMEN_BROKER_V2_WORKSPACE_SCOPE = 9,
    PLAMEN_BROKER_V2_WORKSPACE_SECCOMP = 10,
    PLAMEN_BROKER_V2_WORKSPACE_CREDENTIALS = 11,
    PLAMEN_BROKER_V2_WORKSPACE_BACKEND = 12,
    PLAMEN_BROKER_V2_WORKSPACE_RUNTIME = 13
};

int plamen_broker_v2_workspace_effects_borrow_fd(
    struct plamen_broker_v2_workspace_effects_context *, uint16_t purpose);

/* Copy the authenticated durable AttemptLayout semantic commitment. */
int plamen_broker_v2_workspace_effects_layout_commitment(
    struct plamen_broker_v2_workspace_effects_context *, uint8_t output[32]);

/*
 * Atomic borrowed mount projection for Apple Container lifecycle calls.
 * source_fd remains owned by the workspace context. source_path is an exact
 * absolute, non-symlink path whose lstat identity equals the descriptor.
 */
struct plamen_broker_v2_workspace_mount_view {
    uint32_t version;
    uint16_t purpose;
    uint8_t read_only;
    int source_fd;
    uint8_t identity[32];
    char source_path[PLAMEN_BROKER_V2_WORKSPACE_MOUNT_PATH_MAX];
};

int plamen_broker_v2_workspace_effects_borrow_mount(
    struct plamen_broker_v2_workspace_effects_context *, uint16_t purpose,
    struct plamen_broker_v2_workspace_mount_view *);

/* Provider-only immediate PRE_CREATE/POST_CREATE capture around CREATE. */
int plamen_broker_v2_workspace_effects_capture_recensus(
    struct plamen_broker_v2_workspace_effects_context *, const char *phase,
    const uint8_t operation_key[32],
    struct plamen_broker_v2_operations_effect_result *);

/* Borrow the exact typed LayoutRecensus bytes most recently issued by RPC. */
int plamen_broker_v2_workspace_effects_borrow_recensus(
    struct plamen_broker_v2_workspace_effects_context *, const char *phase,
    const uint8_t **canonical_result, size_t *canonical_result_size,
    uint8_t semantic_commitment_sha256[32]);

/* canonical_sha256(tuple((purpose, provider_mount_identity), ...)). */
int plamen_broker_v2_workspace_effects_provider_mounts_sha256(
    struct plamen_broker_v2_workspace_effects_context *, const char *phase,
    uint8_t output[32]);

/* Python-exact canonical digest of the authenticated PRE/POST mount delta. */
int plamen_broker_v2_workspace_effects_allowed_delta_sha256(
    struct plamen_broker_v2_workspace_effects_context *, uint8_t output[32]);

void plamen_broker_v2_workspace_effects_destroy(
    struct plamen_broker_v2_workspace_effects_context *);

#ifdef __cplusplus
}
#endif

#endif
