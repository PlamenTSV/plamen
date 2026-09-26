#ifndef PLAMEN_BROKER_V2_OPERATIONS_H
#define PLAMEN_BROKER_V2_OPERATIONS_H

#include "../include/plamen_broker_v2.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_OPERATIONS_VERSION 2U
#define PLAMEN_BROKER_V2_OPERATIONS_EFFECTS_VERSION 1U
#define PLAMEN_BROKER_V2_OPERATIONS_MAX_ARGUMENTS 7U
#define PLAMEN_BROKER_V2_OPERATIONS_SCALAR_MAX 4096U
#define PLAMEN_BROKER_V2_OPERATIONS_QUICK_TIMEOUT_MS UINT64_C(60000)
#define PLAMEN_BROKER_V2_OPERATIONS_EFFECT_TIMEOUT_MS UINT64_C(1800000)
#define PLAMEN_BROKER_V2_OPERATIONS_WAIT_TIMEOUT_MS UINT64_C(259200000)

enum plamen_broker_v2_operations_result_kind {
    PLAMEN_BROKER_V2_OPERATIONS_RESPONSE = 1,
    PLAMEN_BROKER_V2_OPERATIONS_ERROR = 2
};

enum plamen_broker_v2_operations_error {
    PLAMEN_BROKER_V2_OPERATIONS_ERR_CALL =
        PLAMEN_BROKER_V2_SERVICE_ERR_INVALID_ENVELOPE,
    PLAMEN_BROKER_V2_OPERATIONS_ERR_BINDING =
        PLAMEN_BROKER_V2_SERVICE_ERR_PEER_AUTH,
    PLAMEN_BROKER_V2_OPERATIONS_ERR_ORDER =
        PLAMEN_BROKER_V2_SERVICE_ERR_UNSUPPORTED,
    PLAMEN_BROKER_V2_OPERATIONS_ERR_PENDING =
        PLAMEN_BROKER_V2_SERVICE_ERR_SESSION,
    PLAMEN_BROKER_V2_OPERATIONS_ERR_EFFECT =
        PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL,
    PLAMEN_BROKER_V2_OPERATIONS_ERR_AMBIGUOUS =
        PLAMEN_BROKER_V2_SERVICE_ERR_DURABILITY,
    PLAMEN_BROKER_V2_OPERATIONS_ERR_DURABILITY =
        PLAMEN_BROKER_V2_SERVICE_ERR_DURABILITY,
    PLAMEN_BROKER_V2_OPERATIONS_ERR_REPLAY_CONFLICT =
        PLAMEN_BROKER_V2_SERVICE_ERR_SESSION,
    PLAMEN_BROKER_V2_OPERATIONS_ERR_EXHAUSTED =
        PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL,
    PLAMEN_BROKER_V2_OPERATIONS_ERR_UNSUPPORTED =
        PLAMEN_BROKER_V2_SERVICE_ERR_UNSUPPORTED
};

enum plamen_broker_v2_operations_effect_outcome {
    PLAMEN_BROKER_V2_OPERATIONS_EFFECT_OK = 0,
    PLAMEN_BROKER_V2_OPERATIONS_EFFECT_NOT_APPLIED = 1,
    PLAMEN_BROKER_V2_OPERATIONS_EFFECT_AMBIGUOUS = 2
};

enum plamen_broker_v2_operations_replay_status {
    PLAMEN_BROKER_V2_OPERATIONS_REPLAY_MISS = 0,
    PLAMEN_BROKER_V2_OPERATIONS_REPLAY_FOUND = 1,
    PLAMEN_BROKER_V2_OPERATIONS_REPLAY_CONFLICT = 2
};

/* SupervisorStage order.  Values are durable ABI and must not be renumbered. */
enum plamen_broker_v2_operations_stage {
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_EMPTY = 0,
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_LAYOUT_READY = 1,
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_CONFIG_READY = 2,
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_GUEST_CREATED = 3,
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_GUEST_ADMITTED = 4,
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_DRIVER_STARTED = 5,
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_DRIVER_EXITED = 6,
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_EXTINCT = 7,
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_CENSUSED = 8,
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_EXPORTED = 9,
    PLAMEN_BROKER_V2_OPERATIONS_STAGE_DELETED = 10
};

struct plamen_broker_v2_operations_argument {
    const char *name;
    const char *type;
    uint8_t commitment_sha256[32];
    const char *scalar;
    size_t scalar_size;
    uint8_t is_receipt;
};

struct plamen_broker_v2_operations_effect_request {
    uint32_t version;
    uint16_t member;
    uint16_t method;
    uint16_t flags;
    uint16_t stage;
    uint16_t pending_operation;
    uint8_t request_fingerprint_sha256[32];
    uint8_t operation_key[32];
    uint8_t call_sha256[32];
    uint8_t current_checkpoint_sha256[32];
    uint64_t monotonic_deadline_ms;
    const uint8_t *canonical_call;
    size_t canonical_call_size;
    const struct plamen_broker_v2_operations_argument *arguments;
    size_t argument_count;
};

/*
 * canonical_result is exactly one canonical JSON value without a trailing LF.
 * result_commitment_sha256 is canonical_sha256(the corresponding typed Python
 * value), not SHA256(canonical_result).  The authenticated native effect owns
 * the buffer until dispose_result returns.  journal.open must return the
 * durable checkpoint and stage.  Other methods leave both unchanged except
 * commit/resolve, whose checkpoint is independently derived by the dispatcher.
 */
struct plamen_broker_v2_operations_effect_result {
    const uint8_t *canonical_result;
    size_t canonical_result_size;
    uint8_t result_commitment_sha256[32];
    uint8_t durable_checkpoint_sha256[32];
    uint16_t durable_stage;
    /* journal.open only: zero or the exact pending MutationOperation value. */
    uint16_t durable_pending_operation;
    uint8_t durable_pending_ticket_sha256[32];
    uint8_t effect_applied;
    uint8_t durability_proven;
};

/* Persisted atomically with each exact RPC terminal wire record. */
struct plamen_broker_v2_operations_replay_state {
    uint32_t version;
    uint8_t current_checkpoint_sha256[32];
    uint8_t pending_ticket_sha256[32];
    uint16_t stage;
    uint16_t pending_operation;
    uint8_t journal_opened;
    uint8_t runtime_authenticated;
    uint8_t target_admitted;
    uint8_t backend_authenticated;
    uint8_t provider_known;
    uint8_t pending_effect_seen;
    uint8_t recovery_seen;
    uint8_t recovery_applied;
    uint8_t finished;
    uint8_t burned;
};

struct plamen_broker_v2_operations_effects {
    uint32_t version;
    void *context;
    /* Revalidate retained descriptor custody; called at open and every RPC. */
    int (*revalidate)(void *, const uint8_t request_fingerprint_sha256[32],
        const uint8_t projection_sha256[32],
        const uint8_t authority_binding_sha256[32], uint16_t member,
        uint16_t method);
    uint64_t (*monotonic_ms)(void *);
    /* One iff the authenticated session socket is dead/cancelled. */
    int (*cancelled)(void *);
    int (*execute)(void *,
        const struct plamen_broker_v2_operations_effect_request *,
        struct plamen_broker_v2_operations_effect_result *);
    void (*dispose_result)(void *,
        struct plamen_broker_v2_operations_effect_result *);
    /* Durable exact-wire RPC replay journal. */
    int (*replay_lookup)(void *, const uint8_t operation_key[32],
        const uint8_t request_sha256[32], uint8_t *kind,
        uint8_t *wire, size_t wire_capacity, size_t *wire_size,
        struct plamen_broker_v2_operations_replay_state *);
    int (*replay_commit)(void *, const uint8_t operation_key[32],
        const uint8_t request_sha256[32], uint8_t kind,
        const uint8_t *wire, size_t wire_size,
        const struct plamen_broker_v2_operations_replay_state *);
};

struct plamen_broker_v2_operations_open {
    uint32_t version;
    uint8_t request_fingerprint_sha256[32];
    uint8_t request_commitment_sha256[32];
    uint8_t projection_sha256[32];
    uint8_t authority_binding_sha256[32];
    uint8_t initial_checkpoint_sha256[32];
    struct plamen_broker_v2_authority_bundle_binding authority_bundle;
    const struct plamen_broker_v2_operations_effects *effects;
};

struct plamen_broker_v2_operations_dispatch_result {
    uint8_t kind;
    uint8_t replayed;
    uint8_t *wire;
    size_t wire_size;
};

struct plamen_broker_v2_operations_session;

int plamen_broker_v2_operations_session_open(
    const struct plamen_broker_v2_operations_open *,
    struct plamen_broker_v2_operations_session **);

/*
 * request_frame_payload_sha256 is SHA256(the exact encoded OPERATION_REQUEST
 * payload). canonical_call must be byte-identical to request->payload.  Zero
 * means an authenticated RESPONSE/ERROR is returned; negative means the
 * session is burned and the caller must close the transport without retry.
 */
int plamen_broker_v2_operations_dispatch(
    struct plamen_broker_v2_operations_session *,
    const struct plamen_broker_v2_operation_request *,
    const uint8_t request_frame_payload_sha256[32],
    const uint8_t *canonical_call, size_t canonical_call_size,
    struct plamen_broker_v2_operations_dispatch_result *);

void plamen_broker_v2_operations_dispatch_result_dispose(
    struct plamen_broker_v2_operations_dispatch_result *);

void plamen_broker_v2_operations_session_close(
    struct plamen_broker_v2_operations_session *);

#ifdef __cplusplus
}
#endif

#endif
