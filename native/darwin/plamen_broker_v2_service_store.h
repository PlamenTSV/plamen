#ifndef PLAMEN_BROKER_V2_SERVICE_STORE_H
#define PLAMEN_BROKER_V2_SERVICE_STORE_H

#include "../include/plamen_broker_v2.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_SERVICE_STORE_VERSION 4U
#define PLAMEN_BROKER_V2_SPECIALIZED_ATTACHMENT_VERSION 1U
#define PLAMEN_BROKER_V2_SPECIALIZED_ATTACHMENT_MAX_SIZE (16U * 1024U * 1024U)

struct plamen_broker_v2_service_consumed_session {
    struct plamen_broker_v2_service_session_challenge session_challenge;
    struct plamen_broker_v2_service_session_open session_open;
    struct plamen_broker_v2_service_session_ack session_ack;
    struct plamen_broker_v2_authority_bundle_binding authority_bundle;
    uint8_t key_sha256[32];
};

struct plamen_broker_v2_service_consumed_specialized_session {
    struct plamen_broker_v2_service_specialized_session_challenge challenge;
    struct plamen_broker_v2_service_specialized_session_open session_open;
    struct plamen_broker_v2_service_specialized_session_ack session_ack;
    uint8_t key_sha256[32];
};

struct plamen_broker_v2_service_store;

struct plamen_broker_v2_specialized_attachment {
    uint32_t version;
    uint64_t size;
    uint8_t sha256[32];
    int descriptor;
};

/*
 * parent_fd is a retained descriptor for a private, installer-admitted state
 * directory.  The store never reconstructs an ambient path from it.  Every
 * transition is serialized, written through an O_EXCL pending inode, fsynced,
 * atomically published without replacement, and recovered byte-for-byte.
 */
int plamen_broker_v2_service_store_open(int parent_fd,
    struct plamen_broker_v2_service_store **out);
void plamen_broker_v2_service_store_close(
    struct plamen_broker_v2_service_store *);

/* Persist an exact unused registration or recover its identical result. */
int plamen_broker_v2_service_store_register(
    struct plamen_broker_v2_service_store *,
    const struct plamen_broker_v2_service_registration *,
    const uint8_t request_envelope_sha256[32],
    const uint8_t broker_closure_sha256[32],
    const uint8_t *request_projection,
    size_t request_projection_size,
    struct plamen_broker_v2_service_registration_ack *);

/* Resolve exactly one unused registration by out-of-band child PID/birth. */
int plamen_broker_v2_service_store_lookup_unused(
    struct plamen_broker_v2_service_store *,
    const struct plamen_broker_v2_peer_identity *,
    struct plamen_broker_v2_service_registration *,
    struct plamen_broker_v2_service_registration_ack *);

/*
 * Return an authenticated copy of the exact projection durably committed
 * before registration acknowledgement.  The caller owns and must zero/free
 * the returned buffer.  No projection is accepted from a session peer.
 */
int plamen_broker_v2_service_store_copy_request_projection(
    struct plamen_broker_v2_service_store *,
    const uint8_t registration_sha256[32],
    uint8_t **request_projection,
    size_t *request_projection_size);

/* Load the immutable canonical registration by its authenticated digest. */
int plamen_broker_v2_service_store_copy_registration(
    struct plamen_broker_v2_service_store *,
    const uint8_t registration_sha256[32],
    struct plamen_broker_v2_service_registration *);

/*
 * Burn an exact registration for one exact session.  A crash after PREPARED
 * but before CONSUMED is recoverable only by replaying identical canonical
 * bytes.  A divergent session can never consume the registration.
 */
int plamen_broker_v2_service_store_consume(
    struct plamen_broker_v2_service_store *,
    const struct plamen_broker_v2_service_session_challenge *,
    const struct plamen_broker_v2_service_session_open *,
    const uint8_t request_envelope_sha256[32],
    const uint8_t member_capability_id
        [PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT][32],
    const uint8_t key_sha256[32],
    int allow_new_prepare,
    struct plamen_broker_v2_service_session_ack *,
    struct plamen_broker_v2_authority_bundle_binding *);

/*
 * Recover an exact prepared or already-consumed session.  The OPEN envelope
 * and key digest must match the durable PREPARED bytes.  If the prior process
 * crashed between PREPARED and CONSUMED, this publishes CONSUMED using the
 * already-stored capability roster; it never mints replacements or makes the
 * registration unused.
 */
int plamen_broker_v2_service_store_recover_consumed(
    struct plamen_broker_v2_service_store *,
    const struct plamen_broker_v2_service_session_open *,
    const uint8_t request_envelope_sha256[32],
    const uint8_t key_sha256[32],
    struct plamen_broker_v2_service_consumed_session *);

/*
 * Commit or recover a lane-bound child session of an already-consumed active
 * interpreter session.  The raw session key is never persisted.  Identical
 * OPEN replay recovers the same ACK; a divergent peer, lane, key, envelope,
 * parent binding, or specialized-session identifier is a permanent conflict.
 */
int plamen_broker_v2_service_store_consume_specialized(
    struct plamen_broker_v2_service_store *,
    const struct plamen_broker_v2_service_session_ack *,
    const struct plamen_broker_v2_service_specialized_session_challenge *,
    const struct plamen_broker_v2_service_specialized_session_open *,
    const uint8_t request_envelope_sha256[32],
    const uint8_t key[32], int allow_new,
    struct plamen_broker_v2_service_specialized_session_ack *);
int plamen_broker_v2_service_store_recover_specialized(
    struct plamen_broker_v2_service_store *,
    const struct plamen_broker_v2_service_specialized_session_open *,
    const uint8_t request_envelope_sha256[32],
    const uint8_t key[32],
    struct plamen_broker_v2_service_consumed_specialized_session *);

/*
 * Prove that a new operation is bound to this durable session and that its
 * input capability is a valid, unconsumed predecessor before any external
 * effect is attempted.  Existing operation nonces and divergent request
 * digests are conflicts; this function never mutates the journal.
 */
int plamen_broker_v2_service_store_specialized_preflight(
    struct plamen_broker_v2_service_store *,
    const struct plamen_broker_v2_service_specialized_session_ack *,
    const struct plamen_broker_v2_specialized_request *,
    const uint8_t request_sha256[32]);

/*
 * Persist the exact authenticated response bytes before they cross the
 * specialized socket.  The store owns capability issuance/consumption and
 * returns an immutable copy on exact replay.  Caller terminal bytes are only
 * accepted for a new operation after the lane executor has authenticated
 * them.  A replay never calls that executor again.
 */
int plamen_broker_v2_service_store_specialized_operation(
    struct plamen_broker_v2_service_store *,
    const struct plamen_broker_v2_service_specialized_session_ack *,
    const struct plamen_broker_v2_specialized_request *,
    const uint8_t request_sha256[32], const uint8_t *terminal,
    size_t terminal_size, int allow_new,
    struct plamen_broker_v2_specialized_response *,
    uint8_t **response_wire, size_t *response_wire_size);

/*
 * Commit one immutable out-of-band response object for an authenticated
 * specialized operation.  The object name binds session, operation nonce,
 * and exact request digest.  It is published owner-read-only before the
 * operation response may be journaled; a crash can leave only an inert
 * orphan, never an authoritative response.  The returned descriptor is a
 * caller-owned O_RDONLY|CLOEXEC exact replay of the committed bytes.
 */
int plamen_broker_v2_service_store_specialized_attachment_prepare(
    struct plamen_broker_v2_service_store *,
    const struct plamen_broker_v2_service_specialized_session_ack *,
    const struct plamen_broker_v2_specialized_request *,
    const uint8_t request_sha256[32], const uint8_t *bytes, size_t size,
    struct plamen_broker_v2_specialized_attachment *);

/*
 * Reopen only after the exact operation response is durable.  The store
 * independently rejoins the current request to that operation record and
 * then revalidates the immutable attachment digest/size before returning it.
 */
int plamen_broker_v2_service_store_specialized_attachment_reopen(
    struct plamen_broker_v2_service_store *,
    const struct plamen_broker_v2_service_specialized_session_ack *,
    const struct plamen_broker_v2_specialized_request *,
    const uint8_t request_sha256[32], const uint8_t expected_sha256[32],
    uint64_t expected_size,
    struct plamen_broker_v2_specialized_attachment *);

void plamen_broker_v2_service_store_specialized_attachment_dispose(
    struct plamen_broker_v2_specialized_attachment *);

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
/* Inject exactly one crash-equivalent return after PREPARED is durable. */
void plamen_broker_v2_service_store_TEST_ONLY_fail_after_prepare_once(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
