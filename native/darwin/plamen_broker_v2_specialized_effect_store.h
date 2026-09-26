#ifndef PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_H
#define PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_VERSION 1U
#define PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_TERMINAL_MAX (2U * 1024U * 1024U)

enum plamen_broker_v2_specialized_effect_store_status {
    PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_OK = 0,
    PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_NOT_FOUND = 1,
    PLAMEN_BROKER_V2_SPECIALIZED_EFFECT_STORE_INVALID = -1
};

struct plamen_broker_v2_specialized_effect_store;

struct plamen_broker_v2_specialized_effect_completion {
    uint32_t version;
    uint16_t lane;
    uint16_t method;
    uint32_t flags;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t runtime_authority_sha256[32];
    uint8_t worker_request_sha256[32];
    uint8_t lifecycle_receipt_sha256[32];
    uint8_t terminal_sha256[32];
    uint8_t terminal_hmac_sha256[32];
    uint8_t network_policy_sha256[32];
    uint8_t observed_egress_sha256[32];
    uint8_t provider_authenticated;
    uint8_t network_policy_enforced;
    uint8_t population_zero;
    uint8_t cleanup_complete;
};

/*
 * directory_fd is retained private host custody.  session_key is borrowed
 * only during open, copied into locked process memory, and never serialized.
 * Previously prepared operations replay their already-sealed terminal key;
 * the current session key cannot re-key or replace them.
 */
int plamen_broker_v2_specialized_effect_store_open(int directory_fd,
    const uint8_t session_key[32], const uint8_t runtime_authority_sha256[32],
    struct plamen_broker_v2_specialized_effect_store **);

/* Write-once before any external effect.  Exact replay returns the same key. */
int plamen_broker_v2_specialized_effect_store_prepare(
    struct plamen_broker_v2_specialized_effect_store *, uint16_t lane,
    uint16_t method, const uint8_t operation_key[32],
    const uint8_t request_sha256[32], uint8_t terminal_hmac_key[32],
    int *created);

/*
 * Publishes the exact canonical worker stdin before provider creation and
 * returns a read-only retained descriptor positioned at byte zero.  An
 * existing operation may reopen only byte-identical stdin; a divergent body
 * is rejected and never replaces the first publication.
 */
int plamen_broker_v2_specialized_effect_store_stage_worker_request(
    struct plamen_broker_v2_specialized_effect_store *,
    const uint8_t operation_key[32], const uint8_t *request,
    size_t request_size, int *request_fd, uint8_t request_bytes_sha256[32]);

/* Publish authenticated observed terminal and operation index exactly once. */
int plamen_broker_v2_specialized_effect_store_commit(
    struct plamen_broker_v2_specialized_effect_store *,
    const struct plamen_broker_v2_specialized_effect_completion *,
    const uint8_t *terminal, size_t terminal_size);

/*
 * Operation replay never executes the provider again.  NOT_FOUND is returned
 * only for an absent index name; a malformed, foreign or divergent existing
 * record returns INVALID so callers cannot turn corruption into a relaunch.
 */
int plamen_broker_v2_specialized_effect_store_lookup_operation(
    struct plamen_broker_v2_specialized_effect_store *,
    const uint8_t operation_key[32], const uint8_t request_sha256[32],
    struct plamen_broker_v2_specialized_effect_completion *,
    uint8_t **terminal, size_t *terminal_size);

/* Semantic replay/recovery is indexed by the authenticated terminal digest. */
int plamen_broker_v2_specialized_effect_store_lookup_terminal(
    struct plamen_broker_v2_specialized_effect_store *,
    const uint8_t terminal_sha256[32],
    struct plamen_broker_v2_specialized_effect_completion *,
    uint8_t **terminal, size_t *terminal_size);

void plamen_broker_v2_specialized_effect_store_close(
    struct plamen_broker_v2_specialized_effect_store *);

#ifdef __cplusplus
}
#endif
#endif
