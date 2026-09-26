#ifndef PLAMEN_BROKER_V2_JOURNAL_H
#define PLAMEN_BROKER_V2_JOURNAL_H

#include "../include/plamen_broker_v2.h"

#define PLAMEN_BROKER_V2_JOURNAL_VERSION 2U
#define PLAMEN_BROKER_V2_JOURNAL_HEADER_SIZE 192U
#define PLAMEN_BROKER_V2_JOURNAL_MAX_RECORDS 1000000U

enum plamen_broker_v2_journal_state {
    PLAMEN_BROKER_V2_JOURNAL_PREPARED = 1,
    PLAMEN_BROKER_V2_JOURNAL_STARTED = 2,
    PLAMEN_BROKER_V2_JOURNAL_WAIT_PREPARED = 3,
    PLAMEN_BROKER_V2_JOURNAL_EXITED = 4,
    PLAMEN_BROKER_V2_JOURNAL_REVOKE_PREPARED = 5,
    PLAMEN_BROKER_V2_JOURNAL_REVOKED = 6
};

struct plamen_broker_v2_journal;

struct plamen_broker_v2_journal_record {
    uint64_t sequence;
    uint16_t state;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t previous_checkpoint_sha256[32];
    uint8_t payload_sha256[32];
    uint8_t checkpoint_sha256[32];
    const uint8_t *payload;
    uint32_t payload_size;
    const uint8_t *canonical_bytes;
    size_t canonical_size;
};

typedef int (*plamen_broker_v2_journal_visitor)(
    const struct plamen_broker_v2_journal_record *, void *);

/*
 * parent_fd must be a retained descriptor for a private, trusted directory.
 * journal_id uses the wire ID grammar.  The returned object owns only duplicated
 * descriptors; it never converts descriptors to ambient paths.
 */
int plamen_broker_v2_journal_open(int parent_fd, const char *journal_id,
    struct plamen_broker_v2_journal **out);
void plamen_broker_v2_journal_close(struct plamen_broker_v2_journal *);

/* Validate every immutable record and its hash chain while holding the lock. */
int plamen_broker_v2_journal_replay(struct plamen_broker_v2_journal *,
    plamen_broker_v2_journal_visitor, void *,
    struct plamen_broker_v2_journal_record *head);

/*
 * Append with compare-and-swap.  Repeating byte-identical input returns the
 * already durable checkpoint; any divergent contender returns CONFLICT.
 */
int plamen_broker_v2_journal_append(struct plamen_broker_v2_journal *,
    uint16_t state, const uint8_t operation_key[32],
    const uint8_t request_sha256[32],
    const uint8_t expected_previous_checkpoint_sha256[32],
    const uint8_t *payload, uint32_t payload_size,
    uint8_t checkpoint_sha256[32]);

/* Return an allocated copy of an exact durable payload; caller must zero/free. */
int plamen_broker_v2_journal_recover(struct plamen_broker_v2_journal *,
    uint16_t state, const uint8_t operation_key[32],
    const uint8_t request_sha256[32], uint8_t **payload,
    uint32_t *payload_size, uint8_t checkpoint_sha256[32]);

#endif
