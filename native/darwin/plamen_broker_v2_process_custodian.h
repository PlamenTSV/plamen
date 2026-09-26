#ifndef PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_H
#define PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_H

#include "plamen_broker_v2_process.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_VERSION 1U

enum plamen_broker_v2_process_custodian_status {
    PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK = 0,
    PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED = 1,
    PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT = 2,
    PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_BUSY = 3,
    PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS = 4,
    PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR = 5
};

struct plamen_broker_v2_process_custodian;

struct plamen_broker_v2_process_custodian_start_request {
    uint32_t version;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t prior_checkpoint_sha256[32];
    uint8_t claim_owner_sha256[32];
    const struct plamen_broker_v2_process_spec *process_spec;
};

struct plamen_broker_v2_process_custodian_start_receipt {
    uint32_t version;
    uint32_t status;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t prior_checkpoint_sha256[32];
    uint8_t claim_owner_sha256[32];
    uint8_t process_spec_sha256[32];
    uint8_t prepared_checkpoint_sha256[32];
    struct plamen_broker_v2_process_start_identity identity;
    uint8_t started_checkpoint_sha256[32];
};

/*
 * Read-only adoption after a client/service session is replaced.  This form
 * deliberately carries no descriptors and can never create a process.  The
 * daemon may satisfy it only from its retained live registry.  A replacement
 * daemon that sees only disk records returns RESTART_AMBIGUOUS.
 */
struct plamen_broker_v2_process_custodian_start_recovery_request {
    uint32_t version;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t prior_checkpoint_sha256[32];
    uint8_t claim_owner_sha256[32];
};

struct plamen_broker_v2_process_custodian_terminal_request {
    uint32_t version;
    uint8_t start_operation_key[32];
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t prior_checkpoint_sha256[32];
    uint8_t claim_owner_sha256[32];
};

struct plamen_broker_v2_process_custodian_terminal_receipt {
    uint32_t version;
    uint32_t status;
    uint8_t start_operation_key[32];
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t prior_checkpoint_sha256[32];
    uint8_t claim_owner_sha256[32];
    uint8_t process_spec_sha256[32];
    uint8_t native_process_handle_sha256[32];
    struct plamen_broker_v2_process_terminal terminal;
    uint32_t stdout_retained_size;
    uint32_t stderr_retained_size;
    uint8_t stdout_retained_sha256[32];
    uint8_t stderr_retained_sha256[32];
    uint8_t stdout_spool_checkpoint_sha256[32];
    uint8_t stderr_spool_checkpoint_sha256[32];
    uint8_t prepared_checkpoint_sha256[32];
    uint8_t terminal_checkpoint_sha256[32];
    uint8_t *stdout_retained;
    uint8_t *stderr_retained;
};

/*
 * The custodian is process-owned, not session-owned.  Closing a client
 * session does not close it or its child.  A durable terminal record can be
 * decoded after custody-daemon restart.  A daemon restart while only
 * PREPARED/STARTED is
 * durable is deliberately reported as RESTART_AMBIGUOUS: Darwin cannot
 * transfer wait(2), kqueue, or pipe ownership to a replacement broker.
 */
int plamen_broker_v2_process_custodian_open(
    int state_parent_fd, struct plamen_broker_v2_process_custodian **);
void plamen_broker_v2_process_custodian_close(
    struct plamen_broker_v2_process_custodian *);

int plamen_broker_v2_process_custodian_start(
    struct plamen_broker_v2_process_custodian *,
    const struct plamen_broker_v2_process_custodian_start_request *,
    struct plamen_broker_v2_process_custodian_start_receipt *);
int plamen_broker_v2_process_custodian_recover_start(
    struct plamen_broker_v2_process_custodian *,
    const struct plamen_broker_v2_process_custodian_start_request *,
    struct plamen_broker_v2_process_custodian_start_receipt *);
int plamen_broker_v2_process_custodian_adopt_start(
    struct plamen_broker_v2_process_custodian *,
    const struct plamen_broker_v2_process_custodian_start_recovery_request *,
    struct plamen_broker_v2_process_custodian_start_receipt *);
int plamen_broker_v2_process_custodian_wait(
    struct plamen_broker_v2_process_custodian *,
    const struct plamen_broker_v2_process_custodian_terminal_request *,
    struct plamen_broker_v2_process_custodian_terminal_receipt *);
int plamen_broker_v2_process_custodian_revoke(
    struct plamen_broker_v2_process_custodian *,
    const struct plamen_broker_v2_process_custodian_terminal_request *,
    struct plamen_broker_v2_process_custodian_terminal_receipt *);
int plamen_broker_v2_process_custodian_recover_terminal(
    struct plamen_broker_v2_process_custodian *,
    const struct plamen_broker_v2_process_custodian_terminal_request *,
    struct plamen_broker_v2_process_custodian_terminal_receipt *);
void plamen_broker_v2_process_custodian_terminal_dispose(
    struct plamen_broker_v2_process_custodian_terminal_receipt *);

enum plamen_broker_v2_process_custodian_test_fault {
    PLAMEN_BROKER_V2_CUSTODIAN_FAULT_NONE = 0,
    PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_START_PREPARED = 1,
    PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_PROCESS_PREPARE = 2,
    PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_START_EFFECT = 3,
    PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_STARTED_DURABLE = 4,
    PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_TERMINAL_PREPARED = 5,
    PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_TERMINAL_EFFECT = 6,
    PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_STDOUT_DURABLE = 7,
    PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_STDERR_DURABLE = 8,
    PLAMEN_BROKER_V2_CUSTODIAN_FAULT_AFTER_TERMINAL_DURABLE = 9
};
#ifdef PLAMEN_BROKER_V2_TEST_ONLY
void plamen_broker_v2_process_custodian_TEST_ONLY_fail_once(uint32_t);
/* Simulates replacement of the custody daemon. Refuses with a live child. */
int plamen_broker_v2_process_custodian_TEST_ONLY_forget_terminal_registry(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
