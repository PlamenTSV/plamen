#ifndef PLAMEN_BROKER_V2_PROCESS_CUSTODY_CLIENT_H
#define PLAMEN_BROKER_V2_PROCESS_CUSTODY_CLIENT_H

#include "../include/plamen_broker_v2.h"
#include "plamen_broker_v2_process_custodian.h"

#include <stdint.h>
#include <xpc/xpc.h>

#ifdef __cplusplus
extern "C" {
#endif

enum plamen_broker_v2_custody_client_status {
    PLAMEN_BROKER_V2_CUSTODY_CLIENT_OK = 0,
    PLAMEN_BROKER_V2_CUSTODY_CLIENT_TRANSPORT_AMBIGUOUS = 1,
    PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED = 2,
    PLAMEN_BROKER_V2_CUSTODY_CLIENT_PEER_REJECTED = 3,
    PLAMEN_BROKER_V2_CUSTODY_CLIENT_INTERNAL_ERROR = 4
};

struct plamen_broker_v2_process_custody_client;
struct plamen_broker_v2_custody_daemon_readiness;
typedef int (*plamen_broker_v2_custody_client_peer_admit)(xpc_connection_t);

/*
 * The daemon transport has a fresh, non-secret session ID per XPC connection.
 * The framed broker HMAC key never crosses this API.  Reconnect rotates the
 * transport session ID; recovery remains bound solely to the authenticated
 * operation key/request/prior/claim tuple.
 */
int plamen_broker_v2_process_custody_client_open(
    const char *daemon_code_requirement,
    plamen_broker_v2_custody_client_peer_admit,
    struct plamen_broker_v2_process_custody_client **);
void plamen_broker_v2_process_custody_client_close(
    struct plamen_broker_v2_process_custody_client *);

int plamen_broker_v2_process_custody_client_readiness(
    struct plamen_broker_v2_process_custody_client *,
    const struct plamen_broker_v2_custody_daemon_readiness *expected,
    uint32_t *daemon_status);

/* Exact broker-frame to daemon-operation mapping; no payload interpretation. */
int plamen_broker_v2_process_custody_client_frame_mapping(
    uint16_t request_type, uint16_t *response_type, const char **operation);

int plamen_broker_v2_process_custody_client_start(
    struct plamen_broker_v2_process_custody_client *,
    const struct plamen_broker_v2_process_custodian_start_request *,
    struct plamen_broker_v2_process_custodian_start_receipt *,
    uint32_t *daemon_status);
int plamen_broker_v2_process_custody_client_adopt(
    struct plamen_broker_v2_process_custody_client *,
    const struct plamen_broker_v2_process_custodian_start_recovery_request *,
    struct plamen_broker_v2_process_custodian_start_receipt *,
    uint32_t *daemon_status);
int plamen_broker_v2_process_custody_client_wait(
    struct plamen_broker_v2_process_custody_client *,
    const struct plamen_broker_v2_process_custodian_terminal_request *,
    struct plamen_broker_v2_process_custodian_terminal_receipt *,
    uint32_t *daemon_status);
int plamen_broker_v2_process_custody_client_recover(
    struct plamen_broker_v2_process_custody_client *,
    const struct plamen_broker_v2_process_custodian_terminal_request *,
    struct plamen_broker_v2_process_custodian_terminal_receipt *,
    uint32_t *daemon_status);
int plamen_broker_v2_process_custody_client_revoke(
    struct plamen_broker_v2_process_custody_client *,
    const struct plamen_broker_v2_process_custodian_terminal_request *,
    struct plamen_broker_v2_process_custodian_terminal_receipt *,
    uint32_t *daemon_status);

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
int plamen_broker_v2_process_custody_client_TEST_ONLY_open_endpoint(
    xpc_endpoint_t,
    struct plamen_broker_v2_process_custody_client **);
void plamen_broker_v2_process_custody_client_TEST_ONLY_disconnect(
    struct plamen_broker_v2_process_custody_client *);
#endif

#ifdef __cplusplus
}
#endif

#endif
