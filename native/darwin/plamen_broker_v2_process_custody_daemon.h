#ifndef PLAMEN_BROKER_V2_PROCESS_CUSTODY_DAEMON_H
#define PLAMEN_BROKER_V2_PROCESS_CUSTODY_DAEMON_H

#include "plamen_broker_v2_process_custodian.h"

#include <xpc/xpc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_CUSTODY_DAEMON_SERVICE_NAME \
    "com.plamen.audit.process-custody.v2"
#define PLAMEN_BROKER_V2_CUSTODY_DAEMON_MODE \
    "--process-custody-daemon"

typedef int (*plamen_broker_v2_custody_daemon_peer_admit)(
    xpc_connection_t peer);

struct plamen_broker_v2_custody_daemon_readiness {
    uint8_t installation_receipt_sha256[32];
    uint8_t generation_id_sha256[32];
    uint8_t service_sha256[32];
};

/*
 * Runs the independently launchd-owned XPC service and does not return.
 * The caller must have authenticated the installed closure and must pass the
 * daemon-owned custodian.  Session invalidation is deliberately not forwarded
 * to the custodian: live operations belong to the daemon, not to a broker
 * connection.
 */
void plamen_broker_v2_process_custody_daemon_run(
    struct plamen_broker_v2_process_custodian *,
    const struct plamen_broker_v2_custody_daemon_readiness *,
    const char *peer_code_requirement,
    plamen_broker_v2_custody_daemon_peer_admit);

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
/* Exercises the production parser/dispatcher without registering a Mach name. */
int plamen_broker_v2_process_custody_daemon_TEST_ONLY_dispatch(
    struct plamen_broker_v2_process_custodian *, xpc_object_t request,
    xpc_object_t *response);
int plamen_broker_v2_process_custody_daemon_TEST_ONLY_dispatch_readiness(
    struct plamen_broker_v2_process_custodian *,
    const struct plamen_broker_v2_custody_daemon_readiness *,
    xpc_object_t request, xpc_object_t *response);
#endif

#ifdef __cplusplus
}
#endif

#endif
