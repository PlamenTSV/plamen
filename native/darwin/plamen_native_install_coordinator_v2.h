#ifndef PLAMEN_NATIVE_INSTALL_COORDINATOR_V2_H
#define PLAMEN_NATIVE_INSTALL_COORDINATOR_V2_H

#include "plamen_native_launchd_installer_v2.h"
#include "plamen_native_deployment_receipt_v2.h"
#include "../posix/plamen_native_installer_v2.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Darwin production coordinator for an already-built/staged generation.
 * The input deployment pointer must be NULL: callers cannot substitute
 * launchd effects.  All descriptors remain caller-owned.
 */
int plamen_native_darwin_install_publish_v2(
    const struct plamen_native_install_request_v2 *,
    struct plamen_native_install_result_v2 *);

/* Recover an interrupted receipt-bound launchd/install transaction. */
int plamen_native_darwin_install_recover_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int *recovered_transaction);

/* Exact, read-only validation of the installed pair, deployment receipt,
 * signed generation closure and live launchd services. */
int plamen_native_darwin_install_validate_installed_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int expected_active_receipt_fd);

/* Resolve an enclosing transaction's retained COMMITTED native publish. */
int plamen_native_darwin_install_finalize_committed_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int expected_successor_receipt_fd);
int plamen_native_darwin_install_rollback_committed_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int expected_successor_receipt_fd, int expected_prior_receipt_fd,
    int expected_prior_present);

#ifdef PLAMEN_NATIVE_INSTALL_COORDINATOR_V2_TESTING
/* Behavioral tests supply deterministic launchd effects, never production. */
int plamen_native_darwin_install_publish_with_effects_v2(
    const struct plamen_native_install_request_v2 *,
    const struct plamen_native_launchd_effects_v2 *,
    struct plamen_native_install_result_v2 *);
int plamen_native_darwin_install_recover_with_effects_v2(int,
    const char *, uid_t, const struct plamen_native_launchd_effects_v2 *, int *);
int plamen_native_darwin_install_validate_installed_with_effects_v2(int,
    const char *, uid_t, int, const struct plamen_native_launchd_effects_v2 *);
int plamen_native_darwin_install_finalize_committed_with_effects_v2(int,
    const char *, uid_t, int, const struct plamen_native_launchd_effects_v2 *);
int plamen_native_darwin_install_rollback_committed_with_effects_v2(int,
    const char *, uid_t, int, int, int,
    const struct plamen_native_launchd_effects_v2 *);
#endif

#ifdef __cplusplus
}
#endif

#endif
