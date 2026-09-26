#ifndef PLAMEN_NATIVE_LAUNCHD_INSTALLER_V2_H
#define PLAMEN_NATIVE_LAUNCHD_INSTALLER_V2_H

#include "plamen_broker_v2_install_receipt.h"
#include "../posix/plamen_native_installer_v2.h"

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_LAUNCHD_BROKER_LABEL "com.plamen.audit.broker.v2"
#define PLAMEN_LAUNCHD_CUSTODY_LABEL \
    "com.plamen.audit.process-custody.v2"

enum plamen_launchd_role_v2 {
    PLAMEN_LAUNCHD_ROLE_BROKER_V2 = 1,
    PLAMEN_LAUNCHD_ROLE_CUSTODY_V2 = 2
};

enum plamen_launchd_action_v2 {
    PLAMEN_LAUNCHD_BOOTOUT_V2 = 1,
    PLAMEN_LAUNCHD_BOOTSTRAP_V2 = 2,
    PLAMEN_LAUNCHD_ENABLE_V2 = 3,
    PLAMEN_LAUNCHD_KICKSTART_V2 = 4,
    PLAMEN_LAUNCHD_PRINT_V2 = 5
};

/* Deterministic deployment plist bytes; the output is chmod(0400)+fsync'd. */
int plamen_native_launchd_render_plist_v2(int output_fd,
    const char *service_absolute_path, enum plamen_launchd_role_v2);

/* Exact-byte validation, including Label, MachServices and ProgramArguments. */
int plamen_native_launchd_validate_plist_v2(int retained_fd,
    const char *service_absolute_path, enum plamen_launchd_role_v2);

/* Fixed /bin/launchctl argv only.  No shell or environment lookup is used. */
int plamen_native_launchd_run_v2(uid_t, enum plamen_launchd_role_v2,
    enum plamen_launchd_action_v2, const char *plist_absolute_path,
    int *exit_status);

/* Validate both retained plist identities and the receipt-bound service code. */
int plamen_native_launchd_validate_deployment_v2(
    const struct plamen_install_receipt *, int generation_fd,
    int broker_plist_fd, int custody_plist_fd);

struct plamen_native_launchd_effects_v2 {
    void *context;
    int (*run)(void *, uid_t, enum plamen_launchd_role_v2,
        enum plamen_launchd_action_v2, const char *, int *exit_status);
    /*
     * Must authenticate the broker peer and match the exact receipt closure.
     * It is invoked only after both jobs are started; broker readiness is
     * transitive custody readiness because broker startup hard-fails unless
     * its receipt-bound custody status exchange succeeds.
     */
    int (*ready)(void *, enum plamen_launchd_role_v2,
        const struct plamen_install_receipt *);
};

struct plamen_native_launchd_closure_v2 {
    const struct plamen_install_receipt *receipt;
    int generation_fd;
    int broker_plist_fd;
    int custody_plist_fd;
};

struct plamen_native_launchd_transaction_v2 {
    uid_t owner_uid;
    struct plamen_native_launchd_closure_v2 replacement;
    struct plamen_native_launchd_closure_v2 prior;
    int prior_present;
    struct plamen_native_launchd_effects_v2 effects;
};

/* Bind the fixed launchctl runner and receipt-bound launcher readiness probe. */
int plamen_native_launchd_production_effects_v2(
    struct plamen_native_launchd_transaction_v2 *);

/* Populate the generic installer's pre-commit deployment callbacks. */
int plamen_native_launchd_deployment_hooks_v2(
    struct plamen_native_launchd_transaction_v2 *,
    struct plamen_native_install_deployment_v2 *);

/* Boot out both fixed jobs and prove both are absent. */
int plamen_native_launchd_uninstall_v2(
    struct plamen_native_launchd_transaction_v2 *);

#ifdef __cplusplus
}
#endif

#endif
