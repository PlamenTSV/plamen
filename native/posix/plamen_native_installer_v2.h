#ifndef PLAMEN_NATIVE_INSTALLER_V2_H
#define PLAMEN_NATIVE_INSTALLER_V2_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_NATIVE_INSTALLER_V2_GENERATION_HEX_SIZE 64U
#define PLAMEN_NATIVE_INSTALLER_V2_RECEIPT_SIZE 16384U
#define PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT 10U

/*
 * The caller retains ownership of every descriptor.  The implementation
 * duplicates and retains them for the complete transaction.  No path is
 * derived from HOME or the process environment.
 */
struct plamen_native_install_request_v2 {
    int install_root_fd;
    int staging_parent_fd;
    int receipt_fd;
    int specialized_authority_fd;
    uint16_t require_specialized_authority;
    int source_bootstrap_authority_fd;
    uint16_t require_source_bootstrap_authority;
    /*
     * Keep the authenticated predecessor pair and durable COMMITTED marker
     * after publication.  This is used only by an enclosing cold-install
     * transaction, which must subsequently call exactly one of finalize or
     * rollback with the retained successor receipt authority.
     */
    uint16_t retain_postcommit_rollback;
    /* Exact receipt role order, launcher through runtime manifest. */
    int generation_member_fds[PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT];
    const char *install_root_absolute;
    const char *staged_generation_name;
    const char *generation_id_hex;
    uid_t owner_uid;
    /*
     * Optional platform deployment authority.  These callbacks execute while
     * the native install lock and durable transaction marker are retained.
     * prepare must be effect-free outside the install root.  activate may
     * perform platform service effects only after DEPLOYMENT_PREPARED is
     * durable.  rollback and commit must be idempotent recovery operations.
     */
    const struct plamen_native_install_deployment_v2 *deployment;
};

struct plamen_native_install_deployment_v2 {
    void *context;
    /*
     * Reconstruct retained platform closure descriptors after a process
     * restart and before rollback/commit observes or changes platform state.
     * The generic installer has already authenticated the durable marker and
     * supplies its exact deployment state.  This callback must be idempotent
     * and must not perform deployment effects.
     */
    int (*bind_recovery)(void *, uint32_t durable_state,
        const uint8_t generation_id[32], int prior_receipt_present);
    int (*prepare)(void *, uint32_t *durable_state);
    int (*activate)(void *, uint32_t durable_state);
    /* Revoke replacement effects before the generic pair is restored. */
    int (*rollback)(void *, uint32_t durable_state);
    /* Re-activate prior effects only after the old receipt/launcher exist. */
    int (*restore)(void *, uint32_t durable_state);
    int (*commit)(void *, uint32_t durable_state);
};

struct plamen_native_install_result_v2 {
    int recovered_prior_transaction;
    int generation_already_present;
};

/*
 * Publish one already-built, read-only generation.  The install root must
 * already contain owner-controlled generations/, bin/, and share/plamen/
 * directories.  On success the active receipt is durable and the stable
 * launcher is a hardlink to the receipt-bound generation launcher.
 */
int plamen_native_installer_publish_v2(
    const struct plamen_native_install_request_v2 *,
    struct plamen_native_install_result_v2 *);

/*
 * Recover a durable interrupted transaction.  PRE-COMMIT transactions are
 * rolled back; COMMITTED transactions are finalized.  The operation is
 * idempotent and returns success when no marker exists.
 */
int plamen_native_installer_recover_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int *recovered_transaction);

/* Platform-aware recovery for transactions which crossed deployment prepare. */
int plamen_native_installer_recover_with_deployment_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    const struct plamen_native_install_deployment_v2 *,
    int *recovered_transaction);

/* Read-only exact active-pair validation under the already-existing lock. */
int plamen_native_installer_validate_installed_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int expected_active_receipt_fd);

/* Resolve an explicitly retained COMMITTED transaction in one direction. */
int plamen_native_installer_finalize_committed_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int expected_successor_receipt_fd,
    const struct plamen_native_install_deployment_v2 *);
int plamen_native_installer_rollback_committed_v2(int install_root_fd,
    const char *install_root_absolute, uid_t owner_uid,
    int expected_successor_receipt_fd,
    int expected_prior_receipt_fd, int expected_prior_present,
    const struct plamen_native_install_deployment_v2 *);

#ifdef PLAMEN_NATIVE_INSTALLER_V2_TESTING
/* Process-local crash boundary used only by native transaction tests. */
int plamen_native_installer_test_crash_after_phase_v2(int phase);
#endif

#ifdef __cplusplus
}
#endif

#endif
