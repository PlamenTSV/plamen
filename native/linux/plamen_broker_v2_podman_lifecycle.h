#ifndef PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_H
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_H

#include "plamen_broker_v2_podman_admission.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Linux outer-provider slice 2.  This ABI defines the closed lifecycle state
 * machine, commands, durable-record format, and authenticated receipts.  The
 * journaled execute entry point implements Linux-only descriptor execution,
 * cgroup-population-zero, overlay cleanup, and restart recovery. Availability
 * remains a release/runtime property until a supported Linux build produces
 * live rootless Podman and systemd-user receipts.
 */
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_VERSION 1U
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECEIPT_VERSION 1U
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_VERSION 1U
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE 640U
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE 832U
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_ARGS 192U
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ARG_SIZE 512U
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_GUEST_ARGS 64U
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_ENV 64U
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_MOUNTS 16U
#define PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OUTPUT_MAX (1024U * 1024U)

enum plamen_broker_v2_podman_lifecycle_result {
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK = 0,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED = 1,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CONFLICT = 2,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED = 3,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_UNSUPPORTED = 78
};

enum plamen_broker_v2_podman_lifecycle_operation {
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE = 1,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START = 2,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_WAIT = 3,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERM = 4,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_KILL = 5,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANUP = 6,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REMOVE = 7,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN = 8,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OBSERVE = 9
};

enum plamen_broker_v2_podman_lifecycle_state {
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_EMPTY = 0,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE_INTENT = 1,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATED_STOPPED = 2,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START_INTENT = 3,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RUNNING = 4,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_WAIT_INTENT = 5,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERM_INTENT = 6,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_KILL_INTENT = 7,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERMINAL = 8,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANUP_INTENT = 9,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANED = 10,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REMOVE_INTENT = 11,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ABSENT = 12,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN_INTENT = 13,
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_SEALED = 14
};

enum plamen_broker_v2_podman_lifecycle_decision {
    PLAMEN_BROKER_V2_PODMAN_DECISION_REJECT = 0,
    PLAMEN_BROKER_V2_PODMAN_DECISION_APPEND_INTENT_THEN_EXECUTE = 1,
    PLAMEN_BROKER_V2_PODMAN_DECISION_REPLAY_COMMITTED = 2,
    PLAMEN_BROKER_V2_PODMAN_DECISION_RECOVER_OBSERVATION_ONLY = 3
};

enum plamen_broker_v2_podman_network_mode {
    PLAMEN_BROKER_V2_PODMAN_NETWORK_NONE = 0,
    PLAMEN_BROKER_V2_PODMAN_NETWORK_VERIFIED_EGRESS_NAMESPACE = 1
};

enum plamen_broker_v2_podman_exit_kind {
    PLAMEN_BROKER_V2_PODMAN_EXIT_NONE = 0,
    PLAMEN_BROKER_V2_PODMAN_EXIT_CODE = 1,
    PLAMEN_BROKER_V2_PODMAN_EXIT_SIGNAL = 2,
    PLAMEN_BROKER_V2_PODMAN_EXIT_TIMEOUT = 3
};

struct plamen_broker_v2_podman_mount_spec {
    int source_fd;
    const char *target;
    uint8_t read_only;
};

struct plamen_broker_v2_podman_lifecycle_spec {
    uint32_t version;
    const char *attempt_name;
    const char *container_id;
    const char *image_reference;
    const char *entrypoint;
    /* This string is never trusted by itself.  Production obtains systemd's
     * D-Bus ControlGroup value and passes it to cgroup_path_revalidate with a
     * retained cgroup-v2 root descriptor immediately before and after every
     * Podman effect. */
    const char *cgroup_parent;
    uint32_t uid;
    uint32_t gid;
    uint32_t pids_limit;
    uint64_t memory_bytes;
    uint32_t cpu_millis;
    uint32_t nofile_limit;
    uint64_t tmpfs_bytes;
    const char *const *guest_argv;
    size_t guest_argc;
    const char *const *environment;
    size_t environment_count;
    const struct plamen_broker_v2_podman_mount_spec *mounts;
    size_t mount_count;
    int seccomp_profile_fd;
    uint32_t network_mode;
    int network_namespace_fd;
    /* Broker-authenticated handoff digest for the retained namespace FD. */
    uint8_t verified_egress_handoff_sha256[32];
    uint8_t request_sha256[32];
    uint8_t operation_key[32];
    uint32_t timeout_ms;
    uint32_t output_limit;
};

struct plamen_broker_v2_podman_lifecycle_command {
    uint32_t operation;
    size_t argc;
    char storage[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_ARGS]
        [PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ARG_SIZE];
    const char *argv[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_ARGS + 1U];
};

struct plamen_broker_v2_podman_lifecycle_receipt {
    uint32_t version;
    uint32_t operation;
    uint32_t from_state;
    uint32_t to_state;
    uint32_t result;
    uint32_t exit_kind;
    int32_t exit_code;
    int32_t signal_number;
    uint32_t timed_out;
    uint32_t stdout_size;
    uint32_t stderr_size;
    uint32_t stdout_truncated;
    uint32_t stderr_truncated;
    uint32_t cgroup_population_zero;
    uint32_t overlay_cleanup_complete;
    uint32_t container_absent;
    uint32_t receipt_requires_broker_authentication;
    uint32_t lifecycle_authority_granted;
    uint64_t journal_sequence;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t admission_sha256[32];
    uint8_t compiled_lifecycle_sha256[32];
    uint8_t host_boot_id_sha256[32];
    uint8_t command_sha256[32];
    uint8_t stdout_sha256[32];
    uint8_t stderr_sha256[32];
    uint8_t cgroup_terminal_sha256[32];
    uint8_t overlay_cleanup_sha256[32];
    uint8_t previous_checkpoint_sha256[32];
    uint8_t checkpoint_sha256[32];
    uint8_t receipt_sha256[32];
};

struct plamen_broker_v2_podman_lifecycle_journal;

struct plamen_broker_v2_podman_lifecycle_head {
    uint32_t state;
    uint32_t operation;
    uint64_t sequence;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t checkpoint_sha256[32];
    struct plamen_broker_v2_podman_lifecycle_receipt committed;
    uint8_t has_committed_receipt;
};

int plamen_broker_v2_podman_lifecycle_transition_valid(
    uint32_t from_state, uint32_t to_state, uint32_t operation);
int plamen_broker_v2_podman_lifecycle_decide(
    const struct plamen_broker_v2_podman_lifecycle_head *,
    const struct plamen_broker_v2_podman_lifecycle_spec *, uint32_t operation,
    uint32_t *decision);
int plamen_broker_v2_podman_lifecycle_render_command(
    const struct plamen_broker_v2_podman_admission_spec *,
    const struct plamen_broker_v2_podman_lifecycle_spec *, uint32_t operation,
    struct plamen_broker_v2_podman_lifecycle_command *);
int plamen_broker_v2_podman_lifecycle_command_sha256(
    const struct plamen_broker_v2_podman_lifecycle_command *, uint8_t out[32]);
int plamen_broker_v2_podman_lifecycle_parse_wait_status(
    const uint8_t *stdout_bytes, size_t stdout_size, int32_t *exit_code);
int plamen_broker_v2_podman_lifecycle_receipt_seal(
    struct plamen_broker_v2_podman_lifecycle_receipt *);
int plamen_broker_v2_podman_lifecycle_receipt_validate(
    const struct plamen_broker_v2_podman_lifecycle_receipt *);
int plamen_broker_v2_podman_lifecycle_record_encode(
    const struct plamen_broker_v2_podman_lifecycle_receipt *,
    uint8_t out[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE]);
int plamen_broker_v2_podman_lifecycle_record_decode(
    const uint8_t record[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE],
    struct plamen_broker_v2_podman_lifecycle_receipt *);

/* Descriptor-rooted, immutable, append-only state.  Every entry is written
 * O_EXCL, fsynced, and followed by a directory fsync.  An unmatched intent is
 * recoverable only by exact observation; append_intent never repeats it. */
int plamen_broker_v2_podman_lifecycle_journal_open(
    int parent_fd, const char *journal_id,
    const uint8_t admission_sha256[32],
    const uint8_t compiled_lifecycle_sha256[32],
    const uint8_t host_boot_id_sha256[32],
    struct plamen_broker_v2_podman_lifecycle_journal **out);
void plamen_broker_v2_podman_lifecycle_journal_close(
    struct plamen_broker_v2_podman_lifecycle_journal *);
int plamen_broker_v2_podman_lifecycle_journal_replay(
    struct plamen_broker_v2_podman_lifecycle_journal *,
    struct plamen_broker_v2_podman_lifecycle_head *);
int plamen_broker_v2_podman_lifecycle_journal_append_intent(
    struct plamen_broker_v2_podman_lifecycle_journal *,
    const struct plamen_broker_v2_podman_lifecycle_spec *,
    uint32_t operation, const uint8_t command_sha256[32],
    uint8_t checkpoint_sha256[32]);
int plamen_broker_v2_podman_lifecycle_journal_commit(
    struct plamen_broker_v2_podman_lifecycle_journal *,
    const struct plamen_broker_v2_podman_lifecycle_receipt *,
    uint8_t checkpoint_sha256[32]);

/* Reopen systemd's exact ControlGroup value beneath a retained cgroup-v2 root
 * with openat2 anti-traversal policy, then match device/inode/mount identity
 * to the admitted leaf.  The absolute property is data returned by systemd's
 * native API; this function never discovers it from argv or environment. */
int plamen_broker_v2_podman_cgroup_path_revalidate(
    const struct plamen_broker_v2_podman_admission_custody *,
    int cgroup_root_fd, const char *systemd_control_group);

/* Compatibility entrypoint has no journal/control-group authority and rejects
 * on Linux. Production callers must use execute_journaled. */
int plamen_broker_v2_podman_lifecycle_execute(
    const struct plamen_broker_v2_podman_admission_custody *,
    const struct plamen_broker_v2_podman_lifecycle_spec *, uint32_t operation,
    struct plamen_broker_v2_podman_lifecycle_receipt *);

/* Production mutation entrypoint.  The caller supplies the already-open
 * durable journal and the exact systemd ControlGroup result.  Intent is
 * fsynced before the descriptor-executed Podman effect; ambiguous execution
 * leaves the intent unresolved and returns RECOVERY_REQUIRED. */
int plamen_broker_v2_podman_lifecycle_execute_journaled(
    const struct plamen_broker_v2_podman_admission_custody *,
    int cgroup_root_fd, const char *systemd_control_group,
    struct plamen_broker_v2_podman_lifecycle_journal *,
    const struct plamen_broker_v2_podman_lifecycle_spec *, uint32_t operation,
    uint8_t *stdout_bytes, size_t stdout_capacity, size_t *stdout_size,
    uint8_t *stderr_bytes, size_t stderr_capacity, size_t *stderr_size,
    struct plamen_broker_v2_podman_lifecycle_receipt *);

#ifdef PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEST_ONLY
int plamen_broker_v2_podman_lifecycle_test_render(
    uint32_t operation, uint32_t network_mode, uint8_t *output,
    size_t capacity, size_t *output_size);
int plamen_broker_v2_podman_lifecycle_test_receipt_and_record_integrity(void);
int plamen_broker_v2_podman_lifecycle_test_decision(
    uint32_t head_state, uint32_t same_key, uint32_t divergent_request,
    uint32_t *decision);
int plamen_broker_v2_podman_lifecycle_test_journal_roundtrip(
    int parent_fd, const char *journal_id);
int plamen_broker_v2_podman_lifecycle_test_journal_replay(
    int parent_fd, const char *journal_id);
int plamen_broker_v2_podman_lifecycle_test_journal_wrong_boot_rejected(
    int parent_fd, const char *journal_id);
#endif

#ifdef __cplusplus
}
#endif

#endif
