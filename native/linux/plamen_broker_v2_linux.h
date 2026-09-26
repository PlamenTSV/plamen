#ifndef PLAMEN_BROKER_V2_LINUX_H
#define PLAMEN_BROKER_V2_LINUX_H

#include "../include/plamen_broker_v2.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Linux has no code-signing identity equivalent to the Darwin audit-token
 * admission path.  The installed executable's retained descriptor identity is
 * therefore the closure identity.  Every session keeps a pidfd and repeats the
 * SO_PEERCRED, /proc start-time, boot-id, and executable checks around I/O.
 */
struct plamen_broker_v2_linux_session {
    int socket_fd;
    int peer_pidfd;
    struct plamen_broker_v2_peer_identity peer;
    uint8_t expected_executable_identity[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t burned;
};

/*
 * systemd Accept=yes passes one connected SOCK_SEQPACKET endpoint as fd 0.
 * This function never consults LISTEN_FDS, argv, a path, or the environment.
 */
int plamen_broker_v2_linux_take_systemd_connection(int *connected_socket_out);
int plamen_broker_v2_linux_session_open(
    int connected_socket_fd,
    const uint8_t expected_executable_identity[PLAMEN_BROKER_V2_DIGEST_SIZE],
    struct plamen_broker_v2_linux_session *session);
int plamen_broker_v2_linux_session_revalidate(
    struct plamen_broker_v2_linux_session *session);
int plamen_broker_v2_linux_session_send_owned(
    struct plamen_broker_v2_linux_session *session,
    const uint8_t *envelope, size_t envelope_size,
    int fds[PLAMEN_BROKER_V2_SERVICE_MAX_FDS], size_t fd_count);
int plamen_broker_v2_linux_session_receive(
    struct plamen_broker_v2_linux_session *session, uint8_t local_role,
    uint8_t **envelope, size_t *envelope_size,
    int fds[PLAMEN_BROKER_V2_SERVICE_MAX_FDS], size_t *fd_count,
    struct plamen_broker_v2_service_envelope_view *view);
void plamen_broker_v2_linux_session_close(
    struct plamen_broker_v2_linux_session *session);

enum plamen_broker_v2_linux_custody_state {
    PLAMEN_BROKER_V2_LINUX_CUSTODY_EMPTY = 0,
    PLAMEN_BROKER_V2_LINUX_CUSTODY_RUNNING = 1,
    PLAMEN_BROKER_V2_LINUX_CUSTODY_EXITED = 2,
    PLAMEN_BROKER_V2_LINUX_CUSTODY_EXTINCT = 3,
    PLAMEN_BROKER_V2_LINUX_CUSTODY_BURNED = 4
};

enum plamen_broker_v2_linux_process_result {
    PLAMEN_BROKER_V2_LINUX_PROCESS_OK = 0,
    PLAMEN_BROKER_V2_LINUX_PROCESS_EXITED = 1,
    PLAMEN_BROKER_V2_LINUX_PROCESS_TIMED_OUT = 2,
    PLAMEN_BROKER_V2_LINUX_PROCESS_REJECTED = 3,
    PLAMEN_BROKER_V2_LINUX_PROCESS_UNSUPPORTED = 78
};

#define PLAMEN_BROKER_V2_LINUX_ARGC_MAX 128U
#define PLAMEN_BROKER_V2_LINUX_ARG_SIZE_MAX 4096U
#define PLAMEN_BROKER_V2_LINUX_EXTINCTION_TIMEOUT_MAX_MS 300000U

/*
 * A custody leaf is supplied as a retained descriptor by native policy.  It
 * must be an initially empty cgroup-v2 directory exposing cgroup.procs,
 * cgroup.events, and cgroup.kill.  There is deliberately no process-group-only
 * production fallback: a process group cannot prevent descendants from
 * calling setsid(2).  The installed service must additionally make the cgroup
 * filesystem unavailable to the admitted workload (container read-only/masked
 * cgroup mount or an equivalent native policy); this substrate cannot infer
 * that fact and therefore exposes no "production available" boolean.
 */
struct plamen_broker_v2_linux_spawn_request {
    int executable_fd;
    int cwd_fd;
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
    int cgroup_fd;
    const char *const *argv;
    size_t argc;
    uint8_t expected_executable_identity[PLAMEN_BROKER_V2_DIGEST_SIZE];
};

struct plamen_broker_v2_linux_process_custody {
    int cgroup_fd;
    int pidfd;
    pid_t leader_pid;
    pid_t process_group;
    uint64_t start_ticks;
    uint8_t boot_id_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t executable_identity[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t state;
};

struct plamen_broker_v2_linux_wait_result {
    int exited;
    int exit_code;
    int signal_number;
    int timed_out;
    int cgroup_population_zero;
};

int plamen_broker_v2_linux_cgroup_leaf_admit(int cgroup_fd);
int plamen_broker_v2_linux_process_spawn_retained(
    const struct plamen_broker_v2_linux_spawn_request *request,
    struct plamen_broker_v2_linux_process_custody *custody);
int plamen_broker_v2_linux_process_revalidate(
    struct plamen_broker_v2_linux_process_custody *custody);
int plamen_broker_v2_linux_process_wait_or_extinguish(
    struct plamen_broker_v2_linux_process_custody *custody,
    uint32_t timeout_ms, uint32_t extinction_timeout_ms,
    struct plamen_broker_v2_linux_wait_result *result);
int plamen_broker_v2_linux_process_extinguish(
    struct plamen_broker_v2_linux_process_custody *custody,
    uint32_t timeout_ms,
    struct plamen_broker_v2_linux_wait_result *result);
void plamen_broker_v2_linux_process_close(
    struct plamen_broker_v2_linux_process_custody *custody);

#ifdef __cplusplus
}
#endif

#endif
