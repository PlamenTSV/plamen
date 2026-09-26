#ifndef PLAMEN_BROKER_V2_PROCESS_H
#define PLAMEN_BROKER_V2_PROCESS_H

#include "../include/plamen_broker_v2.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_SHA256_SIZE 32U
#define PLAMEN_BROKER_V2_SIGNING_TEXT_MAX 256U
#define PLAMEN_BROKER_V2_RETAIN_MAX (1024U * 1024U)
#define PLAMEN_BROKER_V2_OBSERVED_MAX (16U * 1024U * 1024U)
#define PLAMEN_BROKER_V2_PROCESS_ARGC_MAX 64U
#define PLAMEN_BROKER_V2_PROCESS_ENVC_MAX 128U
#define PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX 4096U
#define PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX \
    PLAMEN_BROKER_V2_SERVICE_MAX_FDS
#define PLAMEN_BROKER_V2_PROCESS_TIMEOUT_SECONDS_MAX 259200U

enum plamen_broker_v2_process_status {
    PLAMEN_BROKER_V2_PROCESS_OK = 0,
    PLAMEN_BROKER_V2_PROCESS_TIMEOUT = 1,
    PLAMEN_BROKER_V2_PROCESS_OVERFLOW = 2,
    PLAMEN_BROKER_V2_PROCESS_CANCELLED = 3,
    PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED = 4,
    PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR = 5,
    PLAMEN_BROKER_V2_PROCESS_PRODUCTION_UNAVAILABLE = 78
};

enum plamen_broker_v2_process_environment_policy {
    PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED = 1,
    PLAMEN_BROKER_V2_PROCESS_ENV_EXACT = 2
};

enum plamen_broker_v2_process_stream {
    PLAMEN_BROKER_V2_PROCESS_STREAM_STDOUT = 1,
    PLAMEN_BROKER_V2_PROCESS_STREAM_STDERR = 2
};

struct plamen_broker_v2_process_fd_map {
    int source_fd;
    int target_fd;
};

/*
 * All descriptors and strings are borrowed for this call only.  A successful
 * prepare duplicates the descriptors with CLOEXEC and deep-copies the exact
 * argv/environment.  The executable path is never treated as the authority:
 * executable_fd, its vnode, its content digest, and its code-signing identity
 * are revalidated before spawn and again while the child is suspended.
 */
struct plamen_broker_v2_process_spec {
    uint32_t version;
    int executable_fd;
    const char *executable_path;
    const char *const *argv;
    size_t argc;
    uint32_t environment_policy;
    const char *const *environment;
    size_t environment_count;
    int cwd_fd;
    int stdin_fd;
    const struct plamen_broker_v2_process_fd_map *fd_maps;
    size_t fd_map_count;
    uint32_t timeout_seconds;
    uint32_t stdout_spool_limit;
    uint32_t stderr_spool_limit;
    const uint8_t *expected_executable_sha256;
    const char *expected_signing_identifier;
    const char *expected_team_identifier;
};

struct plamen_broker_v2_process_prepared_identity {
    uint32_t version;
    uint64_t executable_device;
    uint64_t executable_inode;
    uint64_t executable_size;
    uint8_t executable_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t executable_identity_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
};

struct plamen_broker_v2_process_start_identity {
    uint32_t version;
    int32_t child_pid;
    int32_t process_group_id;
    uint64_t child_birth_us;
    uint64_t executable_device;
    uint64_t executable_inode;
    uint8_t executable_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t executable_identity_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t native_process_handle_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t cdhash[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint32_t cdhash_size;
    char signing_identifier[PLAMEN_BROKER_V2_SIGNING_TEXT_MAX];
    char team_identifier[PLAMEN_BROKER_V2_SIGNING_TEXT_MAX];
};

struct plamen_broker_v2_process_terminal {
    uint32_t version;
    uint32_t status;
    int32_t exit_code;
    int32_t signal_number;
    int32_t child_pid;
    int32_t process_group_id;
    uint64_t child_birth_us;
    uint64_t stdout_size;
    uint64_t stderr_size;
    uint8_t stdout_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t stderr_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t stdout_overflow;
    uint8_t stderr_overflow;
    uint8_t child_reaped;
    uint8_t process_group_extinct;
};

struct plamen_broker_v2_process;

/*
 * A handle has one native owner and is deliberately not concurrently callable.
 * The authenticated broker session serializes lifecycle operations and owns the
 * handle until close; exact repeated wait/read calls are replay-safe.
 */

int plamen_broker_v2_process_prepare(
    const struct plamen_broker_v2_process_spec *spec,
    struct plamen_broker_v2_process_prepared_identity *identity,
    struct plamen_broker_v2_process **process);

int plamen_broker_v2_process_start(
    struct plamen_broker_v2_process *process,
    struct plamen_broker_v2_process_start_identity *identity);

int plamen_broker_v2_process_wait(
    struct plamen_broker_v2_process *process,
    struct plamen_broker_v2_process_terminal *terminal);

int plamen_broker_v2_process_read_output(
    struct plamen_broker_v2_process *process, uint32_t stream,
    uint64_t offset, uint32_t maximum, uint8_t *output,
    uint32_t output_capacity, uint32_t *output_size, uint8_t *eof,
    uint8_t chunk_sha256[PLAMEN_BROKER_V2_SHA256_SIZE],
    uint8_t full_sha256[PLAMEN_BROKER_V2_SHA256_SIZE],
    uint64_t *full_size);

int plamen_broker_v2_process_extinguish(
    struct plamen_broker_v2_process *process,
    struct plamen_broker_v2_process_terminal *terminal);

/* Refuses to free a live/unproven process.  Extinguish first on every error. */
int plamen_broker_v2_process_close(struct plamen_broker_v2_process *process);

/*
 * This request is executable only when PLAMEN_BROKER_V2_TEST_ONLY is compiled.
 * It is a native test seam, not a production capability or wire authority.
 */
struct plamen_broker_v2_test_request {
    uint32_t version;
    int executable_fd;
    const char *executable_path;
    const char *const *argv;
    size_t argc;
    int cwd_fd;
    int stdin_fd;
    int pass_fd;
    int pass_target;
    int cancel_fd;
    int test_gate_fd;
    uint32_t timeout_ms;
    uint32_t stdout_retain_limit;
    uint32_t stderr_retain_limit;
    const uint8_t *expected_executable_sha256;
    const char *expected_signing_identifier;
    const char *expected_team_identifier;
};

struct plamen_broker_v2_test_result {
    uint32_t version;
    uint32_t status;
    int32_t exit_code;
    int32_t signal_number;
    int32_t child_pid;
    uint64_t child_birth_us;
    uint8_t executable_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t cdhash[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint32_t cdhash_size;
    char signing_identifier[PLAMEN_BROKER_V2_SIGNING_TEXT_MAX];
    char team_identifier[PLAMEN_BROKER_V2_SIGNING_TEXT_MAX];
    uint8_t stdout_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t stderr_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint64_t stdout_observed;
    uint64_t stderr_observed;
    uint32_t stdout_retained;
    uint32_t stderr_retained;
    uint8_t stdout_truncated;
    uint8_t stderr_truncated;
    uint8_t process_group_extinct;
    uint8_t child_reaped;
    uint8_t *stdout_bytes;
    uint8_t *stderr_bytes;
};

/* One only on Darwin when the production custody implementation is compiled. */
int plamen_broker_v2_production_available(void);

int plamen_broker_v2_test_spawn_wait(
    const struct plamen_broker_v2_test_request *request,
    struct plamen_broker_v2_test_result *result);

void plamen_broker_v2_test_result_dispose(
    struct plamen_broker_v2_test_result *result);

#ifdef __cplusplus
}
#endif

#endif
