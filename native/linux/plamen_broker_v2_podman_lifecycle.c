#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_broker_v2_podman_lifecycle.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/stat.h>
#include <sys/syscall.h>
#endif

#define RECEIPT_CANONICAL_SIZE 512U

static const uint8_t record_magic[8] = {
    'P', 'L', 'P', 'D', 'L', 'C', '2', '\0'
};
static const uint8_t journal_magic[8] = {
    'P', 'L', 'P', 'D', 'J', 'R', '2', '\0'
};

struct plamen_broker_v2_podman_lifecycle_journal {
    int directory_fd;
    int lock_fd;
    uint8_t admission_sha256[32];
    uint8_t compiled_lifecycle_sha256[32];
    uint8_t host_boot_id_sha256[32];
    int poisoned;
};

static void
put_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void
put_u64(uint8_t *out, uint64_t value)
{
    size_t index;
    for (index = 0; index < 8; ++index)
        out[index] = (uint8_t)(value >> ((7U - index) * 8U));
}

static uint32_t
get_u32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t
get_u64(const uint8_t *in)
{
    uint64_t value = 0;
    size_t index;
    for (index = 0; index < 8; ++index) value = (value << 8) | in[index];
    return value;
}

static int
constant_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t different = 0;
    size_t index;
    if (left == NULL || right == NULL) return 0;
    for (index = 0; index < size; ++index) different |= left[index] ^ right[index];
    return different == 0;
}

static int
digest_present(const uint8_t value[32])
{
    uint8_t aggregate = 0;
    size_t index;
    if (value == NULL) return 0;
    for (index = 0; index < 32; ++index) aggregate |= value[index];
    return aggregate != 0;
}

static int
lower_hex(const char *value, size_t count)
{
    size_t index;
    if (value == NULL) return 0;
    for (index = 0; index < count; ++index)
        if (!((value[index] >= '0' && value[index] <= '9')
                || (value[index] >= 'a' && value[index] <= 'f'))) return 0;
    return value[count] == '\0';
}

static int
identifier_valid(const char *value)
{
    size_t index, size;
    if (value == NULL || (size = strlen(value)) == 0 || size > 127) return 0;
    for (index = 0; index < size; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9')
                || byte == '.' || byte == '_' || byte == '-')) return 0;
    }
    return value[0] != '.' && value[0] != '-';
}

static int
absolute_guest_path_valid(const char *value, int mount_target)
{
    const char *component, *cursor;
    size_t length;
    if (value == NULL || value[0] != '/'
        || (length = strlen(value)) < 2 || length >= 256
        || value[length - 1U] == '/') return 0;
    component = value + 1;
    for (cursor = component; ; ++cursor) {
        unsigned char byte = (unsigned char)*cursor;
        if (*cursor == '/' || *cursor == '\0') {
            length = (size_t)(cursor - component);
            if (length == 0 || (length == 1 && component[0] == '.')
                || (length == 2 && component[0] == '.'
                    && component[1] == '.')) return 0;
            if (*cursor == '\0') break;
            component = cursor + 1;
        } else if (byte < 0x21 || byte > 0x7e || byte == '\\'
            || byte == '\'' || byte == '"' || (mount_target && byte == ',')) {
            return 0;
        }
    }
    return 1;
}

static int
argument_valid(const char *value, size_t maximum)
{
    const unsigned char *cursor;
    size_t size;
    if (value == NULL || (size = strlen(value)) == 0 || size > maximum)
        return 0;
    for (cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor)
        if (*cursor < 0x20 || *cursor > 0x7e) return 0;
    return 1;
}

static int
environment_valid(const char *value)
{
    const char *equals;
    size_t index, key_size;
    if (!argument_valid(value, 1024)
        || (equals = strchr(value, '=')) == NULL || equals == value)
        return 0;
    key_size = (size_t)(equals - value);
    if (key_size > 64 || !(value[0] == '_' || (value[0] >= 'A'
            && value[0] <= 'Z'))) return 0;
    for (index = 1; index < key_size; ++index)
        if (!(value[index] == '_' || (value[index] >= 'A'
                && value[index] <= 'Z') || (value[index] >= '0'
                && value[index] <= '9'))) return 0;
    return 1;
}

static int
container_id_valid(const char *value)
{
    return value != NULL && strlen(value) == 64 && lower_hex(value, 64);
}

static int
network_valid(const struct plamen_broker_v2_podman_lifecycle_spec *spec)
{
    if (spec->network_mode == PLAMEN_BROKER_V2_PODMAN_NETWORK_NONE)
        return spec->network_namespace_fd == -1
            && !digest_present(spec->verified_egress_handoff_sha256);
    return spec->network_mode
            == PLAMEN_BROKER_V2_PODMAN_NETWORK_VERIFIED_EGRESS_NAMESPACE
        && spec->network_namespace_fd >= 3
        && digest_present(spec->verified_egress_handoff_sha256);
}

static int
spec_valid(const struct plamen_broker_v2_podman_lifecycle_spec *spec,
    uint32_t operation)
{
    size_t index;
    if (spec == NULL || spec->version != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_VERSION
        || !identifier_valid(spec->attempt_name)
        || !digest_present(spec->request_sha256)
        || !digest_present(spec->operation_key)
        || spec->timeout_ms == 0 || spec->timeout_ms > 86400000U
        || spec->output_limit == 0
        || spec->output_limit > PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OUTPUT_MAX
        || !network_valid(spec)) return 0;
    if (operation != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE
        && operation != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN
        && !container_id_valid(spec->container_id)) return 0;
    if (operation != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE) return 1;
    if (spec->image_reference == NULL
        || strstr(spec->image_reference, "@sha256:") == NULL
        || !absolute_guest_path_valid(spec->entrypoint, 0)
        || !absolute_guest_path_valid(spec->cgroup_parent, 1)
        || spec->uid == 0 || spec->gid == 0 || spec->pids_limit == 0
        || spec->pids_limit > 4096 || spec->memory_bytes < 16U * 1024U * 1024U
        || spec->cpu_millis == 0 || spec->cpu_millis > 64000
        || spec->nofile_limit < 64 || spec->nofile_limit > 1048576
        || spec->tmpfs_bytes < 1024U * 1024U
        || spec->guest_argc > PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_GUEST_ARGS
        || spec->environment_count > PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_ENV
        || spec->mount_count == 0
        || spec->mount_count > PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_MOUNTS
        || (spec->guest_argc != 0 && spec->guest_argv == NULL)
        || (spec->environment_count != 0 && spec->environment == NULL)
        || spec->mounts == NULL || spec->seccomp_profile_fd < 3) return 0;
    for (index = 0; index < spec->guest_argc; ++index)
        if (!argument_valid(spec->guest_argv[index], 4096)) return 0;
    for (index = 0; index < spec->environment_count; ++index)
        if (!environment_valid(spec->environment[index])) return 0;
    for (index = 0; index < spec->mount_count; ++index) {
        size_t prior;
        if (spec->mounts[index].source_fd < 3
            || spec->mounts[index].read_only > 1
            || !absolute_guest_path_valid(spec->mounts[index].target, 1))
            return 0;
        for (prior = 0; prior < index; ++prior)
            if (!strcmp(spec->mounts[index].target,
                    spec->mounts[prior].target)) return 0;
    }
    return 1;
}

int
plamen_broker_v2_podman_lifecycle_transition_valid(uint32_t from,
    uint32_t to, uint32_t operation)
{
    switch (operation) {
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE:
        return (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_EMPTY
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE_INTENT)
            || (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE_INTENT
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATED_STOPPED);
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START:
        return (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATED_STOPPED
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START_INTENT)
            || (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START_INTENT
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RUNNING);
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_WAIT:
        return (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RUNNING
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_WAIT_INTENT)
            || (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_WAIT_INTENT
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERMINAL);
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERM:
        return (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RUNNING
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERM_INTENT)
            || (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERM_INTENT
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERMINAL);
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_KILL:
        return ((from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RUNNING
                    || from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERM_INTENT)
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_KILL_INTENT)
            || (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_KILL_INTENT
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERMINAL);
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANUP:
        return (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERMINAL
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANUP_INTENT)
            || (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANUP_INTENT
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANED);
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REMOVE:
        return ((from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATED_STOPPED
                    || from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANED)
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REMOVE_INTENT)
            || (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REMOVE_INTENT
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ABSENT);
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN:
        return (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ABSENT
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN_INTENT)
            || (from == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN_INTENT
                && to == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_SEALED);
    default:
        return 0;
    }
}

static int
intent_state(uint32_t state)
{
    return state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE_INTENT
        || state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START_INTENT
        || state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_WAIT_INTENT
        || state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERM_INTENT
        || state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_KILL_INTENT
        || state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANUP_INTENT
        || state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REMOVE_INTENT
        || state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN_INTENT;
}

static uint32_t
operation_intent(uint32_t operation)
{
    static const uint32_t values[] = { 0, 1, 3, 5, 6, 7, 9, 11, 13 };
    return operation <= PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN
        ? values[operation] : UINT32_MAX;
}

int
plamen_broker_v2_podman_lifecycle_decide(
    const struct plamen_broker_v2_podman_lifecycle_head *head,
    const struct plamen_broker_v2_podman_lifecycle_spec *spec,
    uint32_t operation, uint32_t *decision)
{
    uint32_t target;
    if (head == NULL || decision == NULL || !spec_valid(spec, operation)
        || operation == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OBSERVE)
        return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
    *decision = PLAMEN_BROKER_V2_PODMAN_DECISION_REJECT;
    if (constant_equal(head->operation_key, spec->operation_key, 32)) {
        if (!constant_equal(head->request_sha256, spec->request_sha256, 32)
            || head->operation != operation)
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CONFLICT;
        if (intent_state(head->state)) {
            *decision = PLAMEN_BROKER_V2_PODMAN_DECISION_RECOVER_OBSERVATION_ONLY;
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
        }
        if (!head->has_committed_receipt
            || plamen_broker_v2_podman_lifecycle_receipt_validate(
                &head->committed) != 0)
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
        *decision = PLAMEN_BROKER_V2_PODMAN_DECISION_REPLAY_COMMITTED;
        return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK;
    }
    target = operation_intent(operation);
    if (target == UINT32_MAX
        || !plamen_broker_v2_podman_lifecycle_transition_valid(
            head->state, target, operation))
        return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CONFLICT;
    *decision = PLAMEN_BROKER_V2_PODMAN_DECISION_APPEND_INTENT_THEN_EXECUTE;
    return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK;
}

static int
command_add(struct plamen_broker_v2_podman_lifecycle_command *command,
    const char *format, const char *text, uint64_t number, int descriptor)
{
    int count;
    size_t index;
    if (command == NULL
        || command->argc >= PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_ARGS)
        return -1;
    index = command->argc;
    if (descriptor >= 0)
        count = snprintf(command->storage[index], sizeof(command->storage[index]),
            format, descriptor);
    else if (text != NULL)
        count = snprintf(command->storage[index], sizeof(command->storage[index]),
            format, text);
    else
        count = snprintf(command->storage[index], sizeof(command->storage[index]),
            format, number);
    if (count < 0 || (size_t)count >= sizeof(command->storage[index])) return -1;
    command->argv[index] = command->storage[index];
    command->argc += 1U;
    command->argv[command->argc] = NULL;
    return 0;
}

#define ADD_LITERAL(command, value) command_add((command), "%s", (value), 0, -1)
#define ADD_NUMBER(command, format, value) \
    command_add((command), (format), NULL, (uint64_t)(value), -1)
#define ADD_FD(command, format, value) \
    command_add((command), (format), NULL, 0, (value))

static int
render_global(const struct plamen_broker_v2_podman_admission_spec *admission,
    struct plamen_broker_v2_podman_lifecycle_command *command)
{
    char option[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ARG_SIZE];
    int fuse_fd = admission->components[
        PLAMEN_BROKER_V2_PODMAN_COMPONENT_FUSE_OVERLAYFS].executable_fd;
    if (ADD_FD(command, "/proc/self/fd/%d", admission->components[
                PLAMEN_BROKER_V2_PODMAN_COMPONENT_PODMAN].executable_fd) != 0
        || ADD_LITERAL(command, "--remote=false") != 0
        || ADD_LITERAL(command, "--root") != 0
        || ADD_FD(command, "/proc/self/fd/%d", admission->roots[
                PLAMEN_BROKER_V2_PODMAN_ROOT_STORAGE].fd) != 0
        || ADD_LITERAL(command, "--runroot") != 0
        || ADD_FD(command, "/proc/self/fd/%d", admission->roots[
                PLAMEN_BROKER_V2_PODMAN_ROOT_RUNROOT].fd) != 0
        || ADD_LITERAL(command, "--tmpdir") != 0
        || ADD_FD(command, "/proc/self/fd/%d", admission->roots[
                PLAMEN_BROKER_V2_PODMAN_ROOT_TMP].fd) != 0
        || ADD_LITERAL(command, "--runtime") != 0
        || ADD_FD(command, "/proc/self/fd/%d", admission->components[
                PLAMEN_BROKER_V2_PODMAN_COMPONENT_CRUN].executable_fd) != 0
        || ADD_LITERAL(command, "--conmon") != 0
        || ADD_FD(command, "/proc/self/fd/%d", admission->components[
                PLAMEN_BROKER_V2_PODMAN_COMPONENT_CONMON].executable_fd) != 0
        || ADD_LITERAL(command, "--cgroup-manager") != 0
        || ADD_LITERAL(command, "cgroupfs") != 0
        || ADD_LITERAL(command, "--events-backend") != 0
        || ADD_LITERAL(command, "file") != 0
        || ADD_LITERAL(command, "--storage-driver") != 0
        || ADD_LITERAL(command, "overlay") != 0) return -1;
    if (snprintf(option, sizeof(option), "mount_program=/proc/self/fd/%d",
            fuse_fd) < 0 || ADD_LITERAL(command, "--storage-opt") != 0
        || ADD_LITERAL(command, option) != 0
        || ADD_LITERAL(command, "--network-config-dir") != 0
        || ADD_FD(command, "/proc/self/fd/%d/empty-networks", admission->roots[
                PLAMEN_BROKER_V2_PODMAN_ROOT_HOME].fd) != 0
        || ADD_LITERAL(command, "--hooks-dir") != 0
        || ADD_FD(command, "/proc/self/fd/%d/empty-hooks", admission->roots[
                PLAMEN_BROKER_V2_PODMAN_ROOT_HOME].fd) != 0) return -1;
    return 0;
}

static int
add_pair(struct plamen_broker_v2_podman_lifecycle_command *command,
    const char *name, const char *value)
{
    return ADD_LITERAL(command, name) == 0 && ADD_LITERAL(command, value) == 0
        ? 0 : -1;
}

static int
render_create(const struct plamen_broker_v2_podman_lifecycle_spec *spec,
    struct plamen_broker_v2_podman_lifecycle_command *command)
{
    static const char *const masks[] = {
        "/proc/acpi", "/proc/interrupts", "/proc/kcore", "/proc/keys",
        "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi",
        "/proc/timer_list", "/proc/timer_stats", "/sys/firmware",
        "/sys/fs/cgroup"
    };
    static const char *const tmpfs_targets[] = {
        "/tmp", "/run", "/var/tmp", "/dev/shm"
    };
    char value[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ARG_SIZE];
    static const char hex[] = "0123456789abcdef";
    char request_label[96];
    size_t index;
    if (ADD_LITERAL(command, "container") != 0
        || ADD_LITERAL(command, "create") != 0
        || add_pair(command, "--name", spec->attempt_name) != 0
        || ADD_LITERAL(command, "--pull=never") != 0
        || ADD_LITERAL(command, "--read-only") != 0
        || ADD_LITERAL(command, "--read-only-tmpfs=false") != 0)
        return -1;
    if (spec->network_mode == PLAMEN_BROKER_V2_PODMAN_NETWORK_NONE) {
        if (ADD_LITERAL(command, "--network=none") != 0) return -1;
    } else if (ADD_FD(command, "--network=ns:/proc/self/fd/%d",
            spec->network_namespace_fd) != 0) return -1;
    if (snprintf(value, sizeof(value), "keep-id:uid=%u,gid=%u,size=65536",
            spec->uid, spec->gid) < 0
        || add_pair(command, "--userns", value) != 0
        || snprintf(value, sizeof(value), "%u:%u", spec->uid, spec->gid) < 0
        || add_pair(command, "--user", value) != 0
        || add_pair(command, "--cgroup-parent", spec->cgroup_parent) != 0
        || ADD_LITERAL(command, "--cgroupns=private") != 0
        || ADD_LITERAL(command, "--cgroups=enabled") != 0
        || ADD_LITERAL(command, "--pid=private") != 0
        || ADD_LITERAL(command, "--ipc=private") != 0
        || ADD_LITERAL(command, "--uts=private") != 0
        || ADD_LITERAL(command, "--cap-drop=all") != 0
        || add_pair(command, "--security-opt", "no-new-privileges") != 0
        || snprintf(value, sizeof(value), "seccomp=/proc/self/fd/%d",
            spec->seccomp_profile_fd) < 0
        || add_pair(command, "--security-opt", value) != 0
        || ADD_LITERAL(command, "--pids-limit") != 0
        || ADD_NUMBER(command, "%llu", spec->pids_limit) != 0
        || ADD_LITERAL(command, "--memory") != 0
        || ADD_NUMBER(command, "%llu", spec->memory_bytes) != 0
        || ADD_LITERAL(command, "--memory-swap") != 0
        || ADD_NUMBER(command, "%llu", spec->memory_bytes) != 0
        || ADD_LITERAL(command, "--cpus") != 0) return -1;
    if (snprintf(value, sizeof(value), "%u.%03u", spec->cpu_millis / 1000U,
            spec->cpu_millis % 1000U) < 0 || ADD_LITERAL(command, value) != 0
        || ADD_LITERAL(command, "--ulimit") != 0
        || snprintf(value, sizeof(value), "nofile=%u:%u", spec->nofile_limit,
            spec->nofile_limit) < 0 || ADD_LITERAL(command, value) != 0
        || add_pair(command, "--ulimit", "core=0:0") != 0
        || ADD_LITERAL(command, "--restart=no") != 0
        || ADD_LITERAL(command, "--unsetenv-all") != 0
        || ADD_LITERAL(command, "--http-proxy=false") != 0
        || ADD_LITERAL(command, "--image-volume=ignore") != 0
        || ADD_LITERAL(command, "--no-healthcheck") != 0
        || add_pair(command, "--hostname", spec->attempt_name) != 0
        || ADD_LITERAL(command, "--hosts-file=none") != 0
        || ADD_LITERAL(command, "--sdnotify=ignore") != 0
        || ADD_LITERAL(command, "--systemd=false") != 0
        || ADD_LITERAL(command, "--log-driver=none") != 0) return -1;
    memcpy(request_label, "io.plamen.request-sha256=", 25);
    for (index = 0; index < 32; ++index) {
        request_label[25 + index * 2U] = hex[spec->request_sha256[index] >> 4];
        request_label[26 + index * 2U] = hex[spec->request_sha256[index] & 15U];
    }
    request_label[89] = '\0';
    if (add_pair(command, "--label", request_label) != 0
        || snprintf(value, sizeof(value), "io.plamen.attempt=%s",
            spec->attempt_name) < 0
        || add_pair(command, "--label", value) != 0) return -1;
    for (index = 0; index < sizeof(masks) / sizeof(masks[0]); ++index) {
        if (snprintf(value, sizeof(value), "mask=%s", masks[index]) < 0
            || add_pair(command, "--security-opt", value) != 0) return -1;
    }
    for (index = 0; index < spec->environment_count; ++index)
        if (add_pair(command, "--env", spec->environment[index]) != 0) return -1;
    for (index = 0; index < spec->mount_count; ++index) {
        if (snprintf(value, sizeof(value),
                "type=bind,source=/proc/self/fd/%d,destination=%s,ro=%s,"
                "bind-propagation=rprivate,bind-nonrecursive",
                spec->mounts[index].source_fd, spec->mounts[index].target,
                spec->mounts[index].read_only ? "true" : "false") < 0
            || add_pair(command, "--mount", value) != 0) return -1;
    }
    for (index = 0; index < sizeof(tmpfs_targets) / sizeof(tmpfs_targets[0]);
            ++index) {
        if (snprintf(value, sizeof(value),
                "%s:rw,nodev,nosuid,noexec,size=%llu,notmpcopyup",
                tmpfs_targets[index], (unsigned long long)spec->tmpfs_bytes) < 0
            || add_pair(command, "--tmpfs", value) != 0) return -1;
    }
    if (add_pair(command, "--entrypoint", spec->entrypoint) != 0
        || ADD_LITERAL(command, spec->image_reference) != 0) return -1;
    for (index = 0; index < spec->guest_argc; ++index)
        if (ADD_LITERAL(command, spec->guest_argv[index]) != 0) return -1;
    return 0;
}

int
plamen_broker_v2_podman_lifecycle_render_command(
    const struct plamen_broker_v2_podman_admission_spec *admission,
    const struct plamen_broker_v2_podman_lifecycle_spec *spec,
    uint32_t operation,
    struct plamen_broker_v2_podman_lifecycle_command *command)
{
    static const char inspect_template[] =
        "{\"id\":{{json .Id}},\"state\":{{json .State.Status}},"
        "\"running\":{{json .State.Running}},"
        "\"exit_code\":{{json .State.ExitCode}},"
        "\"pid\":{{json .State.Pid}},\"conmon_pid\":{{json .State.ConmonPid}}}";
    if (admission == NULL || command == NULL || !spec_valid(spec, operation)
        || (operation == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE
            && (admission->image_reference == NULL
                || strcmp(spec->image_reference,
                    admission->image_reference) != 0)))
        return -1;
    memset(command, 0, sizeof(*command));
    command->operation = operation;
    if (operation == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN) return 0;
    if (render_global(admission, command) != 0) return -1;
    switch (operation) {
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE:
        return render_create(spec, command);
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START:
        return ADD_LITERAL(command, "container") == 0
            && ADD_LITERAL(command, "start") == 0
            && ADD_LITERAL(command, spec->container_id) == 0 ? 0 : -1;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_WAIT:
        return ADD_LITERAL(command, "container") == 0
            && ADD_LITERAL(command, "wait") == 0
            && ADD_LITERAL(command, "--condition=stopped") == 0
            && add_pair(command, "--interval", "250ms") == 0
            && ADD_LITERAL(command, spec->container_id) == 0 ? 0 : -1;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERM:
        return ADD_LITERAL(command, "container") == 0
            && ADD_LITERAL(command, "kill") == 0
            && add_pair(command, "--signal", "TERM") == 0
            && ADD_LITERAL(command, spec->container_id) == 0 ? 0 : -1;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_KILL:
        return ADD_LITERAL(command, "container") == 0
            && ADD_LITERAL(command, "kill") == 0
            && add_pair(command, "--signal", "KILL") == 0
            && ADD_LITERAL(command, spec->container_id) == 0 ? 0 : -1;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANUP:
        return ADD_LITERAL(command, "container") == 0
            && ADD_LITERAL(command, "cleanup") == 0
            && ADD_LITERAL(command, spec->container_id) == 0 ? 0 : -1;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REMOVE:
        return ADD_LITERAL(command, "container") == 0
            && ADD_LITERAL(command, "rm") == 0
            && ADD_LITERAL(command, "--ignore") == 0
            && ADD_LITERAL(command, spec->container_id) == 0 ? 0 : -1;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OBSERVE:
        return ADD_LITERAL(command, "container") == 0
            && ADD_LITERAL(command, "inspect") == 0
            && add_pair(command, "--format", inspect_template) == 0
            && ADD_LITERAL(command, spec->container_id) == 0 ? 0 : -1;
    default:
        return -1;
    }
}

int
plamen_broker_v2_podman_lifecycle_command_sha256(
    const struct plamen_broker_v2_podman_lifecycle_command *command,
    uint8_t output[32])
{
    uint8_t canonical[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_ARGS
        * (PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ARG_SIZE + 4U) + 8U];
    size_t index, offset = 0, size;
    if (command == NULL || output == NULL || command->argc == 0
        || command->argc > PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_ARGS)
        return -1;
    put_u32(canonical + offset, command->operation); offset += 4;
    put_u32(canonical + offset, (uint32_t)command->argc); offset += 4;
    for (index = 0; index < command->argc; ++index) {
        if (command->argv[index] == NULL
            || (size = strlen(command->argv[index]))
                >= PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ARG_SIZE)
            return -1;
        put_u32(canonical + offset, (uint32_t)size); offset += 4;
        memcpy(canonical + offset, command->argv[index], size); offset += size;
    }
    return plamen_broker_v2_sha256(canonical, offset, output);
}

int
plamen_broker_v2_podman_lifecycle_parse_wait_status(
    const uint8_t *bytes, size_t size, int32_t *exit_code)
{
    uint32_t value = 0;
    size_t index, digits;
    if (bytes == NULL || exit_code == NULL || size < 2 || size > 5
        || bytes[size - 1U] != '\n') return -1;
    digits = size - 1U;
    if (digits > 1 && bytes[0] == '0') return -1;
    for (index = 0; index < digits; ++index) {
        if (bytes[index] < '0' || bytes[index] > '9') return -1;
        value = value * 10U + (uint32_t)(bytes[index] - '0');
    }
    if (value > 255U) return -1;
    *exit_code = (int32_t)value;
    return 0;
}

static int
receipt_canonical(
    const struct plamen_broker_v2_podman_lifecycle_receipt *receipt,
    uint8_t out[RECEIPT_CANONICAL_SIZE], int zero_digest)
{
    size_t offset = 0, index;
    if (receipt == NULL || out == NULL) return -1;
    const uint32_t integers[] = {
        receipt->version, receipt->operation, receipt->from_state,
        receipt->to_state, receipt->result, receipt->exit_kind,
        (uint32_t)receipt->exit_code, (uint32_t)receipt->signal_number,
        receipt->timed_out, receipt->stdout_size, receipt->stderr_size,
        receipt->stdout_truncated, receipt->stderr_truncated,
        receipt->cgroup_population_zero, receipt->overlay_cleanup_complete,
        receipt->container_absent,
        receipt->receipt_requires_broker_authentication,
        receipt->lifecycle_authority_granted
    };
    const uint8_t *digests[] = {
        receipt->operation_key, receipt->request_sha256,
        receipt->admission_sha256, receipt->compiled_lifecycle_sha256,
        receipt->host_boot_id_sha256,
        receipt->command_sha256, receipt->stdout_sha256,
        receipt->stderr_sha256, receipt->cgroup_terminal_sha256,
        receipt->overlay_cleanup_sha256,
        receipt->previous_checkpoint_sha256, receipt->checkpoint_sha256,
        receipt->receipt_sha256
    };
    memset(out, 0, RECEIPT_CANONICAL_SIZE);
    for (index = 0; index < sizeof(integers) / sizeof(integers[0]); ++index) {
        put_u32(out + offset, integers[index]); offset += 4;
    }
    put_u64(out + offset, receipt->journal_sequence); offset += 8;
    for (index = 0; index < sizeof(digests) / sizeof(digests[0]); ++index) {
        if (zero_digest && index + 1U
                == sizeof(digests) / sizeof(digests[0]))
            memset(out + offset, 0, 32);
        else
            memcpy(out + offset, digests[index], 32);
        offset += 32;
    }
    return offset <= RECEIPT_CANONICAL_SIZE ? 0 : -1;
}

int
plamen_broker_v2_podman_lifecycle_receipt_seal(
    struct plamen_broker_v2_podman_lifecycle_receipt *receipt)
{
    uint8_t canonical[RECEIPT_CANONICAL_SIZE], digest[32];
    if (receipt == NULL || receipt_canonical(receipt, canonical, 1) != 0
        || plamen_broker_v2_sha256(canonical, sizeof(canonical), digest) != 0)
        return -1;
    memcpy(receipt->receipt_sha256, digest, sizeof(digest));
    return 0;
}

int
plamen_broker_v2_podman_lifecycle_receipt_validate(
    const struct plamen_broker_v2_podman_lifecycle_receipt *receipt)
{
    uint8_t canonical[RECEIPT_CANONICAL_SIZE], digest[32];
    if (receipt == NULL
        || receipt->version != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECEIPT_VERSION
        || receipt->result != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK
        || !plamen_broker_v2_podman_lifecycle_transition_valid(
            receipt->from_state, receipt->to_state, receipt->operation)
        || intent_state(receipt->to_state)
        || receipt->receipt_requires_broker_authentication != 1U
        || receipt->lifecycle_authority_granted != 1U
        || !digest_present(receipt->operation_key)
        || !digest_present(receipt->request_sha256)
        || !digest_present(receipt->admission_sha256)
        || !digest_present(receipt->compiled_lifecycle_sha256)
        || !digest_present(receipt->host_boot_id_sha256)
        || !digest_present(receipt->stdout_sha256)
        || !digest_present(receipt->stderr_sha256)
        || (receipt->operation != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN
            && !digest_present(receipt->command_sha256))
        || receipt->stdout_size > PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OUTPUT_MAX
        || receipt->stderr_size > PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OUTPUT_MAX
        || receipt->stdout_truncated > 1U || receipt->stderr_truncated > 1U
        || receipt->timed_out > 1U
        || (receipt->to_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERMINAL
            && receipt->cgroup_population_zero != 1U)
        || (receipt->to_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ABSENT
            && (receipt->cgroup_population_zero != 1U
                || receipt->container_absent != 1U))
        || (receipt->to_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_SEALED
            && (receipt->cgroup_population_zero != 1U
                || receipt->overlay_cleanup_complete != 1U
                || receipt->container_absent != 1U))
        || receipt_canonical(receipt, canonical, 1) != 0
        || plamen_broker_v2_sha256(canonical, sizeof(canonical), digest) != 0
        || !constant_equal(digest, receipt->receipt_sha256, 32)) return -1;
    if (receipt->to_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERMINAL) {
        if (receipt->exit_kind == PLAMEN_BROKER_V2_PODMAN_EXIT_NONE) return -1;
    } else if (receipt->exit_kind != PLAMEN_BROKER_V2_PODMAN_EXIT_NONE) {
        return -1;
    }
    if (receipt->exit_kind == PLAMEN_BROKER_V2_PODMAN_EXIT_CODE) {
        if (receipt->exit_code < 0 || receipt->exit_code > 255
            || receipt->signal_number != 0 || receipt->timed_out != 0) return -1;
    } else if (receipt->exit_kind == PLAMEN_BROKER_V2_PODMAN_EXIT_SIGNAL) {
        if (receipt->signal_number <= 0 || receipt->signal_number > 64
            || receipt->exit_code != -1 || receipt->timed_out != 0) return -1;
    } else if (receipt->exit_kind == PLAMEN_BROKER_V2_PODMAN_EXIT_TIMEOUT) {
        if (receipt->timed_out != 1U || receipt->exit_code != -1) return -1;
    } else if (receipt->exit_kind != PLAMEN_BROKER_V2_PODMAN_EXIT_NONE
        || receipt->exit_code != -1 || receipt->signal_number != 0
        || receipt->timed_out != 0) return -1;
    return 0;
}

int
plamen_broker_v2_podman_lifecycle_record_encode(
    const struct plamen_broker_v2_podman_lifecycle_receipt *receipt,
    uint8_t out[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE])
{
    uint8_t digest[32];
    if (out == NULL || plamen_broker_v2_podman_lifecycle_receipt_validate(
            receipt) != 0) return -1;
    memset(out, 0, PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE);
    memcpy(out, record_magic, sizeof(record_magic));
    put_u32(out + 8, PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_VERSION);
    put_u32(out + 12, PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE);
    if (receipt_canonical(receipt, out + 16, 0) != 0
        || plamen_broker_v2_sha256(out,
            PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE - 32U,
            digest) != 0) return -1;
    memcpy(out + PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE - 32U,
        digest, sizeof(digest));
    return 0;
}

static int
receipt_from_canonical(const uint8_t canonical[RECEIPT_CANONICAL_SIZE],
    struct plamen_broker_v2_podman_lifecycle_receipt *receipt)
{
    size_t offset = 0, index;
    uint8_t *digests[] = {
        receipt->operation_key, receipt->request_sha256,
        receipt->admission_sha256, receipt->compiled_lifecycle_sha256,
        receipt->host_boot_id_sha256,
        receipt->command_sha256, receipt->stdout_sha256,
        receipt->stderr_sha256, receipt->cgroup_terminal_sha256,
        receipt->overlay_cleanup_sha256,
        receipt->previous_checkpoint_sha256, receipt->checkpoint_sha256,
        receipt->receipt_sha256
    };
    if (canonical == NULL || receipt == NULL) return -1;
    memset(receipt, 0, sizeof(*receipt));
#define GET_RECEIPT_U32(field) do { \
    receipt->field = get_u32(canonical + offset); offset += 4; \
} while (0)
    GET_RECEIPT_U32(version);
    GET_RECEIPT_U32(operation);
    GET_RECEIPT_U32(from_state);
    GET_RECEIPT_U32(to_state);
    GET_RECEIPT_U32(result);
    GET_RECEIPT_U32(exit_kind);
    receipt->exit_code = (int32_t)get_u32(canonical + offset); offset += 4;
    receipt->signal_number = (int32_t)get_u32(canonical + offset); offset += 4;
    GET_RECEIPT_U32(timed_out);
    GET_RECEIPT_U32(stdout_size);
    GET_RECEIPT_U32(stderr_size);
    GET_RECEIPT_U32(stdout_truncated);
    GET_RECEIPT_U32(stderr_truncated);
    GET_RECEIPT_U32(cgroup_population_zero);
    GET_RECEIPT_U32(overlay_cleanup_complete);
    GET_RECEIPT_U32(container_absent);
    GET_RECEIPT_U32(receipt_requires_broker_authentication);
    GET_RECEIPT_U32(lifecycle_authority_granted);
#undef GET_RECEIPT_U32
    receipt->journal_sequence = get_u64(canonical + offset); offset += 8;
    for (index = 0; index < sizeof(digests) / sizeof(digests[0]); ++index) {
        memcpy(digests[index], canonical + offset, 32); offset += 32;
    }
    return plamen_broker_v2_podman_lifecycle_receipt_validate(receipt);
}

int
plamen_broker_v2_podman_lifecycle_record_decode(
    const uint8_t record[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE],
    struct plamen_broker_v2_podman_lifecycle_receipt *receipt)
{
    uint8_t digest[32];
    size_t index;
    if (record == NULL || receipt == NULL) return -1;
    if (memcmp(record, record_magic, sizeof(record_magic)) != 0
        || get_u32(record + 8) != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_VERSION
        || get_u32(record + 12) != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE
        || plamen_broker_v2_sha256(record,
            PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE - 32U,
            digest) != 0
        || !constant_equal(digest,
            record + PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE - 32U,
            32)) return -1;
    for (index = 16U + RECEIPT_CANONICAL_SIZE;
         index < PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE - 32U; ++index)
        if (record[index] != 0) return -1;
    return receipt_from_canonical(record + 16, receipt);
}

struct lifecycle_journal_entry {
    uint64_t sequence;
    uint32_t state;
    uint32_t operation;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t admission_sha256[32];
    uint8_t compiled_lifecycle_sha256[32];
    uint8_t host_boot_id_sha256[32];
    uint8_t command_sha256[32];
    uint8_t previous_checkpoint_sha256[32];
    uint8_t receipt_sha256[32];
    struct plamen_broker_v2_podman_lifecycle_receipt receipt;
    uint8_t checkpoint_sha256[32];
    uint8_t has_receipt;
};

static int
private_directory(int fd)
{
    struct stat value;
    return fd >= 0 && fstat(fd, &value) == 0 && S_ISDIR(value.st_mode)
        && value.st_uid == geteuid() && (value.st_mode & 0777U) == 0700U
        && (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0;
}

static int
valid_journal_id(const char *value)
{
    return identifier_valid(value) && strlen(value) <= 64;
}

static int
set_journal_lock(int fd, short type)
{
    struct flock lock;
    int status;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = type;
    lock.l_whence = SEEK_SET;
    do status = fcntl(fd, type == F_UNLCK ? F_SETLK : F_SETLKW, &lock);
    while (status != 0 && errno == EINTR);
    return status == 0 ? 0 : -1;
}

static int
journal_filename(uint64_t sequence, char output[25])
{
    int size;
    if (sequence == 0 || sequence > 1000000U) return -1;
    size = snprintf(output, 25, "%020" PRIu64 ".lcj", sequence);
    return size == 24 ? 0 : -1;
}

static int
parse_journal_filename(const char *name, uint64_t *sequence)
{
    uint64_t value = 0;
    size_t index;
    if (name == NULL || sequence == NULL || strlen(name) != 24
        || memcmp(name + 20, ".lcj", 4) != 0) return -1;
    for (index = 0; index < 20; ++index) {
        if (name[index] < '0' || name[index] > '9'
            || value > (UINT64_MAX - (uint64_t)(name[index] - '0')) / 10U)
            return -1;
        value = value * 10U + (uint64_t)(name[index] - '0');
    }
    if (value == 0 || value > 1000000U) return -1;
    *sequence = value;
    return 0;
}

static int
scan_journal(struct plamen_broker_v2_podman_lifecycle_journal *journal,
    uint64_t *count)
{
    DIR *directory;
    struct dirent *entry;
    uint64_t sequence, seen = 0, maximum = 0;
    int scan_fd = openat(journal->directory_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0 || (directory = fdopendir(scan_fd)) == NULL) {
        if (scan_fd >= 0) (void)close(scan_fd);
        return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")
            || !strcmp(entry->d_name, ".lock")) continue;
        if (parse_journal_filename(entry->d_name, &sequence) != 0) {
            (void)closedir(directory); return -1;
        }
        ++seen;
        if (sequence > maximum) maximum = sequence;
    }
    if (errno != 0 || closedir(directory) != 0 || seen != maximum) return -1;
    *count = seen;
    return 0;
}

static int
write_full(int fd, const uint8_t *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = write(fd, bytes + offset, size - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int
read_full(int fd, uint8_t *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = pread(fd, bytes + offset, size - offset, (off_t)offset);
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int
entry_encode(const struct lifecycle_journal_entry *entry, uint8_t bytes[
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE])
{
    uint8_t digest[32];
    if (entry == NULL || bytes == NULL || entry->sequence == 0
        || !digest_present(entry->operation_key)
        || !digest_present(entry->request_sha256)
        || !digest_present(entry->admission_sha256)
        || !digest_present(entry->compiled_lifecycle_sha256)
        || !digest_present(entry->host_boot_id_sha256)
        || (entry->operation != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN
            && !digest_present(entry->command_sha256))) return -1;
    memset(bytes, 0, PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE);
    memcpy(bytes, journal_magic, 8);
    put_u32(bytes + 8, PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_VERSION);
    put_u32(bytes + 12,
        PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE);
    put_u64(bytes + 16, entry->sequence);
    put_u32(bytes + 24, entry->state);
    put_u32(bytes + 28, entry->operation);
    memcpy(bytes + 32, entry->operation_key, 32);
    memcpy(bytes + 64, entry->request_sha256, 32);
    memcpy(bytes + 96, entry->admission_sha256, 32);
    memcpy(bytes + 128, entry->compiled_lifecycle_sha256, 32);
    memcpy(bytes + 160, entry->command_sha256, 32);
    memcpy(bytes + 192, entry->previous_checkpoint_sha256, 32);
    memcpy(bytes + 224, entry->host_boot_id_sha256, 32);
    if (entry->has_receipt) {
        if (plamen_broker_v2_podman_lifecycle_receipt_validate(
                &entry->receipt) != 0
            || receipt_canonical(&entry->receipt, bytes + 288, 0) != 0)
            return -1;
        memcpy(bytes + 256, entry->receipt.receipt_sha256, 32);
    } else if (!intent_state(entry->state)) return -1;
    if (plamen_broker_v2_sha256(bytes,
            PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE - 32U,
            digest) != 0) return -1;
    memcpy(bytes + PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE - 32U,
        digest, 32);
    return 0;
}

static int
entry_decode(const uint8_t bytes[
    PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE],
    struct lifecycle_journal_entry *entry)
{
    uint8_t digest[32], aggregate = 0;
    size_t index;
    if (bytes == NULL || entry == NULL || memcmp(bytes, journal_magic, 8) != 0
        || get_u32(bytes + 8) != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_VERSION
        || get_u32(bytes + 12)
            != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE
        || plamen_broker_v2_sha256(bytes,
            PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE - 32U,
            digest) != 0
        || !constant_equal(digest, bytes
            + PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE - 32U,
            32)) return -1;
    memset(entry, 0, sizeof(*entry));
    entry->sequence = get_u64(bytes + 16);
    entry->state = get_u32(bytes + 24);
    entry->operation = get_u32(bytes + 28);
    memcpy(entry->operation_key, bytes + 32, 32);
    memcpy(entry->request_sha256, bytes + 64, 32);
    memcpy(entry->admission_sha256, bytes + 96, 32);
    memcpy(entry->compiled_lifecycle_sha256, bytes + 128, 32);
    memcpy(entry->command_sha256, bytes + 160, 32);
    memcpy(entry->previous_checkpoint_sha256, bytes + 192, 32);
    memcpy(entry->host_boot_id_sha256, bytes + 224, 32);
    memcpy(entry->receipt_sha256, bytes + 256, 32);
    memcpy(entry->checkpoint_sha256, digest, 32);
    for (index = 0; index < 32; ++index) aggregate |= bytes[256 + index];
    if (aggregate != 0) {
        if (receipt_from_canonical(bytes + 288, &entry->receipt) != 0
            || !constant_equal(entry->receipt.receipt_sha256,
                entry->receipt_sha256, 32)) return -1;
        entry->has_receipt = 1U;
    } else {
        for (index = 288; index < 800; ++index)
            if (bytes[index] != 0) return -1;
        if (!intent_state(entry->state)) return -1;
    }
    return 0;
}

static int
read_entry(struct plamen_broker_v2_podman_lifecycle_journal *journal,
    uint64_t sequence, struct lifecycle_journal_entry *entry)
{
    char name[25];
    uint8_t bytes[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE];
    struct stat before, after;
    int fd = -1, result = -1;
    if (journal_filename(sequence, name) != 0) return -1;
    fd = openat(journal->directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_uid != geteuid() || before.st_nlink != 1
        || (before.st_mode & 0777U) != 0400U
        || before.st_size
            != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE
        || read_full(fd, bytes, sizeof(bytes)) != 0 || fstat(fd, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_size != after.st_size || after.st_nlink != 1
        || entry_decode(bytes, entry) != 0 || entry->sequence != sequence)
        goto done;
    result = 0;
done:
    if (fd >= 0) (void)close(fd);
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    return result;
}

static int
replay_locked(struct plamen_broker_v2_podman_lifecycle_journal *journal,
    struct lifecycle_journal_entry *last)
{
    struct lifecycle_journal_entry previous, current;
    uint64_t count, sequence;
    uint8_t *used_operation_keys = NULL;
    size_t used_count = 0, index;
    memset(&previous, 0, sizeof(previous));
    memset(&current, 0, sizeof(current));
    memset(last, 0, sizeof(*last));
    if (scan_journal(journal, &count) != 0) goto corrupt;
    if (count != 0) {
        used_operation_keys = calloc((size_t)count, 32);
        if (used_operation_keys == NULL) return -1;
    }
    for (sequence = 1; sequence <= count; ++sequence) {
        if (read_entry(journal, sequence, &current) != 0
            || !constant_equal(current.admission_sha256,
                journal->admission_sha256, 32)
            || !constant_equal(current.compiled_lifecycle_sha256,
                journal->compiled_lifecycle_sha256, 32)
            || !constant_equal(current.host_boot_id_sha256,
                journal->host_boot_id_sha256, 32)
            || (sequence == 1
                ? digest_present(current.previous_checkpoint_sha256)
                : !constant_equal(current.previous_checkpoint_sha256,
                    previous.checkpoint_sha256, 32))
            || !plamen_broker_v2_podman_lifecycle_transition_valid(
                sequence == 1 ? PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_EMPTY
                    : previous.state,
                current.state, current.operation)) goto corrupt;
        if (intent_state(current.state)) {
            for (index = 0; index < used_count; ++index)
                if (constant_equal(current.operation_key,
                        used_operation_keys + index * 32U, 32)) goto corrupt;
            memcpy(used_operation_keys + used_count * 32U,
                current.operation_key, 32);
            ++used_count;
        }
        if (current.has_receipt) {
            if (sequence == 1 || !intent_state(previous.state)
                || current.receipt.from_state != previous.state
                || current.receipt.to_state != current.state
                || current.receipt.operation != current.operation
                || current.receipt.journal_sequence != current.sequence
                || !constant_equal(current.operation_key,
                    previous.operation_key, 32)
                || !constant_equal(current.request_sha256,
                    previous.request_sha256, 32)
                || !constant_equal(current.command_sha256,
                    previous.command_sha256, 32)
                || !constant_equal(current.receipt.previous_checkpoint_sha256,
                    previous.checkpoint_sha256, 32)) goto corrupt;
        }
        previous = current;
        memset(&current, 0, sizeof(current));
    }
    *last = previous;
    if (used_operation_keys != NULL) {
        plamen_broker_v2_secure_zero(used_operation_keys, (size_t)count * 32U);
        free(used_operation_keys);
    }
    return 0;
corrupt:
    if (used_operation_keys != NULL) {
        plamen_broker_v2_secure_zero(used_operation_keys, (size_t)count * 32U);
        free(used_operation_keys);
    }
    journal->poisoned = 1;
    return -1;
}

static int
find_operation_locked(struct plamen_broker_v2_podman_lifecycle_journal *journal,
    const uint8_t operation_key[32], struct lifecycle_journal_entry *match)
{
    struct lifecycle_journal_entry current;
    uint64_t count, sequence;
    int found = 0;
    memset(match, 0, sizeof(*match));
    if (scan_journal(journal, &count) != 0) return -1;
    for (sequence = 1; sequence <= count; ++sequence) {
        if (read_entry(journal, sequence, &current) != 0) return -1;
        if (constant_equal(current.operation_key, operation_key, 32)) {
            *match = current;
            found = 1;
        }
    }
    return found;
}

static int
commit_entry(struct plamen_broker_v2_podman_lifecycle_journal *journal,
    const struct lifecycle_journal_entry *entry)
{
    char name[25];
    uint8_t bytes[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_JOURNAL_ENTRY_SIZE];
    int fd, result = -1;
    if (journal_filename(entry->sequence, name) != 0
        || entry_encode(entry, bytes) != 0) return -1;
    fd = openat(journal->directory_fd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0400);
    if (fd < 0) goto done;
    if (write_full(fd, bytes, sizeof(bytes)) != 0 || fsync(fd) != 0
        || close(fd) != 0) { fd = -1; goto done; }
    fd = -1;
    if (fsync(journal->directory_fd) != 0) goto done;
    result = 0;
done:
    if (fd >= 0) (void)close(fd);
    plamen_broker_v2_secure_zero(bytes, sizeof(bytes));
    return result;
}

int
plamen_broker_v2_podman_lifecycle_journal_open(int parent_fd,
    const char *journal_id, const uint8_t admission_sha256[32],
    const uint8_t compiled_lifecycle_sha256[32],
    const uint8_t host_boot_id_sha256[32],
    struct plamen_broker_v2_podman_lifecycle_journal **out)
{
    struct plamen_broker_v2_podman_lifecycle_journal *journal;
    struct stat lock_stat;
    int directory_fd = -1, lock_fd = -1, made_directory = 0, made_lock = 0;
    if (out == NULL || !private_directory(parent_fd)
        || !valid_journal_id(journal_id) || !digest_present(admission_sha256)
        || !digest_present(compiled_lifecycle_sha256)
        || !digest_present(host_boot_id_sha256)) return -1;
    *out = NULL;
    if (mkdirat(parent_fd, journal_id, 0700) == 0) made_directory = 1;
    else if (errno != EEXIST) return -1;
    directory_fd = openat(parent_fd, journal_id,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!private_directory(directory_fd)) goto failed;
    if (made_directory && fsync(parent_fd) != 0) goto failed;
    lock_fd = openat(directory_fd, ".lock",
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock_fd >= 0) made_lock = 1;
    else if (errno == EEXIST)
        lock_fd = openat(directory_fd, ".lock", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (lock_fd < 0 || fstat(lock_fd, &lock_stat) != 0
        || !S_ISREG(lock_stat.st_mode) || lock_stat.st_uid != geteuid()
        || lock_stat.st_nlink != 1 || (lock_stat.st_mode & 0777U) != 0600U)
        goto failed;
    if (made_lock && (fsync(lock_fd) != 0 || fsync(directory_fd) != 0))
        goto failed;
    journal = calloc(1, sizeof(*journal));
    if (journal == NULL) goto failed;
    journal->directory_fd = directory_fd;
    journal->lock_fd = lock_fd;
    memcpy(journal->admission_sha256, admission_sha256, 32);
    memcpy(journal->compiled_lifecycle_sha256,
        compiled_lifecycle_sha256, 32);
    memcpy(journal->host_boot_id_sha256, host_boot_id_sha256, 32);
    *out = journal;
    return 0;
failed:
    if (lock_fd >= 0) (void)close(lock_fd);
    if (directory_fd >= 0) (void)close(directory_fd);
    return -1;
}

void
plamen_broker_v2_podman_lifecycle_journal_close(
    struct plamen_broker_v2_podman_lifecycle_journal *journal)
{
    if (journal == NULL) return;
    if (journal->lock_fd >= 0) (void)close(journal->lock_fd);
    if (journal->directory_fd >= 0) (void)close(journal->directory_fd);
    plamen_broker_v2_secure_zero(journal, sizeof(*journal));
    free(journal);
}

int
plamen_broker_v2_podman_lifecycle_journal_replay(
    struct plamen_broker_v2_podman_lifecycle_journal *journal,
    struct plamen_broker_v2_podman_lifecycle_head *head)
{
    struct lifecycle_journal_entry last;
    int status;
    if (journal == NULL || head == NULL || journal->poisoned) return -1;
    memset(head, 0, sizeof(*head));
    if (set_journal_lock(journal->lock_fd, F_WRLCK) != 0) return -1;
    status = replay_locked(journal, &last);
    if (status == 0 && last.sequence != 0) {
        head->sequence = last.sequence;
        head->state = last.state;
        head->operation = last.operation;
        memcpy(head->operation_key, last.operation_key, 32);
        memcpy(head->request_sha256, last.request_sha256, 32);
        memcpy(head->checkpoint_sha256, last.checkpoint_sha256, 32);
        if (last.has_receipt) {
            head->committed = last.receipt;
            head->has_committed_receipt = 1U;
        }
    }
    if (set_journal_lock(journal->lock_fd, F_UNLCK) != 0 && status == 0)
        status = -1;
    return status;
}

int
plamen_broker_v2_podman_lifecycle_journal_append_intent(
    struct plamen_broker_v2_podman_lifecycle_journal *journal,
    const struct plamen_broker_v2_podman_lifecycle_spec *spec,
    uint32_t operation, const uint8_t command_sha256[32],
    uint8_t checkpoint_sha256[32])
{
    struct lifecycle_journal_entry head, candidate, prior_operation;
    uint32_t target;
    int status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
    if (journal == NULL || checkpoint_sha256 == NULL
        || !spec_valid(spec, operation) || journal->poisoned
        || (operation != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN
            && !digest_present(command_sha256))) return status;
    if (set_journal_lock(journal->lock_fd, F_WRLCK) != 0) return status;
    if (replay_locked(journal, &head) != 0) goto done;
    status = find_operation_locked(journal, spec->operation_key,
        &prior_operation);
    if (status < 0) {
        status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
        goto done;
    }
    if (status > 0) {
        if (!constant_equal(prior_operation.request_sha256,
                spec->request_sha256, 32)
            || prior_operation.operation != operation) {
            status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CONFLICT;
            goto done;
        }
        memcpy(checkpoint_sha256, prior_operation.checkpoint_sha256, 32);
        status = intent_state(prior_operation.state)
            ? PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED
            : PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK;
        goto done;
    }
    target = operation_intent(operation);
    if (!plamen_broker_v2_podman_lifecycle_transition_valid(
            head.sequence == 0 ? PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_EMPTY
                : head.state,
            target, operation)) {
        status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CONFLICT;
        goto done;
    }
    memset(&candidate, 0, sizeof(candidate));
    candidate.sequence = head.sequence + 1U;
    candidate.state = target;
    candidate.operation = operation;
    memcpy(candidate.operation_key, spec->operation_key, 32);
    memcpy(candidate.request_sha256, spec->request_sha256, 32);
    memcpy(candidate.admission_sha256, journal->admission_sha256, 32);
    memcpy(candidate.compiled_lifecycle_sha256,
        journal->compiled_lifecycle_sha256, 32);
    memcpy(candidate.host_boot_id_sha256, journal->host_boot_id_sha256, 32);
    if (command_sha256 != NULL)
        memcpy(candidate.command_sha256, command_sha256, 32);
    memcpy(candidate.previous_checkpoint_sha256,
        head.checkpoint_sha256, 32);
    if (commit_entry(journal, &candidate) != 0) goto done;
    if (read_entry(journal, candidate.sequence, &candidate) != 0) goto done;
    memcpy(checkpoint_sha256, candidate.checkpoint_sha256, 32);
    status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK;
done:
    if (set_journal_lock(journal->lock_fd, F_UNLCK) != 0
        && status == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK)
        status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
    return status;
}

int
plamen_broker_v2_podman_lifecycle_journal_commit(
    struct plamen_broker_v2_podman_lifecycle_journal *journal,
    const struct plamen_broker_v2_podman_lifecycle_receipt *receipt,
    uint8_t checkpoint_sha256[32])
{
    struct lifecycle_journal_entry head, candidate;
    int status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
    if (journal == NULL || checkpoint_sha256 == NULL || journal->poisoned
        || plamen_broker_v2_podman_lifecycle_receipt_validate(receipt) != 0)
        return status;
    if (set_journal_lock(journal->lock_fd, F_WRLCK) != 0) return status;
    if (replay_locked(journal, &head) != 0) goto done;
    if (head.has_receipt
        && constant_equal(head.operation_key, receipt->operation_key, 32)) {
        if (!constant_equal(head.receipt.receipt_sha256,
                receipt->receipt_sha256, 32)) {
            status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CONFLICT;
            goto done;
        }
        memcpy(checkpoint_sha256, head.checkpoint_sha256, 32);
        status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK;
        goto done;
    }
    if (!intent_state(head.state) || head.operation != receipt->operation
        || receipt->from_state != head.state
        || receipt->journal_sequence != head.sequence + 1U
        || !constant_equal(head.operation_key, receipt->operation_key, 32)
        || !constant_equal(head.request_sha256, receipt->request_sha256, 32)
        || !constant_equal(head.admission_sha256, receipt->admission_sha256, 32)
        || !constant_equal(head.compiled_lifecycle_sha256,
            receipt->compiled_lifecycle_sha256, 32)
        || !constant_equal(head.host_boot_id_sha256,
            receipt->host_boot_id_sha256, 32)
        || !constant_equal(head.command_sha256, receipt->command_sha256, 32)
        || !constant_equal(head.checkpoint_sha256,
            receipt->previous_checkpoint_sha256, 32)) {
        status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CONFLICT;
        goto done;
    }
    memset(&candidate, 0, sizeof(candidate));
    candidate.sequence = receipt->journal_sequence;
    candidate.state = receipt->to_state;
    candidate.operation = receipt->operation;
    memcpy(candidate.operation_key, receipt->operation_key, 32);
    memcpy(candidate.request_sha256, receipt->request_sha256, 32);
    memcpy(candidate.admission_sha256, receipt->admission_sha256, 32);
    memcpy(candidate.compiled_lifecycle_sha256,
        receipt->compiled_lifecycle_sha256, 32);
    memcpy(candidate.host_boot_id_sha256, receipt->host_boot_id_sha256, 32);
    memcpy(candidate.command_sha256, receipt->command_sha256, 32);
    memcpy(candidate.previous_checkpoint_sha256, head.checkpoint_sha256, 32);
    candidate.receipt = *receipt;
    candidate.has_receipt = 1U;
    if (commit_entry(journal, &candidate) != 0) goto done;
    if (read_entry(journal, candidate.sequence, &candidate) != 0) goto done;
    memcpy(checkpoint_sha256, candidate.checkpoint_sha256, 32);
    status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK;
done:
    if (set_journal_lock(journal->lock_fd, F_UNLCK) != 0
        && status == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK)
        status = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
    return status;
}

int
plamen_broker_v2_podman_cgroup_path_revalidate(
    const struct plamen_broker_v2_podman_admission_custody *custody,
    int cgroup_root_fd, const char *systemd_control_group)
{
#ifndef __linux__
    (void)custody; (void)cgroup_root_fd; (void)systemd_control_group;
    return -1;
#else
    struct stat identity;
    struct statx extended;
    int reopened = -1, status = -1;
    if (custody == NULL || cgroup_root_fd < 3
        || !absolute_guest_path_valid(systemd_control_group, 1)
        || plamen_broker_v2_podman_custody_revalidate(custody) != 0)
        return -1;
    reopened = plamen_broker_v2_podman_open_beneath(cgroup_root_fd,
        systemd_control_group + 1, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (reopened < 0 || fstat(reopened, &identity) != 0
        || (uint64_t)identity.st_dev != custody->cgroup_device
        || (uint64_t)identity.st_ino != custody->cgroup_inode) goto done;
    memset(&extended, 0, sizeof(extended));
    if (syscall(SYS_statx, reopened, "", AT_EMPTY_PATH | AT_NO_AUTOMOUNT,
            STATX_TYPE | STATX_INO | STATX_MNT_ID, &extended) != 0
        || !(extended.stx_mask & STATX_MNT_ID)
        || extended.stx_mnt_id != custody->cgroup_mount_id) goto done;
    status = 0;
done:
    if (reopened >= 0) (void)close(reopened);
    return status;
#endif
}

#ifdef __linux__
static int
lifecycle_state_after(uint32_t operation, uint32_t *state)
{
    if (state == NULL) return -1;
    switch (operation) {
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE:
        *state = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATED_STOPPED; break;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START:
        *state = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RUNNING; break;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_WAIT:
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERM:
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_KILL:
        *state = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERMINAL; break;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANUP:
        *state = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CLEANED; break;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REMOVE:
        *state = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ABSENT; break;
    case PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN:
        *state = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_SEALED; break;
    default: return -1;
    }
    return 0;
}

static int
fd_in_roster(int fd, const int *roster, size_t count)
{
    size_t index;
    for (index = 0; index < count; ++index) if (roster[index] == fd) return 1;
    return 0;
}

static int
inheritance_roster(
    const struct plamen_broker_v2_podman_admission_custody *custody,
    const struct plamen_broker_v2_podman_lifecycle_spec *spec,
    uint32_t operation,
    int roster[PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT
        + PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT
        + PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_MOUNTS + 2U],
    size_t *count)
{
    size_t index, used = 0, prior;
    if (custody == NULL || spec == NULL || roster == NULL || count == NULL)
        return -1;
#define INHERIT_FD(value) do { \
    int inherited_fd = (value); \
    if (inherited_fd < 3) return -1; \
    for (prior = 0; prior < used; ++prior) \
        if (roster[prior] == inherited_fd) break; \
    if (prior == used) roster[used++] = inherited_fd; \
} while (0)
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT; ++index)
        INHERIT_FD(custody->component_fds[index]);
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT; ++index)
        INHERIT_FD(custody->root_fds[index]);
    if (operation == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE) {
        if (spec->mount_count > PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_MAX_MOUNTS
            || (spec->mount_count != 0 && spec->mounts == NULL)) return -1;
        for (index = 0; index < spec->mount_count; ++index)
            INHERIT_FD(spec->mounts[index].source_fd);
        INHERIT_FD(spec->seccomp_profile_fd);
        if (spec->network_mode
                == PLAMEN_BROKER_V2_PODMAN_NETWORK_VERIFIED_EGRESS_NAMESPACE)
            INHERIT_FD(spec->network_namespace_fd);
    }
#undef INHERIT_FD
    *count = used;
    return 0;
}

static int
set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

static int
monotonic_ms(uint64_t *value)
{
    struct timespec now;
    if (value == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    *value = (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
    return 0;
}

static int
capture_one(int fd, uint8_t *output, size_t capacity, size_t *used,
    uint32_t *truncated, int *open_stream)
{
    uint8_t discard[4096];
    for (;;) {
        uint8_t *target = *used < capacity ? output + *used : discard;
        size_t room = *used < capacity ? capacity - *used : sizeof(discard);
        ssize_t amount = read(fd, target, room);
        if (amount > 0) {
            if (*used < capacity) *used += (size_t)amount;
            else *truncated = 1U;
            continue;
        }
        if (amount == 0) { *open_stream = 0; return 0; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
}

static int
execute_command_retained(
    const struct plamen_broker_v2_podman_admission_custody *custody,
    const struct plamen_broker_v2_podman_lifecycle_spec *spec,
    const struct plamen_broker_v2_podman_lifecycle_command *command,
    uint8_t *stdout_bytes, size_t stdout_capacity, size_t *stdout_size,
    uint8_t *stderr_bytes, size_t stderr_capacity, size_t *stderr_size,
    uint32_t *stdout_truncated, uint32_t *stderr_truncated, int *exit_status)
{
    int out_pipe[2] = {-1, -1}, err_pipe[2] = {-1, -1}, roster[40];
    size_t roster_count = 0, out_used = 0, err_used = 0, index;
    int out_open = 1, err_open = 1, child_status = 0, result = -1;
    pid_t child = -1, waited;
    uint64_t start, now;
    static char *const environment[] = {
        "HOME=/", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", NULL
    };
    if (stdout_bytes == NULL || stderr_bytes == NULL || stdout_size == NULL
        || stderr_size == NULL || stdout_truncated == NULL
        || stderr_truncated == NULL || exit_status == NULL
        || stdout_capacity == 0 || stderr_capacity == 0
        || stdout_capacity > spec->output_limit
        || stderr_capacity > spec->output_limit
        || inheritance_roster(custody, spec, command->operation,
            roster, &roster_count) != 0
        || pipe2(out_pipe, O_CLOEXEC) != 0 || pipe2(err_pipe, O_CLOEXEC) != 0)
        goto done;
    child = fork();
    if (child < 0) goto done;
    if (child == 0) {
        long maximum_fd;
        int fd;
        (void)close(out_pipe[0]); (void)close(err_pipe[0]);
        if (dup2(out_pipe[1], STDOUT_FILENO) < 0
            || dup2(err_pipe[1], STDERR_FILENO) < 0) _exit(126);
        (void)close(out_pipe[1]); (void)close(err_pipe[1]);
        maximum_fd = sysconf(_SC_OPEN_MAX);
        if (maximum_fd < 0 || maximum_fd > 1048576L) maximum_fd = 1048576L;
        for (fd = 3; fd < maximum_fd; ++fd)
            if (!fd_in_roster(fd, roster, roster_count)) (void)close(fd);
        for (index = 0; index < roster_count; ++index)
            if (fcntl(roster[index], F_SETFD, 0) != 0) _exit(126);
        fexecve(custody->component_fds[
            PLAMEN_BROKER_V2_PODMAN_COMPONENT_PODMAN],
            (char *const *)command->argv, environment);
        _exit(errno == ENOENT ? 127 : 126);
    }
    (void)close(out_pipe[1]); out_pipe[1] = -1;
    (void)close(err_pipe[1]); err_pipe[1] = -1;
    if (set_nonblocking(out_pipe[0]) != 0 || set_nonblocking(err_pipe[0]) != 0
        || monotonic_ms(&start) != 0) goto terminate;
    while (out_open || err_open) {
        struct pollfd watch[2];
        int polled;
        if (monotonic_ms(&now) != 0 || now - start >= spec->timeout_ms)
            goto terminate;
        watch[0].fd = out_pipe[0]; watch[0].events = POLLIN | POLLHUP;
        watch[0].revents = 0;
        watch[1].fd = err_pipe[0]; watch[1].events = POLLIN | POLLHUP;
        watch[1].revents = 0;
        polled = poll(watch, 2, 50);
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0) goto terminate;
        if (out_open && capture_one(out_pipe[0], stdout_bytes,
                stdout_capacity, &out_used, stdout_truncated, &out_open) != 0)
            goto terminate;
        if (err_open && capture_one(err_pipe[0], stderr_bytes,
                stderr_capacity, &err_used, stderr_truncated, &err_open) != 0)
            goto terminate;
    }
    do { waited = waitpid(child, &child_status, 0); }
    while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(child_status)) goto done;
    *exit_status = WEXITSTATUS(child_status);
    *stdout_size = out_used; *stderr_size = err_used;
    result = 0; child = -1;
    goto done;
terminate:
    (void)kill(child, SIGKILL);
    do { waited = waitpid(child, &child_status, 0); }
    while (waited < 0 && errno == EINTR);
    child = -1;
done:
    if (child > 0) { (void)kill(child, SIGKILL); (void)waitpid(child, NULL, 0); }
    if (out_pipe[0] >= 0) (void)close(out_pipe[0]);
    if (out_pipe[1] >= 0) (void)close(out_pipe[1]);
    if (err_pipe[0] >= 0) (void)close(err_pipe[0]);
    if (err_pipe[1] >= 0) (void)close(err_pipe[1]);
    return result;
}

static int
directory_empty_and_digest(int fd, uint8_t digest[32])
{
    DIR *directory;
    struct dirent *entry;
    int duplicate, status = -1;
    static const char empty[] = "PLAMEN-EMPTY-DIRECTORY-V1";
    duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0 || (directory = fdopendir(duplicate)) == NULL) {
        if (duplicate >= 0) (void)close(duplicate);
        return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            goto done;
    if (errno == 0 && plamen_broker_v2_sha256(empty, sizeof(empty), digest) == 0)
        status = 0;
done:
    (void)closedir(directory);
    return status;
}

static int
remove_directory_contents(int directory_fd, uint64_t expected_device,
    unsigned depth, uint64_t *entries)
{
    DIR *directory = NULL;
    struct dirent *entry;
    struct stat identity;
    int duplicate = -1, child = -1, status = -1;
    if (directory_fd < 3 || entries == NULL || depth > 64U
        || fstat(directory_fd, &identity) != 0 || !S_ISDIR(identity.st_mode)
        || (uint64_t)identity.st_dev != expected_device) return -1;
    duplicate = fcntl(directory_fd, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0 || (directory = fdopendir(duplicate)) == NULL) goto done;
    duplicate = -1;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++*entries > 1000000U
            || fstatat(directory_fd, entry->d_name, &identity,
                AT_SYMLINK_NOFOLLOW) != 0
            || (uint64_t)identity.st_dev != expected_device) goto done;
        if (S_ISDIR(identity.st_mode)) {
            child = openat(directory_fd, entry->d_name,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || remove_directory_contents(child, expected_device,
                    depth + 1U, entries) != 0 || close(child) != 0) {
                child = -1; goto done;
            }
            child = -1;
            if (unlinkat(directory_fd, entry->d_name, AT_REMOVEDIR) != 0)
                goto done;
        } else if (unlinkat(directory_fd, entry->d_name, 0) != 0) goto done;
        errno = 0;
    }
    if (errno == 0 && fsync(directory_fd) == 0) status = 0;
done:
    if (child >= 0) (void)close(child);
    if (directory != NULL) (void)closedir(directory);
    else if (duplicate >= 0) (void)close(duplicate);
    return status;
}

int
plamen_broker_v2_podman_lifecycle_execute_journaled(
    const struct plamen_broker_v2_podman_admission_custody *custody,
    int cgroup_root_fd, const char *systemd_control_group,
    struct plamen_broker_v2_podman_lifecycle_journal *journal,
    const struct plamen_broker_v2_podman_lifecycle_spec *spec,
    uint32_t operation,
    uint8_t *stdout_bytes, size_t stdout_capacity, size_t *stdout_size,
    uint8_t *stderr_bytes, size_t stderr_capacity, size_t *stderr_size,
    struct plamen_broker_v2_podman_lifecycle_receipt *receipt)
{
    struct plamen_broker_v2_podman_lifecycle_head head;
    struct plamen_broker_v2_podman_lifecycle_command command;
    struct plamen_broker_v2_podman_admission_spec admission;
    uint8_t command_digest[32], intent_checkpoint[32], final_checkpoint[32];
    uint8_t upper_digest[32], work_digest[32], overlay_pair[64];
    uint32_t decision, final_state, out_truncated = 0, err_truncated = 0;
    int command_exit = 0, status;
    size_t index;
    if (receipt == NULL) return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
    memset(receipt, 0, sizeof(*receipt));
    if (custody == NULL || journal == NULL || stdout_size == NULL
        || stderr_size == NULL || lifecycle_state_after(operation, &final_state) != 0
        || plamen_broker_v2_podman_cgroup_path_revalidate(custody,
            cgroup_root_fd, systemd_control_group) != 0
        || plamen_broker_v2_podman_lifecycle_journal_replay(journal, &head) != 0
        || plamen_broker_v2_podman_lifecycle_decide(&head, spec,
            operation, &decision) != 0)
        return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
    if (decision == PLAMEN_BROKER_V2_PODMAN_DECISION_REPLAY_COMMITTED) {
        *receipt = head.committed; return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK;
    }
    if (decision != PLAMEN_BROKER_V2_PODMAN_DECISION_APPEND_INTENT_THEN_EXECUTE)
        return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
    memset(&admission, 0, sizeof(admission));
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT; ++index)
        admission.components[index].executable_fd = custody->component_fds[index];
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT; ++index)
        admission.roots[index].fd = custody->root_fds[index];
    admission.image_reference = spec->image_reference;
    memset(&command, 0, sizeof(command));
    memset(command_digest, 0, sizeof(command_digest));
    if (operation != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN
        && (plamen_broker_v2_podman_lifecycle_render_command(&admission,
                spec, operation, &command) != 0
            || plamen_broker_v2_podman_lifecycle_command_sha256(&command,
                command_digest) != 0))
        return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
    if (plamen_broker_v2_podman_lifecycle_journal_append_intent(journal,
            spec, operation, command_digest, intent_checkpoint) != 0)
        return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
    if (operation != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEARDOWN) {
        if (execute_command_retained(custody, spec, &command,
                stdout_bytes, stdout_capacity, stdout_size,
                stderr_bytes, stderr_capacity, stderr_size,
                &out_truncated, &err_truncated, &command_exit) != 0
            || command_exit != 0)
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
    } else {
        uint64_t removed_entries = 0;
        if (remove_directory_contents(custody->root_fds[
                PLAMEN_BROKER_V2_PODMAN_ROOT_UPPER],
                custody->root_identity[PLAMEN_BROKER_V2_PODMAN_ROOT_UPPER].device,
                0, &removed_entries) != 0
            || remove_directory_contents(custody->root_fds[
                PLAMEN_BROKER_V2_PODMAN_ROOT_WORK],
                custody->root_identity[PLAMEN_BROKER_V2_PODMAN_ROOT_WORK].device,
                0, &removed_entries) != 0)
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
        *stdout_size = 0; *stderr_size = 0;
    }
    if (plamen_broker_v2_podman_cgroup_path_revalidate(custody,
            cgroup_root_fd, systemd_control_group) != 0
        || plamen_broker_v2_podman_lifecycle_journal_replay(journal, &head) != 0
        || !intent_state(head.state) || head.operation != operation)
        return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
    memset(receipt, 0, sizeof(*receipt));
    receipt->version = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECEIPT_VERSION;
    receipt->operation = operation; receipt->from_state = head.state;
    receipt->to_state = final_state; receipt->result = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK;
    receipt->exit_kind = PLAMEN_BROKER_V2_PODMAN_EXIT_NONE; receipt->exit_code = -1;
    receipt->stdout_size = (uint32_t)*stdout_size;
    receipt->stderr_size = (uint32_t)*stderr_size;
    receipt->stdout_truncated = out_truncated; receipt->stderr_truncated = err_truncated;
    receipt->journal_sequence = head.sequence + 1U;
    memcpy(receipt->operation_key, spec->operation_key, 32);
    memcpy(receipt->request_sha256, spec->request_sha256, 32);
    memcpy(receipt->admission_sha256, journal->admission_sha256, 32);
    memcpy(receipt->compiled_lifecycle_sha256, journal->compiled_lifecycle_sha256, 32);
    memcpy(receipt->host_boot_id_sha256, journal->host_boot_id_sha256, 32);
    memcpy(receipt->command_sha256, command_digest, 32);
    memcpy(receipt->previous_checkpoint_sha256, head.checkpoint_sha256, 32);
    if (plamen_broker_v2_sha256(stdout_bytes, *stdout_size,
            receipt->stdout_sha256) != 0
        || plamen_broker_v2_sha256(stderr_bytes, *stderr_size,
            receipt->stderr_sha256) != 0)
        return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
    if (final_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERMINAL
        || final_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ABSENT
        || final_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_SEALED) {
        if (plamen_broker_v2_linux_cgroup_leaf_admit(custody->cgroup_fd) != 0)
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
        receipt->cgroup_population_zero = 1U;
        if (plamen_broker_v2_sha256("populated 0\n", 12,
                receipt->cgroup_terminal_sha256) != 0)
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
    }
    if (operation == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_WAIT) {
        if (plamen_broker_v2_podman_lifecycle_parse_wait_status(stdout_bytes,
                *stdout_size, &receipt->exit_code) != 0)
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
        receipt->exit_kind = PLAMEN_BROKER_V2_PODMAN_EXIT_CODE;
    } else if (final_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERMINAL) {
        receipt->exit_kind = PLAMEN_BROKER_V2_PODMAN_EXIT_SIGNAL;
        receipt->signal_number = operation == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TERM
            ? SIGTERM : SIGKILL;
    }
    if (operation == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE) {
        if (*stdout_size != 65U || stdout_bytes[64] != '\n')
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
        for (index = 0; index < 64U; ++index)
            if (!((stdout_bytes[index] >= '0' && stdout_bytes[index] <= '9')
                    || (stdout_bytes[index] >= 'a'
                        && stdout_bytes[index] <= 'f')))
                return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
    }
    if (final_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_ABSENT
        || final_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_SEALED)
        receipt->container_absent = 1U;
    if (final_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_SEALED) {
        if (directory_empty_and_digest(custody->root_fds[
                PLAMEN_BROKER_V2_PODMAN_ROOT_UPPER],
                upper_digest) != 0
            || directory_empty_and_digest(custody->root_fds[
                PLAMEN_BROKER_V2_PODMAN_ROOT_WORK], work_digest) != 0)
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
        memcpy(overlay_pair, upper_digest, 32);
        memcpy(overlay_pair + 32, work_digest, 32);
        if (plamen_broker_v2_sha256(overlay_pair, sizeof(overlay_pair),
                receipt->overlay_cleanup_sha256) != 0)
            return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
        receipt->overlay_cleanup_complete = 1U;
    }
    receipt->receipt_requires_broker_authentication = 1U;
    receipt->lifecycle_authority_granted = 1U;
    if (plamen_broker_v2_podman_lifecycle_receipt_seal(receipt) != 0
        || plamen_broker_v2_podman_lifecycle_journal_commit(journal,
            receipt, final_checkpoint) != 0)
        return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
    status = plamen_broker_v2_podman_lifecycle_receipt_validate(receipt);
    return status == 0 ? PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK
        : PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED;
}
#else
int
plamen_broker_v2_podman_lifecycle_execute_journaled(
    const struct plamen_broker_v2_podman_admission_custody *custody,
    int root, const char *control_group,
    struct plamen_broker_v2_podman_lifecycle_journal *journal,
    const struct plamen_broker_v2_podman_lifecycle_spec *spec, uint32_t operation,
    uint8_t *out, size_t out_capacity, size_t *out_size,
    uint8_t *error, size_t error_capacity, size_t *error_size,
    struct plamen_broker_v2_podman_lifecycle_receipt *receipt)
{
    (void)custody; (void)root; (void)control_group; (void)journal; (void)spec;
    (void)operation; (void)out; (void)out_capacity; (void)out_size;
    (void)error; (void)error_capacity; (void)error_size;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
    return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_UNSUPPORTED;
}
#endif

int
plamen_broker_v2_podman_lifecycle_execute(
    const struct plamen_broker_v2_podman_admission_custody *admission,
    const struct plamen_broker_v2_podman_lifecycle_spec *spec,
    uint32_t operation,
    struct plamen_broker_v2_podman_lifecycle_receipt *receipt)
{
    (void)admission; (void)spec; (void)operation;
    if (receipt != NULL) memset(receipt, 0, sizeof(*receipt));
#ifdef __linux__
    return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_REJECTED;
#else
    return PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_UNSUPPORTED;
#endif
}

#ifdef PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_TEST_ONLY
static void
test_spec(struct plamen_broker_v2_podman_admission_spec *admission,
    struct plamen_broker_v2_podman_lifecycle_spec *spec,
    struct plamen_broker_v2_podman_mount_spec *mount,
    uint32_t network_mode)
{
    static const char *const argv[] = { "-B", "/opt/plamen/driver.py" };
    static const char *const environment[] = { "LANG=C", "LC_ALL=C" };
    size_t index;
    memset(admission, 0, sizeof(*admission));
    memset(spec, 0, sizeof(*spec));
    memset(mount, 0, sizeof(*mount));
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT; ++index)
        admission->components[index].executable_fd = (int)(101U + index);
    for (index = 0; index < PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT; ++index)
        admission->roots[index].fd = (int)(201U + index);
    admission->image_reference =
        "localhost/plamen/runtime@sha256:22222222222222222222222222222222"
        "22222222222222222222222222222222";
    spec->version = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_VERSION;
    spec->attempt_name = "plamen-attempt-0123456789abcdef";
    spec->container_id =
        "1111111111111111111111111111111111111111111111111111111111111111";
    spec->image_reference = admission->image_reference;
    spec->entrypoint = "/usr/bin/python3";
    spec->cgroup_parent = "/user.slice/plamen/payload-0123456789abcdef";
    spec->uid = 1000;
    spec->gid = 1000;
    spec->pids_limit = 256;
    spec->memory_bytes = 536870912U;
    spec->cpu_millis = 1500;
    spec->nofile_limit = 4096;
    spec->tmpfs_bytes = 67108864U;
    spec->guest_argv = argv;
    spec->guest_argc = sizeof(argv) / sizeof(argv[0]);
    spec->environment = environment;
    spec->environment_count = sizeof(environment) / sizeof(environment[0]);
    mount->source_fd = 301;
    mount->target = "/workspace/project";
    mount->read_only = 1;
    spec->mounts = mount;
    spec->mount_count = 1;
    spec->seccomp_profile_fd = 302;
    spec->network_mode = network_mode;
    spec->network_namespace_fd = network_mode
        == PLAMEN_BROKER_V2_PODMAN_NETWORK_NONE ? -1 : 401;
    if (network_mode != PLAMEN_BROKER_V2_PODMAN_NETWORK_NONE)
        memset(spec->verified_egress_handoff_sha256, 7, 32);
    memset(spec->request_sha256, 8, 32);
    memset(spec->operation_key, 9, 32);
    spec->timeout_ms = 60000;
    spec->output_limit = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OUTPUT_MAX;
}

int
plamen_broker_v2_podman_lifecycle_test_render(uint32_t operation,
    uint32_t network_mode, uint8_t *output, size_t capacity,
    size_t *output_size)
{
    struct plamen_broker_v2_podman_admission_spec admission;
    struct plamen_broker_v2_podman_lifecycle_spec spec;
    struct plamen_broker_v2_podman_mount_spec mount;
    struct plamen_broker_v2_podman_lifecycle_command command;
    size_t index, offset = 0, size;
    if (output == NULL || output_size == NULL) return -1;
    test_spec(&admission, &spec, &mount, network_mode);
    if (plamen_broker_v2_podman_lifecycle_render_command(&admission, &spec,
            operation, &command) != 0) return -1;
    for (index = 0; index < command.argc; ++index) {
        size = strlen(command.argv[index]) + 1U;
        if (size > capacity - offset) return -1;
        memcpy(output + offset, command.argv[index], size);
        offset += size;
    }
    *output_size = offset;
    return 0;
}

static void
test_receipt(struct plamen_broker_v2_podman_lifecycle_receipt *receipt)
{
    memset(receipt, 0, sizeof(*receipt));
    receipt->version = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECEIPT_VERSION;
    receipt->operation = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE;
    receipt->from_state = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE_INTENT;
    receipt->to_state = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATED_STOPPED;
    receipt->result = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK;
    receipt->exit_kind = PLAMEN_BROKER_V2_PODMAN_EXIT_NONE;
    receipt->exit_code = -1;
    receipt->journal_sequence = 2;
    memset(receipt->operation_key, 1, 32);
    memset(receipt->request_sha256, 2, 32);
    memset(receipt->admission_sha256, 3, 32);
    memset(receipt->compiled_lifecycle_sha256, 4, 32);
    memset(receipt->host_boot_id_sha256, 5, 32);
    memset(receipt->command_sha256, 6, 32);
    memset(receipt->stdout_sha256, 7, 32);
    memset(receipt->stderr_sha256, 8, 32);
    memset(receipt->previous_checkpoint_sha256, 9, 32);
    memset(receipt->checkpoint_sha256, 10, 32);
    receipt->receipt_requires_broker_authentication = 1U;
    receipt->lifecycle_authority_granted = 1U;
}

int
plamen_broker_v2_podman_lifecycle_test_receipt_and_record_integrity(void)
{
    struct plamen_broker_v2_podman_lifecycle_receipt receipt, decoded;
    uint8_t record[PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECORD_SIZE];
    test_receipt(&receipt);
    if (plamen_broker_v2_podman_lifecycle_receipt_seal(&receipt) != 0
        || plamen_broker_v2_podman_lifecycle_receipt_validate(&receipt) != 0
        || plamen_broker_v2_podman_lifecycle_record_encode(&receipt,
            record) != 0
        || plamen_broker_v2_podman_lifecycle_record_decode(record,
            &decoded) != 0
        || !constant_equal(decoded.receipt_sha256,
            receipt.receipt_sha256, 32)) return -1;
    receipt.command_sha256[0] ^= 1U;
    if (plamen_broker_v2_podman_lifecycle_receipt_validate(&receipt) == 0)
        return -1;
    record[40] ^= 1U;
    return plamen_broker_v2_podman_lifecycle_record_decode(record,
        &decoded) != 0 ? 0 : -1;
}

int
plamen_broker_v2_podman_lifecycle_test_decision(uint32_t head_state,
    uint32_t same_key, uint32_t divergent_request, uint32_t *decision)
{
    struct plamen_broker_v2_podman_admission_spec admission;
    struct plamen_broker_v2_podman_lifecycle_spec spec;
    struct plamen_broker_v2_podman_mount_spec mount;
    struct plamen_broker_v2_podman_lifecycle_head head;
    (void)admission;
    test_spec(&admission, &spec, &mount, PLAMEN_BROKER_V2_PODMAN_NETWORK_NONE);
    memset(&head, 0, sizeof(head));
    head.state = head_state;
    if (same_key) {
        memcpy(head.operation_key, spec.operation_key, 32);
        memcpy(head.request_sha256, spec.request_sha256, 32);
        head.operation = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE;
        if (divergent_request) head.request_sha256[0] ^= 1U;
    }
    if (head_state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATED_STOPPED
        && same_key && !divergent_request) {
        test_receipt(&head.committed);
        memcpy(head.committed.operation_key, spec.operation_key, 32);
        memcpy(head.committed.request_sha256, spec.request_sha256, 32);
        if (plamen_broker_v2_podman_lifecycle_receipt_seal(
                &head.committed) != 0) return -1;
        head.has_committed_receipt = 1U;
    }
    return plamen_broker_v2_podman_lifecycle_decide(&head, &spec,
        PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE, decision);
}

int
plamen_broker_v2_podman_lifecycle_test_journal_roundtrip(int parent_fd,
    const char *journal_id)
{
    struct plamen_broker_v2_podman_lifecycle_journal *journal = NULL;
    struct plamen_broker_v2_podman_admission_spec admission;
    struct plamen_broker_v2_podman_lifecycle_spec spec;
    struct plamen_broker_v2_podman_mount_spec mount;
    struct plamen_broker_v2_podman_lifecycle_command command;
    struct plamen_broker_v2_podman_lifecycle_receipt receipt;
    struct plamen_broker_v2_podman_lifecycle_head head;
    uint8_t admission_digest[32], lifecycle_digest[32], boot_digest[32];
    uint8_t command_digest[32];
    uint8_t intent_checkpoint[32], committed_checkpoint[32], replay[32];
    uint8_t create_operation_key[32];
    int status = -1;
    memset(admission_digest, 3, 32);
    memset(lifecycle_digest, 4, 32);
    memset(boot_digest, 5, 32);
    test_spec(&admission, &spec, &mount, PLAMEN_BROKER_V2_PODMAN_NETWORK_NONE);
    if (plamen_broker_v2_podman_lifecycle_render_command(&admission, &spec,
            PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE, &command) != 0
        || plamen_broker_v2_podman_lifecycle_command_sha256(&command,
            command_digest) != 0
        || plamen_broker_v2_podman_lifecycle_journal_open(parent_fd,
            journal_id, admission_digest, lifecycle_digest, boot_digest,
            &journal) != 0
        || plamen_broker_v2_podman_lifecycle_journal_append_intent(journal,
            &spec, PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE,
            command_digest, intent_checkpoint)
                != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK
        || plamen_broker_v2_podman_lifecycle_journal_append_intent(journal,
            &spec, PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATE,
            command_digest, replay)
                != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RECOVERY_REQUIRED
        || !constant_equal(intent_checkpoint, replay, 32)) goto done;
    test_receipt(&receipt);
    memcpy(receipt.operation_key, spec.operation_key, 32);
    memcpy(receipt.request_sha256, spec.request_sha256, 32);
    memcpy(receipt.admission_sha256, admission_digest, 32);
    memcpy(receipt.compiled_lifecycle_sha256, lifecycle_digest, 32);
    memcpy(receipt.host_boot_id_sha256, boot_digest, 32);
    memcpy(receipt.command_sha256, command_digest, 32);
    memcpy(receipt.previous_checkpoint_sha256, intent_checkpoint, 32);
    receipt.journal_sequence = 2;
    if (plamen_broker_v2_podman_lifecycle_receipt_seal(&receipt) != 0
        || plamen_broker_v2_podman_lifecycle_journal_commit(journal,
            &receipt, committed_checkpoint)
                != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK
        || plamen_broker_v2_podman_lifecycle_journal_commit(journal,
            &receipt, replay) != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK
        || !constant_equal(committed_checkpoint, replay, 32)
        || plamen_broker_v2_podman_lifecycle_journal_replay(journal,
            &head) != 0
        || head.state != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CREATED_STOPPED
        || head.sequence != 2 || head.has_committed_receipt != 1U
        || !constant_equal(head.committed.receipt_sha256,
            receipt.receipt_sha256, 32)) goto done;
    memcpy(create_operation_key, spec.operation_key, 32);
    memset(spec.operation_key, 10, 32);
    memset(spec.request_sha256, 11, 32);
    if (plamen_broker_v2_podman_lifecycle_journal_append_intent(journal,
            &spec, PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START,
            command_digest, intent_checkpoint)
                != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK) goto done;
    test_receipt(&receipt);
    receipt.operation = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START;
    receipt.from_state = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_START_INTENT;
    receipt.to_state = PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RUNNING;
    receipt.journal_sequence = 4;
    memcpy(receipt.operation_key, spec.operation_key, 32);
    memcpy(receipt.request_sha256, spec.request_sha256, 32);
    memcpy(receipt.admission_sha256, admission_digest, 32);
    memcpy(receipt.compiled_lifecycle_sha256, lifecycle_digest, 32);
    memcpy(receipt.host_boot_id_sha256, boot_digest, 32);
    memcpy(receipt.command_sha256, command_digest, 32);
    memcpy(receipt.previous_checkpoint_sha256, intent_checkpoint, 32);
    if (plamen_broker_v2_podman_lifecycle_receipt_seal(&receipt) != 0
        || plamen_broker_v2_podman_lifecycle_journal_commit(journal,
            &receipt, committed_checkpoint)
                != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_OK) goto done;
    memcpy(spec.operation_key, create_operation_key, 32);
    memset(spec.request_sha256, 12, 32);
    if (plamen_broker_v2_podman_lifecycle_journal_append_intent(journal,
            &spec, PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_WAIT,
            command_digest, replay)
                != PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_CONFLICT) goto done;
    status = 0;
done:
    plamen_broker_v2_podman_lifecycle_journal_close(journal);
    return status;
}

int
plamen_broker_v2_podman_lifecycle_test_journal_replay(int parent_fd,
    const char *journal_id)
{
    struct plamen_broker_v2_podman_lifecycle_journal *journal = NULL;
    struct plamen_broker_v2_podman_lifecycle_head head;
    uint8_t admission_digest[32], lifecycle_digest[32], boot_digest[32];
    int status;
    memset(admission_digest, 3, 32);
    memset(lifecycle_digest, 4, 32);
    memset(boot_digest, 5, 32);
    if (plamen_broker_v2_podman_lifecycle_journal_open(parent_fd,
            journal_id, admission_digest, lifecycle_digest, boot_digest,
            &journal) != 0)
        return -1;
    status = plamen_broker_v2_podman_lifecycle_journal_replay(journal, &head);
    plamen_broker_v2_podman_lifecycle_journal_close(journal);
    return status == 0 && head.sequence == 4
        && head.state == PLAMEN_BROKER_V2_PODMAN_LIFECYCLE_RUNNING
        && head.has_committed_receipt == 1U ? 0 : -1;
}

int
plamen_broker_v2_podman_lifecycle_test_journal_wrong_boot_rejected(
    int parent_fd, const char *journal_id)
{
    struct plamen_broker_v2_podman_lifecycle_journal *journal = NULL;
    struct plamen_broker_v2_podman_lifecycle_head head;
    uint8_t admission_digest[32], lifecycle_digest[32], boot_digest[32];
    int status;
    memset(admission_digest, 3, 32);
    memset(lifecycle_digest, 4, 32);
    memset(boot_digest, 6, 32);
    if (plamen_broker_v2_podman_lifecycle_journal_open(parent_fd,
            journal_id, admission_digest, lifecycle_digest, boot_digest,
            &journal) != 0) return -1;
    status = plamen_broker_v2_podman_lifecycle_journal_replay(journal, &head);
    plamen_broker_v2_podman_lifecycle_journal_close(journal);
    return status != 0 ? 0 : -1;
}
#endif
