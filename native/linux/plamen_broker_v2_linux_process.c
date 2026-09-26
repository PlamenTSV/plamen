#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_broker_v2_linux.h"

#include <errno.h>
#include <fcntl.h>
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
#include <sys/syscall.h>
#endif

static void
custody_initialize(struct plamen_broker_v2_linux_process_custody *custody)
{
    if (custody == NULL) return;
    memset(custody, 0, sizeof(*custody));
    custody->cgroup_fd = -1;
    custody->pidfd = -1;
    custody->leader_pid = -1;
    custody->process_group = -1;
    custody->state = PLAMEN_BROKER_V2_LINUX_CUSTODY_EMPTY;
}

#ifdef __linux__
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
hash_fd(int fd, uint8_t output[32])
{
    uint8_t *bytes = NULL;
    struct stat identity;
    off_t original, end;
    size_t size = 0, offset = 0;
    int status = -1;
    if (fd < 0 || output == NULL || fstat(fd, &identity) != 0
        || !S_ISREG(identity.st_mode) || identity.st_size <= 0
        || identity.st_size > 256 * 1024 * 1024) return -1;
    original = lseek(fd, 0, SEEK_CUR);
    end = lseek(fd, 0, SEEK_END);
    if (end != identity.st_size || lseek(fd, 0, SEEK_SET) != 0) goto done;
    size = (size_t)end;
    bytes = malloc(size);
    if (bytes == NULL) goto done;
    while (offset < size) {
        ssize_t amount = read(fd, bytes + offset, size - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    if (plamen_broker_v2_sha256(bytes, size, output) == 0) status = 0;
done:
    if (bytes != NULL) {
        plamen_broker_v2_secure_zero(bytes, size);
        free(bytes);
    }
    if (original >= 0) (void)lseek(fd, original, SEEK_SET);
    return status;
}

static int
read_small_at(int parent_fd, const char *name, char *buffer, size_t capacity,
    size_t *size_out)
{
    int fd, status = -1;
    size_t offset = 0;
    struct stat identity;
    if (parent_fd < 0 || name == NULL || buffer == NULL || capacity < 2)
        return -1;
    fd = openat(parent_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &identity) != 0 || !S_ISREG(identity.st_mode)) goto done;
    while (offset + 1U < capacity) {
        ssize_t amount = read(fd, buffer + offset, capacity - offset - 1U);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) goto done;
        if (amount == 0) { status = 0; break; }
        offset += (size_t)amount;
    }
    if (status == 0) {
        buffer[offset] = '\0';
        if (size_out != NULL) *size_out = offset;
    }
done:
    (void)close(fd);
    return status;
}

static int
cgroup_populated(int cgroup_fd, int *populated)
{
    char buffer[4096], *line, *save = NULL;
    size_t size;
    int found = 0;
    if (populated == NULL
        || read_small_at(cgroup_fd, "cgroup.events", buffer,
            sizeof(buffer), &size) != 0 || size == 0) return -1;
    for (line = strtok_r(buffer, "\n", &save); line != NULL;
            line = strtok_r(NULL, "\n", &save)) {
        if (!strncmp(line, "populated ", 10)) {
            if (found || (strcmp(line + 10, "0") && strcmp(line + 10, "1")))
                return -1;
            *populated = line[10] == '1';
            found = 1;
        }
    }
    return found ? 0 : -1;
}

static int
cgroup_procs_empty(int cgroup_fd)
{
    char buffer[64];
    size_t size;
    return read_small_at(cgroup_fd, "cgroup.procs", buffer,
        sizeof(buffer), &size) == 0 && size == 0 ? 0 : -1;
}

static int
write_control_at(int cgroup_fd, const char *name, const char *value)
{
    int fd, status = -1;
    size_t size = strlen(value), offset = 0;
    fd = openat(cgroup_fd, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    while (offset < size) {
        ssize_t amount = write(fd, value + offset, size - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    status = 0;
done:
    (void)close(fd);
    return status;
}

static int
monotonic_millis(uint64_t *value)
{
    struct timespec now;
    if (value == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    *value = (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
    return 0;
}

static int
wait_population_zero(int cgroup_fd, uint32_t timeout_ms)
{
    uint64_t start, now;
    struct timespec pause = {0, 10 * 1000 * 1000};
    int populated;
    if (monotonic_millis(&start) != 0) return -1;
    for (;;) {
        if (cgroup_populated(cgroup_fd, &populated) != 0) return -1;
        if (!populated && cgroup_procs_empty(cgroup_fd) == 0) return 0;
        if (monotonic_millis(&now) != 0 || now - start >= timeout_ms) return -1;
        while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
        pause.tv_sec = 0; pause.tv_nsec = 10 * 1000 * 1000;
    }
}

static int
boot_id_digest(uint8_t output[32])
{
    int fd;
    char value[37], extra;
    size_t offset = 0;
    static const int hyphens[] = {8, 13, 18, 23};
    size_t index, h = 0;
    fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    while (offset < sizeof(value)) {
        ssize_t amount = read(fd, value + offset, sizeof(value) - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) { (void)close(fd); return -1; }
        offset += (size_t)amount;
    }
    if (read(fd, &extra, 1) != 0 || close(fd) != 0 || value[36] != '\n')
        return -1;
    for (index = 0; index < 36; ++index) {
        if (h < 4 && (int)index == hyphens[h]) { if (value[index] != '-') return -1; ++h; }
        else if (!((value[index] >= '0' && value[index] <= '9')
                || (value[index] >= 'a' && value[index] <= 'f'))) return -1;
    }
    return plamen_broker_v2_sha256(value, 36, output) == 0 ? 0 : -1;
}

static int
proc_start_ticks(pid_t pid, uint64_t *ticks)
{
    char path[64], buffer[4096], *end, *cursor;
    int fd;
    size_t offset = 0;
    unsigned field = 3;
    unsigned long long value;
    if (pid <= 0 || ticks == NULL
        || snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) < 0)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    while (offset + 1U < sizeof(buffer)) {
        ssize_t amount = read(fd, buffer + offset, sizeof(buffer) - offset - 1U);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) { (void)close(fd); return -1; }
        if (amount == 0) break;
        offset += (size_t)amount;
    }
    (void)close(fd); buffer[offset] = '\0';
    cursor = strrchr(buffer, ')');
    if (cursor == NULL || cursor[1] != ' ') return -1;
    cursor += 2;
    while (field < 22) {
        end = strchr(cursor, ' ');
        if (end == NULL) return -1;
        cursor = end + 1; ++field;
    }
    errno = 0; value = strtoull(cursor, &end, 10);
    if (errno != 0 || end == cursor || (*end != ' ' && *end != '\0')) return -1;
    *ticks = (uint64_t)value;
    return 0;
}

static int
proc_executable_digest(pid_t pid, uint8_t output[32])
{
    char path[64];
    int fd, status;
    if (pid <= 0 || output == NULL
        || snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid) < 0)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    status = hash_fd(fd, output);
    (void)close(fd);
    return status;
}

static int
pidfd_open_native(pid_t pid)
{
#ifdef SYS_pidfd_open
    return (int)syscall(SYS_pidfd_open, pid, 0U);
#else
    (void)pid; errno = ENOSYS; return -1;
#endif
}

static int
pidfd_signal(int pidfd, int signal_number)
{
#ifdef SYS_pidfd_send_signal
    return (int)syscall(SYS_pidfd_send_signal, pidfd, signal_number,
        NULL, 0U);
#else
    (void)pidfd; (void)signal_number; errno = ENOSYS; return -1;
#endif
}

static int
argv_valid(const struct plamen_broker_v2_linux_spawn_request *request)
{
    size_t index, length;
    if (request == NULL || request->argv == NULL || request->argc == 0
        || request->argc > PLAMEN_BROKER_V2_LINUX_ARGC_MAX
        || request->argv[request->argc] != NULL) return 0;
    for (index = 0; index < request->argc; ++index) {
        if (request->argv[index] == NULL
            || (length = strlen(request->argv[index])) == 0
            || length > PLAMEN_BROKER_V2_LINUX_ARG_SIZE_MAX) return 0;
    }
    return 1;
}

int
plamen_broker_v2_linux_cgroup_leaf_admit(int cgroup_fd)
{
    struct stat identity;
    int populated, kill_fd;
    if (cgroup_fd < 0 || fstat(cgroup_fd, &identity) != 0
        || !S_ISDIR(identity.st_mode)
        || cgroup_populated(cgroup_fd, &populated) != 0 || populated
        || cgroup_procs_empty(cgroup_fd) != 0) return -1;
    kill_fd = openat(cgroup_fd, "cgroup.kill", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (kill_fd < 0) return -1;
    return close(kill_fd) == 0 ? 0 : -1;
}

int
plamen_broker_v2_linux_process_spawn_retained(
    const struct plamen_broker_v2_linux_spawn_request *request,
    struct plamen_broker_v2_linux_process_custody *custody)
{
    int gate[2] = {-1, -1}, duplicate = -1, pidfd = -1;
    int status = PLAMEN_BROKER_V2_LINUX_PROCESS_REJECTED;
    pid_t child = -1;
    uint8_t digest[32], boot[32], release = 1;
    char pid_text[32];
    int pid_length;
    static char *const environment[] = {
        "HOME=/", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", NULL
    };
    if (custody == NULL) return PLAMEN_BROKER_V2_LINUX_PROCESS_UNSUPPORTED;
    custody_initialize(custody);
    if (request == NULL || request->executable_fd < 3 || request->cwd_fd < 3
        || request->stdin_fd < 0 || request->stdout_fd < 0 || request->stderr_fd < 0
        || request->cgroup_fd < 3 || !argv_valid(request)
        || !digest_present(request->expected_executable_identity)
        || hash_fd(request->executable_fd, digest) != 0
        || !constant_equal(digest, request->expected_executable_identity, 32)
        || boot_id_digest(boot) != 0
        || plamen_broker_v2_linux_cgroup_leaf_admit(request->cgroup_fd) != 0
        || pipe2(gate, O_CLOEXEC) != 0) goto done;
    child = fork();
    if (child < 0) goto done;
    if (child == 0) {
        char byte;
        long maximum_fd;
        int fd;
        (void)close(gate[1]);
        if (setpgid(0, 0) != 0 || fchdir(request->cwd_fd) != 0
            || dup2(request->stdin_fd, STDIN_FILENO) < 0
            || dup2(request->stdout_fd, STDOUT_FILENO) < 0
            || dup2(request->stderr_fd, STDERR_FILENO) < 0
            || read(gate[0], &byte, 1) != 1) _exit(126);
        (void)close(gate[0]);
        maximum_fd = sysconf(_SC_OPEN_MAX);
        if (maximum_fd < 0 || maximum_fd > 1048576L) maximum_fd = 1048576L;
        for (fd = 3; fd < maximum_fd; ++fd)
            if (fd != request->executable_fd) (void)close(fd);
        if (fcntl(request->executable_fd, F_SETFD, 0) != 0) _exit(126);
        fexecve(request->executable_fd, (char *const *)request->argv, environment);
        _exit(errno == ENOENT ? 127 : 126);
    }
    (void)close(gate[0]); gate[0] = -1;
    pidfd = pidfd_open_native(child);
    pid_length = snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)child);
    if (pidfd < 0 || pid_length <= 0 || (size_t)pid_length >= sizeof(pid_text)
        || write_control_at(request->cgroup_fd, "cgroup.procs", pid_text) != 0
        || proc_start_ticks(child, &custody->start_ticks) != 0
        || write(gate[1], &release, 1) != 1) {
        (void)write_control_at(request->cgroup_fd, "cgroup.kill", "1\n");
        (void)pidfd_signal(pidfd, SIGKILL);
        (void)waitpid(child, NULL, 0);
        goto done;
    }
    duplicate = fcntl(request->cgroup_fd, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) {
        (void)write_control_at(request->cgroup_fd, "cgroup.kill", "1\n");
        (void)pidfd_signal(pidfd, SIGKILL); (void)waitpid(child, NULL, 0);
        goto done;
    }
    custody->cgroup_fd = duplicate; duplicate = -1;
    custody->pidfd = pidfd; pidfd = -1;
    custody->leader_pid = child;
    custody->process_group = child;
    memcpy(custody->boot_id_sha256, boot, 32);
    memcpy(custody->executable_identity, digest, 32);
    custody->state = PLAMEN_BROKER_V2_LINUX_CUSTODY_RUNNING;
    status = PLAMEN_BROKER_V2_LINUX_PROCESS_OK;
done:
    if (gate[0] >= 0) (void)close(gate[0]);
    if (gate[1] >= 0) (void)close(gate[1]);
    if (pidfd >= 0) (void)close(pidfd);
    if (duplicate >= 0) (void)close(duplicate);
    plamen_broker_v2_secure_zero(digest, sizeof(digest));
    plamen_broker_v2_secure_zero(boot, sizeof(boot));
    return status;
}

int
plamen_broker_v2_linux_process_revalidate(
    struct plamen_broker_v2_linux_process_custody *custody)
{
    struct pollfd watched;
    uint8_t boot[32];
    uint8_t executable[32];
    uint64_t ticks;
    if (custody == NULL || custody->state != PLAMEN_BROKER_V2_LINUX_CUSTODY_RUNNING
        || custody->cgroup_fd < 3 || custody->pidfd < 0 || custody->leader_pid <= 0
        || boot_id_digest(boot) != 0
        || !constant_equal(boot, custody->boot_id_sha256, 32)
        || proc_start_ticks(custody->leader_pid, &ticks) != 0
        || ticks != custody->start_ticks
        || proc_executable_digest(custody->leader_pid, executable) != 0
        || !constant_equal(executable, custody->executable_identity, 32)) return -1;
    watched.fd = custody->pidfd; watched.events = POLLIN; watched.revents = 0;
    return poll(&watched, 1, 0) == 0 ? 0 : -1;
}

static int
wait_impl(struct plamen_broker_v2_linux_process_custody *custody,
    uint32_t timeout_ms, uint32_t extinction_timeout_ms, int force,
    struct plamen_broker_v2_linux_wait_result *result)
{
    struct pollfd watched;
    int ready, status = 0;
    pid_t waited;
    if (result == NULL || custody == NULL
        || custody->state != PLAMEN_BROKER_V2_LINUX_CUSTODY_RUNNING
        || timeout_ms == 0
        || extinction_timeout_ms > PLAMEN_BROKER_V2_LINUX_EXTINCTION_TIMEOUT_MAX_MS)
        return PLAMEN_BROKER_V2_LINUX_PROCESS_UNSUPPORTED;
    memset(result, 0, sizeof(*result));
    watched.fd = custody->pidfd; watched.events = POLLIN; watched.revents = 0;
    if (force) {
        if (write_control_at(custody->cgroup_fd, "cgroup.kill", "1\n") != 0
            || (pidfd_signal(custody->pidfd, SIGKILL) != 0 && errno != ESRCH))
            return PLAMEN_BROKER_V2_LINUX_PROCESS_REJECTED;
    }
    ready = poll(&watched, 1, force ? (int)extinction_timeout_ms
        : (int)timeout_ms);
    if (ready < 0 && errno == EINTR) ready = 0;
    if (ready == 0 && !force) {
        result->timed_out = 1;
        if (write_control_at(custody->cgroup_fd, "cgroup.kill", "1\n") != 0
            || (pidfd_signal(custody->pidfd, SIGKILL) != 0 && errno != ESRCH))
            return -1;
        watched.revents = 0;
        if (poll(&watched, 1, (int)extinction_timeout_ms) <= 0) return -1;
    } else if (ready <= 0) return PLAMEN_BROKER_V2_LINUX_PROCESS_REJECTED;
    do { waited = waitpid(custody->leader_pid, &status, 0); }
    while (waited < 0 && errno == EINTR);
    if (waited != custody->leader_pid
        || wait_population_zero(custody->cgroup_fd, extinction_timeout_ms) != 0)
        return PLAMEN_BROKER_V2_LINUX_PROCESS_REJECTED;
    result->exited = 1;
    result->cgroup_population_zero = 1;
    if (WIFEXITED(status)) result->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) result->signal_number = WTERMSIG(status);
    else return PLAMEN_BROKER_V2_LINUX_PROCESS_REJECTED;
    custody->state = PLAMEN_BROKER_V2_LINUX_CUSTODY_EXTINCT;
    return result->timed_out ? PLAMEN_BROKER_V2_LINUX_PROCESS_TIMED_OUT
        : PLAMEN_BROKER_V2_LINUX_PROCESS_EXITED;
}

int
plamen_broker_v2_linux_process_wait_or_extinguish(
    struct plamen_broker_v2_linux_process_custody *custody,
    uint32_t timeout_ms, uint32_t extinction_timeout_ms,
    struct plamen_broker_v2_linux_wait_result *result)
{
    return wait_impl(custody, timeout_ms, extinction_timeout_ms, 0, result);
}

int
plamen_broker_v2_linux_process_extinguish(
    struct plamen_broker_v2_linux_process_custody *custody,
    uint32_t timeout_ms, struct plamen_broker_v2_linux_wait_result *result)
{
    return wait_impl(custody, 1, timeout_ms, 1, result);
}

void
plamen_broker_v2_linux_process_close(
    struct plamen_broker_v2_linux_process_custody *custody)
{
    if (custody == NULL) return;
    if (custody->state == PLAMEN_BROKER_V2_LINUX_CUSTODY_RUNNING) {
        (void)write_control_at(custody->cgroup_fd, "cgroup.kill", "1\n");
        (void)pidfd_signal(custody->pidfd, SIGKILL);
        (void)waitpid(custody->leader_pid, NULL, 0);
    }
    if (custody->cgroup_fd >= 0) (void)close(custody->cgroup_fd);
    if (custody->pidfd >= 0) (void)close(custody->pidfd);
    plamen_broker_v2_secure_zero(custody, sizeof(*custody));
    custody->cgroup_fd = -1; custody->pidfd = -1;
    custody->leader_pid = -1; custody->process_group = -1;
    custody->state = PLAMEN_BROKER_V2_LINUX_CUSTODY_BURNED;
}

#else
int plamen_broker_v2_linux_cgroup_leaf_admit(int fd) { (void)fd; return -1; }
int plamen_broker_v2_linux_process_spawn_retained(
    const struct plamen_broker_v2_linux_spawn_request *request,
    struct plamen_broker_v2_linux_process_custody *custody)
{ (void)request; custody_initialize(custody); return PLAMEN_BROKER_V2_LINUX_PROCESS_UNSUPPORTED; }
int plamen_broker_v2_linux_process_revalidate(
    struct plamen_broker_v2_linux_process_custody *custody)
{ (void)custody; return -1; }
int plamen_broker_v2_linux_process_wait_or_extinguish(
    struct plamen_broker_v2_linux_process_custody *custody, uint32_t wait,
    uint32_t extinguish, struct plamen_broker_v2_linux_wait_result *result)
{ (void)custody; (void)wait; (void)extinguish; (void)result; return PLAMEN_BROKER_V2_LINUX_PROCESS_UNSUPPORTED; }
int plamen_broker_v2_linux_process_extinguish(
    struct plamen_broker_v2_linux_process_custody *custody, uint32_t timeout,
    struct plamen_broker_v2_linux_wait_result *result)
{ (void)custody; (void)timeout; (void)result; return PLAMEN_BROKER_V2_LINUX_PROCESS_UNSUPPORTED; }
void plamen_broker_v2_linux_process_close(
    struct plamen_broker_v2_linux_process_custody *custody)
{ custody_initialize(custody); if (custody != NULL) custody->state = PLAMEN_BROKER_V2_LINUX_CUSTODY_BURNED; }
#endif
