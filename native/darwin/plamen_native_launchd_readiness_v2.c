#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_native_launchd_readiness_v2.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef POSIX_SPAWN_CLOEXEC_DEFAULT
#define POSIX_SPAWN_CLOEXEC_DEFAULT 0x4000
#endif

#define READINESS_TIMEOUT_TICKS 500U

static char *const closed_environment[] = { NULL };

static int
canonical_absolute(const char *path)
{
    const unsigned char *cursor = (const unsigned char *)path;
    size_t size;
    if (path == NULL || path[0] != '/' || path[1] == '/'
        || (size = strlen(path)) == 0 || size > 4096U
        || path[size - 1U] == '/' || strstr(path, "//") != NULL
        || strstr(path, "/./") != NULL || strstr(path, "/../") != NULL)
        return 0;
    while (*cursor != '\0') {
        if (*cursor < 32U || *cursor == 127U)
            return 0;
        ++cursor;
    }
    return 1;
}

static int
same_vnode(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino
        && left->st_mode == right->st_mode && left->st_uid == right->st_uid
        && left->st_gid == right->st_gid && left->st_nlink == right->st_nlink
        && left->st_size == right->st_size;
}

static int
wait_bounded(pid_t child)
{
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000L };
    unsigned int tick;
    int status = 0;
    for (tick = 0; tick < READINESS_TIMEOUT_TICKS; ++tick) {
        pid_t observed = waitpid(child, &status, WNOHANG);
        if (observed == child)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
        if (observed < 0 && errno != EINTR)
            return -1;
        (void)nanosleep(&pause, NULL);
    }
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    errno = ETIMEDOUT;
    return -1;
}

int
plamen_native_launchd_authenticated_ready_v2(
    const struct plamen_install_receipt *receipt, int generation_fd)
{
    const struct plamen_install_receipt_member *launcher;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    struct stat retained_before, retained_after, path_before, path_after;
    char executable[PLAMEN_INSTALL_RECEIPT_PATH_MAX
        + PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH_MAX + 2U];
    char *const arguments[] = { executable, "readiness", NULL };
    short flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP;
    pid_t child = -1;
    int retained_fd = -1, actions_ready = 0, attributes_ready = 0;
    int result = -1;

    if (receipt == NULL || generation_fd < 0
        || !canonical_absolute(receipt->generation_path)) {
        errno = EINVAL;
        return -1;
    }
    launcher = &receipt->members[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1];
    if (launcher->role != PLAMEN_INSTALL_MEMBER_LAUNCHER
        || launcher->relative_path[0] == '\0'
        || snprintf(executable, sizeof(executable), "%s/%s",
            receipt->generation_path, launcher->relative_path)
            >= (int)sizeof(executable)
        || !canonical_absolute(executable)
        || plamen_install_receipt_open_member(generation_fd, launcher,
            &retained_fd) != 0
        || fstat(retained_fd, &retained_before) != 0
        || stat(executable, &path_before) != 0
        || !same_vnode(&retained_before, &path_before))
        goto done;
    if (posix_spawn_file_actions_init(&actions) != 0)
        goto done;
    actions_ready = 1;
    if (posix_spawn_file_actions_addopen(&actions, STDIN_FILENO,
            "/dev/null", O_RDONLY, 0) != 0
        || posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO,
            "/dev/null", O_WRONLY, 0) != 0
        || posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
            "/dev/null", O_WRONLY, 0) != 0
        || posix_spawnattr_init(&attributes) != 0)
        goto done;
    attributes_ready = 1;
    if (posix_spawnattr_setflags(&attributes, flags) != 0
        || posix_spawnattr_setpgroup(&attributes, 0) != 0
        || posix_spawn(&child, executable, &actions, &attributes,
            arguments, closed_environment) != 0)
        goto done;
    if (wait_bounded(child) != 0) {
        child = -1;
        goto done;
    }
    child = -1;
    if (plamen_install_receipt_member_revalidate(retained_fd, launcher) != 0
        || fstat(retained_fd, &retained_after) != 0
        || stat(executable, &path_after) != 0
        || !same_vnode(&retained_before, &retained_after)
        || !same_vnode(&retained_after, &path_after))
        goto done;
    result = 0;
done:
    if (child > 0) {
        int status;
        (void)kill(-child, SIGKILL);
        (void)kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    }
    if (attributes_ready)
        posix_spawnattr_destroy(&attributes);
    if (actions_ready)
        posix_spawn_file_actions_destroy(&actions);
    if (retained_fd >= 0)
        close(retained_fd);
    return result;
}
