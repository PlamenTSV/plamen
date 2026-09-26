#include "plamen_broker_v2_process.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int
plamen_broker_v2_production_available(void)
{
#if defined(__APPLE__)
    return 1;
#else
    return 0;
#endif
}

void
plamen_broker_v2_test_result_dispose(struct plamen_broker_v2_test_result *result)
{
    if (result == NULL)
        return;
    free(result->stdout_bytes);
    free(result->stderr_bytes);
    memset(result, 0, sizeof(*result));
}

#if defined(__APPLE__)

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <spawn.h>
#include <sys/event.h>
#include <sys/resource.h>

#ifndef POSIX_SPAWN_CLOEXEC_DEFAULT
#define POSIX_SPAWN_CLOEXEC_DEFAULT 0x4000
#endif

#define PLAMEN_BROKER_V2_DRAIN_ROUNDS 512U
#define PLAMEN_BROKER_V2_RETAINED_FD_MIN 1024

struct stream_capture {
    CC_SHA256_CTX digest;
    uint8_t *retained;
    size_t retained_size;
    size_t retained_limit;
    uint64_t observed_limit;
    uint64_t observed;
    int truncated;
    int overflow;
};

struct signing_identity {
    uint8_t cdhash[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint32_t cdhash_size;
    char identifier[PLAMEN_BROKER_V2_SIGNING_TEXT_MAX];
    char team[PLAMEN_BROKER_V2_SIGNING_TEXT_MAX];
};

enum process_lifecycle_state {
    PROCESS_STATE_PREPARED = 1,
    PROCESS_STATE_RUNNING = 2,
    PROCESS_STATE_TERMINAL = 3
};

struct plamen_broker_v2_process {
    uint32_t state;
    int executable_fd;
    int cwd_fd;
    int stdin_fd;
    char *executable_path;
    char **argv;
    size_t argc;
    char **environment;
    size_t environment_count;
    uint32_t environment_policy;
    struct plamen_broker_v2_process_fd_map
        fd_maps[PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX];
    size_t fd_map_count;
    uint64_t timeout_ms;
    uint32_t stdout_spool_limit;
    uint32_t stderr_spool_limit;
    uint8_t expected_executable_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    char expected_signing_identifier[PLAMEN_BROKER_V2_SIGNING_TEXT_MAX];
    char expected_team_identifier[PLAMEN_BROKER_V2_SIGNING_TEXT_MAX];
    struct stat retained_identity;
    uint8_t executable_identity_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    struct signing_identity signing;
    int stdout_pipe[2];
    int stderr_pipe[2];
    int queue;
    pid_t child;
    uint64_t birth;
    uint64_t deadline_ms;
    struct stream_capture stdout_capture;
    struct stream_capture stderr_capture;
    int captures_ready;
    struct plamen_broker_v2_process_terminal terminal;
};

static int
same_vnode(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev
        && left->st_ino == right->st_ino
        && (left->st_mode & S_IFMT) == (right->st_mode & S_IFMT)
        && left->st_uid == right->st_uid
        && left->st_gid == right->st_gid;
}

static int
constant_equal(const void *left_value, const void *right_value, size_t size)
{
    const uint8_t *left = left_value;
    const uint8_t *right = right_value;
    uint8_t difference = 0;
    size_t index;

    for (index = 0; index < size; index++)
        difference |= left[index] ^ right[index];
    return difference == 0;
}

static int
set_cloexec(int descriptor)
{
    int flags = fcntl(descriptor, F_GETFD);
    return flags >= 0 && fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0
        ? 0 : -1;
}

static int
set_nonblocking(int descriptor)
{
    int flags = fcntl(descriptor, F_GETFL);
    return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0
        ? 0 : -1;
}

static int
make_pipe(int descriptors[2])
{
    if (pipe(descriptors) < 0)
        return -1;
    if (set_cloexec(descriptors[0]) < 0 || set_cloexec(descriptors[1]) < 0) {
        close(descriptors[0]);
        close(descriptors[1]);
        descriptors[0] = descriptors[1] = -1;
        return -1;
    }
    return 0;
}

static uint64_t
monotonic_ms(void)
{
    static mach_timebase_info_data_t timebase;
    uint64_t absolute;
    __uint128_t nanos;

    if (timebase.denom == 0 && mach_timebase_info(&timebase) != KERN_SUCCESS)
        return 0;
    absolute = mach_continuous_time();
    nanos = (__uint128_t)absolute * timebase.numer / timebase.denom;
    return (uint64_t)(nanos / 1000000U);
}

static int
sha256_fd(int descriptor, uint8_t output[PLAMEN_BROKER_V2_SHA256_SIZE])
{
    CC_SHA256_CTX context;
    struct stat before, after;
    uint8_t buffer[65536];
    off_t offset = 0;

    if (fstat(descriptor, &before) < 0 || !S_ISREG(before.st_mode)
        || before.st_size < 0 || CC_SHA256_Init(&context) != 1)
        return -1;
    while (offset < before.st_size) {
        size_t wanted = sizeof(buffer);
        ssize_t amount;
        if ((off_t)wanted > before.st_size - offset)
            wanted = (size_t)(before.st_size - offset);
        do {
            amount = pread(descriptor, buffer, wanted, offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0 || CC_SHA256_Update(&context, buffer,
                (CC_LONG)amount) != 1)
            return -1;
        offset += amount;
    }
    if (fstat(descriptor, &after) < 0 || !same_vnode(&before, &after)
        || before.st_size != after.st_size
        || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
        || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
        || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec
        || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec
        || CC_SHA256_Final(output, &context) != 1)
        return -1;
    return 0;
}

static int
copy_cf_string(CFTypeRef value, char output[PLAMEN_BROKER_V2_SIGNING_TEXT_MAX])
{
    if (value == NULL) {
        output[0] = '\0';
        return 0;
    }
    if (CFGetTypeID(value) != CFStringGetTypeID()
        || !CFStringGetCString((CFStringRef)value, output,
            PLAMEN_BROKER_V2_SIGNING_TEXT_MAX, kCFStringEncodingUTF8))
        return -1;
    return 0;
}

static int
signing_identity_from_info(CFDictionaryRef information,
    struct signing_identity *identity)
{
    CFTypeRef unique;
    CFIndex unique_size;

    memset(identity, 0, sizeof(*identity));
    if (information == NULL
        || CFGetTypeID(information) != CFDictionaryGetTypeID()
        || copy_cf_string(CFDictionaryGetValue(information,
                kSecCodeInfoIdentifier), identity->identifier) < 0
        || copy_cf_string(CFDictionaryGetValue(information,
                kSecCodeInfoTeamIdentifier), identity->team) < 0)
        return -1;
    unique = CFDictionaryGetValue(information, kSecCodeInfoUnique);
    if (unique == NULL || CFGetTypeID(unique) != CFDataGetTypeID())
        return -1;
    unique_size = CFDataGetLength((CFDataRef)unique);
    if (unique_size <= 0
        || unique_size > (CFIndex)PLAMEN_BROKER_V2_SHA256_SIZE)
        return -1;
    CFDataGetBytes((CFDataRef)unique, CFRangeMake(0, unique_size),
        identity->cdhash);
    identity->cdhash_size = (uint32_t)unique_size;
    return 0;
}

static int
copy_dynamic_signing_identity(pid_t child, struct signing_identity *identity)
{
    CFNumberRef pid_number = NULL;
    CFDictionaryRef attributes = NULL;
    CFDictionaryRef information = NULL;
    SecCodeRef guest = NULL;
    const void *keys[1] = { kSecGuestAttributePid };
    const void *values[1];
    int32_t exact_pid = child;
    OSStatus status;
    int result = -1;

    pid_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type,
        &exact_pid);
    if (pid_number == NULL)
        goto done;
    values[0] = pid_number;
    attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (attributes == NULL)
        goto done;
    status = SecCodeCopyGuestWithAttributes(NULL, attributes,
        kSecCSDefaultFlags, &guest);
    if (status != errSecSuccess || guest == NULL)
        goto done;
    status = SecCodeCheckValidity(guest, kSecCSStrictValidate, NULL);
    if (status != errSecSuccess)
        goto done;
    status = SecCodeCopySigningInformation(guest,
        kSecCSSigningInformation, &information);
    if (status != errSecSuccess
        || signing_identity_from_info(information, identity) < 0)
        goto done;
    result = 0;
done:
    if (information != NULL)
        CFRelease(information);
    if (guest != NULL)
        CFRelease(guest);
    if (attributes != NULL)
        CFRelease(attributes);
    if (pid_number != NULL)
        CFRelease(pid_number);
    return result;
}

static int
copy_static_signing_identity(const char *path,
    struct signing_identity *identity)
{
    CFURLRef url = NULL;
    CFDictionaryRef information = NULL;
    SecStaticCodeRef code = NULL;
    OSStatus status;
    int result = -1;

    url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
        (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (url == NULL)
        goto done;
    status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    if (status != errSecSuccess || code == NULL)
        goto done;
    /* A path-based SecStaticCodeRef is only authoritative while that exact
     * object remains named at the path.  Validate every Mach-O slice and
     * reject code bundles whose validation would traverse symlinks; the
     * caller reopens and vnode-compares the path after this observation. */
    status = SecStaticCodeCheckValidity(code,
        kSecCSStrictValidate | kSecCSCheckAllArchitectures
            | kSecCSRestrictSymlinks,
        NULL);
    if (status != errSecSuccess)
        goto done;
    status = SecCodeCopySigningInformation(code,
        kSecCSSigningInformation, &information);
    if (status != errSecSuccess
        || signing_identity_from_info(information, identity) < 0)
        goto done;
    result = 0;
done:
    if (information != NULL)
        CFRelease(information);
    if (code != NULL)
        CFRelease(code);
    if (url != NULL)
        CFRelease(url);
    return result;
}

static int
process_birth_us(pid_t child, uint64_t *birth)
{
    struct proc_bsdinfo information;
    int amount;

    memset(&information, 0, sizeof(information));
    amount = proc_pidinfo(child, PROC_PIDTBSDINFO, 0, &information,
        (int)sizeof(information));
    if (amount != (int)sizeof(information)
        || information.pbi_pid != (uint32_t)child)
        return -1;
    *birth = (uint64_t)information.pbi_start_tvsec * 1000000U
        + information.pbi_start_tvusec;
    return *birth == 0 ? -1 : 0;
}

static int
process_birth_matches(pid_t child, uint64_t birth)
{
    uint64_t observed = 0;
    return process_birth_us(child, &observed) == 0 && observed == birth
        ? 0 : -1;
}

static int
fd_aliases(int left, int right)
{
    struct stat left_info, right_info;
    if (left < 0 || right < 0)
        return 0;
    if (left == right)
        return 1;
    if (fstat(left, &left_info) < 0 || fstat(right, &right_info) < 0)
        return 1;
    return left_info.st_dev == right_info.st_dev
        && left_info.st_ino == right_info.st_ino
        && (left_info.st_mode & S_IFMT) == (right_info.st_mode & S_IFMT);
}

#if defined(PLAMEN_BROKER_V2_TEST_ONLY)
static int
validate_request(const struct plamen_broker_v2_test_request *request)
{
    struct stat executable, cwd, input, pass;
    int access_mode;
    size_t index;

    if (request == NULL || request->version != 1
        || request->executable_fd < 0 || request->executable_path == NULL
        || request->executable_path[0] != '/'
        || request->argv == NULL || request->argc == 0
        || request->argc > PLAMEN_BROKER_V2_PROCESS_ARGC_MAX
        || request->argv[request->argc] != NULL
        || request->cwd_fd < 0 || request->stdin_fd < 0
        || request->timeout_ms == 0
        || request->stdout_retain_limit > PLAMEN_BROKER_V2_RETAIN_MAX
        || request->stderr_retain_limit > PLAMEN_BROKER_V2_RETAIN_MAX
        || request->expected_executable_sha256 == NULL
        || request->expected_signing_identifier == NULL
        || request->expected_team_identifier == NULL)
        return -1;
    if (strlen(request->executable_path) >= PATH_MAX
        || strcmp(request->argv[0], request->executable_path) != 0)
        return -1;
    for (index = 0; index < request->argc; index++) {
        if (request->argv[index] == NULL
            || strnlen(request->argv[index],
                PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX + 1)
                > PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX)
            return -1;
    }
    access_mode = fcntl(request->executable_fd, F_GETFL);
    if (access_mode < 0 || (access_mode & O_ACCMODE) != O_RDONLY
        || fstat(request->executable_fd, &executable) < 0
        || !S_ISREG(executable.st_mode) || executable.st_nlink == 0
        || fstat(request->cwd_fd, &cwd) < 0 || !S_ISDIR(cwd.st_mode)
        || fstat(request->stdin_fd, &input) < 0)
        return -1;
    if (request->pass_fd >= 0) {
        if (request->pass_target < 3 || request->pass_target > 1023
            || request->pass_target == request->test_gate_fd
            || request->pass_target == request->cancel_fd
            || fstat(request->pass_fd, &pass) < 0)
            return -1;
    } else if (request->pass_target != -1) {
        return -1;
    }
    if (fd_aliases(request->executable_fd, request->cwd_fd)
        || fd_aliases(request->executable_fd, request->stdin_fd)
        || fd_aliases(request->cwd_fd, request->stdin_fd)
        || fd_aliases(request->pass_fd, request->executable_fd)
        || fd_aliases(request->pass_fd, request->cwd_fd)
        || fd_aliases(request->pass_fd, request->stdin_fd)
        || fd_aliases(request->pass_fd, request->cancel_fd)
        || fd_aliases(request->pass_fd, request->test_gate_fd)
        || fd_aliases(request->cancel_fd, request->test_gate_fd))
        return -1;
    return 0;
}
#endif

static int
admit_path_before_spawn(const struct plamen_broker_v2_test_request *request,
    struct stat *retained_identity)
{
    struct stat path_identity;
    uint8_t digest[PLAMEN_BROKER_V2_SHA256_SIZE];
    char retained_path[PATH_MAX];
    int path_fd = -1;
    int result = -1;

    if (fstat(request->executable_fd, retained_identity) < 0
        || fcntl(request->executable_fd, F_GETPATH, retained_path) < 0
        || strcmp(retained_path, request->executable_path) != 0
        || sha256_fd(request->executable_fd, digest) < 0
        || !constant_equal(digest, request->expected_executable_sha256,
            sizeof(digest)))
        goto done;
    path_fd = open(request->executable_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (path_fd < 0 || fstat(path_fd, &path_identity) < 0
        || !same_vnode(retained_identity, &path_identity)
        || sha256_fd(path_fd, digest) < 0
        || !constant_equal(digest, request->expected_executable_sha256,
            sizeof(digest)))
        goto done;
    result = 0;
done:
    if (path_fd >= 0)
        close(path_fd);
    return result;
}

#if defined(PLAMEN_BROKER_V2_TEST_ONLY)
static int
wait_test_gate(int descriptor)
{
    uint8_t ready = 0x5a;
    uint8_t byte;
    ssize_t amount;

    if (descriptor < 0)
        return 0;
    do {
        amount = write(descriptor, &ready, 1);
    } while (amount < 0 && errno == EINTR);
    if (amount != 1)
        return -1;
    do {
        amount = read(descriptor, &byte, 1);
    } while (amount < 0 && errno == EINTR);
    return amount == 1 && byte == 0xa5 ? 0 : -1;
}
#endif

static int
authenticate_suspended_image(pid_t child, uint64_t birth,
    const struct plamen_broker_v2_test_request *request,
    const struct stat *retained_identity, struct signing_identity *dynamic_identity)
{
    struct signing_identity static_identity;
    struct stat path_identity, retained_after;
    uint8_t path_digest[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t retained_digest[PLAMEN_BROKER_V2_SHA256_SIZE];
    char process_path[PROC_PIDPATHINFO_MAXSIZE];
    int path_fd = -1, path_after_fd = -1;
    int amount;
    int result = -1;

    memset(&static_identity, 0, sizeof(static_identity));
    memset(process_path, 0, sizeof(process_path));
    if (process_birth_matches(child, birth) < 0 || getpgid(child) != child)
        goto done;
    amount = proc_pidpath(child, process_path, sizeof(process_path));
    if (amount <= 0 || (size_t)amount >= sizeof(process_path)
        || strcmp(process_path, request->executable_path) != 0)
        goto done;
    path_fd = open(process_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (path_fd < 0 || fstat(path_fd, &path_identity) < 0
        || fstat(request->executable_fd, &retained_after) < 0
        || !same_vnode(retained_identity, &retained_after)
        || !same_vnode(retained_identity, &path_identity)
        || sha256_fd(path_fd, path_digest) < 0
        || sha256_fd(request->executable_fd, retained_digest) < 0
        || !constant_equal(path_digest, request->expected_executable_sha256,
            sizeof(path_digest))
        || !constant_equal(retained_digest,
            request->expected_executable_sha256, sizeof(retained_digest))
        || copy_dynamic_signing_identity(child, dynamic_identity) < 0
        || copy_static_signing_identity(process_path, &static_identity) < 0
        /* Security.framework observes a pathname, not our retained fd.
         * Reopen after the observation to close the rename/swap window and
         * prove Security validated the still-retained immutable object. */
        || (path_after_fd = open(process_path,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || fstat(path_after_fd, &path_identity) < 0
        || !same_vnode(retained_identity, &path_identity)
        || sha256_fd(path_after_fd, path_digest) < 0
        || !constant_equal(path_digest, request->expected_executable_sha256,
            sizeof(path_digest))
        || dynamic_identity->cdhash_size != static_identity.cdhash_size
        || !constant_equal(dynamic_identity->cdhash, static_identity.cdhash,
            dynamic_identity->cdhash_size)
        || strcmp(dynamic_identity->identifier, static_identity.identifier) != 0
        || strcmp(dynamic_identity->team, static_identity.team) != 0
        || strcmp(dynamic_identity->identifier,
            request->expected_signing_identifier) != 0
        || strcmp(dynamic_identity->team,
            request->expected_team_identifier) != 0
        || process_birth_matches(child, birth) < 0)
        goto done;
    result = 0;
done:
    if (path_after_fd >= 0)
        close(path_after_fd);
    if (path_fd >= 0)
        close(path_fd);
    return result;
}

static int
capture_init(struct stream_capture *capture, uint32_t retain_limit,
    uint64_t observed_limit)
{
    memset(capture, 0, sizeof(*capture));
    capture->retained_limit = retain_limit;
    capture->observed_limit = observed_limit;
    if (CC_SHA256_Init(&capture->digest) != 1)
        return -1;
    if (retain_limit != 0) {
        capture->retained = malloc(retain_limit);
        if (capture->retained == NULL)
            return -1;
    }
    return 0;
}

static void
capture_dispose(struct stream_capture *capture)
{
    free(capture->retained);
    memset(capture, 0, sizeof(*capture));
}

static int
capture_one_read(int descriptor, struct stream_capture *capture, int *eof,
    int record)
{
    uint8_t buffer[65536];
    ssize_t amount;
    size_t retained;

    do {
        amount = read(descriptor, buffer, sizeof(buffer));
    } while (amount < 0 && errno == EINTR);
    if (amount == 0) {
        *eof = 1;
        return 0;
    }
    if (amount < 0)
        return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
    if (!record)
        return 0;
    if ((uint64_t)amount > UINT64_MAX - capture->observed)
        return -1;
    capture->observed += (uint64_t)amount;
    if (CC_SHA256_Update(&capture->digest, buffer, (CC_LONG)amount) != 1)
        return -1;
    retained = (size_t)amount;
    if (retained > capture->retained_limit - capture->retained_size)
        retained = capture->retained_limit - capture->retained_size;
    if (retained != 0) {
        memcpy(capture->retained + capture->retained_size, buffer, retained);
        capture->retained_size += retained;
    }
    if (retained < (size_t)amount)
        capture->truncated = 1;
    if (capture->observed > capture->observed_limit) {
        capture->overflow = 1;
        capture->observed = capture->observed_limit + 1U;
    }
    return 0;
}

static int
capture_ready(int descriptor, struct stream_capture *capture, int *eof,
    int record)
{
    unsigned int round;
    for (round = 0; round < 256 && !*eof; round++) {
        uint64_t before = capture->observed;
        if (capture_one_read(descriptor, capture, eof, record) < 0)
            return -1;
        if (*eof || capture->overflow || capture->observed == before)
            break;
    }
    return 0;
}

static int
kill_group(pid_t child)
{
    if (child <= 0)
        return 0;
    if (kill(-child, SIGKILL) == 0 || errno == ESRCH)
        return 0;
    if (kill(child, SIGKILL) == 0 || errno == ESRCH)
        return 0;
    return -1;
}

static int
group_extinct(pid_t child, uint64_t original_birth)
{
    unsigned int round;
    struct timespec delay = { 0, 5000000 };

    for (round = 0; round < 200; round++) {
        if (kill(-child, 0) < 0 && errno == ESRCH)
            return 1;
        /* Never signal a newly recycled process-group leader. */
        if (original_birth != 0) {
            uint64_t current_birth = 0;
            if (process_birth_us(child, &current_birth) == 0
                && current_birth != original_birth)
                return 1;
        }
        (void)kill(-child, SIGKILL);
        nanosleep(&delay, NULL);
    }
    return 0;
}

static void
close_if_open(int *descriptor)
{
    if (*descriptor >= 0)
        close(*descriptor);
    *descriptor = -1;
}

#if defined(PLAMEN_BROKER_V2_TEST_ONLY)
static int
spawn_suspended(const struct plamen_broker_v2_test_request *request,
    int stdout_pipe[2], int stderr_pipe[2], pid_t *child)
{
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    sigset_t empty, defaults;
    short flags = POSIX_SPAWN_START_SUSPENDED
        | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP
        | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
    char *const closed_environment[] = { NULL };
    int actions_ready = 0;
    int attributes_ready = 0;
    int spawn_status = -1;

    if (posix_spawn_file_actions_init(&actions) != 0)
        goto done;
    actions_ready = 1;
    if (posix_spawnattr_init(&attributes) != 0)
        goto done;
    attributes_ready = 1;
    sigemptyset(&empty);
    sigfillset(&defaults);
    sigdelset(&defaults, SIGKILL);
    sigdelset(&defaults, SIGSTOP);
    if (posix_spawnattr_setflags(&attributes, flags) != 0
        || posix_spawnattr_setpgroup(&attributes, 0) != 0
        || posix_spawnattr_setsigmask(&attributes, &empty) != 0
        || posix_spawnattr_setsigdefault(&attributes, &defaults) != 0
        || posix_spawn_file_actions_addfchdir_np(&actions,
            request->cwd_fd) != 0
        || posix_spawn_file_actions_adddup2(&actions, request->stdin_fd,
            STDIN_FILENO) != 0
        || posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1],
            STDOUT_FILENO) != 0
        || posix_spawn_file_actions_adddup2(&actions, stderr_pipe[1],
            STDERR_FILENO) != 0)
        goto done;
    if (request->pass_fd >= 0
        && posix_spawn_file_actions_adddup2(&actions, request->pass_fd,
            request->pass_target) != 0)
        goto done;
    spawn_status = posix_spawn(child, request->executable_path, &actions,
        &attributes, (char *const *)request->argv, closed_environment);
done:
    if (attributes_ready)
        posix_spawnattr_destroy(&attributes);
    if (actions_ready)
        posix_spawn_file_actions_destroy(&actions);
    return spawn_status == 0 ? 0 : -1;
}
#endif

static int
register_process_events(int queue, pid_t child, int stdout_fd,
    int stderr_fd, int cancel_fd)
{
    struct kevent changes[4];
    int count = 0;

    EV_SET(&changes[count++], (uintptr_t)child, EVFILT_PROC,
        EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    EV_SET(&changes[count++], (uintptr_t)stdout_fd, EVFILT_READ,
        EV_ADD | EV_CLEAR, 0, 0, NULL);
    EV_SET(&changes[count++], (uintptr_t)stderr_fd, EVFILT_READ,
        EV_ADD | EV_CLEAR, 0, 0, NULL);
    if (cancel_fd >= 0)
        EV_SET(&changes[count++], (uintptr_t)cancel_fd, EVFILT_READ,
            EV_ADD | EV_CLEAR, 0, 0, NULL);
    return kevent(queue, changes, count, NULL, 0, NULL) == 0 ? 0 : -1;
}

static int
run_event_loop(pid_t child, uint64_t birth, int queue, int stdout_fd,
    int stderr_fd, int cancel_fd, uint64_t deadline,
    struct stream_capture *stdout_capture,
    struct stream_capture *stderr_capture, uint32_t *terminal_status,
    int *wait_status)
{
    int stdout_eof = 0, stderr_eof = 0, child_exited = 0;
    int revoked = *terminal_status != PLAMEN_BROKER_V2_PROCESS_OK;
    unsigned int drain_round = 0;

    /* EVFILT_PROC is registered while this exact birth identity is stopped. */
    (void)birth;

    if (deadline == 0)
        return -1;
    if (revoked && kill_group(child) < 0)
        return -1;
    while (!child_exited || !stdout_eof || !stderr_eof) {
        struct kevent events[4];
        struct timespec timeout;
        uint64_t now = monotonic_ms();
        int event_count, index;

        if (!revoked && (stdout_capture->overflow
                || stderr_capture->overflow)) {
            *terminal_status = PLAMEN_BROKER_V2_PROCESS_OVERFLOW;
            revoked = 1;
            if (kill_group(child) < 0)
                return -1;
        }
        if (!revoked && (now == 0 || now >= deadline)) {
            *terminal_status = PLAMEN_BROKER_V2_PROCESS_TIMEOUT;
            revoked = 1;
            if (kill_group(child) < 0)
                return -1;
        }
        if (revoked) {
            timeout.tv_sec = 0;
            timeout.tv_nsec = 10000000;
        } else {
            uint64_t remaining = deadline - now;
            timeout.tv_sec = (time_t)(remaining / 1000U);
            timeout.tv_nsec = (long)((remaining % 1000U) * 1000000U);
        }
        event_count = kevent(queue, NULL, 0, events, 4, &timeout);
        if (event_count < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        for (index = 0; index < event_count; index++) {
            if (events[index].filter == EVFILT_PROC
                && events[index].ident == (uintptr_t)child) {
                child_exited = 1;
                /* Revoke descendants before waiting for inherited pipes. */
                if (kill_group(child) < 0)
                    return -1;
            } else if (events[index].filter == EVFILT_READ
                && events[index].ident == (uintptr_t)stdout_fd) {
                if (capture_ready(stdout_fd, stdout_capture, &stdout_eof,
                        *terminal_status
                            != PLAMEN_BROKER_V2_PROCESS_OVERFLOW) < 0)
                    return -1;
            } else if (events[index].filter == EVFILT_READ
                && events[index].ident == (uintptr_t)stderr_fd) {
                if (capture_ready(stderr_fd, stderr_capture, &stderr_eof,
                        *terminal_status
                            != PLAMEN_BROKER_V2_PROCESS_OVERFLOW) < 0)
                    return -1;
            } else if (cancel_fd >= 0 && events[index].filter == EVFILT_READ
                && events[index].ident == (uintptr_t)cancel_fd && !revoked) {
                *terminal_status = PLAMEN_BROKER_V2_PROCESS_CANCELLED;
                revoked = 1;
                if (kill_group(child) < 0)
                    return -1;
            }
        }
        if (revoked && ++drain_round > PLAMEN_BROKER_V2_DRAIN_ROUNDS)
            return -1;
    }
    {
        pid_t waited;
        do {
            waited = waitpid(child, wait_status, 0);
        } while (waited < 0 && errno == EINTR);
        return waited == child ? 0 : -1;
    }
}

#if defined(PLAMEN_BROKER_V2_TEST_ONLY)
static int
finalize_capture(struct stream_capture *capture, uint8_t digest[32],
    uint8_t **retained, uint32_t *retained_size)
{
    if (CC_SHA256_Final(digest, &capture->digest) != 1)
        return -1;
    *retained = capture->retained;
    capture->retained = NULL;
    *retained_size = (uint32_t)capture->retained_size;
    return 0;
}
#endif

static void
store_u64_be(uint8_t output[8], uint64_t value)
{
    unsigned int index;
    for (index = 0; index < 8; ++index)
        output[7U - index] = (uint8_t)(value >> (index * 8U));
}

static int
hash_executable_identity(const struct stat *identity,
    const uint8_t executable_sha256[PLAMEN_BROKER_V2_SHA256_SIZE],
    uint8_t output[PLAMEN_BROKER_V2_SHA256_SIZE])
{
    static const uint8_t domain[] =
        "PLAMEN-BROKER-V2-EXECUTABLE-IDENTITY\0";
    CC_SHA256_CTX context;
    uint8_t integer[8];

    if (identity == NULL || executable_sha256 == NULL || output == NULL
        || identity->st_size < 0 || CC_SHA256_Init(&context) != 1
        || CC_SHA256_Update(&context, domain, (CC_LONG)sizeof(domain)) != 1)
        return -1;
#define HASH_INTEGER(value) \
    do { \
        store_u64_be(integer, (uint64_t)(value)); \
        if (CC_SHA256_Update(&context, integer, sizeof(integer)) != 1) \
            return -1; \
    } while (0)
    HASH_INTEGER(identity->st_dev);
    HASH_INTEGER(identity->st_ino);
    HASH_INTEGER(identity->st_mode);
    HASH_INTEGER(identity->st_uid);
    HASH_INTEGER(identity->st_gid);
    HASH_INTEGER(identity->st_size);
#undef HASH_INTEGER
    if (CC_SHA256_Update(&context, executable_sha256,
            PLAMEN_BROKER_V2_SHA256_SIZE) != 1
        || CC_SHA256_Final(output, &context) != 1)
        return -1;
    return 0;
}

static int
hash_native_process_handle(pid_t child, uint64_t birth,
    const uint8_t executable_identity_sha256[PLAMEN_BROKER_V2_SHA256_SIZE],
    const struct signing_identity *signing,
    uint8_t output[PLAMEN_BROKER_V2_SHA256_SIZE])
{
    static const uint8_t domain[] =
        "PLAMEN-BROKER-V2-DARWIN-PROCESS-HANDLE\0";
    CC_SHA256_CTX context;
    uint8_t integer[8];

    if (child <= 0 || birth == 0 || executable_identity_sha256 == NULL
        || signing == NULL || output == NULL
        || signing->cdhash_size == 0
        || signing->cdhash_size > PLAMEN_BROKER_V2_SHA256_SIZE
        || CC_SHA256_Init(&context) != 1
        || CC_SHA256_Update(&context, domain, (CC_LONG)sizeof(domain)) != 1)
        return -1;
    store_u64_be(integer, (uint64_t)child);
    if (CC_SHA256_Update(&context, integer, sizeof(integer)) != 1)
        return -1;
    store_u64_be(integer, birth);
    if (CC_SHA256_Update(&context, integer, sizeof(integer)) != 1
        || CC_SHA256_Update(&context, executable_identity_sha256,
            PLAMEN_BROKER_V2_SHA256_SIZE) != 1
        || CC_SHA256_Update(&context, signing->cdhash,
            signing->cdhash_size) != 1
        || CC_SHA256_Update(&context, signing->identifier,
            (CC_LONG)(strlen(signing->identifier) + 1U)) != 1
        || CC_SHA256_Update(&context, signing->team,
            (CC_LONG)(strlen(signing->team) + 1U)) != 1
        || CC_SHA256_Final(output, &context) != 1)
        return -1;
    return 0;
}

static int
duplicate_cloexec(int descriptor)
{
    /*
     * Mapped child targets are confined below this boundary.  Retaining every
     * authority descriptor above it prevents ordered posix_spawn dup2 actions
     * from overwriting a source that a later action still needs.
     */
    return fcntl(descriptor, F_DUPFD_CLOEXEC,
        PLAMEN_BROKER_V2_RETAINED_FD_MIN);
}

static char *
copy_bounded_string(const char *source, size_t maximum)
{
    size_t size;
    char *copy;

    if (source == NULL)
        return NULL;
    size = strnlen(source, maximum + 1U);
    if (size > maximum)
        return NULL;
    copy = malloc(size + 1U);
    if (copy != NULL)
        memcpy(copy, source, size + 1U);
    return copy;
}

static void
dispose_string_vector(char ***vector_pointer, size_t count)
{
    char **vector;
    size_t index;

    if (vector_pointer == NULL || *vector_pointer == NULL)
        return;
    vector = *vector_pointer;
    for (index = 0; index < count; ++index) {
        if (vector[index] != NULL) {
            memset(vector[index], 0, strlen(vector[index]));
            free(vector[index]);
        }
    }
    free(vector);
    *vector_pointer = NULL;
}

static int
environment_name_size(const char *value, size_t *name_size)
{
    const char *separator;
    size_t size;
    size_t index;

    if (value == NULL || name_size == NULL
        || strnlen(value, PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX + 1U)
            > PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX)
        return -1;
    separator = strchr(value, '=');
    if (separator == NULL || separator == value)
        return -1;
    size = (size_t)(separator - value);
    if (!((value[0] >= 'A' && value[0] <= 'Z')
            || (value[0] >= 'a' && value[0] <= 'z')
            || value[0] == '_'))
        return -1;
    for (index = 1; index < size; ++index) {
        if (!((value[index] >= 'A' && value[index] <= 'Z')
                || (value[index] >= 'a' && value[index] <= 'z')
                || (value[index] >= '0' && value[index] <= '9')
                || value[index] == '_'))
            return -1;
    }
    *name_size = size;
    return 0;
}

static int
validate_production_spec(const struct plamen_broker_v2_process_spec *spec)
{
    struct stat executable, cwd, input, mapped;
    struct rlimit descriptor_limit;
    size_t index, prior;
    int flags;

    if (spec == NULL || spec->version != 1 || spec->executable_fd < 0
        || spec->executable_path == NULL || spec->executable_path[0] != '/'
        || strnlen(spec->executable_path, PATH_MAX) >= PATH_MAX
        || spec->argv == NULL || spec->argc == 0
        || spec->argc > PLAMEN_BROKER_V2_PROCESS_ARGC_MAX
        || spec->argv[spec->argc] != NULL
        || strcmp(spec->argv[0], spec->executable_path) != 0
        || spec->cwd_fd < 0 || spec->stdin_fd < 0
        || spec->fd_map_count > PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX
        || (spec->fd_map_count != 0 && spec->fd_maps == NULL)
        || spec->timeout_seconds == 0
        || spec->timeout_seconds
            > PLAMEN_BROKER_V2_PROCESS_TIMEOUT_SECONDS_MAX
        || spec->stdout_spool_limit == 0
        || spec->stdout_spool_limit > PLAMEN_BROKER_V2_OBSERVED_MAX
        || spec->stderr_spool_limit == 0
        || spec->stderr_spool_limit > PLAMEN_BROKER_V2_OBSERVED_MAX
        || spec->expected_executable_sha256 == NULL
        || spec->expected_signing_identifier == NULL
        || spec->expected_team_identifier == NULL
        || spec->expected_signing_identifier[0] == '\0'
        || strnlen(spec->expected_signing_identifier,
            PLAMEN_BROKER_V2_SIGNING_TEXT_MAX)
            >= PLAMEN_BROKER_V2_SIGNING_TEXT_MAX
        || strnlen(spec->expected_team_identifier,
            PLAMEN_BROKER_V2_SIGNING_TEXT_MAX)
            >= PLAMEN_BROKER_V2_SIGNING_TEXT_MAX)
        return -1;
    if (getrlimit(RLIMIT_NOFILE, &descriptor_limit) != 0
        || (descriptor_limit.rlim_cur != RLIM_INFINITY
            && descriptor_limit.rlim_cur
                < (rlim_t)(PLAMEN_BROKER_V2_RETAINED_FD_MIN + 3U
                    + spec->fd_map_count)))
        return -1;
    if (spec->environment_policy == PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED) {
        if (spec->environment != NULL || spec->environment_count != 0)
            return -1;
    } else if (spec->environment_policy
            == PLAMEN_BROKER_V2_PROCESS_ENV_EXACT) {
        if (spec->environment == NULL || spec->environment_count == 0
            || spec->environment_count > PLAMEN_BROKER_V2_PROCESS_ENVC_MAX
            || spec->environment[spec->environment_count] != NULL)
            return -1;
    } else {
        return -1;
    }
    for (index = 0; index < spec->argc; ++index) {
        if (spec->argv[index] == NULL
            || strnlen(spec->argv[index],
                PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX + 1U)
                > PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX)
            return -1;
    }
    for (index = 0; index < spec->environment_count; ++index) {
        size_t name_size;
        if (environment_name_size(spec->environment[index], &name_size) != 0)
            return -1;
        for (prior = 0; prior < index; ++prior) {
            size_t prior_name_size;
            if (environment_name_size(spec->environment[prior],
                    &prior_name_size) != 0)
                return -1;
            if (name_size == prior_name_size
                && memcmp(spec->environment[index], spec->environment[prior],
                    name_size) == 0)
                return -1;
        }
    }
    flags = fcntl(spec->executable_fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY
        || fstat(spec->executable_fd, &executable) != 0
        || !S_ISREG(executable.st_mode) || executable.st_nlink == 0
        || fstat(spec->cwd_fd, &cwd) != 0 || !S_ISDIR(cwd.st_mode)
        || fstat(spec->stdin_fd, &input) != 0
        || fd_aliases(spec->executable_fd, spec->cwd_fd)
        || fd_aliases(spec->executable_fd, spec->stdin_fd)
        || fd_aliases(spec->cwd_fd, spec->stdin_fd))
        return -1;
    flags = fcntl(spec->stdin_fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) == O_WRONLY)
        return -1;
    for (index = 0; index < spec->fd_map_count; ++index) {
        if (spec->fd_maps[index].source_fd < 0
            || spec->fd_maps[index].target_fd < 3
            || spec->fd_maps[index].target_fd
                >= PLAMEN_BROKER_V2_RETAINED_FD_MIN
            || (descriptor_limit.rlim_cur != RLIM_INFINITY
                && (rlim_t)spec->fd_maps[index].target_fd
                    >= descriptor_limit.rlim_cur)
            || fstat(spec->fd_maps[index].source_fd, &mapped) != 0
            || fd_aliases(spec->fd_maps[index].source_fd,
                spec->executable_fd)
            || fd_aliases(spec->fd_maps[index].source_fd, spec->cwd_fd)
            || fd_aliases(spec->fd_maps[index].source_fd, spec->stdin_fd))
            return -1;
        for (prior = 0; prior < index; ++prior) {
            if (spec->fd_maps[index].target_fd
                    == spec->fd_maps[prior].target_fd
                || fd_aliases(spec->fd_maps[index].source_fd,
                    spec->fd_maps[prior].source_fd))
                return -1;
        }
    }
    return 0;
}

static void
process_dispose_storage(struct plamen_broker_v2_process *process)
{
    size_t index;

    if (process == NULL)
        return;
    close_if_open(&process->executable_fd);
    close_if_open(&process->cwd_fd);
    close_if_open(&process->stdin_fd);
    close_if_open(&process->queue);
    close_if_open(&process->stdout_pipe[0]);
    close_if_open(&process->stdout_pipe[1]);
    close_if_open(&process->stderr_pipe[0]);
    close_if_open(&process->stderr_pipe[1]);
    for (index = 0; index < process->fd_map_count; ++index)
        close_if_open(&process->fd_maps[index].source_fd);
    dispose_string_vector(&process->argv, process->argc);
    dispose_string_vector(&process->environment, process->environment_count);
    free(process->executable_path);
    process->executable_path = NULL;
    if (process->captures_ready) {
        capture_dispose(&process->stdout_capture);
        capture_dispose(&process->stderr_capture);
        process->captures_ready = 0;
    }
}

static void
make_admission_view(const struct plamen_broker_v2_process *process,
    struct plamen_broker_v2_test_request *view)
{
    memset(view, 0, sizeof(*view));
    view->version = 1;
    view->executable_fd = process->executable_fd;
    view->executable_path = process->executable_path;
    view->argv = (const char *const *)process->argv;
    view->argc = process->argc;
    view->cwd_fd = process->cwd_fd;
    view->stdin_fd = process->stdin_fd;
    view->pass_fd = -1;
    view->pass_target = -1;
    view->cancel_fd = -1;
    view->test_gate_fd = -1;
    view->expected_executable_sha256 = process->expected_executable_sha256;
    view->expected_signing_identifier =
        process->expected_signing_identifier;
    view->expected_team_identifier = process->expected_team_identifier;
}

int
plamen_broker_v2_process_prepare(
    const struct plamen_broker_v2_process_spec *spec,
    struct plamen_broker_v2_process_prepared_identity *identity,
    struct plamen_broker_v2_process **process_out)
{
    struct plamen_broker_v2_process *process = NULL;
    struct plamen_broker_v2_test_request view;
    struct signing_identity static_signing;
    size_t index;
    int result = PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;

    if (identity == NULL || process_out == NULL)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    memset(identity, 0, sizeof(*identity));
    *process_out = NULL;
    if (validate_production_spec(spec) != 0)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    process = calloc(1, sizeof(*process));
    if (process == NULL)
        return PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    process->executable_fd = -1;
    process->cwd_fd = -1;
    process->stdin_fd = -1;
    process->queue = -1;
    process->child = -1;
    process->stdout_pipe[0] = process->stdout_pipe[1] = -1;
    process->stderr_pipe[0] = process->stderr_pipe[1] = -1;
    for (index = 0; index < PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX; ++index)
        process->fd_maps[index].source_fd = -1;
    process->executable_fd = duplicate_cloexec(spec->executable_fd);
    process->cwd_fd = duplicate_cloexec(spec->cwd_fd);
    process->stdin_fd = duplicate_cloexec(spec->stdin_fd);
    process->executable_path = copy_bounded_string(spec->executable_path,
        PATH_MAX - 1U);
    process->argv = calloc(spec->argc + 1U, sizeof(*process->argv));
    if (process->executable_fd < 0 || process->cwd_fd < 0
        || process->stdin_fd < 0 || process->executable_path == NULL
        || process->argv == NULL) {
        result = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
        goto invalid;
    }
    process->argc = spec->argc;
    for (index = 0; index < spec->argc; ++index) {
        process->argv[index] = copy_bounded_string(spec->argv[index],
            PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX);
        if (process->argv[index] == NULL) {
            result = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
            goto invalid;
        }
    }
    if (spec->environment_policy == PLAMEN_BROKER_V2_PROCESS_ENV_EXACT) {
        process->environment = calloc(spec->environment_count + 1U,
            sizeof(*process->environment));
        if (process->environment == NULL) {
            result = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
            goto invalid;
        }
        process->environment_count = spec->environment_count;
        for (index = 0; index < spec->environment_count; ++index) {
            process->environment[index] = copy_bounded_string(
                spec->environment[index],
                PLAMEN_BROKER_V2_PROCESS_ARGUMENT_MAX);
            if (process->environment[index] == NULL) {
                result = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
                goto invalid;
            }
        }
    }
    process->environment_policy = spec->environment_policy;
    process->fd_map_count = spec->fd_map_count;
    for (index = 0; index < spec->fd_map_count; ++index) {
        process->fd_maps[index].source_fd =
            duplicate_cloexec(spec->fd_maps[index].source_fd);
        process->fd_maps[index].target_fd = spec->fd_maps[index].target_fd;
        if (process->fd_maps[index].source_fd < 0) {
            result = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
            goto invalid;
        }
    }
    process->timeout_ms = (uint64_t)spec->timeout_seconds * 1000U;
    process->stdout_spool_limit = spec->stdout_spool_limit;
    process->stderr_spool_limit = spec->stderr_spool_limit;
    memcpy(process->expected_executable_sha256,
        spec->expected_executable_sha256,
        sizeof(process->expected_executable_sha256));
    memcpy(process->expected_signing_identifier,
        spec->expected_signing_identifier,
        strlen(spec->expected_signing_identifier) + 1U);
    memcpy(process->expected_team_identifier, spec->expected_team_identifier,
        strlen(spec->expected_team_identifier) + 1U);
    make_admission_view(process, &view);
    memset(&static_signing, 0, sizeof(static_signing));
    if (admit_path_before_spawn(&view, &process->retained_identity) != 0
        || copy_static_signing_identity(process->executable_path,
            &static_signing) != 0
        || strcmp(static_signing.identifier,
            process->expected_signing_identifier) != 0
        || strcmp(static_signing.team, process->expected_team_identifier) != 0
        || hash_executable_identity(&process->retained_identity,
            process->expected_executable_sha256,
            process->executable_identity_sha256) != 0)
        goto invalid;
    process->state = PROCESS_STATE_PREPARED;
    identity->version = 1;
    identity->executable_device =
        (uint64_t)process->retained_identity.st_dev;
    identity->executable_inode =
        (uint64_t)process->retained_identity.st_ino;
    identity->executable_size =
        (uint64_t)process->retained_identity.st_size;
    memcpy(identity->executable_sha256,
        process->expected_executable_sha256,
        sizeof(identity->executable_sha256));
    memcpy(identity->executable_identity_sha256,
        process->executable_identity_sha256,
        sizeof(identity->executable_identity_sha256));
    *process_out = process;
    return PLAMEN_BROKER_V2_PROCESS_OK;
invalid:
    process_dispose_storage(process);
    memset(process, 0, sizeof(*process));
    free(process);
    return result;
}

static int
spawn_production_suspended(struct plamen_broker_v2_process *process)
{
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    sigset_t empty, defaults;
    short flags = POSIX_SPAWN_START_SUSPENDED
        | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP
        | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
    char *const closed_environment[] = { NULL };
    char *const *environment = process->environment_policy
        == PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED
        ? closed_environment : process->environment;
    size_t index;
    int actions_ready = 0, attributes_ready = 0, spawn_status = -1;

    if (posix_spawn_file_actions_init(&actions) != 0)
        goto done;
    actions_ready = 1;
    if (posix_spawnattr_init(&attributes) != 0)
        goto done;
    attributes_ready = 1;
    sigemptyset(&empty);
    sigfillset(&defaults);
    sigdelset(&defaults, SIGKILL);
    sigdelset(&defaults, SIGSTOP);
    if (posix_spawnattr_setflags(&attributes, flags) != 0
        || posix_spawnattr_setpgroup(&attributes, 0) != 0
        || posix_spawnattr_setsigmask(&attributes, &empty) != 0
        || posix_spawnattr_setsigdefault(&attributes, &defaults) != 0
        || posix_spawn_file_actions_addfchdir_np(&actions,
            process->cwd_fd) != 0
        || posix_spawn_file_actions_adddup2(&actions, process->stdin_fd,
            STDIN_FILENO) != 0
        || posix_spawn_file_actions_adddup2(&actions,
            process->stdout_pipe[1], STDOUT_FILENO) != 0
        || posix_spawn_file_actions_adddup2(&actions,
            process->stderr_pipe[1], STDERR_FILENO) != 0)
        goto done;
    for (index = 0; index < process->fd_map_count; ++index) {
        if (posix_spawn_file_actions_adddup2(&actions,
                process->fd_maps[index].source_fd,
                process->fd_maps[index].target_fd) != 0)
            goto done;
    }
    spawn_status = posix_spawn(&process->child, process->executable_path,
        &actions, &attributes, process->argv, environment);
done:
    if (attributes_ready)
        posix_spawnattr_destroy(&attributes);
    if (actions_ready)
        posix_spawn_file_actions_destroy(&actions);
    return spawn_status == 0 ? 0 : -1;
}

static int
reap_child(pid_t child, int *wait_status)
{
    pid_t waited;
    do {
        waited = waitpid(child, wait_status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child ? 0 : -1;
}

static int
finalize_production_capture(struct plamen_broker_v2_process *process)
{
    if (CC_SHA256_Final(process->terminal.stdout_sha256,
            &process->stdout_capture.digest) != 1
        || CC_SHA256_Final(process->terminal.stderr_sha256,
            &process->stderr_capture.digest) != 1)
        return -1;
    process->terminal.stdout_overflow =
        (uint8_t)process->stdout_capture.overflow;
    process->terminal.stderr_overflow =
        (uint8_t)process->stderr_capture.overflow;
    process->terminal.stdout_size = process->stdout_capture.observed;
    process->terminal.stderr_size = process->stderr_capture.observed;
    return 0;
}

static int
finish_started_process(struct plamen_broker_v2_process *process,
    uint32_t requested_status,
    struct plamen_broker_v2_process_terminal *terminal)
{
    int wait_status = 0;
    uint32_t terminal_status = requested_status;
    int loop_result;

    loop_result = run_event_loop(process->child, process->birth,
        process->queue, process->stdout_pipe[0], process->stderr_pipe[0], -1,
        process->deadline_ms, &process->stdout_capture,
        &process->stderr_capture, &terminal_status, &wait_status);
    if (loop_result != 0) {
        (void)kill_group(process->child);
        if (reap_child(process->child, &wait_status) != 0)
            process->terminal.child_reaped = 0;
        else
            process->terminal.child_reaped = 1;
        terminal_status = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    } else {
        process->terminal.child_reaped = 1;
    }
    close_if_open(&process->queue);
    close_if_open(&process->stdout_pipe[0]);
    close_if_open(&process->stderr_pipe[0]);
    process->terminal.process_group_extinct =
        (uint8_t)group_extinct(process->child, process->birth);
    if (!process->terminal.child_reaped
        || !process->terminal.process_group_extinct)
        terminal_status = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    if (WIFEXITED(wait_status))
        process->terminal.exit_code = WEXITSTATUS(wait_status);
    else if (WIFSIGNALED(wait_status))
        process->terminal.signal_number = WTERMSIG(wait_status);
    if (finalize_production_capture(process) != 0)
        terminal_status = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    {
        uint8_t executable_digest[PLAMEN_BROKER_V2_SHA256_SIZE];
        struct stat after;
        if (fstat(process->executable_fd, &after) != 0
            || !same_vnode(&process->retained_identity, &after)
            || sha256_fd(process->executable_fd, executable_digest) != 0
            || !constant_equal(executable_digest,
                process->expected_executable_sha256,
                sizeof(executable_digest)))
            terminal_status = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    }
    process->terminal.status = terminal_status;
    process->state = PROCESS_STATE_TERMINAL;
    if (terminal != NULL)
        *terminal = process->terminal;
    return (int)terminal_status;
}

static int
fail_started_process(struct plamen_broker_v2_process *process,
    uint32_t status)
{
    int wait_status = 0;

    (void)kill_group(process->child);
    process->terminal.child_reaped =
        (uint8_t)(reap_child(process->child, &wait_status) == 0);
    process->terminal.process_group_extinct =
        (uint8_t)group_extinct(process->child, process->birth);
    close_if_open(&process->queue);
    close_if_open(&process->stdout_pipe[0]);
    close_if_open(&process->stdout_pipe[1]);
    close_if_open(&process->stderr_pipe[0]);
    close_if_open(&process->stderr_pipe[1]);
    if (finalize_production_capture(process) != 0
        || !process->terminal.child_reaped
        || !process->terminal.process_group_extinct)
        status = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    process->terminal.status = status;
    process->state = PROCESS_STATE_TERMINAL;
    return (int)status;
}

int
plamen_broker_v2_process_start(struct plamen_broker_v2_process *process,
    struct plamen_broker_v2_process_start_identity *identity)
{
    struct plamen_broker_v2_test_request view;
    struct stat retained_now;
    uint64_t started;

    if (process == NULL || identity == NULL
        || process->state != PROCESS_STATE_PREPARED)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    memset(identity, 0, sizeof(*identity));
    make_admission_view(process, &view);
    if (fstat(process->executable_fd, &retained_now) != 0
        || !same_vnode(&process->retained_identity, &retained_now)
        || admit_path_before_spawn(&view, &retained_now) != 0)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    if (capture_init(&process->stdout_capture, process->stdout_spool_limit,
            PLAMEN_BROKER_V2_OBSERVED_MAX) != 0
        || capture_init(&process->stderr_capture, process->stderr_spool_limit,
            PLAMEN_BROKER_V2_OBSERVED_MAX) != 0
        || make_pipe(process->stdout_pipe) != 0
        || make_pipe(process->stderr_pipe) != 0
        || set_nonblocking(process->stdout_pipe[0]) != 0
        || set_nonblocking(process->stderr_pipe[0]) != 0) {
        process->captures_ready = 1;
        return PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    }
    process->captures_ready = 1;
    if (spawn_production_suspended(process) != 0)
        return PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    process->terminal.version = 1;
    process->terminal.exit_code = -1;
    process->terminal.child_pid = process->child;
    process->terminal.process_group_id = process->child;
    close_if_open(&process->stdout_pipe[1]);
    close_if_open(&process->stderr_pipe[1]);
    if (process_birth_us(process->child, &process->birth) != 0)
        return fail_started_process(process,
            PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR);
    process->terminal.child_birth_us = process->birth;
    if (authenticate_suspended_image(process->child, process->birth, &view,
            &process->retained_identity, &process->signing) != 0)
        return fail_started_process(process,
            PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED);
    process->queue = kqueue();
    if (process->queue < 0 || set_cloexec(process->queue) != 0
        || register_process_events(process->queue, process->child,
            process->stdout_pipe[0], process->stderr_pipe[0], -1) != 0)
        return fail_started_process(process,
            PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR);
    started = monotonic_ms();
    if (started == 0 || process->timeout_ms > UINT64_MAX - started)
        return fail_started_process(process,
            PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR);
    process->deadline_ms = started + process->timeout_ms;
    if (kill(process->child, SIGCONT) != 0)
        return fail_started_process(process,
            PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR);
    process->state = PROCESS_STATE_RUNNING;
    identity->version = 1;
    identity->child_pid = process->child;
    identity->process_group_id = process->child;
    identity->child_birth_us = process->birth;
    identity->executable_device =
        (uint64_t)process->retained_identity.st_dev;
    identity->executable_inode =
        (uint64_t)process->retained_identity.st_ino;
    memcpy(identity->executable_sha256,
        process->expected_executable_sha256,
        sizeof(identity->executable_sha256));
    memcpy(identity->executable_identity_sha256,
        process->executable_identity_sha256,
        sizeof(identity->executable_identity_sha256));
    memcpy(identity->cdhash, process->signing.cdhash,
        sizeof(identity->cdhash));
    identity->cdhash_size = process->signing.cdhash_size;
    memcpy(identity->signing_identifier, process->signing.identifier,
        sizeof(identity->signing_identifier));
    memcpy(identity->team_identifier, process->signing.team,
        sizeof(identity->team_identifier));
    if (hash_native_process_handle(process->child, process->birth,
            process->executable_identity_sha256, &process->signing,
            identity->native_process_handle_sha256) != 0)
        return plamen_broker_v2_process_extinguish(process, NULL);
    return PLAMEN_BROKER_V2_PROCESS_OK;
}

int
plamen_broker_v2_process_wait(struct plamen_broker_v2_process *process,
    struct plamen_broker_v2_process_terminal *terminal)
{
    if (process == NULL || terminal == NULL)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    if (process->state == PROCESS_STATE_TERMINAL) {
        *terminal = process->terminal;
        return (int)process->terminal.status;
    }
    if (process->state != PROCESS_STATE_RUNNING)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    return finish_started_process(process, PLAMEN_BROKER_V2_PROCESS_OK,
        terminal);
}

int
plamen_broker_v2_process_extinguish(struct plamen_broker_v2_process *process,
    struct plamen_broker_v2_process_terminal *terminal)
{
    if (process == NULL)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    if (process->state == PROCESS_STATE_TERMINAL) {
        if (terminal != NULL)
            *terminal = process->terminal;
        return (int)process->terminal.status;
    }
    if (process->state == PROCESS_STATE_PREPARED) {
        memset(&process->terminal, 0, sizeof(process->terminal));
        process->terminal.version = 1;
        process->terminal.status = PLAMEN_BROKER_V2_PROCESS_CANCELLED;
        process->terminal.exit_code = -1;
        process->terminal.process_group_extinct = 1;
        process->state = PROCESS_STATE_TERMINAL;
        if (terminal != NULL)
            *terminal = process->terminal;
        return PLAMEN_BROKER_V2_PROCESS_CANCELLED;
    }
    if (process->state != PROCESS_STATE_RUNNING)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    return finish_started_process(process,
        PLAMEN_BROKER_V2_PROCESS_CANCELLED, terminal);
}

int
plamen_broker_v2_process_read_output(
    struct plamen_broker_v2_process *process, uint32_t stream,
    uint64_t offset, uint32_t maximum, uint8_t *output,
    uint32_t output_capacity, uint32_t *output_size, uint8_t *eof,
    uint8_t chunk_sha256[PLAMEN_BROKER_V2_SHA256_SIZE],
    uint8_t full_sha256[PLAMEN_BROKER_V2_SHA256_SIZE], uint64_t *full_size)
{
    const struct stream_capture *capture;
    const uint8_t *full_digest;
    size_t amount;

    if (process == NULL || process->state != PROCESS_STATE_TERMINAL
        || process->terminal.status == PLAMEN_BROKER_V2_PROCESS_OVERFLOW
        || process->terminal.status == PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR
        || process->terminal.status
            == PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED
        || maximum == 0 || maximum > 262144U || output == NULL
        || output_capacity < maximum || output_size == NULL || eof == NULL
        || chunk_sha256 == NULL || full_sha256 == NULL || full_size == NULL)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    if (stream == PLAMEN_BROKER_V2_PROCESS_STREAM_STDOUT) {
        capture = &process->stdout_capture;
        full_digest = process->terminal.stdout_sha256;
        *full_size = process->terminal.stdout_size;
    } else if (stream == PLAMEN_BROKER_V2_PROCESS_STREAM_STDERR) {
        capture = &process->stderr_capture;
        full_digest = process->terminal.stderr_sha256;
        *full_size = process->terminal.stderr_size;
    } else {
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    }
    if (capture->overflow || offset > capture->retained_size)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    amount = capture->retained_size - (size_t)offset;
    if (amount > maximum)
        amount = maximum;
    if (amount != 0)
        memcpy(output, capture->retained + (size_t)offset, amount);
    if (CC_SHA256(output, (CC_LONG)amount, chunk_sha256) == NULL)
        return PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    memcpy(full_sha256, full_digest, PLAMEN_BROKER_V2_SHA256_SIZE);
    *output_size = (uint32_t)amount;
    *eof = (uint8_t)((size_t)offset + amount == capture->retained_size);
    return PLAMEN_BROKER_V2_PROCESS_OK;
}

int
plamen_broker_v2_process_close(struct plamen_broker_v2_process *process)
{
    if (process == NULL)
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    if (process->state == PROCESS_STATE_RUNNING
        || (process->child > 0 && process->state == PROCESS_STATE_TERMINAL
            && (!process->terminal.child_reaped
                || !process->terminal.process_group_extinct)))
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    process_dispose_storage(process);
    memset(process, 0, sizeof(*process));
    free(process);
    return PLAMEN_BROKER_V2_PROCESS_OK;
}

#if defined(PLAMEN_BROKER_V2_TEST_ONLY)
int
plamen_broker_v2_test_spawn_wait(
    const struct plamen_broker_v2_test_request *request,
    struct plamen_broker_v2_test_result *result)
{
    struct stream_capture stdout_capture, stderr_capture;
    struct signing_identity signing;
    struct stat retained_identity;
    uint8_t executable_digest[PLAMEN_BROKER_V2_SHA256_SIZE];
    int stdout_pipe[2] = { -1, -1 };
    int stderr_pipe[2] = { -1, -1 };
    int queue = -1;
    pid_t child = -1;
    uint64_t birth = 0;
    int wait_status = 0;
    uint32_t terminal_status = PLAMEN_BROKER_V2_PROCESS_OK;
    int child_reaped = 0;
    int result_code = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;

    memset(&stdout_capture, 0, sizeof(stdout_capture));
    memset(&stderr_capture, 0, sizeof(stderr_capture));
    memset(&signing, 0, sizeof(signing));
    if (result == NULL)
        return PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    memset(result, 0, sizeof(*result));
    result->version = 1;
    result->exit_code = -1;
    if (validate_request(request) < 0
        || admit_path_before_spawn(request, &retained_identity) < 0) {
        result->status = PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
        return PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
    }
    if (capture_init(&stdout_capture, request->stdout_retain_limit,
            PLAMEN_BROKER_V2_OBSERVED_MAX) < 0
        || capture_init(&stderr_capture, request->stderr_retain_limit,
            PLAMEN_BROKER_V2_OBSERVED_MAX) < 0
        || make_pipe(stdout_pipe) < 0 || make_pipe(stderr_pipe) < 0
        || set_nonblocking(stdout_pipe[0]) < 0
        || set_nonblocking(stderr_pipe[0]) < 0
        || wait_test_gate(request->test_gate_fd) < 0)
        goto done;
    if (spawn_suspended(request, stdout_pipe, stderr_pipe, &child) < 0)
        goto done;
    result->child_pid = child;
    close_if_open(&stdout_pipe[1]);
    close_if_open(&stderr_pipe[1]);
    /* From this point every BaseException-equivalent C failure kills and reaps. */
    if (process_birth_us(child, &birth) < 0)
        goto child_failure;
    result->child_birth_us = birth;
    if (authenticate_suspended_image(child, birth, request,
            &retained_identity, &signing) < 0) {
        terminal_status = PLAMEN_BROKER_V2_PROCESS_ADMISSION_REJECTED;
        goto child_failure;
    }
    queue = kqueue();
    if (queue < 0 || set_cloexec(queue) < 0
        || register_process_events(queue, child, stdout_pipe[0],
            stderr_pipe[0], request->cancel_fd) < 0)
        goto child_failure;
    if (kill(child, SIGCONT) < 0)
        goto child_failure;
    {
        uint64_t started = monotonic_ms();
        uint64_t deadline = started == 0
            || request->timeout_ms > UINT64_MAX - started
            ? 0 : started + request->timeout_ms;
        if (run_event_loop(child, birth, queue, stdout_pipe[0],
                stderr_pipe[0], request->cancel_fd, deadline,
                &stdout_capture, &stderr_capture, &terminal_status,
                &wait_status) < 0)
            goto child_failure;
    }
    child_reaped = 1;
    result->child_reaped = 1;
    result->process_group_extinct = (uint8_t)group_extinct(child, birth);
    if (!result->process_group_extinct
        && terminal_status == PLAMEN_BROKER_V2_PROCESS_OK)
        terminal_status = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    if (WIFEXITED(wait_status))
        result->exit_code = WEXITSTATUS(wait_status);
    else if (WIFSIGNALED(wait_status))
        result->signal_number = WTERMSIG(wait_status);
    if (sha256_fd(request->executable_fd, executable_digest) < 0
        || !constant_equal(executable_digest,
            request->expected_executable_sha256, sizeof(executable_digest))) {
        terminal_status = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
        goto done;
    }
    memcpy(result->executable_sha256, executable_digest,
        sizeof(executable_digest));
    memcpy(result->cdhash, signing.cdhash, sizeof(signing.cdhash));
    result->cdhash_size = signing.cdhash_size;
    memcpy(result->signing_identifier, signing.identifier,
        sizeof(result->signing_identifier));
    memcpy(result->team_identifier, signing.team,
        sizeof(result->team_identifier));
    result->stdout_observed = stdout_capture.observed;
    result->stderr_observed = stderr_capture.observed;
    result->stdout_truncated = (uint8_t)stdout_capture.truncated;
    result->stderr_truncated = (uint8_t)stderr_capture.truncated;
    if (finalize_capture(&stdout_capture, result->stdout_sha256,
            &result->stdout_bytes, &result->stdout_retained) < 0
        || finalize_capture(&stderr_capture, result->stderr_sha256,
            &result->stderr_bytes, &result->stderr_retained) < 0)
        goto done;
    result->status = terminal_status;
    result_code = (int)terminal_status;
    goto done;

child_failure:
    (void)kill_group(child);
    if (!child_reaped) {
        pid_t waited;
        do {
            waited = waitpid(child, &wait_status, 0);
        } while (waited < 0 && errno == EINTR);
        child_reaped = waited == child;
    }
    result->child_reaped = (uint8_t)child_reaped;
    result->process_group_extinct = (uint8_t)group_extinct(child, birth);
    result->status = terminal_status == PLAMEN_BROKER_V2_PROCESS_OK
        ? PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR : terminal_status;
    result_code = (int)result->status;
done:
    close_if_open(&queue);
    close_if_open(&stdout_pipe[0]);
    close_if_open(&stdout_pipe[1]);
    close_if_open(&stderr_pipe[0]);
    close_if_open(&stderr_pipe[1]);
    capture_dispose(&stdout_capture);
    capture_dispose(&stderr_capture);
    if (result_code == PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR)
        result->status = PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    return result_code;
}

#else

int
plamen_broker_v2_test_spawn_wait(
    const struct plamen_broker_v2_test_request *request,
    struct plamen_broker_v2_test_result *result)
{
    (void)request;
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
        result->version = 1;
        result->status = PLAMEN_BROKER_V2_PROCESS_PRODUCTION_UNAVAILABLE;
        result->exit_code = -1;
    }
    return PLAMEN_BROKER_V2_PROCESS_PRODUCTION_UNAVAILABLE;
}

#endif

#else

int
plamen_broker_v2_process_prepare(
    const struct plamen_broker_v2_process_spec *spec,
    struct plamen_broker_v2_process_prepared_identity *identity,
    struct plamen_broker_v2_process **process)
{
    (void)spec;
    if (identity != NULL)
        memset(identity, 0, sizeof(*identity));
    if (process != NULL)
        *process = NULL;
    return PLAMEN_BROKER_V2_PROCESS_PRODUCTION_UNAVAILABLE;
}

int
plamen_broker_v2_process_start(struct plamen_broker_v2_process *process,
    struct plamen_broker_v2_process_start_identity *identity)
{
    (void)process;
    if (identity != NULL)
        memset(identity, 0, sizeof(*identity));
    return PLAMEN_BROKER_V2_PROCESS_PRODUCTION_UNAVAILABLE;
}

int
plamen_broker_v2_process_wait(struct plamen_broker_v2_process *process,
    struct plamen_broker_v2_process_terminal *terminal)
{
    (void)process;
    if (terminal != NULL)
        memset(terminal, 0, sizeof(*terminal));
    return PLAMEN_BROKER_V2_PROCESS_PRODUCTION_UNAVAILABLE;
}

int
plamen_broker_v2_process_extinguish(struct plamen_broker_v2_process *process,
    struct plamen_broker_v2_process_terminal *terminal)
{
    return plamen_broker_v2_process_wait(process, terminal);
}

int
plamen_broker_v2_process_read_output(
    struct plamen_broker_v2_process *process, uint32_t stream,
    uint64_t offset, uint32_t maximum, uint8_t *output,
    uint32_t output_capacity, uint32_t *output_size, uint8_t *eof,
    uint8_t chunk_sha256[PLAMEN_BROKER_V2_SHA256_SIZE],
    uint8_t full_sha256[PLAMEN_BROKER_V2_SHA256_SIZE], uint64_t *full_size)
{
    (void)process;
    (void)stream;
    (void)offset;
    (void)maximum;
    (void)output;
    (void)output_capacity;
    (void)output_size;
    (void)eof;
    (void)chunk_sha256;
    (void)full_sha256;
    (void)full_size;
    return PLAMEN_BROKER_V2_PROCESS_PRODUCTION_UNAVAILABLE;
}

int
plamen_broker_v2_process_close(struct plamen_broker_v2_process *process)
{
    (void)process;
    return PLAMEN_BROKER_V2_PROCESS_PRODUCTION_UNAVAILABLE;
}

int
plamen_broker_v2_test_spawn_wait(
    const struct plamen_broker_v2_test_request *request,
    struct plamen_broker_v2_test_result *result)
{
    (void)request;
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
        result->version = 1;
        result->status = PLAMEN_BROKER_V2_PROCESS_PRODUCTION_UNAVAILABLE;
        result->exit_code = -1;
    }
    return PLAMEN_BROKER_V2_PROCESS_PRODUCTION_UNAVAILABLE;
}

#endif

#if defined(__APPLE__) && defined(PLAMEN_BROKER_V2_TEST_ONLY) \
    && defined(PLAMEN_BROKER_V2_TEST_DRIVER)

static int
parse_integer(const char *text, long minimum, long maximum, long *value)
{
    char *end = NULL;
    long parsed;
    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0'
        || parsed < minimum || parsed > maximum)
        return -1;
    *value = parsed;
    return 0;
}

static int
parse_hex_digest(const char *text, uint8_t digest[32])
{
    size_t index;
    if (strlen(text) != 64)
        return -1;
    for (index = 0; index < 32; index++) {
        char pair[3] = { text[index * 2], text[index * 2 + 1], '\0' };
        char *end = NULL;
        unsigned long byte;
        errno = 0;
        byte = strtoul(pair, &end, 16);
        if (errno != 0 || end != pair + 2 || byte > 255)
            return -1;
        digest[index] = (uint8_t)byte;
    }
    return 0;
}

static void
print_hex(const uint8_t *bytes, size_t size)
{
    size_t index;
    for (index = 0; index < size; index++)
        printf("%02x", bytes[index]);
}

int
main(int argc, char **argv)
{
    struct plamen_broker_v2_test_request request;
    struct plamen_broker_v2_test_result result;
    uint8_t expected_sha[32];
    long parsed;
    int separator = -1;
    int index;
    int returned;

    memset(&request, 0, sizeof(request));
    request.version = 1;
    request.executable_fd = -1;
    request.cwd_fd = -1;
    request.stdin_fd = -1;
    request.pass_fd = -1;
    request.pass_target = -1;
    request.cancel_fd = -1;
    request.test_gate_fd = -1;
    request.timeout_ms = 5000;
    request.stdout_retain_limit = PLAMEN_BROKER_V2_RETAIN_MAX;
    request.stderr_retain_limit = PLAMEN_BROKER_V2_RETAIN_MAX;
    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--") == 0) {
            separator = index;
            break;
        }
#define PARSE_VALUE(name, field, minimum, maximum) \
        if (strcmp(argv[index], name) == 0 && ++index < argc) { \
            if (parse_integer(argv[index], minimum, maximum, &parsed) < 0) \
                return 64; \
            request.field = (int)parsed; \
            continue; \
        }
        PARSE_VALUE("--executable-fd", executable_fd, 0, INT_MAX)
        PARSE_VALUE("--cwd-fd", cwd_fd, 0, INT_MAX)
        PARSE_VALUE("--stdin-fd", stdin_fd, 0, INT_MAX)
        PARSE_VALUE("--pass-fd", pass_fd, 0, INT_MAX)
        PARSE_VALUE("--pass-target", pass_target, 3, 1023)
        PARSE_VALUE("--cancel-fd", cancel_fd, 0, INT_MAX)
        PARSE_VALUE("--gate-fd", test_gate_fd, 0, INT_MAX)
#undef PARSE_VALUE
        if (strcmp(argv[index], "--path") == 0 && ++index < argc) {
            request.executable_path = argv[index];
            continue;
        }
        if (strcmp(argv[index], "--sha256") == 0 && ++index < argc) {
            if (parse_hex_digest(argv[index], expected_sha) < 0)
                return 64;
            request.expected_executable_sha256 = expected_sha;
            continue;
        }
        if (strcmp(argv[index], "--signing-id") == 0 && ++index < argc) {
            request.expected_signing_identifier = argv[index];
            continue;
        }
        if (strcmp(argv[index], "--team-id") == 0 && ++index < argc) {
            request.expected_team_identifier = argv[index];
            continue;
        }
        if (strcmp(argv[index], "--timeout-ms") == 0 && ++index < argc) {
            if (parse_integer(argv[index], 1, UINT32_MAX, &parsed) < 0)
                return 64;
            request.timeout_ms = (uint32_t)parsed;
            continue;
        }
        if (strcmp(argv[index], "--stdout-limit") == 0 && ++index < argc) {
            if (parse_integer(argv[index], 0, PLAMEN_BROKER_V2_RETAIN_MAX,
                    &parsed) < 0)
                return 64;
            request.stdout_retain_limit = (uint32_t)parsed;
            continue;
        }
        if (strcmp(argv[index], "--stderr-limit") == 0 && ++index < argc) {
            if (parse_integer(argv[index], 0, PLAMEN_BROKER_V2_RETAIN_MAX,
                    &parsed) < 0)
                return 64;
            request.stderr_retain_limit = (uint32_t)parsed;
            continue;
        }
        return 64;
    }
    if (separator < 0 || separator + 1 >= argc)
        return 64;
    request.argv = (const char *const *)&argv[separator + 1];
    request.argc = (size_t)(argc - separator - 1);
    returned = plamen_broker_v2_test_spawn_wait(&request, &result);
    printf("STATUS=%u\nRETURNED=%d\nEXIT=%d\nSIGNAL=%d\nPID=%d\n",
        result.status, returned, result.exit_code, result.signal_number,
        result.child_pid);
    printf("BIRTH_US=%llu\nREAPED=%u\nEXTINCT=%u\n",
        (unsigned long long)result.child_birth_us, result.child_reaped,
        result.process_group_extinct);
    printf("SIGNING_ID=%s\nTEAM_ID=%s\nCDHASH=", result.signing_identifier,
        result.team_identifier);
    print_hex(result.cdhash, result.cdhash_size);
    printf("\nSTDOUT_OBSERVED=%llu\nSTDERR_OBSERVED=%llu\nSTDOUT_TRUNCATED=%u\nSTDERR_TRUNCATED=%u\nSTDOUT_HEX=",
        (unsigned long long)result.stdout_observed,
        (unsigned long long)result.stderr_observed, result.stdout_truncated,
        result.stderr_truncated);
    print_hex(result.stdout_bytes, result.stdout_retained);
    printf("\nSTDERR_HEX=");
    print_hex(result.stderr_bytes, result.stderr_retained);
    printf("\nSTDOUT_SHA256=");
    print_hex(result.stdout_sha256, sizeof(result.stdout_sha256));
    printf("\nSTDERR_SHA256=");
    print_hex(result.stderr_sha256, sizeof(result.stderr_sha256));
    printf("\n");
    plamen_broker_v2_test_result_dispose(&result);
    return returned == PLAMEN_BROKER_V2_PROCESS_OK ? 0 : returned;
}

#endif
