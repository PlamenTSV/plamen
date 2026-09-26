#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_native_launchd_installer_v2.h"
#include "plamen_native_launchd_readiness_v2.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef POSIX_SPAWN_CLOEXEC_DEFAULT
#define POSIX_SPAWN_CLOEXEC_DEFAULT 0x4000
#endif

#define PLIST_MAX 8192U
#define LAUNCHCTL_TIMEOUT_TICKS 1000U

extern char **environ;

static const char plist_prefix[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"\n"
    "  \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\">\n<dict>\n"
    "  <key>Label</key>\n  <string>";
static const char plist_middle[] =
    "</string>\n  <key>ProgramArguments</key>\n  <array>\n"
    "    <string>";
static const char plist_after_path[] = "</string>\n";
static const char plist_custody_arg[] =
    "    <string>--process-custody-daemon</string>\n";
static const char plist_suffix_a[] =
    "  </array>\n  <key>MachServices</key>\n  <dict>\n"
    "    <key>";
static const char plist_suffix_b[] =
    "</key>\n    <true/>\n  </dict>\n"
    "  <key>KeepAlive</key>\n  <true/>\n"
    "  <key>ProcessType</key>\n  <string>Background</string>\n"
    "  <key>ThrottleInterval</key>\n  <integer>5</integer>\n"
    "  <key>Umask</key>\n  <integer>63</integer>\n"
    "  <key>AbandonProcessGroup</key>\n  <false/>\n"
    "</dict>\n</plist>\n";

static const char *
role_label(enum plamen_launchd_role_v2 role)
{
    if (role == PLAMEN_LAUNCHD_ROLE_BROKER_V2)
        return PLAMEN_LAUNCHD_BROKER_LABEL;
    if (role == PLAMEN_LAUNCHD_ROLE_CUSTODY_V2)
        return PLAMEN_LAUNCHD_CUSTODY_LABEL;
    return NULL;
}

static int
canonical_absolute(const char *path)
{
    const unsigned char *cursor = (const unsigned char *)path;
    size_t size;
    if (path == NULL || path[0] != '/' || path[1] == '/'
        || (size = strlen(path)) == 0 || size > 4096U || path[size - 1U] == '/')
        return 0;
    while (*cursor != '\0') {
        if (*cursor < 32U || *cursor == 127U)
            return 0;
        cursor++;
    }
    if (strstr(path, "/./") != NULL || strstr(path, "/../") != NULL
        || strstr(path, "//") != NULL)
        return 0;
    return 1;
}

static int
append_bytes(uint8_t *output, size_t capacity, size_t *used,
    const void *bytes, size_t size)
{
    if (size > capacity - *used) {
        errno = EOVERFLOW;
        return -1;
    }
    memcpy(output + *used, bytes, size);
    *used += size;
    return 0;
}

static int
append_xml_path(uint8_t *output, size_t capacity, size_t *used,
    const char *path)
{
    const unsigned char *cursor = (const unsigned char *)path;
    while (*cursor != '\0') {
        const char *escaped = NULL;
        size_t escaped_size = 0;
        if (*cursor == '&') { escaped = "&amp;"; escaped_size = 5U; }
        else if (*cursor == '<') { escaped = "&lt;"; escaped_size = 4U; }
        else if (*cursor == '>') { escaped = "&gt;"; escaped_size = 4U; }
        else if (*cursor == '\"') { escaped = "&quot;"; escaped_size = 6U; }
        else if (*cursor == '\'') { escaped = "&apos;"; escaped_size = 6U; }
        if (escaped != NULL) {
            if (append_bytes(output, capacity, used, escaped,
                    escaped_size) != 0)
                return -1;
        } else if (append_bytes(output, capacity, used, cursor, 1U) != 0) {
            return -1;
        }
        cursor++;
    }
    return 0;
}

static int
render_bytes(const char *path, enum plamen_launchd_role_v2 role,
    uint8_t output[PLIST_MAX], size_t *output_size)
{
    const char *label = role_label(role);
    size_t used = 0;
#define APPEND_LITERAL(value) do { \
    if (append_bytes(output, PLIST_MAX, &used, value, sizeof(value) - 1U) != 0) \
        return -1; \
} while (0)
    if (label == NULL || !canonical_absolute(path) || output == NULL
        || output_size == NULL) {
        errno = EINVAL;
        return -1;
    }
    APPEND_LITERAL(plist_prefix);
    if (append_bytes(output, PLIST_MAX, &used, label, strlen(label)) != 0)
        return -1;
    APPEND_LITERAL(plist_middle);
    if (append_xml_path(output, PLIST_MAX, &used, path) != 0)
        return -1;
    APPEND_LITERAL(plist_after_path);
    if (role == PLAMEN_LAUNCHD_ROLE_CUSTODY_V2)
        APPEND_LITERAL(plist_custody_arg);
    APPEND_LITERAL(plist_suffix_a);
    if (append_bytes(output, PLIST_MAX, &used, label, strlen(label)) != 0)
        return -1;
    APPEND_LITERAL(plist_suffix_b);
#undef APPEND_LITERAL
    *output_size = used;
    return 0;
}

static int
complete_exact_plist(int fd, const uint8_t *bytes, size_t size,
    const struct stat *before)
{
    uint8_t observed[PLIST_MAX];
    struct stat after_read, after_write;
    size_t prefix, offset = 0U;
    int flags;
    if (before == NULL || before->st_size < 0
            || (uint64_t)before->st_size > size
            || (flags = fcntl(fd, F_GETFL)) < 0
            || ((before->st_mode & 07777) == 0600
                ? (flags & O_ACCMODE) != O_RDWR
                : ((before->st_mode & 07777) != 0400
                    || before->st_size != (off_t)size
                    || (flags & O_ACCMODE) != O_RDONLY))) return -1;
    prefix = (size_t)before->st_size;
    while (offset < prefix) {
        ssize_t amount = pread(fd, observed + offset, prefix - offset,
            (off_t)offset);
        if (amount <= 0) goto invalid;
        offset += (size_t)amount;
    }
    if (memcmp(observed, bytes, prefix) != 0
            || fstat(fd, &after_read) != 0
            || after_read.st_dev != before->st_dev
            || after_read.st_ino != before->st_ino
            || after_read.st_mode != before->st_mode
            || after_read.st_uid != before->st_uid
            || after_read.st_gid != before->st_gid
            || after_read.st_nlink != before->st_nlink
            || after_read.st_size != before->st_size)
        goto invalid;
    if ((before->st_mode & 07777) == 0400) {
        memset(observed, 0, sizeof(observed));
        return 0;
    }
    offset = prefix;
    while (offset < size) {
        ssize_t amount = pwrite(fd, bytes + offset, size - offset,
            (off_t)offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) goto invalid;
        offset += (size_t)amount;
    }
    if (fsync(fd) != 0 || fchmod(fd, 0400) != 0 || fsync(fd) != 0
            || fstat(fd, &after_write) != 0
            || after_write.st_dev != before->st_dev
            || after_write.st_ino != before->st_ino
            || after_write.st_uid != before->st_uid
            || after_write.st_gid != before->st_gid
            || after_write.st_nlink != before->st_nlink
            || after_write.st_size != (off_t)size
            || (after_write.st_mode & 07777) != 0400)
        goto invalid;
    memset(observed, 0, sizeof(observed));
    return 0;
invalid:
    memset(observed, 0, sizeof(observed));
    return -1;
}

int
plamen_native_launchd_render_plist_v2(int output_fd,
    const char *service_absolute_path, enum plamen_launchd_role_v2 role)
{
    uint8_t bytes[PLIST_MAX];
    size_t size = 0;
    struct stat information;
    int flags, result = -1;
    memset(bytes, 0, sizeof(bytes));
    if (output_fd < 0 || (flags = fcntl(output_fd, F_GETFL)) < 0
        || fstat(output_fd, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_size < 0
        || render_bytes(service_absolute_path, role, bytes, &size) != 0
        || complete_exact_plist(output_fd, bytes, size, &information) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        memset(bytes, 0, sizeof(bytes));
        if (result != 0) errno = saved;
        return result;
    }
}

int
plamen_native_launchd_validate_plist_v2(int retained_fd,
    const char *service_absolute_path, enum plamen_launchd_role_v2 role)
{
    uint8_t expected[PLIST_MAX], observed[PLIST_MAX];
    struct stat before, after;
    size_t size = 0, offset = 0;
    int flags, result = -1;
    memset(expected, 0, sizeof(expected)); memset(observed, 0, sizeof(observed));
    if (retained_fd < 0 || (flags = fcntl(retained_fd, F_GETFL)) < 0
        || (flags & O_ACCMODE) != O_RDONLY
        || fstat(retained_fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_nlink != 1 || (before.st_mode & 07777) != 0400
        || before.st_size <= 0 || (uint64_t)before.st_size > PLIST_MAX
        || render_bytes(service_absolute_path, role, expected, &size) != 0
        || (off_t)size != before.st_size)
        goto done;
    while (offset < size) {
        ssize_t amount = pread(retained_fd, observed + offset,
            size - offset, (off_t)offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    if (fstat(retained_fd, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_size != after.st_size || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid || before.st_gid != after.st_gid
        || before.st_nlink != after.st_nlink
        || memcmp(expected, observed, size) != 0) {
        errno = EPERM;
        goto done;
    }
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        memset(expected, 0, sizeof(expected)); memset(observed, 0, sizeof(observed));
        if (result != 0) errno = saved;
        return result;
    }
}

static int
wait_bounded(pid_t child, int *exit_status)
{
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000L };
    unsigned int tick;
    int status;
    for (tick = 0; tick < LAUNCHCTL_TIMEOUT_TICKS; ++tick) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            if (!WIFEXITED(status)) { errno = ECHILD; return -1; }
            *exit_status = WEXITSTATUS(status);
            return 0;
        }
        if (waited < 0 && errno != EINTR)
            return -1;
        (void)nanosleep(&pause, NULL);
    }
    (void)kill(-child, SIGKILL); (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    errno = ETIMEDOUT;
    return -1;
}

int
plamen_native_launchd_run_v2(uid_t uid,
    enum plamen_launchd_role_v2 role, enum plamen_launchd_action_v2 action,
    const char *plist_absolute_path, int *exit_status)
{
    const char *label = role_label(role);
    char domain[64], target[160];
    char *argv[7];
    char *empty_environment[] = { NULL };
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_t actions;
    pid_t child = -1;
    int devnull = -1, count = 0, rc, result = -1;
    int attributes_ready = 0, actions_ready = 0;
    short flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP;
    if (exit_status != NULL) *exit_status = -1;
    if (label == NULL || exit_status == NULL
        || snprintf(domain, sizeof(domain), "gui/%u", (unsigned int)uid)
            >= (int)sizeof(domain)
        || snprintf(target, sizeof(target), "gui/%u/%s",
            (unsigned int)uid, label) >= (int)sizeof(target)
        || ((action == PLAMEN_LAUNCHD_BOOTSTRAP_V2)
            && !canonical_absolute(plist_absolute_path))) {
        errno = EINVAL; return -1;
    }
    argv[count++] = "/bin/launchctl";
    if (action == PLAMEN_LAUNCHD_BOOTOUT_V2) {
        argv[count++] = "bootout"; argv[count++] = target;
    } else if (action == PLAMEN_LAUNCHD_BOOTSTRAP_V2) {
        argv[count++] = "bootstrap"; argv[count++] = domain;
        argv[count++] = (char *)plist_absolute_path;
    } else if (action == PLAMEN_LAUNCHD_ENABLE_V2) {
        argv[count++] = "enable"; argv[count++] = target;
    } else if (action == PLAMEN_LAUNCHD_KICKSTART_V2) {
        argv[count++] = "kickstart"; argv[count++] = "-k";
        argv[count++] = target;
    } else if (action == PLAMEN_LAUNCHD_PRINT_V2) {
        argv[count++] = "print"; argv[count++] = target;
    } else { errno = EINVAL; return -1; }
    argv[count] = NULL;
    devnull = open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (devnull < 0 || posix_spawnattr_init(&attributes) != 0)
        goto done;
    attributes_ready = 1;
    if (posix_spawn_file_actions_init(&actions) != 0)
        goto destroy;
    actions_ready = 1;
    if (posix_spawnattr_setflags(&attributes, flags) != 0
        || posix_spawnattr_setpgroup(&attributes, 0) != 0
        || posix_spawn_file_actions_adddup2(&actions, devnull,
            STDIN_FILENO) != 0
        || posix_spawn_file_actions_adddup2(&actions, devnull,
            STDOUT_FILENO) != 0
        || posix_spawn_file_actions_adddup2(&actions, devnull,
            STDERR_FILENO) != 0)
        goto destroy;
    rc = posix_spawn(&child, "/bin/launchctl", &actions, &attributes,
        argv, empty_environment);
    if (rc != 0) { errno = rc; goto destroy; }
    if (wait_bounded(child, exit_status) != 0)
        goto destroy;
    result = 0;
destroy:
    if (actions_ready)
        (void)posix_spawn_file_actions_destroy(&actions);
    if (attributes_ready)
        (void)posix_spawnattr_destroy(&attributes);
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EIO : errno);
        if (devnull >= 0) close(devnull);
        memset(domain, 0, sizeof(domain)); memset(target, 0, sizeof(target));
        if (result != 0) errno = saved;
        return result;
    }
}

static int
same_plist_identity(int fd, const struct plamen_install_receipt_launchd_plist *p)
{
    struct plamen_install_receipt_member synthetic;
    memset(&synthetic, 0, sizeof(synthetic));
    memcpy(synthetic.sha256, p->sha256, 32); synthetic.size = p->size;
    synthetic.mode = p->mode; synthetic.device = p->device;
    synthetic.inode = p->inode; synthetic.uid = p->uid; synthetic.gid = p->gid;
    return plamen_install_receipt_member_revalidate(fd, &synthetic);
}

static int
service_path(const struct plamen_install_receipt *receipt,
    char output[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1U])
{
    const struct plamen_install_receipt_member *service =
        &receipt->members[PLAMEN_INSTALL_MEMBER_SERVICE - 1U];
    int amount = snprintf(output, PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1U,
        "%s/%s", receipt->generation_path, service->relative_path);
    return amount > 0 && amount <= (int)PLAMEN_INSTALL_RECEIPT_PATH_MAX
        && canonical_absolute(output) ? 0 : -1;
}

static int
validate_static_code(const char *path,
    const struct plamen_install_receipt_member *member)
{
    CFStringRef text = NULL, identifier = NULL, team = NULL;
    CFURLRef url = NULL; SecStaticCodeRef code = NULL;
    CFDictionaryRef information = NULL; CFDataRef unique = NULL;
    const UInt8 *bytes; CFIndex size; char observed[129];
    int result = -1;
    memset(observed, 0, sizeof(observed));
    text = CFStringCreateWithCString(kCFAllocatorDefault, path,
        kCFStringEncodingUTF8);
    if (text == NULL || (url = CFURLCreateWithFileSystemPath(
            kCFAllocatorDefault, text, kCFURLPOSIXPathStyle, false)) == NULL
        || SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) != errSecSuccess
        || SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL)
            != errSecSuccess
        || SecCodeCopySigningInformation(code, kSecCSSigningInformation,
            &information) != errSecSuccess)
        goto done;
    identifier = (CFStringRef)CFDictionaryGetValue(information,
        kSecCodeInfoIdentifier);
    team = (CFStringRef)CFDictionaryGetValue(information,
        kSecCodeInfoTeamIdentifier);
    unique = (CFDataRef)CFDictionaryGetValue(information, kSecCodeInfoUnique);
    if (identifier == NULL || CFGetTypeID(identifier) != CFStringGetTypeID()
        || !CFStringGetCString(identifier, observed, sizeof(observed),
            kCFStringEncodingUTF8)
        || strcmp(observed, member->signing_identifier) != 0
        || (member->team_identifier[0] == '\0'
            ? (team != NULL && (CFGetTypeID(team) != CFStringGetTypeID()
                || CFStringGetLength(team) != 0))
            : (team == NULL || CFGetTypeID(team) != CFStringGetTypeID()
                || !CFStringGetCString(team, observed, sizeof(observed),
                    kCFStringEncodingUTF8)
                || strcmp(observed, member->team_identifier) != 0))
        || unique == NULL || CFGetTypeID(unique) != CFDataGetTypeID())
        goto done;
    bytes = CFDataGetBytePtr(unique); size = CFDataGetLength(unique);
    if (bytes == NULL || !(size == 20 || size == 32)
        || (uint16_t)size != member->cdhash_size
        || memcmp(bytes, member->cdhash, (size_t)size) != 0)
        goto done;
    result = 0;
done:
    if (information != NULL) CFRelease(information);
    if (code != NULL) CFRelease(code); if (url != NULL) CFRelease(url);
    if (text != NULL) CFRelease(text); memset(observed, 0, sizeof(observed));
    if (result != 0 && errno == 0) errno = EPERM;
    return result;
}

int
plamen_native_launchd_validate_deployment_v2(
    const struct plamen_install_receipt *receipt, int generation_fd,
    int broker_plist_fd, int custody_plist_fd)
{
    char path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1U];
    struct stat retained, named;
    int service_fd = -1, named_fd = -1, result = -1;
    memset(path, 0, sizeof(path));
    if (receipt == NULL || generation_fd < 0 || broker_plist_fd < 0
        || custody_plist_fd < 0 || service_path(receipt, path) != 0
        || same_plist_identity(broker_plist_fd,
            &receipt->broker_launchd_plist) != 0
        || same_plist_identity(custody_plist_fd,
            &receipt->custody_launchd_plist) != 0
        || plamen_native_launchd_validate_plist_v2(broker_plist_fd, path,
            PLAMEN_LAUNCHD_ROLE_BROKER_V2) != 0
        || plamen_native_launchd_validate_plist_v2(custody_plist_fd, path,
            PLAMEN_LAUNCHD_ROLE_CUSTODY_V2) != 0
        || plamen_install_receipt_open_member(generation_fd,
            &receipt->members[PLAMEN_INSTALL_MEMBER_SERVICE - 1U],
            &service_fd) != 0
        || (named_fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || fstat(service_fd, &retained) != 0 || fstat(named_fd, &named) != 0
        || retained.st_dev != named.st_dev || retained.st_ino != named.st_ino
        || validate_static_code(path,
            &receipt->members[PLAMEN_INSTALL_MEMBER_SERVICE - 1U]) != 0
        || plamen_install_receipt_member_revalidate(named_fd,
            &receipt->members[PLAMEN_INSTALL_MEMBER_SERVICE - 1U]) != 0)
        goto done;
    result = 0;
done:
    if (service_fd >= 0) close(service_fd);
    if (named_fd >= 0) close(named_fd);
    memset(path, 0, sizeof(path));
    return result;
}

#define DEPLOYMENT_STATE_MAGIC UINT32_C(0x504c4d00)
#define DEPLOYMENT_STATE_PRIOR_LOADED UINT32_C(1)

static int
production_run(void *opaque, uid_t uid, enum plamen_launchd_role_v2 role,
    enum plamen_launchd_action_v2 action, const char *plist,
    int *exit_status)
{
    (void)opaque;
    return plamen_native_launchd_run_v2(uid, role, action, plist, exit_status);
}

static int
production_ready(void *opaque, enum plamen_launchd_role_v2 role,
    const struct plamen_install_receipt *receipt)
{
    struct plamen_native_launchd_transaction_v2 *transaction = opaque;
    int generation_fd;
    if (transaction == NULL
        || !(role == PLAMEN_LAUNCHD_ROLE_BROKER_V2
            || role == PLAMEN_LAUNCHD_ROLE_CUSTODY_V2)) {
        errno = EINVAL;
        return -1;
    }
    if (receipt == transaction->replacement.receipt)
        generation_fd = transaction->replacement.generation_fd;
    else if (transaction->prior_present
        && receipt == transaction->prior.receipt)
        generation_fd = transaction->prior.generation_fd;
    else {
        errno = EPERM;
        return -1;
    }
    return plamen_native_launchd_authenticated_ready_v2(
        receipt, generation_fd);
}

int
plamen_native_launchd_production_effects_v2(
    struct plamen_native_launchd_transaction_v2 *transaction)
{
    if (transaction == NULL) {
        errno = EINVAL;
        return -1;
    }
    transaction->effects.context = transaction;
    transaction->effects.run = production_run;
    transaction->effects.ready = production_ready;
    return 0;
}

static int
effect_run(struct plamen_native_launchd_transaction_v2 *transaction,
    enum plamen_launchd_role_v2 role, enum plamen_launchd_action_v2 action,
    const char *path, int *status)
{
    if (transaction->effects.run != NULL)
        return transaction->effects.run(transaction->effects.context,
            transaction->owner_uid, role, action, path, status);
    return plamen_native_launchd_run_v2(transaction->owner_uid, role,
        action, path, status);
}

static int
observed_loaded(struct plamen_native_launchd_transaction_v2 *transaction,
    enum plamen_launchd_role_v2 role, int *loaded)
{
    int status = -1;
    if (effect_run(transaction, role, PLAMEN_LAUNCHD_PRINT_V2,
            NULL, &status) != 0 || !(status == 0 || status == 113)) {
        errno = EPERM; return -1;
    }
    *loaded = status == 0;
    return 0;
}

static int
effect_success(struct plamen_native_launchd_transaction_v2 *transaction,
    enum plamen_launchd_role_v2 role, enum plamen_launchd_action_v2 action,
    const char *path)
{
    int status = -1;
    if (effect_run(transaction, role, action, path, &status) != 0
        || status != 0) { errno = EPERM; return -1; }
    return 0;
}

static int
effect_bootout_idempotent(
    struct plamen_native_launchd_transaction_v2 *transaction,
    enum plamen_launchd_role_v2 role)
{
    int status = -1;
    if (effect_run(transaction, role, PLAMEN_LAUNCHD_BOOTOUT_V2,
            NULL, &status) != 0 || !(status == 0 || status == 113)) {
        errno = EPERM; return -1;
    }
    return 0;
}

static int
closure_valid(const struct plamen_native_launchd_closure_v2 *closure)
{
    return closure != NULL && closure->receipt != NULL
        && closure->generation_fd >= 0 && closure->broker_plist_fd >= 0
        && closure->custody_plist_fd >= 0
        && plamen_native_launchd_validate_deployment_v2(closure->receipt,
            closure->generation_fd, closure->broker_plist_fd,
            closure->custody_plist_fd) == 0;
}

static int
bootstrap_closure(struct plamen_native_launchd_transaction_v2 *transaction,
    const struct plamen_native_launchd_closure_v2 *closure)
{
    if (effect_success(transaction, PLAMEN_LAUNCHD_ROLE_CUSTODY_V2,
            PLAMEN_LAUNCHD_BOOTSTRAP_V2,
            closure->receipt->custody_launchd_plist.path) != 0
        || effect_success(transaction, PLAMEN_LAUNCHD_ROLE_CUSTODY_V2,
            PLAMEN_LAUNCHD_ENABLE_V2, NULL) != 0
        || effect_success(transaction, PLAMEN_LAUNCHD_ROLE_CUSTODY_V2,
            PLAMEN_LAUNCHD_KICKSTART_V2, NULL) != 0
        || effect_success(transaction, PLAMEN_LAUNCHD_ROLE_BROKER_V2,
            PLAMEN_LAUNCHD_BOOTSTRAP_V2,
            closure->receipt->broker_launchd_plist.path) != 0
        || effect_success(transaction, PLAMEN_LAUNCHD_ROLE_BROKER_V2,
            PLAMEN_LAUNCHD_ENABLE_V2, NULL) != 0
        || effect_success(transaction, PLAMEN_LAUNCHD_ROLE_BROKER_V2,
            PLAMEN_LAUNCHD_KICKSTART_V2, NULL) != 0
        || transaction->effects.ready(transaction->effects.context,
            PLAMEN_LAUNCHD_ROLE_BROKER_V2, closure->receipt) != 0
        || transaction->effects.ready(transaction->effects.context,
            PLAMEN_LAUNCHD_ROLE_CUSTODY_V2, closure->receipt) != 0)
        return -1;
    return 0;
}

static int
launchd_prepare(void *opaque, uint32_t *durable_state)
{
    struct plamen_native_launchd_transaction_v2 *transaction = opaque;
    int broker_loaded, custody_loaded;
    if (transaction == NULL || durable_state == NULL
        || transaction->effects.ready == NULL
        || !closure_valid(&transaction->replacement)
        || (transaction->prior_present != 0
            && (transaction->prior_present != 1
                || !closure_valid(&transaction->prior)))
        || observed_loaded(transaction, PLAMEN_LAUNCHD_ROLE_BROKER_V2,
            &broker_loaded) != 0
        || observed_loaded(transaction, PLAMEN_LAUNCHD_ROLE_CUSTODY_V2,
            &custody_loaded) != 0
        || broker_loaded != custody_loaded
        || broker_loaded != transaction->prior_present) {
        errno = EPERM; return -1;
    }
    *durable_state = DEPLOYMENT_STATE_MAGIC
        | (broker_loaded ? DEPLOYMENT_STATE_PRIOR_LOADED : 0U);
    return 0;
}

static int
valid_deployment_state(uint32_t state)
{
    return (state & ~DEPLOYMENT_STATE_PRIOR_LOADED) == DEPLOYMENT_STATE_MAGIC;
}

static int
launchd_activate(void *opaque, uint32_t state)
{
    struct plamen_native_launchd_transaction_v2 *transaction = opaque;
    if (transaction == NULL || !valid_deployment_state(state)
        || ((state & DEPLOYMENT_STATE_PRIOR_LOADED) != 0
            && (effect_bootout_idempotent(transaction,
                    PLAMEN_LAUNCHD_ROLE_BROKER_V2) != 0
                || effect_bootout_idempotent(transaction,
                    PLAMEN_LAUNCHD_ROLE_CUSTODY_V2) != 0))
        || bootstrap_closure(transaction, &transaction->replacement) != 0)
        return -1;
    return 0;
}

static int
launchd_rollback(void *opaque, uint32_t state)
{
    struct plamen_native_launchd_transaction_v2 *transaction = opaque;
    if (transaction == NULL || !valid_deployment_state(state)
        || effect_bootout_idempotent(transaction,
            PLAMEN_LAUNCHD_ROLE_BROKER_V2) != 0
        || effect_bootout_idempotent(transaction,
            PLAMEN_LAUNCHD_ROLE_CUSTODY_V2) != 0)
        return -1;
    return 0;
}

static int
launchd_restore(void *opaque, uint32_t state)
{
    struct plamen_native_launchd_transaction_v2 *transaction = opaque;
    if (transaction == NULL || !valid_deployment_state(state)) {
        errno = EINVAL; return -1;
    }
    if ((state & DEPLOYMENT_STATE_PRIOR_LOADED) != 0
        && (!transaction->prior_present || !closure_valid(&transaction->prior)
            || bootstrap_closure(transaction, &transaction->prior) != 0))
        return -1;
    return 0;
}

static int
launchd_commit(void *opaque, uint32_t state)
{
    struct plamen_native_launchd_transaction_v2 *transaction = opaque;
    int broker_loaded, custody_loaded;
    if (transaction == NULL || !valid_deployment_state(state)
        || !closure_valid(&transaction->replacement)
        || observed_loaded(transaction, PLAMEN_LAUNCHD_ROLE_CUSTODY_V2,
            &custody_loaded) != 0 || !custody_loaded
        || observed_loaded(transaction, PLAMEN_LAUNCHD_ROLE_BROKER_V2,
            &broker_loaded) != 0 || !broker_loaded
        || transaction->effects.ready(transaction->effects.context,
            PLAMEN_LAUNCHD_ROLE_CUSTODY_V2,
            transaction->replacement.receipt) != 0
        || transaction->effects.ready(transaction->effects.context,
            PLAMEN_LAUNCHD_ROLE_BROKER_V2,
            transaction->replacement.receipt) != 0)
        return -1;
    return 0;
}

int
plamen_native_launchd_deployment_hooks_v2(
    struct plamen_native_launchd_transaction_v2 *transaction,
    struct plamen_native_install_deployment_v2 *output)
{
    if (transaction == NULL || output == NULL
        || transaction->effects.ready == NULL
        || transaction->prior_present < 0 || transaction->prior_present > 1) {
        errno = EINVAL; return -1;
    }
    memset(output, 0, sizeof(*output)); output->context = transaction;
    output->prepare = launchd_prepare; output->activate = launchd_activate;
    output->rollback = launchd_rollback; output->restore = launchd_restore;
    output->commit = launchd_commit;
    return 0;
}

int
plamen_native_launchd_uninstall_v2(
    struct plamen_native_launchd_transaction_v2 *transaction)
{
    int broker_loaded, custody_loaded;
    if (transaction == NULL
        || effect_bootout_idempotent(transaction,
            PLAMEN_LAUNCHD_ROLE_BROKER_V2) != 0
        || effect_bootout_idempotent(transaction,
            PLAMEN_LAUNCHD_ROLE_CUSTODY_V2) != 0
        || observed_loaded(transaction, PLAMEN_LAUNCHD_ROLE_BROKER_V2,
            &broker_loaded) != 0 || broker_loaded
        || observed_loaded(transaction, PLAMEN_LAUNCHD_ROLE_CUSTODY_V2,
            &custody_loaded) != 0 || custody_loaded) {
        errno = EPERM; return -1;
    }
    return 0;
}
