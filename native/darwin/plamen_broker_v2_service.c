#define _DARWIN_C_SOURCE 1

#include "../include/plamen_broker_v2.h"
#include "plamen_broker_v2_install_receipt.h"
#include "plamen_broker_v2_apple_container.h"
#include "plamen_broker_v2_effects.h"
#include "plamen_broker_v2_operations.h"
#include "plamen_broker_v2_process.h"
#include "plamen_broker_v2_process_custodian.h"
#include "plamen_broker_v2_process_custody_daemon.h"
#include "plamen_broker_v2_process_custody_client.h"
#include "plamen_broker_v2_service_store.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>
#include <xpc/xpc.h>

#define PLAMEN_SERVICE_HARDSTOP 78
#define PLAMEN_SERVICE_MAX_CHALLENGES 64U
#define PLAMEN_SERVICE_MAX_PENDING_AUTHORITIES 64U
#define PLAMEN_SERVICE_MAX_SPECIALIZED_CHALLENGES 64U
#define PLAMEN_SERVICE_MAX_ACTIVE_SESSIONS 64U
#define PLAMEN_SERVICE_SUFFIX "/lib/plamen/plamen-audit-broker-v2"
#define PLAMEN_SERVICE_PLIST_SUFFIX \
    "/Library/LaunchAgents/com.plamen.audit.broker.v2.plist"
#define PLAMEN_CUSTODY_PLIST_SUFFIX \
    "/Library/LaunchAgents/com.plamen.audit.process-custody.v2.plist"
#define PLAMEN_SERVICE_STATE_DIRECTORY "service-state-v2"
#define PLAMEN_SERVICE_SESSION_IO_TIMEOUT_MS 5000U
#define PLAMEN_SERVICE_CONFIG_MAX (UINT32_C(256) * UINT32_C(1024))
#define PLAMEN_APPLE_CLI_PATH "/usr/local/bin/container"
#define PLAMEN_APPLE_SERVER_PATH "/usr/local/bin/container-apiserver"
#define PLAMEN_APPLE_BOM_PATH "/var/db/receipts/com.apple.container-installer.bom"
#define PLAMEN_APPLE_RECEIPT_PATH "/var/db/receipts/com.apple.container-installer.plist"
#define PLAMEN_APPLE_CORE_IMAGES_PATH "/usr/local/libexec/container/plugins/container-core-images/bin/container-core-images"
#define PLAMEN_APPLE_NETWORK_VMNET_PATH "/usr/local/libexec/container/plugins/container-network-vmnet/bin/container-network-vmnet"
#define PLAMEN_APPLE_RUNTIME_LINUX_PATH "/usr/local/libexec/container/plugins/container-runtime-linux/bin/container-runtime-linux"
#define PLAMEN_APPLE_MACHINE_APISERVER_PATH "/usr/local/libexec/container/plugins/machine-apiserver/bin/machine-apiserver"
#define PLAMEN_APPLE_KERNEL_SUFFIX "/Library/Application Support/com.apple.container/kernels/vmlinux-6.18.35-197-debug"

struct plamen_service_code_identity {
    uint8_t cdhash[PLAMEN_INSTALL_RECEIPT_CDHASH_MAX];
    uint32_t cdhash_size;
    char identifier[PLAMEN_INSTALL_RECEIPT_SIGNING_ID_MAX + 1];
    char team[PLAMEN_INSTALL_RECEIPT_TEAM_ID_MAX + 1];
};

struct plamen_service_authority {
    struct plamen_install_receipt receipt;
    uint8_t installed_closure_sha256[32];
    uint8_t broker_closure_sha256[32];
    uint8_t installation_receipt_sha256[32];
    uint8_t extension_closure_sha256[32];
    uint8_t interpreter_executable_sha256[32];
    uint8_t python_entrypoint_sha256[32];
    uint8_t python_argv_sha256[32];
    uint8_t python_environment_sha256[32];
    int generation_fd;
    int member_fds[PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT];
    int specialized_authority_fd;
    int state_parent_fd;
    struct plamen_broker_v2_service_store *store;
    struct plamen_broker_v2_process_custodian *process_custodian;
    struct plamen_broker_v2_process_custody_client *custody_client;
    char admitted_peer_code_requirement[1024];
};

struct plamen_pending_challenge {
    int occupied;
    uint64_t deadline_ms;
    struct plamen_broker_v2_peer_identity peer;
    struct plamen_broker_v2_service_session_challenge challenge;
    uint8_t envelope_sha256[32];
};

struct plamen_service_session_worker {
    int control_fd;
    uint8_t key[32];
    uint8_t *request_projection;
    size_t request_projection_size;
    struct plamen_broker_v2_service_session_challenge challenge;
    struct plamen_broker_v2_service_session_ack acknowledgement;
    struct plamen_broker_v2_authority_bundle_binding authority_bundle;
    struct plamen_broker_v2_service_registration registration;
    uint16_t authority_presence_mask;
    int authority_fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    struct plamen_broker_v2_fd_metadata
        authority_descriptors[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    struct plamen_broker_v2_effects_context *effects;
    struct plamen_broker_v2_operations_session *operations;
    pthread_mutex_t lifetime_lock;
    size_t references;
    int lifetime_initialized;
    int closing;
#ifdef PLAMEN_BROKER_V2_TEST_ONLY
    uint8_t test_only_wire;
#endif
};

struct plamen_pending_specialized_challenge {
    int occupied;
    uint64_t deadline_ms;
    struct plamen_broker_v2_peer_identity peer;
    struct plamen_broker_v2_service_specialized_session_challenge challenge;
    uint8_t envelope_sha256[32];
};

struct plamen_active_service_session {
    int occupied;
    struct plamen_broker_v2_peer_identity peer;
    struct plamen_broker_v2_service_session_ack acknowledgement;
    struct plamen_broker_v2_authority_bundle_binding authority_bundle;
    struct plamen_service_session_worker *worker;
};

struct plamen_specialized_session_worker {
    int control_fd;
    int registered;
    uint8_t key[32];
    struct plamen_broker_v2_service_specialized_session_ack acknowledgement;
    struct plamen_service_session_worker *parent;
};

struct plamen_active_specialized_session {
    int occupied;
    uint8_t specialized_session_id[32];
    struct plamen_specialized_session_worker *worker;
};

static void session_worker_release(
    struct plamen_service_session_worker *, int);
static int active_session_find(
    const struct plamen_broker_v2_service_specialized_session_lookup *,
    const struct plamen_broker_v2_peer_identity *,
    struct plamen_service_session_worker **);

enum plamen_pending_authority_state {
    PLAMEN_PENDING_AUTHORITY_EMPTY = 0,
    PLAMEN_PENDING_AUTHORITY_RESERVED = 1,
    PLAMEN_PENDING_AUTHORITY_ACTIVE = 2,
    PLAMEN_PENDING_AUTHORITY_CLAIMING = 3
};

struct plamen_pending_authority {
    uint8_t state;
    uint8_t registration_sha256[32];
    struct plamen_broker_v2_peer_identity suspended_child;
    uint16_t presence_mask;
    int fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    struct plamen_broker_v2_fd_metadata
        descriptors[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
};

static struct plamen_service_authority service_authority;
static struct plamen_pending_challenge
    pending_challenges[PLAMEN_SERVICE_MAX_CHALLENGES];
static pthread_mutex_t pending_challenges_lock = PTHREAD_MUTEX_INITIALIZER;
static struct plamen_pending_authority
    pending_authorities[PLAMEN_SERVICE_MAX_PENDING_AUTHORITIES];
static pthread_mutex_t pending_authorities_lock = PTHREAD_MUTEX_INITIALIZER;
static struct plamen_pending_specialized_challenge
    pending_specialized_challenges[
        PLAMEN_SERVICE_MAX_SPECIALIZED_CHALLENGES];
static pthread_mutex_t pending_specialized_challenges_lock =
    PTHREAD_MUTEX_INITIALIZER;
static struct plamen_active_service_session
    active_service_sessions[PLAMEN_SERVICE_MAX_ACTIVE_SESSIONS];
static pthread_mutex_t active_service_sessions_lock =
    PTHREAD_MUTEX_INITIALIZER;
static struct plamen_active_specialized_session
    active_specialized_sessions[PLAMEN_SERVICE_MAX_ACTIVE_SESSIONS];
static pthread_mutex_t active_specialized_sessions_lock =
    PTHREAD_MUTEX_INITIALIZER;

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
all_zero_32(const uint8_t value[32])
{
    uint8_t aggregate = 0;
    size_t index;
    for (index = 0; index < 32; ++index)
        aggregate |= value[index];
    return aggregate == 0;
}

static int
same_peer(const struct plamen_broker_v2_peer_identity *left,
    const struct plamen_broker_v2_peer_identity *right)
{
    return left->pid == right->pid && left->uid == right->uid
        && left->gid == right->gid && left->birth_kind == right->birth_kind
        && left->birth_primary == right->birth_primary
        && left->birth_secondary == right->birth_secondary
        && constant_equal(left->boot_id_sha256, right->boot_id_sha256, 32);
}

static int
same_fd_metadata(const struct plamen_broker_v2_fd_metadata *left,
    const struct plamen_broker_v2_fd_metadata *right)
{
    return left->purpose == right->purpose && left->target == right->target
        && left->access_mode == right->access_mode
        && constant_equal(left->identity, right->identity, 32);
}

static void
close_authority_fd_array(
    int fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT])
{
    size_t index;
    if (fds == NULL)
        return;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++index) {
        if (fds[index] >= 0)
            (void)close(fds[index]);
        fds[index] = -1;
    }
}

static int
authority_fd_array_revalidate(uint16_t presence_mask,
    const struct plamen_broker_v2_fd_metadata
        descriptors[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT],
    const int fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT])
{
    uint8_t identity[32];
    size_t index;
    int result = -1;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++index) {
        int present = (presence_mask & (uint16_t)(UINT16_C(1) << index)) != 0;
        int flags;
        if (!present) {
            if (fds[index] != -1)
                goto done;
            continue;
        }
        flags = fcntl(fds[index], F_GETFD);
        if (fds[index] < 0 || flags < 0 || (flags & FD_CLOEXEC) == 0
            || plamen_broker_v2_fd_identity(fds[index], identity) != 0
            || !constant_equal(identity, descriptors[index].identity, 32))
            goto done;
    }
    result = 0;
done:
    plamen_broker_v2_secure_zero(identity, sizeof(identity));
    return result;
}

static void
pending_authority_reset_locked(struct plamen_pending_authority *pending)
{
    if (pending->state != PLAMEN_PENDING_AUTHORITY_EMPTY)
        close_authority_fd_array(pending->fds);
    plamen_broker_v2_secure_zero(pending, sizeof(*pending));
}

static int
pending_authority_same_locked(const struct plamen_pending_authority *pending,
    const struct plamen_broker_v2_service_registration *registration,
    const int fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT])
{
    size_t index;
    if (!same_peer(&pending->suspended_child,
            &registration->suspended_child)
        || pending->presence_mask != registration->authority_presence_mask
        || authority_fd_array_revalidate(pending->presence_mask,
            pending->descriptors, pending->fds) != 0
        || authority_fd_array_revalidate(registration->authority_presence_mask,
            registration->authority_descriptors, fds) != 0)
        return 0;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++index) {
        if (!same_fd_metadata(&pending->descriptors[index],
                &registration->authority_descriptors[index]))
            return 0;
    }
    return 1;
}

/* Takes ownership of fds only when returning zero.  One means exact replay. */
static int
pending_authority_reserve(const uint8_t registration_sha256[32],
    const struct plamen_broker_v2_service_registration *registration,
    int fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT])
{
    struct plamen_pending_authority *free_slot = NULL;
    size_t index;
    int result = -1;
    if (pthread_mutex_lock(&pending_authorities_lock) != 0)
        return -1;
    for (index = 0; index < PLAMEN_SERVICE_MAX_PENDING_AUTHORITIES; ++index) {
        struct plamen_pending_authority *candidate =
            &pending_authorities[index];
        if (candidate->state == PLAMEN_PENDING_AUTHORITY_EMPTY) {
            if (free_slot == NULL)
                free_slot = candidate;
            continue;
        }
        if (constant_equal(candidate->registration_sha256,
                registration_sha256, 32)) {
            if (candidate->state == PLAMEN_PENDING_AUTHORITY_ACTIVE
                && pending_authority_same_locked(candidate, registration,
                    fds))
                result = 1;
            goto done;
        }
        if (same_peer(&candidate->suspended_child,
                &registration->suspended_child))
            goto done;
    }
    if (free_slot == NULL)
        goto done;
    free_slot->state = PLAMEN_PENDING_AUTHORITY_RESERVED;
    memcpy(free_slot->registration_sha256, registration_sha256, 32);
    free_slot->suspended_child = registration->suspended_child;
    free_slot->presence_mask = registration->authority_presence_mask;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++index) {
        free_slot->fds[index] = fds[index];
        fds[index] = -1;
        free_slot->descriptors[index] =
            registration->authority_descriptors[index];
    }
    result = 0;
done:
    pthread_mutex_unlock(&pending_authorities_lock);
    return result;
}

static int
pending_authority_set_state(const uint8_t registration_sha256[32],
    uint8_t required_state, uint8_t next_state)
{
    size_t index;
    int result = -1;
    if (pthread_mutex_lock(&pending_authorities_lock) != 0)
        return -1;
    for (index = 0; index < PLAMEN_SERVICE_MAX_PENDING_AUTHORITIES; ++index) {
        struct plamen_pending_authority *pending =
            &pending_authorities[index];
        if (pending->state == required_state
            && constant_equal(pending->registration_sha256,
                registration_sha256, 32)) {
            pending->state = next_state;
            result = 0;
            break;
        }
    }
    pthread_mutex_unlock(&pending_authorities_lock);
    return result;
}

static void
pending_authority_abort_reservation(const uint8_t registration_sha256[32])
{
    size_t index;
    if (pthread_mutex_lock(&pending_authorities_lock) != 0)
        return;
    for (index = 0; index < PLAMEN_SERVICE_MAX_PENDING_AUTHORITIES; ++index) {
        struct plamen_pending_authority *pending =
            &pending_authorities[index];
        if (pending->state == PLAMEN_PENDING_AUTHORITY_RESERVED
            && constant_equal(pending->registration_sha256,
                registration_sha256, 32)) {
            pending_authority_reset_locked(pending);
            break;
        }
    }
    pthread_mutex_unlock(&pending_authorities_lock);
}

static int
pending_authority_available(const uint8_t registration_sha256[32],
    const struct plamen_broker_v2_peer_identity *child)
{
    size_t index;
    int result = -1;
    if (pthread_mutex_lock(&pending_authorities_lock) != 0)
        return -1;
    for (index = 0; index < PLAMEN_SERVICE_MAX_PENDING_AUTHORITIES; ++index) {
        struct plamen_pending_authority *pending =
            &pending_authorities[index];
        if (pending->state == PLAMEN_PENDING_AUTHORITY_ACTIVE
            && constant_equal(pending->registration_sha256,
                registration_sha256, 32)
            && same_peer(&pending->suspended_child, child)
            && authority_fd_array_revalidate(pending->presence_mask,
                pending->descriptors, pending->fds) == 0) {
            result = 0;
            break;
        }
    }
    pthread_mutex_unlock(&pending_authorities_lock);
    return result;
}

static int
pending_authority_take_claimed(const uint8_t registration_sha256[32],
    uint16_t *presence_mask,
    int fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT],
    struct plamen_broker_v2_fd_metadata
        descriptors[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT])
{
    size_t index;
    int result = -1;
    for (index = 0; index < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++index)
        fds[index] = -1;
    if (pthread_mutex_lock(&pending_authorities_lock) != 0)
        return -1;
    for (index = 0; index < PLAMEN_SERVICE_MAX_PENDING_AUTHORITIES; ++index) {
        struct plamen_pending_authority *pending =
            &pending_authorities[index];
        size_t slot;
        if (pending->state != PLAMEN_PENDING_AUTHORITY_CLAIMING
            || !constant_equal(pending->registration_sha256,
                registration_sha256, 32))
            continue;
        if (authority_fd_array_revalidate(pending->presence_mask,
                pending->descriptors, pending->fds) != 0)
            break;
        *presence_mask = pending->presence_mask;
        for (slot = 0;
             slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++slot) {
            fds[slot] = pending->fds[slot];
            pending->fds[slot] = -1;
            descriptors[slot] = pending->descriptors[slot];
        }
        pending_authority_reset_locked(pending);
        result = 0;
        break;
    }
    pthread_mutex_unlock(&pending_authorities_lock);
    return result;
}

static void
close_all_pending_authorities(void)
{
    size_t index;
    if (pthread_mutex_lock(&pending_authorities_lock) != 0)
        return;
    for (index = 0; index < PLAMEN_SERVICE_MAX_PENDING_AUTHORITIES; ++index)
        pending_authority_reset_locked(&pending_authorities[index]);
    pthread_mutex_unlock(&pending_authorities_lock);
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
sha256_retained_regular(int descriptor, size_t maximum_size,
    uint8_t digest[32])
{
    struct stat before, after;
    uint8_t *bytes = NULL;
    size_t size, offset = 0;
    int flags, result = -1;

    if (descriptor < 0 || digest == NULL || maximum_size == 0
        || (flags = fcntl(descriptor, F_GETFL)) < 0
        || (flags & O_ACCMODE) != O_RDONLY
        || fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_nlink == 0 || before.st_size <= 0
        || (uint64_t)before.st_size > maximum_size)
        return -1;
    size = (size_t)before.st_size;
    bytes = malloc(size);
    if (bytes == NULL)
        return -1;
    while (offset < size) {
        ssize_t amount = pread(descriptor, bytes + offset, size - offset,
            (off_t)offset);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0)
            goto done;
        offset += (size_t)amount;
    }
    if (fstat(descriptor, &after) != 0 || !same_vnode(&before, &after)
        || plamen_broker_v2_sha256(bytes, size, digest) != 0)
        goto done;
    result = 0;
done:
    plamen_broker_v2_secure_zero(bytes, size);
    free(bytes);
    if (result != 0)
        plamen_broker_v2_secure_zero(digest, 32);
    return result;
}

static int
validate_registration_authority_fds(
    int authority_fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT])
{
    struct plamen_broker_v2_external_authority_facts facts;
    uint8_t config_sha256[32];
    int result = -1;

    memset(&facts, 0, sizeof(facts));
    memset(config_sha256, 0, sizeof(config_sha256));
    if (plamen_install_receipt_member_revalidate(
            authority_fds[PLAMEN_BROKER_V2_RETAINED_ROLE5_SCHEMA],
            &service_authority.receipt.members[
                PLAMEN_INSTALL_MEMBER_SCHEMA - 1]) != 0
        || plamen_install_receipt_member_revalidate(
            authority_fds[PLAMEN_BROKER_V2_RETAINED_RUNTIME_MANIFEST],
            &service_authority.receipt.members[
                PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST - 1]) != 0
        || sha256_retained_regular(
            authority_fds[PLAMEN_BROKER_V2_RETAINED_CONFIG],
            PLAMEN_SERVICE_CONFIG_MAX, config_sha256) != 0
        || plamen_broker_v2_external_authority_validate(
            authority_fds[PLAMEN_BROKER_V2_RETAINED_RUNTIME_MANIFEST],
            service_authority.receipt.members[
                PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST - 1].sha256,
            authority_fds[PLAMEN_BROKER_V2_RETAINED_PROVIDER],
            authority_fds[PLAMEN_BROKER_V2_RETAINED_BACKEND],
            authority_fds[PLAMEN_BROKER_V2_RETAINED_BACKEND_PROFILE],
            authority_fds[PLAMEN_BROKER_V2_RETAINED_EGRESS_POLICY],
            authority_fds[PLAMEN_BROKER_V2_RETAINED_EGRESS_ADMISSION],
            config_sha256, &facts) != 0)
        goto done;
    result = 0;
done:
    plamen_broker_v2_secure_zero(&facts, sizeof(facts));
    plamen_broker_v2_secure_zero(config_sha256, sizeof(config_sha256));
    return result;
}

static void
hex_sha256_text(const uint8_t digest[32], char output[72])
{
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    memcpy(output, "sha256:", 7);
    for (index = 0; index < 32; ++index) {
        output[7 + index * 2] = alphabet[digest[index] >> 4];
        output[8 + index * 2] = alphabet[digest[index] & 15];
    }
    output[71] = '\0';
}

static int
worker_external_authority_facts(struct plamen_service_session_worker *worker,
    struct plamen_broker_v2_external_authority_facts *facts)
{
    uint8_t config_sha256[32];
    int result = -1;
    memset(facts, 0, sizeof(*facts)); memset(config_sha256, 0, 32);
    if (sha256_retained_regular(
            worker->authority_fds[PLAMEN_BROKER_V2_RETAINED_CONFIG],
            PLAMEN_SERVICE_CONFIG_MAX, config_sha256) == 0
        && plamen_broker_v2_external_authority_validate(
            worker->authority_fds[PLAMEN_BROKER_V2_RETAINED_RUNTIME_MANIFEST],
            service_authority.receipt.members[
                PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST - 1].sha256,
            worker->authority_fds[PLAMEN_BROKER_V2_RETAINED_PROVIDER],
            worker->authority_fds[PLAMEN_BROKER_V2_RETAINED_BACKEND],
            worker->authority_fds[PLAMEN_BROKER_V2_RETAINED_BACKEND_PROFILE],
            worker->authority_fds[PLAMEN_BROKER_V2_RETAINED_EGRESS_POLICY],
            worker->authority_fds[PLAMEN_BROKER_V2_RETAINED_EGRESS_ADMISSION],
            config_sha256, facts) == 0)
        result = 0;
    plamen_broker_v2_secure_zero(config_sha256, sizeof(config_sha256));
    if (result != 0) plamen_broker_v2_secure_zero(facts, sizeof(*facts));
    return result;
}

static void
close_apple_closure(int closure[PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT],
    int *cwd_fd, int *stdin_fd)
{
    size_t index;
    for (index = 0; index < PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT;
         ++index) {
        if (closure[index] >= 0) (void)close(closure[index]);
        closure[index] = -1;
    }
    if (*cwd_fd >= 0) (void)close(*cwd_fd);
    if (*stdin_fd >= 0) (void)close(*stdin_fd);
    *cwd_fd = -1; *stdin_fd = -1;
}

static int
open_apple_closure(
    int closure[PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT],
    int *cwd_fd, int *stdin_fd)
{
    static const char *const paths[
        PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT - 1U] = {
        PLAMEN_APPLE_SERVER_PATH, PLAMEN_APPLE_BOM_PATH,
        PLAMEN_APPLE_CORE_IMAGES_PATH, PLAMEN_APPLE_NETWORK_VMNET_PATH,
        PLAMEN_APPLE_RUNTIME_LINUX_PATH, PLAMEN_APPLE_MACHINE_APISERVER_PATH,
        PLAMEN_APPLE_RECEIPT_PATH
    };
    struct passwd password, *found = NULL;
    char password_buffer[4096], kernel[PATH_MAX];
    size_t index;
    int kernel_size;
    memset(password_buffer, 0, sizeof(password_buffer));
    memset(kernel, 0, sizeof(kernel));
    for (index = 0; index < PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT;
         ++index) closure[index] = -1;
    *cwd_fd = -1; *stdin_fd = -1;
    for (index = 0; index < sizeof(paths) / sizeof(paths[0]); ++index) {
        closure[index] = open(paths[index], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (closure[index] < 0) goto invalid;
    }
    if (getpwuid_r(geteuid(), &password, password_buffer,
            sizeof(password_buffer), &found) != 0 || found == NULL
        || found->pw_dir == NULL || found->pw_dir[0] != '/') goto invalid;
    kernel_size = snprintf(kernel, sizeof(kernel), "%s%s", found->pw_dir,
        PLAMEN_APPLE_KERNEL_SUFFIX);
    if (kernel_size <= 0 || (size_t)kernel_size >= sizeof(kernel)) goto invalid;
    closure[PLAMEN_BROKER_V2_APPLE_CONTAINER_KERNEL] = open(kernel,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    *cwd_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    *stdin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (closure[PLAMEN_BROKER_V2_APPLE_CONTAINER_KERNEL] < 0
        || *cwd_fd < 0 || *stdin_fd < 0) goto invalid;
    plamen_broker_v2_secure_zero(password_buffer, sizeof(password_buffer));
    plamen_broker_v2_secure_zero(kernel, sizeof(kernel));
    return 0;
invalid:
    close_apple_closure(closure, cwd_fd, stdin_fd);
    plamen_broker_v2_secure_zero(password_buffer, sizeof(password_buffer));
    plamen_broker_v2_secure_zero(kernel, sizeof(kernel));
    return -1;
}

static int
admit_worker_apple_container(struct plamen_service_session_worker *worker,
    const struct plamen_broker_v2_commitment *commitment,
    struct plamen_broker_v2_apple_container_admission_receipt *receipt)
{
    struct plamen_broker_v2_external_authority_facts facts;
    struct plamen_broker_v2_apple_container_admission_spec spec;
    int closure[PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT];
    char index[72], manifest[72];
    uint8_t provider_sha256[32];
    int cwd_fd = -1, stdin_fd = -1, result = -1;
    size_t role;
    memset(&facts, 0, sizeof(facts)); memset(&spec, 0, sizeof(spec));
    memset(receipt, 0, sizeof(*receipt)); memset(index, 0, sizeof(index));
    memset(manifest, 0, sizeof(manifest)); memset(provider_sha256, 0, 32);
    for (role = 0; role < PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT;
         ++role) closure[role] = -1;
    if (worker_external_authority_facts(worker, &facts) != 0
        || strcmp(facts.provider_identifier, "com.apple.container.cli") != 0
        || strcmp(facts.provider_team, "UPBK2H6LZM") != 0
        || strcmp(facts.provider_selector, "apple-container-v2") != 0
        || strncmp(facts.provider_version,
            "container CLI version ", 22U) != 0
        || all_zero_32(facts.provider_sha256)
        || !constant_equal(facts.image_closure_sha256,
            commitment->image_closure_sha256, 32)
        || open_apple_closure(closure, &cwd_fd, &stdin_fd) != 0)
        goto done;
    memcpy(provider_sha256, facts.provider_sha256, 32);
    spec.version = PLAMEN_BROKER_V2_APPLE_CONTAINER_VERSION;
    spec.cli_fd = worker->authority_fds[PLAMEN_BROKER_V2_RETAINED_PROVIDER];
    spec.cli_path = PLAMEN_APPLE_CLI_PATH;
    spec.cwd_fd = cwd_fd; spec.stdin_fd = stdin_fd; spec.timeout_seconds = 30;
    memcpy(spec.cli_sha256, provider_sha256, 32);
    memcpy(spec.request_fingerprint_sha256, commitment->request_fingerprint, 32);
    memcpy(spec.provider_provenance_sha256,
        commitment->provider_provenance_sha256, 32);
    memcpy(spec.image_closure_sha256, facts.image_closure_sha256, 32);
    for (role = 0; role < PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT;
         ++role) {
        spec.closure[role].fd = closure[role];
        if (role == PLAMEN_BROKER_V2_APPLE_CONTAINER_PACKAGE_RECEIPT) {
            if (sha256_retained_regular(closure[role], 4096,
                    spec.closure[role].expected_sha256) != 0) goto done;
        } else if (role == PLAMEN_BROKER_V2_APPLE_CONTAINER_KERNEL) {
            if (plamen_broker_v2_apple_container_production_closure_sha256(
                    (uint32_t)role,
                    spec.closure[role].expected_sha256) != 0) goto done;
        } else {
            if (sha256_retained_regular(closure[role], 512U * 1024U * 1024U,
                    spec.closure[role].expected_sha256) != 0) goto done;
        }
    }
    spec.package_signed = 1; spec.package_notarized = 1;
    spec.package_timestamped = 1;
    spec.implicit_kernel_install_disabled = 1;
    hex_sha256_text(facts.image_index_sha256, index);
    hex_sha256_text(facts.image_manifest_sha256, manifest);
    spec.runtime_image_reference = facts.image_reference;
    spec.runtime_index_digest = index;
    spec.runtime_manifest_digest = manifest;
    if (plamen_broker_v2_apple_container_admit(&spec, receipt)
            != PLAMEN_BROKER_V2_APPLE_CONTAINER_OK)
        goto done;
    result = 0;
done:
    close_apple_closure(closure, &cwd_fd, &stdin_fd);
    plamen_broker_v2_secure_zero(&facts, sizeof(facts));
    plamen_broker_v2_secure_zero(&spec, sizeof(spec));
    plamen_broker_v2_secure_zero(index, sizeof(index));
    plamen_broker_v2_secure_zero(manifest, sizeof(manifest));
    plamen_broker_v2_secure_zero(provider_sha256, sizeof(provider_sha256));
    if (result != 0) plamen_broker_v2_secure_zero(receipt, sizeof(*receipt));
    return result;
}

static int
pid_identity(pid_t pid, struct plamen_broker_v2_peer_identity *identity,
    uint32_t *status)
{
    struct proc_bsdinfo information;
    int amount;

    memset(identity, 0, sizeof(*identity));
    memset(&information, 0, sizeof(information));
    if (pid <= 0)
        return -1;
    amount = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &information,
        (int)sizeof(information));
    if (amount != (int)sizeof(information)
        || information.pbi_pid != (uint32_t)pid
        || information.pbi_start_tvsec == 0)
        return -1;
    identity->pid = (uint64_t)pid;
    identity->uid = information.pbi_uid;
    identity->gid = information.pbi_gid;
    identity->birth_kind = PLAMEN_BROKER_V2_BIRTH_DARWIN_EPOCH;
    identity->birth_primary = information.pbi_start_tvsec;
    identity->birth_secondary =
        (uint64_t)information.pbi_start_tvusec * UINT64_C(1000);
    if (status != NULL)
        *status = information.pbi_status;
    return identity->birth_secondary < UINT64_C(1000000000) ? 0 : -1;
}

static int
connection_peer_identity(xpc_connection_t connection,
    struct plamen_broker_v2_peer_identity *identity)
{
    pid_t pid = xpc_connection_get_pid(connection);
    uid_t uid = xpc_connection_get_euid(connection);
    gid_t gid = xpc_connection_get_egid(connection);

    return pid > 0 && uid != (uid_t)-1 && gid != (gid_t)-1
        && pid_identity(pid, identity, NULL) == 0
        && identity->uid == uid && identity->gid == gid ? 0 : -1;
}

static int
copy_cf_string(CFTypeRef value, char *output, size_t output_size)
{
    if (value == NULL) {
        output[0] = '\0';
        return 0;
    }
    return CFGetTypeID(value) == CFStringGetTypeID()
        && CFStringGetCString((CFStringRef)value, output,
            (CFIndex)output_size, kCFStringEncodingUTF8) ? 0 : -1;
}

static int
copy_signing_fields(CFDictionaryRef information,
    struct plamen_service_code_identity *identity)
{
    CFTypeRef unique;
    CFIndex size;
    memset(identity, 0, sizeof(*identity));
    if (information == NULL
        || CFGetTypeID(information) != CFDictionaryGetTypeID()
        || copy_cf_string(CFDictionaryGetValue(information,
                kSecCodeInfoIdentifier), identity->identifier,
            sizeof(identity->identifier)) != 0
        || copy_cf_string(CFDictionaryGetValue(information,
                kSecCodeInfoTeamIdentifier), identity->team,
            sizeof(identity->team)) != 0)
        return -1;
    unique = CFDictionaryGetValue(information, kSecCodeInfoUnique);
    if (unique == NULL || CFGetTypeID(unique) != CFDataGetTypeID())
        return -1;
    size = CFDataGetLength((CFDataRef)unique);
    if (!(size == 20 || size == 32))
        return -1;
    CFDataGetBytes((CFDataRef)unique, CFRangeMake(0, size), identity->cdhash);
    identity->cdhash_size = (uint32_t)size;
    return 0;
}

static int
dynamic_code_identity(pid_t pid, const char *identifier,
    struct plamen_service_code_identity *identity)
{
    CFNumberRef pid_number = NULL;
    CFDictionaryRef attributes = NULL;
    CFStringRef requirement_string = NULL;
    SecRequirementRef requirement = NULL;
    SecCodeRef guest = NULL;
    CFDictionaryRef information = NULL;
    const void *keys[1] = { kSecGuestAttributePid };
    const void *values[1];
    char requirement_text[256];
    int32_t exact_pid = pid;
    int result = -1;

    if (identifier == NULL
        || snprintf(requirement_text, sizeof(requirement_text),
            "identifier \"%s\"", identifier) >= (int)sizeof(requirement_text))
        return -1;
    pid_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type,
        &exact_pid);
    requirement_string = CFStringCreateWithCString(kCFAllocatorDefault,
        requirement_text, kCFStringEncodingUTF8);
    if (pid_number == NULL || requirement_string == NULL)
        goto done;
    values[0] = pid_number;
    attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (attributes == NULL
        || SecRequirementCreateWithString(requirement_string,
            kSecCSDefaultFlags, &requirement) != errSecSuccess
        || SecCodeCopyGuestWithAttributes(NULL, attributes,
            kSecCSDefaultFlags, &guest) != errSecSuccess
        || SecCodeCheckValidity(guest, kSecCSStrictValidate,
            requirement) != errSecSuccess
        || SecCodeCopySigningInformation(guest, kSecCSSigningInformation,
            &information) != errSecSuccess
        || copy_signing_fields(information, identity) != 0)
        goto done;
    result = 0;
done:
    if (information != NULL)
        CFRelease(information);
    if (guest != NULL)
        CFRelease(guest);
    if (requirement != NULL)
        CFRelease(requirement);
    if (attributes != NULL)
        CFRelease(attributes);
    if (requirement_string != NULL)
        CFRelease(requirement_string);
    if (pid_number != NULL)
        CFRelease(pid_number);
    return result;
}

static int
static_code_identity(const char *path, const char *identifier,
    struct plamen_service_code_identity *identity)
{
    CFURLRef url = NULL;
    CFStringRef requirement_string = NULL;
    SecRequirementRef requirement = NULL;
    SecStaticCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    char requirement_text[256];
    int result = -1;

    if (path == NULL || identifier == NULL
        || snprintf(requirement_text, sizeof(requirement_text),
            "identifier \"%s\"", identifier) >= (int)sizeof(requirement_text))
        return -1;
    url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
        (const UInt8 *)path, (CFIndex)strlen(path), false);
    requirement_string = CFStringCreateWithCString(kCFAllocatorDefault,
        requirement_text, kCFStringEncodingUTF8);
    if (url == NULL || requirement_string == NULL
        || SecRequirementCreateWithString(requirement_string,
            kSecCSDefaultFlags, &requirement) != errSecSuccess
        || SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags,
            &code) != errSecSuccess
        || SecStaticCodeCheckValidity(code, kSecCSStrictValidate,
            requirement) != errSecSuccess
        || SecCodeCopySigningInformation(code, kSecCSSigningInformation,
            &information) != errSecSuccess
        || copy_signing_fields(information, identity) != 0)
        goto done;
    result = 0;
done:
    if (information != NULL)
        CFRelease(information);
    if (code != NULL)
        CFRelease(code);
    if (requirement != NULL)
        CFRelease(requirement);
    if (requirement_string != NULL)
        CFRelease(requirement_string);
    if (url != NULL)
        CFRelease(url);
    return result;
}

static int
identity_matches_member(const struct plamen_service_code_identity *identity,
    const struct plamen_install_receipt_member *member)
{
    return identity->cdhash_size == member->cdhash_size
        && constant_equal(identity->cdhash, member->cdhash,
            identity->cdhash_size)
        && strcmp(identity->identifier, member->signing_identifier) == 0
        && strcmp(identity->team, member->team_identifier) == 0;
}

static int
admit_peer_code(xpc_connection_t peer, uint16_t member_role)
{
    struct plamen_service_code_identity identity;
    const struct plamen_install_receipt_member *member;
    struct plamen_broker_v2_peer_identity before, after;

    if (member_role == 0
        || member_role > PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT)
        return -1;
    member = &service_authority.receipt.members[member_role - 1];
    return connection_peer_identity(peer, &before) == 0
        && dynamic_code_identity((pid_t)before.pid,
            member->signing_identifier, &identity) == 0
        && identity_matches_member(&identity, member)
        && connection_peer_identity(peer, &after) == 0
        && same_peer(&before, &after) ? 0 : -1;
}

static int
read_exact_file(int fd, uint8_t *output, size_t size)
{
    struct stat before, after;
    size_t offset = 0;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size != (off_t)size || before.st_nlink != 1)
        return -1;
    while (offset < size) {
        ssize_t amount;
        do {
            amount = pread(fd, output + offset, size - offset, (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0)
            return -1;
        offset += (size_t)amount;
    }
    return pread(fd, output, 1, (off_t)size) == 0
        && fstat(fd, &after) == 0 && same_vnode(&before, &after) ? 0 : -1;
}

static int
open_relative_file(int root_fd, const char *relative, int *output)
{
    char copy[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char *part, *slash;
    int current = -1, next = -1, result = -1;

    *output = -1;
    if (root_fd < 0 || relative == NULL || relative[0] == '\0'
        || relative[0] == '/' || strlen(relative) >= sizeof(copy))
        return -1;
    memcpy(copy, relative, strlen(relative) + 1);
    current = openat(root_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0)
        goto done;
    part = copy;
    while ((slash = strchr(part, '/')) != NULL) {
        *slash = '\0';
        if (part[0] == '\0' || strcmp(part, ".") == 0
            || strcmp(part, "..") == 0)
            goto done;
        next = openat(current, part,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0)
            goto done;
        close(current);
        current = next;
        next = -1;
        part = slash + 1;
    }
    if (part[0] == '\0' || strcmp(part, ".") == 0
        || strcmp(part, "..") == 0)
        goto done;
    next = openat(current, part, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (next < 0)
        goto done;
    *output = next;
    next = -1;
    result = 0;
done:
    if (next >= 0)
        close(next);
    if (current >= 0)
        close(current);
    memset(copy, 0, sizeof(copy));
    return result;
}

static int
hex_matches_basename(const char *path, const uint8_t digest[32])
{
    static const char alphabet[] = "0123456789abcdef";
    const char *basename = strrchr(path, '/');
    size_t index;
    if (basename == NULL || strlen(++basename) != 64)
        return 0;
    for (index = 0; index < 32; ++index) {
        if (basename[index * 2] != alphabet[digest[index] >> 4]
            || basename[index * 2 + 1] != alphabet[digest[index] & 15])
            return 0;
    }
    return 1;
}

static int
private_directory_fd(int fd)
{
    struct stat information;
    return fd >= 0 && fstat(fd, &information) == 0
        && S_ISDIR(information.st_mode) && information.st_uid == geteuid()
        && (information.st_mode & 0777) == 0700;
}

static int
open_install_root(int generation_fd, int *root_fd)
{
    struct stat generations_info;
    int generations_fd = -1, candidate = -1, result = -1;

    *root_fd = -1;
    generations_fd = openat(generation_fd, "..",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (generations_fd < 0 || fstat(generations_fd, &generations_info) != 0
        || !S_ISDIR(generations_info.st_mode)
        || generations_info.st_uid != geteuid()
        || (generations_info.st_mode & 0022) != 0)
        goto done;
    candidate = openat(generations_fd, "..",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (candidate < 0 || !private_directory_fd(candidate))
        goto done;
    *root_fd = candidate;
    candidate = -1;
    result = 0;
done:
    if (candidate >= 0)
        close(candidate);
    if (generations_fd >= 0)
        close(generations_fd);
    return result;
}

static int
open_state_parent(int generation_fd, int *state_fd)
{
    int root_fd = -1, result = -1;
    *state_fd = -1;
    if (open_install_root(generation_fd, &root_fd) != 0)
        goto done;
    if (mkdirat(root_fd, PLAMEN_SERVICE_STATE_DIRECTORY, 0700) != 0
        && errno != EEXIST)
        goto done;
    *state_fd = openat(root_fd, PLAMEN_SERVICE_STATE_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (*state_fd < 0 || !private_directory_fd(*state_fd)) {
        if (*state_fd >= 0)
            close(*state_fd);
        *state_fd = -1;
        goto done;
    }
    if (fsync(root_fd) != 0)
        goto done;
    result = 0;
done:
    if (result != 0 && *state_fd >= 0) {
        close(*state_fd);
        *state_fd = -1;
    }
    if (root_fd >= 0)
        close(root_fd);
    return result;
}

static void
close_service_authority(struct plamen_service_authority *authority)
{
    size_t index;
    close_all_pending_authorities();
    if (authority->custody_client != NULL)
        plamen_broker_v2_process_custody_client_close(
            authority->custody_client);
    if (authority->process_custodian != NULL)
        plamen_broker_v2_process_custodian_close(
            authority->process_custodian);
    if (authority->store != NULL)
        plamen_broker_v2_service_store_close(authority->store);
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        if (authority->member_fds[index] >= 0)
            close(authority->member_fds[index]);
    }
    if (authority->specialized_authority_fd >= 0)
        close(authority->specialized_authority_fd);
    if (authority->state_parent_fd >= 0)
        close(authority->state_parent_fd);
    if (authority->generation_fd >= 0)
        close(authority->generation_fd);
    plamen_broker_v2_secure_zero(authority, sizeof(*authority));
    authority->generation_fd = -1;
    authority->specialized_authority_fd = -1;
    authority->state_parent_fd = -1;
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; ++index)
        authority->member_fds[index] = -1;
}

static int
admit_service_authority(struct plamen_service_authority *authority,
    int custody_daemon_mode)
{
    struct passwd password, *password_result = NULL;
    const struct plamen_install_receipt_launchd_plist *selected_plist;
    const char *selected_plist_suffix, *selected_plist_relative;
    struct plamen_service_code_identity static_identity, dynamic_identity;
    struct stat self_info, service_info, receipt_info, plist_info;
    uint8_t receipt_bytes[PLAMEN_INSTALL_RECEIPT_SIZE];
    uint8_t projection_schema_sha256[32], plist_sha256[32];
    char self_path[PROC_PIDPATHINFO_MAXSIZE], generation_path[PROC_PIDPATHINFO_MAXSIZE];
    char expected_plist[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char expected_prefix[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char password_buffer[4096];
    size_t self_length, generation_length, index;
    int self_fd = -1, receipt_fd = -1, plist_fd = -1;
    int install_root_fd = -1;
    int result = PLAMEN_SERVICE_HARDSTOP;

    memset(authority, 0, sizeof(*authority));
    selected_plist = custody_daemon_mode
        ? &authority->receipt.custody_launchd_plist
        : &authority->receipt.broker_launchd_plist;
    selected_plist_suffix = custody_daemon_mode
        ? PLAMEN_CUSTODY_PLIST_SUFFIX : PLAMEN_SERVICE_PLIST_SUFFIX;
    selected_plist_relative = custody_daemon_mode
        ? "Library/LaunchAgents/com.plamen.audit.process-custody.v2.plist"
        : "Library/LaunchAgents/com.plamen.audit.broker.v2.plist";
    authority->generation_fd = -1;
    authority->specialized_authority_fd = -1;
    authority->state_parent_fd = -1;
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; ++index)
        authority->member_fds[index] = -1;
    memset(self_path, 0, sizeof(self_path));
    if (proc_pidpath(getpid(), self_path, sizeof(self_path)) <= 0
        || getpwuid_r(getuid(), &password, password_buffer,
            sizeof(password_buffer), &password_result) != 0
        || password_result == NULL || password.pw_dir == NULL
        || snprintf(expected_prefix, sizeof(expected_prefix),
            "%s/.local/share/plamen/generations/", password.pw_dir)
            >= (int)sizeof(expected_prefix))
        goto done;
    self_length = strlen(self_path);
    if (self_length <= strlen(PLAMEN_SERVICE_SUFFIX)
        || strcmp(self_path + self_length - strlen(PLAMEN_SERVICE_SUFFIX),
            PLAMEN_SERVICE_SUFFIX) != 0)
        goto done;
    generation_length = self_length - strlen(PLAMEN_SERVICE_SUFFIX);
    if (generation_length == 0 || generation_length >= sizeof(generation_path)
        || generation_length <= strlen(expected_prefix)
        || memcmp(self_path, expected_prefix, strlen(expected_prefix)) != 0)
        goto done;
    memcpy(generation_path, self_path, generation_length);
    generation_path[generation_length] = '\0';
    authority->generation_fd = open(generation_path,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    self_fd = open(self_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (authority->generation_fd < 0 || self_fd < 0
        || open_install_root(authority->generation_fd,
            &install_root_fd) != 0
        || open_relative_file(install_root_fd,
            PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH, &receipt_fd) != 0
        || fstat(receipt_fd, &receipt_info) != 0
        || !S_ISREG(receipt_info.st_mode) || receipt_info.st_nlink != 1
        || receipt_info.st_uid != geteuid()
        || (receipt_info.st_mode & 0777) != 0400
        || read_exact_file(receipt_fd, receipt_bytes, sizeof(receipt_bytes)) != 0
        || plamen_install_receipt_decode_exact(receipt_bytes,
            sizeof(receipt_bytes), &authority->receipt) != 0
        || strcmp(authority->receipt.generation_path, generation_path) != 0
        || !hex_matches_basename(generation_path,
            authority->receipt.generation_id_sha256)
        || CC_SHA256(receipt_bytes, sizeof(receipt_bytes),
            authority->installation_receipt_sha256)
            != authority->installation_receipt_sha256
        || CC_SHA256(PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA,
            (CC_LONG)strlen(PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA),
            projection_schema_sha256) != projection_schema_sha256
        || !constant_equal(projection_schema_sha256,
            authority->receipt.projection_schema_sha256, 32)
        || !constant_equal(authority->receipt.protocol_schema_sha256,
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_SHARED_ABI - 1].sha256,
            32))
        goto done;
    if (snprintf(expected_plist, sizeof(expected_plist), "%s%s",
            generation_path, selected_plist_suffix)
            >= (int)sizeof(expected_plist)
        || strcmp(expected_plist, selected_plist->path) != 0
        || open_relative_file(authority->generation_fd,
            selected_plist_relative, &plist_fd) != 0
        || fstat(plist_fd, &plist_info) != 0
        || (uint64_t)plist_info.st_dev != selected_plist->device
        || (uint64_t)plist_info.st_ino != selected_plist->inode
        || (uint64_t)plist_info.st_size != selected_plist->size
        || (uint32_t)(plist_info.st_mode & 07777)
            != selected_plist->mode
        || plist_info.st_uid != selected_plist->uid
        || plist_info.st_gid != selected_plist->gid)
        goto done;
    /* Reuse the descriptor-hashing verifier through a temporary roster row. */
    {
        struct plamen_install_receipt_member plist_member;
        memset(&plist_member, 0, sizeof(plist_member));
        memcpy(plist_member.sha256, selected_plist->sha256, 32);
        plist_member.size = selected_plist->size;
        plist_member.device = selected_plist->device;
        plist_member.inode = selected_plist->inode;
        plist_member.mode = selected_plist->mode;
        plist_member.uid = selected_plist->uid;
        plist_member.gid = selected_plist->gid;
        if (plamen_install_receipt_member_revalidate(plist_fd,
                &plist_member) != 0)
            goto done;
        memcpy(plist_sha256, plist_member.sha256, 32);
    }
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        if (plamen_install_receipt_open_member(authority->generation_fd,
                &authority->receipt.members[index],
                &authority->member_fds[index]) != 0)
            goto done;
    }
    if (authority->receipt.specialized_present != 1U
        || plamen_install_receipt_open_specialized_authority(
            authority->generation_fd, &authority->receipt,
            &authority->specialized_authority_fd) != 0)
        goto done;
    if (fstat(self_fd, &self_info) != 0
        || fstat(authority->member_fds[PLAMEN_INSTALL_MEMBER_SERVICE - 1],
            &service_info) != 0 || !same_vnode(&self_info, &service_info)
        || static_code_identity(self_path,
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_SERVICE - 1]
                .signing_identifier, &static_identity) != 0
        || dynamic_code_identity(getpid(),
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_SERVICE - 1]
                .signing_identifier, &dynamic_identity) != 0
        || !identity_matches_member(&static_identity,
            &authority->receipt.members[PLAMEN_INSTALL_MEMBER_SERVICE - 1])
        || !identity_matches_member(&dynamic_identity,
            &authority->receipt.members[PLAMEN_INSTALL_MEMBER_SERVICE - 1])
        || open_state_parent(authority->generation_fd,
            &authority->state_parent_fd) != 0
        || plamen_broker_v2_service_store_open(authority->state_parent_fd,
            &authority->store) != PLAMEN_BROKER_V2_OK
        || (custody_daemon_mode
            && plamen_broker_v2_process_custodian_open(
                authority->state_parent_fd, &authority->process_custodian)
                != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK))
        goto done;
    memcpy(authority->installed_closure_sha256,
        authority->receipt.generation_id_sha256, 32);
    memcpy(authority->broker_closure_sha256,
        authority->receipt.members[PLAMEN_INSTALL_MEMBER_SERVICE - 1].sha256, 32);
    memcpy(authority->extension_closure_sha256,
        authority->receipt.members[PLAMEN_INSTALL_MEMBER_EXTENSION - 1].sha256, 32);
    memcpy(authority->interpreter_executable_sha256,
        authority->receipt.members[PLAMEN_INSTALL_MEMBER_PYTHON - 1].sha256, 32);
    memcpy(authority->python_entrypoint_sha256,
        authority->receipt.members[
            PLAMEN_INSTALL_MEMBER_OUTER_ENTRYPOINT - 1].sha256, 32);
    if (plamen_install_receipt_python_invocation_digests(&authority->receipt,
            authority->python_argv_sha256,
            authority->python_environment_sha256) != 0)
        goto done;
    if (snprintf(authority->admitted_peer_code_requirement,
            sizeof(authority->admitted_peer_code_requirement),
            "(identifier \"%s\") or (identifier \"%s\")",
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1]
                .signing_identifier,
            authority->receipt.members[PLAMEN_INSTALL_MEMBER_PYTHON - 1]
                .signing_identifier)
            >= (int)sizeof(authority->admitted_peer_code_requirement))
        goto done;
    result = 0;
done:
    if (install_root_fd >= 0)
        close(install_root_fd);
    if (plist_fd >= 0)
        close(plist_fd);
    if (receipt_fd >= 0)
        close(receipt_fd);
    if (self_fd >= 0)
        close(self_fd);
    plamen_broker_v2_secure_zero(receipt_bytes, sizeof(receipt_bytes));
    plamen_broker_v2_secure_zero(plist_sha256, sizeof(plist_sha256));
    if (result != 0)
        close_service_authority(authority);
    return result;
}

static int
authority_xpc_key(size_t slot, char key[16])
{
    int amount;
    if (slot >= PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT)
        return -1;
    amount = snprintf(key, 16, "%s%02zu",
        PLAMEN_BROKER_V2_XPC_KEY_AUTHORITY_PREFIX, slot);
    return amount > 0 && amount < 16 ? 0 : -1;
}

static int
exact_xpc_shape(xpc_object_t message, uint16_t type,
    const struct plamen_broker_v2_service_registration *registration)
{
    __block size_t count = 0;
    __block int envelope = 0, projection = 0, control = 0, key_pipe = 0;
    __block int valid = 1;
    __block uint16_t authority_mask = 0;
    size_t required = 1;

    if (type == PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
        || type == PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY) {
        if (registration == NULL)
            return 0;
        required = 2;
        for (size_t slot = 0;
             slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++slot)
            required += (registration->authority_presence_mask >> slot) & 1U;
    } else if (type == PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN
        || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN)
        required = 3;
    if (xpc_get_type(message) != XPC_TYPE_DICTIONARY)
        return 0;
    xpc_dictionary_apply(message, ^bool(const char *key, xpc_object_t value) {
        count++;
        if (strcmp(key, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE) == 0
            && xpc_get_type(value) == XPC_TYPE_DATA)
            envelope++;
        else if (strcmp(key, PLAMEN_BROKER_V2_XPC_KEY_REQUEST_PROJECTION) == 0
            && xpc_get_type(value) == XPC_TYPE_DATA)
            projection++;
        else if (strcmp(key, PLAMEN_BROKER_V2_XPC_KEY_CONTROL_SOCKET) == 0
            && xpc_get_type(value) == XPC_TYPE_FD)
            control++;
        else if (strcmp(key, PLAMEN_BROKER_V2_XPC_KEY_KEY_PIPE_READ) == 0
            && xpc_get_type(value) == XPC_TYPE_FD)
            key_pipe++;
        else {
            size_t slot;
            int matched = 0;
            for (slot = 0;
                 slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
                 ++slot) {
                char expected[16];
                if (authority_xpc_key(slot, expected) == 0
                    && strcmp(key, expected) == 0) {
                    uint16_t bit = (uint16_t)(UINT16_C(1) << slot);
                    matched = 1;
                    if (xpc_get_type(value) != XPC_TYPE_FD
                        || registration == NULL
                        || (registration->authority_presence_mask & bit) == 0
                        || (authority_mask & bit) != 0)
                        valid = 0;
                    else
                        authority_mask |= bit;
                    break;
                }
            }
            if (!matched)
                valid = 0;
        }
        return true;
    });
    return valid && count == required && envelope == 1
        && projection == (registration != NULL)
        && control == (type == PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN
            || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN)
        && key_pipe == (type == PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN
            || type == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN)
        && (registration == NULL
            || authority_mask == registration->authority_presence_mask);
}

static int
duplicate_registration_authorities(xpc_object_t message,
    const struct plamen_broker_v2_service_registration *registration,
    int slot_fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT])
{
    struct plamen_broker_v2_fd_metadata
        compact_metadata[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    int compact_fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    size_t slot, count = 0;
    int result = -1;

    for (slot = 0; slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++slot)
        slot_fds[slot] = -1;
    for (slot = 0; slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
         ++slot) {
        char key[16];
        if ((registration->authority_presence_mask
                & (uint16_t)(UINT16_C(1) << slot)) == 0)
            continue;
        if (authority_xpc_key(slot, key) != 0)
            goto done;
        slot_fds[slot] = xpc_dictionary_dup_fd(message, key);
        if (slot_fds[slot] < 0)
            goto done;
        compact_fds[count] = slot_fds[slot];
        compact_metadata[count] = registration->authority_descriptors[slot];
        ++count;
    }
    if (plamen_broker_v2_validate_received_fds(compact_fds, count,
            compact_metadata, count) != 0) {
        /* The shared validator closes every compact descriptor on failure. */
        for (slot = 0; slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
             ++slot)
            slot_fds[slot] = -1;
        goto done;
    }
    result = 0;
done:
    if (result != 0)
        close_authority_fd_array(slot_fds);
    plamen_broker_v2_secure_zero(compact_metadata,
        sizeof(compact_metadata));
    return result;
}

static void
send_envelope(xpc_object_t request, uint16_t type,
    const struct plamen_broker_v2_service_envelope_view *request_view,
    const uint8_t *payload, uint32_t payload_size)
{
    uint8_t *envelope = NULL;
    size_t envelope_size = 0;
    xpc_object_t reply = NULL;
    xpc_connection_t peer;

    if (plamen_broker_v2_service_envelope_build(
            PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, type,
            request_view->transaction_nonce, request_view->invocation_nonce,
            payload, payload_size, 0, &envelope, &envelope_size) != 0)
        goto done;
    reply = xpc_dictionary_create_reply(request);
    if (reply == NULL)
        goto done;
    xpc_dictionary_set_data(reply, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE,
        envelope, envelope_size);
    peer = xpc_dictionary_get_remote_connection(request);
    if (peer != NULL)
        xpc_connection_send_message(peer, reply);
done:
    if (reply != NULL)
        xpc_release(reply);
    if (envelope != NULL) {
        plamen_broker_v2_secure_zero(envelope, envelope_size);
        free(envelope);
    }
}

static void
send_error(xpc_object_t request,
    const struct plamen_broker_v2_service_envelope_view *view,
    uint16_t code, uint16_t flags)
{
    struct plamen_broker_v2_service_error error;
    uint8_t payload[PLAMEN_BROKER_V2_SERVICE_ERROR_SIZE];
    memset(&error, 0, sizeof(error));
    error.code = code;
    error.flags = flags;
    error.failed_message_type = view->type;
    memcpy(error.request_envelope_sha256, view->envelope_sha256, 32);
    if (plamen_broker_v2_service_error_encode(&error, payload) == 0)
        send_envelope(request, PLAMEN_BROKER_V2_SERVICE_ERROR, view,
            payload, sizeof(payload));
    plamen_broker_v2_secure_zero(&error, sizeof(error));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
}

static int
suspended_child_matches(
    const struct plamen_broker_v2_peer_identity *expected)
{
    struct plamen_broker_v2_peer_identity observed;
    struct plamen_service_code_identity identity;
    const struct plamen_install_receipt_member *python;
    struct stat retained_info, observed_info;
    char path[PROC_PIDPATHINFO_MAXSIZE];
    int observed_fd = -1;
    uint32_t status = 0;
    int result = 0;

    python = &service_authority.receipt.members[PLAMEN_INSTALL_MEMBER_PYTHON - 1];
    memset(path, 0, sizeof(path));
    if (expected->pid == 0 || expected->pid > (uint64_t)INT32_MAX
        || pid_identity((pid_t)expected->pid, &observed, &status) != 0
        || status != SSTOP || !same_peer(&observed, expected)
        || proc_pidpath((pid_t)expected->pid, path, sizeof(path)) <= 0
        || (observed_fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || fstat(observed_fd, &observed_info) != 0
        || fstat(service_authority.member_fds[PLAMEN_INSTALL_MEMBER_PYTHON - 1],
            &retained_info) != 0 || !same_vnode(&observed_info, &retained_info)
        || plamen_install_receipt_member_revalidate(observed_fd, python) != 0
        || dynamic_code_identity((pid_t)expected->pid,
            python->signing_identifier, &identity) != 0
        || !identity_matches_member(&identity, python)
        || pid_identity((pid_t)expected->pid, &observed, &status) != 0
        || status != SSTOP || !same_peer(&observed, expected))
        result = -1;
    if (observed_fd >= 0)
        close(observed_fd);
    return result;
}

static void
handle_readiness(xpc_connection_t peer, xpc_object_t message,
    const struct plamen_broker_v2_service_envelope_view *view)
{
    struct plamen_broker_v2_service_readiness request;
    struct plamen_broker_v2_service_ready ready;
    uint8_t payload[PLAMEN_BROKER_V2_SERVICE_READY_SIZE];

    memset(&request, 0, sizeof(request));
    memset(&ready, 0, sizeof(ready));
    if (view->fd_count != 0 || !exact_xpc_shape(message, view->type, NULL)
        || admit_peer_code(peer, PLAMEN_INSTALL_MEMBER_LAUNCHER) != 0
        || plamen_broker_v2_service_readiness_decode(view->payload,
            view->payload_size, &request) != 0
        || !constant_equal(request.installed_closure_sha256,
            service_authority.installed_closure_sha256, 32)
        || !constant_equal(request.broker_closure_sha256,
            service_authority.broker_closure_sha256, 32)
        || !constant_equal(request.installation_receipt_sha256,
            service_authority.installation_receipt_sha256, 32)) {
        send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_CLOSURE,
            PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
        goto done;
    }
    memcpy(ready.request_envelope_sha256, view->envelope_sha256, 32);
    if (pid_identity(getpid(), &ready.service_peer, NULL) != 0)
        goto internal;
    memcpy(ready.installed_closure_sha256,
        service_authority.installed_closure_sha256, 32);
    memcpy(ready.broker_closure_sha256,
        service_authority.broker_closure_sha256, 32);
    memcpy(ready.installation_receipt_sha256,
        service_authority.installation_receipt_sha256, 32);
    if (plamen_broker_v2_service_ready_encode(&ready, payload) != 0)
        goto internal;
    send_envelope(message, PLAMEN_BROKER_V2_SERVICE_READY, view,
        payload, sizeof(payload));
    goto done;
internal:
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL,
        PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
done:
    plamen_broker_v2_secure_zero(&request, sizeof(request));
    plamen_broker_v2_secure_zero(&ready, sizeof(ready));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
}

static void
handle_registration(xpc_connection_t peer, xpc_object_t message,
    const struct plamen_broker_v2_service_envelope_view *view)
{
    struct plamen_broker_v2_service_registration registration;
    struct plamen_broker_v2_service_registration_ack acknowledgement;
    struct plamen_broker_v2_peer_identity actual_peer;
    const void *projection;
    size_t projection_size = 0;
    uint8_t payload[PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACK_SIZE];
    uint8_t registration_sha256[32];
    struct plamen_broker_v2_commitment commitment;
    int authority_fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    uint16_t expected_fd_count = 0;
    int reservation = -1, result;

    memset(&registration, 0, sizeof(registration));
    memset(&acknowledgement, 0, sizeof(acknowledgement));
    memset(&commitment, 0, sizeof(commitment));
    memset(registration_sha256, 0, sizeof(registration_sha256));
    for (size_t slot = 0;
         slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++slot)
        authority_fds[slot] = -1;
#if !defined(PLAMEN_BROKER_V2_EXACT_PROJECTION_SEMANTICS_VERSION) \
    || PLAMEN_BROKER_V2_EXACT_PROJECTION_SEMANTICS_VERSION != 1
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_UNSUPPORTED,
        PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
    goto done;
#endif
    projection = xpc_dictionary_get_data(message,
        PLAMEN_BROKER_V2_XPC_KEY_REQUEST_PROJECTION, &projection_size);
    if (plamen_broker_v2_service_registration_decode(view->payload,
            view->payload_size, &registration) != 0
        || plamen_broker_v2_service_registration_fd_count(&registration,
            &expected_fd_count) != 0
        || view->fd_count != expected_fd_count
        || !exact_xpc_shape(message, view->type, &registration)
        || projection == NULL
        || (view->type == PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
            ? (!all_zero_32(registration.prior_audit_checkpoint_sha256)
                || (registration.authority_presence_mask
                    & (uint16_t)(UINT16_C(1)
                        << PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT)) != 0)
            : (all_zero_32(registration.prior_audit_checkpoint_sha256)
                || (registration.authority_presence_mask
                    & (uint16_t)(UINT16_C(1)
                        << PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT)) == 0))
        || admit_peer_code(peer, PLAMEN_INSTALL_MEMBER_LAUNCHER) != 0
        || connection_peer_identity(peer, &actual_peer) != 0
        || !same_peer(&actual_peer, &registration.launcher)
        || !constant_equal(registration.installed_closure_sha256,
            service_authority.installed_closure_sha256, 32)
        || !constant_equal(registration.committed_audit_generation_sha256,
            service_authority.receipt.generation_id_sha256, 32)
        || projection_size != registration.request_projection_size
        || plamen_broker_v2_request_projection_validate_exact(projection,
            projection_size, registration.request_projection_sha256,
            registration.commitment, registration.commitment_size,
            registration.commitment_sha256, &commitment) != 0
        || !constant_equal(registration.audit_request_fingerprint,
            commitment.request_fingerprint, 32)
        || !constant_equal(registration.python_entrypoint_sha256,
            service_authority.python_entrypoint_sha256, 32)
        || !constant_equal(registration.python_argv_sha256,
            service_authority.python_argv_sha256, 32)
        || !constant_equal(registration.python_environment_sha256,
            service_authority.python_environment_sha256, 32)
        || !suspended_child_matches(&registration.suspended_child)
        || duplicate_registration_authorities(message, &registration,
            authority_fds) != 0
        || validate_registration_authority_fds(authority_fds) != 0
        || plamen_broker_v2_sha256(view->payload, view->payload_size,
            registration_sha256) != 0) {
        send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_PEER_AUTH,
            PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
        goto done;
    }
    reservation = pending_authority_reserve(registration_sha256,
        &registration, authority_fds);
    if (reservation < 0) {
        send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_DESCRIPTORS,
            PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
        goto done;
    }
    result = plamen_broker_v2_service_store_register(service_authority.store,
        &registration, view->envelope_sha256,
        service_authority.broker_closure_sha256, projection, projection_size,
        &acknowledgement);
    if (result != 0) {
        if (reservation == 0)
            pending_authority_abort_reservation(registration_sha256);
        send_error(message, view,
            result == PLAMEN_BROKER_V2_BURNED
                ? PLAMEN_BROKER_V2_SERVICE_ERR_REGISTRATION_USED
                : PLAMEN_BROKER_V2_SERVICE_ERR_DURABILITY,
            result == PLAMEN_BROKER_V2_BURNED
                ? PLAMEN_BROKER_V2_SERVICE_REGISTRATION_CONSUMED
                : PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
        goto done;
    }
    if (!constant_equal(acknowledgement.registration_sha256,
            registration_sha256, 32)
        || (reservation == 0
            && pending_authority_set_state(registration_sha256,
                PLAMEN_PENDING_AUTHORITY_RESERVED,
                PLAMEN_PENDING_AUTHORITY_ACTIVE) != 0)) {
        if (reservation == 0)
            pending_authority_abort_reservation(registration_sha256);
        send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL, 0);
        goto done;
    }
    if (plamen_broker_v2_service_registration_ack_encode(
            &acknowledgement, payload) != 0) {
        send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL, 0);
        goto done;
    }
    send_envelope(message, PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACCEPTED,
        view, payload, sizeof(payload));
done:
    close_authority_fd_array(authority_fds);
    plamen_broker_v2_secure_zero(&registration, sizeof(registration));
    plamen_broker_v2_secure_zero(&acknowledgement,
        sizeof(acknowledgement));
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    plamen_broker_v2_secure_zero(registration_sha256,
        sizeof(registration_sha256));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
}

static uint64_t
monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0)
        return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000)
        + (uint64_t)now.tv_nsec / UINT64_C(1000000);
}

static void
expire_challenges_locked(uint64_t now)
{
    size_t index;
    for (index = 0; index < PLAMEN_SERVICE_MAX_CHALLENGES; ++index) {
        if (pending_challenges[index].occupied
            && (now == 0 || now > pending_challenges[index].deadline_ms)) {
            plamen_broker_v2_secure_zero(&pending_challenges[index],
                sizeof(pending_challenges[index]));
        }
    }
}

static int
store_challenge(const struct plamen_broker_v2_peer_identity *peer,
    const struct plamen_broker_v2_service_session_challenge *challenge,
    const uint8_t envelope_sha256[32])
{
    size_t index;
    struct plamen_pending_challenge *free_slot = NULL;
    uint64_t now = monotonic_ms();
    if (now == 0 || peer == NULL || challenge == NULL
        || envelope_sha256 == NULL
        || pthread_mutex_lock(&pending_challenges_lock) != 0)
        return -1;
    expire_challenges_locked(now);
    for (index = 0; index < PLAMEN_SERVICE_MAX_CHALLENGES; ++index) {
        if (pending_challenges[index].occupied
            && (same_peer(&pending_challenges[index].peer, peer)
                || constant_equal(
                    pending_challenges[index].challenge.session_id,
                    challenge->session_id, 32)))
            plamen_broker_v2_secure_zero(&pending_challenges[index],
                sizeof(pending_challenges[index]));
        if (!pending_challenges[index].occupied && free_slot == NULL)
            free_slot = &pending_challenges[index];
    }
    if (free_slot != NULL) {
        free_slot->occupied = 1;
        free_slot->peer = *peer;
        free_slot->challenge = *challenge;
        memcpy(free_slot->envelope_sha256, envelope_sha256, 32);
        free_slot->deadline_ms = now
            + PLAMEN_BROKER_V2_SESSION_CHALLENGE_TIMEOUT_MS;
    }
    pthread_mutex_unlock(&pending_challenges_lock);
    return free_slot == NULL ? -1 : 0;
}

static int
take_challenge_for_peer(const struct plamen_broker_v2_peer_identity *peer,
    struct plamen_pending_challenge *out)
{
    size_t index, matches = 0;
    uint64_t now = monotonic_ms();
    if (out == NULL || peer == NULL || now == 0
        || pthread_mutex_lock(&pending_challenges_lock) != 0)
        return -1;
    memset(out, 0, sizeof(*out));
    expire_challenges_locked(now);
    for (index = 0; index < PLAMEN_SERVICE_MAX_CHALLENGES; ++index) {
        if (pending_challenges[index].occupied
            && same_peer(&pending_challenges[index].peer, peer)) {
            if (++matches == 1)
                *out = pending_challenges[index];
            plamen_broker_v2_secure_zero(&pending_challenges[index],
                sizeof(pending_challenges[index]));
        }
    }
    pthread_mutex_unlock(&pending_challenges_lock);
    if (matches != 1) {
        plamen_broker_v2_secure_zero(out, sizeof(*out));
        return -1;
    }
    return 0;
}

static void
expire_specialized_challenges_locked(uint64_t now)
{
    size_t index;
    for (index = 0; index < PLAMEN_SERVICE_MAX_SPECIALIZED_CHALLENGES;
         ++index) {
        if (pending_specialized_challenges[index].occupied
            && (now == 0
                || now > pending_specialized_challenges[index].deadline_ms))
            plamen_broker_v2_secure_zero(
                &pending_specialized_challenges[index],
                sizeof(pending_specialized_challenges[index]));
    }
}

static int
store_specialized_challenge(
    const struct plamen_broker_v2_peer_identity *peer,
    const struct plamen_broker_v2_service_specialized_session_challenge *challenge,
    const uint8_t envelope_sha256[32])
{
    struct plamen_pending_specialized_challenge *free_slot = NULL;
    size_t index;
    uint64_t now = monotonic_ms();
    if (peer == NULL || challenge == NULL || envelope_sha256 == NULL
        || now == 0
        || pthread_mutex_lock(&pending_specialized_challenges_lock) != 0)
        return -1;
    expire_specialized_challenges_locked(now);
    for (index = 0; index < PLAMEN_SERVICE_MAX_SPECIALIZED_CHALLENGES;
         ++index) {
        if (pending_specialized_challenges[index].occupied
            && (same_peer(&pending_specialized_challenges[index].peer, peer)
                || constant_equal(pending_specialized_challenges[index]
                        .challenge.lookup.specialized_session_id,
                    challenge->lookup.specialized_session_id, 32)))
            plamen_broker_v2_secure_zero(
                &pending_specialized_challenges[index],
                sizeof(pending_specialized_challenges[index]));
        if (!pending_specialized_challenges[index].occupied
            && free_slot == NULL)
            free_slot = &pending_specialized_challenges[index];
    }
    if (free_slot != NULL) {
        free_slot->occupied = 1;
        free_slot->deadline_ms = now
            + PLAMEN_BROKER_V2_SESSION_CHALLENGE_TIMEOUT_MS;
        free_slot->peer = *peer;
        free_slot->challenge = *challenge;
        memcpy(free_slot->envelope_sha256, envelope_sha256, 32);
    }
    pthread_mutex_unlock(&pending_specialized_challenges_lock);
    return free_slot == NULL ? -1 : 0;
}

static int
take_specialized_challenge_for_peer(
    const struct plamen_broker_v2_peer_identity *peer,
    struct plamen_pending_specialized_challenge *out)
{
    size_t index, matches = 0;
    uint64_t now = monotonic_ms();
    if (peer == NULL || out == NULL || now == 0
        || pthread_mutex_lock(&pending_specialized_challenges_lock) != 0)
        return -1;
    memset(out, 0, sizeof(*out));
    expire_specialized_challenges_locked(now);
    for (index = 0; index < PLAMEN_SERVICE_MAX_SPECIALIZED_CHALLENGES;
         ++index) {
        if (pending_specialized_challenges[index].occupied
            && same_peer(&pending_specialized_challenges[index].peer, peer)) {
            if (++matches == 1)
                *out = pending_specialized_challenges[index];
            plamen_broker_v2_secure_zero(
                &pending_specialized_challenges[index],
                sizeof(pending_specialized_challenges[index]));
        }
    }
    pthread_mutex_unlock(&pending_specialized_challenges_lock);
    if (matches != 1) {
        plamen_broker_v2_secure_zero(out, sizeof(*out));
        return -1;
    }
    return 0;
}

static void
handle_session_lookup(xpc_connection_t peer, xpc_object_t message,
    const struct plamen_broker_v2_service_envelope_view *view)
{
    struct plamen_broker_v2_service_session_lookup lookup;
    struct plamen_broker_v2_service_session_challenge challenge;
    struct plamen_broker_v2_service_registration registration;
    struct plamen_broker_v2_service_registration_ack registered;
    struct plamen_broker_v2_peer_identity actual_peer;
    uint8_t payload[PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE];
    uint8_t challenge_envelope_sha256[32];
    uint8_t *envelope = NULL;
    size_t envelope_size = 0;
    xpc_object_t reply = NULL;
    int result;

    memset(&lookup, 0, sizeof(lookup));
    memset(&challenge, 0, sizeof(challenge));
    memset(&registration, 0, sizeof(registration));
    memset(&registered, 0, sizeof(registered));
    if (view->fd_count != 0 || !exact_xpc_shape(message, view->type, NULL)
        || admit_peer_code(peer, PLAMEN_INSTALL_MEMBER_PYTHON) != 0
        || plamen_broker_v2_service_session_lookup_decode(view->payload,
            view->payload_size, &lookup) != 0
        || connection_peer_identity(peer, &actual_peer) != 0
        || !constant_equal(lookup.extension_closure_sha256,
            service_authority.extension_closure_sha256, 32)
        || !constant_equal(lookup.interpreter_executable_sha256,
            service_authority.interpreter_executable_sha256, 32)) {
        send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_PEER_AUTH,
            PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
        goto done;
    }
    result = plamen_broker_v2_service_store_lookup_unused(
        service_authority.store, &actual_peer, &registration, &registered);
    if (result != 0
        || pending_authority_available(registered.registration_sha256,
            &registration.suspended_child) != 0) {
        send_error(message, view,
            PLAMEN_BROKER_V2_SERVICE_ERR_REGISTRATION_MISSING,
            PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
        goto done;
    }
    memcpy(challenge.request_envelope_sha256, view->envelope_sha256, 32);
    memcpy(challenge.registration_sha256,
        registered.registration_sha256, 32);
    memcpy(challenge.committed_audit_generation_sha256,
        registration.committed_audit_generation_sha256, 32);
    memcpy(challenge.request_projection_sha256,
        registration.request_projection_sha256, 32);
    challenge.request_projection_size = registration.request_projection_size;
    memcpy(challenge.commitment_sha256,
        registration.commitment_sha256, 32);
    challenge.commitment_size = registration.commitment_size;
    memcpy(challenge.commitment, registration.commitment,
        registration.commitment_size);
    memcpy(challenge.installed_closure_sha256,
        service_authority.installed_closure_sha256, 32);
    memcpy(challenge.broker_closure_sha256,
        service_authority.broker_closure_sha256, 32);
    memcpy(challenge.extension_closure_sha256,
        lookup.extension_closure_sha256, 32);
    memcpy(challenge.interpreter_executable_sha256,
        lookup.interpreter_executable_sha256, 32);
    challenge.extension_peer = actual_peer;
    memcpy(challenge.session_id, lookup.session_id, 32);
    challenge.initial_interpreter_slot = registration.initial_interpreter_slot;
    challenge.initial_authority_role = registration.initial_authority_role;
    if (getentropy(challenge.challenge_nonce,
            sizeof(challenge.challenge_nonce)) != 0
        || plamen_broker_v2_service_session_challenge_encode(
            &challenge, payload) != 0
        || plamen_broker_v2_service_envelope_build(
            PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER,
            PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE,
            view->transaction_nonce, view->invocation_nonce,
            payload, sizeof(payload), 0, &envelope, &envelope_size) != 0
        || plamen_broker_v2_sha256(envelope, envelope_size,
            challenge_envelope_sha256) != 0)
        goto internal;
    reply = xpc_dictionary_create_reply(message);
    if (reply == NULL
        || store_challenge(&actual_peer, &challenge,
            challenge_envelope_sha256) != 0)
        goto internal;
    xpc_dictionary_set_data(reply, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE,
        envelope, envelope_size);
    xpc_connection_send_message(peer, reply);
    goto done;
internal:
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL,
        PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
done:
    if (reply != NULL)
        xpc_release(reply);
    if (envelope != NULL) {
        plamen_broker_v2_secure_zero(envelope, envelope_size);
        free(envelope);
    }
    plamen_broker_v2_secure_zero(&lookup, sizeof(lookup));
    plamen_broker_v2_secure_zero(&challenge, sizeof(challenge));
    plamen_broker_v2_secure_zero(&registration, sizeof(registration));
    plamen_broker_v2_secure_zero(&registered, sizeof(registered));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
    plamen_broker_v2_secure_zero(challenge_envelope_sha256,
        sizeof(challenge_envelope_sha256));
}

static void
handle_specialized_session_lookup(xpc_connection_t peer, xpc_object_t message,
    const struct plamen_broker_v2_service_envelope_view *view)
{
    struct plamen_broker_v2_service_specialized_session_lookup lookup;
    struct plamen_broker_v2_service_specialized_session_challenge challenge;
    struct plamen_broker_v2_peer_identity actual_peer;
    struct plamen_service_session_worker *parent = NULL;
    uint8_t payload[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE];
    uint8_t challenge_envelope_sha256[32];
    uint8_t *envelope = NULL;
    size_t envelope_size = 0;
    xpc_object_t reply = NULL;

    memset(&lookup, 0, sizeof(lookup));
    memset(&challenge, 0, sizeof(challenge));
    memset(&actual_peer, 0, sizeof(actual_peer));
    memset(payload, 0, sizeof(payload));
    memset(challenge_envelope_sha256, 0,
        sizeof(challenge_envelope_sha256));
    if (view->fd_count != 0 || !exact_xpc_shape(message, view->type, NULL)
        || admit_peer_code(peer, PLAMEN_INSTALL_MEMBER_PYTHON) != 0
        || connection_peer_identity(peer, &actual_peer) != 0
        || plamen_broker_v2_service_specialized_session_lookup_decode(
            view->payload, view->payload_size, &lookup)
            != PLAMEN_BROKER_V2_OK
        || lookup.version != PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION
        || !constant_equal(lookup.extension_closure_sha256,
            service_authority.extension_closure_sha256, 32)
        || !constant_equal(lookup.interpreter_executable_sha256,
            service_authority.interpreter_executable_sha256, 32)
        || active_session_find(&lookup, &actual_peer, &parent) != 0
        || parent->authority_bundle.role
            != PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR) {
        send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_PEER_AUTH,
            PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
        goto done;
    }
    memcpy(challenge.request_envelope_sha256, view->envelope_sha256, 32);
    challenge.lookup = lookup;
    challenge.extension_peer = actual_peer;
    memcpy(challenge.broker_closure_sha256,
        service_authority.broker_closure_sha256, 32);
    if (getentropy(challenge.challenge_nonce,
            sizeof(challenge.challenge_nonce)) != 0
        || plamen_broker_v2_service_specialized_session_challenge_encode(
            &challenge, payload) != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_service_envelope_build(
            PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER,
            PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE,
            view->transaction_nonce, view->invocation_nonce,
            payload, sizeof(payload), 0, &envelope, &envelope_size)
            != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_sha256(envelope, envelope_size,
            challenge_envelope_sha256) != PLAMEN_BROKER_V2_OK
        || store_specialized_challenge(&actual_peer, &challenge,
            challenge_envelope_sha256) != 0) {
        send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL,
            PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
        goto done;
    }
    reply = xpc_dictionary_create_reply(message);
    if (reply == NULL) {
        send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL,
            PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
        goto done;
    }
    xpc_dictionary_set_data(reply, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE,
        envelope, envelope_size);
    xpc_connection_send_message(peer, reply);
done:
    if (parent != NULL)
        session_worker_release(parent, 0);
    if (reply != NULL)
        xpc_release(reply);
    if (envelope != NULL) {
        plamen_broker_v2_secure_zero(envelope, envelope_size);
        free(envelope);
    }
    plamen_broker_v2_secure_zero(&lookup, sizeof(lookup));
    plamen_broker_v2_secure_zero(&challenge, sizeof(challenge));
    plamen_broker_v2_secure_zero(&actual_peer, sizeof(actual_peer));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
    plamen_broker_v2_secure_zero(challenge_envelope_sha256,
        sizeof(challenge_envelope_sha256));
}

static int
wait_descriptor(int descriptor, short events, uint64_t deadline_ms)
{
    struct pollfd item;
    int result, timeout;
    uint64_t now;

    memset(&item, 0, sizeof(item));
    item.fd = descriptor;
    item.events = events;
    for (;;) {
        if (deadline_ms == 0)
            timeout = -1;
        else {
            now = monotonic_ms();
            if (now == 0 || now >= deadline_ms)
                return -1;
            timeout = deadline_ms - now > (uint64_t)INT_MAX
                ? INT_MAX : (int)(deadline_ms - now);
        }
        result = poll(&item, 1, timeout);
        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0 || (item.revents & (POLLERR | POLLNVAL)) != 0)
            return -1;
        return (item.revents & (events | POLLHUP)) != 0 ? 0 : -1;
    }
}

static int
read_session_key(int descriptor, uint8_t key[32])
{
    uint8_t extra;
    size_t offset = 0;
    uint64_t now = monotonic_ms();
    uint64_t deadline;

    if (descriptor < 0 || key == NULL || now == 0)
        return -1;
    deadline = now + PLAMEN_SERVICE_SESSION_IO_TIMEOUT_MS;
    while (offset < 32) {
        ssize_t amount;
        if (wait_descriptor(descriptor, POLLIN, deadline) != 0)
            goto invalid;
        amount = read(descriptor, key + offset, 32 - offset);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0)
            goto invalid;
        offset += (size_t)amount;
    }
    for (;;) {
        ssize_t amount;
        if (wait_descriptor(descriptor, POLLIN, deadline) != 0)
            goto invalid;
        amount = read(descriptor, &extra, 1);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount == 0 && !all_zero_32(key))
            return 0;
        goto invalid;
    }
invalid:
    plamen_broker_v2_secure_zero(key, 32);
    return -1;
}

static uint32_t
frame_payload_size(const uint8_t header[PLAMEN_BROKER_V2_HEADER_SIZE])
{
    return ((uint32_t)header[20] << 24) | ((uint32_t)header[21] << 16)
        | ((uint32_t)header[22] << 8) | header[23];
}

static int
recv_without_descriptors(int descriptor, uint8_t *buffer, size_t size,
    uint64_t deadline_ms)
{
    size_t offset = 0;
    while (offset < size) {
        union {
            struct cmsghdr alignment;
            uint8_t bytes[CMSG_SPACE(sizeof(int) * PLAMEN_BROKER_V2_MAX_FDS)];
        } control;
        struct msghdr message;
        struct iovec vector;
        struct cmsghdr *entry;
        ssize_t amount;
        int ancillary = 0;

        if (wait_descriptor(descriptor, POLLIN, deadline_ms) != 0)
            return -1;
        memset(&message, 0, sizeof(message));
        memset(&control, 0, sizeof(control));
        vector.iov_base = buffer + offset;
        vector.iov_len = size - offset;
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        amount = recvmsg(descriptor, &message, 0);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0)
            return -1;
        if ((message.msg_flags & MSG_CTRUNC) != 0)
            ancillary = 1;
        for (entry = CMSG_FIRSTHDR(&message); entry != NULL;
             entry = CMSG_NXTHDR(&message, entry)) {
            ancillary = 1;
            if (entry->cmsg_level == SOL_SOCKET
                && entry->cmsg_type == SCM_RIGHTS
                && entry->cmsg_len >= CMSG_LEN(0)) {
                size_t bytes = entry->cmsg_len - CMSG_LEN(0);
                size_t count = bytes / sizeof(int), index;
                const int *received = (const int *)CMSG_DATA(entry);
                for (index = 0; index < count; ++index) {
                    if (received[index] >= 0)
                        close(received[index]);
                }
            }
        }
        if (ancillary)
            return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int
receive_frame(int descriptor, uint64_t deadline_ms, uint8_t **frame,
    size_t *frame_size)
{
    uint8_t header[PLAMEN_BROKER_V2_HEADER_SIZE];
    uint8_t *result = NULL;
    uint32_t payload_size;

    *frame = NULL;
    *frame_size = 0;
    if (recv_without_descriptors(descriptor, header, sizeof(header),
            deadline_ms) != 0)
        return -1;
    payload_size = frame_payload_size(header);
    if (payload_size > PLAMEN_BROKER_V2_MAX_PAYLOAD)
        return -1;
    result = malloc(sizeof(header) + (size_t)payload_size);
    if (result == NULL)
        return -1;
    memcpy(result, header, sizeof(header));
    if (payload_size != 0
        && recv_without_descriptors(descriptor, result + sizeof(header),
            payload_size, deadline_ms) != 0) {
        plamen_broker_v2_secure_zero(result,
            sizeof(header) + (size_t)payload_size);
        free(result);
        return -1;
    }
    *frame = result;
    *frame_size = sizeof(header) + (size_t)payload_size;
    return 0;
}

static int
receive_frame_with_descriptors(int descriptor, uint64_t deadline_ms,
    uint8_t **frame, size_t *frame_size, int *fds, size_t *fd_count)
{
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(int) * PLAMEN_BROKER_V2_MAX_FDS)];
    } control;
    struct msghdr message;
    struct iovec vector;
    struct cmsghdr *entry;
    uint8_t header[PLAMEN_BROKER_V2_HEADER_SIZE];
    uint8_t *result = NULL;
    uint32_t payload_size;
    size_t received_count = 0, index;
    ssize_t amount;
    int ancillary_seen = 0;

    if (frame == NULL || frame_size == NULL || fds == NULL || fd_count == NULL)
        return -1;
    *frame = NULL;
    *frame_size = 0;
    *fd_count = 0;
    memset(header, 0, sizeof(header));
    for (index = 0; index < PLAMEN_BROKER_V2_MAX_FDS; ++index)
        fds[index] = -1;
    if (wait_descriptor(descriptor, POLLIN, deadline_ms) != 0)
        return -1;
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    vector.iov_base = header;
    vector.iov_len = 1U;
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    do {
        amount = recvmsg(descriptor, &message, 0);
    } while (amount < 0 && errno == EINTR);
    if (amount != 1 || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0)
        goto invalid;
    for (entry = CMSG_FIRSTHDR(&message); entry != NULL;
         entry = CMSG_NXTHDR(&message, entry)) {
        size_t bytes, count;
        const int *received;
        if (ancillary_seen || entry->cmsg_level != SOL_SOCKET
            || entry->cmsg_type != SCM_RIGHTS
            || entry->cmsg_len < CMSG_LEN(sizeof(int)))
            goto invalid;
        bytes = entry->cmsg_len - CMSG_LEN(0);
        if (bytes % sizeof(int) != 0)
            goto invalid;
        count = bytes / sizeof(int);
        if (count == 0 || count > PLAMEN_BROKER_V2_MAX_FDS)
            goto invalid;
        received = (const int *)CMSG_DATA(entry);
        for (index = 0; index < count; ++index)
            fds[index] = received[index];
        received_count = count;
        ancillary_seen = 1;
    }
    if (recv_without_descriptors(descriptor, header + 1U,
            sizeof(header) - 1U, deadline_ms) != 0)
        goto invalid;
    payload_size = frame_payload_size(header);
    if (payload_size > PLAMEN_BROKER_V2_MAX_PAYLOAD)
        goto invalid;
    result = malloc(sizeof(header) + (size_t)payload_size);
    if (result == NULL)
        goto invalid;
    memcpy(result, header, sizeof(header));
    if (payload_size != 0
        && recv_without_descriptors(descriptor, result + sizeof(header),
            payload_size, deadline_ms) != 0)
        goto invalid;
    *frame = result;
    *frame_size = sizeof(header) + (size_t)payload_size;
    *fd_count = received_count;
    return 0;
invalid:
    if (result != NULL) {
        plamen_broker_v2_secure_zero(result,
            sizeof(header) + (size_t)frame_payload_size(header));
        free(result);
    }
    plamen_broker_v2_close_fds(fds, PLAMEN_BROKER_V2_MAX_FDS);
    return -1;
}

static int
write_bytes(int descriptor, const uint8_t *bytes, size_t size,
    uint64_t deadline_ms)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount;
        if (wait_descriptor(descriptor, POLLOUT, deadline_ms) != 0)
            return -1;
        amount = send(descriptor, bytes + offset, size - offset, MSG_NOSIGNAL);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0)
            return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int
send_frame(int descriptor, struct plamen_broker_v2_session *session,
    uint16_t type, const uint8_t operation_nonce[32], const uint8_t *payload,
    uint32_t payload_size, uint64_t deadline_ms)
{
    uint8_t *frame = NULL;
    size_t frame_size = 0;
    int result = -1;
    if (plamen_broker_v2_frame_build(session, type, operation_nonce, payload,
            payload_size, 0, &frame, &frame_size) == 0
        && write_bytes(descriptor, frame, frame_size, deadline_ms) == 0)
        result = 0;
    if (frame != NULL) {
        plamen_broker_v2_secure_zero(frame, frame_size);
        free(frame);
    }
    return result;
}

static int
active_specialized_session_register(
    struct plamen_specialized_session_worker *worker)
{
    size_t index;
    int result = -1;
    if (worker == NULL
        || pthread_mutex_lock(&active_specialized_sessions_lock) != 0)
        return -1;
    for (index = 0; index < PLAMEN_SERVICE_MAX_ACTIVE_SESSIONS; ++index) {
        if (active_specialized_sessions[index].occupied
            && constant_equal(active_specialized_sessions[index]
                    .specialized_session_id,
                worker->acknowledgement.specialized_session_id, 32))
            goto done;
    }
    for (index = 0; index < PLAMEN_SERVICE_MAX_ACTIVE_SESSIONS; ++index) {
        if (!active_specialized_sessions[index].occupied) {
            active_specialized_sessions[index].occupied = 1;
            memcpy(active_specialized_sessions[index].specialized_session_id,
                worker->acknowledgement.specialized_session_id, 32);
            active_specialized_sessions[index].worker = worker;
            worker->registered = 1;
            result = 0;
            break;
        }
    }
done:
    pthread_mutex_unlock(&active_specialized_sessions_lock);
    return result;
}

static void
active_specialized_session_unregister(
    struct plamen_specialized_session_worker *worker)
{
    size_t index;
    if (worker == NULL || !worker->registered
        || pthread_mutex_lock(&active_specialized_sessions_lock) != 0)
        return;
    for (index = 0; index < PLAMEN_SERVICE_MAX_ACTIVE_SESSIONS; ++index) {
        if (active_specialized_sessions[index].occupied
            && active_specialized_sessions[index].worker == worker) {
            plamen_broker_v2_secure_zero(
                &active_specialized_sessions[index],
                sizeof(active_specialized_sessions[index]));
            worker->registered = 0;
            break;
        }
    }
    pthread_mutex_unlock(&active_specialized_sessions_lock);
}

static void
destroy_specialized_worker(struct plamen_specialized_session_worker *worker)
{
    if (worker == NULL)
        return;
    active_specialized_session_unregister(worker);
    if (worker->control_fd >= 0)
        close(worker->control_fd);
    if (worker->parent != NULL)
        session_worker_release(worker->parent, 0);
    plamen_broker_v2_secure_zero(worker, sizeof(*worker));
    free(worker);
}

static void *
serve_specialized_session(void *opaque)
{
    struct plamen_specialized_session_worker *worker = opaque;
    struct plamen_broker_v2_session transport;
    struct plamen_broker_v2_frame_view view;
    struct plamen_broker_v2_specialized_request request;
    struct plamen_broker_v2_specialized_response response;
    uint8_t *frame = NULL, *terminal = NULL, *response_wire = NULL;
    size_t frame_size = 0, terminal_size = 0, response_wire_size = 0;
    uint8_t request_sha256[32];
    int fds[PLAMEN_BROKER_V2_MAX_FDS];
    size_t fd_count = 0, index;
    int store_result;

    memset(&transport, 0, sizeof(transport));
    memset(&view, 0, sizeof(view));
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(request_sha256, 0, sizeof(request_sha256));
    for (index = 0; index < PLAMEN_BROKER_V2_MAX_FDS; ++index)
        fds[index] = -1;
    if (worker == NULL || worker->parent == NULL
        || worker->parent->effects == NULL
        || plamen_broker_v2_session_init(&transport,
            PLAMEN_BROKER_V2_ROLE_BROKER, worker->key,
            worker->acknowledgement.specialized_session_id)
            != PLAMEN_BROKER_V2_OK)
        goto done;
    for (;;) {
        if (receive_frame_with_descriptors(worker->control_fd, 0,
                &frame, &frame_size, fds, &fd_count) != 0
            || plamen_broker_v2_frame_accept(&transport, frame, frame_size,
                fd_count, &view) != PLAMEN_BROKER_V2_OK
            || view.type != PLAMEN_BROKER_V2_OPERATION_REQUEST
            || plamen_broker_v2_specialized_request_decode_exact(
                view.payload, view.payload_size, &request)
                != PLAMEN_BROKER_V2_OK
            || request.lane != worker->acknowledgement.lane
            || !constant_equal(request.operation_nonce,
                view.operation_nonce, 32)
            || !constant_equal(request.authority_binding_sha256,
                worker->acknowledgement.authority_binding_sha256, 32)
            || request.fd_count != fd_count
            || plamen_broker_v2_specialized_request_validate_fds(
                &request, fds, fd_count) != PLAMEN_BROKER_V2_OK
            || plamen_broker_v2_sha256(view.payload, view.payload_size,
                request_sha256) != PLAMEN_BROKER_V2_OK)
            break;
        /* Exact operation replay is resolved before any external effect. */
        store_result = plamen_broker_v2_service_store_specialized_operation(
                service_authority.store, &worker->acknowledgement,
                &request, request_sha256, NULL, 0, 0, &response,
                &response_wire, &response_wire_size);
        if (store_result != PLAMEN_BROKER_V2_OK) {
            if (store_result != PLAMEN_BROKER_V2_CONFLICT
                || plamen_broker_v2_service_store_specialized_preflight(
                    service_authority.store, &worker->acknowledgement,
                    &request, request_sha256) != PLAMEN_BROKER_V2_OK
                || plamen_broker_v2_effects_dispatch_specialized(
                    worker->parent->effects, &request, view.payload,
                    view.payload_size, request_sha256, worker->key,
                    fds, fd_count,
                    &terminal, &terminal_size) != 0
                || terminal == NULL || terminal_size == 0
                || terminal_size > PLAMEN_BROKER_V2_SPECIALIZED_PAYLOAD_MAX
                || plamen_broker_v2_service_store_specialized_operation(
                    service_authority.store, &worker->acknowledgement,
                    &request, request_sha256, terminal, terminal_size, 1,
                    &response, &response_wire, &response_wire_size)
                    != PLAMEN_BROKER_V2_OK)
                break;
        }
        if (response_wire == NULL || response_wire_size == 0
            || response_wire_size > UINT32_MAX
            || send_frame(worker->control_fd, &transport,
                PLAMEN_BROKER_V2_OPERATION_RESPONSE,
                request.operation_nonce, response_wire,
                (uint32_t)response_wire_size, 0) != 0)
            break;
        plamen_broker_v2_close_fds(fds, fd_count);
        for (index = 0; index < PLAMEN_BROKER_V2_MAX_FDS; ++index)
            fds[index] = -1;
        fd_count = 0;
        if (frame != NULL) {
            plamen_broker_v2_secure_zero(frame, frame_size);
            free(frame);
            frame = NULL;
            frame_size = 0;
        }
        if (terminal != NULL) {
            plamen_broker_v2_secure_zero(terminal, terminal_size);
            free(terminal);
            terminal = NULL;
            terminal_size = 0;
        }
        if (response_wire != NULL) {
            plamen_broker_v2_secure_zero(response_wire, response_wire_size);
            free(response_wire);
            response_wire = NULL;
            response_wire_size = 0;
        }
        plamen_broker_v2_secure_zero(&view, sizeof(view));
        plamen_broker_v2_secure_zero(&request, sizeof(request));
        plamen_broker_v2_secure_zero(&response, sizeof(response));
        plamen_broker_v2_secure_zero(request_sha256,
            sizeof(request_sha256));
    }
done:
    plamen_broker_v2_close_fds(fds, PLAMEN_BROKER_V2_MAX_FDS);
    if (frame != NULL) {
        plamen_broker_v2_secure_zero(frame, frame_size);
        free(frame);
    }
    if (terminal != NULL) {
        plamen_broker_v2_secure_zero(terminal, terminal_size);
        free(terminal);
    }
    if (response_wire != NULL) {
        plamen_broker_v2_secure_zero(response_wire, response_wire_size);
        free(response_wire);
    }
    plamen_broker_v2_session_burn(&transport);
    plamen_broker_v2_secure_zero(&view, sizeof(view));
    plamen_broker_v2_secure_zero(&request, sizeof(request));
    plamen_broker_v2_secure_zero(&response, sizeof(response));
    plamen_broker_v2_secure_zero(request_sha256,
        sizeof(request_sha256));
    destroy_specialized_worker(worker);
    return NULL;
}

static void
destroy_session_worker_final(struct plamen_service_session_worker *worker)
{
    if (worker == NULL)
        return;
    if (worker->operations != NULL)
        plamen_broker_v2_operations_session_close(worker->operations);
    if (worker->effects != NULL)
        plamen_broker_v2_effects_destroy(worker->effects);
    if (worker->control_fd >= 0)
        close(worker->control_fd);
    if (worker->request_projection != NULL) {
        plamen_broker_v2_secure_zero(worker->request_projection,
            worker->request_projection_size);
        free(worker->request_projection);
    }
    close_authority_fd_array(worker->authority_fds);
    if (worker->lifetime_initialized)
        pthread_mutex_destroy(&worker->lifetime_lock);
    plamen_broker_v2_secure_zero(worker, sizeof(*worker));
    free(worker);
}

static int
session_worker_lifetime_init(struct plamen_service_session_worker *worker)
{
    if (worker == NULL || pthread_mutex_init(&worker->lifetime_lock, NULL) != 0)
        return -1;
    worker->references = 1U;
    worker->lifetime_initialized = 1;
    return 0;
}

static int
session_worker_retain(struct plamen_service_session_worker *worker)
{
    int result = -1;
    if (worker == NULL || !worker->lifetime_initialized
        || pthread_mutex_lock(&worker->lifetime_lock) != 0)
        return -1;
    if (!worker->closing && worker->references != SIZE_MAX) {
        ++worker->references;
        result = 0;
    }
    pthread_mutex_unlock(&worker->lifetime_lock);
    return result;
}

static void
session_worker_release(struct plamen_service_session_worker *worker,
    int close_owner)
{
    int destroy = 0;
    if (worker == NULL)
        return;
    if (!worker->lifetime_initialized) {
        destroy_session_worker_final(worker);
        return;
    }
    if (pthread_mutex_lock(&worker->lifetime_lock) != 0)
        return;
    if (close_owner)
        worker->closing = 1;
    if (worker->references != 0 && --worker->references == 0)
        destroy = 1;
    pthread_mutex_unlock(&worker->lifetime_lock);
    if (destroy)
        destroy_session_worker_final(worker);
}

static void
destroy_session_worker(struct plamen_service_session_worker *worker)
{
    session_worker_release(worker, 1);
}

static int
active_session_register(struct plamen_service_session_worker *worker)
{
    size_t index;
    int result = -1;
    if (worker == NULL
        || pthread_mutex_lock(&active_service_sessions_lock) != 0)
        return -1;
    for (index = 0; index < PLAMEN_SERVICE_MAX_ACTIVE_SESSIONS; ++index) {
        if (active_service_sessions[index].occupied
            && (same_peer(&active_service_sessions[index].peer,
                    &worker->challenge.extension_peer)
                || constant_equal(active_service_sessions[index]
                        .acknowledgement.session_id,
                    worker->acknowledgement.session_id, 32)))
            goto done;
    }
    for (index = 0; index < PLAMEN_SERVICE_MAX_ACTIVE_SESSIONS; ++index) {
        if (!active_service_sessions[index].occupied) {
            active_service_sessions[index].occupied = 1;
            active_service_sessions[index].peer = worker->challenge.extension_peer;
            active_service_sessions[index].acknowledgement =
                worker->acknowledgement;
            active_service_sessions[index].authority_bundle =
                worker->authority_bundle;
            active_service_sessions[index].worker = worker;
            result = 0;
            break;
        }
    }
done:
    pthread_mutex_unlock(&active_service_sessions_lock);
    return result;
}

static void
active_session_unregister(struct plamen_service_session_worker *worker)
{
    size_t index;
    if (worker == NULL
        || pthread_mutex_lock(&active_service_sessions_lock) != 0)
        return;
    for (index = 0; index < PLAMEN_SERVICE_MAX_ACTIVE_SESSIONS; ++index) {
        if (active_service_sessions[index].occupied
            && active_service_sessions[index].worker == worker) {
            plamen_broker_v2_secure_zero(&active_service_sessions[index],
                sizeof(active_service_sessions[index]));
            break;
        }
    }
    pthread_mutex_unlock(&active_service_sessions_lock);
}

static int
active_session_find(
    const struct plamen_broker_v2_service_specialized_session_lookup *lookup,
    const struct plamen_broker_v2_peer_identity *peer,
    struct plamen_service_session_worker **worker_out)
{
    size_t index;
    int matches = 0;
    struct plamen_service_session_worker *worker = NULL;
    if (lookup == NULL || peer == NULL || worker_out == NULL
        || pthread_mutex_lock(&active_service_sessions_lock) != 0)
        return -1;
    *worker_out = NULL;
    for (index = 0; index < PLAMEN_SERVICE_MAX_ACTIVE_SESSIONS; ++index) {
        const struct plamen_active_service_session *candidate =
            &active_service_sessions[index];
        if (!candidate->occupied || !same_peer(&candidate->peer, peer)
            || !constant_equal(candidate->acknowledgement.session_id,
                lookup->parent_session_id, 32)
            || !constant_equal(candidate->acknowledgement.registration_sha256,
                lookup->registration_sha256, 32)
            || !constant_equal(
                candidate->acknowledgement.authority_bundle_sha256,
                lookup->authority_bundle_sha256, 32))
            continue;
        ++matches;
        worker = candidate->worker;
    }
    if (matches == 1 && session_worker_retain(worker) == 0)
        *worker_out = worker;
    pthread_mutex_unlock(&active_service_sessions_lock);
    return *worker_out != NULL ? 0 : -1;
}

static int
dispatch_native_operation(int descriptor,
    struct plamen_broker_v2_session *transport,
    const struct plamen_broker_v2_commitment *commitment,
    const struct plamen_broker_v2_authority_bundle_binding *bundle,
    struct plamen_broker_v2_operations_session *operations,
    const struct plamen_broker_v2_frame_view *view)
{
    struct plamen_broker_v2_operation_request request;
    struct plamen_broker_v2_operations_dispatch_result dispatched;
    uint8_t derived_key[32], request_sha256[32];
    int result = -1;

    memset(&request, 0, sizeof(request));
    memset(&dispatched, 0, sizeof(dispatched));
    memset(derived_key, 0, sizeof(derived_key));
    memset(request_sha256, 0, sizeof(request_sha256));
    if (operations == NULL || view == NULL
        || view->type != PLAMEN_BROKER_V2_OPERATION_REQUEST
        || !plamen_broker_v2_initial_authority_allows_frame(bundle->role,
            view->type)
        || plamen_broker_v2_operation_request_decode(view->payload,
            view->payload_size, &request) != 0
        || request.authority_role != bundle->role || request.member == 0
        || request.member > bundle->member_count
        || !constant_equal(request.request_fingerprint,
            commitment->request_fingerprint, 32)
        || plamen_broker_v2_derive_rpc_operation_key(commitment,
            bundle->member_sha256[request.member - 1],
            request.authority_role, request.member, request.method,
            request.payload_sha256, request.prior_checkpoint_sha256,
            derived_key) != 0
        || !constant_equal(derived_key, request.operation_key, 32)
        || !constant_equal(derived_key, view->operation_nonce, 32)
        || plamen_broker_v2_sha256(view->payload, view->payload_size,
            request_sha256) != 0)
        goto done;
    if (plamen_broker_v2_operations_dispatch(operations, &request,
            request_sha256, request.payload, request.payload_size,
            &dispatched) != 0
        || (dispatched.kind != PLAMEN_BROKER_V2_OPERATIONS_RESPONSE
            && dispatched.kind != PLAMEN_BROKER_V2_OPERATIONS_ERROR)
        || dispatched.wire == NULL || dispatched.wire_size == 0
        || dispatched.wire_size > UINT32_MAX
        || send_frame(descriptor, transport,
            dispatched.kind == PLAMEN_BROKER_V2_OPERATIONS_RESPONSE
                ? PLAMEN_BROKER_V2_OPERATION_RESPONSE
                : PLAMEN_BROKER_V2_OPERATION_ERROR,
            request.operation_key, dispatched.wire,
            (uint32_t)dispatched.wire_size, 0) != 0)
        goto done;
    result = 0;
done:
    plamen_broker_v2_operations_dispatch_result_dispose(&dispatched);
    plamen_broker_v2_secure_zero(&request, sizeof(request));
    plamen_broker_v2_secure_zero(derived_key, sizeof(derived_key));
    plamen_broker_v2_secure_zero(request_sha256, sizeof(request_sha256));
    return result;
}

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
static int
dispatch_test_only_unsupported(int descriptor,
    struct plamen_broker_v2_session *transport,
    const struct plamen_broker_v2_commitment *commitment,
    const struct plamen_broker_v2_authority_bundle_binding *bundle,
    const struct plamen_broker_v2_frame_view *view)
{
    struct plamen_broker_v2_operation_request request;
    struct plamen_broker_v2_operation_error error;
    uint8_t derived_key[32], request_sha256[32];
    uint8_t payload[PLAMEN_BROKER_V2_OPERATION_ERROR_SIZE];
    int result = -1;
    memset(&request, 0, sizeof(request));
    memset(&error, 0, sizeof(error));
    memset(derived_key, 0, sizeof(derived_key));
    memset(request_sha256, 0, sizeof(request_sha256));
    memset(payload, 0, sizeof(payload));
    if (view == NULL || view->type != PLAMEN_BROKER_V2_OPERATION_REQUEST
        || plamen_broker_v2_operation_request_decode(view->payload,
            view->payload_size, &request) != 0
        || request.authority_role != bundle->role || request.member == 0
        || request.member > bundle->member_count
        || !constant_equal(request.request_fingerprint,
            commitment->request_fingerprint, 32)
        || plamen_broker_v2_derive_rpc_operation_key(commitment,
            bundle->member_sha256[request.member - 1],
            request.authority_role, request.member, request.method,
            request.payload_sha256, request.prior_checkpoint_sha256,
            derived_key) != 0
        || !constant_equal(derived_key, request.operation_key, 32)
        || !constant_equal(derived_key, view->operation_nonce, 32)
        || plamen_broker_v2_sha256(view->payload, view->payload_size,
            request_sha256) != 0)
        goto done;
    error.authority_role = request.authority_role;
    error.member = request.member;
    error.method = request.method;
    error.error_code = PLAMEN_BROKER_V2_SERVICE_ERR_UNSUPPORTED;
    error.flags = PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED;
    memcpy(error.operation_key, request.operation_key, 32);
    memcpy(error.request_sha256, request_sha256, 32);
    memcpy(error.current_checkpoint_sha256,
        request.prior_checkpoint_sha256, 32);
    if (plamen_broker_v2_operation_error_encode(&error, payload) == 0
        && send_frame(descriptor, transport,
            PLAMEN_BROKER_V2_OPERATION_ERROR, request.operation_key,
            payload, sizeof(payload), 0) == 0)
        result = 0;
done:
    plamen_broker_v2_secure_zero(&request, sizeof(request));
    plamen_broker_v2_secure_zero(&error, sizeof(error));
    plamen_broker_v2_secure_zero(derived_key, sizeof(derived_key));
    plamen_broker_v2_secure_zero(request_sha256, sizeof(request_sha256));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
    return result;
}
#endif

static void *
serve_session(void *opaque)
{
    struct plamen_service_session_worker *worker = opaque;
    struct plamen_broker_v2_effects_open effects_open;
    struct plamen_broker_v2_operations_open operations_open;
    struct plamen_broker_v2_session transport;
    struct plamen_broker_v2_frame_view view;
    struct plamen_broker_v2_commitment commitment;
    struct plamen_broker_v2_apple_container_admission_receipt
        provider_admission;
    uint8_t zeros[32] = { 0 };
    uint8_t bundle_bytes[PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE];
    uint8_t *frame = NULL;
    size_t frame_size = 0, bundle_size = 0;
    uint64_t now, deadline;
    int active_registered = 0;

    memset(&transport, 0, sizeof(transport));
    memset(&view, 0, sizeof(view));
    memset(&commitment, 0, sizeof(commitment));
    memset(&provider_admission, 0, sizeof(provider_admission));
    memset(&effects_open, 0, sizeof(effects_open));
    memset(&operations_open, 0, sizeof(operations_open));
    now = monotonic_ms();
    if (now == 0)
        goto done;
    deadline = now + PLAMEN_SERVICE_SESSION_IO_TIMEOUT_MS;
    if (plamen_broker_v2_session_init(&transport,
            PLAMEN_BROKER_V2_ROLE_BROKER, worker->key,
            worker->acknowledgement.session_id) != 0
        || send_frame(worker->control_fd, &transport,
            PLAMEN_BROKER_V2_HELLO, zeros, NULL, 0, deadline) != 0
        || receive_frame(worker->control_fd, deadline,
            &frame, &frame_size) != 0
        || plamen_broker_v2_frame_accept(&transport, frame, frame_size, 0,
            &view) != 0
        || view.type != PLAMEN_BROKER_V2_REQUEST_PROJECTION
        || view.payload_size != 0)
        goto done;
    plamen_broker_v2_secure_zero(frame, frame_size);
    free(frame);
    frame = NULL;
    frame_size = 0;
    if (send_frame(worker->control_fd, &transport,
            PLAMEN_BROKER_V2_REQUEST_PROJECTED, zeros,
            worker->request_projection,
            (uint32_t)worker->request_projection_size, deadline) != 0
        || receive_frame(worker->control_fd, deadline,
            &frame, &frame_size) != 0
        || plamen_broker_v2_frame_accept(&transport, frame, frame_size, 0,
            &view) != 0
        || view.type != PLAMEN_BROKER_V2_AUTH_CONSUME
        || plamen_broker_v2_auth_consume_matches_challenge(
            &worker->challenge, view.payload, view.payload_size,
            &commitment) != 0)
        goto done;
    plamen_broker_v2_secure_zero(frame, frame_size);
    free(frame);
    frame = NULL;
    frame_size = 0;
#ifdef PLAMEN_BROKER_V2_TEST_ONLY
    if (!worker->test_only_wire) {
#endif
        if (admit_worker_apple_container(worker, &commitment,
                &provider_admission) != 0)
            goto done;
        effects_open.version = PLAMEN_BROKER_V2_EFFECTS_VERSION;
        effects_open.registration = &worker->registration;
        effects_open.request_projection = worker->request_projection;
        effects_open.request_projection_size = worker->request_projection_size;
        memcpy(effects_open.authority_binding_sha256,
            worker->acknowledgement.authority_bundle_sha256, 32);
        effects_open.state_parent_fd = service_authority.state_parent_fd;
        effects_open.generation_fd = service_authority.generation_fd;
        effects_open.runtime_manifest_fd = service_authority.member_fds[
            PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST - 1];
        effects_open.runtime_manifest_member = &service_authority.receipt.members[
            PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST - 1];
        effects_open.image_member_receipt_fd =
            service_authority.specialized_authority_fd;
        effects_open.specialized_runtime_auxiliary =
            &service_authority.receipt.specialized_authority;
        effects_open.custody_client = service_authority.custody_client;
        effects_open.cancellation_fd = worker->control_fd;
        effects_open.authority_fds = worker->authority_fds;
        effects_open.authority_fd_count =
            PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
        if (plamen_broker_v2_effects_create(&effects_open,
                &worker->effects) != 0)
            goto done;
        if (plamen_broker_v2_effects_retain_provider_admission(
                worker->effects, &provider_admission) != 0)
            goto done;
        operations_open.version = PLAMEN_BROKER_V2_OPERATIONS_VERSION;
        memcpy(operations_open.request_fingerprint_sha256,
            commitment.request_fingerprint, 32);
        memcpy(operations_open.request_commitment_sha256,
            worker->challenge.commitment_sha256, 32);
        memcpy(operations_open.projection_sha256,
            worker->challenge.request_projection_sha256, 32);
        memcpy(operations_open.authority_binding_sha256,
            worker->acknowledgement.authority_bundle_sha256, 32);
        memcpy(operations_open.initial_checkpoint_sha256,
            worker->acknowledgement.registration_burn_checkpoint_sha256, 32);
        operations_open.authority_bundle = worker->authority_bundle;
        operations_open.effects =
            plamen_broker_v2_effects_operations(worker->effects);
        if (operations_open.effects == NULL
            || plamen_broker_v2_operations_session_open(&operations_open,
                &worker->operations) != 0)
            goto done;
#ifdef PLAMEN_BROKER_V2_TEST_ONLY
    }
#endif
    if (active_session_register(worker) != 0)
        goto done;
    active_registered = 1;
    if (plamen_broker_v2_authority_bundle_binding_encode(
            &worker->authority_bundle, bundle_bytes, sizeof(bundle_bytes),
            &bundle_size) != 0
        || send_frame(worker->control_fd, &transport,
            PLAMEN_BROKER_V2_AUTH_ACCEPTED, zeros, bundle_bytes,
            (uint32_t)bundle_size, deadline) != 0)
        goto done;
    for (;;) {
        if (receive_frame(worker->control_fd, 0, &frame, &frame_size) != 0
            || plamen_broker_v2_frame_accept(&transport, frame, frame_size, 0,
                &view) != 0)
            break;
#ifdef PLAMEN_BROKER_V2_TEST_ONLY
        if (worker->test_only_wire) {
            if (dispatch_test_only_unsupported(worker->control_fd, &transport,
                    &commitment, &worker->authority_bundle, &view) != 0)
                break;
        } else
#endif
        if (dispatch_native_operation(worker->control_fd, &transport,
                &commitment, &worker->authority_bundle, worker->operations,
                &view) != 0)
            break;
        plamen_broker_v2_secure_zero(frame, frame_size);
        free(frame);
        frame = NULL;
        frame_size = 0;
    }
done:
    if (active_registered)
        active_session_unregister(worker);
    if (frame != NULL) {
        plamen_broker_v2_secure_zero(frame, frame_size);
        free(frame);
    }
    plamen_broker_v2_session_burn(&transport);
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    plamen_broker_v2_secure_zero(&provider_admission,
        sizeof(provider_admission));
    plamen_broker_v2_secure_zero(bundle_bytes, sizeof(bundle_bytes));
    destroy_session_worker(worker);
    return NULL;
}

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
int
plamen_broker_v2_service_TEST_ONLY_serve_session(int control_fd,
    const uint8_t key[32], const uint8_t *request_projection,
    size_t request_projection_size,
    const struct plamen_broker_v2_service_session_challenge *challenge,
    const struct plamen_broker_v2_service_session_ack *acknowledgement,
    const struct plamen_broker_v2_authority_bundle_binding *authority_bundle)
{
    struct plamen_service_session_worker *worker;

    if (control_fd < 0 || key == NULL || request_projection == NULL
        || request_projection_size == 0
        || request_projection_size > PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX
        || challenge == NULL || acknowledgement == NULL
        || authority_bundle == NULL)
        return -1;
    worker = calloc(1, sizeof(*worker));
    if (worker == NULL)
        return -1;
    if (session_worker_lifetime_init(worker) != 0) {
        free(worker);
        return -1;
    }
    for (size_t slot = 0;
         slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++slot)
        worker->authority_fds[slot] = -1;
    worker->request_projection = malloc(request_projection_size);
    if (worker->request_projection == NULL) {
        free(worker);
        return -1;
    }
    worker->control_fd = control_fd;
    memcpy(worker->key, key, 32);
    memcpy(worker->request_projection, request_projection,
        request_projection_size);
    worker->request_projection_size = request_projection_size;
    worker->challenge = *challenge;
    worker->acknowledgement = *acknowledgement;
    worker->authority_bundle = *authority_bundle;
    worker->test_only_wire = 1;
    (void)serve_session(worker);
    return 0;
}
#endif

static int
generate_member_capabilities(uint16_t role,
    uint8_t capabilities[PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT][32])
{
    uint16_t count, index, prior;
    unsigned attempt;

    memset(capabilities, 0,
        PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT * 32U);
    count = role == PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR
        ? PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT
        : role == PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER
            ? PLAMEN_BROKER_V2_GUEST_AUTHORITY_MEMBER_COUNT : 0;
    if (count == 0)
        return -1;
    for (index = 0; index < count; ++index) {
        for (attempt = 0; attempt < 16; ++attempt) {
            if (getentropy(capabilities[index], 32) != 0)
                goto invalid;
            if (all_zero_32(capabilities[index]))
                continue;
            for (prior = 0; prior < index; ++prior) {
                if (constant_equal(capabilities[index],
                        capabilities[prior], 32))
                    break;
            }
            if (prior == index)
                break;
        }
        if (attempt == 16)
            goto invalid;
    }
    return 0;
invalid:
    plamen_broker_v2_secure_zero(capabilities,
        PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT * 32U);
    return -1;
}

static void
handle_session_open(xpc_connection_t peer, xpc_object_t message,
    const struct plamen_broker_v2_service_envelope_view *view)
{
    struct plamen_broker_v2_service_session_open session;
    struct plamen_broker_v2_service_session_ack acknowledgement;
    struct plamen_broker_v2_authority_bundle_binding authority_bundle;
    struct plamen_broker_v2_service_registration registration;
    struct plamen_broker_v2_service_consumed_session recovered;
    struct plamen_broker_v2_peer_identity actual_peer;
    struct plamen_pending_challenge pending;
    struct plamen_service_session_worker *worker = NULL;
    pthread_attr_t thread_attributes;
    pthread_t thread;
    uint8_t member_capabilities
        [PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT][32];
    uint8_t key[32], key_sha256[32];
    uint8_t payload[PLAMEN_BROKER_V2_SERVICE_SESSION_ACK_SIZE];
    uint8_t *projection = NULL;
    size_t projection_size = 0;
    int descriptors[2] = { -1, -1 };
    int challenge_taken = 0, consumed = 0, store_attempted = 0;
    int authority_claimed = 0;
    int attributes_ready = 0;
    int one = 1, result;

    memset(&session, 0, sizeof(session));
    memset(&acknowledgement, 0, sizeof(acknowledgement));
    memset(&authority_bundle, 0, sizeof(authority_bundle));
    memset(&registration, 0, sizeof(registration));
    memset(&recovered, 0, sizeof(recovered));
    memset(&pending, 0, sizeof(pending));
    memset(member_capabilities, 0, sizeof(member_capabilities));
    memset(key, 0, sizeof(key));
    memset(key_sha256, 0, sizeof(key_sha256));
    memset(payload, 0, sizeof(payload));
    if (view->fd_count != 2 || !exact_xpc_shape(message, view->type, NULL)
        || admit_peer_code(peer, PLAMEN_INSTALL_MEMBER_PYTHON) != 0
        || connection_peer_identity(peer, &actual_peer) != 0)
        goto invalid;
    challenge_taken = take_challenge_for_peer(&actual_peer, &pending) == 0;
    descriptors[0] = xpc_dictionary_dup_fd(message,
        PLAMEN_BROKER_V2_XPC_KEY_CONTROL_SOCKET);
    descriptors[1] = xpc_dictionary_dup_fd(message,
        PLAMEN_BROKER_V2_XPC_KEY_KEY_PIPE_READ);
    if (descriptors[0] < 0 || descriptors[1] < 0
        || plamen_broker_v2_service_session_open_decode(view->payload,
            view->payload_size, &session) != 0
        || !same_peer(&actual_peer, &session.extension_peer)
        || plamen_broker_v2_validate_received_fds(descriptors, 2,
            session.descriptors, 2) != 0)
        goto invalid;
    if (challenge_taken
        && !plamen_broker_v2_service_session_open_matches_challenge(
            &pending.challenge, pending.envelope_sha256, &session))
        goto invalid;
    if (setsockopt(descriptors[0], SOL_SOCKET, SO_NOSIGPIPE,
            &one, sizeof(one)) != 0
        || read_session_key(descriptors[1], key) != 0)
        goto key_invalid;
    (void)close(descriptors[1]);
    descriptors[1] = -1;
    if (plamen_broker_v2_sha256(key, sizeof(key), key_sha256) != 0)
        goto key_invalid;
    if (plamen_broker_v2_service_store_copy_registration(
            service_authority.store, session.registration_sha256,
            &registration) != 0
        || !same_peer(&actual_peer, &registration.suspended_child)
        || plamen_broker_v2_service_store_copy_request_projection(
            service_authority.store, session.registration_sha256,
            &projection, &projection_size) != 0)
        goto durability_invalid;
    worker = calloc(1, sizeof(*worker));
    if (worker == NULL || session_worker_lifetime_init(worker) != 0
        || pthread_attr_init(&thread_attributes) != 0)
        goto internal;
    for (size_t slot = 0;
         slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT; ++slot)
        worker->authority_fds[slot] = -1;
    attributes_ready = 1;
    if (pthread_attr_setdetachstate(&thread_attributes,
            PTHREAD_CREATE_DETACHED) != 0)
        goto internal;
    if (pending_authority_set_state(session.registration_sha256,
            PLAMEN_PENDING_AUTHORITY_ACTIVE,
            PLAMEN_PENDING_AUTHORITY_CLAIMING) != 0)
        goto durability_invalid;
    authority_claimed = 1;
    if (challenge_taken) {
        if (generate_member_capabilities(session.initial_authority_role,
                member_capabilities) != 0)
            goto internal;
        store_attempted = 1;
        result = plamen_broker_v2_service_store_consume(
            service_authority.store, &pending.challenge, &session,
            view->envelope_sha256, member_capabilities, key_sha256, 1,
            &acknowledgement, &authority_bundle);
    } else {
        store_attempted = 1;
        result = plamen_broker_v2_service_store_recover_consumed(
            service_authority.store, &session, view->envelope_sha256,
            key_sha256, &recovered);
        if (result == 0) {
            acknowledgement = recovered.session_ack;
            authority_bundle = recovered.authority_bundle;
            pending.challenge = recovered.session_challenge;
        }
    }
    if (result != 0)
        goto durability_invalid;
    consumed = 1;
    if (pending_authority_take_claimed(session.registration_sha256,
            &worker->authority_presence_mask, worker->authority_fds,
            worker->authority_descriptors) != 0)
        goto internal;
    authority_claimed = 0;
    if (plamen_broker_v2_service_session_ack_encode(
            &acknowledgement, payload) != 0)
        goto internal;
    worker->control_fd = descriptors[0];
    descriptors[0] = -1;
    memcpy(worker->key, key, sizeof(key));
    worker->request_projection = projection;
    worker->request_projection_size = projection_size;
    projection = NULL;
    projection_size = 0;
    worker->challenge = pending.challenge;
    worker->acknowledgement = acknowledgement;
    worker->authority_bundle = authority_bundle;
    worker->registration = registration;
    if (pthread_create(&thread, &thread_attributes, serve_session, worker) != 0)
        goto internal;
    worker = NULL;
    pthread_attr_destroy(&thread_attributes);
    attributes_ready = 0;
    send_envelope(message, PLAMEN_BROKER_V2_SERVICE_SESSION_ACCEPTED, view,
        payload, sizeof(payload));
    goto done;
key_invalid:
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_KEY_TRANSFER,
        PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED
            | PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
    goto done;
durability_invalid:
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_DURABILITY,
        PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED
            | (consumed ? PLAMEN_BROKER_V2_SERVICE_REGISTRATION_CONSUMED : 0)
            | (consumed || store_attempted ? 0
                : PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED));
    goto done;
internal:
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL,
        PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED
            | (consumed ? PLAMEN_BROKER_V2_SERVICE_REGISTRATION_CONSUMED : 0)
            | (consumed || store_attempted ? 0
                : PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED));
    goto done;
invalid:
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_DESCRIPTORS,
        PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED
            | PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
done:
    if (authority_claimed) {
        if (consumed) {
            if (pending_authority_set_state(session.registration_sha256,
                    PLAMEN_PENDING_AUTHORITY_CLAIMING,
                    PLAMEN_PENDING_AUTHORITY_RESERVED) == 0)
                pending_authority_abort_reservation(
                    session.registration_sha256);
        } else {
            (void)pending_authority_set_state(session.registration_sha256,
                PLAMEN_PENDING_AUTHORITY_CLAIMING,
                PLAMEN_PENDING_AUTHORITY_ACTIVE);
        }
    }
    if (attributes_ready)
        pthread_attr_destroy(&thread_attributes);
    plamen_broker_v2_close_fds(descriptors, 2);
    if (projection != NULL) {
        plamen_broker_v2_secure_zero(projection, projection_size);
        free(projection);
    }
    destroy_session_worker(worker);
    plamen_broker_v2_secure_zero(&acknowledgement,
        sizeof(acknowledgement));
    plamen_broker_v2_secure_zero(&authority_bundle,
        sizeof(authority_bundle));
    plamen_broker_v2_secure_zero(&registration, sizeof(registration));
    plamen_broker_v2_secure_zero(&recovered, sizeof(recovered));
    plamen_broker_v2_secure_zero(&pending, sizeof(pending));
    plamen_broker_v2_secure_zero(member_capabilities,
        sizeof(member_capabilities));
    plamen_broker_v2_secure_zero(key, sizeof(key));
    plamen_broker_v2_secure_zero(key_sha256, sizeof(key_sha256));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
    plamen_broker_v2_secure_zero(&session, sizeof(session));
}

static int
specialized_open_matches_challenge(
    const struct plamen_pending_specialized_challenge *pending,
    const struct plamen_broker_v2_service_specialized_session_open *session)
{
    const struct plamen_broker_v2_service_specialized_session_challenge *c;
    if (pending == NULL || session == NULL)
        return 0;
    c = &pending->challenge;
    return constant_equal(session->challenge_envelope_sha256,
            pending->envelope_sha256, 32)
        && constant_equal(session->challenge_nonce, c->challenge_nonce, 32)
        && session->version == c->lookup.version
        && session->lane == c->lookup.lane
        && constant_equal(session->parent_session_id,
            c->lookup.parent_session_id, 32)
        && constant_equal(session->specialized_session_id,
            c->lookup.specialized_session_id, 32)
        && same_peer(&session->extension_peer, &c->extension_peer);
}

static void
handle_specialized_session_open(xpc_connection_t peer, xpc_object_t message,
    const struct plamen_broker_v2_service_envelope_view *view)
{
    struct plamen_broker_v2_service_specialized_session_open session;
    struct plamen_broker_v2_service_specialized_session_ack acknowledgement;
    struct plamen_broker_v2_service_consumed_specialized_session recovered;
    struct plamen_pending_specialized_challenge pending;
    struct plamen_broker_v2_peer_identity actual_peer;
    struct plamen_service_session_worker *parent = NULL;
    struct plamen_specialized_session_worker *worker = NULL;
    pthread_attr_t thread_attributes;
    pthread_t thread;
    uint8_t key[32], key_sha256[32];
    uint8_t payload[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACK_SIZE];
    int descriptors[2] = { -1, -1 };
    int challenge_taken = 0, attributes_ready = 0, one = 1;
    int durable_changed = 0, result;

    memset(&session, 0, sizeof(session));
    memset(&acknowledgement, 0, sizeof(acknowledgement));
    memset(&recovered, 0, sizeof(recovered));
    memset(&pending, 0, sizeof(pending));
    memset(&actual_peer, 0, sizeof(actual_peer));
    memset(key, 0, sizeof(key));
    memset(key_sha256, 0, sizeof(key_sha256));
    memset(payload, 0, sizeof(payload));
    if (view->fd_count != 2 || !exact_xpc_shape(message, view->type, NULL)
        || admit_peer_code(peer, PLAMEN_INSTALL_MEMBER_PYTHON) != 0
        || connection_peer_identity(peer, &actual_peer) != 0)
        goto invalid;
    challenge_taken = take_specialized_challenge_for_peer(
        &actual_peer, &pending) == 0;
    descriptors[0] = xpc_dictionary_dup_fd(message,
        PLAMEN_BROKER_V2_XPC_KEY_CONTROL_SOCKET);
    descriptors[1] = xpc_dictionary_dup_fd(message,
        PLAMEN_BROKER_V2_XPC_KEY_KEY_PIPE_READ);
    if (descriptors[0] < 0 || descriptors[1] < 0
        || plamen_broker_v2_service_specialized_session_open_decode(
            view->payload, view->payload_size, &session)
            != PLAMEN_BROKER_V2_OK
        || !same_peer(&session.extension_peer, &actual_peer)
        || plamen_broker_v2_validate_received_fds(descriptors, 2,
            session.descriptors, 2) != PLAMEN_BROKER_V2_OK
        || (challenge_taken
            && !specialized_open_matches_challenge(&pending, &session)))
        goto invalid;
    if (setsockopt(descriptors[0], SOL_SOCKET, SO_NOSIGPIPE,
            &one, sizeof(one)) != 0
        || read_session_key(descriptors[1], key) != 0)
        goto key_invalid;
    close(descriptors[1]);
    descriptors[1] = -1;
    if (plamen_broker_v2_sha256(key, sizeof(key), key_sha256)
            != PLAMEN_BROKER_V2_OK)
        goto key_invalid;
    if (challenge_taken) {
        if (active_session_find(&pending.challenge.lookup,
                &actual_peer, &parent) != 0)
            goto durability_invalid;
        result = plamen_broker_v2_service_store_consume_specialized(
            service_authority.store, &parent->acknowledgement,
            &pending.challenge, &session, view->envelope_sha256,
            key, 1, &acknowledgement);
        if (result == PLAMEN_BROKER_V2_OK)
            durable_changed = 1;
    } else {
        result = plamen_broker_v2_service_store_recover_specialized(
            service_authority.store, &session, view->envelope_sha256,
            key, &recovered);
        if (result == PLAMEN_BROKER_V2_OK) {
            if (active_session_find(&recovered.challenge.lookup,
                    &actual_peer, &parent) != 0)
                result = PLAMEN_BROKER_V2_CONFLICT;
            else
                acknowledgement = recovered.session_ack;
        }
    }
    if (result != PLAMEN_BROKER_V2_OK)
        goto durability_invalid;
    worker = calloc(1, sizeof(*worker));
    if (worker == NULL || pthread_attr_init(&thread_attributes) != 0)
        goto internal;
    attributes_ready = 1;
    if (pthread_attr_setdetachstate(&thread_attributes,
            PTHREAD_CREATE_DETACHED) != 0
        || plamen_broker_v2_service_specialized_session_ack_encode(
            &acknowledgement, payload) != PLAMEN_BROKER_V2_OK)
        goto internal;
    worker->control_fd = descriptors[0];
    descriptors[0] = -1;
    memcpy(worker->key, key, sizeof(key));
    worker->acknowledgement = acknowledgement;
    worker->parent = parent;
    parent = NULL;
    if (active_specialized_session_register(worker) != 0
        || pthread_create(&thread, &thread_attributes,
            serve_specialized_session, worker) != 0)
        goto internal;
    worker = NULL;
    pthread_attr_destroy(&thread_attributes);
    attributes_ready = 0;
    send_envelope(message,
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACCEPTED,
        view, payload, sizeof(payload));
    goto done;
key_invalid:
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_KEY_TRANSFER,
        PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED
            | PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
    goto done;
durability_invalid:
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_DURABILITY,
        PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED
            | (durable_changed ? 0
                : PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED));
    goto done;
internal:
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL,
        PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED
            | (durable_changed ? 0
                : PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED));
    goto done;
invalid:
    send_error(message, view, PLAMEN_BROKER_V2_SERVICE_ERR_DESCRIPTORS,
        PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED
            | PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED);
done:
    if (attributes_ready)
        pthread_attr_destroy(&thread_attributes);
    plamen_broker_v2_close_fds(descriptors, 2);
    if (parent != NULL)
        session_worker_release(parent, 0);
    destroy_specialized_worker(worker);
    plamen_broker_v2_secure_zero(&session, sizeof(session));
    plamen_broker_v2_secure_zero(&acknowledgement,
        sizeof(acknowledgement));
    plamen_broker_v2_secure_zero(&recovered, sizeof(recovered));
    plamen_broker_v2_secure_zero(&pending, sizeof(pending));
    plamen_broker_v2_secure_zero(&actual_peer, sizeof(actual_peer));
    plamen_broker_v2_secure_zero(key, sizeof(key));
    plamen_broker_v2_secure_zero(key_sha256, sizeof(key_sha256));
    plamen_broker_v2_secure_zero(payload, sizeof(payload));
}

static void
handle_message(xpc_connection_t peer, xpc_object_t message)
{
    struct plamen_broker_v2_service_envelope_view view;
    const void *envelope;
    size_t envelope_size = 0;
    __block uint16_t attachment_count = 0;

    memset(&view, 0, sizeof(view));
    if (xpc_get_type(message) != XPC_TYPE_DICTIONARY)
        return;
    envelope = xpc_dictionary_get_data(message,
        PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE, &envelope_size);
    xpc_dictionary_apply(message, ^bool(const char *key, xpc_object_t value) {
        if (strcmp(key, PLAMEN_BROKER_V2_XPC_KEY_REQUEST_PROJECTION) == 0
            || strcmp(key, PLAMEN_BROKER_V2_XPC_KEY_CONTROL_SOCKET) == 0
            || strcmp(key, PLAMEN_BROKER_V2_XPC_KEY_KEY_PIPE_READ) == 0) {
            if (attachment_count < UINT16_MAX)
                ++attachment_count;
        } else {
            for (size_t slot = 0;
                 slot < PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT;
                 ++slot) {
                char expected[16];
                if (authority_xpc_key(slot, expected) == 0
                    && strcmp(key, expected) == 0) {
                    if (xpc_get_type(value) == XPC_TYPE_FD
                        && attachment_count < UINT16_MAX)
                        ++attachment_count;
                    break;
                }
            }
        }
        return true;
    });
    if (envelope == NULL
        || envelope_size > PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE
            + PLAMEN_BROKER_V2_SERVICE_MAX_PAYLOAD
        || plamen_broker_v2_service_envelope_accept(
            PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER, envelope, envelope_size,
            attachment_count, &view) != 0)
        return;
    if (view.type == PLAMEN_BROKER_V2_SERVICE_READINESS)
        handle_readiness(peer, message, &view);
    else if (view.type == PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
        || view.type == PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY)
        handle_registration(peer, message, &view);
    else if (view.type == PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP)
        handle_session_lookup(peer, message, &view);
    else if (view.type == PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN)
        handle_session_open(peer, message, &view);
    else if (view.type
        == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP)
        handle_specialized_session_lookup(peer, message, &view);
    else if (view.type
        == PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN)
        handle_specialized_session_open(peer, message, &view);
}

static void
run_listener(void)
{
    xpc_connection_t listener = xpc_connection_create_mach_service(
        PLAMEN_BROKER_V2_DARWIN_SERVICE_NAME,
        dispatch_get_main_queue(), XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (listener == NULL
        || xpc_connection_set_peer_code_signing_requirement(listener,
            service_authority.admitted_peer_code_requirement) != 0)
        exit(PLAMEN_SERVICE_HARDSTOP);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION)
            return;
        xpc_connection_t peer = (xpc_connection_t)event;
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            handle_message(peer, message);
        });
        xpc_connection_activate(peer);
    });
    xpc_connection_activate(listener);
    dispatch_main();
}

static int
admit_custody_daemon_peer(xpc_connection_t peer)
{
    return admit_peer_code(peer, PLAMEN_INSTALL_MEMBER_SERVICE);
}

static int
custody_daemon_peer_requirement(
    const struct plamen_install_receipt_member *member,
    char *output, size_t output_size)
{
    static const char alphabet[] = "0123456789abcdef";
    char cdhash[PLAMEN_INSTALL_RECEIPT_CDHASH_MAX * 2U + 1U];
    size_t index;
    int amount;
    if (member == NULL || output == NULL || output_size == 0
        || member->signing_identifier[0] == '\0'
        || !(member->cdhash_size == 20 || member->cdhash_size == 32))
        return -1;
    for (index = 0; index < member->cdhash_size; ++index) {
        cdhash[index * 2U] = alphabet[member->cdhash[index] >> 4];
        cdhash[index * 2U + 1U] = alphabet[member->cdhash[index] & 15U];
    }
    cdhash[member->cdhash_size * 2U] = '\0';
    amount = snprintf(output, output_size,
        "identifier \"%s\" and cdhash H\"%s\"",
        member->signing_identifier, cdhash);
    return amount > 0 && (size_t)amount < output_size ? 0 : -1;
}

int
main(int argc, char **argv)
{
    int custody_daemon_mode = argc == 2
        && strcmp(argv[1], PLAMEN_BROKER_V2_CUSTODY_DAEMON_MODE) == 0;
    struct plamen_broker_v2_custody_daemon_readiness custody_readiness;
    uint32_t custody_status = UINT32_MAX;
    char peer_requirement[512];
    memset(&custody_readiness, 0, sizeof(custody_readiness));
    if (!(argc == 1 || custody_daemon_mode))
        return 64;
    if (admit_service_authority(&service_authority,
            custody_daemon_mode) != 0) {
        close_service_authority(&service_authority);
        fputs("PLAMEN_BROKER_V2_SERVICE_HARDSTOP_NATIVE_INSTALL_RECEIPT_REQUIRED\n",
            stderr);
        return PLAMEN_SERVICE_HARDSTOP;
    }
    if (custody_daemon_mode) {
        const struct plamen_install_receipt_member *service =
            &service_authority.receipt.members[
                PLAMEN_INSTALL_MEMBER_SERVICE - 1];
        if (custody_daemon_peer_requirement(service, peer_requirement,
                sizeof(peer_requirement)) != 0) {
            close_service_authority(&service_authority);
            return PLAMEN_SERVICE_HARDSTOP;
        }
        memcpy(custody_readiness.installation_receipt_sha256,
            service_authority.installation_receipt_sha256, 32);
        memcpy(custody_readiness.generation_id_sha256,
            service_authority.receipt.generation_id_sha256, 32);
        memcpy(custody_readiness.service_sha256, service->sha256, 32);
        plamen_broker_v2_process_custody_daemon_run(
            service_authority.process_custodian, &custody_readiness,
            peer_requirement,
            admit_custody_daemon_peer);
    } else {
        const struct plamen_install_receipt_member *service =
            &service_authority.receipt.members[
                PLAMEN_INSTALL_MEMBER_SERVICE - 1];
        if (custody_daemon_peer_requirement(service, peer_requirement,
                sizeof(peer_requirement)) != 0
            || plamen_broker_v2_process_custody_client_open(
                peer_requirement, admit_custody_daemon_peer,
                &service_authority.custody_client) != 0) {
            close_service_authority(&service_authority);
            return PLAMEN_SERVICE_HARDSTOP;
        }
        memcpy(custody_readiness.installation_receipt_sha256,
            service_authority.installation_receipt_sha256, 32);
        memcpy(custody_readiness.generation_id_sha256,
            service_authority.receipt.generation_id_sha256, 32);
        memcpy(custody_readiness.service_sha256, service->sha256, 32);
        if (plamen_broker_v2_process_custody_client_readiness(
                service_authority.custody_client, &custody_readiness,
                &custody_status)
                != PLAMEN_BROKER_V2_CUSTODY_CLIENT_OK
            || custody_status != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK) {
            close_service_authority(&service_authority);
            return PLAMEN_SERVICE_HARDSTOP;
        }
    }
    plamen_broker_v2_secure_zero(&custody_readiness,
        sizeof(custody_readiness));
    run_listener();
    close_service_authority(&service_authority);
    return PLAMEN_SERVICE_HARDSTOP;
}
