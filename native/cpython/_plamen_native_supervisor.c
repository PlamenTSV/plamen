#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#ifdef __linux__
#define _GNU_SOURCE 1
#endif
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "../include/plamen_broker_v2.h"
#if defined(__APPLE__) && !defined(PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY) && \
        defined(PLAMEN_NATIVE_INSTALLED_BACKEND_GENERATION_V1)
#define PLAMEN_NATIVE_INSTALLED_BACKEND_GENERATION_ENABLED 1
#endif
#if defined(__APPLE__) && !defined(PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY)
#include "../darwin/plamen_broker_v2_install_receipt.h"
#ifdef PLAMEN_NATIVE_INSTALLED_BACKEND_GENERATION_ENABLED
#include "../darwin/plamen_native_source_bootstrap_coordinator_v1.h"
#endif
#endif
#if defined(__linux__) && !defined(PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY)
#include "../linux/plamen_linux_install_receipt_v2.h"
#include "plamen_linux_install_release_pins_v2.generated.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#ifndef __APPLE__
#include <sys/random.h>
#endif
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__) && !defined(PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY)
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <libproc.h>
#include <xpc/xpc.h>
#endif

/*
 * This extension is an authority-consumption boundary and authenticated
 * canonical-bytes RPC client.  Its platform bootstrap accepts only a retained
 * native install receipt plus the authenticated broker service; Python has no
 * constructor, registry, callback, argv/environment token, descriptor, key,
 * or authority factory.
 */

#define PLAMEN_PROTOCOL_VERSION 1U
#define PLAMEN_PROTOCOL_MAX_PAYLOAD 128U
#define PLAMEN_PROTOCOL_FIRST_SEQUENCE UINT64_C(1)
#define PLAMEN_IO_DEADLINE_MS 1000

/*
 * Broker v2 is a separate, canonical wire protocol.  Keep the old TEST_ONLY
 * parser below until its existing tests and callers are retired, but never
 * accept a v1 frame through the v2 consumer.  Production exposes the static
 * types, ABI constants, and a C-only module-initialization acquisition path.
 * That path publishes no INITIAL_AUTHORITY until the installed launcher/service
 * bootstrap described by the v2 contract supplies a fully admitted session.
 */
#define PLAMEN_BROKER_V2_AUTH_PAYLOAD_MAX \
    PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE
#define PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS INT64_C(60000)
#define PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS INT64_C(1800000)
#define PLAMEN_V2_OPERATION_WAIT_DEADLINE_MS INT64_C(259500000)

#if defined(__APPLE__)
#define PLAMEN_NATIVE_PLATFORM_NAME "MACOS"
#elif defined(__linux__)
#define PLAMEN_NATIVE_PLATFORM_NAME "LINUX"
#elif defined(_WIN32)
#define PLAMEN_NATIVE_PLATFORM_NAME "WINDOWS"
#else
#define PLAMEN_NATIVE_PLATFORM_NAME "UNKNOWN"
#endif

static const unsigned char PLAMEN_BROKER_V2_MAGIC[8] = {
    'P', 'L', 'M', 'B', 'R', 'K', '2', '\0'
};

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
#define PLAMEN_MODULE_NAME "_plamen_native_supervisor_testonly"
#define PLAMEN_PRODUCTION_TYPE_NAME \
    "_plamen_native_supervisor_testonly.NativeAuthorityConsumer"
#define PLAMEN_TEST_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_NativeAuthorityConsumer"
#define PLAMEN_V2_CONSUMER_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_BrokerV2AuthorityConsumer"
#define PLAMEN_V2_BUNDLE_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_SupervisorAuthorities"
#define PLAMEN_V2_RUNTIME_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_RuntimeImageAuthority"
#define PLAMEN_V2_WORKSPACE_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_WorkspaceAuthority"
#define PLAMEN_V2_BACKEND_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_BackendContextAuthority"
#define PLAMEN_V2_PROVIDER_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_ProviderAuthority"
#define PLAMEN_V2_GUEST_ADMISSION_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_GuestAdmissionAuthority"
#define PLAMEN_V2_EXTINCTION_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_ExtinctionAuthority"
#define PLAMEN_V2_ARTIFACT_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_ArtifactAuthority"
#define PLAMEN_V2_EXPORT_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_ExportAuthority"
#define PLAMEN_V2_JOURNAL_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_JournalAuthority"
#define PLAMEN_V2_RECOVERY_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_RecoveryAuthority"
#define PLAMEN_V2_GUEST_BUNDLE_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_GuestDriverAuthorities"
#define PLAMEN_V2_BACKEND_EXECUTION_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_BackendExecutionAuthority"
#define PLAMEN_V2_SUPERVISOR_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_SupervisorAuthority"
#define PLAMEN_V2_PROCESS_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_ProcessReceiptProjection"
#define PLAMEN_V2_EXIT_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_ExitReceiptProjection"
#define PLAMEN_V2_NETWORK_TYPE_NAME \
    "_plamen_native_supervisor_testonly.TEST_ONLY_NetworkReceiptProjection"
#define PLAMEN_JS_AUTHORITY_TYPE_NAME \
    "_plamen_native_supervisor_testonly.JSDependencyMaterializerAuthority"
#define PLAMEN_JS_SESSION_TYPE_NAME \
    "_plamen_native_supervisor_testonly.JSDependencyMaterializerSessionLease"
#define PLAMEN_JS_EXECUTION_TYPE_NAME \
    "_plamen_native_supervisor_testonly.JSDependencyMaterializerExecutionLease"
#define PLAMEN_JS_REPLAY_TYPE_NAME \
    "_plamen_native_supervisor_testonly.JSDependencyMaterializerTerminalReplayLease"
#define PLAMEN_MANAGED_INITIAL_TYPE_NAME \
    "_plamen_native_supervisor_testonly.ManagedEVMToolchainInitialAuthority"
#define PLAMEN_MANAGED_LEASE_TYPE_NAME \
    "_plamen_native_supervisor_testonly.ManagedEVMToolchainProvisionLease"
#define PLAMEN_MANAGED_TERMINAL_TYPE_NAME \
    "_plamen_native_supervisor_testonly.ManagedEVMToolchainProvisionTerminal"
#define PLAMEN_EVM_PROJECTION_TYPE_NAME \
    "_plamen_native_supervisor_testonly.EVMAnalysisProjectionAuthority"
#define PLAMEN_DARWIN_TOOL_CUSTODY_TYPE_NAME \
    "_plamen_native_supervisor_testonly.DarwinToolCustodyAuthority"
#define PLAMEN_DARWIN_TOOL_EXECUTION_TYPE_NAME \
    "_plamen_native_supervisor_testonly.DarwinToolExecutionLease"
#define PLAMEN_DARWIN_TOOL_TERMINAL_TYPE_NAME \
    "_plamen_native_supervisor_testonly.DarwinToolExecutionTerminal"
#define PLAMEN_APPLE_FUZZ_SERVICE_TYPE_NAME \
    "_plamen_native_supervisor_testonly.AppleFuzzServiceSessionAuthority"
#define PLAMEN_APPLE_FUZZ_LEASE_TYPE_NAME \
    "_plamen_native_supervisor_testonly.AppleFuzzAdmissionContinuationLease"
#define PLAMEN_APPLE_FUZZ_TERMINAL_TYPE_NAME \
    "_plamen_native_supervisor_testonly.AppleFuzzLifecycleTerminal"
#define PLAMEN_BACKEND_INSTALL_GENERATION_TYPE_NAME \
    "_plamen_native_supervisor_testonly.BackendInstallGenerationAuthority"
#define PLAMEN_MODULE_INIT PyInit__plamen_native_supervisor_testonly
#else
#define PLAMEN_MODULE_NAME "_plamen_native_supervisor"
#define PLAMEN_PRODUCTION_TYPE_NAME \
    "_plamen_native_supervisor.NativeAuthorityConsumer"
#define PLAMEN_V2_CONSUMER_TYPE_NAME \
    "_plamen_native_supervisor.NativeAuthorityConsumer"
#define PLAMEN_V2_BUNDLE_TYPE_NAME \
    "_plamen_native_supervisor.SupervisorAuthorities"
#define PLAMEN_V2_RUNTIME_TYPE_NAME \
    "_plamen_native_supervisor.RuntimeImageAuthority"
#define PLAMEN_V2_WORKSPACE_TYPE_NAME \
    "_plamen_native_supervisor.WorkspaceAuthority"
#define PLAMEN_V2_BACKEND_TYPE_NAME \
    "_plamen_native_supervisor.BackendContextAuthority"
#define PLAMEN_V2_PROVIDER_TYPE_NAME \
    "_plamen_native_supervisor.ProviderAuthority"
#define PLAMEN_V2_GUEST_ADMISSION_TYPE_NAME \
    "_plamen_native_supervisor.GuestAdmissionAuthority"
#define PLAMEN_V2_EXTINCTION_TYPE_NAME \
    "_plamen_native_supervisor.ExtinctionAuthority"
#define PLAMEN_V2_ARTIFACT_TYPE_NAME \
    "_plamen_native_supervisor.ArtifactAuthority"
#define PLAMEN_V2_EXPORT_TYPE_NAME \
    "_plamen_native_supervisor.ExportAuthority"
#define PLAMEN_V2_JOURNAL_TYPE_NAME \
    "_plamen_native_supervisor.JournalAuthority"
#define PLAMEN_V2_RECOVERY_TYPE_NAME \
    "_plamen_native_supervisor.RecoveryAuthority"
#define PLAMEN_V2_GUEST_BUNDLE_TYPE_NAME \
    "_plamen_native_supervisor.GuestDriverAuthorities"
#define PLAMEN_V2_BACKEND_EXECUTION_TYPE_NAME \
    "_plamen_native_supervisor.BackendExecutionAuthority"
#define PLAMEN_V2_SUPERVISOR_TYPE_NAME \
    "_plamen_native_supervisor.SupervisorAuthority"
#define PLAMEN_V2_PROCESS_TYPE_NAME \
    "_plamen_native_supervisor.ProcessReceiptProjection"
#define PLAMEN_V2_EXIT_TYPE_NAME \
    "_plamen_native_supervisor.ExitReceiptProjection"
#define PLAMEN_V2_NETWORK_TYPE_NAME \
    "_plamen_native_supervisor.NetworkReceiptProjection"
#define PLAMEN_JS_AUTHORITY_TYPE_NAME \
    "_plamen_native_supervisor.JSDependencyMaterializerAuthority"
#define PLAMEN_JS_SESSION_TYPE_NAME \
    "_plamen_native_supervisor.JSDependencyMaterializerSessionLease"
#define PLAMEN_JS_EXECUTION_TYPE_NAME \
    "_plamen_native_supervisor.JSDependencyMaterializerExecutionLease"
#define PLAMEN_JS_REPLAY_TYPE_NAME \
    "_plamen_native_supervisor.JSDependencyMaterializerTerminalReplayLease"
#define PLAMEN_MANAGED_INITIAL_TYPE_NAME \
    "_plamen_native_supervisor.ManagedEVMToolchainInitialAuthority"
#define PLAMEN_MANAGED_LEASE_TYPE_NAME \
    "_plamen_native_supervisor.ManagedEVMToolchainProvisionLease"
#define PLAMEN_MANAGED_TERMINAL_TYPE_NAME \
    "_plamen_native_supervisor.ManagedEVMToolchainProvisionTerminal"
#define PLAMEN_EVM_PROJECTION_TYPE_NAME \
    "_plamen_native_supervisor.EVMAnalysisProjectionAuthority"
#define PLAMEN_DARWIN_TOOL_CUSTODY_TYPE_NAME \
    "_plamen_native_supervisor.DarwinToolCustodyAuthority"
#define PLAMEN_DARWIN_TOOL_EXECUTION_TYPE_NAME \
    "_plamen_native_supervisor.DarwinToolExecutionLease"
#define PLAMEN_DARWIN_TOOL_TERMINAL_TYPE_NAME \
    "_plamen_native_supervisor.DarwinToolExecutionTerminal"
#define PLAMEN_APPLE_FUZZ_SERVICE_TYPE_NAME \
    "_plamen_native_supervisor.AppleFuzzServiceSessionAuthority"
#define PLAMEN_APPLE_FUZZ_LEASE_TYPE_NAME \
    "_plamen_native_supervisor.AppleFuzzAdmissionContinuationLease"
#define PLAMEN_APPLE_FUZZ_TERMINAL_TYPE_NAME \
    "_plamen_native_supervisor.AppleFuzzLifecycleTerminal"
#define PLAMEN_BACKEND_INSTALL_GENERATION_TYPE_NAME \
    "_plamen_native_supervisor.BackendInstallGenerationAuthority"
#define PLAMEN_MODULE_INIT PyInit__plamen_native_supervisor
#endif

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static const unsigned char PLAMEN_SESSION_MAGIC[8] = {
    'P', 'L', 'A', 'M', 'E', 'N', 'S', '1'
};
static const unsigned char PLAMEN_FRAME_MAGIC[8] = {
    'P', 'L', 'A', 'M', 'E', 'N', 'F', '1'
};
#endif

/*
 * Canonical wire structs use byte arrays for every integer so their layout is
 * independent of host endianness and compiler alignment.  Integer fields are
 * unsigned, big-endian.  A future authenticated broker must authenticate the
 * complete byte stream before it can create a production consumer.
 */
typedef struct {
    unsigned char magic[8];
    unsigned char version_be[2];
    unsigned char header_size_be[2];
    unsigned char session_id[32];
    unsigned char reserved_be[4];
} PlamenNativeSessionV1;

typedef struct {
    unsigned char magic[8];
    unsigned char version_be[2];
    unsigned char frame_type_be[2];
    unsigned char header_size_be[4];
    unsigned char payload_size_be[4];
    unsigned char sequence_be[8];
    unsigned char session_id[32];
    unsigned char request_fingerprint[32];
} PlamenNativeFrameV1;

_Static_assert(sizeof(PlamenNativeSessionV1) == 48,
               "unexpected session header layout");
_Static_assert(sizeof(PlamenNativeFrameV1) == 92,
               "unexpected frame header layout");

typedef struct {
    PyObject_HEAD
    pid_t creator_pid;
    int64_t creator_interpreter_id;
    _Atomic int consumed;
    int session_fd;
    unsigned char expected_fingerprint[32];
    unsigned char expected_session_id[32];
    char expected_attempt[129];
    Py_ssize_t expected_attempt_len;
} NativeAuthorityConsumerObject;

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static PyTypeObject NativeAuthorityConsumerType;
static PyTypeObject TestOnlyNativeAuthorityConsumerType;

static void
close_session_fd(NativeAuthorityConsumerObject *self)
{
    int fd = self->session_fd;
    self->session_fd = -1;
    if (fd >= 0) {
        int saved_errno = errno;
        /* Never retry close(2): after EINTR, descriptor state is platform-specific. */
        (void)close(fd);
        errno = saved_errno;
    }
}
#endif

static PyObject *
consumer_forbidden_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    (void)type;
    (void)args;
    (void)kwargs;
    PyErr_SetString(PyExc_TypeError,
                    "native authority consumers cannot be constructed by Python");
    return NULL;
}

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static void
consumer_dealloc(PyObject *object)
{
    NativeAuthorityConsumerObject *self =
        (NativeAuthorityConsumerObject *)object;
    close_session_fd(self);
    PyObject_Del(object);
}
#endif

static PyObject *
consumer_forbidden_copy(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    (void)self;
    PyErr_SetString(PyExc_TypeError,
                    "native authority consumers cannot be copied or serialized");
    return NULL;
}

static PyObject *
consumer_forbidden_deepcopy(PyObject *self, PyObject *args)
{
    (void)self;
    (void)args;
    PyErr_SetString(PyExc_TypeError,
                    "native authority consumers cannot be copied or serialized");
    return NULL;
}

static PyObject *
consumer_forbidden_reduce(PyObject *self, PyObject *args)
{
    (void)self;
    (void)args;
    PyErr_SetString(PyExc_TypeError,
                    "native authority consumers cannot be copied or serialized");
    return NULL;
}

static int64_t
current_interpreter_id(void)
{
    PyThreadState *thread_state = PyThreadState_Get();
    if (thread_state == NULL) {
        return -1;
    }
    return PyInterpreterState_GetID(PyThreadState_GetInterpreter(thread_state));
}

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static int
burn_consumer(NativeAuthorityConsumerObject *self)
{
    if (atomic_exchange_explicit(&self->consumed, 1, memory_order_acq_rel) != 0) {
        close_session_fd(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority consumer is already consumed");
        return -1;
    }
    return 0;
}

static PyObject *
production_consume_once(PyObject *object, PyObject *args)
{
    NativeAuthorityConsumerObject *self =
        (NativeAuthorityConsumerObject *)object;
    (void)args;

    /* The one-shot is irreversibly burned before every other observation. */
    if (burn_consumer(self) < 0) {
        return NULL;
    }
    close_session_fd(self);
    PyErr_SetString(
        PyExc_RuntimeError,
        "production native authority acquisition is unavailable until an "
        "authenticated native dispatcher is integrated"
    );
    return NULL;
}

static PyMethodDef production_consumer_methods[] = {
    {"consume_once", production_consume_once, METH_VARARGS,
     PyDoc_STR("Consume an authenticated native authority exactly once.")},
    {"__copy__", consumer_forbidden_copy, METH_NOARGS, NULL},
    {"__deepcopy__", consumer_forbidden_deepcopy, METH_VARARGS, NULL},
    {"__reduce__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__reduce_ex__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__getnewargs__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyTypeObject NativeAuthorityConsumerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PLAMEN_PRODUCTION_TYPE_NAME,
    .tp_basicsize = sizeof(NativeAuthorityConsumerObject),
    .tp_dealloc = consumer_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION,
    .tp_doc = PyDoc_STR("Opaque one-shot native authority consumer."),
    .tp_methods = production_consumer_methods,
    .tp_new = consumer_forbidden_new,
};
#endif

typedef struct V2SharedNativeSession V2SharedNativeSession;

typedef struct {
    uint16_t role;
    uint16_t member;
    uint16_t method;
    uint16_t flags;
    unsigned char payload_sha256[32];
    unsigned char prior_checkpoint_sha256[32];
    unsigned char operation_key[32];
    unsigned char request_sha256[32];
} V2RpcReplayEntry;

_Static_assert(
    sizeof(V2RpcReplayEntry) * PLAMEN_BROKER_V2_RPC_REPLAY_MAX_ENTRIES <=
        PLAMEN_BROKER_V2_RPC_REPLAY_METADATA_MAX,
    "broker v2 replay metadata exceeds its frozen bound");

struct V2SharedNativeSession {
    _Atomic unsigned int references;
    pid_t creator_pid;
    int64_t creator_interpreter_id;
    int control_fd;
    uint16_t role;
    uint64_t next_sequence;
    PyThread_type_lock operation_lock;
    unsigned char key[32];
    unsigned char session_id[32];
    unsigned char previous_frame_sha256[32];
    unsigned char issuance_checkpoint_sha256[32];
    unsigned char current_checkpoint_sha256[32];
    struct plamen_broker_v2_commitment commitment;
    V2RpcReplayEntry *replay_entries;
    size_t replay_count;
};

typedef struct {
    PyObject_HEAD
    pid_t creator_pid;
    int64_t creator_interpreter_id;
    _Atomic int consumed;
    unsigned int kind;
    unsigned char member_capability_id[32];
    V2SharedNativeSession *native_session;
} V2OpaqueCapabilityObject;

typedef struct {
    PyObject_HEAD
    pid_t creator_pid;
    int64_t creator_interpreter_id;
    _Atomic int consumed;
    PyObject *runtime;
    PyObject *workspace;
    PyObject *backend;
    PyObject *provider;
    PyObject *guest_admission;
    PyObject *extinction;
    PyObject *artifacts;
    PyObject *exporter;
    PyObject *journal;
    PyObject *recovery;
} V2AuthorityBundleObject;

typedef struct {
    PyObject_HEAD
    pid_t creator_pid;
    int64_t creator_interpreter_id;
    _Atomic int consumed;
    PyObject *backend_execution;
} V2GuestAuthorityBundleObject;

typedef struct {
    PyObject_HEAD
    pid_t creator_pid;
    int64_t creator_interpreter_id;
    _Atomic int consumed;
    uint16_t initial_authority_role;
    int session_fd;
    int test_peer_fd;
    unsigned char session_key[32];
    unsigned char expected_session_id[32];
    unsigned char expected_operation_nonce[32];
    unsigned char expected_fingerprint[32];
    unsigned char expected_registration_sha256[32];
    unsigned char expected_issuance_checkpoint_sha256[32];
    unsigned char expected_authority_bundle_sha256[32];
    unsigned char expected_request_projection_sha256[32];
    unsigned char native_deployment_receipt_sha256[32];
    unsigned char runtime_closure_sha256[32];
    unsigned char broker_peer_identity_sha256[32];
    unsigned char managed_toolchain_custody_sha256[32];
    uint32_t expected_request_projection_size;
    unsigned char previous_frame_sha256[32];
    unsigned char *request_projection;
    size_t request_projection_size;
    int protocol_ready;
    char expected_attempt[129];
    Py_ssize_t expected_attempt_len;
    unsigned char expected_auth_payload[PLAMEN_BROKER_V2_AUTH_PAYLOAD_MAX];
    size_t expected_auth_payload_size;
} V2AuthorityConsumerObject;

static PyTypeObject V2AuthorityConsumerType;
static PyTypeObject V2AuthorityBundleType;
static PyTypeObject V2GuestAuthorityBundleType;
static PyTypeObject V2RuntimeAuthorityType;
static PyTypeObject V2WorkspaceAuthorityType;
static PyTypeObject V2BackendAuthorityType;
static PyTypeObject V2ProviderAuthorityType;
static PyTypeObject V2GuestAdmissionAuthorityType;
static PyTypeObject V2ExtinctionAuthorityType;
static PyTypeObject V2ArtifactAuthorityType;
static PyTypeObject V2ExportAuthorityType;
static PyTypeObject V2JournalAuthorityType;
static PyTypeObject V2RecoveryAuthorityType;
static PyTypeObject V2BackendExecutionAuthorityType;
static PyTypeObject V2SupervisorAuthorityType;
static PyTypeObject V2ProcessReceiptType;
static PyTypeObject V2ExitReceiptType;
static PyTypeObject V2NetworkReceiptType;

static void
secure_zero(void *raw, size_t size)
{
    volatile unsigned char *bytes = (volatile unsigned char *)raw;
    while (size-- != 0) {
        *bytes++ = 0;
    }
}

static V2SharedNativeSession *
v2_shared_session_new(pid_t creator_pid, int64_t creator_interpreter_id,
                      uint16_t role, int owned_control_fd,
                      const unsigned char key[32],
                      const unsigned char session_id[32],
                      const unsigned char previous_frame_sha256[32],
                      uint64_t next_sequence,
                      const unsigned char issuance_checkpoint_sha256[32],
                      const struct plamen_broker_v2_commitment *commitment)
{
    V2SharedNativeSession *session;

    if (owned_control_fd < 0 || key == NULL || session_id == NULL ||
            previous_frame_sha256 == NULL ||
            issuance_checkpoint_sha256 == NULL || commitment == NULL ||
            (role != PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR &&
             role != PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER)) {
        return NULL;
    }
    session = (V2SharedNativeSession *)calloc(1, sizeof(*session));
    if (session == NULL) {
        return NULL;
    }
    atomic_init(&session->references, 1U);
    session->operation_lock = PyThread_allocate_lock();
    if (session->operation_lock == NULL) {
        free(session);
        return NULL;
    }
    session->creator_pid = creator_pid;
    session->creator_interpreter_id = creator_interpreter_id;
    session->control_fd = owned_control_fd;
    session->role = role;
    session->next_sequence = next_sequence;
    memcpy(session->key, key, 32);
    memcpy(session->session_id, session_id, 32);
    memcpy(session->previous_frame_sha256, previous_frame_sha256, 32);
    memcpy(session->issuance_checkpoint_sha256,
           issuance_checkpoint_sha256, 32);
    memcpy(session->current_checkpoint_sha256,
           issuance_checkpoint_sha256, 32);
    session->commitment = *commitment;
    return session;
}

static void
v2_shared_session_retain(V2SharedNativeSession *session)
{
    if (session != NULL) {
        (void)atomic_fetch_add_explicit(&session->references, 1U,
                                        memory_order_relaxed);
    }
}

static void
v2_shared_session_release(V2SharedNativeSession *session)
{
    if (session == NULL ||
            atomic_fetch_sub_explicit(&session->references, 1U,
                                      memory_order_acq_rel) != 1U) {
        return;
    }
    if (session->control_fd >= 0) {
        (void)close(session->control_fd);
        session->control_fd = -1;
    }
    if (session->operation_lock != NULL) {
        PyThread_free_lock(session->operation_lock);
        session->operation_lock = NULL;
    }
    if (session->replay_entries != NULL) {
        secure_zero(session->replay_entries,
                    sizeof(*session->replay_entries) * session->replay_count);
        free(session->replay_entries);
        session->replay_entries = NULL;
    }
    secure_zero(session->key, sizeof(session->key));
    secure_zero(session->session_id, sizeof(session->session_id));
    secure_zero(session->previous_frame_sha256,
                sizeof(session->previous_frame_sha256));
    secure_zero(session->issuance_checkpoint_sha256,
                sizeof(session->issuance_checkpoint_sha256));
    secure_zero(session->current_checkpoint_sha256,
                sizeof(session->current_checkpoint_sha256));
    plamen_broker_v2_secure_zero(&session->commitment,
                                 sizeof(session->commitment));
    session->replay_count = 0;
    session->role = 0;
    session->next_sequence = 0;
    session->creator_pid = 0;
    session->creator_interpreter_id = -1;
    free(session);
}

static PyObject *
opaque_capability_repr(PyObject *object)
{
    (void)object;
    return PyUnicode_FromString("<plamen native capability: opaque>");
}

static void
v2_opaque_dealloc(PyObject *object)
{
    V2OpaqueCapabilityObject *self = (V2OpaqueCapabilityObject *)object;
    v2_shared_session_release(self->native_session);
    self->native_session = NULL;
    secure_zero((unsigned char *)self + sizeof(PyObject),
                sizeof(*self) - sizeof(PyObject));
    PyObject_Del(object);
}

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static int
burn_v2_opaque(V2OpaqueCapabilityObject *self)
{
    if (atomic_exchange_explicit(&self->consumed, 1, memory_order_acq_rel) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native capability is already consumed");
        return -1;
    }
    if (getpid() != self->creator_pid) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native capability cannot cross a process boundary");
        return -1;
    }
    if (current_interpreter_id() != self->creator_interpreter_id) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native capability cannot cross an interpreter boundary");
        return -1;
    }
    return 0;
}

static PyObject *
v2_opaque_consume_once(PyObject *object, PyObject *args)
{
    V2OpaqueCapabilityObject *self = (V2OpaqueCapabilityObject *)object;
    static const char *const kind_names[] = {
        "INVALID", "RUNTIME", "WORKSPACE", "BACKEND", "PROVIDER",
        "GUEST_ADMISSION", "EXTINCTION", "ARTIFACTS", "EXPORTER",
        "JOURNAL", "RECOVERY", "SUPERVISOR", "PROCESS", "EXIT",
        "NETWORK", "BACKEND_EXECUTION"
    };
    if (!PyArg_ParseTuple(args, ":consume_once")) {
        return NULL;
    }
    if (burn_v2_opaque(self) < 0) {
        return NULL;
    }
    if (self->native_session == NULL ||
            self->native_session->control_fd < 0 ||
            self->native_session->creator_pid != self->creator_pid ||
            self->native_session->creator_interpreter_id !=
                self->creator_interpreter_id ||
            fcntl(self->native_session->control_fd, F_GETFD) < 0 ||
            self->kind < 1U || self->kind > 15U) {
        PyErr_SetString(PyExc_RuntimeError, "native capability is invalid");
        return NULL;
    }
    return PyUnicode_FromString(kind_names[self->kind]);
}

static PyMethodDef v2_opaque_methods[] = {
    {"consume_once", v2_opaque_consume_once, METH_VARARGS,
     PyDoc_STR("Consume this opaque native capability exactly once.")},
    {"__copy__", consumer_forbidden_copy, METH_NOARGS, NULL},
    {"__deepcopy__", consumer_forbidden_deepcopy, METH_VARARGS, NULL},
    {"__reduce__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__reduce_ex__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__getnewargs__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};
#else
static PyMethodDef v2_opaque_methods[] = {
    {"__copy__", consumer_forbidden_copy, METH_NOARGS, NULL},
    {"__deepcopy__", consumer_forbidden_deepcopy, METH_VARARGS, NULL},
    {"__reduce__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__reduce_ex__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__getnewargs__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};
#endif

#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static PyObject *
v2_operation_rpc(PyObject *object, PyObject *args, uint16_t member,
                 uint16_t method, uint16_t flags, int64_t receive_timeout_ms);
#define PLAMEN_V2_OPERATION_CALL(object, args, member, method, flags, deadline, \
                                 operation_name) \
    v2_operation_rpc(object, args, member, method, flags, deadline)
#else
static PyObject *
v2_operation_schema_hardstop(PyObject *object, PyObject *args,
                             Py_ssize_t expected_arity,
                             const char *operation_name)
{
    (void)object;
    if (!PyTuple_Check(args) || PyTuple_GET_SIZE(args) != expected_arity) {
        PyErr_Format(PyExc_TypeError, "%s requires exactly %zd positional arguments",
                     operation_name, expected_arity);
        return NULL;
    }
    PyErr_SetString(
        PyExc_RuntimeError,
        "native broker v2 operation unavailable: authenticated schema is not frozen");
    return NULL;
}
#define PLAMEN_V2_OPERATION_CALL(object, args, member, method, flags, deadline, \
                                 operation_name) \
    v2_operation_schema_hardstop(object, args, 1, operation_name)
#endif

#define PLAMEN_V2_RPC_WRAPPER(function_name, python_name, member, method, \
                              flags, deadline) \
    static PyObject *function_name(PyObject *object, PyObject *args) \
    { \
        (void)python_name; \
        return PLAMEN_V2_OPERATION_CALL(object, args, member, method, flags, \
                                        deadline, python_name); \
    }

PLAMEN_V2_RPC_WRAPPER(v2_runtime_authenticate, "authenticate",
    PLAMEN_BROKER_V2_AUTHORITY_RUNTIME_IMAGE,
    PLAMEN_BROKER_V2_METHOD_RUNTIME_AUTHENTICATE, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_workspace_admit_target, "admit_target",
    PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_workspace_revalidate_target, "revalidate_target",
    PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_REVALIDATE_TARGET, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_workspace_prepare_layout, "prepare_layout",
    PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_PREPARE_LAYOUT, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_workspace_resume_layout, "resume_layout",
    PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_RESUME_LAYOUT, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_workspace_write_guest_config, "write_guest_config",
    PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_WRITE_GUEST_CONFIG, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_workspace_recensus_layout, "recensus_layout",
    PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_RECENSUS_LAYOUT, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_backend_authenticate, "authenticate",
    PLAMEN_BROKER_V2_AUTHORITY_BACKEND_CONTEXT,
    PLAMEN_BROKER_V2_METHOD_BACKEND_AUTHENTICATE, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_provider_kind, "provider_kind",
    PLAMEN_BROKER_V2_AUTHORITY_PROVIDER_LIFECYCLE,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_provider_create_stopped, "create_stopped",
    PLAMEN_BROKER_V2_AUTHORITY_PROVIDER_LIFECYCLE,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_CREATE_STOPPED, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_provider_inspect_stopped, "inspect_stopped",
    PLAMEN_BROKER_V2_AUTHORITY_PROVIDER_LIFECYCLE,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_INSPECT_STOPPED, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_provider_resume_guest, "resume_guest",
    PLAMEN_BROKER_V2_AUTHORITY_PROVIDER_LIFECYCLE,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_RESUME_GUEST, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_provider_start_driver, "start_driver",
    PLAMEN_BROKER_V2_AUTHORITY_PROVIDER_LIFECYCLE,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_START_DRIVER, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_provider_wait_driver, "wait_driver",
    PLAMEN_BROKER_V2_AUTHORITY_PROVIDER_LIFECYCLE,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_WAIT_DRIVER, 0,
    PLAMEN_V2_OPERATION_WAIT_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_provider_delete_guest, "delete_guest",
    PLAMEN_BROKER_V2_AUTHORITY_PROVIDER_LIFECYCLE,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_DELETE_GUEST, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_guest_admit_stopped_guest, "admit_stopped_guest",
    PLAMEN_BROKER_V2_AUTHORITY_GUEST_ADMISSION,
    PLAMEN_BROKER_V2_METHOD_GUEST_ADMIT_STOPPED, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_guest_resume_admission, "resume_admission",
    PLAMEN_BROKER_V2_AUTHORITY_GUEST_ADMISSION,
    PLAMEN_BROKER_V2_METHOD_GUEST_RESUME_ADMISSION, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_extinction_extinguish, "extinguish",
    PLAMEN_BROKER_V2_AUTHORITY_EXTINCTION,
    PLAMEN_BROKER_V2_METHOD_EXTINCTION_EXTINGUISH, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_artifact_census, "census",
    PLAMEN_BROKER_V2_AUTHORITY_ARTIFACT,
    PLAMEN_BROKER_V2_METHOD_ARTIFACT_CENSUS, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_export_export, "export",
    PLAMEN_BROKER_V2_AUTHORITY_EXPORT,
    PLAMEN_BROKER_V2_METHOD_EXPORT_EXPORT, 0,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_journal_open, "open",
    PLAMEN_BROKER_V2_AUTHORITY_DURABLE_JOURNAL,
    PLAMEN_BROKER_V2_METHOD_JOURNAL_OPEN, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_journal_arm, "arm",
    PLAMEN_BROKER_V2_AUTHORITY_DURABLE_JOURNAL,
    PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_journal_commit, "commit",
    PLAMEN_BROKER_V2_AUTHORITY_DURABLE_JOURNAL,
    PLAMEN_BROKER_V2_METHOD_JOURNAL_COMMIT, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_journal_resolve, "resolve",
    PLAMEN_BROKER_V2_AUTHORITY_DURABLE_JOURNAL,
    PLAMEN_BROKER_V2_METHOD_JOURNAL_RESOLVE, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_journal_finish, "finish",
    PLAMEN_BROKER_V2_AUTHORITY_DURABLE_JOURNAL,
    PLAMEN_BROKER_V2_METHOD_JOURNAL_FINISH, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_recovery_recover, "recover",
    PLAMEN_BROKER_V2_AUTHORITY_RECOVERY,
    PLAMEN_BROKER_V2_METHOD_RECOVERY_RECOVER,
    PLAMEN_BROKER_V2_OPERATION_RECOVER,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_backend_execution_prepare, "prepare",
    PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION,
    PLAMEN_BROKER_V2_METHOD_BACKEND_PREPARE, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_backend_execution_start_or_recover,
    "start_or_recover", PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION,
    PLAMEN_BROKER_V2_METHOD_BACKEND_START_OR_RECOVER,
    PLAMEN_BROKER_V2_OPERATION_RECOVER,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_backend_execution_wait_or_recover,
    "wait_or_recover", PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION,
    PLAMEN_BROKER_V2_METHOD_BACKEND_WAIT_OR_RECOVER,
    PLAMEN_BROKER_V2_OPERATION_RECOVER,
    PLAMEN_V2_OPERATION_WAIT_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_backend_execution_read_output_or_recover,
    "read_output_or_recover",
    PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION,
    PLAMEN_BROKER_V2_METHOD_BACKEND_READ_OUTPUT_OR_RECOVER,
    PLAMEN_BROKER_V2_OPERATION_RECOVER,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_backend_execution_extinguish_or_recover,
    "extinguish_or_recover",
    PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION,
    PLAMEN_BROKER_V2_METHOD_BACKEND_EXTINGUISH_OR_RECOVER,
    PLAMEN_BROKER_V2_OPERATION_RECOVER,
    PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS)
PLAMEN_V2_RPC_WRAPPER(v2_backend_execution_close_operation,
    "close_operation", PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION,
    PLAMEN_BROKER_V2_METHOD_BACKEND_CLOSE_OPERATION, 0,
    PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS)

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
#define PLAMEN_V2_TEST_CONSUME_METHOD \
    {"consume_once", v2_opaque_consume_once, METH_VARARGS, \
     PyDoc_STR("Consume this opaque TEST_ONLY capability exactly once.")},
#else
#define PLAMEN_V2_TEST_CONSUME_METHOD
#endif

#define PLAMEN_V2_SEALED_METHODS \
    PLAMEN_V2_TEST_CONSUME_METHOD \
    {"__copy__", consumer_forbidden_copy, METH_NOARGS, NULL}, \
    {"__deepcopy__", consumer_forbidden_deepcopy, METH_VARARGS, NULL}, \
    {"__reduce__", consumer_forbidden_reduce, METH_VARARGS, NULL}, \
    {"__reduce_ex__", consumer_forbidden_reduce, METH_VARARGS, NULL}, \
    {"__getnewargs__", consumer_forbidden_reduce, METH_VARARGS, NULL}

static PyMethodDef v2_runtime_methods[] = {
    {"authenticate", v2_runtime_authenticate, METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

static PyMethodDef v2_workspace_methods[] = {
    {"admit_target", v2_workspace_admit_target, METH_VARARGS, NULL},
    {"revalidate_target", v2_workspace_revalidate_target, METH_VARARGS, NULL},
    {"prepare_layout", v2_workspace_prepare_layout, METH_VARARGS, NULL},
    {"resume_layout", v2_workspace_resume_layout, METH_VARARGS, NULL},
    {"write_guest_config", v2_workspace_write_guest_config, METH_VARARGS, NULL},
    {"recensus_layout", v2_workspace_recensus_layout, METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

static PyMethodDef v2_backend_methods[] = {
    {"authenticate", v2_backend_authenticate, METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

static PyMethodDef v2_provider_methods[] = {
    {"provider_kind", v2_provider_kind, METH_VARARGS, NULL},
    {"create_stopped", v2_provider_create_stopped, METH_VARARGS, NULL},
    {"inspect_stopped", v2_provider_inspect_stopped, METH_VARARGS, NULL},
    {"resume_guest", v2_provider_resume_guest, METH_VARARGS, NULL},
    {"start_driver", v2_provider_start_driver, METH_VARARGS, NULL},
    {"wait_driver", v2_provider_wait_driver, METH_VARARGS, NULL},
    {"delete_guest", v2_provider_delete_guest, METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

static PyMethodDef v2_guest_admission_methods[] = {
    {"admit_stopped_guest", v2_guest_admit_stopped_guest, METH_VARARGS, NULL},
    {"resume_admission", v2_guest_resume_admission, METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

static PyMethodDef v2_extinction_methods[] = {
    {"extinguish", v2_extinction_extinguish, METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

static PyMethodDef v2_artifact_methods[] = {
    {"census", v2_artifact_census, METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

static PyMethodDef v2_export_methods[] = {
    {"export", v2_export_export, METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

static PyMethodDef v2_journal_methods[] = {
    {"open", v2_journal_open, METH_VARARGS, NULL},
    {"arm", v2_journal_arm, METH_VARARGS, NULL},
    {"commit", v2_journal_commit, METH_VARARGS, NULL},
    {"resolve", v2_journal_resolve, METH_VARARGS, NULL},
    {"finish", v2_journal_finish, METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

static PyMethodDef v2_recovery_methods[] = {
    {"recover", v2_recovery_recover, METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

static PyMethodDef v2_backend_execution_methods[] = {
    {"prepare", v2_backend_execution_prepare, METH_VARARGS, NULL},
    {"start_or_recover", v2_backend_execution_start_or_recover,
     METH_VARARGS, NULL},
    {"wait_or_recover", v2_backend_execution_wait_or_recover,
     METH_VARARGS, NULL},
    {"read_output_or_recover", v2_backend_execution_read_output_or_recover,
     METH_VARARGS, NULL},
    {"extinguish_or_recover", v2_backend_execution_extinguish_or_recover,
     METH_VARARGS, NULL},
    {"close_operation", v2_backend_execution_close_operation,
     METH_VARARGS, NULL},
    PLAMEN_V2_SEALED_METHODS,
    {NULL, NULL, 0, NULL}
};

#define PLAMEN_V2_OPAQUE_TYPE(variable, qualified_name, description, methods) \
    static PyTypeObject variable = { \
        PyVarObject_HEAD_INIT(NULL, 0) \
        .tp_name = qualified_name, \
        .tp_basicsize = sizeof(V2OpaqueCapabilityObject), \
        .tp_dealloc = v2_opaque_dealloc, \
        .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION, \
        .tp_doc = PyDoc_STR(description), \
        .tp_methods = methods, \
        .tp_repr = opaque_capability_repr, \
        .tp_new = consumer_forbidden_new, \
    }

PLAMEN_V2_OPAQUE_TYPE(V2RuntimeAuthorityType, PLAMEN_V2_RUNTIME_TYPE_NAME,
                      "Opaque one-shot runtime-image authority.",
                      v2_runtime_methods);
PLAMEN_V2_OPAQUE_TYPE(V2WorkspaceAuthorityType, PLAMEN_V2_WORKSPACE_TYPE_NAME,
                      "Opaque one-shot workspace authority.",
                      v2_workspace_methods);
PLAMEN_V2_OPAQUE_TYPE(V2BackendAuthorityType, PLAMEN_V2_BACKEND_TYPE_NAME,
                      "Opaque one-shot backend-context authority.",
                      v2_backend_methods);
PLAMEN_V2_OPAQUE_TYPE(V2ProviderAuthorityType, PLAMEN_V2_PROVIDER_TYPE_NAME,
                      "Opaque one-shot provider authority.",
                      v2_provider_methods);
PLAMEN_V2_OPAQUE_TYPE(V2GuestAdmissionAuthorityType,
                      PLAMEN_V2_GUEST_ADMISSION_TYPE_NAME,
                      "Opaque one-shot guest-admission authority.",
                      v2_guest_admission_methods);
PLAMEN_V2_OPAQUE_TYPE(V2ExtinctionAuthorityType,
                      PLAMEN_V2_EXTINCTION_TYPE_NAME,
                      "Opaque one-shot extinction authority.",
                      v2_extinction_methods);
PLAMEN_V2_OPAQUE_TYPE(V2ArtifactAuthorityType, PLAMEN_V2_ARTIFACT_TYPE_NAME,
                      "Opaque one-shot artifact authority.",
                      v2_artifact_methods);
PLAMEN_V2_OPAQUE_TYPE(V2ExportAuthorityType, PLAMEN_V2_EXPORT_TYPE_NAME,
                      "Opaque one-shot export authority.",
                      v2_export_methods);
PLAMEN_V2_OPAQUE_TYPE(V2JournalAuthorityType, PLAMEN_V2_JOURNAL_TYPE_NAME,
                      "Opaque one-shot journal authority.",
                      v2_journal_methods);
PLAMEN_V2_OPAQUE_TYPE(V2RecoveryAuthorityType, PLAMEN_V2_RECOVERY_TYPE_NAME,
                      "Opaque one-shot recovery authority.",
                      v2_recovery_methods);
PLAMEN_V2_OPAQUE_TYPE(V2BackendExecutionAuthorityType,
                      PLAMEN_V2_BACKEND_EXECUTION_TYPE_NAME,
                      "Opaque operation-keyed guest backend-execution authority.",
                      v2_backend_execution_methods);
PLAMEN_V2_OPAQUE_TYPE(V2SupervisorAuthorityType, PLAMEN_V2_SUPERVISOR_TYPE_NAME,
                      "Opaque one-shot supervisor authority.",
                      v2_opaque_methods);
PLAMEN_V2_OPAQUE_TYPE(V2ProcessReceiptType, PLAMEN_V2_PROCESS_TYPE_NAME,
                      "Opaque one-shot native process receipt projection.",
                      v2_opaque_methods);
PLAMEN_V2_OPAQUE_TYPE(V2ExitReceiptType, PLAMEN_V2_EXIT_TYPE_NAME,
                      "Opaque one-shot native exit receipt projection.",
                      v2_opaque_methods);
PLAMEN_V2_OPAQUE_TYPE(V2NetworkReceiptType, PLAMEN_V2_NETWORK_TYPE_NAME,
                      "Opaque one-shot native network receipt projection.",
                      v2_opaque_methods);

static void
v2_bundle_clear(V2AuthorityBundleObject *self)
{
    Py_CLEAR(self->runtime);
    Py_CLEAR(self->workspace);
    Py_CLEAR(self->backend);
    Py_CLEAR(self->provider);
    Py_CLEAR(self->guest_admission);
    Py_CLEAR(self->extinction);
    Py_CLEAR(self->artifacts);
    Py_CLEAR(self->exporter);
    Py_CLEAR(self->journal);
    Py_CLEAR(self->recovery);
}

static void
v2_bundle_dealloc(PyObject *object)
{
    V2AuthorityBundleObject *self = (V2AuthorityBundleObject *)object;
    v2_bundle_clear(self);
    secure_zero((unsigned char *)self + sizeof(PyObject),
                sizeof(*self) - sizeof(PyObject));
    PyObject_Del(object);
}

static PyObject *
v2_bundle_consume_once(PyObject *object, PyObject *args)
{
    V2AuthorityBundleObject *self = (V2AuthorityBundleObject *)object;
    PyObject *result;
    if (!PyArg_ParseTuple(args, ":consume_once")) {
        return NULL;
    }
    if (atomic_exchange_explicit(&self->consumed, 1,
                                 memory_order_acq_rel) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority bundle is already consumed");
        return NULL;
    }
    if (getpid() != self->creator_pid) {
        v2_bundle_clear(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority bundle cannot cross a process boundary");
        return NULL;
    }
    if (current_interpreter_id() != self->creator_interpreter_id) {
        v2_bundle_clear(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority bundle cannot cross an interpreter boundary");
        return NULL;
    }
    if (self->runtime == NULL || self->workspace == NULL ||
            self->backend == NULL || self->provider == NULL ||
            self->guest_admission == NULL || self->extinction == NULL ||
            self->artifacts == NULL || self->exporter == NULL ||
            self->journal == NULL || self->recovery == NULL) {
        v2_bundle_clear(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority bundle is incomplete");
        return NULL;
    }
    result = PyTuple_Pack(
        10, self->runtime, self->workspace, self->backend, self->provider,
        self->guest_admission, self->extinction, self->artifacts,
        self->exporter, self->journal, self->recovery);
    v2_bundle_clear(self);
    return result;
}

static PyMethodDef v2_bundle_methods[] = {
    {"consume_once", v2_bundle_consume_once, METH_VARARGS,
     PyDoc_STR("Consume this native authority bundle exactly once.")},
    {"__copy__", consumer_forbidden_copy, METH_NOARGS, NULL},
    {"__deepcopy__", consumer_forbidden_deepcopy, METH_VARARGS, NULL},
    {"__reduce__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__reduce_ex__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__getnewargs__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyTypeObject V2AuthorityBundleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PLAMEN_V2_BUNDLE_TYPE_NAME,
    .tp_basicsize = sizeof(V2AuthorityBundleObject),
    .tp_dealloc = v2_bundle_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION,
    .tp_doc = PyDoc_STR("Opaque one-shot native SupervisorAuthorities bundle."),
    .tp_methods = v2_bundle_methods,
    .tp_repr = opaque_capability_repr,
    .tp_new = consumer_forbidden_new,
};

static void
v2_guest_bundle_clear(V2GuestAuthorityBundleObject *self)
{
    Py_CLEAR(self->backend_execution);
}

static void
v2_guest_bundle_dealloc(PyObject *object)
{
    V2GuestAuthorityBundleObject *self =
        (V2GuestAuthorityBundleObject *)object;
    v2_guest_bundle_clear(self);
    secure_zero((unsigned char *)self + sizeof(PyObject),
                sizeof(*self) - sizeof(PyObject));
    PyObject_Del(object);
}

static PyObject *
v2_guest_bundle_consume_once(PyObject *object, PyObject *args)
{
    V2GuestAuthorityBundleObject *self =
        (V2GuestAuthorityBundleObject *)object;
    PyObject *result;
    if (!PyArg_ParseTuple(args, ":consume_once")) {
        return NULL;
    }
    if (atomic_exchange_explicit(&self->consumed, 1,
                                 memory_order_acq_rel) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native guest authority bundle is already consumed");
        return NULL;
    }
    if (getpid() != self->creator_pid) {
        v2_guest_bundle_clear(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native guest authority bundle cannot cross a process boundary");
        return NULL;
    }
    if (current_interpreter_id() != self->creator_interpreter_id) {
        v2_guest_bundle_clear(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native guest authority bundle cannot cross an interpreter boundary");
        return NULL;
    }
    if (self->backend_execution == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native guest authority bundle is incomplete");
        return NULL;
    }
    result = PyTuple_Pack(1, self->backend_execution);
    v2_guest_bundle_clear(self);
    return result;
}

static PyMethodDef v2_guest_bundle_methods[] = {
    {"consume_once", v2_guest_bundle_consume_once, METH_VARARGS,
     PyDoc_STR("Consume this native guest-driver authority bundle exactly once.")},
    {"__copy__", consumer_forbidden_copy, METH_NOARGS, NULL},
    {"__deepcopy__", consumer_forbidden_deepcopy, METH_VARARGS, NULL},
    {"__reduce__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__reduce_ex__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__getnewargs__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyTypeObject V2GuestAuthorityBundleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PLAMEN_V2_GUEST_BUNDLE_TYPE_NAME,
    .tp_basicsize = sizeof(V2GuestAuthorityBundleObject),
    .tp_dealloc = v2_guest_bundle_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION,
    .tp_doc = PyDoc_STR("Opaque one-shot native GuestDriverAuthorities bundle."),
    .tp_methods = v2_guest_bundle_methods,
    .tp_repr = opaque_capability_repr,
    .tp_new = consumer_forbidden_new,
};

/*
 * Tool-materialization bridges.
 *
 * These objects are deliberately static, non-subclassable CPython types.  No
 * production constructor is exported.  A capability may only be published by
 * the authenticated native bootstrap below, and every derived capability is
 * tied to the creating pid, interpreter, exact parent object, and immutable
 * canonical request bytes.  The actual platform executors are intentionally
 * separate provider hooks: until those hooks return a native terminal, the
 * execution entry points burn their leases and fail closed.
 */

#define PLAMEN_BRIDGE_MAX_CANONICAL_BYTES (4U * 1024U * 1024U)
#define PLAMEN_BRIDGE_JS_FD_COUNT 4U

_Static_assert(PLAMEN_BROKER_V2_MAX_FDS >= PLAMEN_BRIDGE_JS_FD_COUNT,
               "specialized JS descriptor roster exceeds wire capacity");

enum plamen_bridge_kind {
    PLAMEN_BRIDGE_JS_AUTHORITY = 1,
    PLAMEN_BRIDGE_JS_SESSION = 2,
    PLAMEN_BRIDGE_JS_EXECUTION = 3,
    PLAMEN_BRIDGE_JS_REPLAY = 4,
    PLAMEN_BRIDGE_MANAGED_INITIAL = 5,
    PLAMEN_BRIDGE_MANAGED_LEASE = 6,
    PLAMEN_BRIDGE_MANAGED_TERMINAL = 7,
    PLAMEN_BRIDGE_EVM_PROJECTION = 8,
    PLAMEN_BRIDGE_DARWIN_TOOL_CUSTODY = 9,
    PLAMEN_BRIDGE_DARWIN_TOOL_EXECUTION = 10,
    PLAMEN_BRIDGE_DARWIN_TOOL_TERMINAL = 11,
    PLAMEN_BRIDGE_APPLE_FUZZ_SERVICE = 12,
    PLAMEN_BRIDGE_APPLE_FUZZ_LEASE = 13,
    PLAMEN_BRIDGE_APPLE_FUZZ_TERMINAL = 14
};

typedef struct BridgeSpecializedSession BridgeSpecializedSession;

struct BridgeSpecializedSession {
    _Atomic unsigned int references;
    pid_t creator_pid;
    int64_t creator_interpreter_id;
    int control_fd;
    uint16_t lane;
    uint64_t next_sequence;
    PyThread_type_lock operation_lock;
    unsigned char key[32];
    unsigned char session_id[32];
    unsigned char authority_binding_sha256[32];
    unsigned char previous_frame_sha256[32];
};

typedef struct {
    PyObject_HEAD
    pid_t creator_pid;
    int64_t creator_interpreter_id;
    _Atomic int consumed;
    _Atomic int in_flight;
    unsigned int kind;
    PyObject *parent;
    PyObject *owner;
    PyObject *request_bytes;
    PyObject *terminal_bytes;
    unsigned char request_sha256[32];
    unsigned char terminal_sha256[32];
    unsigned char capability_id[32];
    BridgeSpecializedSession *specialized_session;
    int retained_fds[PLAMEN_BROKER_V2_MAX_FDS];
    struct plamen_broker_v2_fd_metadata
        retained_fd_metadata[PLAMEN_BROKER_V2_MAX_FDS];
    size_t retained_fd_count;
} PlamenBridgeCapabilityObject;

static BridgeSpecializedSession *bridge_js_session = NULL;
static BridgeSpecializedSession *bridge_managed_session = NULL;
static BridgeSpecializedSession *bridge_projection_session = NULL;
static BridgeSpecializedSession *bridge_snapshot_session = NULL;

static PyTypeObject JSDependencyMaterializerAuthorityType;
static PyTypeObject JSDependencyMaterializerSessionLeaseType;
static PyTypeObject JSDependencyMaterializerExecutionLeaseType;
static PyTypeObject JSDependencyMaterializerTerminalReplayLeaseType;
static PyTypeObject ManagedEVMToolchainInitialAuthorityType;
static PyTypeObject ManagedEVMToolchainProvisionLeaseType;
static PyTypeObject ManagedEVMToolchainProvisionTerminalType;
static PyTypeObject EVMAnalysisProjectionAuthorityType;
static PyTypeObject DarwinToolCustodyAuthorityType;
static PyTypeObject DarwinToolExecutionLeaseType;
static PyTypeObject DarwinToolExecutionTerminalType;
static PyTypeObject AppleFuzzServiceSessionAuthorityType;
static PyTypeObject AppleFuzzAdmissionContinuationLeaseType;
static PyTypeObject AppleFuzzLifecycleTerminalType;
static PyTypeObject BackendInstallGenerationAuthorityType;
static int bridge_initial_consumer_live(PyObject *);
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static PyObject *acquire_backend_install_generation(PyObject *, PyObject *);
static PyObject *project_backend_install_generation(PyObject *, PyObject *);
#endif
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static PyObject *bridge_runtime_identity(
    PyObject *, V2AuthorityConsumerObject *, int);
#endif
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static PyObject *bridge_specialized_rpc(
    BridgeSpecializedSession *, const unsigned char[32], uint16_t,
    uint16_t, PyObject *,
    const struct plamen_broker_v2_fd_metadata *, const int *, size_t,
    uint16_t, unsigned char[32], int64_t);
#endif

/*
 * The Apple fuzz surface is intentionally declared before the shared bridge
 * implementation so its public call order mirrors acquire/admit/execute.
 * Keep these internal declarations exact; none of them is an authority
 * constructor exposed to Python.
 */
static BridgeSpecializedSession *bridge_specialized_session_retain(
    BridgeSpecializedSession *);
static void bridge_close_fds(PlamenBridgeCapabilityObject *);
static int bridge_capability_live(
    PlamenBridgeCapabilityObject *, PyTypeObject *, unsigned int, int);
static int bridge_burn(PlamenBridgeCapabilityObject *);
static PlamenBridgeCapabilityObject *bridge_new(
    PyTypeObject *, unsigned int, PyObject *, PyObject *, PyObject *, PyObject *);
static int bridge_canonical_json_bytes(PyObject *, int, const char *);
static int bridge_duplicate_fd(int, int, int, int, int *);
static int bridge_bind_retained_fd(
    PlamenBridgeCapabilityObject *, size_t, uint16_t, uint8_t);
static int v2_decode_lower_hex_32(PyObject *, unsigned char[32]);

static void
bridge_encode_lower_hex_32(const unsigned char input[32], char output[65])
{
    static const char hex[] = "0123456789abcdef";
    size_t index;
    for (index = 0U; index < 32U; ++index) {
        output[index * 2U] = hex[(input[index] >> 4U) & 0x0fU];
        output[index * 2U + 1U] = hex[input[index] & 0x0fU];
    }
    output[64] = '\0';
}

static PyObject *
acquire_apple_fuzz_service_session(PyObject *module, PyObject *args)
{
    PyObject *initial;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:acquire_apple_fuzz_service_session",
                          &initial)) return NULL;
    if (!bridge_initial_consumer_live(initial)) return NULL;
    if (((V2AuthorityConsumerObject *)initial)->initial_authority_role !=
            PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Apple fuzz service requires guest-driver authority");
        return NULL;
    }
#if defined(__APPLE__) && !defined(PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY)
    PlamenBridgeCapabilityObject *session;
    if (bridge_snapshot_session == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "authenticated Apple fuzz service session is unavailable");
        return NULL;
    }
    session = bridge_new(&AppleFuzzServiceSessionAuthorityType,
                         PLAMEN_BRIDGE_APPLE_FUZZ_SERVICE,
                         initial, initial, NULL, NULL);
    if (session != NULL)
        session->specialized_session = bridge_specialized_session_retain(
            bridge_snapshot_session);
    return (PyObject *)session;
#else
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    PyErr_SetString(PyExc_RuntimeError,
                    "TEST_ONLY cannot issue production Apple fuzz service authority");
#else
    PyErr_SetString(PyExc_RuntimeError,
                    "Apple fuzz service is unavailable on this platform");
#endif
    return NULL;
#endif
}

static PyObject *
admit_apple_fuzz_campaign(PyObject *module, PyObject *args)
{
    PyObject *session_object, *request, *projection = NULL;
    PlamenBridgeCapabilityObject *session, *lease = NULL;
    struct stat identities[4];
    int descriptors[4], expected = 0; size_t index, prior;
    unsigned char issued[32];
    (void)module;
    memset(issued, 0, sizeof(issued));
    if (!PyArg_ParseTuple(args, "OOiiii:admit_apple_fuzz_campaign",
                          &session_object, &request, &descriptors[0],
                          &descriptors[1], &descriptors[2], &descriptors[3]))
        return NULL;
    session = (PlamenBridgeCapabilityObject *)session_object;
    if (!bridge_capability_live(session,
            &AppleFuzzServiceSessionAuthorityType,
            PLAMEN_BRIDGE_APPLE_FUZZ_SERVICE, 0)
        || !bridge_canonical_json_bytes(request, 0,
            "Apple fuzz admission request")) return NULL;
    for (index = 0U; index < 4U; ++index) {
        int flags;
        if (fstat(descriptors[index], &identities[index]) != 0
            || !S_ISDIR(identities[index].st_mode)
            || (flags = fcntl(descriptors[index], F_GETFL)) < 0
            || ((index == 0U || index == 3U)
                && (flags & O_ACCMODE) != O_RDONLY)) {
            PyErr_SetString(PyExc_ValueError,
                            "Apple fuzz descriptor roster is invalid");
            return NULL;
        }
        for (prior = 0U; prior < index; ++prior)
            if (identities[index].st_dev == identities[prior].st_dev
                && identities[index].st_ino == identities[prior].st_ino) {
                PyErr_SetString(PyExc_ValueError,
                                "Apple fuzz descriptor roster is aliased");
                return NULL;
            }
    }
    if (!atomic_compare_exchange_strong_explicit(&session->in_flight,
            &expected, 1, memory_order_acq_rel, memory_order_acquire)) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Apple fuzz service already has an admitted campaign");
        return NULL;
    }
    lease = bridge_new(&AppleFuzzAdmissionContinuationLeaseType,
                       PLAMEN_BRIDGE_APPLE_FUZZ_LEASE,
                       session_object, session->owner, request, NULL);
    if (lease == NULL) goto failed;
    for (index = 0U; index < 4U; ++index) {
        if (bridge_duplicate_fd(descriptors[index], 1, 0,
                index == 0U || index == 3U,
                &lease->retained_fds[index]) < 0) goto failed;
        lease->retained_fd_count = index + 1U;
        if (bridge_bind_retained_fd(lease, index,
                index == 0U ? PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE
                : index == 1U ? PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH
                : index == 2U ? PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE
                              : PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT,
                index == 0U || index == 3U
                    ? PLAMEN_BROKER_V2_FD_READ
                    : PLAMEN_BROKER_V2_FD_READ_WRITE) < 0) goto failed;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    projection = bridge_specialized_rpc(session->specialized_session,
        (const unsigned char[32]){0},
        PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT, 0, request,
        lease->retained_fd_metadata, lease->retained_fds,
        lease->retained_fd_count, PLAMEN_BROKER_V2_SPECIALIZED_ISSUED,
        issued, PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
    bridge_close_fds(lease);
    if (projection == NULL) goto failed;
    lease->terminal_bytes = projection;
    projection = NULL;
    memcpy(lease->capability_id, issued, 32U);
    secure_zero(issued, sizeof(issued));
    return (PyObject *)lease;
#else
    PyErr_SetString(PyExc_RuntimeError,
                    "TEST_ONLY cannot mint Apple fuzz admission authority");
#endif
failed:
    Py_XDECREF(projection);
    Py_XDECREF((PyObject *)lease);
    atomic_store_explicit(&session->in_flight, 0, memory_order_release);
    secure_zero(issued, sizeof(issued));
    return NULL;
}

static PyObject *
project_apple_fuzz_secure_receipt(PyObject *module, PyObject *args)
{
    PyObject *object; PlamenBridgeCapabilityObject *lease;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:project_apple_fuzz_secure_receipt", &object))
        return NULL;
    lease = (PlamenBridgeCapabilityObject *)object;
    if (!bridge_capability_live(lease,
            &AppleFuzzAdmissionContinuationLeaseType,
            PLAMEN_BRIDGE_APPLE_FUZZ_LEASE, 0)
        || lease->terminal_bytes == NULL
        || !bridge_canonical_json_bytes(lease->terminal_bytes, 0,
            "Apple fuzz secure receipt")) return NULL;
    return Py_NewRef(lease->terminal_bytes);
}

static PyObject *
execute_admitted_apple_fuzz_campaign(PyObject *module, PyObject *args)
{
    PyObject *session_object, *lease_object, *prepared_object, *secure_object;
    PlamenBridgeCapabilityObject *session, *lease, *terminal = NULL;
    unsigned char prepared[32], secure[32]; char prepared_hex[65], secure_hex[65];
    char payload[256]; int amount;
    PyObject *payload_bytes = NULL, *terminal_bytes = NULL;
    (void)module;
    memset(prepared, 0, sizeof(prepared)); memset(secure, 0, sizeof(secure));
    if (!PyArg_ParseTuple(args, "OOOO:execute_admitted_apple_fuzz_campaign",
            &session_object, &lease_object, &prepared_object, &secure_object))
        return NULL;
    session = (PlamenBridgeCapabilityObject *)session_object;
    lease = (PlamenBridgeCapabilityObject *)lease_object;
    if (!bridge_capability_live(session,
            &AppleFuzzServiceSessionAuthorityType,
            PLAMEN_BRIDGE_APPLE_FUZZ_SERVICE, 0)
        || !bridge_capability_live(lease,
            &AppleFuzzAdmissionContinuationLeaseType,
            PLAMEN_BRIDGE_APPLE_FUZZ_LEASE, 0)
        || lease->parent != session_object
        || v2_decode_lower_hex_32(prepared_object, prepared) < 0
        || v2_decode_lower_hex_32(secure_object, secure) < 0
        || bridge_burn(lease) < 0) goto failed;
    bridge_encode_lower_hex_32(prepared, prepared_hex);
    bridge_encode_lower_hex_32(secure, secure_hex);
    amount = snprintf(payload, sizeof(payload),
        "{\"prepared_campaign_sha256\":\"%s\","
        "\"schema\":\"plamen.apple-fuzz-service-execute-request.v1\","
        "\"secure_receipt_sha256\":\"%s\"}", prepared_hex, secure_hex);
    if (amount <= 0 || (size_t)amount >= sizeof(payload)
        || (payload_bytes = PyBytes_FromStringAndSize(payload, amount)) == NULL)
        goto failed;
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    terminal_bytes = bridge_specialized_rpc(lease->specialized_session,
        lease->capability_id, PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE,
        0, payload_bytes, NULL, NULL, 0,
        PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED, NULL,
        PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS);
    if (terminal_bytes == NULL) goto failed;
    terminal = bridge_new(&AppleFuzzLifecycleTerminalType,
        PLAMEN_BRIDGE_APPLE_FUZZ_TERMINAL, lease_object, lease->owner,
        payload_bytes, terminal_bytes);
    if (terminal == NULL) goto failed;
    Py_DECREF(payload_bytes); Py_DECREF(terminal_bytes);
    atomic_store_explicit(&session->in_flight, 0, memory_order_release);
    secure_zero(prepared, sizeof(prepared)); secure_zero(secure, sizeof(secure));
    secure_zero(prepared_hex, sizeof(prepared_hex));
    secure_zero(secure_hex, sizeof(secure_hex)); secure_zero(payload, sizeof(payload));
    return (PyObject *)terminal;
#else
    PyErr_SetString(PyExc_RuntimeError,
                    "TEST_ONLY cannot execute Apple fuzz lifecycle");
#endif
failed:
    Py_XDECREF(payload_bytes); Py_XDECREF(terminal_bytes);
    Py_XDECREF((PyObject *)terminal);
    if (session != NULL && Py_TYPE(session_object) ==
            &AppleFuzzServiceSessionAuthorityType)
        atomic_store_explicit(&session->in_flight, 0, memory_order_release);
    secure_zero(prepared, sizeof(prepared)); secure_zero(secure, sizeof(secure));
    secure_zero(prepared_hex, sizeof(prepared_hex));
    secure_zero(secure_hex, sizeof(secure_hex)); secure_zero(payload, sizeof(payload));
    return NULL;
}

static PyObject *
project_admitted_apple_fuzz_terminal(PyObject *module, PyObject *args)
{
    PyObject *object; PlamenBridgeCapabilityObject *terminal;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:project_admitted_apple_fuzz_terminal",
                          &object)) return NULL;
    terminal = (PlamenBridgeCapabilityObject *)object;
    if (!bridge_capability_live(terminal, &AppleFuzzLifecycleTerminalType,
            PLAMEN_BRIDGE_APPLE_FUZZ_TERMINAL, 0)
        || terminal->terminal_bytes == NULL
        || !bridge_canonical_json_bytes(terminal->terminal_bytes, 0,
            "Apple fuzz lifecycle terminal")) return NULL;
    return Py_NewRef(terminal->terminal_bytes);
}

static BridgeSpecializedSession *
bridge_specialized_session_retain(BridgeSpecializedSession *session)
{
    if (session != NULL) {
        (void)atomic_fetch_add_explicit(
            &session->references, 1U, memory_order_relaxed);
    }
    return session;
}

static void
bridge_specialized_session_release(BridgeSpecializedSession *session)
{
    if (session == NULL || atomic_fetch_sub_explicit(
            &session->references, 1U, memory_order_acq_rel) != 1U) {
        return;
    }
    if (session->control_fd >= 0) {
        (void)close(session->control_fd);
    }
    if (session->operation_lock != NULL) {
        PyThread_free_lock(session->operation_lock);
    }
    secure_zero(session->key, sizeof(session->key));
    secure_zero(session->session_id, sizeof(session->session_id));
    secure_zero(session->authority_binding_sha256,
                sizeof(session->authority_binding_sha256));
    secure_zero(session->previous_frame_sha256,
                sizeof(session->previous_frame_sha256));
    free(session);
}

static void
bridge_close_fds(PlamenBridgeCapabilityObject *self)
{
    size_t index;
    int saved_errno = errno;
    for (index = 0; index < self->retained_fd_count; index++) {
        if (self->retained_fds[index] >= 0) {
            (void)close(self->retained_fds[index]);
            self->retained_fds[index] = -1;
        }
    }
    self->retained_fd_count = 0;
    plamen_broker_v2_secure_zero(
        self->retained_fd_metadata, sizeof(self->retained_fd_metadata));
    errno = saved_errno;
}

static void
bridge_capability_dealloc(PyObject *object)
{
    PlamenBridgeCapabilityObject *self =
        (PlamenBridgeCapabilityObject *)object;
    bridge_close_fds(self);
    Py_CLEAR(self->parent);
    Py_CLEAR(self->owner);
    Py_CLEAR(self->request_bytes);
    Py_CLEAR(self->terminal_bytes);
    bridge_specialized_session_release(self->specialized_session);
    self->specialized_session = NULL;
    secure_zero(self->request_sha256, sizeof(self->request_sha256));
    secure_zero(self->terminal_sha256, sizeof(self->terminal_sha256));
    secure_zero(self->capability_id, sizeof(self->capability_id));
    self->creator_pid = 0;
    self->creator_interpreter_id = -1;
    self->kind = 0;
    PyObject_Del(object);
}

static int
bridge_capability_live(PlamenBridgeCapabilityObject *self,
                       PyTypeObject *exact_type, unsigned int kind,
                       int allow_consumed)
{
    if (Py_TYPE((PyObject *)self) != exact_type || self->kind != kind ||
            self->creator_pid != getpid() ||
            self->creator_interpreter_id != current_interpreter_id() ||
            (!allow_consumed && atomic_load_explicit(
                &self->consumed, memory_order_acquire) != 0)) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native bridge capability is invalid, consumed, or crossed a boundary");
        return 0;
    }
    return 1;
}

static int
bridge_burn(PlamenBridgeCapabilityObject *self)
{
    if (atomic_exchange_explicit(&self->consumed, 1,
                                 memory_order_acq_rel) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native bridge capability is already consumed");
        return -1;
    }
    return 0;
}

static PlamenBridgeCapabilityObject *
bridge_new(PyTypeObject *type, unsigned int kind, PyObject *parent,
           PyObject *owner, PyObject *request_bytes, PyObject *terminal_bytes)
{
    PlamenBridgeCapabilityObject *result;
    size_t index;

    result = PyObject_New(PlamenBridgeCapabilityObject, type);
    if (result == NULL) {
        return NULL;
    }
    result->creator_pid = getpid();
    result->creator_interpreter_id = current_interpreter_id();
    atomic_init(&result->consumed, 0);
    atomic_init(&result->in_flight, 0);
    result->kind = kind;
    result->parent = Py_XNewRef(parent);
    result->owner = Py_XNewRef(owner);
    result->request_bytes = Py_XNewRef(request_bytes);
    result->terminal_bytes = Py_XNewRef(terminal_bytes);
    memset(result->request_sha256, 0, sizeof(result->request_sha256));
    memset(result->terminal_sha256, 0, sizeof(result->terminal_sha256));
    memset(result->capability_id, 0, sizeof(result->capability_id));
    result->specialized_session = NULL;
    if (parent != NULL && (
            Py_TYPE(parent) == &JSDependencyMaterializerAuthorityType ||
            Py_TYPE(parent) == &JSDependencyMaterializerSessionLeaseType ||
            Py_TYPE(parent) == &JSDependencyMaterializerExecutionLeaseType ||
            Py_TYPE(parent) == &ManagedEVMToolchainInitialAuthorityType ||
            Py_TYPE(parent) == &ManagedEVMToolchainProvisionLeaseType ||
            Py_TYPE(parent) == &ManagedEVMToolchainProvisionTerminalType ||
            Py_TYPE(parent) == &EVMAnalysisProjectionAuthorityType ||
            Py_TYPE(parent) == &DarwinToolCustodyAuthorityType ||
            Py_TYPE(parent) == &DarwinToolExecutionLeaseType ||
            Py_TYPE(parent) == &DarwinToolExecutionTerminalType ||
            Py_TYPE(parent) == &AppleFuzzServiceSessionAuthorityType ||
            Py_TYPE(parent) == &AppleFuzzAdmissionContinuationLeaseType ||
            Py_TYPE(parent) == &AppleFuzzLifecycleTerminalType)) {
        result->specialized_session = bridge_specialized_session_retain(
            ((PlamenBridgeCapabilityObject *)parent)->specialized_session);
    }
    for (index = 0; index < PLAMEN_BROKER_V2_MAX_FDS; index++) {
        result->retained_fds[index] = -1;
    }
    memset(result->retained_fd_metadata, 0,
           sizeof(result->retained_fd_metadata));
    result->retained_fd_count = 0;
    if (request_bytes != NULL && PyBytes_CheckExact(request_bytes)) {
        if (plamen_broker_v2_sha256(
                (const unsigned char *)PyBytes_AS_STRING(request_bytes),
                (size_t)PyBytes_GET_SIZE(request_bytes),
                result->request_sha256) != PLAMEN_BROKER_V2_OK) {
            Py_DECREF(result);
            PyErr_SetString(PyExc_RuntimeError,
                            "native request digest calculation failed");
            return NULL;
        }
    }
    if (terminal_bytes != NULL && PyBytes_CheckExact(terminal_bytes)) {
        if (plamen_broker_v2_sha256(
                (const unsigned char *)PyBytes_AS_STRING(terminal_bytes),
                (size_t)PyBytes_GET_SIZE(terminal_bytes),
                result->terminal_sha256) != PLAMEN_BROKER_V2_OK) {
            Py_DECREF(result);
            PyErr_SetString(PyExc_RuntimeError,
                            "native terminal digest calculation failed");
            return NULL;
        }
    }
    return result;
}

static int
bridge_canonical_json_bytes(PyObject *value, int newline_required,
                            const char *label)
{
    const unsigned char *raw;
    Py_ssize_t size, index, content_size;
    int quoted = 0, escaped = 0;

    if (!PyBytes_CheckExact(value)) {
        PyErr_Format(PyExc_TypeError, "%s must be exact bytes", label);
        return 0;
    }
    raw = (const unsigned char *)PyBytes_AS_STRING(value);
    size = PyBytes_GET_SIZE(value);
    if (size < (newline_required ? 3 : 2) ||
            (uint64_t)size > PLAMEN_BRIDGE_MAX_CANONICAL_BYTES) {
        PyErr_Format(PyExc_ValueError, "%s byte bound is invalid", label);
        return 0;
    }
    content_size = size;
    if (newline_required) {
        if (raw[size - 1] != '\n') {
            PyErr_Format(PyExc_ValueError, "%s lacks its canonical terminator", label);
            return 0;
        }
        content_size--;
    }
    if (raw[0] != '{' || raw[content_size - 1] != '}') {
        PyErr_Format(PyExc_ValueError, "%s is not a JSON object", label);
        return 0;
    }
    for (index = 0; index < content_size; index++) {
        unsigned char current = raw[index];
        if (current == 0 || current > 0x7fU || current == '\n' ||
                current == '\r' || current == '\t') {
            PyErr_Format(PyExc_ValueError, "%s is not canonical ASCII JSON", label);
            return 0;
        }
        if (quoted) {
            if (escaped) {
                escaped = 0;
            } else if (current == '\\') {
                escaped = 1;
            } else if (current == '"') {
                quoted = 0;
            } else if (current < 0x20U) {
                PyErr_Format(PyExc_ValueError, "%s contains a control character", label);
                return 0;
            }
        } else if (current == '"') {
            quoted = 1;
        } else if (current == ' ') {
            PyErr_Format(PyExc_ValueError, "%s contains noncanonical whitespace", label);
            return 0;
        }
    }
    if (quoted || escaped) {
        PyErr_Format(PyExc_ValueError, "%s has an unterminated JSON string", label);
        return 0;
    }
    return 1;
}

static int
bridge_duplicate_fd(int source, int require_directory, int require_regular,
                    int require_read_only, int *destination)
{
    struct stat info;
    int flags, duplicate_fd;

    *destination = -1;
    if (source < 0 || fstat(source, &info) != 0 ||
            (require_directory && !S_ISDIR(info.st_mode)) ||
            (require_regular && (!S_ISREG(info.st_mode) || info.st_nlink != 1)) ||
            (!require_directory && !require_regular &&
             !S_ISDIR(info.st_mode) && !S_ISREG(info.st_mode)) ||
            ((!require_directory || require_regular) &&
             S_ISREG(info.st_mode) && info.st_nlink != 1)) {
        PyErr_SetString(PyExc_ValueError,
                        "native bridge descriptor identity is invalid");
        return -1;
    }
    flags = fcntl(source, F_GETFL);
    if (flags < 0 || (require_read_only && (flags & O_ACCMODE) != O_RDONLY)) {
        PyErr_SetString(PyExc_ValueError,
                        "native bridge descriptor access is invalid");
        return -1;
    }
#ifdef F_DUPFD_CLOEXEC
    duplicate_fd = fcntl(source, F_DUPFD_CLOEXEC, 3);
#else
    duplicate_fd = dup(source);
    if (duplicate_fd >= 0 &&
            fcntl(duplicate_fd, F_SETFD, FD_CLOEXEC) != 0) {
        (void)close(duplicate_fd);
        duplicate_fd = -1;
    }
#endif
    if (duplicate_fd < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    *destination = duplicate_fd;
    return 0;
}

static int
bridge_bind_retained_fd(PlamenBridgeCapabilityObject *lease, size_t index,
                        uint16_t purpose, uint8_t access)
{
    struct plamen_broker_v2_fd_metadata *metadata;
    if (lease == NULL || index >= lease->retained_fd_count ||
            index >= PLAMEN_BROKER_V2_MAX_FDS ||
            lease->retained_fds[index] < 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native retained descriptor roster is invalid");
        return -1;
    }
    metadata = &lease->retained_fd_metadata[index];
    memset(metadata, 0, sizeof(*metadata));
    metadata->purpose = purpose;
    metadata->target = (uint16_t)(index + 1U);
    metadata->access_mode = access;
    if (plamen_broker_v2_fd_identity(
            lease->retained_fds[index], metadata->identity) !=
                PLAMEN_BROKER_V2_OK) {
        memset(metadata, 0, sizeof(*metadata));
        PyErr_SetString(PyExc_RuntimeError,
                        "native retained descriptor identity failed");
        return -1;
    }
    return 0;
}

static int
bridge_retain_js_descriptors(PlamenBridgeCapabilityObject *lease,
                             int source_fd, int scratch_fd, int state_fd,
                             int archive_root_fd)
{
    int source_flags;
    struct stat source_info, scratch_info, state_info;
    struct stat identities[PLAMEN_BRIDGE_JS_FD_COUNT];
    size_t index, prior;

    if (fstat(source_fd, &source_info) != 0 ||
            fstat(scratch_fd, &scratch_info) != 0 ||
            fstat(state_fd, &state_info) != 0 ||
            fstat(archive_root_fd, &identities[3]) != 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    identities[0] = source_info;
    identities[1] = scratch_info;
    identities[2] = state_info;
    for (index = 0; index < PLAMEN_BRIDGE_JS_FD_COUNT; ++index) {
        if (!S_ISDIR(identities[index].st_mode)) {
            PyErr_SetString(PyExc_ValueError,
                            "materializer descriptors must be directories");
            return -1;
        }
        for (prior = 0; prior < index; ++prior) {
            if (identities[index].st_dev == identities[prior].st_dev &&
                    identities[index].st_ino == identities[prior].st_ino) {
                PyErr_SetString(PyExc_ValueError,
                                "materializer directories must be identity-disjoint");
                return -1;
            }
        }
    }
    if (!S_ISDIR(source_info.st_mode) ||
            !S_ISDIR(scratch_info.st_mode) ||
            !S_ISDIR(state_info.st_mode)) {
        PyErr_SetString(PyExc_ValueError,
                        "materializer roots must be directories");
        return -1;
    }
    source_flags = fcntl(source_fd, F_GETFL);
    if (source_flags < 0 || (source_flags & O_ACCMODE) != O_RDONLY) {
        PyErr_SetString(PyExc_ValueError,
                        "source descriptor must be read-only");
        return -1;
    }
    if (bridge_duplicate_fd(source_fd, 1, 0, 1,
                            &lease->retained_fds[0]) < 0) {
        return -1;
    }
    lease->retained_fd_count = 1;
    if (bridge_duplicate_fd(scratch_fd, 1, 0, 0,
                            &lease->retained_fds[1]) < 0) {
        bridge_close_fds(lease);
        return -1;
    }
    lease->retained_fd_count = 2;
    if (bridge_duplicate_fd(state_fd, 1, 0, 0,
                            &lease->retained_fds[2]) < 0) {
        bridge_close_fds(lease);
        return -1;
    }
    lease->retained_fd_count = 3;
    if (bridge_duplicate_fd(archive_root_fd, 1, 0, 1,
                            &lease->retained_fds[3]) < 0) {
        bridge_close_fds(lease);
        return -1;
    }
    lease->retained_fd_count = PLAMEN_BRIDGE_JS_FD_COUNT;
    if (bridge_bind_retained_fd(
            lease, 0, PLAMEN_BROKER_V2_FD_JS_SOURCE,
            PLAMEN_BROKER_V2_FD_READ) < 0 ||
            bridge_bind_retained_fd(
            lease, 1, PLAMEN_BROKER_V2_FD_JS_SCRATCH,
            PLAMEN_BROKER_V2_FD_READ_WRITE) < 0 ||
            bridge_bind_retained_fd(
            lease, 2, PLAMEN_BROKER_V2_FD_JS_STATE,
            PLAMEN_BROKER_V2_FD_READ_WRITE) < 0 ||
            bridge_bind_retained_fd(
            lease, 3, PLAMEN_BROKER_V2_FD_JS_ARCHIVE_ROOT,
            PLAMEN_BROKER_V2_FD_READ) < 0) {
        bridge_close_fds(lease);
        return -1;
    }
    return 0;
}

static PyMethodDef bridge_sealed_methods[] = {
    {"__copy__", consumer_forbidden_copy, METH_NOARGS, NULL},
    {"__deepcopy__", consumer_forbidden_deepcopy, METH_VARARGS, NULL},
    {"__reduce__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__reduce_ex__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__getnewargs__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

#define PLAMEN_BRIDGE_TYPE(variable, qualified_name, description) \
    static PyTypeObject variable = { \
        PyVarObject_HEAD_INIT(NULL, 0) \
        .tp_name = qualified_name, \
        .tp_basicsize = sizeof(PlamenBridgeCapabilityObject), \
        .tp_dealloc = bridge_capability_dealloc, \
        .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION, \
        .tp_doc = PyDoc_STR(description), \
        .tp_methods = bridge_sealed_methods, \
        .tp_repr = opaque_capability_repr, \
        .tp_new = consumer_forbidden_new, \
    }

PLAMEN_BRIDGE_TYPE(JSDependencyMaterializerAuthorityType,
                   PLAMEN_JS_AUTHORITY_TYPE_NAME,
                   "Opaque native JavaScript dependency materializer authority.");
PLAMEN_BRIDGE_TYPE(JSDependencyMaterializerSessionLeaseType,
                   PLAMEN_JS_SESSION_TYPE_NAME,
                   "Opaque process-bound JavaScript materializer session lease.");
PLAMEN_BRIDGE_TYPE(JSDependencyMaterializerExecutionLeaseType,
                   PLAMEN_JS_EXECUTION_TYPE_NAME,
                   "Opaque descriptor-bound JavaScript materializer execution lease.");
PLAMEN_BRIDGE_TYPE(JSDependencyMaterializerTerminalReplayLeaseType,
                   PLAMEN_JS_REPLAY_TYPE_NAME,
                   "Opaque durable JavaScript terminal replay lease.");
PLAMEN_BRIDGE_TYPE(ManagedEVMToolchainInitialAuthorityType,
                   PLAMEN_MANAGED_INITIAL_TYPE_NAME,
                   "Opaque one-shot managed EVM toolchain initial authority.");
PLAMEN_BRIDGE_TYPE(ManagedEVMToolchainProvisionLeaseType,
                   PLAMEN_MANAGED_LEASE_TYPE_NAME,
                   "Opaque immutable-plan managed EVM toolchain provision lease.");
PLAMEN_BRIDGE_TYPE(ManagedEVMToolchainProvisionTerminalType,
                   PLAMEN_MANAGED_TERMINAL_TYPE_NAME,
                   "Opaque managed EVM toolchain terminal authority.");
PLAMEN_BRIDGE_TYPE(EVMAnalysisProjectionAuthorityType,
                   PLAMEN_EVM_PROJECTION_TYPE_NAME,
                   "Opaque native EVM analysis projection authority.");
PLAMEN_BRIDGE_TYPE(DarwinToolCustodyAuthorityType,
                   PLAMEN_DARWIN_TOOL_CUSTODY_TYPE_NAME,
                   "Opaque authenticated Darwin tool custody authority.");
PLAMEN_BRIDGE_TYPE(DarwinToolExecutionLeaseType,
                   PLAMEN_DARWIN_TOOL_EXECUTION_TYPE_NAME,
                   "Opaque snapshot-bound Darwin tool execution lease.");
PLAMEN_BRIDGE_TYPE(DarwinToolExecutionTerminalType,
                   PLAMEN_DARWIN_TOOL_TERMINAL_TYPE_NAME,
                   "Opaque authenticated snapshot-bound tool terminal.");
PLAMEN_BRIDGE_TYPE(AppleFuzzServiceSessionAuthorityType,
                   PLAMEN_APPLE_FUZZ_SERVICE_TYPE_NAME,
                   "Opaque authenticated Apple fuzz service session authority.");
PLAMEN_BRIDGE_TYPE(AppleFuzzAdmissionContinuationLeaseType,
                   PLAMEN_APPLE_FUZZ_LEASE_TYPE_NAME,
                   "Opaque one-shot Apple fuzz admission continuation.");
PLAMEN_BRIDGE_TYPE(AppleFuzzLifecycleTerminalType,
                   PLAMEN_APPLE_FUZZ_TERMINAL_TYPE_NAME,
                   "Opaque Apple fuzz lifecycle terminal authority.");

typedef struct {
    PyObject_HEAD
    pid_t creator_pid;
    int64_t creator_interpreter_id;
    _Atomic int consumed;
    PyObject *parent;
#ifdef PLAMEN_NATIVE_INSTALLED_BACKEND_GENERATION_ENABLED
    struct plamen_source_bootstrap_installed_binding_v1 binding;
    struct plamen_source_bootstrap_installed_projection_v1 projection;
#endif
} BackendInstallGenerationObject;

static void
backend_install_generation_dealloc(PyObject *object)
{
    BackendInstallGenerationObject *self =
        (BackendInstallGenerationObject *)object;
#ifdef PLAMEN_NATIVE_INSTALLED_BACKEND_GENERATION_ENABLED
    plamen_source_bootstrap_installed_projection_dispose_v1(
        &self->projection);
    plamen_broker_v2_secure_zero(&self->binding, sizeof(self->binding));
#endif
    Py_CLEAR(self->parent);
    self->creator_pid = 0;
    self->creator_interpreter_id = -1;
    PyObject_Del(object);
}

static PyTypeObject BackendInstallGenerationAuthorityType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PLAMEN_BACKEND_INSTALL_GENERATION_TYPE_NAME,
    .tp_basicsize = sizeof(BackendInstallGenerationObject),
    .tp_dealloc = backend_install_generation_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION,
    .tp_doc = PyDoc_STR(
        "Opaque descriptor-bound installed backend generation authority."),
    .tp_methods = bridge_sealed_methods,
    .tp_repr = opaque_capability_repr,
    .tp_new = consumer_forbidden_new,
};

static PyObject *
authenticate_js_dependency_materializer_capability(PyObject *module,
                                                    PyObject *args)
{
    PyObject *authority_object, *admission;
    PlamenBridgeCapabilityObject *authority, *session;
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    PyObject *projection;
    unsigned char issued[32];
#endif
    (void)module;
    if (!PyArg_ParseTuple(args, "OO:authenticate_js_dependency_materializer_capability",
                          &authority_object, &admission)) {
        return NULL;
    }
    authority = (PlamenBridgeCapabilityObject *)authority_object;
    if (!bridge_capability_live(authority,
            &JSDependencyMaterializerAuthorityType,
            PLAMEN_BRIDGE_JS_AUTHORITY, 0) ||
            !bridge_canonical_json_bytes(admission, 0,
                                         "materializer admission")) {
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    projection = bridge_specialized_rpc(authority->specialized_session,
        authority->capability_id,
        PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE, 0,
        admission, NULL, NULL, 0, PLAMEN_BROKER_V2_SPECIALIZED_ISSUED,
        issued, PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
    if (projection == NULL) {
        (void)bridge_burn(authority);
        return NULL;
    }
    Py_DECREF(projection);
#endif
    if (bridge_burn(authority) < 0) {
        return NULL;
    }
    session = bridge_new(&JSDependencyMaterializerSessionLeaseType,
                         PLAMEN_BRIDGE_JS_SESSION, authority_object,
                         authority->owner, admission, NULL);
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    if (session != NULL) {
        memcpy(session->capability_id, issued, 32);
    }
    secure_zero(issued, sizeof(issued));
#endif
    return (PyObject *)session;
}

static PyObject *
js_dependency_materializer_runtime_identity(PyObject *module, PyObject *args)
{
    PyObject *authority_object, *empty, *result;
    PlamenBridgeCapabilityObject *authority;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:js_dependency_materializer_runtime_identity",
                          &authority_object)) {
        return NULL;
    }
    authority = (PlamenBridgeCapabilityObject *)authority_object;
    if (!bridge_capability_live(authority,
            &JSDependencyMaterializerAuthorityType,
            PLAMEN_BRIDGE_JS_AUTHORITY, 0)) {
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    empty = PyBytes_FromString("{}");
    if (empty == NULL) {
        return NULL;
    }
    result = bridge_specialized_rpc(authority->specialized_session,
        authority->capability_id,
        PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_RUNTIME_IDENTITY, 0,
        empty, NULL, NULL, 0,
        PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED, NULL,
        PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
    Py_DECREF(empty);
    return result;
#else
    (void)empty;
    (void)result;
    PyErr_SetString(PyExc_RuntimeError,
                    "native JavaScript runtime identity provider hook is unavailable");
    return NULL;
#endif
}

static PyObject *
prepare_js_dependency_materializer_execution(PyObject *module, PyObject *args)
{
    PyObject *authority_object, *session_object, *request;
    PlamenBridgeCapabilityObject *authority, *session, *lease;
    int source_fd, scratch_fd, state_fd, archive_root_fd;
    int expected = 0;
    (void)module;
    if (!PyArg_ParseTuple(args, "OOOiiii:prepare_js_dependency_materializer_execution",
                          &authority_object, &session_object, &request,
                          &source_fd, &scratch_fd, &state_fd,
                          &archive_root_fd)) {
        return NULL;
    }
    authority = (PlamenBridgeCapabilityObject *)authority_object;
    session = (PlamenBridgeCapabilityObject *)session_object;
    if (!bridge_capability_live(authority,
            &JSDependencyMaterializerAuthorityType,
            PLAMEN_BRIDGE_JS_AUTHORITY, 1) ||
            !bridge_capability_live(session,
            &JSDependencyMaterializerSessionLeaseType,
            PLAMEN_BRIDGE_JS_SESSION, 0) ||
            session->parent != authority_object ||
            !bridge_canonical_json_bytes(request, 1,
                                         "materializer request")) {
        return NULL;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &session->in_flight, &expected, 1,
            memory_order_acq_rel, memory_order_acquire)) {
        PyErr_SetString(PyExc_RuntimeError,
                        "materializer session already has an in-flight operation");
        return NULL;
    }
    lease = bridge_new(&JSDependencyMaterializerExecutionLeaseType,
                       PLAMEN_BRIDGE_JS_EXECUTION, session_object,
                       authority_object, request, NULL);
    if (lease == NULL || bridge_retain_js_descriptors(
            lease, source_fd, scratch_fd, state_fd, archive_root_fd) < 0) {
        atomic_store_explicit(&session->in_flight, 0, memory_order_release);
        Py_XDECREF(lease);
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        PyObject *projection;
        unsigned char issued[32];
        projection = bridge_specialized_rpc(session->specialized_session,
            session->capability_id,
            PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE, 0,
            request, lease->retained_fd_metadata, lease->retained_fds,
            lease->retained_fd_count, PLAMEN_BROKER_V2_SPECIALIZED_ISSUED,
            issued, PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
        if (projection == NULL) {
            atomic_store_explicit(&session->in_flight, 0,
                                  memory_order_release);
            Py_DECREF(lease);
            return NULL;
        }
        Py_XSETREF(lease->terminal_bytes, Py_NewRef(projection));
        Py_DECREF(projection);
        memcpy(lease->capability_id, issued, 32);
        secure_zero(issued, sizeof(issued));
    }
#endif
    return (PyObject *)lease;
}

static PyObject *
execute_js_dependency_materializer(PyObject *module, PyObject *args)
{
    PyObject *authority_object, *session_object, *lease_object;
    PlamenBridgeCapabilityObject *authority, *session, *lease;
    (void)module;
    if (!PyArg_ParseTuple(args, "OOO:execute_js_dependency_materializer",
                          &authority_object, &session_object, &lease_object)) {
        return NULL;
    }
    authority = (PlamenBridgeCapabilityObject *)authority_object;
    session = (PlamenBridgeCapabilityObject *)session_object;
    lease = (PlamenBridgeCapabilityObject *)lease_object;
    if (!bridge_capability_live(authority,
            &JSDependencyMaterializerAuthorityType,
            PLAMEN_BRIDGE_JS_AUTHORITY, 1) ||
            !bridge_capability_live(session,
            &JSDependencyMaterializerSessionLeaseType,
            PLAMEN_BRIDGE_JS_SESSION, 0) ||
            !bridge_capability_live(lease,
            &JSDependencyMaterializerExecutionLeaseType,
            PLAMEN_BRIDGE_JS_EXECUTION, 0) ||
            session->parent != authority_object ||
            lease->parent != session_object || lease->owner != authority_object ||
            bridge_burn(lease) < 0) {
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        PyObject *terminal = bridge_specialized_rpc(
            lease->specialized_session, lease->capability_id,
            PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE, 0,
            lease->request_bytes, NULL, NULL, 0,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED, NULL,
            PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS);
        bridge_close_fds(lease);
        atomic_store_explicit(&session->in_flight, 0, memory_order_release);
        return terminal;
    }
#else
    bridge_close_fds(lease);
    atomic_store_explicit(&session->in_flight, 0, memory_order_release);
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    if (lease->terminal_bytes != NULL) {
        return Py_NewRef(lease->terminal_bytes);
    }
#endif
    PyErr_SetString(PyExc_RuntimeError,
                    "native JavaScript materializer provider hook is unavailable");
    return NULL;
#endif
}

static PyObject *
replay_js_dependency_materializer_terminal(PyObject *module, PyObject *args)
{
    PyObject *authority_object, *session_object, *request, *terminal;
    PlamenBridgeCapabilityObject *authority, *session, *replay;
    int source_fd, scratch_fd, state_fd, archive_root_fd;
    (void)module;
    if (!PyArg_ParseTuple(args, "OOOOiiii:replay_js_dependency_materializer_terminal",
                          &authority_object, &session_object, &request, &terminal,
                          &source_fd, &scratch_fd, &state_fd,
                          &archive_root_fd)) {
        return NULL;
    }
    authority = (PlamenBridgeCapabilityObject *)authority_object;
    session = (PlamenBridgeCapabilityObject *)session_object;
    if (!bridge_capability_live(authority,
            &JSDependencyMaterializerAuthorityType,
            PLAMEN_BRIDGE_JS_AUTHORITY, 1) ||
            !bridge_capability_live(session,
            &JSDependencyMaterializerSessionLeaseType,
            PLAMEN_BRIDGE_JS_SESSION, 0) ||
            session->parent != authority_object ||
            !bridge_canonical_json_bytes(request, 1,
                                         "materializer replay request") ||
            !bridge_canonical_json_bytes(terminal, 1,
                                         "materializer replay terminal")) {
        return NULL;
    }
    /* A provider must attest the durable operation-key record. */
    replay = bridge_new(&JSDependencyMaterializerTerminalReplayLeaseType,
                        PLAMEN_BRIDGE_JS_REPLAY, session_object,
                        authority_object, request, terminal);
    if (replay == NULL || bridge_retain_js_descriptors(
            replay, source_fd, scratch_fd, state_fd, archive_root_fd) < 0) {
        Py_XDECREF(replay);
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        PyObject *payload, *projection;
        unsigned char issued[32];
        Py_ssize_t request_size = PyBytes_GET_SIZE(request);
        Py_ssize_t terminal_size = PyBytes_GET_SIZE(terminal);
        static const char request_prefix[] = "{\"request\":";
        static const char terminal_prefix[] = ",\"terminal\":";
        Py_ssize_t total, offset;
        char *rendered;
        if (request_size < 2 || terminal_size < 2 ||
                request_size > PY_SSIZE_T_MAX - terminal_size -
                    (Py_ssize_t)sizeof(request_prefix) -
                    (Py_ssize_t)sizeof(terminal_prefix)) {
            Py_DECREF(replay);
            PyErr_SetString(PyExc_OverflowError,
                            "materializer replay payload is too large");
            return NULL;
        }
        total = (Py_ssize_t)(sizeof(request_prefix) - 1U) +
            request_size - 1 +
            (Py_ssize_t)(sizeof(terminal_prefix) - 1U) +
            terminal_size - 1 + 1;
        payload = PyBytes_FromStringAndSize(NULL, total);
        if (payload == NULL) {
            Py_DECREF(replay);
            return NULL;
        }
        rendered = PyBytes_AS_STRING(payload);
        offset = 0;
        memcpy(rendered + offset, request_prefix,
               sizeof(request_prefix) - 1U);
        offset += (Py_ssize_t)(sizeof(request_prefix) - 1U);
        memcpy(rendered + offset, PyBytes_AS_STRING(request),
               (size_t)request_size - 1U);
        offset += request_size - 1;
        memcpy(rendered + offset, terminal_prefix,
               sizeof(terminal_prefix) - 1U);
        offset += (Py_ssize_t)(sizeof(terminal_prefix) - 1U);
        memcpy(rendered + offset, PyBytes_AS_STRING(terminal),
               (size_t)terminal_size - 1U);
        offset += terminal_size - 1;
        rendered[offset] = '}';
        projection = bridge_specialized_rpc(session->specialized_session,
            session->capability_id,
            PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY,
            PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER, payload,
            replay->retained_fd_metadata, replay->retained_fds,
            replay->retained_fd_count, PLAMEN_BROKER_V2_SPECIALIZED_REPLAYED,
            issued, PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
        Py_DECREF(payload);
        if (projection == NULL) {
            Py_DECREF(replay);
            return NULL;
        }
        Py_DECREF(projection);
        memcpy(replay->capability_id, issued, 32);
        secure_zero(issued, sizeof(issued));
        bridge_close_fds(replay);
        return (PyObject *)replay;
    }
#else
    Py_DECREF(replay);
    PyErr_SetString(PyExc_RuntimeError,
                    "native JavaScript durable replay provider hook is unavailable");
    return NULL;
#endif
}

static PyObject *
managed_evm_toolchain_runtime_identity(PyObject *module, PyObject *args)
{
    PyObject *initial_object;
    PlamenBridgeCapabilityObject *initial;
    if (!PyArg_ParseTuple(args, "O:managed_evm_toolchain_runtime_identity",
                          &initial_object)) {
        return NULL;
    }
    initial = (PlamenBridgeCapabilityObject *)initial_object;
    if (!bridge_capability_live(initial,
            &ManagedEVMToolchainInitialAuthorityType,
            PLAMEN_BRIDGE_MANAGED_INITIAL, 0)) {
        return NULL;
    }
    if (initial->owner == NULL ||
            !bridge_initial_consumer_live(initial->owner)) {
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        PyObject *empty = PyBytes_FromString("{}");
        PyObject *result;
        (void)module;
        if (empty == NULL) {
            return NULL;
        }
        result = bridge_specialized_rpc(initial->specialized_session,
            initial->capability_id,
            PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_RUNTIME_IDENTITY, 0,
            empty, NULL, NULL, 0,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED, NULL,
            PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
        Py_DECREF(empty);
        return result;
    }
#else
    return bridge_runtime_identity(
        module, (V2AuthorityConsumerObject *)initial->owner, 1);
#endif
}

static int
bridge_retain_managed_descriptors(PlamenBridgeCapabilityObject *lease,
                                  const int supplied[5])
{
    static const uint16_t purposes[5] = {
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_POLICY,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_PROJECT,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_CACHE,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_GENERATIONS,
        PLAMEN_BROKER_V2_FD_MANAGED_EVM_ACQUISITION_RECEIPT
    };
    size_t index, prior;
    for (index = 0; index < 5U; index++) {
        struct stat current;
        int regular = index == 0U || index == 4U;
        int directory = !regular;
        if (bridge_duplicate_fd(supplied[index], directory, regular,
                index == 0U || index == 1U || index == 4U,
                &lease->retained_fds[index]) < 0) {
            bridge_close_fds(lease);
            return -1;
        }
        lease->retained_fd_count++;
        if (fstat(lease->retained_fds[index], &current) != 0) {
            bridge_close_fds(lease);
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        for (prior = 0; prior < index; prior++) {
            struct stat earlier;
            if (fstat(lease->retained_fds[prior], &earlier) != 0 ||
                    (current.st_dev == earlier.st_dev &&
                     current.st_ino == earlier.st_ino)) {
                bridge_close_fds(lease);
                PyErr_SetString(PyExc_ValueError,
                    "managed EVM descriptors must be identity-disjoint");
                return -1;
            }
        }
        if (bridge_bind_retained_fd(lease, index, purposes[index],
                index == 2U || index == 3U
                    ? PLAMEN_BROKER_V2_FD_READ_WRITE
                    : PLAMEN_BROKER_V2_FD_READ) < 0) {
            bridge_close_fds(lease);
            return -1;
        }
    }
    return 0;
}

static PyObject *
prepare_managed_evm_toolchain_provision(PyObject *module, PyObject *args)
{
    PyObject *initial_object, *plan;
    PlamenBridgeCapabilityObject *initial, *lease;
    int supplied[5];
    (void)module;
    if (!PyArg_ParseTuple(args,
            "OOiiiii:prepare_managed_evm_toolchain_provision",
            &initial_object, &plan, &supplied[0], &supplied[1], &supplied[2],
            &supplied[3], &supplied[4])) {
        return NULL;
    }
    initial = (PlamenBridgeCapabilityObject *)initial_object;
    if (!bridge_capability_live(initial,
            &ManagedEVMToolchainInitialAuthorityType,
            PLAMEN_BRIDGE_MANAGED_INITIAL, 0) ||
            !bridge_canonical_json_bytes(plan, 0,
                                         "managed EVM provision plan")) {
        return NULL;
    }
    lease = bridge_new(&ManagedEVMToolchainProvisionLeaseType,
                       PLAMEN_BRIDGE_MANAGED_LEASE, initial_object,
                       initial->owner, plan, NULL);
    if (lease == NULL || bridge_retain_managed_descriptors(
            lease, supplied) < 0) {
        Py_XDECREF(lease);
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        PyObject *projection;
        unsigned char issued[32];
        projection = bridge_specialized_rpc(initial->specialized_session,
            initial->capability_id,
            PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE, 0, plan,
            lease->retained_fd_metadata, lease->retained_fds,
            lease->retained_fd_count,
            PLAMEN_BROKER_V2_SPECIALIZED_ISSUED, issued,
            PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS);
        if (projection == NULL) {
            (void)bridge_burn(initial);
            Py_DECREF(lease);
            return NULL;
        }
        Py_DECREF(projection);
        if (bridge_burn(initial) < 0) {
            Py_DECREF(lease);
            return NULL;
        }
        memcpy(lease->capability_id, issued, 32);
        secure_zero(issued, sizeof(issued));
        return (PyObject *)lease;
    }
#else
    if (bridge_burn(initial) < 0) {
        return NULL;
    }
    return (PyObject *)lease;
#endif
}

static PyObject *
execute_managed_evm_toolchain_provision(PyObject *module, PyObject *args)
{
    PyObject *lease_object;
    PlamenBridgeCapabilityObject *lease;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:execute_managed_evm_toolchain_provision",
                          &lease_object)) {
        return NULL;
    }
    lease = (PlamenBridgeCapabilityObject *)lease_object;
    if (!bridge_capability_live(lease,
            &ManagedEVMToolchainProvisionLeaseType,
            PLAMEN_BRIDGE_MANAGED_LEASE, 0) || bridge_burn(lease) < 0) {
        return NULL;
    }
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    if (lease->terminal_bytes != NULL) {
        PyObject *terminal = (PyObject *)bridge_new(
            &ManagedEVMToolchainProvisionTerminalType,
            PLAMEN_BRIDGE_MANAGED_TERMINAL, lease_object, lease->owner,
            lease->request_bytes, lease->terminal_bytes);
        bridge_close_fds(lease);
        return terminal;
    }
#else
    {
        PyObject *terminal_bytes;
        PlamenBridgeCapabilityObject *terminal;
        unsigned char issued[32];
        terminal_bytes = bridge_specialized_rpc(lease->specialized_session,
            lease->capability_id,
            PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE, 0,
            lease->request_bytes, NULL, NULL, 0,
            PLAMEN_BROKER_V2_SPECIALIZED_ISSUED, issued,
            PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS);
        if (terminal_bytes == NULL) {
            bridge_close_fds(lease);
            return NULL;
        }
        terminal = bridge_new(&ManagedEVMToolchainProvisionTerminalType,
            PLAMEN_BRIDGE_MANAGED_TERMINAL, lease_object, lease->owner,
            lease->request_bytes, terminal_bytes);
        Py_DECREF(terminal_bytes);
        if (terminal != NULL) {
            memcpy(terminal->capability_id, issued, 32);
        }
        secure_zero(issued, sizeof(issued));
        bridge_close_fds(lease);
        return (PyObject *)terminal;
    }
#endif
    bridge_close_fds(lease);
    PyErr_SetString(PyExc_RuntimeError,
                    "native managed-EVM provision provider hook is unavailable");
    return NULL;
}

static PyObject *
project_managed_evm_toolchain_terminal(PyObject *module, PyObject *args)
{
    PyObject *terminal_object;
    PlamenBridgeCapabilityObject *terminal;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:project_managed_evm_toolchain_terminal",
                          &terminal_object)) {
        return NULL;
    }
    terminal = (PlamenBridgeCapabilityObject *)terminal_object;
    if (!bridge_capability_live(terminal,
            &ManagedEVMToolchainProvisionTerminalType,
            PLAMEN_BRIDGE_MANAGED_TERMINAL, 0) ||
            terminal->terminal_bytes == NULL ||
            !bridge_canonical_json_bytes(terminal->terminal_bytes, 0,
                                         "managed EVM terminal")) {
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        PyObject *result = bridge_specialized_rpc(
            terminal->specialized_session, terminal->capability_id,
            PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PROJECT, 0,
            terminal->terminal_bytes, NULL, NULL, 0,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED, NULL,
            PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
        if (result == NULL) {
            (void)bridge_burn(terminal);
            return NULL;
        }
        if (bridge_burn(terminal) < 0) {
            Py_DECREF(result);
            return NULL;
        }
        return result;
    }
#else
    if (bridge_burn(terminal) < 0) {
        return NULL;
    }
    return Py_NewRef(terminal->terminal_bytes);
#endif
}

static PyObject *
project_evm_analysis_projection_receipt(PyObject *module, PyObject *args)
{
    PyObject *authority_object;
    PlamenBridgeCapabilityObject *authority;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:project_evm_analysis_projection_receipt",
                          &authority_object)) {
        return NULL;
    }
    authority = (PlamenBridgeCapabilityObject *)authority_object;
    if (!bridge_capability_live(authority,
            &EVMAnalysisProjectionAuthorityType,
            PLAMEN_BRIDGE_EVM_PROJECTION, 0) ||
            authority->terminal_bytes == NULL ||
            !bridge_canonical_json_bytes(authority->terminal_bytes, 0,
                                         "EVM analysis projection receipt")) {
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    return bridge_specialized_rpc(authority->specialized_session,
        authority->capability_id,
        PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_PROJECT, 0,
        authority->terminal_bytes, NULL, NULL, 0,
        PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED, NULL,
        PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
#else
    return Py_NewRef(authority->terminal_bytes);
#endif
}

static void
bridge_projection_hex32(const unsigned char input[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0U; index < 32U; index++) {
        output[index * 2U] = digits[input[index] >> 4];
        output[index * 2U + 1U] = digits[input[index] & 15U];
    }
    output[64] = '\0';
}

static int
bridge_projection_authority_live(PyObject *object,
                                 PlamenBridgeCapabilityObject **authority)
{
    PlamenBridgeCapabilityObject *value =
        (PlamenBridgeCapabilityObject *)object;
    if (authority != NULL) *authority = NULL;
    if (authority == NULL || !bridge_capability_live(value,
            &EVMAnalysisProjectionAuthorityType,
            PLAMEN_BRIDGE_EVM_PROJECTION, 0)
        || value->terminal_bytes == NULL
        || !bridge_canonical_json_bytes(value->terminal_bytes, 0,
            "EVM analysis projection receipt")
        || value->retained_fd_count != 4U
        || value->retained_fds[1] < 0 || value->retained_fds[2] < 0) {
        return 0;
    }
    *authority = value;
    return 1;
}

static PyObject *
project_evm_analysis_projection_lineage(PyObject *module, PyObject *args)
{
    PyObject *authority_object, *result = NULL;
    PlamenBridgeCapabilityObject *authority = NULL;
    struct stat information, replay;
    char *raw = NULL;
    size_t offset = 0U;
    ssize_t amount;
    int descriptor = -1;
    (void)module;
    memset(&information, 0, sizeof(information));
    memset(&replay, 0, sizeof(replay));
    if (!PyArg_ParseTuple(args, "O:project_evm_analysis_projection_lineage",
            &authority_object)
        || !bridge_projection_authority_live(authority_object, &authority))
        return NULL;
    descriptor = openat(authority->retained_fds[2],
        "materialization-lineage.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 1
        || information.st_size <= 0 || information.st_size > 8 * 1024 * 1024) {
        PyErr_SetString(PyExc_RuntimeError,
            "native projection lineage descriptor is unavailable");
        goto done;
    }
    raw = malloc((size_t)information.st_size);
    if (raw == NULL) { PyErr_NoMemory(); goto done; }
    while (offset < (size_t)information.st_size) {
        amount = pread(descriptor, raw + offset,
            (size_t)information.st_size - offset, (off_t)offset);
        if (amount <= 0) {
            PyErr_SetFromErrno(PyExc_OSError); goto done;
        }
        offset += (size_t)amount;
    }
    if (fstat(descriptor, &replay) != 0
        || replay.st_dev != information.st_dev
        || replay.st_ino != information.st_ino
        || replay.st_size != information.st_size) {
        PyErr_SetString(PyExc_RuntimeError,
            "native projection lineage changed during replay");
        goto done;
    }
    result = PyBytes_FromStringAndSize(raw, (Py_ssize_t)offset);
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (raw != NULL) { secure_zero(raw, (size_t)information.st_size); free(raw); }
    return result;
}

static int
bridge_projection_path_json_safe(const char *path)
{
    const unsigned char *cursor = (const unsigned char *)path;
    if (path == NULL || path[0] != '/') return 0;
    for (; *cursor != 0U; ++cursor) {
        if (*cursor < 0x20U || *cursor == 0x22U || *cursor == 0x5cU)
            return 0;
    }
    return 1;
}

static PyObject *
project_evm_analysis_projection_workspace_binding(PyObject *module,
                                                  PyObject *args)
{
    PyObject *authority_object, *result = NULL;
    PlamenBridgeCapabilityObject *authority = NULL;
    unsigned char identity[32];
    char identity_hex[65], receipt_hex[65], path[PATH_MAX];
    char *raw = NULL;
    int descriptor = -1, amount;
    size_t capacity;
    (void)module;
    memset(identity, 0, sizeof(identity));
    memset(identity_hex, 0, sizeof(identity_hex));
    memset(receipt_hex, 0, sizeof(receipt_hex));
    memset(path, 0, sizeof(path));
    if (!PyArg_ParseTuple(args,
            "O:project_evm_analysis_projection_workspace_binding",
            &authority_object)
        || !bridge_projection_authority_live(authority_object, &authority))
        return NULL;
    descriptor = openat(authority->retained_fds[1], "analysis-workspace",
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY);
    if (descriptor < 0
        || plamen_broker_v2_fd_identity(descriptor, identity)
            != PLAMEN_BROKER_V2_OK
#ifdef F_GETPATH
        || fcntl(descriptor, F_GETPATH, path) != 0
#else
        || 1
#endif
        || !bridge_projection_path_json_safe(path)) {
        PyErr_SetString(PyExc_RuntimeError,
            "native projection workspace descriptor is unavailable");
        goto done;
    }
    bridge_projection_hex32(identity, identity_hex);
    bridge_projection_hex32(authority->terminal_sha256, receipt_hex);
    capacity = strlen(path) + 384U;
    raw = malloc(capacity);
    if (raw == NULL) { PyErr_NoMemory(); goto done; }
    amount = snprintf(raw, capacity,
        "{\"descriptor_identity_sha256\":\"%s\",\"projection_receipt_sha256\":\"%s\",\"schema\":\"plamen.evm-analysis-projection-workspace-binding.v1\",\"workspace_path\":\"%s\"}",
        identity_hex, receipt_hex, path);
    if (amount <= 0 || (size_t)amount >= capacity) {
        PyErr_SetString(PyExc_RuntimeError,
            "native projection workspace binding exceeds its bound");
        goto done;
    }
    result = PyBytes_FromStringAndSize(raw, (Py_ssize_t)amount);
done:
    if (descriptor >= 0) (void)close(descriptor);
    if (raw != NULL) { secure_zero(raw, capacity); free(raw); }
    secure_zero(identity, sizeof(identity));
    secure_zero(identity_hex, sizeof(identity_hex));
    secure_zero(receipt_hex, sizeof(receipt_hex));
    secure_zero(path, sizeof(path));
    return result;
}

static int
bridge_retain_projection_descriptors(PlamenBridgeCapabilityObject *authority,
                                     const int supplied[4])
{
    static const uint16_t purposes[4] = {
        PLAMEN_BROKER_V2_FD_PROJECTION_PROJECT,
        PLAMEN_BROKER_V2_FD_PROJECTION_SCRATCH,
        PLAMEN_BROKER_V2_FD_PROJECTION_STATE,
        PLAMEN_BROKER_V2_FD_PROJECTION_MODULES
    };
    size_t index, prior;
    for (index = 0; index < 4U; index++) {
        struct stat current;
        if (bridge_duplicate_fd(supplied[index], 1,
                0, index == 0U || index == 3U,
                &authority->retained_fds[index]) < 0) {
            bridge_close_fds(authority);
            return -1;
        }
        authority->retained_fd_count++;
        if (fstat(authority->retained_fds[index], &current) != 0) {
            bridge_close_fds(authority);
            PyErr_SetFromErrno(PyExc_OSError);
            return -1;
        }
        for (prior = 0; prior < index; prior++) {
            struct stat earlier;
            if (fstat(authority->retained_fds[prior], &earlier) != 0 ||
                    (current.st_dev == earlier.st_dev &&
                     current.st_ino == earlier.st_ino)) {
                bridge_close_fds(authority);
                PyErr_SetString(PyExc_ValueError,
                                "projection descriptors must be identity-disjoint");
                return -1;
            }
        }
        if (bridge_bind_retained_fd(authority, index, purposes[index],
                index == 1U || index == 2U
                    ? PLAMEN_BROKER_V2_FD_READ_WRITE
                    : PLAMEN_BROKER_V2_FD_READ) < 0) {
            bridge_close_fds(authority);
            return -1;
        }
    }
    return 0;
}

static PyObject *
commit_evm_analysis_projection(PyObject *module, PyObject *args)
{
    PyObject *request, *receipt;
    PlamenBridgeCapabilityObject *authority;
    int supplied[4];
    unsigned char issued[32];
    (void)module;
    if (!PyArg_ParseTuple(args, "Oiiii:commit_evm_analysis_projection",
            &request, &supplied[0], &supplied[1], &supplied[2],
            &supplied[3]) ||
            !bridge_canonical_json_bytes(request, 0,
                                         "EVM projection commit request")) {
        return NULL;
    }
    authority = bridge_new(&EVMAnalysisProjectionAuthorityType,
        PLAMEN_BRIDGE_EVM_PROJECTION, NULL, NULL, request, NULL);
    if (authority == NULL) {
        return NULL;
    }
    authority->specialized_session = bridge_specialized_session_retain(
        bridge_projection_session);
    if (bridge_retain_projection_descriptors(authority, supplied) < 0) {
        Py_DECREF(authority);
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    receipt = bridge_specialized_rpc(authority->specialized_session,
        authority->capability_id,
        PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT, 0, request,
        authority->retained_fd_metadata, authority->retained_fds,
        authority->retained_fd_count, PLAMEN_BROKER_V2_SPECIALIZED_ISSUED,
        issued, PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS);
    if (receipt == NULL) {
        Py_DECREF(authority);
        return NULL;
    }
    authority->terminal_bytes = receipt;
    if (plamen_broker_v2_sha256(
            (const unsigned char *)PyBytes_AS_STRING(receipt),
            (size_t)PyBytes_GET_SIZE(receipt), authority->terminal_sha256) !=
                PLAMEN_BROKER_V2_OK) {
        Py_DECREF(authority);
        PyErr_SetString(PyExc_RuntimeError,
                        "projection receipt digest failed");
        return NULL;
    }
    memcpy(authority->capability_id, issued, 32);
    secure_zero(issued, sizeof(issued));
    return (PyObject *)authority;
#else
    (void)receipt;
    (void)issued;
    Py_DECREF(authority);
    PyErr_SetString(PyExc_RuntimeError,
                    "native EVM projection commit provider hook is unavailable");
    return NULL;
#endif
}

static PyObject *
recover_evm_analysis_projection_authority(PyObject *module, PyObject *args)
{
    const char *receipt_sha256;
    Py_ssize_t size, index;
    (void)module;
    if (!PyArg_ParseTuple(args, "s#:recover_evm_analysis_projection_authority",
                          &receipt_sha256, &size)) {
        return NULL;
    }
    if (size != 64) {
        PyErr_SetString(PyExc_ValueError,
                        "projection recovery digest must be lowercase SHA-256");
        return NULL;
    }
    for (index = 0; index < size; index++) {
        unsigned char value = (unsigned char)receipt_sha256[index];
        if (!((value >= '0' && value <= '9') ||
              (value >= 'a' && value <= 'f'))) {
            PyErr_SetString(PyExc_ValueError,
                            "projection recovery digest must be lowercase SHA-256");
            return NULL;
        }
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        char payload[96];
        int amount;
        PyObject *payload_object, *receipt;
        PlamenBridgeCapabilityObject *authority;
        unsigned char zeros[32] = {0}, issued[32];
        amount = snprintf(payload, sizeof(payload),
            "{\"receipt_sha256\":\"%.*s\"}", (int)size, receipt_sha256);
        if (amount <= 0 || (size_t)amount >= sizeof(payload) ||
                (payload_object = PyBytes_FromStringAndSize(
                    payload, (Py_ssize_t)amount)) == NULL) {
            return NULL;
        }
        receipt = bridge_specialized_rpc(bridge_projection_session, zeros,
            PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER,
            PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER, payload_object,
            NULL, NULL, 0, PLAMEN_BROKER_V2_SPECIALIZED_RECOVERED, issued,
            PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
        Py_DECREF(payload_object);
        if (receipt == NULL) {
            return NULL;
        }
        authority = bridge_new(&EVMAnalysisProjectionAuthorityType,
            PLAMEN_BRIDGE_EVM_PROJECTION, NULL, NULL, NULL, receipt);
        Py_DECREF(receipt);
        if (authority == NULL) {
            return NULL;
        }
        authority->specialized_session = bridge_specialized_session_retain(
            bridge_projection_session);
        memcpy(authority->capability_id, issued, 32);
        secure_zero(issued, sizeof(issued));
        return (PyObject *)authority;
    }
#else
    PyErr_SetString(PyExc_RuntimeError,
                    "native EVM projection durable recovery provider hook is unavailable");
    return NULL;
#endif
}

static int
bridge_initial_consumer_live(PyObject *object)
{
    V2AuthorityConsumerObject *initial;
    if (Py_TYPE(object) != &V2AuthorityConsumerType) {
        PyErr_SetString(PyExc_TypeError,
                        "exact native initial authority is required");
        return 0;
    }
    initial = (V2AuthorityConsumerObject *)object;
    if (initial->creator_pid != getpid() ||
            initial->creator_interpreter_id != current_interpreter_id() ||
            atomic_load_explicit(&initial->consumed,
                                 memory_order_acquire) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native initial authority is consumed or crossed a boundary");
        return 0;
    }
    return 1;
}

static _Atomic int darwin_tool_custody_acquired = 0;
#ifdef PLAMEN_NATIVE_INSTALLED_BACKEND_GENERATION_ENABLED
static _Atomic int backend_install_generation_acquired = 0;
#endif

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static void
bridge_hex32(const unsigned char input[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32U; index++) {
        output[index * 2U] = digits[input[index] >> 4];
        output[index * 2U + 1U] = digits[input[index] & 15U];
    }
    output[64] = '\0';
}

/* Match json.dumps(..., ensure_ascii=True) for one already-decoded path. */
static int
bridge_json_escape_unicode(PyObject *value, char **output, size_t *output_size)
{
    static const char hex[] = "0123456789abcdef";
    Py_ssize_t length, index;
    char *escaped;
    size_t offset = 0, capacity;

    *output = NULL;
    *output_size = 0;
    if (!PyUnicode_CheckExact(value)) {
        return -1;
    }
    length = PyUnicode_GET_LENGTH(value);
    if (length < 1 || (uint64_t)length > (SIZE_MAX - 1U) / 12U) {
        return -1;
    }
    capacity = (size_t)length * 12U + 1U;
    escaped = (char *)malloc(capacity);
    if (escaped == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    for (index = 0; index < length; index++) {
        Py_UCS4 value_at = PyUnicode_ReadChar(value, index);
        if (value_at == (Py_UCS4)-1 && PyErr_Occurred()) {
            free(escaped);
            return -1;
        }
        if (value_at == '"' || value_at == '\\') {
            escaped[offset++] = '\\';
            escaped[offset++] = (char)value_at;
        } else if (value_at == '\b' || value_at == '\f' ||
                   value_at == '\n' || value_at == '\r' ||
                   value_at == '\t') {
            static const char short_escapes[] = "bfnrt";
            static const char controls[] = "\b\f\n\r\t";
            const char *matched = strchr(controls, (int)value_at);
            escaped[offset++] = '\\';
            escaped[offset++] = short_escapes[matched - controls];
        } else if (value_at >= 0x20U && value_at <= 0x7eU) {
            escaped[offset++] = (char)value_at;
        } else if (value_at <= 0xffffU) {
            escaped[offset++] = '\\';
            escaped[offset++] = 'u';
            escaped[offset++] = hex[(value_at >> 12) & 15U];
            escaped[offset++] = hex[(value_at >> 8) & 15U];
            escaped[offset++] = hex[(value_at >> 4) & 15U];
            escaped[offset++] = hex[value_at & 15U];
        } else if (value_at <= 0x10ffffU) {
            Py_UCS4 scalar = value_at - 0x10000U;
            Py_UCS4 high = 0xd800U + (scalar >> 10);
            Py_UCS4 low = 0xdc00U + (scalar & 0x3ffU);
            escaped[offset++] = '\\';
            escaped[offset++] = 'u';
            escaped[offset++] = hex[(high >> 12) & 15U];
            escaped[offset++] = hex[(high >> 8) & 15U];
            escaped[offset++] = hex[(high >> 4) & 15U];
            escaped[offset++] = hex[high & 15U];
            escaped[offset++] = '\\';
            escaped[offset++] = 'u';
            escaped[offset++] = hex[(low >> 12) & 15U];
            escaped[offset++] = hex[(low >> 8) & 15U];
            escaped[offset++] = hex[(low >> 4) & 15U];
            escaped[offset++] = hex[low & 15U];
        } else {
            secure_zero(escaped, capacity);
            free(escaped);
            return -1;
        }
    }
    escaped[offset] = '\0';
    *output = escaped;
    *output_size = offset;
    return 0;
}

static PyObject *
bridge_runtime_identity(PyObject *module,
                        V2AuthorityConsumerObject *initial, int managed)
{
    PyObject *filename_object = NULL, *result = NULL;
    const char *filename;
    Py_ssize_t filename_size;
    struct stat before, after;
    unsigned char extension_sha256[32];
    void *mapping = MAP_FAILED;
    char extension_hex[65], deployment_hex[65], runtime_hex[65];
    char peer_hex[65], custody_hex[65];
    char *escaped_filename = NULL, *rendered = NULL;
    size_t escaped_filename_size = 0, capacity;
    int extension_fd = -1, amount;

    memset(&before, 0, sizeof(before));
    memset(&after, 0, sizeof(after));
    memset(extension_sha256, 0, sizeof(extension_sha256));
    filename_object = PyModule_GetFilenameObject(module);
    if (filename_object == NULL ||
            (filename = PyUnicode_AsUTF8AndSize(
                filename_object, &filename_size)) == NULL ||
            filename_size < 1 || filename_size >= PATH_MAX ||
            filename[0] != '/' ||
            memchr(filename, '\0', (size_t)filename_size) != NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native extension filename is unavailable or noncanonical");
        goto done;
    }
    if (bridge_json_escape_unicode(filename_object, &escaped_filename,
                                   &escaped_filename_size) < 0) {
        if (!PyErr_Occurred()) {
            PyErr_SetString(PyExc_RuntimeError,
                            "native extension filename cannot be represented canonically");
        }
        goto done;
    }
    extension_fd = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (extension_fd < 0 || fstat(extension_fd, &before) != 0 ||
            !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
            before.st_size < 1 || before.st_size > 512 * 1024 * 1024 ||
            (before.st_mode & 0022) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native extension file identity is unsafe");
        goto done;
    }
    mapping = mmap(NULL, (size_t)before.st_size, PROT_READ,
                   MAP_PRIVATE, extension_fd, 0);
    if (mapping == MAP_FAILED ||
            plamen_broker_v2_sha256(
                (const unsigned char *)mapping, (size_t)before.st_size,
                extension_sha256) != PLAMEN_BROKER_V2_OK ||
            fstat(extension_fd, &after) != 0 ||
            before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
            before.st_mode != after.st_mode || before.st_uid != after.st_uid ||
            before.st_gid != after.st_gid || before.st_nlink != after.st_nlink ||
            before.st_size != after.st_size ||
            before.st_mtime != after.st_mtime || before.st_ctime != after.st_ctime) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native extension changed during identity capture");
        goto done;
    }
    bridge_hex32(extension_sha256, extension_hex);
    bridge_hex32(initial->native_deployment_receipt_sha256, deployment_hex);
    bridge_hex32(initial->runtime_closure_sha256, runtime_hex);
    bridge_hex32(initial->broker_peer_identity_sha256, peer_hex);
    bridge_hex32(initial->managed_toolchain_custody_sha256, custody_hex);
    capacity = escaped_filename_size + 1024U;
    rendered = (char *)malloc(capacity);
    if (rendered == NULL) {
        PyErr_NoMemory();
        goto done;
    }
    if (managed) {
        amount = snprintf(rendered, capacity,
            "{\"broker_peer_identity_sha256\":\"%s\","
            "\"extension_byte_count\":%llu,"
            "\"extension_path\":\"%s\","
            "\"extension_sha256\":\"%s\","
            "\"managed_toolchain_custody_sha256\":\"%s\","
            "\"native_deployment_receipt_sha256\":\"%s\","
            "\"platform\":\"%s\","
            "\"runtime_closure_sha256\":\"%s\","
            "\"schema\":\"plamen.managed-evm-toolchain-runtime-identity.v1\"}",
            peer_hex, (unsigned long long)before.st_size, escaped_filename,
            extension_hex, custody_hex, deployment_hex,
            PLAMEN_NATIVE_PLATFORM_NAME, runtime_hex);
    } else {
        amount = snprintf(rendered, capacity,
            "{\"broker_peer_identity_sha256\":\"%s\","
            "\"extension_byte_count\":%llu,"
            "\"extension_path\":\"%s\","
            "\"extension_sha256\":\"%s\","
            "\"native_deployment_receipt_sha256\":\"%s\","
            "\"platform\":\"%s\","
            "\"runtime_closure_sha256\":\"%s\","
            "\"schema\":\"plamen.darwin-tool-runtime-identity.v1\"}",
            peer_hex, (unsigned long long)before.st_size, escaped_filename,
            extension_hex, deployment_hex, PLAMEN_NATIVE_PLATFORM_NAME,
            runtime_hex);
    }
    if (amount <= 0 || (size_t)amount >= capacity) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native runtime identity exceeded its bound");
        goto done;
    }
    result = PyBytes_FromStringAndSize(rendered, (Py_ssize_t)amount);

done:
    if (mapping != MAP_FAILED) {
        (void)munmap(mapping, (size_t)before.st_size);
    }
    if (extension_fd >= 0) {
        (void)close(extension_fd);
    }
    Py_XDECREF(filename_object);
    if (escaped_filename != NULL) {
        secure_zero(escaped_filename, escaped_filename_size + 1U);
        free(escaped_filename);
    }
    if (rendered != NULL) {
        secure_zero(rendered, capacity);
        free(rendered);
    }
    secure_zero(extension_sha256, sizeof(extension_sha256));
    secure_zero(extension_hex, sizeof(extension_hex));
    secure_zero(deployment_hex, sizeof(deployment_hex));
    secure_zero(runtime_hex, sizeof(runtime_hex));
    secure_zero(peer_hex, sizeof(peer_hex));
    secure_zero(custody_hex, sizeof(custody_hex));
    return result;
}
#endif

static PyObject *
darwin_tool_runtime_identity(PyObject *module, PyObject *args)
{
    PyObject *initial;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:darwin_tool_runtime_identity", &initial)) {
        return NULL;
    }
    if (!bridge_initial_consumer_live(initial)) {
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        unsigned char zeros[32] = {0};
        PyObject *empty = PyBytes_FromString("{}");
        PyObject *result;
        (void)module;
        if (empty == NULL) {
            return NULL;
        }
        result = bridge_specialized_rpc(bridge_snapshot_session, zeros,
            PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_RUNTIME_IDENTITY, 0,
            empty, NULL, NULL, 0,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED, NULL,
            PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
        Py_DECREF(empty);
        return result;
    }
#else
    return bridge_runtime_identity(
        module, (V2AuthorityConsumerObject *)initial, 0);
#endif
}

static PyObject *
acquire_darwin_tool_custody(PyObject *module, PyObject *args)
{
    PyObject *initial;
    PlamenBridgeCapabilityObject *custody;
    int expected = 0;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:acquire_darwin_tool_custody", &initial)) {
        return NULL;
    }
    if (!bridge_initial_consumer_live(initial)) {
        return NULL;
    }
    if (((V2AuthorityConsumerObject *)initial)->initial_authority_role !=
            PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER) {
        PyErr_SetString(
            PyExc_RuntimeError,
            "native tool custody requires guest-driver initial authority");
        return NULL;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &darwin_tool_custody_acquired, &expected, 1,
            memory_order_acq_rel, memory_order_acquire)) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native Darwin tool custody was already acquired");
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        unsigned char zeros[32] = {0}, issued[32];
        PyObject *empty = PyBytes_FromString("{}");
        PyObject *projection;
        if (empty == NULL) {
            atomic_store_explicit(&darwin_tool_custody_acquired, 0,
                                  memory_order_release);
            return NULL;
        }
        projection = bridge_specialized_rpc(bridge_snapshot_session, zeros,
            PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE, 0, empty,
            NULL, NULL, 0, PLAMEN_BROKER_V2_SPECIALIZED_ISSUED, issued,
            PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
        Py_DECREF(empty);
        if (projection == NULL) {
            atomic_store_explicit(&darwin_tool_custody_acquired, 0,
                                  memory_order_release);
            return NULL;
        }
        Py_DECREF(projection);
        custody = bridge_new(&DarwinToolCustodyAuthorityType,
                             PLAMEN_BRIDGE_DARWIN_TOOL_CUSTODY,
                             initial, initial, NULL, NULL);
        if (custody != NULL) {
            custody->specialized_session = bridge_specialized_session_retain(
                bridge_snapshot_session);
            memcpy(custody->capability_id, issued, 32);
        } else {
            atomic_store_explicit(&darwin_tool_custody_acquired, 0,
                                  memory_order_release);
        }
        secure_zero(issued, sizeof(issued));
        return (PyObject *)custody;
    }
#else
    custody = bridge_new(&DarwinToolCustodyAuthorityType,
                         PLAMEN_BRIDGE_DARWIN_TOOL_CUSTODY,
                         initial, initial, NULL, NULL);
    if (custody == NULL) {
        atomic_store_explicit(&darwin_tool_custody_acquired, 0,
                              memory_order_release);
    }
    return (PyObject *)custody;
#endif
}

static PyObject *
prepare_darwin_tool_execution(PyObject *module, PyObject *args)
{
    PyObject *custody_object, *request;
    PlamenBridgeCapabilityObject *custody, *lease;
    struct stat source_info, scratch_info, state_info, project_info;
    int source_fd, scratch_fd, state_fd, project_fd, expected = 0;
    (void)module;
    if (!PyArg_ParseTuple(args, "OOiiii:prepare_darwin_tool_execution",
                          &custody_object, &request, &source_fd,
                          &scratch_fd, &state_fd, &project_fd)) {
        return NULL;
    }
    custody = (PlamenBridgeCapabilityObject *)custody_object;
    if (!bridge_capability_live(custody, &DarwinToolCustodyAuthorityType,
            PLAMEN_BRIDGE_DARWIN_TOOL_CUSTODY, 0) ||
            !bridge_canonical_json_bytes(request, 0,
                                         "snapshot-bound tool request")) {
        return NULL;
    }
    if (fstat(source_fd, &source_info) != 0 ||
            fstat(scratch_fd, &scratch_info) != 0 ||
            fstat(state_fd, &state_info) != 0 ||
            fstat(project_fd, &project_info) != 0 ||
            !S_ISDIR(scratch_info.st_mode) || !S_ISDIR(state_info.st_mode) ||
            !S_ISDIR(project_info.st_mode) ||
            (source_info.st_dev == scratch_info.st_dev &&
             source_info.st_ino == scratch_info.st_ino) ||
            (source_info.st_dev == state_info.st_dev &&
             source_info.st_ino == state_info.st_ino) ||
            (scratch_info.st_dev == state_info.st_dev &&
             scratch_info.st_ino == state_info.st_ino) ||
            (project_info.st_dev == source_info.st_dev &&
             project_info.st_ino == source_info.st_ino) ||
            (project_info.st_dev == scratch_info.st_dev &&
             project_info.st_ino == scratch_info.st_ino) ||
            (project_info.st_dev == state_info.st_dev &&
             project_info.st_ino == state_info.st_ino)) {
        PyErr_SetString(PyExc_ValueError,
                        "snapshot-bound tool descriptors are invalid or aliased");
        return NULL;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &custody->in_flight, &expected, 1,
            memory_order_acq_rel, memory_order_acquire)) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native tool custody already has an in-flight execution");
        return NULL;
    }
    lease = bridge_new(&DarwinToolExecutionLeaseType,
                       PLAMEN_BRIDGE_DARWIN_TOOL_EXECUTION,
                       custody_object, custody->owner, request, NULL);
    if (lease == NULL) {
        atomic_store_explicit(&custody->in_flight, 0, memory_order_release);
        return NULL;
    }
    if (bridge_duplicate_fd(source_fd, 0, 0, 1,
                            &lease->retained_fds[0]) < 0) {
        atomic_store_explicit(&custody->in_flight, 0, memory_order_release);
        Py_DECREF(lease);
        return NULL;
    }
    lease->retained_fd_count = 1;
    if (bridge_duplicate_fd(scratch_fd, 1, 0, 0,
                            &lease->retained_fds[1]) < 0) {
        atomic_store_explicit(&custody->in_flight, 0, memory_order_release);
        Py_DECREF(lease);
        return NULL;
    }
    lease->retained_fd_count = 2;
    if (bridge_duplicate_fd(state_fd, 1, 0, 0,
                            &lease->retained_fds[2]) < 0) {
        atomic_store_explicit(&custody->in_flight, 0, memory_order_release);
        Py_DECREF(lease);
        return NULL;
    }
    lease->retained_fd_count = 3;
    if (bridge_duplicate_fd(project_fd, 1, 0, 1,
                            &lease->retained_fds[3]) < 0) {
        atomic_store_explicit(&custody->in_flight, 0, memory_order_release);
        Py_DECREF(lease);
        return NULL;
    }
    lease->retained_fd_count = 4;
    if (bridge_bind_retained_fd(
            lease, 0, PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE,
            PLAMEN_BROKER_V2_FD_READ) < 0 ||
            bridge_bind_retained_fd(
            lease, 1, PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH,
            PLAMEN_BROKER_V2_FD_READ_WRITE) < 0 ||
            bridge_bind_retained_fd(
            lease, 2, PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE,
            PLAMEN_BROKER_V2_FD_READ_WRITE) < 0 ||
            bridge_bind_retained_fd(
            lease, 3, PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT,
            PLAMEN_BROKER_V2_FD_READ) < 0) {
        atomic_store_explicit(&custody->in_flight, 0, memory_order_release);
        Py_DECREF(lease);
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        PyObject *projection;
        unsigned char issued[32];
        projection = bridge_specialized_rpc(custody->specialized_session,
            custody->capability_id,
            PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE, 0, request,
            lease->retained_fd_metadata, lease->retained_fds,
            lease->retained_fd_count, PLAMEN_BROKER_V2_SPECIALIZED_ISSUED,
            issued, PLAMEN_V2_OPERATION_QUICK_DEADLINE_MS);
        if (projection == NULL) {
            atomic_store_explicit(&custody->in_flight, 0,
                                  memory_order_release);
            Py_DECREF(lease);
            return NULL;
        }
        Py_DECREF(projection);
        memcpy(lease->capability_id, issued, 32);
        secure_zero(issued, sizeof(issued));
    }
#endif
    return (PyObject *)lease;
}

static PyObject *
project_darwin_fuzz_campaign_prepared(PyObject *module, PyObject *args)
{
    PyObject *lease_object;
    PlamenBridgeCapabilityObject *lease;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:project_darwin_fuzz_campaign_prepared",
                          &lease_object)) return NULL;
    lease = (PlamenBridgeCapabilityObject *)lease_object;
    if (!bridge_capability_live(lease, &DarwinToolExecutionLeaseType,
            PLAMEN_BRIDGE_DARWIN_TOOL_EXECUTION, 0)
            || lease->terminal_bytes == NULL
            || !bridge_canonical_json_bytes(lease->terminal_bytes, 0,
                                             "fuzz campaign prepared authority"))
        return NULL;
    return Py_NewRef(lease->terminal_bytes);
}

static PyObject *
execute_darwin_tool(PyObject *module, PyObject *args)
{
    PyObject *custody_object, *lease_object;
    PlamenBridgeCapabilityObject *custody, *lease;
    (void)module;
    if (!PyArg_ParseTuple(args, "OO:execute_darwin_tool",
                          &custody_object, &lease_object)) {
        return NULL;
    }
    custody = (PlamenBridgeCapabilityObject *)custody_object;
    lease = (PlamenBridgeCapabilityObject *)lease_object;
    if (!bridge_capability_live(custody, &DarwinToolCustodyAuthorityType,
            PLAMEN_BRIDGE_DARWIN_TOOL_CUSTODY, 0) ||
            !bridge_capability_live(lease, &DarwinToolExecutionLeaseType,
            PLAMEN_BRIDGE_DARWIN_TOOL_EXECUTION, 0) ||
            lease->parent != custody_object || bridge_burn(lease) < 0) {
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        PyObject *terminal_bytes = bridge_specialized_rpc(
            lease->specialized_session, lease->capability_id,
            PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE, 0,
            lease->request_bytes, NULL, NULL, 0,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED, NULL,
            PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS);
        PlamenBridgeCapabilityObject *terminal = NULL;
        if (terminal_bytes != NULL) {
            terminal = bridge_new(&DarwinToolExecutionTerminalType,
                PLAMEN_BRIDGE_DARWIN_TOOL_TERMINAL, lease_object,
                lease->owner, lease->request_bytes, terminal_bytes);
            Py_DECREF(terminal_bytes);
        }
        bridge_close_fds(lease);
        atomic_store_explicit(&custody->in_flight, 0, memory_order_release);
        return (PyObject *)terminal;
    }
#else
    bridge_close_fds(lease);
    atomic_store_explicit(&custody->in_flight, 0, memory_order_release);
    PyErr_SetString(PyExc_RuntimeError,
                    "native Darwin snapshot-bound tool provider hook is unavailable");
    return NULL;
#endif
}

static PyObject *
execute_darwin_fuzz_campaign(PyObject *module, PyObject *args)
{
    PyObject *custody_object, *lease_object;
    PlamenBridgeCapabilityObject *custody, *lease;
    (void)module;
    if (!PyArg_ParseTuple(args, "OO:execute_darwin_fuzz_campaign",
                          &custody_object, &lease_object)) {
        return NULL;
    }
    custody = (PlamenBridgeCapabilityObject *)custody_object;
    lease = (PlamenBridgeCapabilityObject *)lease_object;
    if (!bridge_capability_live(custody, &DarwinToolCustodyAuthorityType,
            PLAMEN_BRIDGE_DARWIN_TOOL_CUSTODY, 0) ||
            !bridge_capability_live(lease, &DarwinToolExecutionLeaseType,
            PLAMEN_BRIDGE_DARWIN_TOOL_EXECUTION, 0) ||
            lease->parent != custody_object || bridge_burn(lease) < 0) {
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    {
        PyObject *terminal_bytes = bridge_specialized_rpc(
            lease->specialized_session, lease->capability_id,
            PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE, 0,
            lease->request_bytes, NULL, NULL, 0,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED, NULL,
            PLAMEN_V2_OPERATION_MUTATION_DEADLINE_MS);
        PlamenBridgeCapabilityObject *terminal = NULL;
        if (terminal_bytes != NULL) {
            terminal = bridge_new(&DarwinToolExecutionTerminalType,
                PLAMEN_BRIDGE_DARWIN_TOOL_TERMINAL, lease_object,
                lease->owner, lease->request_bytes, terminal_bytes);
            Py_DECREF(terminal_bytes);
        }
        bridge_close_fds(lease);
        atomic_store_explicit(&custody->in_flight, 0, memory_order_release);
        return (PyObject *)terminal;
    }
#else
    bridge_close_fds(lease);
    atomic_store_explicit(&custody->in_flight, 0, memory_order_release);
    PyErr_SetString(PyExc_RuntimeError,
                    "native Darwin fuzz campaign provider hook is unavailable");
    return NULL;
#endif
}

static PyObject *
project_darwin_tool_execution_terminal(PyObject *module, PyObject *args)
{
    PyObject *terminal_object;
    PlamenBridgeCapabilityObject *terminal;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:project_darwin_tool_execution_terminal",
                          &terminal_object)) {
        return NULL;
    }
    terminal = (PlamenBridgeCapabilityObject *)terminal_object;
    if (!bridge_capability_live(terminal,
            &DarwinToolExecutionTerminalType,
            PLAMEN_BRIDGE_DARWIN_TOOL_TERMINAL, 0) ||
            terminal->terminal_bytes == NULL ||
            !bridge_canonical_json_bytes(terminal->terminal_bytes, 0,
                                         "snapshot tool terminal")) {
        return NULL;
    }
    return Py_NewRef(terminal->terminal_bytes);
}

static PyObject *
native_specialized_bridge_status(PyObject *module, PyObject *args)
{
    char status[512];
    int amount;
    (void)module;
    if (!PyArg_ParseTuple(args, ":native_specialized_bridge_status")) {
        return NULL;
    }
    amount = snprintf(status, sizeof(status),
        "{\"evm_analysis_projection\":\"%s\","
        "\"js_dependency_materializer\":\"%s\","
        "\"managed_evm_toolchain\":\"%s\","
        "\"schema\":\"plamen.native-specialized-bridge-status.v1\","
        "\"snapshot_bound_tools\":\"%s\"}",
        bridge_projection_session != NULL ? "READY" : "PROVIDER_UNAVAILABLE",
        bridge_js_session != NULL ? "READY" : "PROVIDER_UNAVAILABLE",
        bridge_managed_session != NULL ? "READY" : "PROVIDER_UNAVAILABLE",
        bridge_snapshot_session != NULL ? "READY" : "PROVIDER_UNAVAILABLE");
    if (amount <= 0 || (size_t)amount >= sizeof(status)) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native specialized bridge status overflow");
        return NULL;
    }
    return PyBytes_FromStringAndSize(status, (Py_ssize_t)amount);
}

#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static int
bridge_publish_bootstrap_authorities(PyObject *module, PyObject *native_anchor)
{
    PlamenBridgeCapabilityObject *js_authority = NULL;
    PlamenBridgeCapabilityObject *managed_authority = NULL;

    if (bridge_js_session != NULL) {
        js_authority = bridge_new(&JSDependencyMaterializerAuthorityType,
                                  PLAMEN_BRIDGE_JS_AUTHORITY,
                                  native_anchor, native_anchor, NULL, NULL);
        if (js_authority == NULL) {
            return -1;
        }
        js_authority->specialized_session =
            bridge_specialized_session_retain(bridge_js_session);
    }
    if (bridge_managed_session != NULL) {
        managed_authority = bridge_new(
            &ManagedEVMToolchainInitialAuthorityType,
            PLAMEN_BRIDGE_MANAGED_INITIAL,
            native_anchor, native_anchor, NULL, NULL);
        if (managed_authority == NULL) {
            Py_XDECREF(js_authority);
            return -1;
        }
        managed_authority->specialized_session =
            bridge_specialized_session_retain(bridge_managed_session);
    }
    if (js_authority != NULL && PyModule_AddObject(module,
            "JS_DEPENDENCY_MATERIALIZER_INITIAL_AUTHORITY",
            (PyObject *)js_authority) < 0) {
        Py_DECREF(js_authority);
        Py_XDECREF(managed_authority);
        return -1;
    }
    if (managed_authority != NULL && PyModule_AddObject(module,
            "MANAGED_EVM_TOOLCHAIN_INITIAL_AUTHORITY",
            (PyObject *)managed_authority) < 0) {
        Py_DECREF(managed_authority);
        return -1;
    }
    return 0;
}
#endif

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY

static uint16_t
load_be16(const unsigned char value[2])
{
    return (uint16_t)(((uint16_t)value[0] << 8) | (uint16_t)value[1]);
}

static uint32_t
load_be32(const unsigned char value[4])
{
    return ((uint32_t)value[0] << 24) |
           ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) |
           (uint32_t)value[3];
}

static uint64_t
load_be64(const unsigned char value[8])
{
    uint64_t result = 0;
    size_t index;
    for (index = 0; index < 8; index++) {
        result = (result << 8) | (uint64_t)value[index];
    }
    return result;
}

static int64_t
monotonic_milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return ((int64_t)now.tv_sec * INT64_C(1000)) +
           ((int64_t)now.tv_nsec / INT64_C(1000000));
}

static int
wait_readable_until(int fd, int64_t deadline_ms)
{
    for (;;) {
        struct pollfd poll_fd;
        int64_t now_ms = monotonic_milliseconds();
        int remaining;
        int result;

        if (now_ms < 0 || now_ms >= deadline_ms) {
            return -1;
        }
        remaining = (int)(deadline_ms - now_ms);
        poll_fd.fd = fd;
        poll_fd.events = POLLIN;
        poll_fd.revents = 0;
        result = poll(&poll_fd, 1, remaining);
        if (result > 0) {
            if ((poll_fd.revents & (POLLERR | POLLNVAL)) != 0) {
                return -1;
            }
            if ((poll_fd.revents & (POLLIN | POLLHUP)) != 0) {
                return 0;
            }
            return -1;
        }
        if (result == 0) {
            return -1;
        }
        if (errno != EINTR) {
            return -1;
        }
    }
}

static int
read_exact_until(int fd, unsigned char *destination, size_t size,
                 int64_t deadline_ms)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t received;
        if (wait_readable_until(fd, deadline_ms) < 0) {
            return -1;
        }
        received = recv(fd, destination + offset, size - offset, 0);
        if (received > 0) {
            offset += (size_t)received;
            continue;
        }
        if (received == 0) {
            return -1;
        }
        if (errno != EINTR) {
            return -1;
        }
    }
    return 0;
}

static int
require_stream_end(int fd, int64_t deadline_ms)
{
    unsigned char extra;
    ssize_t received;
    if (wait_readable_until(fd, deadline_ms) < 0) {
        return -1;
    }
    do {
        received = recv(fd, &extra, 1, 0);
    } while (received < 0 && errno == EINTR);
    return received == 0 ? 0 : -1;
}

static int
decode_lower_hex_32(PyObject *text, unsigned char output[32])
{
    const char *value;
    Py_ssize_t size;
    Py_ssize_t index;

    if (!PyUnicode_CheckExact(text)) {
        return -1;
    }
    value = PyUnicode_AsUTF8AndSize(text, &size);
    if (value == NULL) {
        PyErr_Clear();
        return -1;
    }
    if (size != 64) {
        return -1;
    }
    for (index = 0; index < 32; index++) {
        unsigned char high = (unsigned char)value[index * 2];
        unsigned char low = (unsigned char)value[(index * 2) + 1];
        unsigned char high_value;
        unsigned char low_value;
        if (high >= '0' && high <= '9') {
            high_value = (unsigned char)(high - '0');
        } else if (high >= 'a' && high <= 'f') {
            high_value = (unsigned char)(high - 'a' + 10);
        } else {
            return -1;
        }
        if (low >= '0' && low <= '9') {
            low_value = (unsigned char)(low - '0');
        } else if (low >= 'a' && low <= 'f') {
            low_value = (unsigned char)(low - 'a' + 10);
        } else {
            return -1;
        }
        output[index] = (unsigned char)((high_value << 4) | low_value);
    }
    return 0;
}

static int
decode_attempt(PyObject *text, const char **output, Py_ssize_t *output_size)
{
    const char *value;
    Py_ssize_t size;
    Py_ssize_t index;

    if (!PyUnicode_CheckExact(text)) {
        return -1;
    }
    value = PyUnicode_AsUTF8AndSize(text, &size);
    if (value == NULL) {
        PyErr_Clear();
        return -1;
    }
    if (size < 1 || size > 128) {
        return -1;
    }
    for (index = 0; index < size; index++) {
        unsigned char character = (unsigned char)value[index];
        int valid = (character >= 'A' && character <= 'Z') ||
                    (character >= 'a' && character <= 'z') ||
                    (character >= '0' && character <= '9') ||
                    (index > 0 && (character == '_' || character == '.' ||
                                   character == ':' || character == '-'));
        if (!valid) {
            return -1;
        }
    }
    *output = value;
    *output_size = size;
    return 0;
}

static int
socket_is_local_stream(int fd)
{
    int socket_type = 0;
    socklen_t type_size = (socklen_t)sizeof(socket_type);
    struct sockaddr_storage address;
    socklen_t address_size = (socklen_t)sizeof(address);

    memset(&address, 0, sizeof(address));
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &type_size) != 0 ||
        socket_type != SOCK_STREAM ||
        getsockname(fd, (struct sockaddr *)&address, &address_size) != 0 ||
        address.ss_family != AF_UNIX) {
        return 0;
    }
    return 1;
}

static int
duplicate_cloexec_fd(int fd)
{
#ifdef F_DUPFD_CLOEXEC
    return fcntl(fd, F_DUPFD_CLOEXEC, 64);
#else
    int duplicate = fcntl(fd, F_DUPFD, 64);
    if (duplicate >= 0 && fcntl(duplicate, F_SETFD, FD_CLOEXEC) != 0) {
        int saved_errno = errno;
        close(duplicate);
        errno = saved_errno;
        return -1;
    }
    return duplicate;
#endif
}

static int
validate_test_frame(NativeAuthorityConsumerObject *self)
{
    PlamenNativeSessionV1 session;
    PlamenNativeFrameV1 frame;
    unsigned char payload[PLAMEN_PROTOCOL_MAX_PAYLOAD];
    uint32_t payload_size;
    int64_t now_ms = monotonic_milliseconds();
    int64_t deadline_ms;

    if (now_ms < 0 || now_ms > INT64_MAX - PLAMEN_IO_DEADLINE_MS) {
        return -1;
    }
    deadline_ms = now_ms + PLAMEN_IO_DEADLINE_MS;
    if (read_exact_until(self->session_fd, (unsigned char *)&session,
                         sizeof(session), deadline_ms) < 0 ||
        memcmp(session.magic, PLAMEN_SESSION_MAGIC,
               sizeof(PLAMEN_SESSION_MAGIC)) != 0 ||
        load_be16(session.version_be) != PLAMEN_PROTOCOL_VERSION ||
        load_be16(session.header_size_be) != sizeof(session) ||
        memcmp(session.session_id, self->expected_session_id, 32) != 0 ||
        load_be32(session.reserved_be) != 0) {
        return -1;
    }
    if (read_exact_until(self->session_fd, (unsigned char *)&frame,
                         sizeof(frame), deadline_ms) < 0 ||
        memcmp(frame.magic, PLAMEN_FRAME_MAGIC,
               sizeof(PLAMEN_FRAME_MAGIC)) != 0 ||
        load_be16(frame.version_be) != PLAMEN_PROTOCOL_VERSION ||
        load_be16(frame.frame_type_be) != 1U ||
        load_be32(frame.header_size_be) != sizeof(frame) ||
        load_be64(frame.sequence_be) != PLAMEN_PROTOCOL_FIRST_SEQUENCE ||
        memcmp(frame.session_id, self->expected_session_id, 32) != 0 ||
        memcmp(frame.request_fingerprint, self->expected_fingerprint, 32) != 0) {
        return -1;
    }
    payload_size = load_be32(frame.payload_size_be);
    if (payload_size == 0 || payload_size > PLAMEN_PROTOCOL_MAX_PAYLOAD ||
        payload_size != (uint32_t)self->expected_attempt_len) {
        return -1;
    }
    if (read_exact_until(self->session_fd, payload, payload_size,
                         deadline_ms) < 0 ||
        memcmp(payload, self->expected_attempt, payload_size) != 0 ||
        require_stream_end(self->session_fd, deadline_ms) < 0) {
        return -1;
    }
    return 0;
}

static PyObject *
test_consume_once(PyObject *object, PyObject *args)
{
    NativeAuthorityConsumerObject *self =
        (NativeAuthorityConsumerObject *)object;
    PyObject *fingerprint_object;
    PyObject *attempt_object;
    unsigned char supplied_fingerprint[32];
    const char *supplied_attempt;
    Py_ssize_t supplied_attempt_len;
    int frame_result;

    /* Burn before parsing, identity checks, FD I/O, or any comparison. */
    if (burn_consumer(self) < 0) {
        return NULL;
    }
    if (getpid() != self->creator_pid) {
        close_session_fd(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority consumer cannot cross a process boundary");
        return NULL;
    }
    if (current_interpreter_id() != self->creator_interpreter_id) {
        close_session_fd(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority consumer cannot cross an interpreter boundary");
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "OO:consume_once", &fingerprint_object,
                          &attempt_object)) {
        PyErr_Clear();
        close_session_fd(self);
        PyErr_SetString(PyExc_TypeError,
                        "consume_once requires canonical fingerprint and attempt IDs");
        return NULL;
    }
    if (decode_lower_hex_32(fingerprint_object, supplied_fingerprint) < 0 ||
        decode_attempt(attempt_object, &supplied_attempt,
                       &supplied_attempt_len) < 0) {
        close_session_fd(self);
        PyErr_SetString(PyExc_ValueError,
                        "consume_once binding is not canonical");
        return NULL;
    }
    if (memcmp(supplied_fingerprint, self->expected_fingerprint, 32) != 0 ||
        supplied_attempt_len != self->expected_attempt_len ||
        memcmp(supplied_attempt, self->expected_attempt,
               (size_t)supplied_attempt_len) != 0) {
        close_session_fd(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority consumer binding mismatch");
        return NULL;
    }

    frame_result = validate_test_frame(self);
    close_session_fd(self);
    if (frame_result < 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority session frame is invalid");
        return NULL;
    }
    return Py_BuildValue("(sKK)", "TEST_ONLY_CONSUMED",
                         (unsigned long long)PLAMEN_PROTOCOL_VERSION,
                         (unsigned long long)PLAMEN_PROTOCOL_FIRST_SEQUENCE);
}

static PyObject *
test_only_fileno(PyObject *object, PyObject *Py_UNUSED(ignored))
{
    NativeAuthorityConsumerObject *self =
        (NativeAuthorityConsumerObject *)object;
    return PyLong_FromLong((long)self->session_fd);
}

static PyMethodDef test_consumer_methods[] = {
    {"consume_once", test_consume_once, METH_VARARGS,
     PyDoc_STR("Exercise the one-shot parser in a TEST_ONLY build.")},
    {"TEST_ONLY_fileno", test_only_fileno, METH_NOARGS,
     PyDoc_STR("Return the retained descriptor for TEST_ONLY assertions.")},
    {"__copy__", consumer_forbidden_copy, METH_NOARGS, NULL},
    {"__deepcopy__", consumer_forbidden_deepcopy, METH_VARARGS, NULL},
    {"__reduce__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__reduce_ex__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__getnewargs__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyTypeObject TestOnlyNativeAuthorityConsumerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PLAMEN_TEST_TYPE_NAME,
    .tp_basicsize = sizeof(NativeAuthorityConsumerObject),
    .tp_dealloc = consumer_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION,
    .tp_doc = PyDoc_STR("Distinct non-production parser test consumer."),
    .tp_methods = test_consumer_methods,
    .tp_new = consumer_forbidden_new,
};

static PyObject *
test_only_create_consumer(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {
        "socket_fd", "fingerprint_sha256", "attempt_id", "session_id_hex",
        "creator_pid_override", "creator_interpreter_id_override", NULL
    };
    int socket_fd;
    PyObject *fingerprint_object;
    PyObject *attempt_object;
    PyObject *session_object;
    long long creator_pid_override = -1;
    long long creator_interpreter_override = -1;
    unsigned char fingerprint[32];
    unsigned char session_id[32];
    const char *attempt;
    Py_ssize_t attempt_len;
    int owned_fd;
    NativeAuthorityConsumerObject *consumer;

    (void)module;
    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "iOOO|LL:TEST_ONLY_create_consumer", keywords,
            &socket_fd, &fingerprint_object, &attempt_object, &session_object,
            &creator_pid_override, &creator_interpreter_override)) {
        return NULL;
    }
    if (decode_lower_hex_32(fingerprint_object, fingerprint) < 0 ||
        decode_lower_hex_32(session_object, session_id) < 0 ||
        decode_attempt(attempt_object, &attempt, &attempt_len) < 0) {
        PyErr_SetString(PyExc_ValueError,
                        "TEST_ONLY consumer binding is not canonical");
        return NULL;
    }
    if (!socket_is_local_stream(socket_fd)) {
        PyErr_SetString(PyExc_ValueError,
                        "TEST_ONLY consumer requires an AF_UNIX stream socket");
        return NULL;
    }
    owned_fd = duplicate_cloexec_fd(socket_fd);
    if (owned_fd < 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "TEST_ONLY consumer could not retain its socket");
        return NULL;
    }
    consumer = PyObject_New(NativeAuthorityConsumerObject,
                            &TestOnlyNativeAuthorityConsumerType);
    if (consumer == NULL) {
        close(owned_fd);
        return NULL;
    }
    consumer->creator_pid = creator_pid_override >= 0
                                ? (pid_t)creator_pid_override
                                : getpid();
    consumer->creator_interpreter_id = creator_interpreter_override >= 0
                                           ? (int64_t)creator_interpreter_override
                                           : current_interpreter_id();
    atomic_init(&consumer->consumed, 0);
    consumer->session_fd = owned_fd;
    memcpy(consumer->expected_fingerprint, fingerprint, 32);
    memcpy(consumer->expected_session_id, session_id, 32);
    memcpy(consumer->expected_attempt, attempt, (size_t)attempt_len);
    consumer->expected_attempt[attempt_len] = '\0';
    consumer->expected_attempt_len = attempt_len;
    return (PyObject *)consumer;
}

#endif /* PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY: legacy v1 seam */

typedef struct {
    uint32_t state[8];
    uint64_t bits;
    unsigned char block[64];
    size_t used;
} V2Sha256;

typedef struct {
    unsigned char header[PLAMEN_BROKER_V2_HEADER_SIZE];
    unsigned char *payload;
    size_t payload_size;
    int fds[PLAMEN_BROKER_V2_MAX_FDS];
    size_t fd_count;
} V2ReceivedFrame;

static int64_t
v2_monotonic_milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return ((int64_t)now.tv_sec * INT64_C(1000)) +
           ((int64_t)now.tv_nsec / INT64_C(1000000));
}

static int
v2_wait_readable_until(int fd, int64_t deadline_ms)
{
    for (;;) {
        struct pollfd poll_fd;
        int64_t now_ms = v2_monotonic_milliseconds();
        int remaining;
        int result;

        if (now_ms < 0 || now_ms >= deadline_ms) {
            return -1;
        }
        remaining = (int)(deadline_ms - now_ms);
        poll_fd.fd = fd;
        poll_fd.events = POLLIN;
        poll_fd.revents = 0;
        result = poll(&poll_fd, 1, remaining);
        if (result > 0) {
            if ((poll_fd.revents & (POLLERR | POLLNVAL)) != 0) {
                return -1;
            }
            return (poll_fd.revents & (POLLIN | POLLHUP)) != 0 ? 0 : -1;
        }
        if (result == 0 || errno != EINTR) {
            return -1;
        }
    }
}

static int
v2_wait_writable_until(int fd, int64_t deadline_ms)
{
    for (;;) {
        struct pollfd poll_fd;
        int64_t now_ms = v2_monotonic_milliseconds();
        int remaining;
        int result;

        if (now_ms < 0 || now_ms >= deadline_ms) {
            return -1;
        }
        remaining = (int)(deadline_ms - now_ms);
        poll_fd.fd = fd;
        poll_fd.events = POLLOUT;
        poll_fd.revents = 0;
        result = poll(&poll_fd, 1, remaining);
        if (result > 0) {
            if ((poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                return -1;
            }
            return (poll_fd.revents & POLLOUT) != 0 ? 0 : -1;
        }
        if (result == 0 || errno != EINTR) {
            return -1;
        }
    }
}

static int
v2_decode_lower_hex_32(PyObject *text, unsigned char output[32])
{
    const char *value;
    Py_ssize_t size;
    Py_ssize_t index;

    if (!PyUnicode_CheckExact(text)) {
        return -1;
    }
    value = PyUnicode_AsUTF8AndSize(text, &size);
    if (value == NULL) {
        PyErr_Clear();
        return -1;
    }
    if (size != 64) {
        return -1;
    }
    for (index = 0; index < 32; index++) {
        unsigned char high = (unsigned char)value[index * 2];
        unsigned char low = (unsigned char)value[(index * 2) + 1];
        unsigned char high_value;
        unsigned char low_value;
        if (high >= '0' && high <= '9') {
            high_value = (unsigned char)(high - '0');
        } else if (high >= 'a' && high <= 'f') {
            high_value = (unsigned char)(high - 'a' + 10);
        } else {
            return -1;
        }
        if (low >= '0' && low <= '9') {
            low_value = (unsigned char)(low - '0');
        } else if (low >= 'a' && low <= 'f') {
            low_value = (unsigned char)(low - 'a' + 10);
        } else {
            return -1;
        }
        output[index] = (unsigned char)((high_value << 4) | low_value);
    }
    return 0;
}

static int
v2_decode_id(PyObject *text, const char **output, Py_ssize_t *output_size)
{
    const char *value;
    Py_ssize_t size;
    Py_ssize_t index;

    if (!PyUnicode_CheckExact(text)) {
        return -1;
    }
    value = PyUnicode_AsUTF8AndSize(text, &size);
    if (value == NULL) {
        PyErr_Clear();
        return -1;
    }
    if (size < 1 || size > PLAMEN_BROKER_V2_MAX_ID) {
        return -1;
    }
    for (index = 0; index < size; index++) {
        unsigned char character = (unsigned char)value[index];
        int valid = (character >= 'A' && character <= 'Z') ||
                    (character >= 'a' && character <= 'z') ||
                    (character >= '0' && character <= '9') ||
                    character == '_' || character == '.' ||
                    character == ':' || character == '-';
        if (!valid) {
            return -1;
        }
    }
    *output = value;
    *output_size = size;
    return 0;
}

static uint32_t
v2_rotr32(uint32_t value, unsigned int amount)
{
    return (value >> amount) | (value << (32U - amount));
}

static void
v2_sha256_transform(V2Sha256 *context, const unsigned char block[64])
{
    static const uint32_t constants[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,
        0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,
        0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,
        0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,
        0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,
        0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,
        0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,
        0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,
        0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
    };
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned int index;

    for (index = 0; index < 16; index++) {
        words[index] = ((uint32_t)block[index * 4] << 24) |
                       ((uint32_t)block[index * 4 + 1] << 16) |
                       ((uint32_t)block[index * 4 + 2] << 8) |
                       (uint32_t)block[index * 4 + 3];
    }
    for (index = 16; index < 64; index++) {
        uint32_t s0 = v2_rotr32(words[index - 15], 7) ^
                      v2_rotr32(words[index - 15], 18) ^
                      (words[index - 15] >> 3);
        uint32_t s1 = v2_rotr32(words[index - 2], 17) ^
                      v2_rotr32(words[index - 2], 19) ^
                      (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    a=context->state[0]; b=context->state[1]; c=context->state[2];
    d=context->state[3]; e=context->state[4]; f=context->state[5];
    g=context->state[6]; h=context->state[7];
    for (index = 0; index < 64; index++) {
        uint32_t s1=v2_rotr32(e,6)^v2_rotr32(e,11)^v2_rotr32(e,25);
        uint32_t choice=(e&f)^((~e)&g);
        uint32_t t1=h+s1+choice+constants[index]+words[index];
        uint32_t s0=v2_rotr32(a,2)^v2_rotr32(a,13)^v2_rotr32(a,22);
        uint32_t majority=(a&b)^(a&c)^(b&c);
        uint32_t t2=s0+majority;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    context->state[0]+=a; context->state[1]+=b;
    context->state[2]+=c; context->state[3]+=d;
    context->state[4]+=e; context->state[5]+=f;
    context->state[6]+=g; context->state[7]+=h;
    secure_zero(words, sizeof(words));
}

static void
v2_sha256_init(V2Sha256 *context)
{
    static const uint32_t initial[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    memcpy(context->state, initial, sizeof(initial));
    context->bits = 0;
    context->used = 0;
}

static void
v2_sha256_update(V2Sha256 *context, const void *raw, size_t size)
{
    const unsigned char *data = (const unsigned char *)raw;
    context->bits += (uint64_t)size * UINT64_C(8);
    while (size != 0) {
        size_t room = 64U - context->used;
        size_t take = size < room ? size : room;
        memcpy(context->block + context->used, data, take);
        context->used += take;
        data += take;
        size -= take;
        if (context->used == 64U) {
            v2_sha256_transform(context, context->block);
            context->used = 0;
        }
    }
}

static void
v2_sha256_final(V2Sha256 *context, unsigned char digest[32])
{
    uint64_t bits = context->bits;
    unsigned int index;
    context->block[context->used++] = 0x80U;
    if (context->used > 56U) {
        memset(context->block + context->used, 0, 64U - context->used);
        v2_sha256_transform(context, context->block);
        context->used = 0;
    }
    memset(context->block + context->used, 0, 56U - context->used);
    for (index = 0; index < 8; index++) {
        context->block[63U - index] =
            (unsigned char)(bits >> (index * 8U));
    }
    v2_sha256_transform(context, context->block);
    for (index = 0; index < 8; index++) {
        digest[index*4]=(unsigned char)(context->state[index]>>24);
        digest[index*4+1]=(unsigned char)(context->state[index]>>16);
        digest[index*4+2]=(unsigned char)(context->state[index]>>8);
        digest[index*4+3]=(unsigned char)context->state[index];
    }
    secure_zero(context, sizeof(*context));
}

static void
v2_sha256_bytes(const void *data, size_t size, unsigned char digest[32])
{
    V2Sha256 context;
    v2_sha256_init(&context);
    v2_sha256_update(&context, data, size);
    v2_sha256_final(&context, digest);
}

static void
v2_hmac_sha256(const unsigned char key[32],
               const unsigned char header[PLAMEN_BROKER_V2_HEADER_SIZE],
               const unsigned char *payload, size_t payload_size,
               unsigned char digest[32])
{
    unsigned char inner_key[64], outer_key[64], inner_digest[32];
    V2Sha256 context;
    size_t index;
    memset(inner_key, 0x36, sizeof(inner_key));
    memset(outer_key, 0x5c, sizeof(outer_key));
    for (index = 0; index < 32; index++) {
        inner_key[index] ^= key[index];
        outer_key[index] ^= key[index];
    }
    v2_sha256_init(&context);
    v2_sha256_update(&context, inner_key, sizeof(inner_key));
    v2_sha256_update(&context, header, PLAMEN_BROKER_V2_AUTH_OFFSET);
    v2_sha256_update(&context, payload, payload_size);
    v2_sha256_final(&context, inner_digest);
    v2_sha256_init(&context);
    v2_sha256_update(&context, outer_key, sizeof(outer_key));
    v2_sha256_update(&context, inner_digest, sizeof(inner_digest));
    v2_sha256_final(&context, digest);
    secure_zero(inner_key, sizeof(inner_key));
    secure_zero(outer_key, sizeof(outer_key));
    secure_zero(inner_digest, sizeof(inner_digest));
}

static int
v2_constant_equal(const unsigned char *left, const unsigned char *right,
                  size_t size)
{
    unsigned char difference = 0;
    size_t index;
    for (index = 0; index < size; index++) {
        difference |= (unsigned char)(left[index] ^ right[index]);
    }
    return difference == 0;
}

static void
v2_put_u16(unsigned char *output, uint16_t value)
{
    output[0] = (unsigned char)(value >> 8);
    output[1] = (unsigned char)value;
}

static void
v2_put_u32(unsigned char *output, uint32_t value)
{
    output[0]=(unsigned char)(value>>24);
    output[1]=(unsigned char)(value>>16);
    output[2]=(unsigned char)(value>>8);
    output[3]=(unsigned char)value;
}

static void
v2_put_u64(unsigned char *output, uint64_t value)
{
    v2_put_u32(output, (uint32_t)(value >> 32));
    v2_put_u32(output + 4, (uint32_t)value);
}

static uint16_t
v2_get_u16(const unsigned char *input)
{
    return (uint16_t)(((uint16_t)input[0] << 8) | (uint16_t)input[1]);
}

static uint32_t
v2_get_u32(const unsigned char *input)
{
    return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] << 8) | (uint32_t)input[3];
}

static uint64_t
v2_get_u64(const unsigned char *input)
{
    return ((uint64_t)v2_get_u32(input) << 32) | v2_get_u32(input + 4);
}

static int
v2_random(unsigned char *output, size_t size)
{
#ifdef __APPLE__
    arc4random_buf(output, size);
    return 0;
#else
    while (size != 0) {
        ssize_t amount = getrandom(output, size, 0);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return -1;
        }
        output += (size_t)amount;
        size -= (size_t)amount;
    }
    return 0;
#endif
}

static void
v2_close_fds(int *fds, size_t count)
{
    size_t index;
    for (index = 0; index < count; index++) {
        if (fds[index] >= 0) {
            (void)close(fds[index]);
            fds[index] = -1;
        }
    }
}

static int
v2_set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0 ? 0 : -1;
}

static int
v2_recv_exact_no_rights(int fd, unsigned char *output, size_t size,
                        int64_t deadline_ms)
{
    size_t offset = 0;
    while (offset < size) {
        struct iovec iov;
        struct msghdr message;
        union {
            struct cmsghdr alignment;
            unsigned char bytes[CMSG_SPACE(sizeof(int) * PLAMEN_BROKER_V2_MAX_FDS)];
        } ancillary;
        ssize_t amount;
        memset(&message, 0, sizeof(message));
        memset(&ancillary, 0, sizeof(ancillary));
        iov.iov_base = output + offset;
        iov.iov_len = size - offset;
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.bytes;
        message.msg_controllen = sizeof(ancillary.bytes);
        if (v2_wait_readable_until(fd, deadline_ms) < 0) {
            return -1;
        }
        do {
            amount = recvmsg(fd, &message, 0);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
                CMSG_FIRSTHDR(&message) != NULL) {
            struct cmsghdr *header;
            for (header = CMSG_FIRSTHDR(&message); header != NULL;
                    header = CMSG_NXTHDR(&message, header)) {
                if (header->cmsg_level == SOL_SOCKET &&
                        header->cmsg_type == SCM_RIGHTS &&
                        header->cmsg_len >= CMSG_LEN(0)) {
                    size_t bytes = header->cmsg_len - CMSG_LEN(0);
                    size_t count = bytes / sizeof(int);
                    int *received = (int *)CMSG_DATA(header);
                    v2_close_fds(received, count);
                }
            }
            return -1;
        }
        offset += (size_t)amount;
    }
    return 0;
}

static void
v2_received_clear(V2ReceivedFrame *frame)
{
    v2_close_fds(frame->fds, frame->fd_count);
    frame->fd_count = 0;
    if (frame->payload != NULL) {
        secure_zero(frame->payload, frame->payload_size);
        free(frame->payload);
        frame->payload = NULL;
    }
    frame->payload_size = 0;
    secure_zero(frame->header, sizeof(frame->header));
}

static int
v2_receive_frame_with_deadline(int fd, V2ReceivedFrame *frame,
                               int64_t timeout_ms)
{
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr *header;
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int) * PLAMEN_BROKER_V2_MAX_FDS)];
    } ancillary;
    ssize_t amount;
    size_t count = 0, header_offset = 0;
    uint32_t payload_size;
    int64_t now_ms = v2_monotonic_milliseconds();
    int64_t deadline_ms;

    memset(frame, 0, sizeof(*frame));
    memset(frame->fds, -1, sizeof(frame->fds));
    memset(&message, 0, sizeof(message));
    memset(&ancillary, 0, sizeof(ancillary));
    iov.iov_base = frame->header;
    iov.iov_len = sizeof(frame->header);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes;
    message.msg_controllen = sizeof(ancillary.bytes);
    if (timeout_ms <= 0 || now_ms < 0 ||
            now_ms > INT64_MAX - timeout_ms) {
        return -1;
    }
    deadline_ms = now_ms + timeout_ms;
    if (v2_wait_readable_until(fd, deadline_ms) < 0) {
        return -1;
    }
    do {
        amount = recvmsg(fd, &message,
#ifdef MSG_CMSG_CLOEXEC
                         MSG_CMSG_CLOEXEC
#else
                         0
#endif
        );
    } while (amount < 0 && errno == EINTR);
    for (header = CMSG_FIRSTHDR(&message); header != NULL;
            header = CMSG_NXTHDR(&message, header)) {
        size_t bytes;
        size_t received_count;
        if (header->cmsg_level != SOL_SOCKET ||
                header->cmsg_type != SCM_RIGHTS ||
                header->cmsg_len < CMSG_LEN(0)) {
            v2_close_fds(frame->fds, count);
            return -1;
        }
        bytes = header->cmsg_len - CMSG_LEN(0);
        if (bytes % sizeof(int) != 0) {
            v2_close_fds(frame->fds, count);
            return -1;
        }
        received_count = bytes / sizeof(int);
        if (received_count > PLAMEN_BROKER_V2_MAX_FDS - count) {
            v2_close_fds((int *)CMSG_DATA(header), received_count);
            v2_close_fds(frame->fds, count);
            return -1;
        }
        memcpy(frame->fds + count, CMSG_DATA(header), bytes);
        count += received_count;
        frame->fd_count = count;
        while (received_count != 0) {
            size_t descriptor_index = count - received_count;
            if (v2_set_cloexec(frame->fds[descriptor_index]) < 0) {
                v2_received_clear(frame);
                return -1;
            }
            received_count--;
        }
    }
    frame->fd_count = count;
    if (amount <= 0 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
        v2_received_clear(frame);
        return -1;
    }
    header_offset = (size_t)amount;
    if (header_offset > sizeof(frame->header) ||
            (header_offset < sizeof(frame->header) &&
             v2_recv_exact_no_rights(fd, frame->header + header_offset,
                                     sizeof(frame->header) - header_offset,
                                     deadline_ms) < 0)) {
        v2_received_clear(frame);
        return -1;
    }
    payload_size = v2_get_u32(frame->header + 20);
    if (payload_size > PLAMEN_BROKER_V2_MAX_PAYLOAD) {
        v2_received_clear(frame);
        return -1;
    }
    frame->payload_size = payload_size;
    if (payload_size != 0) {
        frame->payload = (unsigned char *)malloc(payload_size);
        if (frame->payload == NULL ||
                v2_recv_exact_no_rights(fd, frame->payload, payload_size,
                                        deadline_ms) < 0) {
            v2_received_clear(frame);
            return -1;
        }
    }
    return 0;
}

static int
v2_receive_frame(int fd, V2ReceivedFrame *frame)
{
    return v2_receive_frame_with_deadline(
        fd, frame, (int64_t)PLAMEN_IO_DEADLINE_MS);
}

static int
v2_fd_roster_valid(const V2ReceivedFrame *frame)
{
    size_t left, right;
    for (left = 0; left < frame->fd_count; left++) {
        struct stat left_info;
        if (fstat(frame->fds[left], &left_info) != 0) {
            return 0;
        }
        for (right = left + 1; right < frame->fd_count; right++) {
            struct stat right_info;
            if (fstat(frame->fds[right], &right_info) != 0 ||
                    (left_info.st_dev == right_info.st_dev &&
                     left_info.st_ino == right_info.st_ino &&
                     left_info.st_rdev == right_info.st_rdev)) {
                return 0;
            }
        }
    }
    return 1;
}

static int
v2_validate_frame(const V2ReceivedFrame *frame, uint16_t expected_type,
                  uint64_t expected_sequence,
                  const unsigned char expected_session[32],
                  const unsigned char expected_nonce[32],
                  const unsigned char expected_previous[32],
                  const unsigned char key[32])
{
    unsigned char digest[32], tag[32];
    int valid;
    v2_sha256_bytes(frame->payload, frame->payload_size, digest);
    v2_hmac_sha256(key, frame->header, frame->payload,
                   frame->payload_size, tag);
    valid = memcmp(frame->header, PLAMEN_BROKER_V2_MAGIC, 8) == 0 &&
        v2_get_u16(frame->header + 8) == PLAMEN_BROKER_V2_VERSION &&
        v2_get_u16(frame->header + 10) == expected_type &&
        v2_get_u32(frame->header + 12) == 0 &&
        v2_get_u32(frame->header + 16) == PLAMEN_BROKER_V2_HEADER_SIZE &&
        v2_get_u32(frame->header + 20) == frame->payload_size &&
        v2_get_u16(frame->header + 24) == frame->fd_count &&
        frame->fd_count <= PLAMEN_BROKER_V2_MAX_FDS &&
        v2_get_u16(frame->header + 26) == 0 &&
        v2_get_u64(frame->header + 28) == expected_sequence &&
        v2_constant_equal(frame->header + 36, expected_session, 32) &&
        v2_constant_equal(frame->header + 68, expected_nonce, 32) &&
        v2_constant_equal(frame->header + 100, expected_previous, 32) &&
        v2_constant_equal(frame->header + 132, digest, 32) &&
        v2_constant_equal(frame->header + 164, tag, 32) &&
        v2_fd_roster_valid(frame);
    secure_zero(digest, sizeof(digest));
    secure_zero(tag, sizeof(tag));
    return valid;
}

static void
v2_frame_digest(const V2ReceivedFrame *frame, unsigned char digest[32])
{
    V2Sha256 context;
    v2_sha256_init(&context);
    v2_sha256_update(&context, frame->header, sizeof(frame->header));
    v2_sha256_update(&context, frame->payload, frame->payload_size);
    v2_sha256_final(&context, digest);
}

static int
v2_build_frame(unsigned char **output, size_t *output_size,
               uint16_t type, uint64_t sequence, uint16_t declared_fds,
               const unsigned char session[32],
               const unsigned char nonce[32],
               const unsigned char previous[32],
               const unsigned char key[32],
               const unsigned char *payload, size_t payload_size)
{
    unsigned char *frame;
    unsigned char digest[32], tag[32];

    if (payload_size > PLAMEN_BROKER_V2_MAX_PAYLOAD ||
            (payload_size != 0 && payload == NULL)) {
        return -1;
    }
    frame = (unsigned char *)calloc(
        1, PLAMEN_BROKER_V2_HEADER_SIZE + payload_size);
    if (frame == NULL) {
        return -1;
    }
    memcpy(frame, PLAMEN_BROKER_V2_MAGIC, 8);
    v2_put_u16(frame + 8, PLAMEN_BROKER_V2_VERSION);
    v2_put_u16(frame + 10, type);
    v2_put_u32(frame + 12, 0);
    v2_put_u32(frame + 16, PLAMEN_BROKER_V2_HEADER_SIZE);
    v2_put_u32(frame + 20, (uint32_t)payload_size);
    v2_put_u16(frame + 24, declared_fds);
    v2_put_u16(frame + 26, 0);
    v2_put_u64(frame + 28, sequence);
    memcpy(frame + 36, session, 32);
    memcpy(frame + 68, nonce, 32);
    memcpy(frame + 100, previous, 32);
    v2_sha256_bytes(payload, payload_size, digest);
    memcpy(frame + 132, digest, 32);
    v2_hmac_sha256(key, frame, payload, payload_size, tag);
    memcpy(frame + 164, tag, 32);
    if (payload_size != 0) {
        memcpy(frame + PLAMEN_BROKER_V2_HEADER_SIZE, payload, payload_size);
    }
    secure_zero(digest, sizeof(digest));
    secure_zero(tag, sizeof(tag));
    *output = frame;
    *output_size = PLAMEN_BROKER_V2_HEADER_SIZE + payload_size;
    return 0;
}

static int
v2_send_all(int fd, const unsigned char *data, size_t size)
{
    size_t offset = 0;
    int64_t now_ms = v2_monotonic_milliseconds();
    int64_t deadline_ms;

    if (now_ms < 0 || now_ms > INT64_MAX - PLAMEN_IO_DEADLINE_MS) {
        return -1;
    }
    deadline_ms = now_ms + PLAMEN_IO_DEADLINE_MS;
    while (offset < size) {
        ssize_t amount;
#ifdef MSG_NOSIGNAL
        int flags = MSG_NOSIGNAL | MSG_DONTWAIT;
#else
        int flags = MSG_DONTWAIT;
#endif
        if (v2_wait_writable_until(fd, deadline_ms) < 0) {
            return -1;
        }
        amount = send(fd, data + offset, size - offset, flags);
        if (amount < 0 && (errno == EINTR || errno == EAGAIN ||
                           errno == EWOULDBLOCK)) {
            continue;
        }
        if (amount <= 0) {
            return -1;
        }
        offset += (size_t)amount;
    }
    return 0;
}

#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static int
bridge_send_frame_with_fds(int fd, const unsigned char *frame,
                           size_t frame_size, const int *fds,
                           size_t fd_count)
{
    struct iovec iov;
    struct msghdr message;
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(
            sizeof(int) * PLAMEN_BROKER_V2_MAX_FDS)];
    } ancillary;
    struct cmsghdr *header;
    ssize_t amount;
    int64_t now_ms, deadline_ms;

    if (fd < 0 || frame == NULL || frame_size == 0 ||
            fd_count > PLAMEN_BROKER_V2_MAX_FDS ||
            (fd_count != 0 && fds == NULL)) {
        return -1;
    }
    if (fd_count == 0) {
        return v2_send_all(fd, frame, frame_size);
    }
    now_ms = v2_monotonic_milliseconds();
    if (now_ms < 0 || now_ms > INT64_MAX - PLAMEN_IO_DEADLINE_MS) {
        return -1;
    }
    deadline_ms = now_ms + PLAMEN_IO_DEADLINE_MS;
    memset(&message, 0, sizeof(message));
    memset(&ancillary, 0, sizeof(ancillary));
    iov.iov_base = (void *)frame;
    iov.iov_len = frame_size;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes;
    message.msg_controllen = CMSG_SPACE(sizeof(int) * fd_count);
    header = CMSG_FIRSTHDR(&message);
    if (header == NULL) {
        return -1;
    }
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);
    memcpy(CMSG_DATA(header), fds, sizeof(int) * fd_count);
    if (v2_wait_writable_until(fd, deadline_ms) < 0) {
        return -1;
    }
    do {
        amount = sendmsg(fd, &message,
#ifdef MSG_NOSIGNAL
                         MSG_NOSIGNAL | MSG_DONTWAIT
#else
                         MSG_DONTWAIT
#endif
        );
    } while (amount < 0 && errno == EINTR);
    if (amount <= 0 || (size_t)amount > frame_size) {
        return -1;
    }
    return (size_t)amount == frame_size ? 0 :
        v2_send_all(fd, frame + (size_t)amount,
                    frame_size - (size_t)amount);
}

static void
bridge_specialized_session_burn_locked(BridgeSpecializedSession *session)
{
    if (session->control_fd >= 0) {
        (void)close(session->control_fd);
        session->control_fd = -1;
    }
    secure_zero(session->key, sizeof(session->key));
    secure_zero(session->session_id, sizeof(session->session_id));
    secure_zero(session->authority_binding_sha256,
                sizeof(session->authority_binding_sha256));
    secure_zero(session->previous_frame_sha256,
                sizeof(session->previous_frame_sha256));
    session->next_sequence = 0;
}

static PyObject *
bridge_specialized_rpc(
        BridgeSpecializedSession *session,
        const unsigned char capability_id[32], uint16_t method,
        uint16_t flags, PyObject *payload_object,
        const struct plamen_broker_v2_fd_metadata *descriptors,
        const int *fds, size_t fd_count, uint16_t expected_disposition,
        unsigned char issued_capability_id[32], int64_t timeout_ms)
{
    struct plamen_broker_v2_specialized_request request;
    struct plamen_broker_v2_specialized_response response;
    V2ReceivedFrame received;
    const unsigned char *payload;
    Py_ssize_t payload_size;
    unsigned char *encoded = NULL, *frame = NULL;
    unsigned char request_sha256[32] = {0};
    unsigned char frame_sha256[32] = {0};
    unsigned char response_frame_sha256[32] = {0};
    size_t encoded_size = 0, frame_size = 0, capacity, index;
    uint64_t request_sequence;
    int acquired = 0, io_status = -1, failure = 0;
    PyObject *result = NULL;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&received, 0, sizeof(received));
    for (index = 0; index < PLAMEN_BROKER_V2_MAX_FDS; index++) {
        received.fds[index] = -1;
    }
    if (issued_capability_id != NULL) {
        memset(issued_capability_id, 0, 32);
    }
    if (session == NULL || capability_id == NULL ||
            !PyBytes_CheckExact(payload_object) ||
            PyBytes_AsStringAndSize(payload_object, (char **)&payload,
                                    &payload_size) < 0 ||
            payload_size <= 0 ||
            (uint64_t)payload_size >
                PLAMEN_BROKER_V2_SPECIALIZED_PAYLOAD_MAX ||
            fd_count > PLAMEN_BROKER_V2_MAX_FDS ||
            (fd_count != 0 && (descriptors == NULL || fds == NULL)) ||
            timeout_ms <= 0 || session->creator_pid != getpid() ||
            session->creator_interpreter_id != current_interpreter_id()) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native specialized session is unavailable");
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    acquired = PyThread_acquire_lock(session->operation_lock, WAIT_LOCK);
    Py_END_ALLOW_THREADS
    if (!acquired) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native specialized session is unavailable");
        return NULL;
    }
    if (session->control_fd < 0 ||
            session->next_sequence > UINT64_MAX - UINT64_C(2) ||
            v2_random(request.operation_nonce,
                      sizeof(request.operation_nonce)) != 0) {
        failure = 1;
        goto done;
    }
    request.lane = session->lane;
    request.method = method;
    request.flags = flags;
    memcpy(request.capability_id, capability_id, 32);
    memcpy(request.authority_binding_sha256,
           session->authority_binding_sha256, 32);
    request.fd_count = (uint16_t)fd_count;
    for (index = 0; index < fd_count; index++) {
        request.descriptors[index] = descriptors[index];
    }
    request.payload = payload;
    request.payload_size = (uint32_t)payload_size;
    capacity = PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE +
        fd_count * PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE +
        (size_t)payload_size;
    encoded = (unsigned char *)malloc(capacity);
    if (encoded == NULL) {
        PyErr_NoMemory();
        goto done;
    }
    if (plamen_broker_v2_specialized_request_encode(
            &request, encoded, capacity, &encoded_size) !=
                PLAMEN_BROKER_V2_OK || encoded_size != capacity ||
            plamen_broker_v2_sha256(encoded, encoded_size,
                                    request_sha256) !=
                PLAMEN_BROKER_V2_OK) {
        failure = 1;
        goto done;
    }
    request_sequence = session->next_sequence;
    if (v2_build_frame(&frame, &frame_size,
            PLAMEN_BROKER_V2_OPERATION_REQUEST, request_sequence,
            (uint16_t)fd_count, session->session_id,
            request.operation_nonce, session->previous_frame_sha256,
            session->key, encoded, encoded_size) != 0) {
        PyErr_NoMemory();
        goto done;
    }
    v2_sha256_bytes(frame, frame_size, frame_sha256);
    Py_BEGIN_ALLOW_THREADS
    io_status = bridge_send_frame_with_fds(
        session->control_fd, frame, frame_size, fds, fd_count);
    if (io_status == 0) {
        io_status = v2_receive_frame_with_deadline(
            session->control_fd, &received, timeout_ms);
    }
    Py_END_ALLOW_THREADS
    if (io_status != 0 || received.fd_count != 0 ||
            !v2_validate_frame(&received,
                PLAMEN_BROKER_V2_OPERATION_RESPONSE,
                request_sequence + UINT64_C(1), session->session_id,
                request.operation_nonce, frame_sha256, session->key) ||
            plamen_broker_v2_specialized_response_decode_exact(
                received.payload, received.payload_size, &response) !=
                    PLAMEN_BROKER_V2_OK ||
            response.lane != session->lane || response.method != method ||
            (expected_disposition != 0 &&
             response.disposition != expected_disposition) ||
            !v2_constant_equal(response.operation_nonce,
                               request.operation_nonce, 32) ||
            !v2_constant_equal(response.request_sha256,
                               request_sha256, 32)) {
        failure = 1;
        goto done;
    }
    if (issued_capability_id != NULL) {
        memcpy(issued_capability_id, response.capability_id, 32);
    }
    result = PyBytes_FromStringAndSize(
        (const char *)response.payload, (Py_ssize_t)response.payload_size);
    if (result == NULL) {
        goto done;
    }
    v2_frame_digest(&received, response_frame_sha256);
    memcpy(session->previous_frame_sha256, response_frame_sha256, 32);
    session->next_sequence = request_sequence + UINT64_C(2);

done:
    if (failure) {
        bridge_specialized_session_burn_locked(session);
    }
    PyThread_release_lock(session->operation_lock);
    v2_received_clear(&received);
    if (frame != NULL) {
        secure_zero(frame, frame_size);
        free(frame);
    }
    if (encoded != NULL) {
        secure_zero(encoded, encoded_size);
        free(encoded);
    }
    secure_zero(request_sha256, sizeof(request_sha256));
    secure_zero(frame_sha256, sizeof(frame_sha256));
    secure_zero(response_frame_sha256, sizeof(response_frame_sha256));
    plamen_broker_v2_secure_zero(&request, sizeof(request));
    plamen_broker_v2_secure_zero(&response, sizeof(response));
    if (result != NULL) {
        return result;
    }
    if (!PyErr_Occurred()) {
        PyErr_SetString(PyExc_RuntimeError,
                        failure ? "native specialized response authentication failed"
                                : "native specialized operation failed");
    }
    return NULL;
}
#endif

static int
v2_prepare_control_fd(int fd)
{
    int socket_type = 0;
    socklen_t socket_type_size = (socklen_t)sizeof(socket_type);
    struct sockaddr_storage address, peer_address;
    socklen_t address_size = (socklen_t)sizeof(address);
    socklen_t peer_address_size = (socklen_t)sizeof(peer_address);

    memset(&address, 0, sizeof(address));
    memset(&peer_address, 0, sizeof(peer_address));
    if (fd < 0 ||
            getsockopt(fd, SOL_SOCKET, SO_TYPE,
                       &socket_type, &socket_type_size) != 0 ||
            socket_type != SOCK_STREAM ||
            getsockname(fd, (struct sockaddr *)&address, &address_size) != 0 ||
            address.ss_family != AF_UNIX ||
            getpeername(fd, (struct sockaddr *)&peer_address,
                        &peer_address_size) != 0 ||
            peer_address.ss_family != AF_UNIX ||
            v2_set_cloexec(fd) < 0) {
        return -1;
    }
#ifdef __APPLE__
    {
        int enabled = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
                       &enabled, (socklen_t)sizeof(enabled)) != 0) {
            return -1;
        }
    }
#endif
    return 0;
}

#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY

static void
v2_shared_session_burn_locked(V2SharedNativeSession *session)
{
    if (session->control_fd >= 0) {
        (void)close(session->control_fd);
        session->control_fd = -1;
    }
    secure_zero(session->key, sizeof(session->key));
    secure_zero(session->session_id, sizeof(session->session_id));
    secure_zero(session->previous_frame_sha256,
                sizeof(session->previous_frame_sha256));
    secure_zero(session->issuance_checkpoint_sha256,
                sizeof(session->issuance_checkpoint_sha256));
    secure_zero(session->current_checkpoint_sha256,
                sizeof(session->current_checkpoint_sha256));
    plamen_broker_v2_secure_zero(&session->commitment,
                                 sizeof(session->commitment));
    session->next_sequence = 0;
}

static int
v2_operation_payload_valid(const char *payload, Py_ssize_t payload_size)
{
    Py_ssize_t index;
    if (payload == NULL || payload_size <= 0 ||
            (uint64_t)payload_size >
                (uint64_t)PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX ||
            payload[payload_size - 1] != '\n') {
        return 0;
    }
    for (index = 0; index < payload_size; index++) {
        unsigned char value = (unsigned char)payload[index];
        if (value == 0 || value > 0x7fU) {
            return 0;
        }
    }
    return 1;
}

static V2RpcReplayEntry *
v2_rpc_replay_find(V2SharedNativeSession *session, uint16_t member,
                   uint16_t method, uint16_t flags,
                   const unsigned char payload_sha256[32])
{
    size_t index;
    for (index = 0; index < session->replay_count; index++) {
        V2RpcReplayEntry *entry = &session->replay_entries[index];
        if (entry->role == session->role && entry->member == member &&
                entry->method == method && entry->flags == flags &&
                v2_constant_equal(entry->payload_sha256,
                                  payload_sha256, 32)) {
            return entry;
        }
    }
    return NULL;
}

static int
v2_rpc_replay_reserve(V2SharedNativeSession *session,
                      V2RpcReplayEntry **entry)
{
    if (session->replay_count >=
            PLAMEN_BROKER_V2_RPC_REPLAY_MAX_ENTRIES) {
        return -1;
    }
    if (session->replay_entries == NULL) {
        session->replay_entries = (V2RpcReplayEntry *)calloc(
            PLAMEN_BROKER_V2_RPC_REPLAY_MAX_ENTRIES,
            sizeof(*session->replay_entries));
        if (session->replay_entries == NULL) {
            return -2;
        }
    }
    *entry = &session->replay_entries[session->replay_count];
    memset(*entry, 0, sizeof(**entry));
    return 0;
}

static int
v2_operation_object_matches_member(const V2OpaqueCapabilityObject *self,
                                   uint16_t member)
{
    if (self->native_session->role ==
            PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR) {
        return self->kind == (unsigned int)member && member >= 1U &&
            member <= PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT;
    }
    return self->native_session->role ==
               PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER &&
        self->kind == 15U &&
        member == PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION;
}

static PyObject *
v2_operation_rpc(PyObject *object, PyObject *args, uint16_t member,
                 uint16_t method, uint16_t flags, int64_t receive_timeout_ms)
{
    V2OpaqueCapabilityObject *self = (V2OpaqueCapabilityObject *)object;
    V2SharedNativeSession *session = self->native_session;
    PyObject *payload_object;
    PyObject *result = NULL;
    const char *payload;
    Py_ssize_t payload_size;
    struct plamen_broker_v2_operation_request request;
    struct plamen_broker_v2_operation_response response;
    struct plamen_broker_v2_operation_error operation_error;
    V2RpcReplayEntry *cache_entry = NULL;
    V2ReceivedFrame received;
    unsigned char payload_sha256[32] = {0};
    unsigned char request_frame_sha256[32] = {0};
    unsigned char response_frame_sha256[32] = {0};
    unsigned char *encoded_request = NULL;
    unsigned char *request_frame = NULL;
    size_t encoded_request_size = 0, request_frame_size = 0;
    size_t request_capacity;
    size_t received_fd_index;
    uint64_t request_sequence = 0;
    uint16_t response_type = 0;
    int lock_acquired = 0, io_status = -1, known_replay = 0;
    int terminal_failure = 0, retryable_operation_error = 0;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&operation_error, 0, sizeof(operation_error));
    memset(&received, 0, sizeof(received));
    for (received_fd_index = 0;
            received_fd_index < PLAMEN_BROKER_V2_MAX_FDS;
            received_fd_index++) {
        received.fds[received_fd_index] = -1;
    }
    if (!PyTuple_Check(args) || PyTuple_GET_SIZE(args) != 1) {
        PyErr_SetString(PyExc_TypeError,
                        "native authority method requires exactly 1 positional argument");
        return NULL;
    }
    if (session == NULL || getpid() != self->creator_pid ||
            current_interpreter_id() != self->creator_interpreter_id ||
            session->creator_pid != self->creator_pid ||
            session->creator_interpreter_id !=
                self->creator_interpreter_id ||
            receive_timeout_ms <= 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority session is unavailable");
        return NULL;
    }
    payload_object = PyTuple_GET_ITEM(args, 0);
    if (!PyBytes_CheckExact(payload_object) ||
            PyBytes_AsStringAndSize(payload_object, (char **)&payload,
                                    &payload_size) < 0) {
        PyErr_Clear();
        PyErr_SetString(PyExc_TypeError,
                        "native authority request must be exact bytes");
        return NULL;
    }
    if (!v2_operation_payload_valid(payload, payload_size)) {
        PyErr_SetString(PyExc_ValueError,
                        "native authority request is not canonical");
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    lock_acquired = PyThread_acquire_lock(session->operation_lock, WAIT_LOCK);
    Py_END_ALLOW_THREADS
    if (!lock_acquired) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority session is unavailable");
        return NULL;
    }
    if (session->control_fd < 0 ||
            !v2_operation_object_matches_member(self, member) ||
            !plamen_broker_v2_authority_method_valid(
                session->role, member, method, flags) ||
            session->next_sequence > UINT64_MAX - UINT64_C(2) ||
            plamen_broker_v2_sha256(payload, (size_t)payload_size,
                                    payload_sha256) !=
                PLAMEN_BROKER_V2_OK) {
        terminal_failure = 1;
        goto done;
    }
    cache_entry = v2_rpc_replay_find(
        session, member, method, flags, payload_sha256);
    known_replay = cache_entry != NULL;
    request.authority_role = session->role;
    request.member = member;
    request.method = method;
    request.flags = flags;
    request.payload = (const unsigned char *)payload;
    request.payload_size = (uint32_t)payload_size;
    memcpy(request.request_fingerprint,
           session->commitment.request_fingerprint, 32);
    memcpy(request.payload_sha256, payload_sha256, 32);
    if (known_replay) {
        memcpy(request.prior_checkpoint_sha256,
               cache_entry->prior_checkpoint_sha256, 32);
        memcpy(request.operation_key, cache_entry->operation_key, 32);
    } else {
        if (session->role == PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR) {
            memcpy(request.prior_checkpoint_sha256,
                   session->current_checkpoint_sha256, 32);
        } else {
            memcpy(request.prior_checkpoint_sha256,
                   session->issuance_checkpoint_sha256, 32);
        }
        if (plamen_broker_v2_derive_rpc_operation_key(
                &session->commitment, self->member_capability_id,
                session->role, member, method, payload_sha256,
                request.prior_checkpoint_sha256,
                request.operation_key) != PLAMEN_BROKER_V2_OK) {
            terminal_failure = 1;
            goto done;
        }
        io_status = v2_rpc_replay_reserve(session, &cache_entry);
        if (io_status != 0) {
            if (io_status == -2) {
                PyErr_NoMemory();
            } else {
                PyErr_SetString(PyExc_RuntimeError,
                                "native authority replay cache is full");
            }
            goto done;
        }
    }
    request_capacity = PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE +
        (size_t)payload_size;
    encoded_request = (unsigned char *)malloc(request_capacity);
    if (encoded_request == NULL) {
        PyErr_NoMemory();
        goto done;
    }
    if (plamen_broker_v2_operation_request_encode(
            &request, encoded_request, request_capacity,
            &encoded_request_size) != PLAMEN_BROKER_V2_OK ||
            encoded_request_size != request_capacity ||
            plamen_broker_v2_sha256(encoded_request, encoded_request_size,
                                    request_frame_sha256) !=
                PLAMEN_BROKER_V2_OK) {
        terminal_failure = 1;
        goto done;
    }
    if (known_replay) {
        if (!v2_constant_equal(cache_entry->request_sha256,
                               request_frame_sha256, 32)) {
            terminal_failure = 1;
            goto done;
        }
    } else {
        cache_entry->role = session->role;
        cache_entry->member = member;
        cache_entry->method = method;
        cache_entry->flags = flags;
        memcpy(cache_entry->payload_sha256, payload_sha256, 32);
        memcpy(cache_entry->prior_checkpoint_sha256,
               request.prior_checkpoint_sha256, 32);
        memcpy(cache_entry->operation_key, request.operation_key, 32);
        memcpy(cache_entry->request_sha256, request_frame_sha256, 32);
    }
    request_sequence = session->next_sequence;
    if (v2_build_frame(&request_frame, &request_frame_size,
            PLAMEN_BROKER_V2_OPERATION_REQUEST, request_sequence, 0,
            session->session_id, request.operation_key,
            session->previous_frame_sha256, session->key,
            encoded_request, encoded_request_size) < 0) {
        PyErr_NoMemory();
        goto done;
    }
    if (!known_replay) {
        session->replay_count++;
    }
    v2_sha256_bytes(request_frame, request_frame_size,
                    request_frame_sha256);
    Py_BEGIN_ALLOW_THREADS
    io_status = v2_send_all(session->control_fd, request_frame,
                            request_frame_size);
    if (io_status == 0) {
        io_status = v2_receive_frame_with_deadline(
            session->control_fd, &received, receive_timeout_ms);
    }
    Py_END_ALLOW_THREADS
    if (io_status != 0 || received.fd_count != 0) {
        terminal_failure = 1;
        goto done;
    }
    response_type = v2_get_u16(received.header + 10);
    if ((response_type != PLAMEN_BROKER_V2_OPERATION_RESPONSE &&
         response_type != PLAMEN_BROKER_V2_OPERATION_ERROR) ||
            !v2_validate_frame(&received, response_type,
                               request_sequence + UINT64_C(1),
                               session->session_id, request.operation_key,
                               request_frame_sha256, session->key)) {
        terminal_failure = 1;
        goto done;
    }
    v2_frame_digest(&received, response_frame_sha256);
    memcpy(session->previous_frame_sha256,
           response_frame_sha256, 32);
    session->next_sequence = request_sequence + UINT64_C(2);
    if (response_type == PLAMEN_BROKER_V2_OPERATION_RESPONSE) {
        if (plamen_broker_v2_operation_response_decode(
                received.payload, received.payload_size,
                &response) != PLAMEN_BROKER_V2_OK ||
                !plamen_broker_v2_operation_response_matches_request(
                    encoded_request, encoded_request_size,
                    &request, &response) ||
                !v2_operation_payload_valid(
                    (const char *)response.payload,
                    (Py_ssize_t)response.payload_size)) {
            terminal_failure = 1;
            goto done;
        }
        if (!known_replay && session->role ==
                PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR) {
            memcpy(session->current_checkpoint_sha256,
                   response.next_checkpoint_sha256, 32);
        }
        result = PyBytes_FromStringAndSize(
            (const char *)response.payload,
            (Py_ssize_t)response.payload_size);
    } else {
        if (plamen_broker_v2_operation_error_decode(
                received.payload, received.payload_size,
                &operation_error) != PLAMEN_BROKER_V2_OK ||
                !plamen_broker_v2_operation_error_matches_request(
                    encoded_request, encoded_request_size,
                    &request, &operation_error) ||
                (operation_error.flags &
                    PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED) == 0 ||
                !v2_constant_equal(
                    operation_error.current_checkpoint_sha256,
                    request.prior_checkpoint_sha256, 32) ||
                (operation_error.flags &
                    PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED) != 0) {
            terminal_failure = 1;
        } else {
            retryable_operation_error = 1;
        }
    }

done:
    if (terminal_failure) {
        v2_shared_session_burn_locked(session);
    }
    PyThread_release_lock(session->operation_lock);
    v2_received_clear(&received);
    if (request_frame != NULL) {
        secure_zero(request_frame, request_frame_size);
        free(request_frame);
    }
    if (encoded_request != NULL) {
        secure_zero(encoded_request, encoded_request_size);
        free(encoded_request);
    }
    secure_zero(payload_sha256, sizeof(payload_sha256));
    secure_zero(request_frame_sha256, sizeof(request_frame_sha256));
    secure_zero(response_frame_sha256, sizeof(response_frame_sha256));
    plamen_broker_v2_secure_zero(&request, sizeof(request));
    plamen_broker_v2_secure_zero(&response, sizeof(response));
    plamen_broker_v2_secure_zero(&operation_error,
                                 sizeof(operation_error));
    if (result != NULL) {
        return result;
    }
    if (PyErr_Occurred()) {
        return NULL;
    }
    if (retryable_operation_error) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority operation failed");
    } else {
        PyErr_SetString(PyExc_RuntimeError,
                        "native authority session is invalid");
    }
    return NULL;
}

#endif /* !PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY */

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static int
v2_require_eof(int fd)
{
    unsigned char extra;
    ssize_t amount;
    int64_t now_ms = v2_monotonic_milliseconds();
    int64_t deadline_ms;
    if (now_ms < 0 || now_ms > INT64_MAX - PLAMEN_IO_DEADLINE_MS) {
        return -1;
    }
    deadline_ms = now_ms + PLAMEN_IO_DEADLINE_MS;
    if (v2_wait_readable_until(fd, deadline_ms) < 0) {
        return -1;
    }
    do {
        amount = recv(fd, &extra, 1, 0);
    } while (amount < 0 && errno == EINTR);
    return amount == 0 ? 0 : -1;
}
#endif

static void
v2_consumer_close(V2AuthorityConsumerObject *self)
{
    int fd = self->session_fd;
    self->session_fd = -1;
    if (fd >= 0) {
        (void)close(fd);
    }
    fd = self->test_peer_fd;
    self->test_peer_fd = -1;
    if (fd >= 0) {
        (void)close(fd);
    }
    if (self->request_projection != NULL) {
        secure_zero(self->request_projection,
                    self->request_projection_size);
        free(self->request_projection);
        self->request_projection = NULL;
    }
    self->request_projection_size = 0;
    self->protocol_ready = 0;
    secure_zero(self->previous_frame_sha256,
                sizeof(self->previous_frame_sha256));
    secure_zero(self->session_key, sizeof(self->session_key));
}

static void
v2_consumer_dealloc(PyObject *object)
{
    V2AuthorityConsumerObject *self = (V2AuthorityConsumerObject *)object;
    v2_consumer_close(self);
    secure_zero(self->expected_session_id, sizeof(self->expected_session_id));
    secure_zero(self->expected_operation_nonce,
                sizeof(self->expected_operation_nonce));
    secure_zero(self->expected_fingerprint,
                sizeof(self->expected_fingerprint));
    secure_zero(self->expected_registration_sha256,
                sizeof(self->expected_registration_sha256));
    secure_zero(self->expected_issuance_checkpoint_sha256,
                sizeof(self->expected_issuance_checkpoint_sha256));
    secure_zero(self->expected_authority_bundle_sha256,
                sizeof(self->expected_authority_bundle_sha256));
    secure_zero(self->expected_request_projection_sha256,
                sizeof(self->expected_request_projection_sha256));
    secure_zero(self->native_deployment_receipt_sha256,
                sizeof(self->native_deployment_receipt_sha256));
    secure_zero(self->runtime_closure_sha256,
                sizeof(self->runtime_closure_sha256));
    secure_zero(self->broker_peer_identity_sha256,
                sizeof(self->broker_peer_identity_sha256));
    secure_zero(self->managed_toolchain_custody_sha256,
                sizeof(self->managed_toolchain_custody_sha256));
    self->expected_request_projection_size = 0;
    secure_zero(self->expected_attempt, sizeof(self->expected_attempt));
    secure_zero(self->expected_auth_payload,
                sizeof(self->expected_auth_payload));
    self->expected_auth_payload_size = 0;
    PyObject_Del(object);
}

static int
v2_burn_consumer(V2AuthorityConsumerObject *self)
{
    if (atomic_exchange_explicit(&self->consumed, 1,
                                 memory_order_acq_rel) != 0) {
        v2_consumer_close(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native broker v2 authority is already consumed");
        return -1;
    }
    return 0;
}

static int
v2_ascii_id_valid(const char *value, size_t size)
{
    size_t index;
    if (value == NULL || size < 1 || size > PLAMEN_BROKER_V2_MAX_ID) {
        return 0;
    }
    for (index = 0; index < size; index++) {
        unsigned char character = (unsigned char)value[index];
        if (!((character >= 'A' && character <= 'Z') ||
              (character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') ||
              character == '_' || character == '.' ||
              character == ':' || character == '-')) {
            return 0;
        }
    }
    return 1;
}

static int
v2_auth_payload_valid(const unsigned char *payload, size_t payload_size,
                      const unsigned char fingerprint[32],
                      const char *attempt, size_t attempt_size)
{
    struct plamen_broker_v2_commitment commitment;
    int valid = 0;

    memset(&commitment, 0, sizeof(commitment));
    if (payload != NULL && fingerprint != NULL &&
            v2_ascii_id_valid(attempt, attempt_size) &&
            payload_size <= PLAMEN_BROKER_V2_AUTH_PAYLOAD_MAX &&
            plamen_broker_v2_decode_commitment_exact(
                payload, payload_size, &commitment) == PLAMEN_BROKER_V2_OK &&
            v2_constant_equal(commitment.request_fingerprint,
                              fingerprint, 32) &&
            attempt_size < sizeof(commitment.attempt_id) &&
            commitment.attempt_id[attempt_size] == '\0' &&
            memcmp(commitment.attempt_id, attempt, attempt_size) == 0) {
        valid = 1;
    }
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    return valid;
}

/*
 * The platform bootstrap will call this C-only constructor after it has
 * authenticated and burned a launcher registration.  Neither this function
 * nor any of its inputs is reachable through the module API.
 */
static PyObject *
v2_new_consumer_from_native_session(
        int owned_control_fd, int owned_test_peer_fd,
        uint16_t initial_authority_role,
        const unsigned char key[32], const unsigned char session_id[32],
        const unsigned char operation_nonce[32],
        const unsigned char fingerprint[32],
        const char *attempt, size_t attempt_size,
        const unsigned char *auth_payload, size_t auth_payload_size,
        const unsigned char registration_sha256[32],
        const unsigned char issuance_checkpoint_sha256[32],
        const unsigned char authority_bundle_sha256[32],
        const unsigned char request_projection_sha256[32],
        uint32_t request_projection_size,
        const unsigned char native_deployment_receipt_sha256[32],
        const unsigned char runtime_closure_sha256[32],
        const unsigned char broker_peer_identity_sha256[32],
        const unsigned char managed_toolchain_custody_sha256[32])
{
    V2AuthorityConsumerObject *consumer;
    unsigned char zeros[32] = {0};

    if (key == NULL || session_id == NULL || operation_nonce == NULL ||
            fingerprint == NULL || attempt == NULL || auth_payload == NULL ||
            registration_sha256 == NULL ||
            issuance_checkpoint_sha256 == NULL ||
            authority_bundle_sha256 == NULL ||
            request_projection_sha256 == NULL ||
            native_deployment_receipt_sha256 == NULL ||
            runtime_closure_sha256 == NULL ||
            broker_peer_identity_sha256 == NULL ||
            managed_toolchain_custody_sha256 == NULL ||
            initial_authority_role <
                PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR ||
            initial_authority_role >
                PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER ||
            v2_constant_equal(key, zeros, 32) ||
            v2_constant_equal(session_id, zeros, 32) ||
            v2_constant_equal(fingerprint, zeros, 32) ||
            v2_constant_equal(registration_sha256, zeros, 32) ||
            v2_constant_equal(issuance_checkpoint_sha256, zeros, 32) ||
            v2_constant_equal(authority_bundle_sha256, zeros, 32) ||
            v2_constant_equal(request_projection_sha256, zeros, 32) ||
            v2_constant_equal(native_deployment_receipt_sha256, zeros, 32) ||
            v2_constant_equal(runtime_closure_sha256, zeros, 32) ||
            v2_constant_equal(broker_peer_identity_sha256, zeros, 32) ||
            v2_constant_equal(managed_toolchain_custody_sha256, zeros, 32) ||
            request_projection_size == 0 ||
            request_projection_size > PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX ||
            !v2_constant_equal(operation_nonce, zeros, 32) ||
            !v2_auth_payload_valid(auth_payload, auth_payload_size,
                                   fingerprint, attempt, attempt_size) ||
            v2_prepare_control_fd(owned_control_fd) < 0) {
        if (owned_control_fd >= 0) {
            (void)close(owned_control_fd);
        }
        if (owned_test_peer_fd >= 0) {
            (void)close(owned_test_peer_fd);
        }
        return NULL;
    }
    consumer = PyObject_New(V2AuthorityConsumerObject,
                            &V2AuthorityConsumerType);
    if (consumer == NULL) {
        (void)close(owned_control_fd);
        if (owned_test_peer_fd >= 0) {
            (void)close(owned_test_peer_fd);
        }
        return NULL;
    }
    consumer->creator_pid = getpid();
    consumer->creator_interpreter_id = current_interpreter_id();
    atomic_init(&consumer->consumed, 0);
    consumer->initial_authority_role = initial_authority_role;
    consumer->session_fd = owned_control_fd;
    consumer->test_peer_fd = owned_test_peer_fd;
    memcpy(consumer->session_key, key, 32);
    memcpy(consumer->expected_session_id, session_id, 32);
    memcpy(consumer->expected_operation_nonce, operation_nonce, 32);
    memcpy(consumer->expected_fingerprint, fingerprint, 32);
    memcpy(consumer->expected_registration_sha256,
           registration_sha256, 32);
    memcpy(consumer->expected_issuance_checkpoint_sha256,
           issuance_checkpoint_sha256, 32);
    memcpy(consumer->expected_authority_bundle_sha256,
           authority_bundle_sha256, 32);
    memcpy(consumer->expected_request_projection_sha256,
           request_projection_sha256, 32);
    memcpy(consumer->native_deployment_receipt_sha256,
           native_deployment_receipt_sha256, 32);
    memcpy(consumer->runtime_closure_sha256, runtime_closure_sha256, 32);
    memcpy(consumer->broker_peer_identity_sha256,
           broker_peer_identity_sha256, 32);
    memcpy(consumer->managed_toolchain_custody_sha256,
           managed_toolchain_custody_sha256, 32);
    consumer->expected_request_projection_size = request_projection_size;
    memset(consumer->previous_frame_sha256, 0,
           sizeof(consumer->previous_frame_sha256));
    consumer->request_projection = NULL;
    consumer->request_projection_size = 0;
    consumer->protocol_ready = 0;
    memcpy(consumer->expected_attempt, attempt, attempt_size);
    consumer->expected_attempt[attempt_size] = '\0';
    consumer->expected_attempt_len = (Py_ssize_t)attempt_size;
    memcpy(consumer->expected_auth_payload, auth_payload, auth_payload_size);
    consumer->expected_auth_payload_size = auth_payload_size;
    return (PyObject *)consumer;
}

static V2OpaqueCapabilityObject *
v2_new_opaque(PyTypeObject *type, unsigned int kind, pid_t pid,
              int64_t interpreter_id,
              const unsigned char member_capability_id[32],
              V2SharedNativeSession *native_session)
{
    V2OpaqueCapabilityObject *object =
        PyObject_New(V2OpaqueCapabilityObject, type);
    if (object != NULL && native_session != NULL) {
        object->creator_pid = pid;
        object->creator_interpreter_id = interpreter_id;
        atomic_init(&object->consumed, 0);
        object->kind = kind;
        memcpy(object->member_capability_id, member_capability_id, 32);
        v2_shared_session_retain(native_session);
        object->native_session = native_session;
    } else if (object != NULL) {
        PyObject_Del(object);
        object = NULL;
    }
    return object;
}

static PyObject *
v2_new_bundle(pid_t pid, int64_t interpreter_id,
              const struct plamen_broker_v2_authority_bundle_binding *binding,
              V2SharedNativeSession *native_session)
{
    V2AuthorityBundleObject *bundle =
        PyObject_New(V2AuthorityBundleObject, &V2AuthorityBundleType);
    if (bundle == NULL) {
        return NULL;
    }
    bundle->creator_pid = pid;
    bundle->creator_interpreter_id = interpreter_id;
    atomic_init(&bundle->consumed, 0);
    bundle->runtime = NULL;
    bundle->workspace = NULL;
    bundle->backend = NULL;
    bundle->provider = NULL;
    bundle->guest_admission = NULL;
    bundle->extinction = NULL;
    bundle->artifacts = NULL;
    bundle->exporter = NULL;
    bundle->journal = NULL;
    bundle->recovery = NULL;
    bundle->runtime = (PyObject *)v2_new_opaque(
        &V2RuntimeAuthorityType, 1U, pid, interpreter_id,
        binding->member_sha256[0], native_session);
    bundle->workspace = (PyObject *)v2_new_opaque(
        &V2WorkspaceAuthorityType, 2U, pid, interpreter_id,
        binding->member_sha256[1], native_session);
    bundle->backend = (PyObject *)v2_new_opaque(
        &V2BackendAuthorityType, 3U, pid, interpreter_id,
        binding->member_sha256[2], native_session);
    bundle->provider = (PyObject *)v2_new_opaque(
        &V2ProviderAuthorityType, 4U, pid, interpreter_id,
        binding->member_sha256[3], native_session);
    bundle->guest_admission = (PyObject *)v2_new_opaque(
        &V2GuestAdmissionAuthorityType, 5U, pid, interpreter_id,
        binding->member_sha256[4], native_session);
    bundle->extinction = (PyObject *)v2_new_opaque(
        &V2ExtinctionAuthorityType, 6U, pid, interpreter_id,
        binding->member_sha256[5], native_session);
    bundle->artifacts = (PyObject *)v2_new_opaque(
        &V2ArtifactAuthorityType, 7U, pid, interpreter_id,
        binding->member_sha256[6], native_session);
    bundle->exporter = (PyObject *)v2_new_opaque(
        &V2ExportAuthorityType, 8U, pid, interpreter_id,
        binding->member_sha256[7], native_session);
    bundle->journal = (PyObject *)v2_new_opaque(
        &V2JournalAuthorityType, 9U, pid, interpreter_id,
        binding->member_sha256[8], native_session);
    bundle->recovery = (PyObject *)v2_new_opaque(
        &V2RecoveryAuthorityType, 10U, pid, interpreter_id,
        binding->member_sha256[9], native_session);
    if (bundle->runtime == NULL || bundle->workspace == NULL ||
            bundle->backend == NULL || bundle->provider == NULL ||
            bundle->guest_admission == NULL || bundle->extinction == NULL ||
            bundle->artifacts == NULL || bundle->exporter == NULL ||
            bundle->journal == NULL || bundle->recovery == NULL) {
        Py_DECREF(bundle);
        return NULL;
    }
    return (PyObject *)bundle;
}

static PyObject *
v2_new_guest_bundle(pid_t pid, int64_t interpreter_id,
                    const struct plamen_broker_v2_authority_bundle_binding *binding,
                    V2SharedNativeSession *native_session)
{
    V2GuestAuthorityBundleObject *bundle =
        PyObject_New(V2GuestAuthorityBundleObject, &V2GuestAuthorityBundleType);
    if (bundle == NULL) {
        return NULL;
    }
    bundle->creator_pid = pid;
    bundle->creator_interpreter_id = interpreter_id;
    atomic_init(&bundle->consumed, 0);
    bundle->backend_execution = (PyObject *)v2_new_opaque(
        &V2BackendExecutionAuthorityType, 15U, pid, interpreter_id,
        binding->member_sha256[0], native_session);
    if (bundle->backend_execution == NULL) {
        Py_DECREF(bundle);
        return NULL;
    }
    return (PyObject *)bundle;
}

static int
v2_fetch_request_projection(V2AuthorityConsumerObject *self)
{
    unsigned char zeros[32] = {0};
    unsigned char hello_digest[32] = {0};
    unsigned char request_digest[32] = {0};
    unsigned char commitment_digest[32] = {0};
    unsigned char *request_frame = NULL;
    size_t request_frame_size = 0;
    V2ReceivedFrame hello, projected;
    struct plamen_broker_v2_commitment commitment;
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    V2ReceivedFrame observed_request;
#endif
    int valid = 0;

    if (self->request_projection != NULL) {
        return 0;
    }
    memset(&hello, 0, sizeof(hello));
    memset(&projected, 0, sizeof(projected));
    memset(&commitment, 0, sizeof(commitment));
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    memset(&observed_request, 0, sizeof(observed_request));
#endif
    if (self->protocol_ready ||
            v2_receive_frame(self->session_fd, &hello) < 0 ||
            hello.fd_count != 0 || hello.payload_size != 0 ||
            !v2_validate_frame(&hello, PLAMEN_BROKER_V2_HELLO, 0,
                               self->expected_session_id, zeros, zeros,
                               self->session_key)) {
        goto done;
    }
    v2_frame_digest(&hello, hello_digest);
    if (v2_build_frame(
            &request_frame, &request_frame_size,
            PLAMEN_BROKER_V2_REQUEST_PROJECTION, 1, 0,
            self->expected_session_id, zeros, hello_digest,
            self->session_key, NULL, 0) < 0) {
        goto done;
    }
    v2_sha256_bytes(request_frame, request_frame_size, request_digest);
    if (v2_send_all(self->session_fd, request_frame, request_frame_size) < 0) {
        goto done;
    }
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    if (self->test_peer_fd < 0 ||
            v2_receive_frame(self->test_peer_fd, &observed_request) < 0 ||
            observed_request.fd_count != 0 ||
            observed_request.payload_size != 0 ||
            !v2_validate_frame(
                &observed_request, PLAMEN_BROKER_V2_REQUEST_PROJECTION, 1,
                self->expected_session_id, zeros, hello_digest,
                self->session_key)) {
        goto done;
    }
#endif
    v2_sha256_bytes(self->expected_auth_payload,
                    self->expected_auth_payload_size,
                    commitment_digest);
    if (v2_receive_frame(self->session_fd, &projected) < 0 ||
            projected.fd_count != 0 ||
            projected.payload_size != self->expected_request_projection_size ||
            !v2_validate_frame(
                &projected, PLAMEN_BROKER_V2_REQUEST_PROJECTED, 2,
                self->expected_session_id, zeros, request_digest,
                self->session_key) ||
            plamen_broker_v2_request_projection_validate_exact(
                projected.payload, projected.payload_size,
                self->expected_request_projection_sha256,
                self->expected_auth_payload,
                self->expected_auth_payload_size,
                commitment_digest, &commitment) !=
                    PLAMEN_BROKER_V2_OK) {
        goto done;
    }
    v2_frame_digest(&projected, self->previous_frame_sha256);
    self->request_projection = projected.payload;
    self->request_projection_size = projected.payload_size;
    projected.payload = NULL;
    projected.payload_size = 0;
    self->protocol_ready = 1;
    valid = 1;

done:
    v2_received_clear(&hello);
    v2_received_clear(&projected);
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    v2_received_clear(&observed_request);
#endif
    if (request_frame != NULL) {
        secure_zero(request_frame, request_frame_size);
        free(request_frame);
    }
    secure_zero(hello_digest, sizeof(hello_digest));
    secure_zero(request_digest, sizeof(request_digest));
    secure_zero(commitment_digest, sizeof(commitment_digest));
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    return valid ? 0 : -1;
}

static int
v2_consumer_origin_valid(V2AuthorityConsumerObject *self)
{
    return getpid() == self->creator_pid &&
        current_interpreter_id() == self->creator_interpreter_id &&
        (self->initial_authority_role ==
             PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR ||
         self->initial_authority_role ==
             PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER);
}

static PyObject *
v2_request_projection(PyObject *object, PyObject *Py_UNUSED(ignored))
{
    V2AuthorityConsumerObject *self = (V2AuthorityConsumerObject *)object;
    PyObject *result;
    if (atomic_load_explicit(&self->consumed, memory_order_acquire) != 0) {
        v2_consumer_close(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native broker v2 authority is already consumed");
        return NULL;
    }
    if (!v2_consumer_origin_valid(self) ||
            v2_fetch_request_projection(self) < 0) {
        (void)atomic_exchange_explicit(&self->consumed, 1,
                                       memory_order_acq_rel);
        v2_consumer_close(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native broker v2 request projection is invalid");
        return NULL;
    }
    result = PyBytes_FromStringAndSize(
        (const char *)self->request_projection,
        (Py_ssize_t)self->request_projection_size);
    if (result == NULL) {
        (void)atomic_exchange_explicit(&self->consumed, 1,
                                       memory_order_acq_rel);
        v2_consumer_close(self);
    }
    return result;
}

static PyObject *
v2_consume_once(PyObject *object, PyObject *args)
{
    V2AuthorityConsumerObject *self = (V2AuthorityConsumerObject *)object;
    PyObject *fingerprint_object, *attempt_object;
    unsigned char fingerprint[32], auth_digest[32];
    unsigned char authority_bundle_digest[32];
    unsigned char accepted_digest[32];
    unsigned char zeros[32] = {0};
    unsigned char *auth_frame = NULL;
    size_t auth_frame_size = 0;
    const char *attempt;
    Py_ssize_t attempt_len;
    V2ReceivedFrame accepted, observed_request;
    struct plamen_broker_v2_authority_bundle_binding authority_binding;
    struct plamen_broker_v2_commitment commitment;
    V2SharedNativeSession *native_session = NULL;
    PyObject *bundle = NULL;
    int valid = 0;

    memset(&accepted, 0, sizeof(accepted));
    memset(&observed_request, 0, sizeof(observed_request));
    memset(auth_digest, 0, sizeof(auth_digest));
    memset(authority_bundle_digest, 0, sizeof(authority_bundle_digest));
    memset(accepted_digest, 0, sizeof(accepted_digest));
    memset(&authority_binding, 0, sizeof(authority_binding));
    memset(&commitment, 0, sizeof(commitment));
    if (v2_burn_consumer(self) < 0) {
        return NULL;
    }
    if (getpid() != self->creator_pid) {
        v2_consumer_close(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native broker v2 authority cannot cross a process boundary");
        return NULL;
    }
    if (current_interpreter_id() != self->creator_interpreter_id) {
        v2_consumer_close(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native broker v2 authority cannot cross an interpreter boundary");
        return NULL;
    }
    if (self->initial_authority_role !=
            PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR &&
            self->initial_authority_role !=
                PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER) {
        v2_consumer_close(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native broker v2 initial authority role mismatch");
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "OO:consume_once", &fingerprint_object,
                          &attempt_object)) {
        PyErr_Clear();
        v2_consumer_close(self);
        PyErr_SetString(PyExc_TypeError,
                        "consume_once requires canonical binding values");
        return NULL;
    }
    if (v2_decode_lower_hex_32(fingerprint_object, fingerprint) < 0 ||
            v2_decode_id(attempt_object, &attempt, &attempt_len) < 0) {
        secure_zero(fingerprint, sizeof(fingerprint));
        v2_consumer_close(self);
        PyErr_SetString(PyExc_ValueError,
                        "consume_once binding is not canonical");
        return NULL;
    }
    if (!v2_constant_equal(fingerprint, self->expected_fingerprint, 32) ||
            attempt_len != self->expected_attempt_len ||
            memcmp(attempt, self->expected_attempt, (size_t)attempt_len) != 0) {
        secure_zero(fingerprint, sizeof(fingerprint));
        v2_consumer_close(self);
        PyErr_SetString(PyExc_RuntimeError,
                        "native broker v2 authority binding mismatch");
        return NULL;
    }
    secure_zero(fingerprint, sizeof(fingerprint));

    if (v2_fetch_request_projection(self) < 0) {
        goto done;
    }
    if (v2_build_frame(
            &auth_frame, &auth_frame_size,
            PLAMEN_BROKER_V2_AUTH_CONSUME, 3, 0,
            self->expected_session_id, zeros,
            self->previous_frame_sha256,
            self->session_key, self->expected_auth_payload,
            self->expected_auth_payload_size) < 0) {
        goto done;
    }
    v2_sha256_bytes(auth_frame, auth_frame_size, auth_digest);
    if (v2_send_all(self->session_fd, auth_frame, auth_frame_size) < 0) {
        goto done;
    }
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    /* The distinct test issuer retains the peer only to prove our request. */
    if (self->test_peer_fd < 0 ||
            v2_receive_frame(self->test_peer_fd, &observed_request) < 0 ||
            observed_request.fd_count != 0 ||
            !v2_validate_frame(
                &observed_request, PLAMEN_BROKER_V2_AUTH_CONSUME, 3,
                self->expected_session_id, zeros,
                self->previous_frame_sha256,
                self->session_key) ||
            observed_request.payload_size != self->expected_auth_payload_size ||
            !v2_constant_equal(observed_request.payload,
                               self->expected_auth_payload,
                               self->expected_auth_payload_size)) {
        goto done;
    }
    (void)close(self->test_peer_fd);
    self->test_peer_fd = -1;
#endif
    if (v2_receive_frame(self->session_fd, &accepted) < 0 ||
            accepted.fd_count != 0 ||
            !v2_validate_frame(&accepted, PLAMEN_BROKER_V2_AUTH_ACCEPTED, 4,
                               self->expected_session_id,
                               self->expected_operation_nonce, auth_digest,
                               self->session_key) ||
            plamen_broker_v2_authority_bundle_binding_decode(
                accepted.payload, accepted.payload_size,
                &authority_binding) != PLAMEN_BROKER_V2_OK ||
            authority_binding.role != self->initial_authority_role ||
            !v2_constant_equal(authority_binding.registration_sha256,
                               self->expected_registration_sha256, 32) ||
            !v2_constant_equal(
                authority_binding.issuance_checkpoint_sha256,
                self->expected_issuance_checkpoint_sha256, 32) ||
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
            v2_require_eof(self->session_fd) < 0) {
#else
            0) {
#endif
        goto done;
    }
    v2_sha256_bytes(accepted.payload, accepted.payload_size,
                    authority_bundle_digest);
    if (!v2_constant_equal(authority_bundle_digest,
                           self->expected_authority_bundle_sha256, 32)) {
        goto done;
    }
    v2_frame_digest(&accepted, accepted_digest);
    if (plamen_broker_v2_decode_commitment_exact(
            self->expected_auth_payload, self->expected_auth_payload_size,
            &commitment) != PLAMEN_BROKER_V2_OK) {
        goto done;
    }
    native_session = v2_shared_session_new(
        self->creator_pid, self->creator_interpreter_id,
        self->initial_authority_role, self->session_fd,
        self->session_key, self->expected_session_id, accepted_digest, 5U,
        self->expected_issuance_checkpoint_sha256, &commitment);
    if (native_session == NULL) {
        PyErr_NoMemory();
        goto done;
    }
    self->session_fd = -1;
    valid = 1;

done:
    v2_received_clear(&accepted);
    v2_received_clear(&observed_request);
    if (auth_frame != NULL) {
        secure_zero(auth_frame, auth_frame_size);
        free(auth_frame);
    }
    secure_zero(auth_digest, sizeof(auth_digest));
    secure_zero(authority_bundle_digest, sizeof(authority_bundle_digest));
    secure_zero(accepted_digest, sizeof(accepted_digest));
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    v2_consumer_close(self);
    if (!valid) {
        v2_shared_session_release(native_session);
        plamen_broker_v2_secure_zero(&authority_binding,
                                     sizeof(authority_binding));
        if (!PyErr_Occurred()) {
            PyErr_SetString(PyExc_RuntimeError,
                            "native broker v2 session is invalid");
        }
        return NULL;
    }
    if (self->initial_authority_role ==
            PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR) {
        bundle = v2_new_bundle(self->creator_pid,
                               self->creator_interpreter_id,
                               &authority_binding, native_session);
    } else {
        bundle = v2_new_guest_bundle(self->creator_pid,
                                     self->creator_interpreter_id,
                                     &authority_binding, native_session);
    }
    v2_shared_session_release(native_session);
    plamen_broker_v2_secure_zero(&authority_binding,
                                 sizeof(authority_binding));
    return bundle;
}

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY

static PyMethodDef v2_consumer_methods[] = {
    {"request_projection", v2_request_projection, METH_NOARGS,
     PyDoc_STR("Return authenticated immutable request projection bytes.")},
    {"consume_once", v2_consume_once, METH_VARARGS,
     PyDoc_STR("Consume a complete authenticated TEST_ONLY broker v2 session.")},
    {"__copy__", consumer_forbidden_copy, METH_NOARGS, NULL},
    {"__deepcopy__", consumer_forbidden_deepcopy, METH_VARARGS, NULL},
    {"__reduce__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__reduce_ex__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__getnewargs__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyTypeObject V2AuthorityConsumerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PLAMEN_V2_CONSUMER_TYPE_NAME,
    .tp_basicsize = sizeof(V2AuthorityConsumerObject),
    .tp_dealloc = v2_consumer_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION,
    .tp_doc = PyDoc_STR("Distinct TEST_ONLY broker v2 authority consumer."),
    .tp_methods = v2_consumer_methods,
    .tp_repr = opaque_capability_repr,
    .tp_new = consumer_forbidden_new,
};

static int
v2_make_frame(unsigned char **output, size_t *output_size,
              uint16_t type, uint64_t sequence, uint16_t declared_fds,
              const unsigned char session[32], const unsigned char nonce[32],
              const unsigned char previous[32], const unsigned char key[32],
              const unsigned char *payload, size_t payload_size)
{
    return v2_build_frame(output, output_size, type, sequence, declared_fds,
                          session, nonce, previous, key, payload,
                          payload_size);
}

static int
v2_send_frame(int fd, const unsigned char *frame, size_t frame_size,
              const int *fds, size_t fd_count)
{
    struct iovec iov;
    struct msghdr message;
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int) *
                                       (PLAMEN_BROKER_V2_MAX_FDS + 1U))];
    } ancillary;
    size_t offset = 0;
    ssize_t amount;
    memset(&message, 0, sizeof(message));
    memset(&ancillary, 0, sizeof(ancillary));
    iov.iov_base = (void *)frame;
    iov.iov_len = frame_size;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    if (fd_count != 0) {
        struct cmsghdr *header;
        if (fd_count > PLAMEN_BROKER_V2_MAX_FDS + 1U) {
            return -1;
        }
        message.msg_control = ancillary.bytes;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * fd_count);
        header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);
        memcpy(CMSG_DATA(header), fds, sizeof(int) * fd_count);
    }
    do {
        amount = sendmsg(fd, &message, 0);
    } while (amount < 0 && errno == EINTR);
    if (amount <= 0) {
        return -1;
    }
    offset = (size_t)amount;
    while (offset < frame_size) {
        do {
            amount = send(fd, frame + offset, frame_size - offset, 0);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0) {
            return -1;
        }
        offset += (size_t)amount;
    }
    return 0;
}

static int
v2_mutation_id(PyObject *object)
{
    const char *value;
    Py_ssize_t size;
    static const char *const names[] = {
        "none", "hello_bad_tag", "bad_magic", "bad_version", "bad_flags",
        "bad_header_size", "bad_payload_size", "bad_payload_digest", "bad_tag",
        "sequence_gap", "sequence_rollback", "bad_previous", "wrong_session",
        "cross_nonce", "trailing", "truncated", "fd_missing", "fd_surplus",
        "fd_alias", "hello_fd", "replay", "wrong_role", "guest_role",
        "projection_bad_tag", "projection_bad_payload",
        "projection_binding_sha", "projection_binding_size",
        "unconnected_control_socket", "projection_sequence",
        "projection_previous", "projection_session", "projection_nonce",
        "projection_fd", "projection_truncated",
        "projection_semantic_invalid", "accepted_binding_role",
        "accepted_binding_registration", "accepted_binding_checkpoint",
        "accepted_binding_sha", "accepted_member_count",
        "accepted_member_duplicate", "accepted_member_zero"
    };
    size_t index;
    if (!PyUnicode_CheckExact(object)) {
        return -1;
    }
    value = PyUnicode_AsUTF8AndSize(object, &size);
    if (value == NULL) {
        return -1;
    }
    for (index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        if ((size_t)size == strlen(names[index]) &&
                memcmp(value, names[index], (size_t)size) == 0) {
            return (int)index;
        }
    }
    return -1;
}

static PyObject *
test_only_broker_v2_crypto_kat(PyObject *module, PyObject *args)
{
    static const unsigned char public_key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const unsigned char first[] = "broker-v2-public-kat-header";
    static const unsigned char second[] = "broker-v2-public-kat-payload";
    unsigned char sha[32], tag[32];
    V2Sha256 context;
    PyObject *sha_object, *tag_object, *result;
    (void)module;
    if (!PyArg_ParseTuple(args, ":TEST_ONLY_broker_v2_crypto_kat")) {
        return NULL;
    }
    v2_sha256_init(&context);
    v2_sha256_update(&context, first, sizeof(first) - 1U);
    v2_sha256_update(&context, second, sizeof(second) - 1U);
    v2_sha256_final(&context, sha);
    {
        unsigned char header[PLAMEN_BROKER_V2_HEADER_SIZE] = {0};
        memcpy(header, first, sizeof(first) - 1U);
        v2_hmac_sha256(public_key, header, second, sizeof(second) - 1U, tag);
        secure_zero(header, sizeof(header));
    }
    sha_object = PyBytes_FromStringAndSize((const char *)sha, sizeof(sha));
    tag_object = PyBytes_FromStringAndSize((const char *)tag, sizeof(tag));
    secure_zero(sha, sizeof(sha));
    secure_zero(tag, sizeof(tag));
    if (sha_object == NULL || tag_object == NULL) {
        Py_XDECREF(sha_object);
        Py_XDECREF(tag_object);
        return NULL;
    }
    result = PyTuple_Pack(2, sha_object, tag_object);
    Py_DECREF(sha_object);
    Py_DECREF(tag_object);
    return result;
}

static PyObject *
test_only_issue_broker_v2(PyObject *module, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {
        "fingerprint_sha256", "attempt_id", "mutation",
        "creator_pid_override", "creator_interpreter_id_override", NULL
    };
    PyObject *fingerprint_object, *attempt_object;
    PyObject *mutation_object = NULL;
    long long creator_pid_override = -1;
    long long creator_interpreter_override = -1;
    static const unsigned char request_projection[] =
        "{\"audit_request\":{\"attempt_id\":\"attempt-1\",\"backend\":\"codex\",\"backend_admission_sha256\":\"6666666"
        "666666666666666666666666666666666666666666666666666666666\",\"backend_context_sha256\":\"bbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"credential_bundle_sha256\":\"ccccccccccccc"
        "ccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"credential_isolation_sha256\":\"777777777777"
        "7777777777777777777777777777777777777777777777777777\",\"docs_sha256\":\"ddddddddddddddddddddddddddd"
        "ddddddddddddddddddddddddddddddddddddd\",\"egress_admission_sha256\":\"888888888888888888888888888888"
        "8888888888888888888888888888888888\",\"egress_policy_sha256\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"export_allowlist\":[\"project/AUDIT_REPORT.md\",\"scratch/_plamen.log"
        "\",\"scratch/_v2_checkpoint.json\"],\"export_destination_identity_sha256\":\"fffffffffffffffffffffffff"
        "fffffffffffffffffffffffffffffffffffffff\",\"export_max_total_bytes\":2147483648,\"failure_required_a"
        "rtifacts\":[\"scratch/_plamen.log\"],\"image_closure_sha256\":\"44444444444444444444444444444444444444"
        "44444444444444444444444444\",\"image_manifest_digest\":\"sha256:999999999999999999999999999999999999"
        "9999999999999999999999999999\",\"language\":\"evm\",\"mode\":\"core\",\"pipeline\":\"sc\",\"provider_provenanc"
        "e_sha256\":\"5555555555555555555555555555555555555555555555555555555555555555\",\"request_id\":\"reque"
        "st-1\",\"request_type\":\"SC_NEW\",\"required_artifacts\":[\"project/AUDIT_REPORT.md\",\"scratch/_v2_check"
        "point.json\"],\"run_id\":\"run-1\",\"runtime_layout_sha256\":\"33333333333333333333333333333333333333333"
        "33333333333333333333333\",\"schema\":\"plamen.posix_audit_supervisor.v1\",\"scope_sha256\":\"11111111111"
        "11111111111111111111111111111111111111111111111111111\",\"seccomp_profile_sha256\":\"222222222222222"
        "2222222222222222222222222222222222222222222222222\",\"source_config\":{\"authenticated\":true,\"canoni"
        "cal_utf8_b64\":\"eyJfcnVuX2lkIjoicnVuLTEiLCJjbGlfYmFja2VuZCI6ImNvZGV4IiwibGFuZ3VhZ2UiOiJldm0iLCJtb"
        "2RlIjoiY29yZSIsInBpcGVsaW5lIjoic2MiLCJwcm9qZWN0X3Jvb3QiOiIvd29ya3NwYWNlL3Byb2plY3QiLCJzY3JhdGNoc"
        "GFkIjoiL3dvcmtzcGFjZS9zY3JhdGNoIn0K\",\"retained_source_handle\":\"opaque:aaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"sha256\":\"201e8183f9df23e133f2b8bca392eec769e13525a6d38a"
        "b4c3231d63e33a7e83\"},\"source_config_sha256\":\"201e8183f9df23e133f2b8bca392eec769e13525a6d38ab4c32"
        "31d63e33a7e83\",\"startup_decision_receipt_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaa\",\"target_identity_sha256\":\"00000000000000000000000000000000000000000000000000"
        "00000000000000\"},\"projection_schema\":\"plamen.native_audit_request_projection.v1\"}";
    unsigned char fingerprint[32], session[32], key[32], nonce[32];
    unsigned char wrong[32], zeros[32] = {0}, hello_digest[32];
    unsigned char projection_sha256[32], projection_request_digest[32];
    unsigned char commitment_sha256[32];
    unsigned char projected_digest[32], auth_digest[32];
    unsigned char auth_payload[PLAMEN_BROKER_V2_AUTH_PAYLOAD_MAX];
    unsigned char registration[32], bundle_digest[32], checkpoint[32];
    unsigned char *hello = NULL, *projection_request_frame = NULL;
    unsigned char *projected = NULL, *auth_frame = NULL;
    unsigned char *accepted = NULL, *payload = NULL;
    size_t hello_size = 0, projection_request_frame_size = 0;
    size_t projected_size = 0, auth_frame_size = 0, accepted_size = 0;
    size_t auth_payload_size, payload_size;
    const char *attempt;
    Py_ssize_t attempt_len;
    int sockets[2] = {-1, -1};
    int sent_fds[PLAMEN_BROKER_V2_MAX_FDS + 1U];
    int auxiliary[PLAMEN_BROKER_V2_MAX_FDS + 1U][2];
    size_t sent_count = 0, index;
    uint16_t declared_count = 0;
    int mutation;
    V2AuthorityConsumerObject *consumer = NULL;
    struct plamen_broker_v2_authority_bundle_binding authority_binding;
    struct plamen_broker_v2_commitment commitment;

    (void)module;
    memset(sent_fds, -1, sizeof(sent_fds));
    memset(auxiliary, -1, sizeof(auxiliary));
    memset(auth_payload, 0, sizeof(auth_payload));
    memset(auth_digest, 0, sizeof(auth_digest));
    memset(commitment_sha256, 0, sizeof(commitment_sha256));
    memset(&authority_binding, 0, sizeof(authority_binding));
    memset(&commitment, 0, sizeof(commitment));
    if (mutation_object == NULL) {
        mutation_object = Py_None;
    }
    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "OO|OLL:TEST_ONLY_issue_broker_v2", keywords,
            &fingerprint_object, &attempt_object, &mutation_object,
            &creator_pid_override, &creator_interpreter_override)) {
        return NULL;
    }
    if (mutation_object == Py_None) {
        mutation_object = PyUnicode_FromString("none");
        if (mutation_object == NULL) {
            return NULL;
        }
        mutation = v2_mutation_id(mutation_object);
        Py_DECREF(mutation_object);
    } else {
        mutation = v2_mutation_id(mutation_object);
    }
    if (mutation < 0 ||
            v2_decode_lower_hex_32(fingerprint_object, fingerprint) < 0 ||
            v2_decode_id(attempt_object, &attempt, &attempt_len) < 0) {
        PyErr_SetString(PyExc_ValueError,
                        "TEST_ONLY broker v2 issuance input is not canonical");
        return NULL;
    }
    if (v2_random(session, sizeof(session)) < 0 ||
            v2_random(key, sizeof(key)) < 0 ||
            v2_random(registration, sizeof(registration)) < 0 ||
            v2_random(checkpoint, sizeof(checkpoint)) < 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "TEST_ONLY broker v2 randomness failed");
        goto fail;
    }
    memset(nonce, 0, sizeof(nonce));
    memset(wrong, 0xa5, sizeof(wrong));
    if (plamen_broker_v2_request_projection_derive_exact(
            request_projection, sizeof(request_projection) - 1U,
            &commitment, auth_payload, sizeof(auth_payload),
            &auth_payload_size, projection_sha256,
            commitment_sha256) != PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(commitment.request_fingerprint,
                               fingerprint, 32) ||
            (size_t)attempt_len >= sizeof(commitment.attempt_id) ||
            commitment.attempt_id[attempt_len] != '\0' ||
            memcmp(commitment.attempt_id, attempt,
                   (size_t)attempt_len) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "TEST_ONLY native session construction failed");
        goto fail;
    }
    authority_binding.role = mutation == 22
        ? PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER
        : PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    if (mutation == 35) {
        authority_binding.role = PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER;
    }
    authority_binding.member_count = authority_binding.role ==
            PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR
        ? PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT
        : PLAMEN_BROKER_V2_GUEST_AUTHORITY_MEMBER_COUNT;
    memcpy(authority_binding.registration_sha256, registration, 32);
    memcpy(authority_binding.issuance_checkpoint_sha256, checkpoint, 32);
    if (mutation == 36) {
        memcpy(authority_binding.registration_sha256, wrong, 32);
    }
    if (mutation == 37) {
        memcpy(authority_binding.issuance_checkpoint_sha256, wrong, 32);
    }
    for (index = 0; index < authority_binding.member_count; index++) {
        memset(authority_binding.member_sha256[index],
               (int)(0x20U + index), 32);
    }
    payload = (unsigned char *)malloc(
        PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE);
    if (payload == NULL) {
        PyErr_NoMemory();
        goto fail;
    }
    if (plamen_broker_v2_authority_bundle_binding_encode(
            &authority_binding, payload,
            PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE,
            &payload_size) != PLAMEN_BROKER_V2_OK) {
        PyErr_SetString(PyExc_RuntimeError,
                        "TEST_ONLY authority binding encoding failed");
        goto fail;
    }
    if (mutation == 39) {
        payload[5] ^= 1U;
    }
    if (mutation == 40) {
        memcpy(payload + 72U + 32U, payload + 72U, 32U);
    }
    if (mutation == 41) {
        memset(payload + 72U, 0, 32U);
    }
    v2_sha256_bytes(payload, payload_size, bundle_digest);
    if (v2_make_frame(&hello, &hello_size, PLAMEN_BROKER_V2_HELLO, 0, 0,
                      session, zeros, zeros, key, NULL, 0) < 0) {
        PyErr_NoMemory();
        goto fail;
    }
    v2_sha256_bytes(hello, hello_size, hello_digest);
    if (v2_make_frame(
            &projection_request_frame, &projection_request_frame_size,
            PLAMEN_BROKER_V2_REQUEST_PROJECTION, 1, 0,
            session, zeros, hello_digest, key, NULL, 0) < 0) {
        PyErr_NoMemory();
        goto fail;
    }
    v2_sha256_bytes(projection_request_frame, projection_request_frame_size,
                    projection_request_digest);
    v2_sha256_bytes(request_projection,
                    sizeof(request_projection) - 1U,
                    projection_sha256);
    if (v2_make_frame(
            &projected, &projected_size,
            PLAMEN_BROKER_V2_REQUEST_PROJECTED, 2, 0,
            session, zeros, projection_request_digest, key,
            request_projection, sizeof(request_projection) - 1U) < 0) {
        PyErr_NoMemory();
        goto fail;
    }
    if (mutation == 23) projected[164] ^= 1U;
    if (mutation == 24) {
        projected[PLAMEN_BROKER_V2_HEADER_SIZE] ^= 1U;
    }
    if (mutation == 28) {
        v2_put_u64(projected + 28, 3);
        v2_hmac_sha256(key, projected,
                       projected + PLAMEN_BROKER_V2_HEADER_SIZE,
                       sizeof(request_projection) - 1U, projected + 164);
    }
    if (mutation == 29) {
        memcpy(projected + 100, wrong, 32);
        v2_hmac_sha256(key, projected,
                       projected + PLAMEN_BROKER_V2_HEADER_SIZE,
                       sizeof(request_projection) - 1U, projected + 164);
    }
    if (mutation == 30) {
        memcpy(projected + 36, wrong, 32);
        v2_hmac_sha256(key, projected,
                       projected + PLAMEN_BROKER_V2_HEADER_SIZE,
                       sizeof(request_projection) - 1U, projected + 164);
    }
    if (mutation == 31) {
        memcpy(projected + 68, wrong, 32);
        v2_hmac_sha256(key, projected,
                       projected + PLAMEN_BROKER_V2_HEADER_SIZE,
                       sizeof(request_projection) - 1U, projected + 164);
    }
    if (mutation == 32) {
        v2_put_u16(projected + 24, 1);
        v2_hmac_sha256(key, projected,
                       projected + PLAMEN_BROKER_V2_HEADER_SIZE,
                       sizeof(request_projection) - 1U, projected + 164);
    }
    if (mutation == 34) {
        projected[PLAMEN_BROKER_V2_HEADER_SIZE] = '[';
        v2_sha256_bytes(projected + PLAMEN_BROKER_V2_HEADER_SIZE,
                        sizeof(request_projection) - 1U, projected + 132);
        v2_hmac_sha256(key, projected,
                       projected + PLAMEN_BROKER_V2_HEADER_SIZE,
                       sizeof(request_projection) - 1U, projected + 164);
        v2_sha256_bytes(projected + PLAMEN_BROKER_V2_HEADER_SIZE,
                        sizeof(request_projection) - 1U,
                        projection_sha256);
    }
    v2_sha256_bytes(projected, projected_size, projected_digest);
    if (v2_make_frame(
            &auth_frame, &auth_frame_size, PLAMEN_BROKER_V2_AUTH_CONSUME,
            3, 0, session, zeros, projected_digest, key,
            auth_payload, auth_payload_size) < 0) {
        PyErr_NoMemory();
        goto fail;
    }
    v2_sha256_bytes(auth_frame, auth_frame_size, auth_digest);

    if (mutation == 19) { /* hello_fd */
        if (pipe(auxiliary[0]) != 0) {
            PyErr_SetFromErrno(PyExc_OSError);
            goto fail;
        }
        sent_fds[0] = auxiliary[0][0];
        v2_put_u16(hello + 24, 1);
        v2_hmac_sha256(key, hello, NULL, 0, hello + 164);
        v2_sha256_bytes(hello, hello_size, hello_digest);
    }
    if (mutation == 1) { /* hello_bad_tag */
        hello[164] ^= 1U;
        v2_sha256_bytes(hello, hello_size, hello_digest);
    }

    declared_count = 0;
    sent_count = 0;
    if (mutation == 16) { /* fd_missing */
        declared_count = 1;
    } else if (mutation == 17 || mutation == 18) { /* surplus or alias */
        declared_count = mutation == 17 ? 0 : 2;
        if (pipe(auxiliary[0]) != 0) {
            PyErr_SetFromErrno(PyExc_OSError);
            goto fail;
        }
        sent_fds[0] = auxiliary[0][0];
        sent_count = 1;
        if (mutation == 18) {
            sent_fds[1] = auxiliary[0][0];
            sent_count = 2;
        }
    }
    if (v2_make_frame(
            &accepted, &accepted_size, PLAMEN_BROKER_V2_AUTH_ACCEPTED,
            mutation == 9 ? 5 : mutation == 10 ? 3 : 4,
            declared_count,
            mutation == 12 ? wrong : session,
            mutation == 13 ? wrong : zeros,
            mutation == 11 ? wrong : auth_digest,
            key, payload, payload_size) < 0) {
        PyErr_NoMemory();
        goto fail;
    }
    if (mutation == 2) accepted[0] ^= 1U;
    if (mutation == 3) v2_put_u16(accepted + 8, 3);
    if (mutation == 4) v2_put_u32(accepted + 12, 1);
    if (mutation == 5) v2_put_u32(accepted + 16, 195);
    if (mutation == 6) v2_put_u32(accepted + 20, (uint32_t)payload_size - 1U);
    if (mutation == 7) accepted[132] ^= 1U;
    if (mutation == 8) accepted[164] ^= 1U;
    if (mutation == 6) {
        /* Header has already been authenticated for the original exact size. */
    }
    if (mutation == 14) { /* trailing */
        unsigned char *replacement =
            (unsigned char *)realloc(accepted, accepted_size + 1U);
        if (replacement == NULL) {
            PyErr_NoMemory();
            goto fail;
        }
        accepted = replacement;
        accepted[accepted_size++] = 0xeeU;
    }
    if (mutation == 20) { /* replay */
        unsigned char *replacement =
            (unsigned char *)malloc(accepted_size * 2U);
        if (replacement == NULL) {
            PyErr_NoMemory();
            goto fail;
        }
        memcpy(replacement, accepted, accepted_size);
        memcpy(replacement + accepted_size, accepted, accepted_size);
        free(accepted);
        accepted = replacement;
        accepted_size *= 2U;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
            v2_set_cloexec(sockets[0]) < 0 ||
            v2_set_cloexec(sockets[1]) < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto fail;
    }
    if (mutation == 32 && pipe(auxiliary[1]) != 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto fail;
    }
    if (mutation == 19) {
        sent_fds[0] = auxiliary[0][0];
        sent_count = 1;
    } else if (mutation != 17 && mutation != 18) {
        sent_count = 0;
    }
    if (v2_send_frame(sockets[1], hello, hello_size,
                      mutation == 19 ? sent_fds : NULL,
                      mutation == 19 ? sent_count : 0) < 0) {
        PyErr_SetString(PyExc_RuntimeError, "TEST_ONLY broker v2 send failed");
        goto fail;
    }
    if (mutation == 19) {
        sent_count = 0;
    } else if (mutation == 17 || mutation == 18) {
        sent_count = mutation == 17 ? 1 : 2;
        sent_fds[0] = auxiliary[0][0];
        if (mutation == 18) sent_fds[1] = auxiliary[0][0];
    }
    if (v2_send_frame(
            sockets[1], projected,
            mutation == 33 ? PLAMEN_BROKER_V2_HEADER_SIZE / 2U
                           : projected_size,
            mutation == 32 ? auxiliary[1] : NULL,
            mutation == 32 ? 1U : 0U) < 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "TEST_ONLY broker v2 projection send failed");
        goto fail;
    }
    if (mutation == 15) { /* truncated */
        accepted_size = PLAMEN_BROKER_V2_HEADER_SIZE / 2U;
    }
    if (v2_send_frame(sockets[1], accepted, accepted_size,
                      sent_count != 0 ? sent_fds : NULL, sent_count) < 0) {
        PyErr_SetString(PyExc_RuntimeError, "TEST_ONLY broker v2 send failed");
        goto fail;
    }
    (void)shutdown(sockets[1], SHUT_WR);

    if (mutation == 27) {
        v2_close_fds(sockets, 2);
        sockets[0] = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockets[0] < 0 || v2_set_cloexec(sockets[0]) < 0) {
            PyErr_SetFromErrno(PyExc_OSError);
            goto fail;
        }
    }

    consumer = (V2AuthorityConsumerObject *)
        v2_new_consumer_from_native_session(
            sockets[0], sockets[1],
            mutation == 22 ? PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER
                           : PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR,
            key, session, zeros, fingerprint,
            attempt, (size_t)attempt_len, auth_payload, auth_payload_size,
            registration, checkpoint, mutation == 38 ? wrong : bundle_digest,
            mutation == 25 ? wrong : projection_sha256,
            (uint32_t)(sizeof(request_projection) - 1U) +
                (mutation == 26 ? 1U : 0U),
            registration, commitment.runtime_closure_sha256,
            checkpoint, bundle_digest);
    if (consumer == NULL) {
        sockets[0] = -1;
        sockets[1] = -1;
        if (!PyErr_Occurred()) {
            PyErr_SetString(PyExc_RuntimeError,
                            "TEST_ONLY native session construction failed");
        }
        goto fail;
    }
    sockets[0] = -1;
    sockets[1] = -1;
    consumer->creator_pid = creator_pid_override >= 0
                                ? (pid_t)creator_pid_override : getpid();
    consumer->creator_interpreter_id = creator_interpreter_override >= 0
        ? (int64_t)creator_interpreter_override : current_interpreter_id();
    if (mutation == 21) {
        /* Inject a role that can never be an INITIAL_AUTHORITY. */
        consumer->initial_authority_role =
            PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION;
    }

    secure_zero(key, sizeof(key));
    secure_zero(session, sizeof(session));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(fingerprint, sizeof(fingerprint));
    secure_zero(registration, sizeof(registration));
    secure_zero(bundle_digest, sizeof(bundle_digest));
    secure_zero(checkpoint, sizeof(checkpoint));
    secure_zero(hello_digest, sizeof(hello_digest));
    secure_zero(projection_sha256, sizeof(projection_sha256));
    secure_zero(projection_request_digest, sizeof(projection_request_digest));
    secure_zero(projected_digest, sizeof(projected_digest));
    secure_zero(auth_digest, sizeof(auth_digest));
    secure_zero(commitment_sha256, sizeof(commitment_sha256));
    secure_zero(auth_payload, sizeof(auth_payload));
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    plamen_broker_v2_secure_zero(&authority_binding,
                                 sizeof(authority_binding));
    if (hello != NULL) { secure_zero(hello, hello_size); free(hello); }
    if (projection_request_frame != NULL) {
        secure_zero(projection_request_frame, projection_request_frame_size);
        free(projection_request_frame);
    }
    if (projected != NULL) {
        secure_zero(projected, projected_size);
        free(projected);
    }
    if (auth_frame != NULL) {
        secure_zero(auth_frame, auth_frame_size);
        free(auth_frame);
    }
    if (accepted != NULL) { secure_zero(accepted, accepted_size); free(accepted); }
    if (payload != NULL) { secure_zero(payload, payload_size); free(payload); }
    for (index = 0; index < PLAMEN_BROKER_V2_MAX_FDS + 1U; index++) {
        v2_close_fds(auxiliary[index], 2);
    }
    return (PyObject *)consumer;

fail:
    if (consumer != NULL) Py_DECREF(consumer);
    v2_close_fds(sockets, 2);
    for (index = 0; index < PLAMEN_BROKER_V2_MAX_FDS + 1U; index++) {
        v2_close_fds(auxiliary[index], 2);
    }
    if (hello != NULL) { secure_zero(hello, hello_size); free(hello); }
    if (projection_request_frame != NULL) {
        secure_zero(projection_request_frame, projection_request_frame_size);
        free(projection_request_frame);
    }
    if (projected != NULL) {
        secure_zero(projected, projected_size);
        free(projected);
    }
    if (auth_frame != NULL) {
        secure_zero(auth_frame, auth_frame_size);
        free(auth_frame);
    }
    if (accepted != NULL) { secure_zero(accepted, accepted_size); free(accepted); }
    if (payload != NULL) { secure_zero(payload, payload_size); free(payload); }
    secure_zero(key, sizeof(key));
    secure_zero(session, sizeof(session));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(fingerprint, sizeof(fingerprint));
    secure_zero(registration, sizeof(registration));
    secure_zero(bundle_digest, sizeof(bundle_digest));
    secure_zero(checkpoint, sizeof(checkpoint));
    secure_zero(hello_digest, sizeof(hello_digest));
    secure_zero(projection_sha256, sizeof(projection_sha256));
    secure_zero(projection_request_digest, sizeof(projection_request_digest));
    secure_zero(projected_digest, sizeof(projected_digest));
    secure_zero(auth_digest, sizeof(auth_digest));
    secure_zero(commitment_sha256, sizeof(commitment_sha256));
    secure_zero(auth_payload, sizeof(auth_payload));
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    plamen_broker_v2_secure_zero(&authority_binding,
                                 sizeof(authority_binding));
    return NULL;
}

static PyObject *
test_only_issue_specialized_bridge_authorities(PyObject *module, PyObject *args)
{
    PyObject *initial;
    PlamenBridgeCapabilityObject *js_authority, *managed_authority;
    PyObject *result;
    (void)module;
    if (!PyArg_ParseTuple(args, "O:TEST_ONLY_issue_specialized_bridge_authorities",
                          &initial)) {
        return NULL;
    }
    if (!bridge_initial_consumer_live(initial)) {
        return NULL;
    }
    js_authority = bridge_new(&JSDependencyMaterializerAuthorityType,
                              PLAMEN_BRIDGE_JS_AUTHORITY,
                              initial, initial, NULL, NULL);
    if (js_authority == NULL) {
        return NULL;
    }
    managed_authority = bridge_new(&ManagedEVMToolchainInitialAuthorityType,
                                   PLAMEN_BRIDGE_MANAGED_INITIAL,
                                   initial, initial, NULL, NULL);
    if (managed_authority == NULL) {
        Py_DECREF(js_authority);
        return NULL;
    }
    result = PyTuple_Pack(2, js_authority, managed_authority);
    Py_DECREF(js_authority);
    Py_DECREF(managed_authority);
    return result;
}

static PyMethodDef test_only_module_methods[] = {
    {"TEST_ONLY_issue_specialized_bridge_authorities",
     test_only_issue_specialized_bridge_authorities, METH_VARARGS, NULL},
    {"authenticate_js_dependency_materializer_capability",
     authenticate_js_dependency_materializer_capability, METH_VARARGS, NULL},
    {"js_dependency_materializer_runtime_identity",
     js_dependency_materializer_runtime_identity, METH_VARARGS, NULL},
    {"prepare_js_dependency_materializer_execution",
     prepare_js_dependency_materializer_execution, METH_VARARGS, NULL},
    {"execute_js_dependency_materializer",
     execute_js_dependency_materializer, METH_VARARGS, NULL},
    {"replay_js_dependency_materializer_terminal",
     replay_js_dependency_materializer_terminal, METH_VARARGS, NULL},
    {"managed_evm_toolchain_runtime_identity",
     managed_evm_toolchain_runtime_identity, METH_VARARGS, NULL},
    {"prepare_managed_evm_toolchain_provision",
     prepare_managed_evm_toolchain_provision, METH_VARARGS, NULL},
    {"execute_managed_evm_toolchain_provision",
     execute_managed_evm_toolchain_provision, METH_VARARGS, NULL},
    {"project_managed_evm_toolchain_terminal",
     project_managed_evm_toolchain_terminal, METH_VARARGS, NULL},
    {"project_evm_analysis_projection_receipt",
     project_evm_analysis_projection_receipt, METH_VARARGS, NULL},
    {"project_evm_analysis_projection_lineage",
     project_evm_analysis_projection_lineage, METH_VARARGS, NULL},
    {"project_evm_analysis_projection_workspace_binding",
     project_evm_analysis_projection_workspace_binding, METH_VARARGS, NULL},
    {"commit_evm_analysis_projection",
     commit_evm_analysis_projection, METH_VARARGS, NULL},
    {"recover_evm_analysis_projection_authority",
     recover_evm_analysis_projection_authority, METH_VARARGS, NULL},
    {"darwin_tool_runtime_identity",
     darwin_tool_runtime_identity, METH_VARARGS, NULL},
    {"acquire_darwin_tool_custody",
     acquire_darwin_tool_custody, METH_VARARGS, NULL},
    {"prepare_darwin_tool_execution",
     prepare_darwin_tool_execution, METH_VARARGS, NULL},
    {"project_darwin_fuzz_campaign_prepared",
     project_darwin_fuzz_campaign_prepared, METH_VARARGS, NULL},
    {"execute_darwin_tool", execute_darwin_tool, METH_VARARGS, NULL},
    {"execute_darwin_fuzz_campaign", execute_darwin_fuzz_campaign,
     METH_VARARGS, NULL},
    {"project_darwin_tool_execution_terminal",
     project_darwin_tool_execution_terminal, METH_VARARGS, NULL},
    {"acquire_apple_fuzz_service_session",
     acquire_apple_fuzz_service_session, METH_VARARGS, NULL},
    {"admit_apple_fuzz_campaign",
     admit_apple_fuzz_campaign, METH_VARARGS, NULL},
    {"project_apple_fuzz_secure_receipt",
     project_apple_fuzz_secure_receipt, METH_VARARGS, NULL},
    {"execute_admitted_apple_fuzz_campaign",
     execute_admitted_apple_fuzz_campaign, METH_VARARGS, NULL},
    {"project_admitted_apple_fuzz_terminal",
     project_admitted_apple_fuzz_terminal, METH_VARARGS, NULL},
    {"native_specialized_bridge_status",
     native_specialized_bridge_status, METH_VARARGS, NULL},
    {"TEST_ONLY_create_consumer",
     (PyCFunction)(void (*)(void))test_only_create_consumer,
     METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("Create the distinct TEST_ONLY consumer type.")},
    {"TEST_ONLY_issue_broker_v2",
     (PyCFunction)(void (*)(void))test_only_issue_broker_v2,
     METH_VARARGS | METH_KEYWORDS,
     PyDoc_STR("Issue a complete native-held TEST_ONLY broker v2 session.")},
    {"TEST_ONLY_broker_v2_crypto_kat",
     test_only_broker_v2_crypto_kat, METH_VARARGS,
     PyDoc_STR("Return public fixed-vector SHA-256/HMAC results.")},
    {NULL, NULL, 0, NULL}
};

#endif /* PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY */

#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
static PyMethodDef production_module_methods[] = {
    {"acquire_backend_install_generation",
     acquire_backend_install_generation, METH_VARARGS, NULL},
    {"project_backend_install_generation",
     project_backend_install_generation, METH_VARARGS, NULL},
    {"authenticate_js_dependency_materializer_capability",
     authenticate_js_dependency_materializer_capability, METH_VARARGS, NULL},
    {"js_dependency_materializer_runtime_identity",
     js_dependency_materializer_runtime_identity, METH_VARARGS, NULL},
    {"prepare_js_dependency_materializer_execution",
     prepare_js_dependency_materializer_execution, METH_VARARGS, NULL},
    {"execute_js_dependency_materializer",
     execute_js_dependency_materializer, METH_VARARGS, NULL},
    {"replay_js_dependency_materializer_terminal",
     replay_js_dependency_materializer_terminal, METH_VARARGS, NULL},
    {"managed_evm_toolchain_runtime_identity",
     managed_evm_toolchain_runtime_identity, METH_VARARGS, NULL},
    {"prepare_managed_evm_toolchain_provision",
     prepare_managed_evm_toolchain_provision, METH_VARARGS, NULL},
    {"execute_managed_evm_toolchain_provision",
     execute_managed_evm_toolchain_provision, METH_VARARGS, NULL},
    {"project_managed_evm_toolchain_terminal",
     project_managed_evm_toolchain_terminal, METH_VARARGS, NULL},
    {"project_evm_analysis_projection_receipt",
     project_evm_analysis_projection_receipt, METH_VARARGS, NULL},
    {"project_evm_analysis_projection_lineage",
     project_evm_analysis_projection_lineage, METH_VARARGS, NULL},
    {"project_evm_analysis_projection_workspace_binding",
     project_evm_analysis_projection_workspace_binding, METH_VARARGS, NULL},
    {"commit_evm_analysis_projection",
     commit_evm_analysis_projection, METH_VARARGS, NULL},
    {"recover_evm_analysis_projection_authority",
     recover_evm_analysis_projection_authority, METH_VARARGS, NULL},
    {"darwin_tool_runtime_identity",
     darwin_tool_runtime_identity, METH_VARARGS, NULL},
    {"acquire_darwin_tool_custody",
     acquire_darwin_tool_custody, METH_VARARGS, NULL},
    {"prepare_darwin_tool_execution",
     prepare_darwin_tool_execution, METH_VARARGS, NULL},
    {"project_darwin_fuzz_campaign_prepared",
     project_darwin_fuzz_campaign_prepared, METH_VARARGS, NULL},
    {"execute_darwin_tool", execute_darwin_tool, METH_VARARGS, NULL},
    {"execute_darwin_fuzz_campaign", execute_darwin_fuzz_campaign,
     METH_VARARGS, NULL},
    {"project_darwin_tool_execution_terminal",
     project_darwin_tool_execution_terminal, METH_VARARGS, NULL},
    {"acquire_apple_fuzz_service_session",
     acquire_apple_fuzz_service_session, METH_VARARGS, NULL},
    {"admit_apple_fuzz_campaign",
     admit_apple_fuzz_campaign, METH_VARARGS, NULL},
    {"project_apple_fuzz_secure_receipt",
     project_apple_fuzz_secure_receipt, METH_VARARGS, NULL},
    {"execute_admitted_apple_fuzz_campaign",
     execute_admitted_apple_fuzz_campaign, METH_VARARGS, NULL},
    {"project_admitted_apple_fuzz_terminal",
     project_admitted_apple_fuzz_terminal, METH_VARARGS, NULL},
    {"native_specialized_bridge_status",
     native_specialized_bridge_status, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};
#endif

#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
typedef struct {
    int control_fd;
    uint16_t initial_authority_role;
    unsigned char key[32];
    unsigned char session_id[32];
    unsigned char operation_nonce[32];
    unsigned char fingerprint[32];
    unsigned char registration_sha256[32];
    unsigned char issuance_checkpoint_sha256[32];
    unsigned char authority_bundle_sha256[32];
    unsigned char request_projection_sha256[32];
    unsigned char native_deployment_receipt_sha256[32];
    unsigned char runtime_closure_sha256[32];
    unsigned char broker_peer_identity_sha256[32];
    unsigned char managed_toolchain_custody_sha256[32];
    unsigned char extension_closure_sha256[32];
    unsigned char interpreter_executable_sha256[32];
#ifdef __linux__
    uint16_t linux_scope;
    uint64_t linux_expected_uid;
    unsigned char linux_broker_executable_identity[32];
    unsigned char linux_interpreter_executable_identity[32];
#endif
    uint32_t request_projection_size;
    char attempt[129];
    size_t attempt_size;
    unsigned char auth_payload[PLAMEN_BROKER_V2_AUTH_PAYLOAD_MAX];
    size_t auth_payload_size;
} V2NativeBootstrapSession;

static _Atomic int v2_initial_acquisition_attempted = 0;

static void
v2_native_bootstrap_clear(V2NativeBootstrapSession *session)
{
    if (session->control_fd >= 0) {
        (void)close(session->control_fd);
        session->control_fd = -1;
    }
    secure_zero(session->key, sizeof(session->key));
    secure_zero(session->session_id, sizeof(session->session_id));
    secure_zero(session->operation_nonce, sizeof(session->operation_nonce));
    secure_zero(session->fingerprint, sizeof(session->fingerprint));
    secure_zero(session->registration_sha256,
                sizeof(session->registration_sha256));
    secure_zero(session->issuance_checkpoint_sha256,
                sizeof(session->issuance_checkpoint_sha256));
    secure_zero(session->authority_bundle_sha256,
                sizeof(session->authority_bundle_sha256));
    secure_zero(session->request_projection_sha256,
                sizeof(session->request_projection_sha256));
    secure_zero(session->native_deployment_receipt_sha256,
                sizeof(session->native_deployment_receipt_sha256));
    secure_zero(session->runtime_closure_sha256,
                sizeof(session->runtime_closure_sha256));
    secure_zero(session->broker_peer_identity_sha256,
                sizeof(session->broker_peer_identity_sha256));
    secure_zero(session->extension_closure_sha256,
                sizeof(session->extension_closure_sha256));
    secure_zero(session->interpreter_executable_sha256,
                sizeof(session->interpreter_executable_sha256));
#ifdef __linux__
    session->linux_scope = 0;
    session->linux_expected_uid = 0;
    secure_zero(session->linux_broker_executable_identity,
                sizeof(session->linux_broker_executable_identity));
    secure_zero(session->linux_interpreter_executable_identity,
                sizeof(session->linux_interpreter_executable_identity));
#endif
    secure_zero(session->managed_toolchain_custody_sha256,
                sizeof(session->managed_toolchain_custody_sha256));
    session->request_projection_size = 0;
    secure_zero(session->attempt, sizeof(session->attempt));
    secure_zero(session->auth_payload, sizeof(session->auth_payload));
    session->attempt_size = 0;
    session->auth_payload_size = 0;
}

#ifdef __APPLE__

#define PLAMEN_V2_DARWIN_XPC_TIMEOUT_NS \
    (UINT64_C(5) * NSEC_PER_SEC)

typedef struct {
    struct plamen_install_receipt receipt;
    int install_root_fd;
    int receipt_fd;
    int generation_fd;
    int member_fds[PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT];
    unsigned char receipt_bytes[PLAMEN_INSTALL_RECEIPT_SIZE];
    unsigned char receipt_sha256[32];
    char broker_requirement[512];
} V2DarwinInstallAuthority;

static int
v2_darwin_same_stat(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev &&
        left->st_ino == right->st_ino &&
        left->st_mode == right->st_mode &&
        left->st_uid == right->st_uid &&
        left->st_gid == right->st_gid &&
        left->st_nlink == right->st_nlink &&
        left->st_size == right->st_size &&
        left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec &&
        left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
        left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
        left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
}

static int
v2_darwin_open_absolute_directory(const char *path, int *result_fd)
{
    char copy[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char *component, *separator;
    size_t length;
    int current = -1, child = -1, status = -1;

    if (result_fd == NULL) {
        return -1;
    }
    *result_fd = -1;
    if (path == NULL || path[0] != '/' ||
            (length = strlen(path)) < 2 || length >= sizeof(copy) ||
            path[length - 1] == '/') {
        return -1;
    }
    memcpy(copy, path + 1, length);
    current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0) {
        goto done;
    }
    component = copy;
    for (;;) {
        separator = strchr(component, '/');
        if (separator != NULL) {
            *separator = '\0';
        }
        if (component[0] == '\0' || strcmp(component, ".") == 0 ||
                strcmp(component, "..") == 0) {
            goto done;
        }
        child = openat(current, component,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child < 0) {
            goto done;
        }
        (void)close(current);
        current = child;
        child = -1;
        if (separator == NULL) {
            break;
        }
        component = separator + 1;
    }
    *result_fd = current;
    current = -1;
    status = 0;

done:
    if (child >= 0) {
        (void)close(child);
    }
    if (current >= 0) {
        (void)close(current);
    }
    secure_zero(copy, sizeof(copy));
    return status;
}

static int
v2_darwin_open_relative_file(int root_fd, const char *relative,
                             int *result_fd)
{
    char copy[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char *component, *separator;
    size_t length;
    int current = -1, child = -1, status = -1;

    if (result_fd == NULL) {
        return -1;
    }
    *result_fd = -1;
    if (root_fd < 0 || relative == NULL || relative[0] == '\0' ||
            relative[0] == '/' ||
            (length = strlen(relative)) >= sizeof(copy)) {
        return -1;
    }
    memcpy(copy, relative, length + 1U);
    current = openat(root_fd, ".",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0) {
        goto done;
    }
    component = copy;
    for (;;) {
        separator = strchr(component, '/');
        if (separator != NULL) {
            *separator = '\0';
        }
        if (component[0] == '\0' || strcmp(component, ".") == 0 ||
                strcmp(component, "..") == 0) {
            goto done;
        }
        if (separator == NULL) {
            child = openat(current, component,
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        } else {
            child = openat(current, component,
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
        if (child < 0) {
            goto done;
        }
        if (separator == NULL) {
            *result_fd = child;
            child = -1;
            status = 0;
            break;
        }
        (void)close(current);
        current = child;
        child = -1;
        component = separator + 1;
    }

done:
    if (child >= 0) {
        (void)close(child);
    }
    if (current >= 0) {
        (void)close(current);
    }
    secure_zero(copy, sizeof(copy));
    return status;
}

static int
v2_darwin_read_receipt_exact(
        int fd, unsigned char output[PLAMEN_INSTALL_RECEIPT_SIZE])
{
    struct stat before, after;
    unsigned char extra;
    size_t offset = 0;
    ssize_t amount;

    if (fd < 0 || output == NULL || fstat(fd, &before) != 0 ||
            !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
            before.st_uid != geteuid() || (before.st_mode & 0777) != 0400 ||
            before.st_size != (off_t)PLAMEN_INSTALL_RECEIPT_SIZE) {
        return -1;
    }
    while (offset < PLAMEN_INSTALL_RECEIPT_SIZE) {
        do {
            amount = pread(fd, output + offset,
                           PLAMEN_INSTALL_RECEIPT_SIZE - offset,
                           (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0) {
            return -1;
        }
        offset += (size_t)amount;
    }
    do {
        amount = pread(fd, &extra, 1, (off_t)PLAMEN_INSTALL_RECEIPT_SIZE);
    } while (amount < 0 && errno == EINTR);
    return amount == 0 && fstat(fd, &after) == 0 &&
        v2_darwin_same_stat(&before, &after) ? 0 : -1;
}

static void
v2_darwin_hex(const unsigned char *bytes, size_t size, char *output)
{
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < size; index++) {
        output[index * 2U] = alphabet[bytes[index] >> 4];
        output[index * 2U + 1U] = alphabet[bytes[index] & 0x0fU];
    }
    output[size * 2U] = '\0';
}

static void
v2_darwin_install_clear(V2DarwinInstallAuthority *authority)
{
    size_t index;
    if (authority == NULL) {
        return;
    }
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; index++) {
        if (authority->member_fds[index] >= 0) {
            (void)close(authority->member_fds[index]);
            authority->member_fds[index] = -1;
        }
    }
    if (authority->generation_fd >= 0) {
        (void)close(authority->generation_fd);
        authority->generation_fd = -1;
    }
    if (authority->receipt_fd >= 0) {
        (void)close(authority->receipt_fd);
        authority->receipt_fd = -1;
    }
    if (authority->install_root_fd >= 0) {
        (void)close(authority->install_root_fd);
        authority->install_root_fd = -1;
    }
    plamen_broker_v2_secure_zero(&authority->receipt,
                                 sizeof(authority->receipt));
    secure_zero(authority->receipt_bytes, sizeof(authority->receipt_bytes));
    secure_zero(authority->receipt_sha256,
                sizeof(authority->receipt_sha256));
    secure_zero(authority->broker_requirement,
                sizeof(authority->broker_requirement));
}

static int
v2_darwin_current_binaries_match(V2DarwinInstallAuthority *authority)
{
    Dl_info extension_info;
    struct stat observed, retained;
    char executable_path[PROC_PIDPATHINFO_MAXSIZE];
    int extension_fd = -1, executable_fd = -1, status = -1;

    memset(&extension_info, 0, sizeof(extension_info));
    memset(executable_path, 0, sizeof(executable_path));
    if (dladdr((const void *)&v2_darwin_current_binaries_match,
               &extension_info) == 0 || extension_info.dli_fname == NULL ||
            proc_pidpath(getpid(), executable_path,
                         (uint32_t)sizeof(executable_path)) <= 0) {
        goto done;
    }
    extension_fd = open(extension_info.dli_fname,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    executable_fd = open(executable_path,
                         O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (extension_fd < 0 || executable_fd < 0 ||
            fstat(extension_fd, &observed) != 0 ||
            fstat(authority->member_fds[
                PLAMEN_INSTALL_MEMBER_EXTENSION - 1], &retained) != 0 ||
            observed.st_dev != retained.st_dev ||
            observed.st_ino != retained.st_ino ||
            fstat(executable_fd, &observed) != 0 ||
            fstat(authority->member_fds[
                PLAMEN_INSTALL_MEMBER_PYTHON - 1], &retained) != 0 ||
            observed.st_dev != retained.st_dev ||
            observed.st_ino != retained.st_ino ||
            plamen_install_receipt_member_revalidate(
                authority->member_fds[PLAMEN_INSTALL_MEMBER_EXTENSION - 1],
                &authority->receipt.members[
                    PLAMEN_INSTALL_MEMBER_EXTENSION - 1]) != 0 ||
            plamen_install_receipt_member_revalidate(
                authority->member_fds[PLAMEN_INSTALL_MEMBER_PYTHON - 1],
                &authority->receipt.members[
                    PLAMEN_INSTALL_MEMBER_PYTHON - 1]) != 0) {
        goto done;
    }
    status = 0;

done:
    if (extension_fd >= 0) {
        (void)close(extension_fd);
    }
    if (executable_fd >= 0) {
        (void)close(executable_fd);
    }
    secure_zero(executable_path, sizeof(executable_path));
    return status;
}

/* Return 1 for an admitted receipt, 0 for no installed receipt, -1 invalid. */
static int
v2_darwin_install_open(V2DarwinInstallAuthority *authority)
{
    struct passwd password, *password_result = NULL;
    struct stat root_info;
    unsigned char projection_schema_sha256[32];
    char password_buffer[4096];
    char install_root[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char generation_hex[65];
    char generation_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char cdhash_hex[PLAMEN_INSTALL_RECEIPT_CDHASH_MAX * 2U + 1U];
    size_t index;
    int generations_fd = -1, status = -1;

    memset(authority, 0, sizeof(*authority));
    authority->install_root_fd = -1;
    authority->receipt_fd = -1;
    authority->generation_fd = -1;
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; index++) {
        authority->member_fds[index] = -1;
    }
    memset(projection_schema_sha256, 0, sizeof(projection_schema_sha256));
    memset(password_buffer, 0, sizeof(password_buffer));
    memset(install_root, 0, sizeof(install_root));
    memset(generation_path, 0, sizeof(generation_path));
    memset(cdhash_hex, 0, sizeof(cdhash_hex));
    if (getpwuid_r(getuid(), &password, password_buffer,
                   sizeof(password_buffer), &password_result) != 0 ||
            password_result == NULL || password.pw_dir == NULL ||
            snprintf(install_root, sizeof(install_root),
                     "%s/.local/share/plamen", password.pw_dir) >=
                (int)sizeof(install_root) ||
            v2_darwin_open_absolute_directory(
                install_root, &authority->install_root_fd) != 0) {
        status = 0;
        goto done;
    }
    if (v2_darwin_open_relative_file(
            authority->install_root_fd,
            PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH,
            &authority->receipt_fd) != 0) {
        status = errno == ENOENT ? 0 : -1;
        goto done;
    }
    if (fstat(authority->install_root_fd, &root_info) != 0 ||
            !S_ISDIR(root_info.st_mode) || root_info.st_uid != geteuid() ||
            (root_info.st_mode & 0777) != 0700 ||
            v2_darwin_read_receipt_exact(
                authority->receipt_fd, authority->receipt_bytes) != 0 ||
            plamen_broker_v2_sha256(
                authority->receipt_bytes, sizeof(authority->receipt_bytes),
                authority->receipt_sha256) != PLAMEN_BROKER_V2_OK ||
            plamen_install_receipt_decode_exact(
                authority->receipt_bytes, sizeof(authority->receipt_bytes),
                &authority->receipt) != 0 ||
            authority->receipt.python_major != PY_MAJOR_VERSION ||
            authority->receipt.python_minor != PY_MINOR_VERSION ||
            authority->receipt.python_micro != PY_MICRO_VERSION ||
            strcmp(authority->receipt.python_abi_tag,
                   "cpython-312-darwin") != 0 ||
            plamen_broker_v2_sha256(
                PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA,
                strlen(PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA),
                projection_schema_sha256) != PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(
                projection_schema_sha256,
                authority->receipt.projection_schema_sha256, 32) ||
            !v2_constant_equal(
                authority->receipt.protocol_schema_sha256,
                authority->receipt.members[
                    PLAMEN_INSTALL_MEMBER_SHARED_ABI - 1].sha256, 32)) {
        goto done;
    }
    v2_darwin_hex(authority->receipt.generation_id_sha256, 32,
                  generation_hex);
    if (snprintf(generation_path, sizeof(generation_path),
                 "%s/generations/%s", install_root, generation_hex) >=
            (int)sizeof(generation_path) ||
            strcmp(generation_path, authority->receipt.generation_path) != 0) {
        goto done;
    }
    generations_fd = openat(authority->install_root_fd, "generations",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    authority->generation_fd = generations_fd < 0 ? -1 :
        openat(generations_fd, generation_hex,
               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (authority->generation_fd < 0) {
        goto done;
    }
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; index++) {
        if (plamen_install_receipt_open_member(
                authority->generation_fd, &authority->receipt.members[index],
                &authority->member_fds[index]) != 0) {
            goto done;
        }
    }
    if (v2_darwin_current_binaries_match(authority) != 0) {
        /* A retained test-shape or stale interpreter is not an admitted child. */
        status = 0;
        goto done;
    }
    if (authority->receipt.members[
            PLAMEN_INSTALL_MEMBER_SERVICE - 1].cdhash_size == 0) {
        goto done;
    }
    v2_darwin_hex(
        authority->receipt.members[
            PLAMEN_INSTALL_MEMBER_SERVICE - 1].cdhash,
        authority->receipt.members[
            PLAMEN_INSTALL_MEMBER_SERVICE - 1].cdhash_size,
        cdhash_hex);
    if (snprintf(authority->broker_requirement,
                 sizeof(authority->broker_requirement),
                 "identifier \"%s\" and cdhash H\"%s\"",
                 authority->receipt.members[
                    PLAMEN_INSTALL_MEMBER_SERVICE - 1].signing_identifier,
                 cdhash_hex) >= (int)sizeof(authority->broker_requirement)) {
        goto done;
    }
    status = 1;

done:
    if (generations_fd >= 0) {
        (void)close(generations_fd);
    }
    secure_zero(password_buffer, sizeof(password_buffer));
    secure_zero(install_root, sizeof(install_root));
    secure_zero(generation_hex, sizeof(generation_hex));
    secure_zero(generation_path, sizeof(generation_path));
    secure_zero(cdhash_hex, sizeof(cdhash_hex));
    secure_zero(projection_schema_sha256,
                sizeof(projection_schema_sha256));
    if (status != 1) {
        v2_darwin_install_clear(authority);
    }
    return status;
}

#ifdef PLAMEN_NATIVE_INSTALLED_BACKEND_GENERATION_ENABLED

#define PLAMEN_BACKEND_PRODUCER_RECEIPT_MAX (16U * 1024U * 1024U)
#define PLAMEN_BACKEND_SOURCE_MANIFEST_MAX (2U * 1024U * 1024U)

static int
v2_darwin_projection_backend_is(const V2AuthorityConsumerObject *initial,
                                const char *backend)
{
    static const unsigned char codex[] = "\"backend\":\"codex\"";
    static const unsigned char claude[] = "\"backend\":\"claude\"";
    const unsigned char *needle;
    size_t needle_size, index, matches = 0;
    if (initial == NULL || initial->request_projection == NULL ||
            (strcmp(backend, "codex") != 0 &&
             strcmp(backend, "claude") != 0)) {
        return 0;
    }
    needle = strcmp(backend, "codex") == 0 ? codex : claude;
    needle_size = strcmp(backend, "codex") == 0 ?
        sizeof(codex) - 1U : sizeof(claude) - 1U;
    if (initial->request_projection_size < needle_size) {
        return 0;
    }
    for (index = 0;
            index + needle_size <= initial->request_projection_size;
            index++) {
        if (memcmp(initial->request_projection + index,
                   needle, needle_size) == 0) {
            matches++;
        }
    }
    return matches == 1U;
}

static PyObject *
v2_darwin_read_bound_file(int fd, size_t maximum, const char *label)
{
    struct stat before, after;
    PyObject *result = NULL;
    unsigned char *destination;
    size_t offset = 0, size;
    ssize_t amount;
    int flags;
    if (fd < 3 || maximum == 0 || label == NULL ||
            (flags = fcntl(fd, F_GETFL)) < 0 ||
            (flags & O_ACCMODE) != O_RDONLY || fstat(fd, &before) != 0 ||
            !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
            before.st_uid != geteuid() || (before.st_mode & 0777) != 0400 ||
            before.st_size <= 0 || (uint64_t)before.st_size > maximum) {
        PyErr_Format(PyExc_RuntimeError,
                     "installed %s descriptor identity is invalid", label);
        return NULL;
    }
    size = (size_t)before.st_size;
    result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)size);
    if (result == NULL) {
        return NULL;
    }
    destination = (unsigned char *)PyBytes_AS_STRING(result);
    while (offset < size) {
        do {
            amount = pread(fd, destination + offset, size - offset,
                           (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0) {
            PyErr_Format(PyExc_RuntimeError,
                         "installed %s descriptor was truncated", label);
            Py_CLEAR(result);
            return NULL;
        }
        offset += (size_t)amount;
    }
    if (fstat(fd, &after) != 0 || !v2_darwin_same_stat(&before, &after)) {
        PyErr_Format(PyExc_RuntimeError,
                     "installed %s descriptor changed while read", label);
        Py_CLEAR(result);
    }
    return result;
}

static PyObject *
v2_darwin_backend_projection_binding(
    const struct plamen_source_bootstrap_installed_projection_v1 *projection)
{
    char payload[65], producer[65], manifest[65], policy[65];
    char coordinator[65], acquisition[65], verifier[65], roster[65];
    char member[65], code[65], rendered[2048];
    int amount;
    if (projection == NULL ||
            (projection->ordinal != PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1 &&
             projection->ordinal != PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1)) {
        PyErr_SetString(PyExc_RuntimeError,
                        "installed backend projection role is invalid");
        return NULL;
    }
    v2_darwin_hex(projection->row.payload.sha256, 32, payload);
    v2_darwin_hex(projection->row.producer_receipt.sha256, 32, producer);
    v2_darwin_hex(projection->row.source_manifest.sha256, 32, manifest);
    v2_darwin_hex(projection->row.policy_sha256, 32, policy);
    v2_darwin_hex(projection->coordinator_receipt_sha256, 32, coordinator);
    v2_darwin_hex(projection->acquisition_roster_sha256, 32, acquisition);
    v2_darwin_hex(projection->producer_verifier_key_sha256, 32, verifier);
    v2_darwin_hex(projection->installed_authority_roster_sha256, 32, roster);
    v2_darwin_hex(projection->coordinator_member_identity_sha256, 32, member);
    v2_darwin_hex(projection->coordinator_code_identity_sha256, 32, code);
    amount = snprintf(rendered, sizeof(rendered),
        "{\"acquisition_roster_sha256\":\"%s\","
        "\"backend\":\"%s\","
        "\"coordinator_code_identity_sha256\":\"%s\","
        "\"coordinator_member_identity_sha256\":\"%s\","
        "\"coordinator_receipt_sha256\":\"%s\","
        "\"installed_authority_roster_sha256\":\"%s\","
        "\"ordinal\":%u,"
        "\"payload_sha256\":\"%s\",\"payload_size\":%llu,"
        "\"policy_sha256\":\"%s\","
        "\"producer_receipt_sha256\":\"%s\","
        "\"producer_receipt_size\":%llu,"
        "\"producer_verifier_key_sha256\":\"%s\","
        "\"schema\":\"plamen.native-installed-backend-generation-projection.v1\","
        "\"source_manifest_sha256\":\"%s\","
        "\"source_manifest_size\":%llu}",
        acquisition, projection->role, code, member, coordinator, roster,
        (unsigned int)projection->ordinal, payload,
        (unsigned long long)projection->row.payload.size, policy, producer,
        (unsigned long long)projection->row.producer_receipt.size, verifier,
        manifest, (unsigned long long)projection->row.source_manifest.size);
    secure_zero(payload, sizeof(payload));
    secure_zero(producer, sizeof(producer));
    secure_zero(manifest, sizeof(manifest));
    secure_zero(policy, sizeof(policy));
    secure_zero(coordinator, sizeof(coordinator));
    secure_zero(acquisition, sizeof(acquisition));
    secure_zero(verifier, sizeof(verifier));
    secure_zero(roster, sizeof(roster));
    secure_zero(member, sizeof(member));
    secure_zero(code, sizeof(code));
    if (amount <= 0 || (size_t)amount >= sizeof(rendered)) {
        secure_zero(rendered, sizeof(rendered));
        PyErr_SetString(PyExc_RuntimeError,
                        "installed backend projection exceeded its bound");
        return NULL;
    }
    {
        PyObject *result = PyBytes_FromStringAndSize(rendered, amount);
        secure_zero(rendered, sizeof(rendered));
        return result;
    }
}

static PyObject *
acquire_backend_install_generation(PyObject *module, PyObject *args)
{
    PyObject *initial_object, *backend_object;
    V2AuthorityConsumerObject *initial;
    V2DarwinInstallAuthority install;
    struct plamen_source_bootstrap_installed_binding_v1 binding;
    struct plamen_source_bootstrap_installed_authority_v1 *installed = NULL;
    struct plamen_source_bootstrap_installed_projection_v1 projection;
    BackendInstallGenerationObject *result = NULL;
    const char *backend, *paths[3];
    Py_ssize_t backend_size;
    uint16_t role;
    int source_receipt_fd = -1, member_fds[3] = {-1, -1, -1};
    int expected = 0;
    size_t index;
    (void)module;
    memset(&install, 0, sizeof(install));
    install.install_root_fd = install.receipt_fd = install.generation_fd = -1;
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; index++)
        install.member_fds[index] = -1;
    memset(&binding, 0, sizeof(binding));
    memset(&projection, 0, sizeof(projection));
    projection.payload_fd = projection.producer_receipt_fd = -1;
    projection.source_manifest_fd = projection.coordinator_receipt_fd = -1;
    if (!PyArg_ParseTuple(args, "OO:acquire_backend_install_generation",
                          &initial_object, &backend_object) ||
            !PyUnicode_CheckExact(backend_object)) {
        return NULL;
    }
    backend = PyUnicode_AsUTF8AndSize(backend_object, &backend_size);
    if (backend == NULL ||
            !((backend_size == 5 && memcmp(backend, "codex", 5) == 0) ||
              (backend_size == 6 && memcmp(backend, "claude", 6) == 0))) {
        PyErr_SetString(PyExc_ValueError,
                        "installed backend selector is invalid");
        return NULL;
    }
    if (!bridge_initial_consumer_live(initial_object)) return NULL;
    initial = (V2AuthorityConsumerObject *)initial_object;
    if (initial->initial_authority_role !=
            PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER ||
            v2_fetch_request_projection(initial) < 0 ||
            !v2_darwin_projection_backend_is(initial, backend)) {
        PyErr_SetString(PyExc_RuntimeError,
                        "installed backend differs from authenticated request");
        return NULL;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &backend_install_generation_acquired, &expected, 1,
            memory_order_acq_rel, memory_order_acquire)) {
        PyErr_SetString(PyExc_RuntimeError,
                        "installed backend generation was already acquired");
        return NULL;
    }
    if (v2_darwin_install_open(&install) != 1 ||
            install.receipt.source_bootstrap_present != 1U ||
            plamen_install_receipt_open_source_bootstrap_authority(
                install.generation_fd, &install.receipt,
                &source_receipt_fd) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "installed source authority is unavailable");
        goto done;
    }
    binding.receipt_size =
        PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE;
    memcpy(binding.receipt_sha256,
           install.receipt.source_bootstrap_authority.sha256, 32U);
    memcpy(binding.acquisition_roster_sha256,
           install.receipt.source_bootstrap_authority
               .acquisition_roster_sha256, 32U);
    memcpy(binding.producer_verifier_key_sha256,
           install.receipt.source_bootstrap_authority
               .producer_verifier_key_sha256, 32U);
    memcpy(binding.installed_authority_roster_sha256,
           install.receipt.source_bootstrap_authority
               .installed_authority_roster_sha256, 32U);
    memcpy(binding.coordinator_member_identity_sha256,
           install.receipt.source_bootstrap_authority
               .coordinator_member_identity_sha256, 32U);
    memcpy(binding.coordinator_code_identity_sha256,
           install.receipt.source_bootstrap_authority
               .coordinator_code_identity_sha256, 32U);
    if (plamen_source_bootstrap_installed_readmit_v1(
            source_receipt_fd, geteuid(), &binding, &installed) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "installed source authority failed readmission");
        goto done;
    }
    role = strcmp(backend, "codex") == 0 ?
        PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1 :
        PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1;
    for (index = 0; index < 3U; index++) {
        paths[index] = plamen_source_bootstrap_installed_member_relative_path_v1(
            role, (uint16_t)index);
        if (paths[index] == NULL || v2_darwin_open_relative_file(
                install.generation_fd, paths[index], &member_fds[index]) != 0) {
            PyErr_SetString(PyExc_RuntimeError,
                            "installed backend authority member is unavailable");
            goto done;
        }
    }
    if (plamen_source_bootstrap_installed_project_role_v1(
            installed, role, member_fds[0], member_fds[1], member_fds[2],
            &projection) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "installed backend authority identity differs");
        goto done;
    }
    result = PyObject_New(BackendInstallGenerationObject,
                          &BackendInstallGenerationAuthorityType);
    if (result == NULL) goto done;
    result->creator_pid = getpid();
    result->creator_interpreter_id = current_interpreter_id();
    atomic_init(&result->consumed, 0);
    result->parent = Py_NewRef(initial_object);
    result->binding = binding;
    result->projection = projection;
    projection.payload_fd = projection.producer_receipt_fd = -1;
    projection.source_manifest_fd = projection.coordinator_receipt_fd = -1;

done:
    for (index = 0; index < 3U; index++)
        if (member_fds[index] >= 0) (void)close(member_fds[index]);
    if (source_receipt_fd >= 0) (void)close(source_receipt_fd);
    plamen_source_bootstrap_installed_projection_dispose_v1(&projection);
    plamen_source_bootstrap_installed_authority_dispose_v1(installed);
    v2_darwin_install_clear(&install);
    plamen_broker_v2_secure_zero(&binding, sizeof(binding));
    return (PyObject *)result;
}

static PyObject *
project_backend_install_generation(PyObject *module, PyObject *args)
{
    PyObject *object, *producer = NULL, *manifest = NULL, *binding = NULL;
    PyObject *result = NULL;
    BackendInstallGenerationObject *authority;
    struct plamen_source_bootstrap_installed_authority_v1 *installed = NULL;
    struct plamen_source_bootstrap_installed_projection_v1 fresh;
    (void)module;
    memset(&fresh, 0, sizeof(fresh));
    fresh.payload_fd = fresh.producer_receipt_fd = -1;
    fresh.source_manifest_fd = fresh.coordinator_receipt_fd = -1;
    if (!PyArg_ParseTuple(args, "O:project_backend_install_generation",
                          &object)) return NULL;
    if (Py_TYPE(object) != &BackendInstallGenerationAuthorityType) {
        PyErr_SetString(PyExc_TypeError,
                        "exact installed backend authority is required");
        return NULL;
    }
    authority = (BackendInstallGenerationObject *)object;
    if (authority->creator_pid != getpid() ||
            authority->creator_interpreter_id != current_interpreter_id() ||
            atomic_exchange_explicit(&authority->consumed, 1,
                                     memory_order_acq_rel) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "installed backend authority is invalid or consumed");
        return NULL;
    }
    if (plamen_source_bootstrap_installed_readmit_v1(
            authority->projection.coordinator_receipt_fd, geteuid(),
            &authority->binding, &installed) != 0 ||
            plamen_source_bootstrap_installed_project_role_v1(
                installed, authority->projection.ordinal,
                authority->projection.payload_fd,
                authority->projection.producer_receipt_fd,
                authority->projection.source_manifest_fd, &fresh) != 0) {
        PyErr_SetString(PyExc_RuntimeError,
                        "installed backend authority failed final revalidation");
        goto done;
    }
    producer = v2_darwin_read_bound_file(
        fresh.producer_receipt_fd, PLAMEN_BACKEND_PRODUCER_RECEIPT_MAX,
        "backend producer receipt");
    if (producer == NULL) goto done;
    manifest = v2_darwin_read_bound_file(
        fresh.source_manifest_fd, PLAMEN_BACKEND_SOURCE_MANIFEST_MAX,
        "backend source manifest");
    if (manifest == NULL) goto done;
    binding = v2_darwin_backend_projection_binding(&fresh);
    if (binding == NULL) goto done;
    result = PyTuple_Pack(3, producer, manifest, binding);

done:
    Py_XDECREF(producer);
    Py_XDECREF(manifest);
    Py_XDECREF(binding);
    plamen_source_bootstrap_installed_projection_dispose_v1(&fresh);
    plamen_source_bootstrap_installed_authority_dispose_v1(installed);
    plamen_source_bootstrap_installed_projection_dispose_v1(
        &authority->projection);
    return result;
}

#endif /* PLAMEN_NATIVE_INSTALLED_BACKEND_GENERATION_ENABLED */

static int
v2_darwin_xpc_exact_envelope(xpc_object_t object)
{
    __block size_t count = 0;
    __block int valid = 1;
    if (object == NULL || xpc_get_type(object) != XPC_TYPE_DICTIONARY) {
        return 0;
    }
    xpc_dictionary_apply(object, ^bool(const char *key, xpc_object_t value) {
        count++;
        if (strcmp(key, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE) != 0 ||
                xpc_get_type(value) != XPC_TYPE_DATA) {
            valid = 0;
        }
        return true;
    });
    return valid && count == 1;
}

/* Return 0 with copied reply, 1 for connection unavailable, -1 malformed. */
static int
v2_darwin_xpc_exchange(xpc_connection_t connection, xpc_object_t message,
                       int key_write_fd, const unsigned char key[32],
                       unsigned char **reply_bytes, size_t *reply_size)
{
    dispatch_semaphore_t semaphore;
    dispatch_time_t deadline;
    __block xpc_object_t reply = NULL;
    const void *data;
    size_t size = 0, offset = 0;
    int status = -1;

    *reply_bytes = NULL;
    *reply_size = 0;
    semaphore = dispatch_semaphore_create(0);
    if (connection == NULL || message == NULL || semaphore == NULL ||
            (key_write_fd >= 0 && key == NULL)) {
        return -1;
    }
    deadline = dispatch_time(DISPATCH_TIME_NOW,
                             PLAMEN_V2_DARWIN_XPC_TIMEOUT_NS);
    xpc_connection_send_message_with_reply(
        connection, message,
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        ^(xpc_object_t response) {
            reply = xpc_retain(response);
            dispatch_semaphore_signal(semaphore);
        });
    if (key_write_fd >= 0) {
        while (offset < 32U) {
            ssize_t amount;
            do {
                amount = write(key_write_fd, key + offset, 32U - offset);
            } while (amount < 0 && errno == EINTR);
            if (amount <= 0) {
                goto done;
            }
            offset += (size_t)amount;
        }
        (void)close(key_write_fd);
        key_write_fd = -1;
    }
    if (dispatch_semaphore_wait(semaphore, deadline) != 0) {
        xpc_connection_cancel(connection);
        status = 1;
        goto done;
    }
    if (reply == NULL || xpc_get_type(reply) == XPC_TYPE_ERROR) {
        status = 1;
        goto done;
    }
    if (!v2_darwin_xpc_exact_envelope(reply)) {
        goto done;
    }
    data = xpc_dictionary_get_data(
        reply, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE, &size);
    if (data == NULL || size < PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE ||
            size > PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE +
                PLAMEN_BROKER_V2_SERVICE_MAX_PAYLOAD) {
        goto done;
    }
    *reply_bytes = (unsigned char *)malloc(size);
    if (*reply_bytes == NULL) {
        goto done;
    }
    memcpy(*reply_bytes, data, size);
    *reply_size = size;
    status = 0;

done:
    if (key_write_fd >= 0) {
        (void)close(key_write_fd);
    }
    if (reply != NULL) {
        xpc_release(reply);
    }
    return status;
}

static int
v2_darwin_current_peer(struct plamen_broker_v2_peer_identity *peer)
{
    struct proc_bsdinfo information;
    int amount;
    memset(&information, 0, sizeof(information));
    memset(peer, 0, sizeof(*peer));
    amount = proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0,
                          &information, (int)sizeof(information));
    if (amount != (int)sizeof(information) ||
            information.pbi_pid != (uint32_t)getpid() ||
            information.pbi_start_tvsec == 0 ||
            information.pbi_start_tvusec >= 1000000U) {
        return -1;
    }
    peer->pid = (uint64_t)getpid();
    peer->uid = information.pbi_uid;
    peer->gid = information.pbi_gid;
    peer->birth_kind = PLAMEN_BROKER_V2_BIRTH_DARWIN_EPOCH;
    peer->birth_primary = information.pbi_start_tvsec;
    peer->birth_secondary =
        (uint64_t)information.pbi_start_tvusec * UINT64_C(1000);
    return 0;
}

static int
v2_darwin_revalidate_install(V2DarwinInstallAuthority *authority)
{
    unsigned char bytes[PLAMEN_INSTALL_RECEIPT_SIZE];
    unsigned char digest[32];
    size_t index;
    int valid = v2_darwin_read_receipt_exact(
        authority->receipt_fd, bytes) == 0 &&
        plamen_broker_v2_sha256(bytes, sizeof(bytes), digest) ==
            PLAMEN_BROKER_V2_OK &&
        v2_constant_equal(bytes, authority->receipt_bytes,
                          sizeof(bytes)) &&
        v2_constant_equal(digest, authority->receipt_sha256, 32);
    for (index = 0; valid &&
            index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; index++) {
        valid = plamen_install_receipt_member_revalidate(
            authority->member_fds[index],
            &authority->receipt.members[index]) == 0;
    }
    secure_zero(bytes, sizeof(bytes));
    secure_zero(digest, sizeof(digest));
    return valid ? 0 : -1;
}

static int
v2_darwin_service_error_is_absent(
        const struct plamen_broker_v2_service_envelope_view *view,
        const unsigned char request_sha256[32])
{
    struct plamen_broker_v2_service_error error;
    int absent;
    memset(&error, 0, sizeof(error));
    absent = view->type == PLAMEN_BROKER_V2_SERVICE_ERROR &&
        plamen_broker_v2_service_error_decode(
            view->payload, view->payload_size, &error) ==
                PLAMEN_BROKER_V2_OK &&
        error.code == PLAMEN_BROKER_V2_SERVICE_ERR_REGISTRATION_MISSING &&
        error.failed_message_type ==
            PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP &&
        (error.flags & PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED) != 0 &&
        (error.flags & (PLAMEN_BROKER_V2_SERVICE_REGISTRATION_CONSUMED |
                        PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED)) == 0 &&
        v2_constant_equal(error.request_envelope_sha256,
                          request_sha256, 32);
    plamen_broker_v2_secure_zero(&error, sizeof(error));
    return absent;
}

static int
v2_darwin_take_initial_session(V2NativeBootstrapSession *session)
{
    V2DarwinInstallAuthority authority;
    struct plamen_broker_v2_service_session_lookup lookup;
    struct plamen_broker_v2_service_session_challenge challenge;
    struct plamen_broker_v2_service_session_open open_request;
    struct plamen_broker_v2_service_session_ack acknowledgement;
    struct plamen_broker_v2_service_envelope_view reply_view;
    struct plamen_broker_v2_commitment commitment;
    unsigned char lookup_payload[PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE];
    unsigned char open_payload[PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE];
    unsigned char transaction_nonce[32], invocation_nonce[32];
    unsigned char lookup_sha256[32], key[32], zeros[32] = {0};
    static const unsigned char managed_custody_domain[] =
        "PLAMEN-MANAGED-EVM-TOOLCHAIN-CUSTODY-V1\0";
    unsigned char managed_custody_preimage[
        sizeof(managed_custody_domain) - 1U + 128U];
    unsigned char *lookup_envelope = NULL, *open_envelope = NULL;
    unsigned char *reply = NULL;
    size_t lookup_envelope_size = 0, open_envelope_size = 0, reply_size = 0;
    size_t attempt_size;
    xpc_connection_t connection = NULL;
    xpc_object_t message = NULL;
    int sockets[2] = {-1, -1}, key_pipe[2] = {-1, -1};
    int install_status, exchange_status, status = -1;

    memset(&authority, 0, sizeof(authority));
    memset(&lookup, 0, sizeof(lookup));
    memset(&challenge, 0, sizeof(challenge));
    memset(&open_request, 0, sizeof(open_request));
    memset(&acknowledgement, 0, sizeof(acknowledgement));
    memset(&reply_view, 0, sizeof(reply_view));
    memset(&commitment, 0, sizeof(commitment));
    memset(lookup_payload, 0, sizeof(lookup_payload));
    memset(open_payload, 0, sizeof(open_payload));
    memset(transaction_nonce, 0, sizeof(transaction_nonce));
    memset(invocation_nonce, 0, sizeof(invocation_nonce));
    memset(lookup_sha256, 0, sizeof(lookup_sha256));
    memset(key, 0, sizeof(key));
    memset(managed_custody_preimage, 0, sizeof(managed_custody_preimage));
    install_status = v2_darwin_install_open(&authority);
    if (install_status != 1) {
        return install_status;
    }
    memcpy(lookup.extension_closure_sha256,
        authority.receipt.members[
            PLAMEN_INSTALL_MEMBER_EXTENSION - 1].sha256, 32);
    memcpy(lookup.interpreter_executable_sha256,
        authority.receipt.members[
            PLAMEN_INSTALL_MEMBER_PYTHON - 1].sha256, 32);
    if (v2_random(lookup.session_id, sizeof(lookup.session_id)) != 0 ||
            v2_random(transaction_nonce, sizeof(transaction_nonce)) != 0 ||
            v2_random(invocation_nonce, sizeof(invocation_nonce)) != 0 ||
            v2_constant_equal(lookup.session_id, zeros, 32) ||
            plamen_broker_v2_service_session_lookup_encode(
                &lookup, lookup_payload) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_envelope_build(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP,
                transaction_nonce, invocation_nonce, lookup_payload,
                sizeof(lookup_payload), 0, &lookup_envelope,
                &lookup_envelope_size) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_sha256(lookup_envelope,
                lookup_envelope_size, lookup_sha256) != PLAMEN_BROKER_V2_OK) {
        goto done;
    }
    connection = xpc_connection_create_mach_service(
        PLAMEN_BROKER_V2_DARWIN_SERVICE_NAME, NULL, 0);
    if (connection == NULL ||
            xpc_connection_set_peer_code_signing_requirement(
                connection, authority.broker_requirement) != 0) {
        status = 0;
        goto done;
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    xpc_connection_activate(connection);
    message = xpc_dictionary_create(NULL, NULL, 0);
    if (message == NULL) {
        goto done;
    }
    xpc_dictionary_set_data(message, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE,
                            lookup_envelope, lookup_envelope_size);
    exchange_status = v2_darwin_xpc_exchange(
        connection, message, -1, NULL, &reply, &reply_size);
    xpc_release(message);
    message = NULL;
    if (exchange_status != 0 ||
            plamen_broker_v2_service_envelope_accept(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                reply, reply_size, 0, &reply_view) != PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(reply_view.transaction_nonce,
                               transaction_nonce, 32) ||
            !v2_constant_equal(reply_view.invocation_nonce,
                               invocation_nonce, 32)) {
        goto done;
    }
    if (reply_view.type == PLAMEN_BROKER_V2_SERVICE_ERROR) {
        status = v2_darwin_service_error_is_absent(
            &reply_view, lookup_sha256) ? 0 : -1;
        goto done;
    }
    if (reply_view.type != PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE ||
            plamen_broker_v2_service_session_challenge_decode(
                reply_view.payload, reply_view.payload_size,
                &challenge) != PLAMEN_BROKER_V2_OK ||
            !plamen_broker_v2_service_session_challenge_matches_lookup(
                &lookup, lookup_sha256, &challenge) ||
            challenge.initial_interpreter_slot != 0 ||
            (challenge.initial_authority_role !=
                 PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR &&
             challenge.initial_authority_role !=
                 PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER) ||
            !v2_constant_equal(challenge.installed_closure_sha256,
                               authority.receipt.generation_id_sha256, 32) ||
            !v2_constant_equal(challenge.broker_closure_sha256,
                authority.receipt.members[
                    PLAMEN_INSTALL_MEMBER_SERVICE - 1].sha256, 32) ||
            v2_darwin_current_peer(&open_request.extension_peer) != 0 ||
            memcmp(&challenge.extension_peer, &open_request.extension_peer,
                   sizeof(challenge.extension_peer)) != 0 ||
            plamen_broker_v2_auth_consume_matches_challenge(
                &challenge, challenge.commitment,
                challenge.commitment_size, &commitment) !=
                    PLAMEN_BROKER_V2_OK) {
        goto done;
    }
    attempt_size = strnlen(commitment.attempt_id,
                           sizeof(commitment.attempt_id));
    if (attempt_size == 0 || attempt_size > PLAMEN_BROKER_V2_MAX_ID ||
            !v2_ascii_id_valid(commitment.attempt_id, attempt_size) ||
            challenge.request_projection_size == 0 ||
            challenge.request_projection_size >
                PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX) {
        goto done;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
            pipe(key_pipe) != 0 ||
            v2_prepare_control_fd(sockets[0]) != 0 ||
            v2_prepare_control_fd(sockets[1]) != 0 ||
            v2_set_cloexec(key_pipe[0]) != 0 ||
            v2_set_cloexec(key_pipe[1]) != 0 ||
            v2_random(key, sizeof(key)) != 0 ||
            v2_constant_equal(key, zeros, 32)) {
        goto done;
    }
    memcpy(open_request.challenge_envelope_sha256,
           reply_view.envelope_sha256, 32);
    memcpy(open_request.challenge_nonce, challenge.challenge_nonce, 32);
    memcpy(open_request.commitment_sha256, challenge.commitment_sha256, 32);
    memcpy(open_request.registration_sha256,
           challenge.registration_sha256, 32);
    memcpy(open_request.committed_audit_generation_sha256,
           challenge.committed_audit_generation_sha256, 32);
    memcpy(open_request.extension_closure_sha256,
           challenge.extension_closure_sha256, 32);
    memcpy(open_request.interpreter_executable_sha256,
           challenge.interpreter_executable_sha256, 32);
    open_request.initial_interpreter_slot =
        challenge.initial_interpreter_slot;
    open_request.initial_authority_role = challenge.initial_authority_role;
    memcpy(open_request.session_id, challenge.session_id, 32);
    open_request.descriptors[0].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET;
    open_request.descriptors[0].target = 0;
    open_request.descriptors[0].access_mode =
        PLAMEN_BROKER_V2_FD_READ_WRITE;
    open_request.descriptors[1].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ;
    open_request.descriptors[1].target = 1;
    open_request.descriptors[1].access_mode = PLAMEN_BROKER_V2_FD_READ;
    if (plamen_broker_v2_fd_identity(
            sockets[1], open_request.descriptors[0].identity) !=
                PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_fd_identity(
                key_pipe[0], open_request.descriptors[1].identity) !=
                    PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_session_open_encode(
                &open_request, open_payload) != PLAMEN_BROKER_V2_OK ||
            !plamen_broker_v2_service_session_open_matches_challenge(
                &challenge, reply_view.envelope_sha256, &open_request) ||
            v2_random(transaction_nonce, sizeof(transaction_nonce)) != 0 ||
            v2_random(invocation_nonce, sizeof(invocation_nonce)) != 0 ||
            plamen_broker_v2_service_envelope_build(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN,
                transaction_nonce, invocation_nonce, open_payload,
                sizeof(open_payload), 2, &open_envelope,
                &open_envelope_size) != PLAMEN_BROKER_V2_OK) {
        goto done;
    }
    secure_zero(reply, reply_size);
    free(reply);
    reply = NULL;
    reply_size = 0;
    memset(&reply_view, 0, sizeof(reply_view));
    message = xpc_dictionary_create(NULL, NULL, 0);
    if (message == NULL) {
        goto done;
    }
    xpc_dictionary_set_data(message, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE,
                            open_envelope, open_envelope_size);
    xpc_dictionary_set_fd(message,
                          PLAMEN_BROKER_V2_XPC_KEY_CONTROL_SOCKET,
                          sockets[1]);
    xpc_dictionary_set_fd(message,
                          PLAMEN_BROKER_V2_XPC_KEY_KEY_PIPE_READ,
                          key_pipe[0]);
    exchange_status = v2_darwin_xpc_exchange(
        connection, message, key_pipe[1], key, &reply, &reply_size);
    key_pipe[1] = -1;
    xpc_release(message);
    message = NULL;
    (void)close(sockets[1]);
    sockets[1] = -1;
    (void)close(key_pipe[0]);
    key_pipe[0] = -1;
    if (exchange_status == 1) {
        status = 0;
        goto done;
    }
    if (exchange_status != 0 ||
            plamen_broker_v2_service_envelope_accept(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                reply, reply_size, 0, &reply_view) != PLAMEN_BROKER_V2_OK ||
            reply_view.type != PLAMEN_BROKER_V2_SERVICE_SESSION_ACCEPTED ||
            !v2_constant_equal(reply_view.transaction_nonce,
                               transaction_nonce, 32) ||
            !v2_constant_equal(reply_view.invocation_nonce,
                               invocation_nonce, 32) ||
            plamen_broker_v2_service_session_ack_decode(
                reply_view.payload, reply_view.payload_size,
                &acknowledgement) != PLAMEN_BROKER_V2_OK ||
            !plamen_broker_v2_service_session_ack_matches_open(
                &open_request, &acknowledgement) ||
            v2_darwin_revalidate_install(&authority) != 0 ||
            v2_darwin_current_binaries_match(&authority) != 0) {
        goto done;
    }
    memcpy(managed_custody_preimage, managed_custody_domain,
           sizeof(managed_custody_domain) - 1U);
    memcpy(managed_custody_preimage + sizeof(managed_custody_domain) - 1U,
           authority.receipt_sha256, 32);
    memcpy(managed_custody_preimage + sizeof(managed_custody_domain) - 1U + 32U,
           commitment.runtime_closure_sha256, 32);
    memcpy(managed_custody_preimage + sizeof(managed_custody_domain) - 1U + 64U,
           commitment.provider_provenance_sha256, 32);
    memcpy(managed_custody_preimage + sizeof(managed_custody_domain) - 1U + 96U,
           challenge.broker_closure_sha256, 32);
    if (plamen_broker_v2_sha256(
            managed_custody_preimage, sizeof(managed_custody_preimage),
            session->managed_toolchain_custody_sha256) !=
                PLAMEN_BROKER_V2_OK) {
        goto done;
    }
    session->control_fd = sockets[0];
    sockets[0] = -1;
    session->initial_authority_role = challenge.initial_authority_role;
    memcpy(session->key, key, 32);
    memcpy(session->session_id, challenge.session_id, 32);
    memset(session->operation_nonce, 0, sizeof(session->operation_nonce));
    memcpy(session->fingerprint, commitment.request_fingerprint, 32);
    memcpy(session->registration_sha256,
           challenge.registration_sha256, 32);
    memcpy(session->issuance_checkpoint_sha256,
           acknowledgement.registration_burn_checkpoint_sha256, 32);
    memcpy(session->authority_bundle_sha256,
           acknowledgement.authority_bundle_sha256, 32);
    memcpy(session->request_projection_sha256,
           challenge.request_projection_sha256, 32);
    memcpy(session->native_deployment_receipt_sha256,
           authority.receipt_sha256, 32);
    memcpy(session->runtime_closure_sha256,
           commitment.runtime_closure_sha256, 32);
    memcpy(session->broker_peer_identity_sha256,
           challenge.broker_closure_sha256, 32);
    memcpy(session->extension_closure_sha256,
           authority.receipt.members[
               PLAMEN_INSTALL_MEMBER_EXTENSION - 1].sha256, 32);
    memcpy(session->interpreter_executable_sha256,
           authority.receipt.members[
               PLAMEN_INSTALL_MEMBER_PYTHON - 1].sha256, 32);
    session->request_projection_size = challenge.request_projection_size;
    memcpy(session->attempt, commitment.attempt_id, attempt_size + 1U);
    session->attempt_size = attempt_size;
    memcpy(session->auth_payload, challenge.commitment,
           challenge.commitment_size);
    session->auth_payload_size = challenge.commitment_size;
    status = 1;

done:
    if (message != NULL) {
        xpc_release(message);
    }
    if (connection != NULL) {
        xpc_connection_cancel(connection);
        xpc_release(connection);
    }
    if (reply != NULL) {
        secure_zero(reply, reply_size);
        free(reply);
    }
    if (lookup_envelope != NULL) {
        secure_zero(lookup_envelope, lookup_envelope_size);
        free(lookup_envelope);
    }
    if (open_envelope != NULL) {
        secure_zero(open_envelope, open_envelope_size);
        free(open_envelope);
    }
    v2_close_fds(sockets, 2);
    v2_close_fds(key_pipe, 2);
    if (status != 1) {
        v2_native_bootstrap_clear(session);
    }
    v2_darwin_install_clear(&authority);
    secure_zero(transaction_nonce, sizeof(transaction_nonce));
    secure_zero(invocation_nonce, sizeof(invocation_nonce));
    secure_zero(lookup_sha256, sizeof(lookup_sha256));
    secure_zero(key, sizeof(key));
    secure_zero(managed_custody_preimage,
                sizeof(managed_custody_preimage));
    plamen_broker_v2_secure_zero(&lookup, sizeof(lookup));
    plamen_broker_v2_secure_zero(&challenge, sizeof(challenge));
    plamen_broker_v2_secure_zero(&open_request, sizeof(open_request));
    plamen_broker_v2_secure_zero(&acknowledgement,
                                 sizeof(acknowledgement));
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    secure_zero(lookup_payload, sizeof(lookup_payload));
    secure_zero(open_payload, sizeof(open_payload));
    return status;
}

static int
v2_darwin_take_specialized_session_once(
        const V2NativeBootstrapSession *parent, uint16_t lane,
        BridgeSpecializedSession **result)
{
    V2DarwinInstallAuthority authority;
    struct plamen_broker_v2_service_specialized_session_lookup lookup;
    struct plamen_broker_v2_service_specialized_session_challenge challenge;
    struct plamen_broker_v2_service_specialized_session_open open_request;
    struct plamen_broker_v2_service_specialized_session_ack acknowledgement;
    struct plamen_broker_v2_service_envelope_view view;
    struct plamen_broker_v2_service_error service_error;
    unsigned char lookup_payload[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP_SIZE];
    unsigned char open_payload[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE];
    unsigned char transaction_nonce[32], invocation_nonce[32], key[32];
    unsigned char lookup_envelope_sha256[32], open_envelope_sha256[32];
    unsigned char expected_session_binding[32];
    unsigned char *lookup_envelope = NULL, *open_envelope = NULL;
    unsigned char *reply = NULL;
    size_t lookup_envelope_size = 0, open_envelope_size = 0, reply_size = 0;
    int sockets[2] = {-1, -1}, key_pipe[2] = {-1, -1};
    xpc_connection_t connection = NULL;
    xpc_object_t message = NULL;
    BridgeSpecializedSession *session = NULL;
    int exchange_status, status = -1;

    *result = NULL;
    memset(&authority, 0, sizeof(authority));
    memset(&lookup, 0, sizeof(lookup));
    memset(&challenge, 0, sizeof(challenge));
    memset(&open_request, 0, sizeof(open_request));
    memset(&acknowledgement, 0, sizeof(acknowledgement));
    memset(&view, 0, sizeof(view));
    memset(&service_error, 0, sizeof(service_error));
    memset(lookup_payload, 0, sizeof(lookup_payload));
    memset(open_payload, 0, sizeof(open_payload));
    memset(transaction_nonce, 0, sizeof(transaction_nonce));
    memset(invocation_nonce, 0, sizeof(invocation_nonce));
    memset(key, 0, sizeof(key));
    memset(lookup_envelope_sha256, 0, sizeof(lookup_envelope_sha256));
    memset(open_envelope_sha256, 0, sizeof(open_envelope_sha256));
    memset(expected_session_binding, 0, sizeof(expected_session_binding));
    if (parent == NULL || parent->control_fd < 0 ||
            lane < PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER ||
            lane > PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL) {
        return -1;
    }
    status = v2_darwin_install_open(&authority);
    if (status != 1) {
        goto done;
    }
    lookup.version = PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION;
    lookup.lane = lane;
    memcpy(lookup.parent_session_id, parent->session_id, 32);
    memcpy(lookup.registration_sha256, parent->registration_sha256, 32);
    memcpy(lookup.authority_bundle_sha256,
           parent->authority_bundle_sha256, 32);
    memcpy(lookup.extension_closure_sha256,
           parent->extension_closure_sha256, 32);
    memcpy(lookup.interpreter_executable_sha256,
           parent->interpreter_executable_sha256, 32);
    if (v2_random(lookup.specialized_session_id, 32) != 0 ||
            v2_random(transaction_nonce, 32) != 0 ||
            v2_random(invocation_nonce, 32) != 0 ||
            plamen_broker_v2_service_specialized_session_lookup_encode(
                &lookup, lookup_payload) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_envelope_build(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP,
                transaction_nonce, invocation_nonce, lookup_payload,
                sizeof(lookup_payload), 0, &lookup_envelope,
                &lookup_envelope_size) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_sha256(lookup_envelope,
                lookup_envelope_size, lookup_envelope_sha256) !=
                    PLAMEN_BROKER_V2_OK) {
        status = -1;
        goto done;
    }
    connection = xpc_connection_create_mach_service(
        PLAMEN_BROKER_V2_DARWIN_SERVICE_NAME, NULL, 0);
    if (connection == NULL ||
            xpc_connection_set_peer_code_signing_requirement(
                connection, authority.broker_requirement) != 0) {
        status = 0;
        goto done;
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    xpc_connection_activate(connection);
    message = xpc_dictionary_create(NULL, NULL, 0);
    if (message == NULL) {
        status = -1;
        goto done;
    }
    xpc_dictionary_set_data(message, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE,
                            lookup_envelope, lookup_envelope_size);
    exchange_status = v2_darwin_xpc_exchange(
        connection, message, -1, NULL, &reply, &reply_size);
    xpc_release(message);
    message = NULL;
    if (exchange_status == 1) {
        status = 0;
        goto done;
    }
    if (exchange_status != 0 ||
            plamen_broker_v2_service_envelope_accept(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                reply, reply_size, 0, &view) != PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(view.transaction_nonce,
                               transaction_nonce, 32) ||
            !v2_constant_equal(view.invocation_nonce,
                               invocation_nonce, 32)) {
        status = -1;
        goto done;
    }
    if (view.type == PLAMEN_BROKER_V2_SERVICE_ERROR) {
        status = plamen_broker_v2_service_error_decode(
                view.payload, view.payload_size, &service_error) ==
                    PLAMEN_BROKER_V2_OK &&
                service_error.failed_message_type ==
                    PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP &&
                (service_error.flags &
                    PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED) != 0 &&
                v2_constant_equal(service_error.request_envelope_sha256,
                                  lookup_envelope_sha256, 32)
            ? 0 : -1;
        goto done;
    }
    if (view.type !=
            PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE ||
            plamen_broker_v2_service_specialized_session_challenge_decode(
                view.payload, view.payload_size, &challenge) !=
                    PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(challenge.request_envelope_sha256,
                               lookup_envelope_sha256, 32) ||
            memcmp(&challenge.lookup, &lookup, sizeof(lookup)) != 0 ||
            !v2_constant_equal(challenge.broker_closure_sha256,
                               parent->broker_peer_identity_sha256, 32) ||
            v2_darwin_current_peer(&open_request.extension_peer) != 0 ||
            memcmp(&challenge.extension_peer, &open_request.extension_peer,
                   sizeof(challenge.extension_peer)) != 0 ||
            socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
            pipe(key_pipe) != 0 ||
            v2_prepare_control_fd(sockets[0]) != 0 ||
            v2_prepare_control_fd(sockets[1]) != 0 ||
            v2_set_cloexec(key_pipe[0]) != 0 ||
            v2_set_cloexec(key_pipe[1]) != 0 ||
            v2_random(key, 32) != 0) {
        status = -1;
        goto done;
    }
    memcpy(open_request.challenge_envelope_sha256,
           view.envelope_sha256, 32);
    memcpy(open_request.challenge_nonce, challenge.challenge_nonce, 32);
    open_request.version = PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION;
    open_request.lane = lane;
    memcpy(open_request.parent_session_id, parent->session_id, 32);
    memcpy(open_request.specialized_session_id,
           lookup.specialized_session_id, 32);
    open_request.descriptors[0].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET;
    open_request.descriptors[0].target = 0;
    open_request.descriptors[0].access_mode =
        PLAMEN_BROKER_V2_FD_READ_WRITE;
    open_request.descriptors[1].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ;
    open_request.descriptors[1].target = 1;
    open_request.descriptors[1].access_mode = PLAMEN_BROKER_V2_FD_READ;
    if (plamen_broker_v2_fd_identity(
            sockets[1], open_request.descriptors[0].identity) !=
                PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_fd_identity(
            key_pipe[0], open_request.descriptors[1].identity) !=
                PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_specialized_session_open_encode(
                &open_request, open_payload) != PLAMEN_BROKER_V2_OK ||
            v2_random(transaction_nonce, 32) != 0 ||
            v2_random(invocation_nonce, 32) != 0 ||
            plamen_broker_v2_service_envelope_build(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN,
                transaction_nonce, invocation_nonce, open_payload,
                sizeof(open_payload), 2, &open_envelope,
                &open_envelope_size) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_sha256(open_envelope, open_envelope_size,
                                    open_envelope_sha256) !=
                PLAMEN_BROKER_V2_OK) {
        status = -1;
        goto done;
    }
    secure_zero(reply, reply_size);
    free(reply);
    reply = NULL;
    reply_size = 0;
    memset(&view, 0, sizeof(view));
    message = xpc_dictionary_create(NULL, NULL, 0);
    if (message == NULL) {
        status = -1;
        goto done;
    }
    xpc_dictionary_set_data(message, PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE,
                            open_envelope, open_envelope_size);
    xpc_dictionary_set_fd(message,
                          PLAMEN_BROKER_V2_XPC_KEY_CONTROL_SOCKET,
                          sockets[1]);
    xpc_dictionary_set_fd(message,
                          PLAMEN_BROKER_V2_XPC_KEY_KEY_PIPE_READ,
                          key_pipe[0]);
    exchange_status = v2_darwin_xpc_exchange(
        connection, message, key_pipe[1], key, &reply, &reply_size);
    key_pipe[1] = -1;
    xpc_release(message);
    message = NULL;
    (void)close(sockets[1]);
    sockets[1] = -1;
    (void)close(key_pipe[0]);
    key_pipe[0] = -1;
    if (exchange_status != 0 ||
            plamen_broker_v2_service_envelope_accept(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                reply, reply_size, 0, &view) != PLAMEN_BROKER_V2_OK ||
            view.type !=
                PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACCEPTED ||
            !v2_constant_equal(view.transaction_nonce,
                               transaction_nonce, 32) ||
            !v2_constant_equal(view.invocation_nonce,
                               invocation_nonce, 32) ||
            plamen_broker_v2_service_specialized_session_ack_decode(
                view.payload, view.payload_size, &acknowledgement) !=
                    PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(acknowledgement.request_envelope_sha256,
                               open_envelope_sha256, 32) ||
            acknowledgement.version !=
                PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION ||
            acknowledgement.lane != lane ||
            !v2_constant_equal(acknowledgement.parent_session_id,
                               parent->session_id, 32) ||
            !v2_constant_equal(acknowledgement.specialized_session_id,
                               lookup.specialized_session_id, 32) ||
            plamen_broker_v2_specialized_session_binding(
                key, parent->session_id, lookup.specialized_session_id,
                lane, acknowledgement.authority_binding_sha256,
                expected_session_binding) != PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(acknowledgement.session_binding_sha256,
                               expected_session_binding, 32) ||
            v2_darwin_revalidate_install(&authority) != 0 ||
            v2_darwin_current_binaries_match(&authority) != 0) {
        status = -1;
        goto done;
    }
    session = (BridgeSpecializedSession *)calloc(1, sizeof(*session));
    if (session == NULL) {
        status = -1;
        goto done;
    }
    atomic_init(&session->references, 1U);
    session->operation_lock = PyThread_allocate_lock();
    if (session->operation_lock == NULL) {
        free(session);
        session = NULL;
        status = -1;
        goto done;
    }
    session->creator_pid = getpid();
    session->creator_interpreter_id = current_interpreter_id();
    session->control_fd = sockets[0];
    sockets[0] = -1;
    session->lane = lane;
    session->next_sequence = 0;
    memcpy(session->key, key, 32);
    memcpy(session->session_id, lookup.specialized_session_id, 32);
    memcpy(session->authority_binding_sha256,
           acknowledgement.authority_binding_sha256, 32);
    memset(session->previous_frame_sha256, 0, 32);
    *result = session;
    session = NULL;
    status = 1;

done:
    if (message != NULL) xpc_release(message);
    if (connection != NULL) {
        xpc_connection_cancel(connection);
        xpc_release(connection);
    }
    if (reply != NULL) { secure_zero(reply, reply_size); free(reply); }
    if (lookup_envelope != NULL) {
        secure_zero(lookup_envelope, lookup_envelope_size);
        free(lookup_envelope);
    }
    if (open_envelope != NULL) {
        secure_zero(open_envelope, open_envelope_size);
        free(open_envelope);
    }
    v2_close_fds(sockets, 2);
    v2_close_fds(key_pipe, 2);
    bridge_specialized_session_release(session);
    v2_darwin_install_clear(&authority);
    secure_zero(transaction_nonce, sizeof(transaction_nonce));
    secure_zero(invocation_nonce, sizeof(invocation_nonce));
    secure_zero(key, sizeof(key));
    secure_zero(lookup_envelope_sha256, sizeof(lookup_envelope_sha256));
    secure_zero(open_envelope_sha256, sizeof(open_envelope_sha256));
    secure_zero(expected_session_binding,
                sizeof(expected_session_binding));
    plamen_broker_v2_secure_zero(&lookup, sizeof(lookup));
    plamen_broker_v2_secure_zero(&challenge, sizeof(challenge));
    plamen_broker_v2_secure_zero(&open_request, sizeof(open_request));
    plamen_broker_v2_secure_zero(&acknowledgement,
                                 sizeof(acknowledgement));
    plamen_broker_v2_secure_zero(&service_error, sizeof(service_error));
    return status;
}

static int
v2_darwin_take_specialized_session(
        const V2NativeBootstrapSession *parent, uint16_t lane,
        BridgeSpecializedSession **result)
{
    int status;

    if (result == NULL) {
        return -1;
    }
    *result = NULL;
    status = v2_darwin_take_specialized_session_once(parent, lane, result);
    if (status != 0) {
        return status;
    }
    /*
     * An ACCEPTED reply can be lost after the broker durably consumes OPEN.
     * The first call closes its client endpoint on every non-success path, so
     * any orphan service worker reaches EOF.  Retry once with an entirely new
     * child session/socket/pipe/key; never reuse an EOF-bound key pipe or put a
     * second service reader on the original control endpoint.
     */
    return v2_darwin_take_specialized_session_once(parent, lane, result);
}

#endif /* __APPLE__ */

#ifdef __linux__

typedef struct {
    struct plamen_linux_install_receipt_v2 receipt;
    int receipt_fd;
    int install_root_fd;
} V2LinuxInstallAuthority;

static const uint8_t v2_linux_expected_provenance[32] =
    PLAMEN_LINUX_INSTALL_PROVENANCE_SHA256_BYTES;
static const uint8_t v2_linux_expected_protocol[32] =
    PLAMEN_LINUX_PROTOCOL_SCHEMA_SHA256_BYTES;

static void
v2_linux_install_clear(V2LinuxInstallAuthority *authority)
{
    if (authority == NULL) return;
    if (authority->receipt_fd >= 0) (void)close(authority->receipt_fd);
    if (authority->install_root_fd >= 0) (void)close(authority->install_root_fd);
    authority->receipt_fd = -1;
    authority->install_root_fd = -1;
    plamen_broker_v2_secure_zero(&authority->receipt,
                                 sizeof(authority->receipt));
}

static int
v2_linux_duplicate_inherited(int inherited, int *duplicate)
{
    int flags;
    *duplicate = -1;
    flags = fcntl(inherited, F_GETFD);
    if (flags < 0) return errno == EBADF ? 0 : -1;
#ifdef F_DUPFD_CLOEXEC
    *duplicate = fcntl(inherited, F_DUPFD_CLOEXEC, 3);
#else
    *duplicate = fcntl(inherited, F_DUPFD, 3);
    if (*duplicate >= 0 && v2_set_cloexec(*duplicate) != 0) {
        (void)close(*duplicate);
        *duplicate = -1;
    }
#endif
    return *duplicate >= 0 ? 1 : -1;
}

static int
v2_linux_current_extension_matches(
        const V2LinuxInstallAuthority *authority)
{
    Dl_info loaded;
    unsigned char identity[32];
    int member_fd = -1, loaded_fd = -1, result = -1;
    memset(&loaded, 0, sizeof(loaded));
    memset(identity, 0, sizeof(identity));
    if (authority == NULL ||
            plamen_linux_install_receipt_v2_open_member(
                authority->install_root_fd,
                &authority->receipt.members[
                    PLAMEN_LINUX_INSTALL_MEMBER_EXTENSION - 1U],
                &member_fd) != 0 ||
            dladdr((const void *)(uintptr_t)&v2_linux_current_extension_matches,
                   &loaded) == 0 || loaded.dli_fname == NULL ||
            loaded.dli_fname[0] != '/') {
        goto done;
    }
    loaded_fd = open(loaded.dli_fname, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (loaded_fd < 0 ||
            plamen_broker_v2_fd_identity(loaded_fd, identity) !=
                PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(identity,
                authority->receipt.members[
                    PLAMEN_LINUX_INSTALL_MEMBER_EXTENSION - 1U].fd_identity,
                32)) {
        goto done;
    }
    result = 0;
done:
    if (loaded_fd >= 0) (void)close(loaded_fd);
    if (member_fd >= 0) (void)close(member_fd);
    secure_zero(identity, sizeof(identity));
    return result;
}

static int
v2_linux_install_open(V2LinuxInstallAuthority *authority)
{
    int receipt_status, root_status, status = -1;
    memset(authority, 0, sizeof(*authority));
    authority->receipt_fd = -1;
    authority->install_root_fd = -1;
    receipt_status = v2_linux_duplicate_inherited(
        PLAMEN_LINUX_INSTALL_RECEIPT_V2_FD, &authority->receipt_fd);
    root_status = v2_linux_duplicate_inherited(
        PLAMEN_LINUX_INSTALL_ROOT_V2_FD, &authority->install_root_fd);
    if (receipt_status != 0) (void)close(PLAMEN_LINUX_INSTALL_RECEIPT_V2_FD);
    if (root_status != 0) (void)close(PLAMEN_LINUX_INSTALL_ROOT_V2_FD);
    if (receipt_status == 0 && root_status == 0) return 0;
    if (receipt_status != 1 || root_status != 1 ||
            plamen_linux_install_receipt_v2_revalidate_authority_phase1(
                authority->receipt_fd, authority->install_root_fd,
                (uint32_t)geteuid(), v2_linux_expected_provenance,
                v2_linux_expected_protocol, &authority->receipt) != 0 ||
            authority->receipt.expected_gid != (uint32_t)getegid() ||
            v2_linux_current_extension_matches(authority) != 0) {
        goto done;
    }
    status = 1;
done:
    if (status != 1) v2_linux_install_clear(authority);
    return status;
}

static int
v2_linux_write_key_and_close(int *descriptor, const unsigned char key[32])
{
    size_t offset = 0;
    if (descriptor == NULL || *descriptor < 0 || key == NULL) return -1;
    while (offset < 32U) {
        ssize_t amount;
        do {
            amount = write(*descriptor, key + offset, 32U - offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    if (close(*descriptor) != 0) {
        *descriptor = -1;
        return -1;
    }
    *descriptor = -1;
    return 0;
}

static int
v2_linux_exchange(const V2LinuxInstallAuthority *authority,
        const unsigned char *request, size_t request_size,
        const int *fds, size_t fd_count, unsigned char **reply,
        size_t *reply_size, struct plamen_broker_v2_service_envelope_view *view,
        struct plamen_broker_v2_peer_identity *service_peer)
{
    int status = plamen_broker_v2_linux_client_exchange(
        authority->receipt.scope, authority->receipt.expected_uid,
        authority->receipt.members[
            PLAMEN_LINUX_INSTALL_MEMBER_BROKER - 1U].fd_identity,
        request, request_size, fds, fd_count,
        PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION, reply, reply_size,
        view, service_peer);
    if (status == PLAMEN_BROKER_V2_OK) return 1;
    return status == PLAMEN_BROKER_V2_SYSTEM &&
        (errno == ENOENT || errno == ECONNREFUSED || errno == EAGAIN ||
         errno == ETIMEDOUT) ? 0 : -1;
}

static int
v2_linux_service_error_is_absent(
        const struct plamen_broker_v2_service_envelope_view *view,
        const unsigned char request_sha256[32], uint16_t failed_type)
{
    struct plamen_broker_v2_service_error error;
    int absent;
    memset(&error, 0, sizeof(error));
    absent = view->type == PLAMEN_BROKER_V2_SERVICE_ERROR &&
        plamen_broker_v2_service_error_decode(
            view->payload, view->payload_size, &error) ==
                PLAMEN_BROKER_V2_OK &&
        error.code == PLAMEN_BROKER_V2_SERVICE_ERR_REGISTRATION_MISSING &&
        error.failed_message_type == failed_type &&
        (error.flags &
            PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED) != 0 &&
        (error.flags &
            (PLAMEN_BROKER_V2_SERVICE_REGISTRATION_CONSUMED |
             PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED)) == 0 &&
        v2_constant_equal(error.request_envelope_sha256,
                          request_sha256, 32);
    plamen_broker_v2_secure_zero(&error, sizeof(error));
    return absent;
}

static int
v2_linux_take_initial_session(V2NativeBootstrapSession *session)
{
    V2LinuxInstallAuthority authority;
    struct plamen_broker_v2_service_linux_session_lookup lookup;
    struct plamen_broker_v2_service_linux_session_challenge challenge;
    struct plamen_broker_v2_service_linux_session_open open_request;
    struct plamen_broker_v2_service_linux_session_ack acknowledgement;
    struct plamen_broker_v2_service_envelope_view reply_view;
    struct plamen_broker_v2_peer_identity service_peer, current_peer;
    struct plamen_broker_v2_commitment commitment;
    unsigned char receipt_binding[32];
    unsigned char lookup_payload[
        PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP_SIZE];
    unsigned char open_payload[
        PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN_SIZE];
    unsigned char transaction_nonce[32], invocation_nonce[32];
    unsigned char lookup_sha256[32], open_sha256[32], key[32], zeros[32] = {0};
    static const unsigned char managed_custody_domain[] =
        "PLAMEN-MANAGED-EVM-TOOLCHAIN-CUSTODY-V1\0";
    unsigned char managed_custody_preimage[
        sizeof(managed_custody_domain) - 1U + 128U];
    unsigned char *lookup_envelope = NULL, *open_envelope = NULL, *reply = NULL;
    size_t lookup_envelope_size = 0, open_envelope_size = 0, reply_size = 0;
    size_t attempt_size;
    int sockets[2] = {-1, -1}, key_pipe[2] = {-1, -1}, transfer_fds[2];
    int exchange_status, install_status, status = -1;

    memset(&authority, 0, sizeof(authority));
    authority.receipt_fd = authority.install_root_fd = -1;
    memset(&lookup, 0, sizeof(lookup));
    memset(&challenge, 0, sizeof(challenge));
    memset(&open_request, 0, sizeof(open_request));
    memset(&acknowledgement, 0, sizeof(acknowledgement));
    memset(&reply_view, 0, sizeof(reply_view));
    memset(&service_peer, 0, sizeof(service_peer));
    memset(&current_peer, 0, sizeof(current_peer));
    memset(&commitment, 0, sizeof(commitment));
    memset(receipt_binding, 0, sizeof(receipt_binding));
    memset(transaction_nonce, 0, sizeof(transaction_nonce));
    memset(invocation_nonce, 0, sizeof(invocation_nonce));
    memset(lookup_sha256, 0, sizeof(lookup_sha256));
    memset(open_sha256, 0, sizeof(open_sha256));
    memset(key, 0, sizeof(key));
    memset(managed_custody_preimage, 0, sizeof(managed_custody_preimage));
    memset(lookup_payload, 0, sizeof(lookup_payload));
    memset(open_payload, 0, sizeof(open_payload));
    install_status = v2_linux_install_open(&authority);
    if (install_status != 1) return install_status;
    if (plamen_linux_install_receipt_v2_session_binding(
            &authority.receipt, receipt_binding) != 0) goto done;
    lookup.version = PLAMEN_BROKER_V2_LINUX_SESSION_ABI_VERSION;
    lookup.scope = authority.receipt.scope;
    lookup.expected_uid = authority.receipt.expected_uid;
    lookup.expected_gid = authority.receipt.expected_gid;
    memcpy(lookup.install_receipt_sha256, authority.receipt.receipt_sha256, 32);
    memcpy(lookup.receipt_session_binding_sha256, receipt_binding, 32);
    memcpy(lookup.native_deployment_receipt_sha256,
           authority.receipt.native_deployment_receipt_sha256, 32);
    memcpy(lookup.service_bootstrap_sha256,
           authority.receipt.members[
               PLAMEN_LINUX_INSTALL_MEMBER_SERVICE_BOOTSTRAP - 1U].sha256, 32);
    memcpy(lookup.base.extension_closure_sha256,
           authority.receipt.members[
               PLAMEN_LINUX_INSTALL_MEMBER_EXTENSION - 1U].sha256, 32);
    memcpy(lookup.base.interpreter_executable_sha256,
           authority.receipt.members[
               PLAMEN_LINUX_INSTALL_MEMBER_INTERPRETER - 1U].sha256, 32);
    if (v2_random(lookup.base.session_id, 32) != 0 ||
            v2_random(transaction_nonce, 32) != 0 ||
            v2_random(invocation_nonce, 32) != 0 ||
            v2_constant_equal(lookup.base.session_id, zeros, 32) ||
            plamen_broker_v2_service_linux_session_lookup_encode(
                &lookup, lookup_payload) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_envelope_build(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP,
                transaction_nonce, invocation_nonce, lookup_payload,
                sizeof(lookup_payload), 0, &lookup_envelope,
                &lookup_envelope_size) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_sha256(lookup_envelope, lookup_envelope_size,
                                    lookup_sha256) != PLAMEN_BROKER_V2_OK) {
        goto done;
    }
    exchange_status = v2_linux_exchange(&authority, lookup_envelope,
        lookup_envelope_size, NULL, 0, &reply, &reply_size, &reply_view,
        &service_peer);
    if (exchange_status != 1) { status = exchange_status; goto done; }
    if (!v2_constant_equal(reply_view.transaction_nonce,
                           transaction_nonce, 32) ||
            !v2_constant_equal(reply_view.invocation_nonce,
                               invocation_nonce, 32)) goto done;
    if (reply_view.type == PLAMEN_BROKER_V2_SERVICE_ERROR) {
        status = v2_linux_service_error_is_absent(&reply_view, lookup_sha256,
            PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP) ? 0 : -1;
        goto done;
    }
    if (reply_view.type != PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE ||
            plamen_broker_v2_service_linux_session_challenge_decode(
                reply_view.payload, reply_view.payload_size, &challenge) !=
                    PLAMEN_BROKER_V2_OK ||
            !plamen_broker_v2_service_linux_session_challenge_matches_lookup(
                &lookup, lookup_sha256, &challenge) ||
            challenge.base.initial_interpreter_slot != 0 ||
            (challenge.base.initial_authority_role !=
                PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR &&
             challenge.base.initial_authority_role !=
                PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER) ||
            !v2_constant_equal(challenge.base.installed_closure_sha256,
                authority.receipt.installed_closure_sha256, 32) ||
            !v2_constant_equal(challenge.base.broker_closure_sha256,
                authority.receipt.members[
                    PLAMEN_LINUX_INSTALL_MEMBER_BROKER - 1U].sha256, 32) ||
            plamen_broker_v2_linux_current_peer(
                authority.receipt.expected_uid,
                authority.receipt.members[
                    PLAMEN_LINUX_INSTALL_MEMBER_INTERPRETER - 1U].fd_identity,
                &current_peer) != PLAMEN_BROKER_V2_OK ||
            memcmp(&challenge.base.extension_peer, &current_peer,
                   sizeof(current_peer)) != 0 ||
            plamen_broker_v2_auth_consume_matches_challenge(
                &challenge.base, challenge.base.commitment,
                challenge.base.commitment_size, &commitment) !=
                    PLAMEN_BROKER_V2_OK) goto done;
    attempt_size = strnlen(commitment.attempt_id, sizeof(commitment.attempt_id));
    if (attempt_size == 0 || attempt_size > PLAMEN_BROKER_V2_MAX_ID ||
            !v2_ascii_id_valid(commitment.attempt_id, attempt_size) ||
            challenge.base.request_projection_size == 0 ||
            challenge.base.request_projection_size >
                PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX ||
            socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0 ||
            pipe2(key_pipe, O_CLOEXEC) != 0 ||
            v2_prepare_control_fd(sockets[0]) != 0 ||
            v2_prepare_control_fd(sockets[1]) != 0 ||
            v2_random(key, 32) != 0 || v2_constant_equal(key, zeros, 32)) {
        goto done;
    }
    open_request.version = lookup.version;
    open_request.scope = lookup.scope;
    open_request.expected_uid = lookup.expected_uid;
    open_request.expected_gid = lookup.expected_gid;
    memcpy(open_request.install_receipt_sha256,
           lookup.install_receipt_sha256, 32);
    memcpy(open_request.receipt_session_binding_sha256,
           lookup.receipt_session_binding_sha256, 32);
    memcpy(open_request.native_deployment_receipt_sha256,
           challenge.native_deployment_receipt_sha256, 32);
    memcpy(open_request.service_bootstrap_sha256,
           lookup.service_bootstrap_sha256, 32);
    memcpy(open_request.base.challenge_envelope_sha256,
           reply_view.envelope_sha256, 32);
    memcpy(open_request.base.challenge_nonce,
           challenge.base.challenge_nonce, 32);
    memcpy(open_request.base.commitment_sha256,
           challenge.base.commitment_sha256, 32);
    memcpy(open_request.base.registration_sha256,
           challenge.base.registration_sha256, 32);
    memcpy(open_request.base.committed_audit_generation_sha256,
           challenge.base.committed_audit_generation_sha256, 32);
    memcpy(open_request.base.extension_closure_sha256,
           challenge.base.extension_closure_sha256, 32);
    memcpy(open_request.base.interpreter_executable_sha256,
           challenge.base.interpreter_executable_sha256, 32);
    open_request.base.extension_peer = current_peer;
    open_request.base.initial_interpreter_slot =
        challenge.base.initial_interpreter_slot;
    open_request.base.initial_authority_role =
        challenge.base.initial_authority_role;
    memcpy(open_request.base.session_id, challenge.base.session_id, 32);
    open_request.base.descriptors[0].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET;
    open_request.base.descriptors[0].target = 0;
    open_request.base.descriptors[0].access_mode =
        PLAMEN_BROKER_V2_FD_READ_WRITE;
    open_request.base.descriptors[1].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ;
    open_request.base.descriptors[1].target = 1;
    open_request.base.descriptors[1].access_mode = PLAMEN_BROKER_V2_FD_READ;
    if (plamen_broker_v2_fd_identity(sockets[1],
            open_request.base.descriptors[0].identity) !=
                PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_fd_identity(key_pipe[0],
            open_request.base.descriptors[1].identity) !=
                PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_linux_session_open_encode(
                &open_request, open_payload) != PLAMEN_BROKER_V2_OK ||
            !plamen_broker_v2_service_linux_session_open_matches_challenge(
                &challenge, reply_view.envelope_sha256, &open_request) ||
            v2_random(transaction_nonce, 32) != 0 ||
            v2_random(invocation_nonce, 32) != 0 ||
            plamen_broker_v2_service_envelope_build(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN,
                transaction_nonce, invocation_nonce, open_payload,
                sizeof(open_payload), 2, &open_envelope,
                &open_envelope_size) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_sha256(open_envelope, open_envelope_size,
                                    open_sha256) != PLAMEN_BROKER_V2_OK ||
            v2_linux_write_key_and_close(&key_pipe[1], key) != 0) goto done;
    secure_zero(reply, reply_size); free(reply); reply = NULL; reply_size = 0;
    memset(&reply_view, 0, sizeof(reply_view));
    transfer_fds[0] = sockets[1]; transfer_fds[1] = key_pipe[0];
    exchange_status = v2_linux_exchange(&authority, open_envelope,
        open_envelope_size, transfer_fds, 2, &reply, &reply_size, &reply_view,
        &service_peer);
    (void)close(sockets[1]); sockets[1] = -1;
    (void)close(key_pipe[0]); key_pipe[0] = -1;
    if (exchange_status != 1 ||
            reply_view.type != PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACCEPTED ||
            !v2_constant_equal(reply_view.transaction_nonce,
                               transaction_nonce, 32) ||
            !v2_constant_equal(reply_view.invocation_nonce,
                               invocation_nonce, 32) ||
            plamen_broker_v2_service_linux_session_ack_decode(
                reply_view.payload, reply_view.payload_size,
                &acknowledgement) != PLAMEN_BROKER_V2_OK ||
            !plamen_broker_v2_service_linux_session_ack_matches_open(
                &open_request, open_sha256, &acknowledgement) ||
            plamen_linux_install_receipt_v2_revalidate_authority(
                authority.receipt_fd, authority.install_root_fd,
                authority.receipt.scope, authority.receipt.expected_uid,
                authority.receipt.expected_gid,
                v2_linux_expected_provenance,
                v2_linux_expected_protocol,
                challenge.native_deployment_receipt_sha256,
                &authority.receipt) != 0 ||
            v2_linux_current_extension_matches(&authority) != 0) goto done;
    memcpy(managed_custody_preimage, managed_custody_domain,
           sizeof(managed_custody_domain) - 1U);
    memcpy(managed_custody_preimage + sizeof(managed_custody_domain) - 1U,
           authority.receipt.receipt_sha256, 32);
    memcpy(managed_custody_preimage + sizeof(managed_custody_domain) - 1U + 32U,
           commitment.runtime_closure_sha256, 32);
    memcpy(managed_custody_preimage + sizeof(managed_custody_domain) - 1U + 64U,
           commitment.provider_provenance_sha256, 32);
    memcpy(managed_custody_preimage + sizeof(managed_custody_domain) - 1U + 96U,
           challenge.base.broker_closure_sha256, 32);
    if (plamen_broker_v2_sha256(managed_custody_preimage,
            sizeof(managed_custody_preimage),
            session->managed_toolchain_custody_sha256) !=
                PLAMEN_BROKER_V2_OK) goto done;
    session->control_fd = sockets[0]; sockets[0] = -1;
    session->initial_authority_role = challenge.base.initial_authority_role;
    memcpy(session->key, key, 32);
    memcpy(session->session_id, challenge.base.session_id, 32);
    memcpy(session->fingerprint, commitment.request_fingerprint, 32);
    memcpy(session->registration_sha256,
           challenge.base.registration_sha256, 32);
    memcpy(session->issuance_checkpoint_sha256,
           acknowledgement.base.registration_burn_checkpoint_sha256, 32);
    memcpy(session->authority_bundle_sha256,
           acknowledgement.base.authority_bundle_sha256, 32);
    memcpy(session->request_projection_sha256,
           challenge.base.request_projection_sha256, 32);
    memcpy(session->native_deployment_receipt_sha256,
           challenge.native_deployment_receipt_sha256, 32);
    memcpy(session->runtime_closure_sha256,
           commitment.runtime_closure_sha256, 32);
    memcpy(session->broker_peer_identity_sha256,
           challenge.base.broker_closure_sha256, 32);
    memcpy(session->extension_closure_sha256,
           lookup.base.extension_closure_sha256, 32);
    memcpy(session->interpreter_executable_sha256,
           lookup.base.interpreter_executable_sha256, 32);
    session->request_projection_size = challenge.base.request_projection_size;
    memcpy(session->attempt, commitment.attempt_id, attempt_size + 1U);
    session->attempt_size = attempt_size;
    memcpy(session->auth_payload, challenge.base.commitment,
           challenge.base.commitment_size);
    session->auth_payload_size = challenge.base.commitment_size;
    session->linux_scope = authority.receipt.scope;
    session->linux_expected_uid = authority.receipt.expected_uid;
    memcpy(session->linux_broker_executable_identity,
           authority.receipt.members[
               PLAMEN_LINUX_INSTALL_MEMBER_BROKER - 1U].fd_identity, 32);
    memcpy(session->linux_interpreter_executable_identity,
           authority.receipt.members[
               PLAMEN_LINUX_INSTALL_MEMBER_INTERPRETER - 1U].fd_identity, 32);
    status = 1;
done:
    if (reply != NULL) { secure_zero(reply, reply_size); free(reply); }
    if (lookup_envelope != NULL) {
        secure_zero(lookup_envelope, lookup_envelope_size); free(lookup_envelope);
    }
    if (open_envelope != NULL) {
        secure_zero(open_envelope, open_envelope_size); free(open_envelope);
    }
    v2_close_fds(sockets, 2); v2_close_fds(key_pipe, 2);
    if (status != 1) v2_native_bootstrap_clear(session);
    v2_linux_install_clear(&authority);
    secure_zero(receipt_binding, sizeof(receipt_binding));
    secure_zero(transaction_nonce, sizeof(transaction_nonce));
    secure_zero(invocation_nonce, sizeof(invocation_nonce));
    secure_zero(lookup_sha256, sizeof(lookup_sha256));
    secure_zero(open_sha256, sizeof(open_sha256));
    secure_zero(key, sizeof(key));
    secure_zero(managed_custody_preimage, sizeof(managed_custody_preimage));
    plamen_broker_v2_secure_zero(&lookup, sizeof(lookup));
    plamen_broker_v2_secure_zero(&challenge, sizeof(challenge));
    plamen_broker_v2_secure_zero(&open_request, sizeof(open_request));
    plamen_broker_v2_secure_zero(&acknowledgement, sizeof(acknowledgement));
    plamen_broker_v2_secure_zero(&reply_view, sizeof(reply_view));
    plamen_broker_v2_secure_zero(&service_peer, sizeof(service_peer));
    plamen_broker_v2_secure_zero(&current_peer, sizeof(current_peer));
    plamen_broker_v2_secure_zero(&commitment, sizeof(commitment));
    return status;
}

static int
v2_linux_take_specialized_session_once(
        const V2NativeBootstrapSession *parent, uint16_t lane,
        BridgeSpecializedSession **result)
{
    struct plamen_broker_v2_service_specialized_session_lookup lookup;
    struct plamen_broker_v2_service_specialized_session_challenge challenge;
    struct plamen_broker_v2_service_specialized_session_open open_request;
    struct plamen_broker_v2_service_specialized_session_ack acknowledgement;
    struct plamen_broker_v2_service_envelope_view view;
    struct plamen_broker_v2_peer_identity service_peer;
    unsigned char lookup_payload[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP_SIZE];
    unsigned char open_payload[
        PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE];
    unsigned char transaction_nonce[32], invocation_nonce[32], key[32];
    unsigned char lookup_sha256[32], open_sha256[32], expected_binding[32];
    unsigned char *lookup_envelope = NULL, *open_envelope = NULL, *reply = NULL;
    size_t lookup_envelope_size = 0, open_envelope_size = 0, reply_size = 0;
    int sockets[2] = {-1, -1}, key_pipe[2] = {-1, -1}, transfer_fds[2];
    BridgeSpecializedSession *session = NULL;
    int exchange_status, status = -1;
    V2LinuxInstallAuthority transport;

    *result = NULL;
    memset(&lookup, 0, sizeof(lookup)); memset(&challenge, 0, sizeof(challenge));
    memset(&open_request, 0, sizeof(open_request));
    memset(&acknowledgement, 0, sizeof(acknowledgement));
    memset(&view, 0, sizeof(view)); memset(&service_peer, 0, sizeof(service_peer));
    memset(&transport, 0, sizeof(transport));
    memset(transaction_nonce, 0, 32); memset(invocation_nonce, 0, 32);
    memset(key, 0, 32); memset(lookup_sha256, 0, 32);
    memset(open_sha256, 0, 32); memset(expected_binding, 0, 32);
    if (parent == NULL || parent->control_fd < 0 ||
            parent->linux_expected_uid != (uint64_t)geteuid() ||
            lane < PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER ||
            lane > PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL) return -1;
    transport.receipt.scope = parent->linux_scope;
    transport.receipt.expected_uid = (uint32_t)parent->linux_expected_uid;
    memcpy(transport.receipt.members[
        PLAMEN_LINUX_INSTALL_MEMBER_BROKER - 1U].fd_identity,
        parent->linux_broker_executable_identity, 32);
    lookup.version = PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION;
    lookup.lane = lane;
    memcpy(lookup.parent_session_id, parent->session_id, 32);
    memcpy(lookup.registration_sha256, parent->registration_sha256, 32);
    memcpy(lookup.authority_bundle_sha256, parent->authority_bundle_sha256, 32);
    memcpy(lookup.extension_closure_sha256,
           parent->extension_closure_sha256, 32);
    memcpy(lookup.interpreter_executable_sha256,
           parent->interpreter_executable_sha256, 32);
    if (v2_random(lookup.specialized_session_id, 32) != 0 ||
            v2_random(transaction_nonce, 32) != 0 ||
            v2_random(invocation_nonce, 32) != 0 ||
            plamen_broker_v2_service_specialized_session_lookup_encode(
                &lookup, lookup_payload) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_envelope_build(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP,
                transaction_nonce, invocation_nonce, lookup_payload,
                sizeof(lookup_payload), 0, &lookup_envelope,
                &lookup_envelope_size) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_sha256(lookup_envelope, lookup_envelope_size,
                                    lookup_sha256) != PLAMEN_BROKER_V2_OK)
        goto done;
    exchange_status = v2_linux_exchange(&transport, lookup_envelope,
        lookup_envelope_size, NULL, 0, &reply, &reply_size, &view,
        &service_peer);
    if (exchange_status != 1) { status = exchange_status; goto done; }
    if (view.type != PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE ||
            !v2_constant_equal(view.transaction_nonce, transaction_nonce, 32) ||
            !v2_constant_equal(view.invocation_nonce, invocation_nonce, 32) ||
            plamen_broker_v2_service_specialized_session_challenge_decode(
                view.payload, view.payload_size, &challenge) !=
                    PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(challenge.request_envelope_sha256,
                               lookup_sha256, 32) ||
            memcmp(&challenge.lookup, &lookup, sizeof(lookup)) != 0 ||
            !v2_constant_equal(challenge.broker_closure_sha256,
                               parent->broker_peer_identity_sha256, 32) ||
            plamen_broker_v2_linux_current_peer(parent->linux_expected_uid,
                parent->linux_interpreter_executable_identity,
                &open_request.extension_peer) != PLAMEN_BROKER_V2_OK ||
            memcmp(&challenge.extension_peer, &open_request.extension_peer,
                   sizeof(challenge.extension_peer)) != 0 ||
            socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0 ||
            pipe2(key_pipe, O_CLOEXEC) != 0 ||
            v2_prepare_control_fd(sockets[0]) != 0 ||
            v2_prepare_control_fd(sockets[1]) != 0 ||
            v2_random(key, 32) != 0) goto done;
    memcpy(open_request.challenge_envelope_sha256, view.envelope_sha256, 32);
    memcpy(open_request.challenge_nonce, challenge.challenge_nonce, 32);
    open_request.version = PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION;
    open_request.lane = lane;
    memcpy(open_request.parent_session_id, parent->session_id, 32);
    memcpy(open_request.specialized_session_id,
           lookup.specialized_session_id, 32);
    open_request.descriptors[0].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET;
    open_request.descriptors[0].target = 0;
    open_request.descriptors[0].access_mode = PLAMEN_BROKER_V2_FD_READ_WRITE;
    open_request.descriptors[1].purpose =
        PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ;
    open_request.descriptors[1].target = 1;
    open_request.descriptors[1].access_mode = PLAMEN_BROKER_V2_FD_READ;
    if (plamen_broker_v2_fd_identity(sockets[1],
            open_request.descriptors[0].identity) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_fd_identity(key_pipe[0],
            open_request.descriptors[1].identity) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_service_specialized_session_open_encode(
                &open_request, open_payload) != PLAMEN_BROKER_V2_OK ||
            v2_random(transaction_nonce, 32) != 0 ||
            v2_random(invocation_nonce, 32) != 0 ||
            plamen_broker_v2_service_envelope_build(
                PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION,
                PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN,
                transaction_nonce, invocation_nonce, open_payload,
                sizeof(open_payload), 2, &open_envelope,
                &open_envelope_size) != PLAMEN_BROKER_V2_OK ||
            plamen_broker_v2_sha256(open_envelope, open_envelope_size,
                                    open_sha256) != PLAMEN_BROKER_V2_OK ||
            v2_linux_write_key_and_close(&key_pipe[1], key) != 0) goto done;
    secure_zero(reply, reply_size); free(reply); reply = NULL; reply_size = 0;
    memset(&view, 0, sizeof(view));
    transfer_fds[0] = sockets[1]; transfer_fds[1] = key_pipe[0];
    exchange_status = v2_linux_exchange(&transport, open_envelope,
        open_envelope_size, transfer_fds, 2, &reply, &reply_size, &view,
        &service_peer);
    (void)close(sockets[1]); sockets[1] = -1;
    (void)close(key_pipe[0]); key_pipe[0] = -1;
    if (exchange_status != 1 ||
            view.type != PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACCEPTED ||
            !v2_constant_equal(view.transaction_nonce, transaction_nonce, 32) ||
            !v2_constant_equal(view.invocation_nonce, invocation_nonce, 32) ||
            plamen_broker_v2_service_specialized_session_ack_decode(
                view.payload, view.payload_size, &acknowledgement) !=
                    PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(acknowledgement.request_envelope_sha256,
                               open_sha256, 32) ||
            acknowledgement.version != PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION ||
            acknowledgement.lane != lane ||
            !v2_constant_equal(acknowledgement.parent_session_id,
                               parent->session_id, 32) ||
            !v2_constant_equal(acknowledgement.specialized_session_id,
                               lookup.specialized_session_id, 32) ||
            plamen_broker_v2_specialized_session_binding(key,
                parent->session_id, lookup.specialized_session_id, lane,
                acknowledgement.authority_binding_sha256,
                expected_binding) != PLAMEN_BROKER_V2_OK ||
            !v2_constant_equal(acknowledgement.session_binding_sha256,
                               expected_binding, 32)) goto done;
    session = calloc(1, sizeof(*session));
    if (session == NULL) goto done;
    atomic_init(&session->references, 1U);
    session->operation_lock = PyThread_allocate_lock();
    if (session->operation_lock == NULL) goto done;
    session->creator_pid = getpid();
    session->creator_interpreter_id = current_interpreter_id();
    session->control_fd = sockets[0]; sockets[0] = -1;
    session->lane = lane;
    memcpy(session->key, key, 32);
    memcpy(session->session_id, lookup.specialized_session_id, 32);
    memcpy(session->authority_binding_sha256,
           acknowledgement.authority_binding_sha256, 32);
    *result = session; session = NULL; status = 1;
done:
    if (reply != NULL) { secure_zero(reply, reply_size); free(reply); }
    if (lookup_envelope != NULL) {
        secure_zero(lookup_envelope, lookup_envelope_size); free(lookup_envelope);
    }
    if (open_envelope != NULL) {
        secure_zero(open_envelope, open_envelope_size); free(open_envelope);
    }
    v2_close_fds(sockets, 2); v2_close_fds(key_pipe, 2);
    bridge_specialized_session_release(session);
    secure_zero(transaction_nonce, 32); secure_zero(invocation_nonce, 32);
    secure_zero(key, 32); secure_zero(lookup_sha256, 32);
    secure_zero(open_sha256, 32); secure_zero(expected_binding, 32);
    plamen_broker_v2_secure_zero(&lookup, sizeof(lookup));
    plamen_broker_v2_secure_zero(&challenge, sizeof(challenge));
    plamen_broker_v2_secure_zero(&open_request, sizeof(open_request));
    plamen_broker_v2_secure_zero(&acknowledgement, sizeof(acknowledgement));
    return status;
}

static int
v2_linux_take_specialized_session(const V2NativeBootstrapSession *parent,
        uint16_t lane, BridgeSpecializedSession **result)
{
    int status = v2_linux_take_specialized_session_once(parent, lane, result);
    return status != 0 ? status :
        v2_linux_take_specialized_session_once(parent, lane, result);
}

#endif /* __linux__ */

#if !defined(PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY) && \
        !defined(PLAMEN_NATIVE_INSTALLED_BACKEND_GENERATION_ENABLED)
static PyObject *
acquire_backend_install_generation(PyObject *module, PyObject *args)
{
    (void)module;
    (void)args;
    PyErr_SetString(PyExc_RuntimeError,
                    "installed backend generation authority is unavailable "
                    "without an authenticated platform role10 projection");
    return NULL;
}

static PyObject *
project_backend_install_generation(PyObject *module, PyObject *args)
{
    (void)module;
    (void)args;
    PyErr_SetString(PyExc_RuntimeError,
                    "installed backend generation authority is unavailable "
                    "without an authenticated platform role10 projection");
    return NULL;
}
#endif

/*
 * Fail-closed platform boundary.  The authenticated XPC/Linux service client
 * is not linked until the shared bootstrap ABI, installed receipt closure, and
 * service-side SESSION_OPEN authority issuance are jointly frozen.  Replace
 * only this function once that admitted native transport exists.  Return 1
 * with every field populated after the launcher registration has been
 * atomically burned, 0 when no registration or admitted service exists, and
 * -1 for a malformed/authentication failure.
 */
static int
v2_platform_take_initial_session(V2NativeBootstrapSession *session)
{
#ifdef __APPLE__
    return v2_darwin_take_initial_session(session);
#elif defined(__linux__)
    return v2_linux_take_initial_session(session);
#else
    (void)session;
    return 0;
#endif
}

static int
v2_publish_initial_authority(PyObject *module, int *available)
{
    V2NativeBootstrapSession session;
    PyObject *consumer;
    int acquired;

    *available = 0;
    if (atomic_exchange_explicit(&v2_initial_acquisition_attempted, 1,
                                 memory_order_acq_rel) != 0) {
        return 0;
    }
    memset(&session, 0, sizeof(session));
    session.control_fd = -1;
    acquired = v2_platform_take_initial_session(&session);
    if (acquired == 0) {
        v2_native_bootstrap_clear(&session);
        return 0;
    }
    if (acquired != 1) {
        v2_native_bootstrap_clear(&session);
        PyErr_SetString(PyExc_ImportError,
                        "native broker v2 bootstrap authentication failed");
        return -1;
    }
#if defined(__APPLE__) || defined(__linux__)
    {
#ifdef __APPLE__
#define V2_TAKE_SPECIALIZED v2_darwin_take_specialized_session
#else
#define V2_TAKE_SPECIALIZED v2_linux_take_specialized_session
#endif
        int js_status = V2_TAKE_SPECIALIZED(
            &session, PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER,
            &bridge_js_session);
        int managed_status = js_status != 1 ? js_status :
            V2_TAKE_SPECIALIZED(
                &session, PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM,
                &bridge_managed_session);
        int projection_status = managed_status != 1 ? managed_status :
            V2_TAKE_SPECIALIZED(
                &session, PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION,
                &bridge_projection_session);
        int snapshot_status = projection_status != 1 ? projection_status :
            V2_TAKE_SPECIALIZED(
                &session, PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
                &bridge_snapshot_session);
        if (js_status != 1 || managed_status != 1 ||
                projection_status != 1 || snapshot_status != 1) {
            bridge_specialized_session_release(bridge_js_session);
            bridge_specialized_session_release(bridge_managed_session);
            bridge_specialized_session_release(bridge_projection_session);
            bridge_specialized_session_release(bridge_snapshot_session);
            bridge_js_session = NULL;
            bridge_managed_session = NULL;
            bridge_projection_session = NULL;
            bridge_snapshot_session = NULL;
            v2_native_bootstrap_clear(&session);
            PyErr_SetString(PyExc_ImportError,
                            "native specialized session authentication failed");
            return -1;
        }
#undef V2_TAKE_SPECIALIZED
    }
#endif
    consumer = v2_new_consumer_from_native_session(
        session.control_fd, -1, session.initial_authority_role,
        session.key, session.session_id,
        session.operation_nonce, session.fingerprint, session.attempt,
        session.attempt_size, session.auth_payload,
        session.auth_payload_size, session.registration_sha256,
        session.issuance_checkpoint_sha256,
        session.authority_bundle_sha256,
        session.request_projection_sha256,
        session.request_projection_size,
        session.native_deployment_receipt_sha256,
        session.runtime_closure_sha256,
        session.broker_peer_identity_sha256,
        session.managed_toolchain_custody_sha256);
    session.control_fd = -1;
    v2_native_bootstrap_clear(&session);
    if (consumer == NULL) {
        if (!PyErr_Occurred()) {
            PyErr_SetString(PyExc_ImportError,
                            "native broker v2 bootstrap session is invalid");
        }
        return -1;
    }
    if (bridge_publish_bootstrap_authorities(module, consumer) < 0) {
        Py_DECREF(consumer);
        return -1;
    }
    if (PyModule_AddObject(module, "INITIAL_AUTHORITY", consumer) < 0) {
        Py_DECREF(consumer);
        return -1;
    }
    *available = 1;
    return 0;
}

static PyMethodDef v2_production_consumer_methods[] = {
    {"request_projection", v2_request_projection, METH_NOARGS,
     PyDoc_STR("Return authenticated immutable request projection bytes.")},
    {"consume_once", v2_consume_once, METH_VARARGS,
     PyDoc_STR("Consume an authenticated broker v2 authority exactly once.")},
    {"__copy__", consumer_forbidden_copy, METH_NOARGS, NULL},
    {"__deepcopy__", consumer_forbidden_deepcopy, METH_VARARGS, NULL},
    {"__reduce__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__reduce_ex__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {"__getnewargs__", consumer_forbidden_reduce, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyTypeObject V2AuthorityConsumerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PLAMEN_V2_CONSUMER_TYPE_NAME,
    .tp_basicsize = sizeof(V2AuthorityConsumerObject),
    .tp_dealloc = v2_consumer_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_DISALLOW_INSTANTIATION,
    .tp_doc = PyDoc_STR("Opaque broker v2 initial authority consumer."),
    .tp_methods = v2_production_consumer_methods,
    .tp_repr = opaque_capability_repr,
    .tp_new = consumer_forbidden_new,
};
#endif

static struct PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    .m_name = PLAMEN_MODULE_NAME,
    .m_doc = "Native one-shot authority-consumption boundary for Plamen.",
    .m_size = -1,
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    .m_methods = test_only_module_methods,
#else
    .m_methods = production_module_methods,
#endif
};

static int
add_integer_constant(PyObject *module, const char *name, unsigned long value)
{
    PyObject *number = PyLong_FromUnsignedLong(value);
    if (number == NULL) {
        return -1;
    }
    if (PyModule_AddObject(module, name, number) < 0) {
        Py_DECREF(number);
        return -1;
    }
    return 0;
}

static int
add_type_constant(PyObject *module, const char *name, PyTypeObject *type)
{
    Py_INCREF(type);
    if (PyModule_AddObject(module, name, (PyObject *)type) < 0) {
        Py_DECREF(type);
        return -1;
    }
    return 0;
}

PyMODINIT_FUNC
PLAMEN_MODULE_INIT(void)
{
    PyObject *module;
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    int initial_authority_available = 0;
#endif

#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    if (PyType_Ready(&NativeAuthorityConsumerType) < 0) {
        return NULL;
    }
#endif
    if (PyType_Ready(&V2AuthorityConsumerType) < 0 ||
            PyType_Ready(&V2AuthorityBundleType) < 0 ||
            PyType_Ready(&V2GuestAuthorityBundleType) < 0 ||
            PyType_Ready(&V2RuntimeAuthorityType) < 0 ||
            PyType_Ready(&V2WorkspaceAuthorityType) < 0 ||
            PyType_Ready(&V2BackendAuthorityType) < 0 ||
            PyType_Ready(&V2ProviderAuthorityType) < 0 ||
            PyType_Ready(&V2GuestAdmissionAuthorityType) < 0 ||
            PyType_Ready(&V2ExtinctionAuthorityType) < 0 ||
            PyType_Ready(&V2ArtifactAuthorityType) < 0 ||
            PyType_Ready(&V2ExportAuthorityType) < 0 ||
            PyType_Ready(&V2JournalAuthorityType) < 0 ||
            PyType_Ready(&V2RecoveryAuthorityType) < 0 ||
            PyType_Ready(&V2BackendExecutionAuthorityType) < 0 ||
            PyType_Ready(&V2SupervisorAuthorityType) < 0 ||
            PyType_Ready(&V2ProcessReceiptType) < 0 ||
            PyType_Ready(&V2ExitReceiptType) < 0 ||
            PyType_Ready(&V2NetworkReceiptType) < 0 ||
            PyType_Ready(&JSDependencyMaterializerAuthorityType) < 0 ||
            PyType_Ready(&JSDependencyMaterializerSessionLeaseType) < 0 ||
            PyType_Ready(&JSDependencyMaterializerExecutionLeaseType) < 0 ||
            PyType_Ready(&JSDependencyMaterializerTerminalReplayLeaseType) < 0 ||
            PyType_Ready(&ManagedEVMToolchainInitialAuthorityType) < 0 ||
            PyType_Ready(&ManagedEVMToolchainProvisionLeaseType) < 0 ||
            PyType_Ready(&ManagedEVMToolchainProvisionTerminalType) < 0 ||
            PyType_Ready(&EVMAnalysisProjectionAuthorityType) < 0 ||
            PyType_Ready(&DarwinToolCustodyAuthorityType) < 0 ||
            PyType_Ready(&DarwinToolExecutionLeaseType) < 0 ||
            PyType_Ready(&DarwinToolExecutionTerminalType) < 0 ||
            PyType_Ready(&AppleFuzzServiceSessionAuthorityType) < 0 ||
            PyType_Ready(&AppleFuzzAdmissionContinuationLeaseType) < 0 ||
            PyType_Ready(&AppleFuzzLifecycleTerminalType) < 0 ||
            PyType_Ready(&BackendInstallGenerationAuthorityType) < 0) {
        return NULL;
    }
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    if (PyType_Ready(&TestOnlyNativeAuthorityConsumerType) < 0) {
        return NULL;
    }
#endif
    module = PyModule_Create(&module_definition);
    if (module == NULL) {
        return NULL;
    }
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    Py_INCREF(&NativeAuthorityConsumerType);
    if (PyModule_AddObject(module, "NativeAuthorityConsumer",
                           (PyObject *)&NativeAuthorityConsumerType) < 0) {
        Py_DECREF(&NativeAuthorityConsumerType);
        Py_DECREF(module);
        return NULL;
    }
    Py_INCREF(&TestOnlyNativeAuthorityConsumerType);
    if (PyModule_AddObject(
            module, "TEST_ONLY_NativeAuthorityConsumer",
            (PyObject *)&TestOnlyNativeAuthorityConsumerType) < 0) {
        Py_DECREF(&TestOnlyNativeAuthorityConsumerType);
        Py_DECREF(module);
        return NULL;
    }
#else
    if (add_type_constant(module, "NativeAuthorityConsumer",
                          &V2AuthorityConsumerType) < 0) {
        Py_DECREF(module);
        return NULL;
    }
#endif
    if (
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
            add_type_constant(module, "TEST_ONLY_BrokerV2AuthorityConsumer",
                              &V2AuthorityConsumerType) < 0 ||
            add_type_constant(module, "TEST_ONLY_SupervisorAuthorities",
                              &V2AuthorityBundleType) < 0 ||
            add_type_constant(module, "TEST_ONLY_GuestDriverAuthorities",
                              &V2GuestAuthorityBundleType) < 0 ||
            add_type_constant(module, "TEST_ONLY_RuntimeImageAuthority",
                              &V2RuntimeAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_WorkspaceAuthority",
                              &V2WorkspaceAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_BackendContextAuthority",
                              &V2BackendAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_ProviderAuthority",
                              &V2ProviderAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_GuestAdmissionAuthority",
                              &V2GuestAdmissionAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_ExtinctionAuthority",
                              &V2ExtinctionAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_ArtifactAuthority",
                              &V2ArtifactAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_ExportAuthority",
                              &V2ExportAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_JournalAuthority",
                              &V2JournalAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_RecoveryAuthority",
                              &V2RecoveryAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_BackendExecutionAuthority",
                              &V2BackendExecutionAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_SupervisorAuthority",
                              &V2SupervisorAuthorityType) < 0 ||
            add_type_constant(module, "TEST_ONLY_ProcessReceiptProjection",
                              &V2ProcessReceiptType) < 0 ||
            add_type_constant(module, "TEST_ONLY_ExitReceiptProjection",
                              &V2ExitReceiptType) < 0 ||
            add_type_constant(module, "TEST_ONLY_NetworkReceiptProjection",
                              &V2NetworkReceiptType) < 0
#else
            add_type_constant(module, "BrokerV2AuthorityConsumer",
                              &V2AuthorityConsumerType) < 0 ||
            add_type_constant(module, "SupervisorAuthorities",
                              &V2AuthorityBundleType) < 0 ||
            add_type_constant(module, "GuestDriverAuthorities",
                              &V2GuestAuthorityBundleType) < 0 ||
            add_type_constant(module, "RuntimeImageAuthority",
                              &V2RuntimeAuthorityType) < 0 ||
            add_type_constant(module, "WorkspaceAuthority",
                              &V2WorkspaceAuthorityType) < 0 ||
            add_type_constant(module, "BackendContextAuthority",
                              &V2BackendAuthorityType) < 0 ||
            add_type_constant(module, "ProviderAuthority",
                              &V2ProviderAuthorityType) < 0 ||
            add_type_constant(module, "GuestAdmissionAuthority",
                              &V2GuestAdmissionAuthorityType) < 0 ||
            add_type_constant(module, "ExtinctionAuthority",
                              &V2ExtinctionAuthorityType) < 0 ||
            add_type_constant(module, "ArtifactAuthority",
                              &V2ArtifactAuthorityType) < 0 ||
            add_type_constant(module, "ExportAuthority",
                              &V2ExportAuthorityType) < 0 ||
            add_type_constant(module, "JournalAuthority",
                              &V2JournalAuthorityType) < 0 ||
            add_type_constant(module, "RecoveryAuthority",
                              &V2RecoveryAuthorityType) < 0 ||
            add_type_constant(module, "BackendExecutionAuthority",
                              &V2BackendExecutionAuthorityType) < 0 ||
            add_type_constant(module, "SupervisorAuthority",
                              &V2SupervisorAuthorityType) < 0 ||
            add_type_constant(module, "ProcessReceiptProjection",
                              &V2ProcessReceiptType) < 0 ||
            add_type_constant(module, "ExitReceiptProjection",
                              &V2ExitReceiptType) < 0 ||
            add_type_constant(module, "NetworkReceiptProjection",
                              &V2NetworkReceiptType) < 0
#endif
       ) {
        Py_DECREF(module);
        return NULL;
    }
    if (add_type_constant(module, "JSDependencyMaterializerAuthority",
                          &JSDependencyMaterializerAuthorityType) < 0 ||
            add_type_constant(module, "JSDependencyMaterializerSessionLease",
                              &JSDependencyMaterializerSessionLeaseType) < 0 ||
            add_type_constant(module, "JSDependencyMaterializerExecutionLease",
                              &JSDependencyMaterializerExecutionLeaseType) < 0 ||
            add_type_constant(module,
                              "JSDependencyMaterializerTerminalReplayLease",
                              &JSDependencyMaterializerTerminalReplayLeaseType) < 0 ||
            add_type_constant(module, "ManagedEVMToolchainInitialAuthority",
                              &ManagedEVMToolchainInitialAuthorityType) < 0 ||
            add_type_constant(module, "ManagedEVMToolchainProvisionLease",
                              &ManagedEVMToolchainProvisionLeaseType) < 0 ||
            add_type_constant(module, "ManagedEVMToolchainProvisionTerminal",
                              &ManagedEVMToolchainProvisionTerminalType) < 0 ||
            add_type_constant(module, "EVMAnalysisProjectionAuthority",
                              &EVMAnalysisProjectionAuthorityType) < 0 ||
            add_type_constant(module, "DarwinToolCustodyAuthority",
                              &DarwinToolCustodyAuthorityType) < 0 ||
            add_type_constant(module, "DarwinToolExecutionLease",
                              &DarwinToolExecutionLeaseType) < 0 ||
            add_type_constant(module, "DarwinToolExecutionTerminal",
                              &DarwinToolExecutionTerminalType) < 0 ||
            add_type_constant(module, "AppleFuzzServiceSessionAuthority",
                              &AppleFuzzServiceSessionAuthorityType) < 0 ||
            add_type_constant(module, "AppleFuzzAdmissionContinuationLease",
                              &AppleFuzzAdmissionContinuationLeaseType) < 0 ||
            add_type_constant(module, "AppleFuzzLifecycleTerminal",
                              &AppleFuzzLifecycleTerminalType) < 0 ||
            add_type_constant(module, "BackendInstallGenerationAuthority",
                              &BackendInstallGenerationAuthorityType) < 0) {
        Py_DECREF(module);
        return NULL;
    }
    if (add_integer_constant(module, "PROTOCOL_VERSION",
                             PLAMEN_PROTOCOL_VERSION) < 0 ||
        add_integer_constant(module, "SESSION_HEADER_SIZE",
                             sizeof(PlamenNativeSessionV1)) < 0 ||
        add_integer_constant(module, "FRAME_HEADER_SIZE",
                             sizeof(PlamenNativeFrameV1)) < 0 ||
        add_integer_constant(module, "MAX_FRAME_PAYLOAD_BYTES",
                             PLAMEN_PROTOCOL_MAX_PAYLOAD) < 0) {
        Py_DECREF(module);
        return NULL;
    }
    if (add_integer_constant(module, "BROKER_V2_PROTOCOL_VERSION",
                             PLAMEN_BROKER_V2_VERSION) < 0 ||
        add_integer_constant(module, "BROKER_V2_FRAME_HEADER_SIZE",
                             PLAMEN_BROKER_V2_HEADER_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_AUTH_OFFSET",
                             PLAMEN_BROKER_V2_AUTH_OFFSET) < 0 ||
        add_integer_constant(module, "BROKER_V2_MAX_FRAME_PAYLOAD_BYTES",
                             PLAMEN_BROKER_V2_MAX_PAYLOAD) < 0 ||
        add_integer_constant(module, "BROKER_V2_MAX_SCM_RIGHTS_FDS",
                             PLAMEN_BROKER_V2_MAX_FDS) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_ABI_VERSION",
                             PLAMEN_BROKER_V2_SERVICE_ABI_VERSION) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_HEADER_SIZE",
                             PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_MAX_PAYLOAD_BYTES",
                             PLAMEN_BROKER_V2_SERVICE_MAX_PAYLOAD) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_MAX_FDS",
                             PLAMEN_BROKER_V2_SERVICE_MAX_FDS) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_READINESS_SIZE",
                             PLAMEN_BROKER_V2_SERVICE_READINESS_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_READY_SIZE",
                             PLAMEN_BROKER_V2_SERVICE_READY_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_REGISTRATION_SIZE",
                             PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_REGISTRATION_ACK_SIZE",
                             PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACK_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE",
                             PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE",
                             PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_SESSION_OPEN_SIZE",
                             PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_SESSION_ACK_SIZE",
                             PLAMEN_BROKER_V2_SERVICE_SESSION_ACK_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_SERVICE_ERROR_SIZE",
                             PLAMEN_BROKER_V2_SERVICE_ERROR_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_REQUEST_PROJECTION_MAX_BYTES",
                             PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX) < 0 ||
        add_integer_constant(module, "BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT",
                             PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT) < 0 ||
        add_integer_constant(module, "BROKER_V2_GUEST_AUTHORITY_MEMBER_COUNT",
                             PLAMEN_BROKER_V2_GUEST_AUTHORITY_MEMBER_COUNT) < 0 ||
        add_integer_constant(module, "BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE",
                             PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_GUEST_AUTHORITY_BUNDLE_SIZE",
                             PLAMEN_BROKER_V2_GUEST_AUTHORITY_BUNDLE_SIZE) < 0 ||
        add_integer_constant(module, "BROKER_V2_INITIAL_OUTER_SUPERVISOR",
                             PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR) < 0 ||
        add_integer_constant(module, "BROKER_V2_INITIAL_GUEST_DRIVER",
                             PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER) < 0 ||
        add_integer_constant(module, "BROKER_V2_PROCESS_BACKEND_EXECUTION",
                             PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION) < 0 ||
        PyModule_AddStringConstant(module, "BROKER_V2_ABI_SCHEMA",
                                  "plamen.native-broker.v2") < 0 ||
        PyModule_AddStringConstant(
            module, "APPLE_FUZZ_SERVICE_ABI_SCHEMA",
            "plamen.apple-fuzz-service-admission.v1") < 0 ||
        PyModule_AddStringConstant(
            module, "BROKER_V2_REQUEST_PROJECTION_SCHEMA",
            PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA) < 0 ||
        PyModule_AddStringConstant(
            module, "BROKER_V2_AUDIT_REQUEST_SCHEMA",
            PLAMEN_BROKER_V2_AUDIT_REQUEST_SCHEMA) < 0 ||
        PyModule_AddStringConstant(
            module, "BROKER_V2_OPERATION_DISPATCH",
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
            "TEST_ONLY_DISTINCT_OPERATION_DISPATCH_HARD_STOP"
#else
            "AUTHENTICATED_CANONICAL_BYTES_RPC"
#endif
            ) < 0) {
        Py_DECREF(module);
        return NULL;
    }
#ifndef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    if (v2_publish_initial_authority(
            module, &initial_authority_available) < 0 ||
            PyModule_AddObject(
                module, "BROKER_V2_INITIAL_AUTHORITY_AVAILABLE",
                Py_NewRef(initial_authority_available ? Py_True : Py_False)) < 0 ||
            PyModule_AddStringConstant(
                module, "BROKER_V2_PRODUCTION_ACQUISITION",
                initial_authority_available
                    ? "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
                    : "HARD_STOP_NO_AUTHENTICATED_NATIVE_SERVICE_SESSION") < 0) {
        Py_DECREF(module);
        return NULL;
    }
#else
    if (PyModule_AddObject(
            module, "BROKER_V2_INITIAL_AUTHORITY_AVAILABLE",
            Py_NewRef(Py_False)) < 0 ||
            PyModule_AddStringConstant(
                module, "BROKER_V2_PRODUCTION_ACQUISITION",
                "TEST_ONLY_DISTINCT_NO_PRODUCTION_AUTHORITY") < 0) {
        Py_DECREF(module);
        return NULL;
    }
#endif
    if (PyModule_AddStringConstant(
            module, "PRODUCTION_ACQUISITION",
            "HARD_STOP_PENDING_AUTHENTICATED_NATIVE_DISPATCHER") < 0) {
        Py_DECREF(module);
        return NULL;
    }
#ifdef PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY
    if (PyModule_AddObject(module, "TEST_ONLY_BUILD", Py_NewRef(Py_True)) < 0) {
        Py_DECREF(module);
        return NULL;
    }
#else
    if (PyModule_AddObject(module, "TEST_ONLY_BUILD", Py_NewRef(Py_False)) < 0) {
        Py_DECREF(module);
        return NULL;
    }
#endif
    return module;
}
