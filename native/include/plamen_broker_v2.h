#ifndef PLAMEN_BROKER_V2_H
#define PLAMEN_BROKER_V2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_VERSION 2U
#define PLAMEN_BROKER_V2_HEADER_SIZE 196U
#define PLAMEN_BROKER_V2_AUTH_OFFSET 164U
#define PLAMEN_BROKER_V2_MAX_PAYLOAD 2097152U
#define PLAMEN_BROKER_V2_MAX_FDS 16U
#define PLAMEN_BROKER_V2_SESSION_KEY_SIZE 32U
#define PLAMEN_BROKER_V2_SESSION_ID_SIZE 32U
#define PLAMEN_BROKER_V2_NONCE_SIZE 32U
#define PLAMEN_BROKER_V2_DIGEST_SIZE 32U
#define PLAMEN_BROKER_V2_MAX_ID 128U
#define PLAMEN_BROKER_V2_MAX_TEXT 4096U
#define PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE 516U
#define PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX 1048576U
#define PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA \
    "plamen.native_audit_request_projection.v1"
#define PLAMEN_BROKER_V2_AUDIT_REQUEST_SCHEMA \
    "plamen.posix_audit_supervisor.v1"
#define PLAMEN_BROKER_V2_EXACT_PROJECTION_SEMANTICS_VERSION 1U
#define PLAMEN_BROKER_V2_PROJECTION_BUILDER_ABI_VERSION 1U
#define PLAMEN_BROKER_V2_ROLE5_SCHEMA_RECEIPT_BOUND 1U
#define PLAMEN_BROKER_V2_RUNTIME_MANIFEST_HEADER_SIZE 256U
#define PLAMEN_BROKER_V2_RUNTIME_BINDING_SIZE 2048U
#define PLAMEN_BROKER_V2_RUNTIME_BINDING_DIGEST_COUNT 14U
#define PLAMEN_BROKER_V2_RUNTIME_MANIFEST_MAX_SIZE 536870912U
#define PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT 14U
#define PLAMEN_BROKER_V2_PROJECTION_DISCOVERY_ABI_VERSION 1U
#define PLAMEN_BROKER_V2_PROJECTION_PATH_MAX 4096U

/* Native launcher/extension <-> durable service bootstrap envelope. */
#define PLAMEN_BROKER_V2_SERVICE_ABI_VERSION 2U
#define PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE 124U
#define PLAMEN_BROKER_V2_SERVICE_MAX_PAYLOAD 4096U
#define PLAMEN_BROKER_V2_SERVICE_MAX_FDS 15U
#define PLAMEN_BROKER_V2_SERVICE_READINESS_SIZE 96U
#define PLAMEN_BROKER_V2_SERVICE_READY_SIZE 204U
#define PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE 1488U
#define PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACK_SIZE 210U
#define PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE 96U
#define PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE 954U
#define PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE 410U
#define PLAMEN_BROKER_V2_SERVICE_SESSION_ACK_SIZE 164U
#define PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP_SIZE 196U
#define PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE 368U
#define PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE 282U
#define PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACK_SIZE 164U
#define PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP_SIZE 236U
#define PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE_SIZE 1094U
#define PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN_SIZE 550U
#define PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACK_SIZE 260U
#define PLAMEN_BROKER_V2_SERVICE_ERROR_SIZE 40U
#define PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT 10U
#define PLAMEN_BROKER_V2_GUEST_AUTHORITY_MEMBER_COUNT 1U
#define PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE 392U
#define PLAMEN_BROKER_V2_GUEST_AUTHORITY_BUNDLE_SIZE 104U
#define PLAMEN_BROKER_V2_BACKEND_PROCESS_IDENTITY_SIZE 212U
#define PLAMEN_BROKER_V2_OUTPUT_CHUNK_MAX 262144U
#define PLAMEN_BROKER_V2_OUTPUT_STREAM_MAX 16777216U
#define PLAMEN_BROKER_V2_OUTPUT_READ_SIZE 79U
#define PLAMEN_BROKER_V2_OUTPUT_CHUNK_PREFIX_SIZE 188U
#define PLAMEN_BROKER_V2_OUTPUT_CHUNK_PAYLOAD_MAX \
    (PLAMEN_BROKER_V2_OUTPUT_CHUNK_PREFIX_SIZE + \
        PLAMEN_BROKER_V2_OUTPUT_CHUNK_MAX)
#define PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE 142U
#define PLAMEN_BROKER_V2_OPERATION_RESPONSE_PREFIX_SIZE 176U
#define PLAMEN_BROKER_V2_OPERATION_ERROR_SIZE 108U
#define PLAMEN_BROKER_V2_WORKER_SESSION_OPEN_SIZE 177U
#define PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED_SIZE 140U
#define PLAMEN_BROKER_V2_ROLE2_WORKER_MAX_ACTIVE 64U
#define PLAMEN_BROKER_V2_WORKER_SESSION_USE_TIMEOUT_MS 5000U
#define PLAMEN_BROKER_V2_GUEST_BOOTSTRAP_MAX_SIZE 1016U
#define PLAMEN_BROKER_V2_GUEST_BOOTSTRAP_PATH \
    "/workspace/control/native-bootstrap-v2.bin"
#define PLAMEN_BROKER_V2_GUEST_RUNTIME_DIRECTORY "/run/plamen"
#define PLAMEN_BROKER_V2_GUEST_RUNTIME_DIRECTORY_MODE 0700U
#define PLAMEN_BROKER_V2_GUEST_BOOTSTRAP_FILE_MODE 0400U
#define PLAMEN_BROKER_V2_EXTERNAL_PROFILE_SIZE 2048U
#define PLAMEN_BROKER_V2_EXTERNAL_PROFILE_HASHED_SIZE 2016U
#define PLAMEN_BROKER_V2_OPERATION_CANONICAL_MAX \
    (PLAMEN_BROKER_V2_MAX_PAYLOAD - \
        PLAMEN_BROKER_V2_OPERATION_RESPONSE_PREFIX_SIZE)
#define PLAMEN_BROKER_V2_RPC_REPLAY_MAX_ENTRIES 4096U
#define PLAMEN_BROKER_V2_RPC_REPLAY_METADATA_MAX 1048576U
#define PLAMEN_BROKER_V2_RPC_QUICK_DEADLINE_SECONDS 300U
#define PLAMEN_BROKER_V2_RPC_MUTATION_DEADLINE_SECONDS 1800U
#define PLAMEN_BROKER_V2_RPC_WAIT_DEADLINE_SECONDS 259200U
#define PLAMEN_BROKER_V2_RPC_CLIENT_GRACE_SECONDS 300U
#define PLAMEN_BROKER_V2_OPERATION_KEY_DOMAIN \
    "PLAMEN-BROKER-V2-OPERATION-KEY\0"
#define PLAMEN_BROKER_V2_RPC_OPERATION_KEY_DOMAIN \
    "PLAMEN-BROKER-V2-RPC-OPERATION-KEY\0"
#define PLAMEN_BROKER_V2_WORKER_SESSION_KEY_DOMAIN \
    "PLAMEN-BROKER-V2-WORKER-SESSION-KEY\0"
#define PLAMEN_BROKER_V2_WORKER_SESSION_BINDING_DOMAIN \
    "PLAMEN-BROKER-V2-WORKER-SESSION-BINDING\0"
#define PLAMEN_BROKER_V2_GUEST_BOOTSTRAP_DIGEST_DOMAIN \
    "PLAMEN-BROKER-V2-GUEST-BOOTSTRAP\0"
#define PLAMEN_BROKER_V2_DARWIN_SERVICE_NAME "com.plamen.audit.broker.v2"
#define PLAMEN_BROKER_V2_LINUX_SERVICE_NAME "plamen-audit-broker-v2"
#define PLAMEN_BROKER_V2_LINUX_GUEST_SOCKET "/run/plamen/broker-v2.sock"
#define PLAMEN_BROKER_V2_LINUX_USER_SOCKET_FORMAT \
    "/run/user/%llu/plamen/broker-v2.sock"
#define PLAMEN_BROKER_V2_LINUX_GUEST_LAUNCHER \
    "/usr/local/libexec/plamen-guest"
#define PLAMEN_BROKER_V2_LINUX_GUEST_PYTHON "/usr/bin/python3"
#define PLAMEN_BROKER_V2_LINUX_GUEST_DRIVER \
    "/opt/plamen/scripts/plamen_driver.py"
#define PLAMEN_BROKER_V2_LINUX_GUEST_EXTENSION \
    "/usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so"
#define PLAMEN_BROKER_V2_LINUX_GUEST_INSTALL_RECEIPT \
    "/usr/local/share/plamen/native-install-receipt-v2.bin"
#define PLAMEN_BROKER_V2_LINUX_LAUNCHER_ARGC 8U
#define PLAMEN_BROKER_V2_LINUX_PYTHON_ARGC 10U
#define PLAMEN_BROKER_V2_LINUX_CONFIG_PATH "/workspace/control/config.json"
#define PLAMEN_BROKER_V2_LINUX_STARTUP_INTENT_FLAG "--startup-intent"
#define PLAMEN_BROKER_V2_LINUX_START_NEW_RUN "START_NEW_RUN"
#define PLAMEN_BROKER_V2_LINUX_RESUME_EXISTING "RESUME_EXISTING"
#define PLAMEN_BROKER_V2_LINUX_UNATTENDED_FLAG "--unattended"
#define PLAMEN_BROKER_V2_LINUX_NO_SLEEP_FLAG "--no-sleep"
#define PLAMEN_BROKER_V2_LINUX_STARTUP_RECEIPT_FLAG \
    "--startup-decision-receipt"
#define PLAMEN_BROKER_V2_LINUX_STARTUP_RECEIPT_PATH \
    "/workspace/control/startup-decision.json"
#define PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE "envelope"
#define PLAMEN_BROKER_V2_XPC_KEY_CONTROL_SOCKET "control_socket"
#define PLAMEN_BROKER_V2_XPC_KEY_KEY_PIPE_READ "key_pipe_read"
#define PLAMEN_BROKER_V2_XPC_KEY_REQUEST_PROJECTION "request_projection"
#define PLAMEN_BROKER_V2_XPC_KEY_AUTHORITY_PREFIX "authority_"
#define PLAMEN_BROKER_V2_LINUX_SERVICE_PACKET_MAX 4220U
#define PLAMEN_BROKER_V2_SESSION_CHALLENGE_TIMEOUT_MS 5000U

/* Append-only service-issued sessions for materialization/tool custody. */
#define PLAMEN_BROKER_V2_SPECIALIZED_ABI_VERSION 1U
#define PLAMEN_BROKER_V2_LINUX_SESSION_ABI_VERSION 1U
#define PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_PREFIX_SIZE 144U
#define PLAMEN_BROKER_V2_SPECIALIZED_RESPONSE_PREFIX_SIZE 144U
#define PLAMEN_BROKER_V2_SPECIALIZED_PAYLOAD_MAX 1048576U
#define PLAMEN_BROKER_V2_SPECIALIZED_FD_METADATA_SIZE 37U
#define PLAMEN_BROKER_V2_SPECIALIZED_CAPABILITY_SIZE 32U
#define PLAMEN_BROKER_V2_SPECIALIZED_FLAG_RECOVER 0x0001U
#define PLAMEN_BROKER_V2_SPECIALIZED_SESSION_BINDING_DOMAIN \
    "PLAMEN-BROKER-V2-SPECIALIZED-SESSION-BINDING-V1\0"

/*
 * Native guest-launcher argv is exactly argv[0]=LINUX_GUEST_LAUNCHER,
 * argv[1]=LINUX_CONFIG_PATH, argv[2]=LINUX_STARTUP_INTENT_FLAG,
 * argv[3]=START_NEW_RUN or RESUME_EXISTING, argv[4]=UNATTENDED_FLAG,
 * argv[5]=NO_SLEEP_FLAG, argv[6]=STARTUP_RECEIPT_FLAG,
 * argv[7]=STARTUP_RECEIPT_PATH, argv[8]=NULL.  Its environment is closed.
 * The launcher validates the two retained files and binds their content and
 * identities into the request projection/registration before it spawns the
 * fixed Python/interpreter/extension closure.
 * The child argv is exactly Python, "-B", driver, followed by launcher
 * argv[1]..argv[7], then NULL (argc=10); envp is exactly {NULL}.
 */

enum plamen_broker_v2_frame_type {
    PLAMEN_BROKER_V2_HELLO = 0x0001,
    PLAMEN_BROKER_V2_AUTH_CONSUME = 0x0002,
    PLAMEN_BROKER_V2_AUTH_ACCEPTED = 0x0003,
    PLAMEN_BROKER_V2_REQUEST_PROJECTION = 0x0004,
    PLAMEN_BROKER_V2_REQUEST_PROJECTED = 0x0005,
    PLAMEN_BROKER_V2_CLI_PREPARE = 0x0010,
    PLAMEN_BROKER_V2_CLI_COMMITTED = 0x0011,
    PLAMEN_BROKER_V2_START_PREPARE = 0x0020,
    PLAMEN_BROKER_V2_STARTED = 0x0021,
    PLAMEN_BROKER_V2_START_RECOVER = 0x0022,
    PLAMEN_BROKER_V2_WAIT_PREPARE = 0x0030,
    PLAMEN_BROKER_V2_EXITED = 0x0031,
    PLAMEN_BROKER_V2_WAIT_RECOVER = 0x0032,
    PLAMEN_BROKER_V2_REVOKE_PREPARE = 0x0040,
    PLAMEN_BROKER_V2_REVOKED = 0x0041,
    PLAMEN_BROKER_V2_BACKEND_PREPARE = 0x0050,
    PLAMEN_BROKER_V2_BACKEND_PREPARED = 0x0051,
    PLAMEN_BROKER_V2_OUTPUT_READ = 0x0060,
    PLAMEN_BROKER_V2_OUTPUT_CHUNK = 0x0061,
    PLAMEN_BROKER_V2_OPERATION_CLOSE = 0x0070,
    PLAMEN_BROKER_V2_OPERATION_FINISHED = 0x0071,
    PLAMEN_BROKER_V2_OPERATION_REQUEST = 0x0080,
    PLAMEN_BROKER_V2_OPERATION_RESPONSE = 0x0081,
    PLAMEN_BROKER_V2_OPERATION_ERROR = 0x0082,
    PLAMEN_BROKER_V2_WORKER_SESSION_OPEN = 0x0090,
    PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED = 0x0091,
    PLAMEN_BROKER_V2_ERROR = 0x00ff
};

/*
 * REQUEST_PROJECTION has an empty payload and is accepted only before the
 * one-shot AUTH_CONSUME.  REQUEST_PROJECTED carries the exact canonical UTF-8
 * JSON bytes (no wrapper) and may replay byte-identically any number of times
 * before consume; it is forbidden after consume.  Its SHA-256 and byte length
 * must equal the durable registration/session-challenge binding.
 */

enum plamen_broker_v2_role {
    PLAMEN_BROKER_V2_ROLE_EXTENSION = 1,
    PLAMEN_BROKER_V2_ROLE_BROKER = 2
};

enum plamen_broker_v2_fd_access {
    PLAMEN_BROKER_V2_FD_READ = 1,
    PLAMEN_BROKER_V2_FD_WRITE = 2,
    PLAMEN_BROKER_V2_FD_READ_WRITE = 3
};

/* Purpose values are protocol ABI.  Values may be added, never renumbered. */
enum plamen_broker_v2_fd_purpose {
    PLAMEN_BROKER_V2_FD_APPLE_CLI_EXECUTABLE = 0x0001,
    PLAMEN_BROKER_V2_FD_JOURNAL_DIRECTORY = 0x0002,
    PLAMEN_BROKER_V2_FD_WORKING_DIRECTORY = 0x0003,
    PLAMEN_BROKER_V2_FD_BACKEND_EXECUTABLE = 0x0010,
    PLAMEN_BROKER_V2_FD_STDIN_PROMPT = 0x0011,
    PLAMEN_BROKER_V2_FD_SEALED_POLICY = 0x0012,
    PLAMEN_BROKER_V2_FD_PUBLIC_CA = 0x0013,
    PLAMEN_BROKER_V2_FD_CREDENTIAL = 0x0014,
    PLAMEN_BROKER_V2_FD_PROFILE = 0x0015,
    PLAMEN_BROKER_V2_FD_SETTINGS = 0x0016,
    PLAMEN_BROKER_V2_FD_MCP_CONFIG = 0x0017,
    PLAMEN_BROKER_V2_FD_PROXY_AUTH = 0x0018,
    PLAMEN_BROKER_V2_FD_CHILD_PASS = 0x0019,
    PLAMEN_BROKER_V2_FD_SERVICE_CONTROL_SOCKET = 0x1001,
    PLAMEN_BROKER_V2_FD_SERVICE_KEY_PIPE_READ = 0x1002,
    PLAMEN_BROKER_V2_FD_SERVICE_REQUEST_PROJECTION = 0x1003,
    PLAMEN_BROKER_V2_FD_AUTHORITY_CONFIG = 0x2001,
    PLAMEN_BROKER_V2_FD_AUTHORITY_TARGET = 0x2002,
    PLAMEN_BROKER_V2_FD_AUTHORITY_DOCS = 0x2003,
    PLAMEN_BROKER_V2_FD_AUTHORITY_SCOPE = 0x2004,
    PLAMEN_BROKER_V2_FD_AUTHORITY_EXPORT = 0x2005,
    PLAMEN_BROKER_V2_FD_AUTHORITY_ROLE5_SCHEMA = 0x2006,
    PLAMEN_BROKER_V2_FD_AUTHORITY_RUNTIME_MANIFEST = 0x2007,
    PLAMEN_BROKER_V2_FD_AUTHORITY_PROVIDER_EXECUTABLE = 0x2008,
    PLAMEN_BROKER_V2_FD_AUTHORITY_BACKEND_EXECUTABLE = 0x2009,
    PLAMEN_BROKER_V2_FD_AUTHORITY_BACKEND_PROFILE = 0x200a,
    PLAMEN_BROKER_V2_FD_AUTHORITY_CREDENTIAL = 0x200b,
    PLAMEN_BROKER_V2_FD_AUTHORITY_EGRESS_POLICY = 0x200c,
    PLAMEN_BROKER_V2_FD_AUTHORITY_EGRESS_ADMISSION = 0x200d,
    PLAMEN_BROKER_V2_FD_AUTHORITY_RESUME_CHECKPOINT = 0x200e,
    PLAMEN_BROKER_V2_FD_GUEST_BOOTSTRAP_RECORD = 0x3001,
    PLAMEN_BROKER_V2_FD_JS_SOURCE = 0x4001,
    PLAMEN_BROKER_V2_FD_JS_SCRATCH = 0x4002,
    PLAMEN_BROKER_V2_FD_JS_STATE = 0x4003,
    PLAMEN_BROKER_V2_FD_JS_ARCHIVE_ROOT = 0x4004,
    PLAMEN_BROKER_V2_FD_PROJECTION_PROJECT = 0x4010,
    PLAMEN_BROKER_V2_FD_PROJECTION_SCRATCH = 0x4011,
    PLAMEN_BROKER_V2_FD_PROJECTION_STATE = 0x4012,
    PLAMEN_BROKER_V2_FD_PROJECTION_RECEIPT = 0x4013,
    PLAMEN_BROKER_V2_FD_PROJECTION_LINEAGE = 0x4014,
    PLAMEN_BROKER_V2_FD_PROJECTION_MATERIALIZATION_TERMINAL = 0x4015,
    /* Immutable JS materializer output consumed by projection commit. */
    PLAMEN_BROKER_V2_FD_PROJECTION_MODULES = 0x4016,
    PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SOURCE = 0x4020,
    PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_SCRATCH = 0x4021,
    PLAMEN_BROKER_V2_FD_SNAPSHOT_TOOL_STATE = 0x4022,
    PLAMEN_BROKER_V2_FD_SNAPSHOT_AUDITED_PROJECT = 0x4023,
    PLAMEN_BROKER_V2_FD_MANAGED_EVM_POLICY = 0x4030,
    PLAMEN_BROKER_V2_FD_MANAGED_EVM_PROJECT = 0x4031,
    PLAMEN_BROKER_V2_FD_MANAGED_EVM_CACHE = 0x4032,
    PLAMEN_BROKER_V2_FD_MANAGED_EVM_GENERATIONS = 0x4033,
    PLAMEN_BROKER_V2_FD_MANAGED_EVM_ACQUISITION_RECEIPT = 0x4034
};

enum plamen_broker_v2_service_message_type {
    PLAMEN_BROKER_V2_SERVICE_READINESS = 0x1000,
    PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL = 0x1001,
    PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY = 0x1002,
    PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACCEPTED = 0x1003,
    PLAMEN_BROKER_V2_SERVICE_READY = 0x1004,
    PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP = 0x1008,
    PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE = 0x1009,
    PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN = 0x1010,
    PLAMEN_BROKER_V2_SERVICE_SESSION_ACCEPTED = 0x1011,
    PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP = 0x1012,
    PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE = 0x1013,
    PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN = 0x1014,
    PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACCEPTED = 0x1015,
    PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP = 0x1020,
    PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE = 0x1021,
    PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN = 0x1022,
    PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACCEPTED = 0x1023,
    PLAMEN_BROKER_V2_SERVICE_ERROR = 0x10ff
};

enum plamen_broker_v2_service_role {
    PLAMEN_BROKER_V2_SERVICE_ROLE_LAUNCHER = 1,
    PLAMEN_BROKER_V2_SERVICE_ROLE_EXTENSION = 2,
    PLAMEN_BROKER_V2_SERVICE_ROLE_BROKER = 3
};

/*
 * Exactly one role-bound INITIAL_AUTHORITY is pre-issued per registration for
 * roles OUTER_SUPERVISOR or GUEST_DRIVER only.
 * The only Python consume surface is
 * INITIAL_AUTHORITY.consume_once(request_fingerprint, attempt_id); Python does
 * not pass or select the role.  Native code compares the durable registered
 * role and returns only that role's static capability bundle.  A wrong-role
 * operation burns the one-shot consumer and fails before an external effect.
 * BACKEND_EXECUTION is never an INITIAL_AUTHORITY: it is the identity of an
 * exact native-spawned backend/helper admitted by the role-2 static authority.
 */
enum plamen_broker_v2_initial_authority_role {
    PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR = 1,
    PLAMEN_BROKER_V2_INITIAL_GUEST_DRIVER = 2
};

enum plamen_broker_v2_process_role {
    PLAMEN_BROKER_V2_PROCESS_BACKEND_EXECUTION = 3
};

enum plamen_broker_v2_outer_authority_member {
    PLAMEN_BROKER_V2_AUTHORITY_RUNTIME_IMAGE = 1,
    PLAMEN_BROKER_V2_AUTHORITY_WORKSPACE = 2,
    PLAMEN_BROKER_V2_AUTHORITY_BACKEND_CONTEXT = 3,
    PLAMEN_BROKER_V2_AUTHORITY_PROVIDER_LIFECYCLE = 4,
    PLAMEN_BROKER_V2_AUTHORITY_GUEST_ADMISSION = 5,
    PLAMEN_BROKER_V2_AUTHORITY_EXTINCTION = 6,
    PLAMEN_BROKER_V2_AUTHORITY_ARTIFACT = 7,
    PLAMEN_BROKER_V2_AUTHORITY_EXPORT = 8,
    PLAMEN_BROKER_V2_AUTHORITY_DURABLE_JOURNAL = 9,
    PLAMEN_BROKER_V2_AUTHORITY_RECOVERY = 10
};

enum plamen_broker_v2_guest_authority_member {
    PLAMEN_BROKER_V2_AUTHORITY_BACKEND_EXECUTION = 1
};

/* MutationOperation order in posix_audit_supervisor.py is protocol ABI. */
enum plamen_broker_v2_outer_operation {
    PLAMEN_BROKER_V2_OUTER_PREPARE_LAYOUT = 1,
    PLAMEN_BROKER_V2_OUTER_WRITE_CONFIG = 2,
    PLAMEN_BROKER_V2_OUTER_CREATE_GUEST = 3,
    PLAMEN_BROKER_V2_OUTER_ADMIT_GUEST = 4,
    PLAMEN_BROKER_V2_OUTER_START_DRIVER = 5,
    PLAMEN_BROKER_V2_OUTER_WAIT_DRIVER = 6,
    PLAMEN_BROKER_V2_OUTER_EXTINGUISH = 7,
    PLAMEN_BROKER_V2_OUTER_CENSUS_ARTIFACTS = 8,
    PLAMEN_BROKER_V2_OUTER_EXPORT_ARTIFACTS = 9,
    PLAMEN_BROKER_V2_OUTER_DELETE_GUEST = 10
};

enum plamen_broker_v2_backend_operation {
    PLAMEN_BROKER_V2_BACKEND_OPERATION_PREPARE = 0x0100,
    PLAMEN_BROKER_V2_BACKEND_OPERATION_START = 0x0101,
    PLAMEN_BROKER_V2_BACKEND_OPERATION_WAIT = 0x0102,
    PLAMEN_BROKER_V2_BACKEND_OPERATION_EXTINGUISH = 0x0103,
    PLAMEN_BROKER_V2_BACKEND_OPERATION_OUTPUT_STDOUT = 0x0104,
    PLAMEN_BROKER_V2_BACKEND_OPERATION_OUTPUT_STDERR = 0x0105,
    PLAMEN_BROKER_V2_BACKEND_OPERATION_CLOSE = 0x0106
};

enum plamen_broker_v2_output_stream {
    PLAMEN_BROKER_V2_OUTPUT_STDOUT = 1,
    PLAMEN_BROKER_V2_OUTPUT_STDERR = 2
};

/* Static Python-visible authority methods.  Values are append-only ABI. */
enum plamen_broker_v2_authority_method {
    PLAMEN_BROKER_V2_METHOD_RUNTIME_AUTHENTICATE = 0x1001,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_ADMIT_TARGET = 0x1101,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_REVALIDATE_TARGET = 0x1102,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_PREPARE_LAYOUT = 0x1103,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_RESUME_LAYOUT = 0x1104,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_WRITE_GUEST_CONFIG = 0x1105,
    PLAMEN_BROKER_V2_METHOD_WORKSPACE_RECENSUS_LAYOUT = 0x1106,
    PLAMEN_BROKER_V2_METHOD_BACKEND_AUTHENTICATE = 0x1201,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND = 0x1301,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_CREATE_STOPPED = 0x1302,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_INSPECT_STOPPED = 0x1303,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_RESUME_GUEST = 0x1304,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_START_DRIVER = 0x1305,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_WAIT_DRIVER = 0x1306,
    PLAMEN_BROKER_V2_METHOD_PROVIDER_DELETE_GUEST = 0x1307,
    PLAMEN_BROKER_V2_METHOD_GUEST_ADMIT_STOPPED = 0x1401,
    PLAMEN_BROKER_V2_METHOD_GUEST_RESUME_ADMISSION = 0x1402,
    PLAMEN_BROKER_V2_METHOD_EXTINCTION_EXTINGUISH = 0x1501,
    PLAMEN_BROKER_V2_METHOD_ARTIFACT_CENSUS = 0x1601,
    PLAMEN_BROKER_V2_METHOD_EXPORT_EXPORT = 0x1701,
    PLAMEN_BROKER_V2_METHOD_JOURNAL_OPEN = 0x1801,
    PLAMEN_BROKER_V2_METHOD_JOURNAL_ARM = 0x1802,
    PLAMEN_BROKER_V2_METHOD_JOURNAL_COMMIT = 0x1803,
    PLAMEN_BROKER_V2_METHOD_JOURNAL_RESOLVE = 0x1804,
    PLAMEN_BROKER_V2_METHOD_JOURNAL_FINISH = 0x1805,
    PLAMEN_BROKER_V2_METHOD_RECOVERY_RECOVER = 0x1901,
    PLAMEN_BROKER_V2_METHOD_BACKEND_PREPARE = 0x2001,
    PLAMEN_BROKER_V2_METHOD_BACKEND_START_OR_RECOVER = 0x2002,
    PLAMEN_BROKER_V2_METHOD_BACKEND_WAIT_OR_RECOVER = 0x2003,
    PLAMEN_BROKER_V2_METHOD_BACKEND_EXTINGUISH_OR_RECOVER = 0x2004,
    PLAMEN_BROKER_V2_METHOD_BACKEND_READ_OUTPUT_OR_RECOVER = 0x2005,
    PLAMEN_BROKER_V2_METHOD_BACKEND_CLOSE_OPERATION = 0x2006,
    PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE = 0x2101,
    PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_PREPARE = 0x2102,
    PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE = 0x2103,
    PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY = 0x2104,
    PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_RUNTIME_IDENTITY = 0x2105,
    PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_RUNTIME_IDENTITY = 0x2201,
    PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PREPARE = 0x2202,
    PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_EXECUTE = 0x2203,
    PLAMEN_BROKER_V2_METHOD_MANAGED_EVM_PROJECT = 0x2204,
    PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_COMMIT = 0x2301,
    PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_RECOVER = 0x2302,
    PLAMEN_BROKER_V2_METHOD_EVM_PROJECTION_PROJECT = 0x2303,
    PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_RUNTIME_IDENTITY = 0x2401,
    PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_ACQUIRE = 0x2402,
    PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_PREPARE = 0x2403,
    PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE = 0x2404,
    /* Dedicated Forge/Medusa Apple-Container lifecycle.  This is not the
     * snapshot worker protocol and never aliases Provider.start_driver. */
    PLAMEN_BROKER_V2_METHOD_FUZZ_CAMPAIGN_EXECUTE = 0x2405,
    /* Atomic service admission: ADMIT mints an opaque one-shot capability
     * and secure receipt; EXECUTE consumes that exact capability. */
    PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_ADMIT = 0x2406,
    PLAMEN_BROKER_V2_METHOD_FUZZ_SERVICE_EXECUTE = 0x2407
};

enum plamen_broker_v2_specialized_lane {
    PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER = 1,
    PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM = 2,
    PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION = 3,
    PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL = 4
};

enum plamen_broker_v2_specialized_disposition {
    PLAMEN_BROKER_V2_SPECIALIZED_ISSUED = 1,
    PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED = 2,
    PLAMEN_BROKER_V2_SPECIALIZED_REPLAYED = 3,
    PLAMEN_BROKER_V2_SPECIALIZED_RECOVERED = 4
};

enum plamen_broker_v2_operation_flag {
    PLAMEN_BROKER_V2_OPERATION_RECOVER = 0x0001
};

enum plamen_broker_v2_operation_disposition {
    PLAMEN_BROKER_V2_OPERATION_OBSERVED = 1,
    PLAMEN_BROKER_V2_OPERATION_COMMITTED = 2,
    PLAMEN_BROKER_V2_OPERATION_REPLAYED = 3,
    PLAMEN_BROKER_V2_OPERATION_RECOVERED = 4
};

enum plamen_broker_v2_operation_state {
    PLAMEN_BROKER_V2_OPERATION_STATE_UNCHANGED = 0,
    PLAMEN_BROKER_V2_OPERATION_STATE_PREPARED = 1,
    PLAMEN_BROKER_V2_OPERATION_STATE_EFFECTED = 2,
    PLAMEN_BROKER_V2_OPERATION_STATE_COMMITTED = 3,
    PLAMEN_BROKER_V2_OPERATION_STATE_REVOKED = 4,
    PLAMEN_BROKER_V2_OPERATION_STATE_FINISHED = 5
};

enum plamen_broker_v2_birth_kind {
    /* primary=seconds since Unix epoch, secondary=nanoseconds, boot digest zero. */
    PLAMEN_BROKER_V2_BIRTH_DARWIN_EPOCH = 1,
    /* primary=/proc start ticks, secondary=CLK_TCK, boot digest required. */
    PLAMEN_BROKER_V2_BIRTH_LINUX_BOOT_TICKS = 2
};

enum plamen_broker_v2_linux_service_scope {
    PLAMEN_BROKER_V2_LINUX_SCOPE_OUTER_USER = 1,
    PLAMEN_BROKER_V2_LINUX_SCOPE_GUEST_ROOT = 2
};

enum plamen_broker_v2_service_error_code {
    PLAMEN_BROKER_V2_SERVICE_ERR_INVALID_ENVELOPE = 1,
    PLAMEN_BROKER_V2_SERVICE_ERR_PEER_AUTH = 2,
    PLAMEN_BROKER_V2_SERVICE_ERR_CLOSURE = 3,
    PLAMEN_BROKER_V2_SERVICE_ERR_REGISTRATION_MISSING = 4,
    PLAMEN_BROKER_V2_SERVICE_ERR_REGISTRATION_USED = 5,
    PLAMEN_BROKER_V2_SERVICE_ERR_DESCRIPTORS = 6,
    PLAMEN_BROKER_V2_SERVICE_ERR_DURABILITY = 7,
    PLAMEN_BROKER_V2_SERVICE_ERR_KEY_TRANSFER = 8,
    PLAMEN_BROKER_V2_SERVICE_ERR_SESSION = 9,
    PLAMEN_BROKER_V2_SERVICE_ERR_UNSUPPORTED = 10,
    PLAMEN_BROKER_V2_SERVICE_ERR_INTERNAL = 11
};

enum plamen_broker_v2_service_error_flag {
    PLAMEN_BROKER_V2_SERVICE_REGISTRATION_CONSUMED = 0x0001,
    PLAMEN_BROKER_V2_SERVICE_SESSION_BURNED = 0x0002,
    PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED = 0x0004
};

enum plamen_broker_v2_status {
    PLAMEN_BROKER_V2_OK = 0,
    PLAMEN_BROKER_V2_INVALID = -1,
    PLAMEN_BROKER_V2_AUTH_FAILED = -2,
    PLAMEN_BROKER_V2_REPLAY = -3,
    PLAMEN_BROKER_V2_DIRECTION = -4,
    PLAMEN_BROKER_V2_FD_INVALID = -5,
    PLAMEN_BROKER_V2_NOMEM = -6,
    PLAMEN_BROKER_V2_SYSTEM = -7,
    PLAMEN_BROKER_V2_BURNED = -8,
    PLAMEN_BROKER_V2_CONFLICT = -9,
    PLAMEN_BROKER_V2_CORRUPT = -10,
    PLAMEN_BROKER_V2_UNSUPPORTED = -11
};

enum plamen_broker_v2_startup_intent {
    PLAMEN_BROKER_V2_STARTUP_START_NEW_RUN = 1,
    PLAMEN_BROKER_V2_STARTUP_RESUME_EXISTING = 2
};

enum plamen_broker_v2_runtime_binding_digest_index {
    PLAMEN_BROKER_V2_RUNTIME_OCI_INDEX = 0,
    PLAMEN_BROKER_V2_RUNTIME_OCI_MANIFEST = 1,
    PLAMEN_BROKER_V2_RUNTIME_OCI_CONFIG = 2,
    PLAMEN_BROKER_V2_RUNTIME_IMAGE_CLOSURE = 3,
    PLAMEN_BROKER_V2_RUNTIME_APPLE_CONFIG = 4,
    PLAMEN_BROKER_V2_RUNTIME_SECCOMP = 5,
    PLAMEN_BROKER_V2_RUNTIME_TOOLCHAIN = 6,
    PLAMEN_BROKER_V2_RUNTIME_OCI_LOCK = 7,
    PLAMEN_BROKER_V2_RUNTIME_MATERIALIZATION = 8,
    PLAMEN_BROKER_V2_RUNTIME_ROOTFS_ARCHIVE = 9,
    PLAMEN_BROKER_V2_RUNTIME_ROOTFS_DIFF_ID = 10,
    PLAMEN_BROKER_V2_RUNTIME_CLOSURE_CENSUS = 11,
    PLAMEN_BROKER_V2_RUNTIME_SBOM = 12,
    PLAMEN_BROKER_V2_RUNTIME_PROVENANCE = 13
};

enum plamen_broker_v2_projection_retained_fd_index {
    PLAMEN_BROKER_V2_RETAINED_CONFIG = 0,
    PLAMEN_BROKER_V2_RETAINED_TARGET = 1,
    PLAMEN_BROKER_V2_RETAINED_DOCS = 2,
    PLAMEN_BROKER_V2_RETAINED_SCOPE = 3,
    PLAMEN_BROKER_V2_RETAINED_EXPORT = 4,
    PLAMEN_BROKER_V2_RETAINED_ROLE5_SCHEMA = 5,
    PLAMEN_BROKER_V2_RETAINED_RUNTIME_MANIFEST = 6,
    PLAMEN_BROKER_V2_RETAINED_PROVIDER = 7,
    PLAMEN_BROKER_V2_RETAINED_BACKEND = 8,
    PLAMEN_BROKER_V2_RETAINED_BACKEND_PROFILE = 9,
    PLAMEN_BROKER_V2_RETAINED_CREDENTIAL = 10,
    PLAMEN_BROKER_V2_RETAINED_EGRESS_POLICY = 11,
    PLAMEN_BROKER_V2_RETAINED_EGRESS_ADMISSION = 12,
    PLAMEN_BROKER_V2_RETAINED_RESUME_CHECKPOINT = 13
};

struct plamen_broker_v2_writer {
    uint8_t *data;
    size_t capacity;
    size_t offset;
};

struct plamen_broker_v2_reader {
    const uint8_t *data;
    size_t size;
    size_t offset;
};

struct plamen_broker_v2_commitment {
    uint8_t request_fingerprint[32];
    char attempt_id[129];
    char run_identity[129];
    uint8_t config_sha256[32];
    uint8_t runtime_closure_sha256[32];
    uint8_t image_closure_sha256[32];
    uint8_t provider_provenance_sha256[32];
    uint8_t backend_admission_sha256[32];
    uint8_t credential_isolation_sha256[32];
    uint8_t egress_admission_sha256[32];
};

struct plamen_broker_v2_frame_view {
    uint16_t type;
    uint16_t fd_count;
    uint64_t sequence;
    uint8_t operation_nonce[32];
    const uint8_t *payload;
    uint32_t payload_size;
    uint8_t frame_sha256[32];
};

struct plamen_broker_v2_session {
    uint8_t key[32];
    uint8_t session_id[32];
    uint8_t previous_frame_sha256[32];
    uint64_t next_sequence;
    uint8_t role;
    uint8_t hello_seen;
    uint8_t projection_requested;
    uint8_t projection_seen;
    uint8_t auth_consumed;
    uint8_t authenticated;
    uint8_t burned;
};

struct plamen_broker_v2_fd_metadata {
    uint16_t purpose;
    uint16_t target;
    uint8_t access_mode;
    uint8_t identity[32];
};

/*
 * The prefix is followed by fd_count metadata rows and canonical compact JSON
 * (sorted keys). Requests may carry exactly one trailing LF under the existing
 * call convention; responses have none. capability_id is zero only for acquisition
 * and runtime-identity calls. Issued IDs are random service authority bound to
 * lane, authenticated peer PID/birth, interpreter, and installed closure.
 * PREPARE returns a one-shot lease; EXECUTE consumes it durably. Recovery and
 * projection are read-only durable lookups, never caller receipt authority.
 * JS canonical request bytes include the sorted exact HTTPS-origin allowlist;
 * terminal bytes include native verified-egress evidence for every origin.
 */
struct plamen_broker_v2_specialized_request {
    uint16_t lane;
    uint16_t method;
    uint16_t flags;
    uint8_t capability_id[32];
    uint8_t operation_nonce[32];
    uint8_t authority_binding_sha256[32];
    uint16_t fd_count;
    struct plamen_broker_v2_fd_metadata
        descriptors[PLAMEN_BROKER_V2_MAX_FDS];
    uint32_t payload_size;
    const uint8_t *payload;
};

struct plamen_broker_v2_specialized_response {
    uint16_t lane;
    uint16_t method;
    uint16_t disposition;
    uint16_t status;
    uint8_t capability_id[32];
    uint8_t operation_nonce[32];
    uint8_t request_sha256[32];
    uint8_t terminal_sha256[32];
    uint32_t payload_size;
    const uint8_t *payload;
};

struct plamen_broker_v2_service_envelope_view {
    uint16_t type;
    uint16_t fd_count;
    uint8_t transaction_nonce[32];
    uint8_t invocation_nonce[32];
    const uint8_t *payload;
    uint32_t payload_size;
    uint8_t envelope_sha256[32];
};

/*
 * The platform audit token/SO_PEERCRED is out-of-band authority.  These claimed
 * fields are accepted only after exact comparison with that native authority.
 * Darwin birth is proc_bsdinfo start time converted to epoch seconds/nanoseconds;
 * Linux birth is /proc/<pid>/stat starttime plus SHA-256 of the canonical boot ID.
 */
struct plamen_broker_v2_peer_identity {
    uint64_t pid;
    uint64_t uid;
    uint64_t gid;
    uint16_t birth_kind;
    uint64_t birth_primary;
    uint64_t birth_secondary;
    uint8_t boot_id_sha256[32];
};

struct plamen_broker_v2_service_registration {
    uint8_t installed_closure_sha256[32];
    uint8_t committed_audit_generation_sha256[32];
    uint8_t audit_request_fingerprint[32];
    uint8_t request_projection_sha256[32];
    uint32_t request_projection_size;
    uint8_t commitment_sha256[32];
    uint16_t commitment_size;
    uint8_t commitment[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    uint8_t python_entrypoint_sha256[32];
    uint8_t python_argv_sha256[32];
    uint8_t python_environment_sha256[32];
    struct plamen_broker_v2_peer_identity launcher;
    struct plamen_broker_v2_peer_identity suspended_child;
    uint8_t prior_audit_checkpoint_sha256[32];
    uint16_t initial_interpreter_slot;
    uint16_t initial_authority_role;
    uint16_t authority_presence_mask;
    struct plamen_broker_v2_fd_metadata
        authority_descriptors[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
};

/*
 * The request projection is canonical UTF-8 JSON, <=1 MiB, without a trailing
 * LF.  Its exact top-level keys are `projection_schema` and `audit_request`.
 * projection_schema is PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA.
 * audit_request has exactly these keys:
 * schema, request_type, request_id, attempt_id, run_id, pipeline, mode,
 * backend, language, source_config, source_config_sha256,
 * startup_decision_receipt_sha256, target_identity_sha256,
 * runtime_layout_sha256, image_manifest_digest, image_closure_sha256,
 * docs_sha256, scope_sha256, seccomp_profile_sha256,
 * credential_bundle_sha256, credential_isolation_sha256,
 * backend_context_sha256, backend_admission_sha256, egress_policy_sha256,
 * egress_admission_sha256, provider_provenance_sha256, export_allowlist,
 * required_artifacts, failure_required_artifacts,
 * export_destination_identity_sha256, export_max_total_bytes.
 * audit_request.schema is PLAMEN_BROKER_V2_AUDIT_REQUEST_SCHEMA.
 * source_config has exactly authenticated=true, canonical_utf8_b64,
 * retained_source_handle, sha256.  The handle is `opaque:` plus 64 lowercase
 * hex characters and is semantic only.  Digests are 64 lowercase hex; the
 * image digest is `sha256:` plus 64 lowercase hex.  The three roster arrays
 * are sorted and unique.  JSON keys are sorted; separators are comma/colon;
 * strings are UTF-8 NFC with no null/control character; duplicate keys, null,
 * float, and trailing LF are forbidden.  Base64 is canonical padded RFC4648;
 * its decoded config is <=256 KiB and itself canonical JSON.
 *
 * Darwin REGISTER carries these bytes only as XPC data under
 * PLAMEN_BROKER_V2_XPC_KEY_REQUEST_PROJECTION.  Linux REGISTER carries one
 * read-only sealed memfd in descriptor position zero.  That single typed
 * registration attachment is reflected in the service envelope fd_count;
 * no SESSION/READY message accepts it.  The service verifies the bound length
 * and SHA-256 before its durable registration write and retains exact bytes.
 */

/*
 * Pre-publication readiness is a no-FD, non-durable liveness/closure exchange.
 * It neither registers a child nor consumes authority.  The launcher compares
 * `service_peer` with the native audit token/SO_PEERCRED and checks all three
 * closure digests before it publishes or invokes the production entrypoint.
 *
 * READINESS bytes (96): installed closure, broker closure, install receipt.
 * READY bytes (204): request envelope, service peer (76), then those digests.
 */
struct plamen_broker_v2_service_readiness {
    uint8_t installed_closure_sha256[32];
    uint8_t broker_closure_sha256[32];
    uint8_t installation_receipt_sha256[32];
};

struct plamen_broker_v2_service_ready {
    uint8_t request_envelope_sha256[32];
    struct plamen_broker_v2_peer_identity service_peer;
    uint8_t installed_closure_sha256[32];
    uint8_t broker_closure_sha256[32];
    uint8_t installation_receipt_sha256[32];
};

struct plamen_broker_v2_service_registration_ack {
    uint8_t request_envelope_sha256[32];
    uint8_t registration_sha256[32];
    uint8_t registration_checkpoint_sha256[32];
    uint8_t broker_closure_sha256[32];
    struct plamen_broker_v2_peer_identity suspended_child;
    uint16_t initial_interpreter_slot;
    uint16_t initial_authority_role;
    uint16_t issuance_state; /* exactly zero: durable and unused */
};

/*
 * The extension has no Python/argv/environment registration token.  It asks
 * the authenticated service to look up its unused registration by the native
 * peer PID/birth identity.  SESSION_CHALLENGE returns every value that must be
 * echoed by SESSION_OPEN.  The extension obtains both closure digests from
 * its compiled native closure and creates session_id with the OS CSPRNG.
 */
struct plamen_broker_v2_service_session_lookup {
    uint8_t extension_closure_sha256[32];
    uint8_t interpreter_executable_sha256[32];
    uint8_t session_id[32];
};

/*
 * A challenge is valid for one exact peer and at most 5000 monotonic
 * milliseconds.  Issuing a replacement burns the prior in-memory challenge.
 * Mismatch, timeout, disconnect, or replay burns only the challenge/session;
 * none consumes the durable registration.  After exact OPEN descriptor
 * validation/duplication, the service durably burns the registration before
 * replying SESSION_ACCEPTED.  A consumed registration is never resurrected.
 */

struct plamen_broker_v2_service_session_challenge {
    uint8_t request_envelope_sha256[32];
    uint8_t registration_sha256[32];
    uint8_t committed_audit_generation_sha256[32];
    uint8_t request_projection_sha256[32];
    uint32_t request_projection_size;
    uint8_t commitment_sha256[32];
    uint16_t commitment_size;
    uint8_t commitment[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    uint8_t installed_closure_sha256[32];
    uint8_t broker_closure_sha256[32];
    uint8_t extension_closure_sha256[32];
    uint8_t interpreter_executable_sha256[32];
    struct plamen_broker_v2_peer_identity extension_peer;
    uint8_t session_id[32];
    uint16_t initial_interpreter_slot;
    uint16_t initial_authority_role;
    uint8_t challenge_nonce[32];
};

struct plamen_broker_v2_service_session_open {
    uint8_t challenge_envelope_sha256[32];
    uint8_t challenge_nonce[32];
    uint8_t commitment_sha256[32];
    uint8_t registration_sha256[32];
    uint8_t committed_audit_generation_sha256[32];
    uint8_t extension_closure_sha256[32];
    uint8_t interpreter_executable_sha256[32];
    struct plamen_broker_v2_peer_identity extension_peer;
    uint16_t initial_interpreter_slot;
    uint16_t initial_authority_role;
    uint8_t session_id[32];
    struct plamen_broker_v2_fd_metadata descriptors[2];
};

struct plamen_broker_v2_service_session_ack {
    uint8_t registration_sha256[32];
    uint8_t session_binding_sha256[32];
    uint8_t registration_burn_checkpoint_sha256[32];
    uint8_t authority_bundle_sha256[32];
    uint8_t session_id[32];
    uint16_t initial_authority_role;
};

/*
 * Linux session bootstrap is deliberately a distinct append-only family.
 * Its receipt and ELF closure authority cannot be interpreted as Darwin
 * launchd/Mach-O authority.  The service loaded the same installed receipt
 * independently before it may echo these bindings.
 */
struct plamen_broker_v2_service_linux_session_lookup {
    uint16_t version;
    uint16_t scope;
    uint32_t expected_uid;
    uint32_t expected_gid;
    uint8_t install_receipt_sha256[32];
    uint8_t receipt_session_binding_sha256[32];
    uint8_t native_deployment_receipt_sha256[32];
    uint8_t service_bootstrap_sha256[32];
    struct plamen_broker_v2_service_session_lookup base;
};

struct plamen_broker_v2_service_linux_session_challenge {
    uint16_t version;
    uint16_t scope;
    uint32_t expected_uid;
    uint32_t expected_gid;
    uint8_t install_receipt_sha256[32];
    uint8_t receipt_session_binding_sha256[32];
    uint8_t native_deployment_receipt_sha256[32];
    uint8_t service_bootstrap_sha256[32];
    struct plamen_broker_v2_service_session_challenge base;
};

struct plamen_broker_v2_service_linux_session_open {
    uint16_t version;
    uint16_t scope;
    uint32_t expected_uid;
    uint32_t expected_gid;
    uint8_t install_receipt_sha256[32];
    uint8_t receipt_session_binding_sha256[32];
    uint8_t native_deployment_receipt_sha256[32];
    uint8_t service_bootstrap_sha256[32];
    struct plamen_broker_v2_service_session_open base;
};

struct plamen_broker_v2_service_linux_session_ack {
    uint8_t request_envelope_sha256[32];
    uint8_t receipt_session_binding_sha256[32];
    uint8_t native_deployment_receipt_sha256[32];
    struct plamen_broker_v2_service_session_ack base;
};

/*
 * A specialized session is derived from one already-authenticated active
 * interpreter session but has a disjoint control socket, HMAC key, sequence,
 * and lane.  Derivation never consumes or multiplexes INITIAL_AUTHORITY.
 */
struct plamen_broker_v2_service_specialized_session_lookup {
    uint16_t version;
    uint16_t lane;
    uint8_t parent_session_id[32];
    uint8_t registration_sha256[32];
    uint8_t authority_bundle_sha256[32];
    uint8_t extension_closure_sha256[32];
    uint8_t interpreter_executable_sha256[32];
    uint8_t specialized_session_id[32];
};

struct plamen_broker_v2_service_specialized_session_challenge {
    uint8_t request_envelope_sha256[32];
    struct plamen_broker_v2_service_specialized_session_lookup lookup;
    struct plamen_broker_v2_peer_identity extension_peer;
    uint8_t challenge_nonce[32];
    uint8_t broker_closure_sha256[32];
};

struct plamen_broker_v2_service_specialized_session_open {
    uint8_t challenge_envelope_sha256[32];
    uint8_t challenge_nonce[32];
    uint16_t version;
    uint16_t lane;
    uint8_t parent_session_id[32];
    uint8_t specialized_session_id[32];
    struct plamen_broker_v2_peer_identity extension_peer;
    struct plamen_broker_v2_fd_metadata descriptors[2];
};

struct plamen_broker_v2_service_specialized_session_ack {
    uint8_t request_envelope_sha256[32];
    uint16_t version;
    uint16_t lane;
    uint8_t parent_session_id[32];
    uint8_t specialized_session_id[32];
    uint8_t authority_binding_sha256[32];
    uint8_t session_binding_sha256[32];
};

struct plamen_broker_v2_service_error {
    uint16_t code;
    uint16_t flags;
    uint16_t failed_message_type;
    uint8_t request_envelope_sha256[32];
};

/*
 * Canonical C-only bundle binding.  Role 1 has the ten ordered outer members
 * above; role 2 has exactly one BACKEND_EXECUTION member.  Member digests bind
 * static native objects and are never Python minting tokens or lookup keys.
 */
struct plamen_broker_v2_authority_bundle_binding {
    uint16_t role;
    uint16_t member_count;
    uint8_t registration_sha256[32];
    uint8_t issuance_checkpoint_sha256[32];
    uint8_t member_sha256[PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT][32];
};

/* Exact role-3 process identity committed by role-2 backend lifecycle state. */
struct plamen_broker_v2_backend_process_identity {
    uint8_t operation_key[32];
    uint8_t start_request_sha256[32];
    uint8_t executable_identity_sha256[32];
    struct plamen_broker_v2_peer_identity peer;
    uint8_t native_process_handle_sha256[32];
};

/*
 * Role-2 output is broker-spooled and never embedded in EXITED.  A successful
 * process has one immutable stream object per stdout/stderr, each capped at
 * 16 MiB.  OUTPUT_READ is operation-keyed and replayable; OUTPUT_CHUNK returns
 * at most 256 KiB and binds both the chunk and complete stream.  Exceeding the
 * spool cap prevents a successful EXITED, durably transitions through revoke,
 * and makes all output reads fail terminally.
 *
 * OUTPUT_READ bytes (79): version U16, operation_key DIGEST,
 * exited_receipt_sha256 DIGEST, stream U8, offset U64, max_bytes U32.
 * OUTPUT_CHUNK bytes (188+N): version U16, operation_key DIGEST,
 * request_sha256 DIGEST, exited_receipt_sha256 DIGEST, stream U8, offset U64,
 * length U32, eof BOOL, chunk_sha256 DIGEST, full_stream_sha256 DIGEST,
 * full_stream_size U64, chunk BYTES.  N equals both length fields.
 */
struct plamen_broker_v2_output_read {
    uint8_t operation_key[32];
    uint8_t exited_receipt_sha256[32];
    uint8_t stream;
    uint64_t offset;
    uint32_t max_bytes;
};

struct plamen_broker_v2_output_chunk {
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t exited_receipt_sha256[32];
    uint8_t stream;
    uint64_t offset;
    uint32_t length;
    uint8_t eof;
    uint8_t chunk_sha256[32];
    uint8_t full_stream_sha256[32];
    uint64_t full_stream_size;
    const uint8_t *chunk;
};

/*
 * Canonical-bytes authority RPC.  OPERATION_REQUEST bytes (142+N): version,
 * authority role, member, method, flags, operation key, request fingerprint,
 * prior native checkpoint, SHA256(canonical request), N U32, request bytes.
 * OPERATION_RESPONSE bytes (176+N): version, role, member, method,
 * disposition, durable state, operation key, SHA256(exact request frame
 * payload), prior checkpoint, next checkpoint, SHA256(response), N, response.
 * OPERATION_ERROR is fixed 108 bytes: version, role, member, method, error
 * code, flags, operation key, request SHA, current durable checkpoint.
 *
 * Frame operation_nonce equals operation_key.  Unknown flags/IDs burn the
 * session.  Repeating an exact operation-key/request tuple returns the stored
 * byte-identical response/error; reusing a key with different bytes is a
 * conflict before effect.  RECOVER is admitted only by *_OR_RECOVER methods
 * and RecoveryAuthority.recover.  Canonical request/response bytes are never
 * interpreted as process/environment/descriptor authority.
 * Canonical JSON call payloads end in exactly one LF and their payload digest
 * includes it.  Canonical response/receipt payloads have no trailing LF.
 *
 * For role 1, prior_checkpoint is the session's current global supervisor
 * checkpoint and a committed response advances it to next_checkpoint.  A
 * client retains the exact encoded request/key/prior until its response is
 * acknowledged so an in-session retry does not accidentally derive a new key.
 * For role 2, prior_checkpoint is always the authority-bundle issuance
 * checkpoint: operation-specific state is selected and authenticated only by
 * the broker after parsing the canonical payload, so concurrent shards never
 * race on a client-global checkpoint.  next_checkpoint then proves that one
 * shard's durable state but is not the next request's transport-key input.
 * The native client replay cache holds metadata only, keyed by role/member/
 * method/payload SHA.  Each entry retains the original prior checkpoint,
 * operation key, and exact request SHA; response bytes remain service-owned.
 * It admits at most RPC_REPLAY_MAX_ENTRIES and RPC_REPLAY_METADATA_MAX bytes,
 * never evicts during a session, permits a known exact replay when full, and
 * hard-stops a new call before sending a frame when either cap is exhausted.
 */
struct plamen_broker_v2_operation_request {
    uint16_t authority_role;
    uint16_t member;
    uint16_t method;
    uint16_t flags;
    uint8_t operation_key[32];
    uint8_t request_fingerprint[32];
    uint8_t prior_checkpoint_sha256[32];
    uint8_t payload_sha256[32];
    uint32_t payload_size;
    const uint8_t *payload;
};

struct plamen_broker_v2_operation_response {
    uint16_t authority_role;
    uint16_t member;
    uint16_t method;
    uint16_t disposition;
    uint16_t state;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t prior_checkpoint_sha256[32];
    uint8_t next_checkpoint_sha256[32];
    uint8_t payload_sha256[32];
    uint32_t payload_size;
    const uint8_t *payload;
};

struct plamen_broker_v2_operation_error {
    uint16_t authority_role;
    uint16_t member;
    uint16_t method;
    uint16_t error_code;
    uint16_t flags;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t current_checkpoint_sha256[32];
};

/*
 * Role-2 long operations run on independently chained child sessions so one
 * terminal WAIT cannot block extinction or another shard.  INITIAL_AUTHORITY
 * remains one-shot: its authenticated parent session issues children.  OPEN
 * is sent on that parent with exactly one SCM_RIGHTS AF_UNIX control endpoint;
 * ACCEPTED has no descriptors.  Both sides derive the child key from the
 * parent key and the bound operation/session IDs, then the broker starts the
 * child chain with HELLO.  The exact OPERATION_REQUEST follows on the child.
 *
 * OPEN bytes (177): version, role, member, method, flags, reserved-zero,
 * operation key, request SHA, prior checkpoint, child session ID, and one
 * 37-byte FD metadata row (SERVICE_CONTROL_SOCKET, target 0, READ_WRITE).
 * ACCEPTED bytes (140): version, role, member, method, status=1,
 * reserved-zero, request-frame SHA, operation key, child session ID, binding.
 * A child must be used within 5s.  At most 64 are active per parent.  Only one
 * child for an operation key may be active; after EOF/burn an exact durable
 * retry may issue a fresh child ID.  Child failure burns only that child.
 */
struct plamen_broker_v2_worker_session_open {
    uint16_t authority_role;
    uint16_t member;
    uint16_t method;
    uint16_t flags;
    uint8_t operation_key[32];
    uint8_t request_sha256[32];
    uint8_t prior_checkpoint_sha256[32];
    uint8_t child_session_id[32];
    struct plamen_broker_v2_fd_metadata control_socket;
};

struct plamen_broker_v2_worker_session_accepted {
    uint16_t authority_role;
    uint16_t member;
    uint16_t method;
    uint16_t status;
    uint8_t request_frame_sha256[32];
    uint8_t operation_key[32];
    uint8_t child_session_id[32];
    uint8_t child_binding_sha256[32];
};

/*
 * Host/guest VM boundary.  SCM_RIGHTS never crosses Apple Container's VM.
 * The host provider creates this one-shot record at GUEST_BOOTSTRAP_PATH,
 * mode 0400, uid/gid 0 in the guest view, and binds SHA256(exact record) in
 * create/admission receipts.  `/usr/local/libexec/plamen-guest` alone opens it
 * O_RDONLY|O_CLOEXEC|O_NOFOLLOW, verifies the receipt-bound digest and every
 * field, starts the guest-local Linux broker at LINUX_GUEST_SOCKET in a 0700
 * root-owned /run/plamen, unlinks the record before resuming Python, and never
 * exposes the bytes/key via argv, environment, logs, or Python descriptors.
 * The Linux broker then uses SO_PEERCRED + pid birth/boot-id/executable checks.
 *
 * The record is variable canonical binary, max 1016 bytes: magic PLMGBS2\0,
 * version U16, role=GUEST_DRIVER U16, total U32; request/attempt/run/provider
 * guest IDs; request fingerprint, projection, runtime layout, image closure,
 * backend executable/profile, credential, egress policy/admission, network
 * closure, and proxy-endpoint digests; session ID, one-shot session key and
 * nonce; then SHA256(domain || every preceding byte).  Network/proxy bindings
 * are intentionally additional provider-transport closure, not untrusted
 * projection fields; the authenticated egress admission must bind them.
 */
struct plamen_broker_v2_guest_bootstrap_record {
    char request_id[PLAMEN_BROKER_V2_MAX_ID + 1U];
    char attempt_id[PLAMEN_BROKER_V2_MAX_ID + 1U];
    char run_id[PLAMEN_BROKER_V2_MAX_ID + 1U];
    char provider_guest_id[PLAMEN_BROKER_V2_MAX_ID + 1U];
    uint8_t request_fingerprint[32];
    uint8_t request_projection_sha256[32];
    uint8_t runtime_layout_sha256[32];
    uint8_t image_closure_sha256[32];
    uint8_t backend_executable_identity[32];
    uint8_t backend_profile_identity[32];
    uint8_t credential_identity[32];
    uint8_t egress_policy_identity[32];
    uint8_t egress_admission_identity[32];
    uint8_t network_closure_sha256[32];
    uint8_t proxy_endpoint_sha256[32];
    uint8_t session_id[32];
    uint8_t session_key[32];
    uint8_t one_shot_nonce[32];
};

/*
 * Exact retained external-authority admission.  This portable byte validator
 * accepts descriptors only: it strict-decodes PLMBPF2, proves that profile's
 * exact row in the receipt-bound role-8 runtime manifest, hashes the retained
 * provider/backend executables, and validates the canonical generated egress
 * policy/admission documents against those observations and the unchanged
 * host config content digest.  No path, environment value, Python object, or
 * callback can confer authority.  The caller still performs additive native
 * platform code-signing/version checks before using the returned facts.
 */
struct plamen_broker_v2_external_authority_facts {
    uint8_t runtime_manifest_sha256[32];
    uint8_t image_index_sha256[32];
    uint8_t image_manifest_sha256[32];
    uint8_t image_configuration_sha256[32];
    uint8_t image_closure_sha256[32];
    uint8_t seccomp_profile_sha256[32];
    uint8_t provider_sha256[32];
    uint8_t backend_sha256[32];
    uint8_t profile_sha256[32];
    uint8_t policy_sha256[32];
    uint8_t admission_sha256[32];
    uint8_t policy_nonce[32];
    uint8_t provider_cdhash[32];
    uint8_t backend_cdhash[32];
    uint16_t provider_cdhash_size;
    uint16_t backend_cdhash_size;
    char provider_identifier[129];
    char provider_team[129];
    char provider_version[129];
    char backend_identifier[129];
    char backend_team[129];
    char backend_version[129];
    char backend_release[257];
    char backend_selector[33];
    char provider_selector[33];
    char image_reference[512];
};

/*
 * Closed native config -> projection composer.  Discovery parses the retained
 * config into bounded path/backend selector requests but confers no authority.
 * Native launcher code descriptor-opens those requests under its admitted
 * roots/provider stores, then the final builder re-reads the original fd and
 * requires the discovery bytes/identity to match before consuming any opened
 * descriptor.  Thus neither launcher nor Python implements an independent
 * JSON/path parser and no config string is treated as a digest/capability.
 * provider_selector selects only the receipt-bound platform provider roster;
 * backend_profile_selector selects an executable/profile in the retained
 * runtime generation; credential_selector is resolved by the native OS
 * credential broker; egress_selector creates a sealed role5-policy instance
 * and its independently observed admission receipt.  PATH/environment and
 * caller-supplied executable/profile/credential/egress paths are forbidden.
 *
 * The final launcher supplies only retained descriptors and the two expected
 * manifest hashes from its authenticated install receipt.  It never supplies
 * request digests or projection bytes.  docs/scope may be -1 only when absent;
 * every other non-resume fd is required.  RESUME identities are decoded from
 * the retained native checkpoint fd; NEW creates three UUIDv4 identities with
 * the OS CSPRNG.  Missing policy/admission observations return UNSUPPORTED.
 */
struct plamen_broker_v2_projection_discovery {
    uint32_t ownership_magic;
    uint16_t startup_intent;
    uint8_t config_identity[32];
    uint8_t config_content_sha256[32];
    char config_path[PLAMEN_BROKER_V2_PROJECTION_PATH_MAX + 1U];
    char project_root[PLAMEN_BROKER_V2_PROJECTION_PATH_MAX + 1U];
    char scratchpad[PLAMEN_BROKER_V2_PROJECTION_PATH_MAX + 1U];
    char docs_path[PLAMEN_BROKER_V2_PROJECTION_PATH_MAX + 1U];
    char scope_file[PLAMEN_BROKER_V2_PROJECTION_PATH_MAX + 1U];
    char resume_checkpoint_path[PLAMEN_BROKER_V2_PROJECTION_PATH_MAX + 1U];
    char pipeline[8];
    char mode[16];
    char backend[16];
    char language[33];
    char provider_selector[32];
    char backend_profile_selector[32];
    char credential_selector[32];
    char egress_selector[32];
    uint8_t has_docs;
    uint8_t has_scope;
};

struct plamen_broker_v2_projection_builder_inputs {
    uint16_t startup_intent;
    const char *config_path;
    int config_fd;
    const struct plamen_broker_v2_projection_discovery *discovery;
    int target_root_fd;
    int docs_root_fd;
    int scope_fd;
    int export_root_fd;
    int role5_schema_fd;
    int runtime_manifest_fd;
    int provider_executable_fd;
    int backend_executable_fd;
    int backend_profile_fd;
    int credential_source_fd;
    int egress_policy_fd;
    int egress_admission_fd;
    int resume_checkpoint_fd;
    uint8_t expected_role5_schema_sha256[32];
    uint8_t expected_runtime_manifest_sha256[32];
};

struct plamen_broker_v2_projection_builder_result {
    uint32_t ownership_magic;
    uint16_t startup_intent;
    uint16_t retained_presence_mask;
    uint8_t *guest_config;
    size_t guest_config_size;
    uint8_t *request_projection;
    size_t request_projection_size;
    uint8_t commitment[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    size_t commitment_size;
    uint8_t guest_config_sha256[32];
    uint8_t request_projection_sha256[32];
    uint8_t commitment_sha256[32];
    char request_id[PLAMEN_BROKER_V2_MAX_ID + 1U];
    char attempt_id[PLAMEN_BROKER_V2_MAX_ID + 1U];
    char run_id[PLAMEN_BROKER_V2_MAX_ID + 1U];
    int retained_fds[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT];
    uint8_t retained_identities[PLAMEN_BROKER_V2_PROJECTION_RETAINED_FD_COUNT][32];
};

void plamen_broker_v2_secure_zero(void *data, size_t size);
int plamen_broker_v2_sha256(const void *data, size_t size, uint8_t out[32]);
int plamen_broker_v2_hmac_sha256(const uint8_t key[32], const void *first,
    size_t first_size, const void *second, size_t second_size, uint8_t out[32]);
int plamen_broker_v2_specialized_session_binding(
    const uint8_t key[32], const uint8_t parent_session_id[32],
    const uint8_t specialized_session_id[32], uint16_t lane,
    const uint8_t authority_binding_sha256[32], uint8_t out[32]);

void plamen_broker_v2_writer_init(struct plamen_broker_v2_writer *writer,
    uint8_t *data, size_t capacity);
void plamen_broker_v2_reader_init(struct plamen_broker_v2_reader *reader,
    const uint8_t *data, size_t size);
int plamen_broker_v2_put_u8(struct plamen_broker_v2_writer *, uint8_t);
int plamen_broker_v2_put_u16(struct plamen_broker_v2_writer *, uint16_t);
int plamen_broker_v2_put_u32(struct plamen_broker_v2_writer *, uint32_t);
int plamen_broker_v2_put_u64(struct plamen_broker_v2_writer *, uint64_t);
int plamen_broker_v2_put_bool(struct plamen_broker_v2_writer *, int);
int plamen_broker_v2_put_digest(struct plamen_broker_v2_writer *, const uint8_t[32]);
int plamen_broker_v2_put_id(struct plamen_broker_v2_writer *, const char *, size_t);
int plamen_broker_v2_put_text(struct plamen_broker_v2_writer *, const uint8_t *, size_t);
int plamen_broker_v2_put_bytes(struct plamen_broker_v2_writer *, const uint8_t *,
    size_t, size_t);
int plamen_broker_v2_get_u8(struct plamen_broker_v2_reader *, uint8_t *);
int plamen_broker_v2_get_u16(struct plamen_broker_v2_reader *, uint16_t *);
int plamen_broker_v2_get_u32(struct plamen_broker_v2_reader *, uint32_t *);
int plamen_broker_v2_get_u64(struct plamen_broker_v2_reader *, uint64_t *);
int plamen_broker_v2_get_bool(struct plamen_broker_v2_reader *, int *);
int plamen_broker_v2_get_digest(struct plamen_broker_v2_reader *, uint8_t[32]);
int plamen_broker_v2_get_id(struct plamen_broker_v2_reader *, char *, size_t);
int plamen_broker_v2_get_text(struct plamen_broker_v2_reader *, const uint8_t **,
    uint32_t *);
int plamen_broker_v2_get_bytes(struct plamen_broker_v2_reader *, const uint8_t **,
    uint32_t *, uint32_t);
int plamen_broker_v2_encode_commitment(struct plamen_broker_v2_writer *,
    const struct plamen_broker_v2_commitment *);
int plamen_broker_v2_decode_commitment_exact(const uint8_t *, size_t,
    struct plamen_broker_v2_commitment *);
int plamen_broker_v2_request_projection_derive_exact(const uint8_t *, size_t,
    struct plamen_broker_v2_commitment *, uint8_t *, size_t, size_t *,
    uint8_t projection_sha256[32], uint8_t commitment_sha256[32]);
int plamen_broker_v2_request_projection_validate_exact(const uint8_t *, size_t,
    const uint8_t expected_projection_sha256[32], const uint8_t *, size_t,
    const uint8_t expected_commitment_sha256[32],
    struct plamen_broker_v2_commitment *);

int plamen_broker_v2_session_init(struct plamen_broker_v2_session *, uint8_t role,
    const uint8_t key[32], const uint8_t session_id[32]);
void plamen_broker_v2_session_burn(struct plamen_broker_v2_session *);
int plamen_broker_v2_frame_build(struct plamen_broker_v2_session *, uint16_t type,
    const uint8_t operation_nonce[32], const uint8_t *payload, uint32_t payload_size,
    uint16_t fd_count, uint8_t **frame, size_t *frame_size);
int plamen_broker_v2_frame_accept(struct plamen_broker_v2_session *,
    const uint8_t *frame, size_t frame_size, size_t received_fd_count,
    struct plamen_broker_v2_frame_view *);

int plamen_broker_v2_fd_identity(int fd, uint8_t out[32]);
int plamen_broker_v2_validate_received_fds(int *fds, size_t fd_count,
    const struct plamen_broker_v2_fd_metadata *metadata, size_t metadata_count);
void plamen_broker_v2_close_fds(int *fds, size_t fd_count);
int plamen_broker_v2_specialized_request_encode(
    const struct plamen_broker_v2_specialized_request *, uint8_t *, size_t,
    size_t *);
int plamen_broker_v2_specialized_request_decode_exact(const uint8_t *, size_t,
    struct plamen_broker_v2_specialized_request *);
int plamen_broker_v2_specialized_response_encode(
    const struct plamen_broker_v2_specialized_response *, uint8_t *, size_t,
    size_t *);
int plamen_broker_v2_specialized_response_decode_exact(const uint8_t *, size_t,
    struct plamen_broker_v2_specialized_response *);
int plamen_broker_v2_specialized_request_validate_fds(
    const struct plamen_broker_v2_specialized_request *, int *, size_t);

/*
 * The service transport contains exactly the `envelope` byte string plus one
 * typed request-projection attachment for REGISTER, or, for SESSION_OPEN only,
 * `control_socket` then `key_pipe_read`.  No PID, secret,
 * path, digest, or status is accepted from a second transport field.  Native
 * audit-token/SO_PEERCRED and code-identity checks happen before this parser.
 * The service duplicates both descriptors with CLOEXEC before durably burning
 * the launcher registration; only then may SESSION_ACCEPTED be sent.  Sender
 * originals and receiver duplicates are closed on every error.  After success,
 * the extension writes exactly 32 key bytes and closes its pipe endpoint; short,
 * surplus, or missing EOF burns the session.  ERROR is terminal and discloses
 * only its fixed status/flags; it never authorizes retry of a durable effect.
 */
int plamen_broker_v2_service_envelope_build(uint8_t local_role, uint16_t type,
    const uint8_t transaction_nonce[32], const uint8_t invocation_nonce[32],
    const uint8_t *payload, uint32_t payload_size, uint16_t fd_count,
    uint8_t **envelope, size_t *envelope_size);
int plamen_broker_v2_service_envelope_accept(uint8_t local_role,
    const uint8_t *envelope, size_t envelope_size, size_t received_fd_count,
    struct plamen_broker_v2_service_envelope_view *);
int plamen_broker_v2_service_readiness_encode(
    const struct plamen_broker_v2_service_readiness *, uint8_t out[96]);
int plamen_broker_v2_service_readiness_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_service_readiness *);
int plamen_broker_v2_service_ready_encode(
    const struct plamen_broker_v2_service_ready *, uint8_t out[204]);
int plamen_broker_v2_service_ready_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_service_ready *);
int plamen_broker_v2_service_ready_matches_readiness(
    const struct plamen_broker_v2_service_readiness *, const uint8_t[32],
    const struct plamen_broker_v2_service_ready *);
int plamen_broker_v2_service_registration_encode(
    const struct plamen_broker_v2_service_registration *,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE]);
int plamen_broker_v2_service_registration_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_service_registration *);
int plamen_broker_v2_service_registration_descriptors_valid(
    const struct plamen_broker_v2_service_registration *);
int plamen_broker_v2_service_registration_fd_count(
    const struct plamen_broker_v2_service_registration *, uint16_t *);
int plamen_broker_v2_service_registration_ack_encode(
    const struct plamen_broker_v2_service_registration_ack *, uint8_t out[210]);
int plamen_broker_v2_service_registration_ack_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_service_registration_ack *);
int plamen_broker_v2_service_session_lookup_encode(
    const struct plamen_broker_v2_service_session_lookup *, uint8_t out[96]);
int plamen_broker_v2_service_session_lookup_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_service_session_lookup *);
int plamen_broker_v2_service_session_challenge_encode(
    const struct plamen_broker_v2_service_session_challenge *, uint8_t out[954]);
int plamen_broker_v2_service_session_challenge_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_service_session_challenge *);
int plamen_broker_v2_service_session_open_encode(
    const struct plamen_broker_v2_service_session_open *, uint8_t out[410]);
int plamen_broker_v2_service_session_open_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_service_session_open *);
int plamen_broker_v2_service_session_ack_encode(
    const struct plamen_broker_v2_service_session_ack *, uint8_t out[164]);
int plamen_broker_v2_service_session_ack_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_service_session_ack *);
int plamen_broker_v2_service_linux_session_lookup_encode(
    const struct plamen_broker_v2_service_linux_session_lookup *,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_LOOKUP_SIZE]);
int plamen_broker_v2_service_linux_session_lookup_decode(
    const uint8_t *, size_t,
    struct plamen_broker_v2_service_linux_session_lookup *);
int plamen_broker_v2_service_linux_session_challenge_encode(
    const struct plamen_broker_v2_service_linux_session_challenge *,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_CHALLENGE_SIZE]);
int plamen_broker_v2_service_linux_session_challenge_decode(
    const uint8_t *, size_t,
    struct plamen_broker_v2_service_linux_session_challenge *);
int plamen_broker_v2_service_linux_session_open_encode(
    const struct plamen_broker_v2_service_linux_session_open *,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_OPEN_SIZE]);
int plamen_broker_v2_service_linux_session_open_decode(
    const uint8_t *, size_t,
    struct plamen_broker_v2_service_linux_session_open *);
int plamen_broker_v2_service_linux_session_ack_encode(
    const struct plamen_broker_v2_service_linux_session_ack *,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_LINUX_SESSION_ACK_SIZE]);
int plamen_broker_v2_service_linux_session_ack_decode(
    const uint8_t *, size_t,
    struct plamen_broker_v2_service_linux_session_ack *);
int plamen_broker_v2_service_linux_session_challenge_matches_lookup(
    const struct plamen_broker_v2_service_linux_session_lookup *,
    const uint8_t lookup_envelope_sha256[32],
    const struct plamen_broker_v2_service_linux_session_challenge *);
int plamen_broker_v2_service_linux_session_open_matches_challenge(
    const struct plamen_broker_v2_service_linux_session_challenge *,
    const uint8_t challenge_envelope_sha256[32],
    const struct plamen_broker_v2_service_linux_session_open *);
int plamen_broker_v2_service_linux_session_ack_matches_open(
    const struct plamen_broker_v2_service_linux_session_open *,
    const uint8_t open_envelope_sha256[32],
    const struct plamen_broker_v2_service_linux_session_ack *);
int plamen_broker_v2_service_specialized_session_lookup_encode(
    const struct plamen_broker_v2_service_specialized_session_lookup *,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP_SIZE]);
int plamen_broker_v2_service_specialized_session_lookup_decode(
    const uint8_t *, size_t,
    struct plamen_broker_v2_service_specialized_session_lookup *);
int plamen_broker_v2_service_specialized_session_challenge_encode(
    const struct plamen_broker_v2_service_specialized_session_challenge *,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE_SIZE]);
int plamen_broker_v2_service_specialized_session_challenge_decode(
    const uint8_t *, size_t,
    struct plamen_broker_v2_service_specialized_session_challenge *);
int plamen_broker_v2_service_specialized_session_open_encode(
    const struct plamen_broker_v2_service_specialized_session_open *,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN_SIZE]);
int plamen_broker_v2_service_specialized_session_open_decode(
    const uint8_t *, size_t,
    struct plamen_broker_v2_service_specialized_session_open *);
int plamen_broker_v2_service_specialized_session_ack_encode(
    const struct plamen_broker_v2_service_specialized_session_ack *,
    uint8_t out[PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACK_SIZE]);
int plamen_broker_v2_service_specialized_session_ack_decode(
    const uint8_t *, size_t,
    struct plamen_broker_v2_service_specialized_session_ack *);
int plamen_broker_v2_service_error_encode(
    const struct plamen_broker_v2_service_error *, uint8_t out[40]);
int plamen_broker_v2_service_error_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_service_error *);
int plamen_broker_v2_initial_authority_allows_frame(uint16_t authority_role,
    uint16_t frame_type);
int plamen_broker_v2_service_session_open_matches_registration(
    const struct plamen_broker_v2_service_registration_ack *,
    const struct plamen_broker_v2_service_session_open *);
int plamen_broker_v2_service_session_challenge_matches_lookup(
    const struct plamen_broker_v2_service_session_lookup *, const uint8_t[32],
    const struct plamen_broker_v2_service_session_challenge *);
int plamen_broker_v2_service_session_open_matches_challenge(
    const struct plamen_broker_v2_service_session_challenge *, const uint8_t[32],
    const struct plamen_broker_v2_service_session_open *);
int plamen_broker_v2_service_session_ack_matches_open(
    const struct plamen_broker_v2_service_session_open *,
    const struct plamen_broker_v2_service_session_ack *);
int plamen_broker_v2_authority_bundle_binding_encode(
    const struct plamen_broker_v2_authority_bundle_binding *, uint8_t *,
    size_t, size_t *);
int plamen_broker_v2_authority_bundle_binding_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_authority_bundle_binding *);
int plamen_broker_v2_auth_consume_matches_challenge(
    const struct plamen_broker_v2_service_session_challenge *,
    const uint8_t *, size_t, struct plamen_broker_v2_commitment *);
int plamen_broker_v2_auth_accepted_matches_session_ack(
    const struct plamen_broker_v2_service_session_ack *, const uint8_t *,
    size_t, struct plamen_broker_v2_authority_bundle_binding *);
int plamen_broker_v2_backend_process_identity_encode(
    const struct plamen_broker_v2_backend_process_identity *, uint8_t out[212]);
int plamen_broker_v2_backend_process_identity_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_backend_process_identity *);
int plamen_broker_v2_derive_operation_key(
    const struct plamen_broker_v2_commitment *, uint16_t,
    const uint8_t operation_nonce[32], const uint8_t spec_sha256[32],
    const uint8_t launch_request_sha256[32],
    const uint8_t prior_native_checkpoint_sha256[32], uint8_t out[32]);
int plamen_broker_v2_derive_rpc_operation_key(
    const struct plamen_broker_v2_commitment *,
    const uint8_t member_capability_id[32], uint16_t authority_role,
    uint16_t member, uint16_t method,
    const uint8_t payload_sha256[32],
    const uint8_t prior_native_checkpoint_sha256[32], uint8_t out[32]);
int plamen_broker_v2_output_read_encode(
    const struct plamen_broker_v2_output_read *, uint8_t out[79]);
int plamen_broker_v2_output_read_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_output_read *);
int plamen_broker_v2_output_chunk_encode(
    const struct plamen_broker_v2_output_chunk *, uint8_t *, size_t, size_t *);
int plamen_broker_v2_output_chunk_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_output_chunk *);
int plamen_broker_v2_authority_method_valid(uint16_t role, uint16_t member,
    uint16_t method, uint16_t flags);
int plamen_broker_v2_authority_method_deadline(uint16_t role, uint16_t member,
    uint16_t method, uint32_t *service_seconds, uint32_t *client_seconds);
int plamen_broker_v2_operation_request_encode(
    const struct plamen_broker_v2_operation_request *, uint8_t *, size_t,
    size_t *);
int plamen_broker_v2_operation_request_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_operation_request *);
int plamen_broker_v2_operation_response_encode(
    const struct plamen_broker_v2_operation_response *, uint8_t *, size_t,
    size_t *);
int plamen_broker_v2_operation_response_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_operation_response *);
int plamen_broker_v2_operation_error_encode(
    const struct plamen_broker_v2_operation_error *, uint8_t out[108]);
int plamen_broker_v2_operation_error_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_operation_error *);
int plamen_broker_v2_operation_response_matches_request(
    const uint8_t *, size_t,
    const struct plamen_broker_v2_operation_request *,
    const struct plamen_broker_v2_operation_response *);
int plamen_broker_v2_operation_error_matches_request(const uint8_t *, size_t,
    const struct plamen_broker_v2_operation_request *,
    const struct plamen_broker_v2_operation_error *);
int plamen_broker_v2_worker_session_open_encode(
    const struct plamen_broker_v2_worker_session_open *,
    uint8_t out[PLAMEN_BROKER_V2_WORKER_SESSION_OPEN_SIZE]);
int plamen_broker_v2_worker_session_open_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_worker_session_open *);
int plamen_broker_v2_worker_session_accepted_encode(
    const struct plamen_broker_v2_worker_session_accepted *,
    uint8_t out[PLAMEN_BROKER_V2_WORKER_SESSION_ACCEPTED_SIZE]);
int plamen_broker_v2_worker_session_accepted_decode(const uint8_t *, size_t,
    struct plamen_broker_v2_worker_session_accepted *);
int plamen_broker_v2_worker_session_derive_key(const uint8_t parent_key[32],
    const uint8_t parent_session_id[32], const uint8_t operation_key[32],
    const uint8_t child_session_id[32], uint8_t child_key[32]);
int plamen_broker_v2_worker_session_derive_binding(
    const uint8_t parent_session_id[32],
    const struct plamen_broker_v2_worker_session_open *,
    uint8_t child_binding_sha256[32]);
int plamen_broker_v2_guest_bootstrap_encode(
    const struct plamen_broker_v2_guest_bootstrap_record *, uint8_t *, size_t,
    size_t *, uint8_t record_sha256[32]);
int plamen_broker_v2_guest_bootstrap_decode(const uint8_t *, size_t,
    const uint8_t expected_record_sha256[32],
    struct plamen_broker_v2_guest_bootstrap_record *);
int plamen_broker_v2_external_authority_validate(int runtime_manifest_fd,
    const uint8_t expected_runtime_manifest_sha256[32],
    int provider_executable_fd, int backend_executable_fd,
    int backend_profile_fd, int egress_policy_fd, int egress_admission_fd,
    const uint8_t config_content_sha256[32],
    struct plamen_broker_v2_external_authority_facts *);
int plamen_broker_v2_projection_build_from_retained(
    const struct plamen_broker_v2_projection_builder_inputs *,
    struct plamen_broker_v2_projection_builder_result *);
int plamen_broker_v2_projection_discover_config(uint16_t startup_intent,
    const char *config_path, int config_fd,
    struct plamen_broker_v2_projection_discovery *);
void plamen_broker_v2_projection_discovery_destroy(
    struct plamen_broker_v2_projection_discovery *);
int plamen_broker_v2_projection_builder_revalidate(
    const struct plamen_broker_v2_projection_builder_result *);
int plamen_broker_v2_projection_registration_roster(
    const struct plamen_broker_v2_projection_builder_result *,
    struct plamen_broker_v2_service_registration *);
void plamen_broker_v2_projection_builder_result_destroy(
    struct plamen_broker_v2_projection_builder_result *);

#ifdef __linux__
/*
 * Linux uses one connected AF_UNIX SOCK_SEQPACKET per authenticated service
 * exchange.  The caller obtains it only through native service activation or
 * native launcher/extension code; Python, argv, and the environment never
 * carry this descriptor.  SO_PEERCRED, /proc start ticks, the canonical boot
 * ID, a pidfd, and the installed peer executable identity are all revalidated
 * before an envelope or SCM_RIGHTS descriptor is accepted.
 */
int plamen_broker_v2_linux_peer_admit(int connected_socket_fd,
    const uint8_t expected_executable_identity[32],
    struct plamen_broker_v2_peer_identity *, int *pidfd_out);
int plamen_broker_v2_linux_projection_fd_validate(int projection_fd,
    const struct plamen_broker_v2_service_registration *);
int plamen_broker_v2_linux_service_send_owned(int connected_socket_fd,
    const uint8_t *envelope, size_t envelope_size,
    int fds[PLAMEN_BROKER_V2_SERVICE_MAX_FDS], size_t fd_count);
int plamen_broker_v2_linux_service_receive(int connected_socket_fd,
    uint8_t local_role, uint8_t **envelope, size_t *envelope_size,
    int fds[PLAMEN_BROKER_V2_SERVICE_MAX_FDS], size_t *fd_count,
    struct plamen_broker_v2_service_envelope_view *);

/*
 * Extension-side service exchange.  `scope` selects one compiled socket
 * policy; no caller-supplied pathname is accepted.  The connected service is
 * admitted and revalidated with SO_PEERCRED, pidfd, procfs birth/boot
 * identity, and the exact retained broker executable descriptor identity.
 * Request descriptors are borrowed and never closed by this function; service
 * replies carrying SCM_RIGHTS are rejected.  `errno` remains meaningful for
 * connection-unavailable failures.
 */
int plamen_broker_v2_linux_client_exchange(
    uint16_t scope, uint64_t expected_uid,
    const uint8_t expected_executable_identity[32],
    const uint8_t *request_envelope, size_t request_envelope_size,
    const int *request_fds, size_t request_fd_count, uint8_t local_role,
    uint8_t **response_envelope, size_t *response_envelope_size,
    struct plamen_broker_v2_service_envelope_view *response_view,
    struct plamen_broker_v2_peer_identity *service_peer);
int plamen_broker_v2_linux_current_peer(
    uint64_t expected_uid,
    const uint8_t expected_interpreter_executable_identity[32],
    struct plamen_broker_v2_peer_identity *current_peer);
#endif

#ifdef __cplusplus
}
#endif
#endif
