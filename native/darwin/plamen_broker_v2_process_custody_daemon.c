#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_process_custody_daemon.h"

#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KEY_OPERATION "operation"
#define KEY_BROKER_SESSION "broker_session_id"
#define KEY_START_OPERATION "start_operation"
#define KEY_OPERATION_KEY "operation_key"
#define KEY_REQUEST "request_sha256"
#define KEY_PRIOR "prior_checkpoint_sha256"
#define KEY_CLAIM "claim_owner_sha256"
#define KEY_EXECUTABLE "executable"
#define KEY_CWD "cwd"
#define KEY_STDIN "stdin"
#define KEY_EXECUTABLE_PATH "executable_path"
#define KEY_ARGV "argv"
#define KEY_TIMEOUT "timeout_seconds"
#define KEY_STDOUT_LIMIT "stdout_limit"
#define KEY_STDERR_LIMIT "stderr_limit"
#define KEY_EXECUTABLE_SHA "executable_sha256"
#define KEY_SIGNING "signing_identifier"
#define KEY_TEAM "team_identifier"
#define KEY_STATUS "status"
#define KEY_RECEIPT "receipt"
#define KEY_STDOUT "stdout"
#define KEY_STDERR "stderr"
#define KEY_PROCESS_SPEC_VERSION "process_spec_version"
#define KEY_ENVIRONMENT_POLICY "environment_policy"
#define KEY_ENVIRONMENT "environment"
#define KEY_FD_MAPS "fd_maps"
#define KEY_FD_SOURCE "source"
#define KEY_FD_TARGET "target"

#define PROCESS_SPEC_WIRE_VERSION 2U

#define OP_START "start"
#define OP_ADOPT "adopt"
#define OP_WAIT "wait"
#define OP_RECOVER "recover"
#define OP_REVOKE "revoke"
#define OP_STATUS "status"

struct daemon_context {
    struct plamen_broker_v2_process_custodian *custodian;
    plamen_broker_v2_custody_daemon_peer_admit admit;
    dispatch_queue_t work_queue;
    struct plamen_broker_v2_custody_daemon_readiness readiness;
};

static int
data32(xpc_object_t message, const char *key, uint8_t output[32])
{
    size_t size = 0;
    xpc_object_t object = xpc_dictionary_get_value(message, key);
    const void *value;
    if (object == NULL || xpc_get_type(object) != XPC_TYPE_DATA)
        return -1;
    value = xpc_data_get_bytes_ptr(object);
    size = xpc_data_get_length(object);
    if (value == NULL || size != 32)
        return -1;
    memcpy(output, value, 32);
    return 0;
}

static int
uint32_value(xpc_object_t message, const char *key, uint32_t *output)
{
    xpc_object_t object = xpc_dictionary_get_value(message, key);
    uint64_t value;
    if (object == NULL || xpc_get_type(object) != XPC_TYPE_UINT64)
        return -1;
    value = xpc_uint64_get_value(object);
    if (value == 0 || value > UINT32_MAX)
        return -1;
    *output = (uint32_t)value;
    return 0;
}

static int
known_key(const char *operation, const char *key)
{
    if (strcmp(key, KEY_OPERATION) == 0
        || strcmp(key, KEY_BROKER_SESSION) == 0)
        return 1;
    if (strcmp(operation, OP_STATUS) == 0)
        return 0;
    if (strcmp(key, KEY_OPERATION_KEY) == 0
        || strcmp(key, KEY_REQUEST) == 0 || strcmp(key, KEY_PRIOR) == 0
        || strcmp(key, KEY_CLAIM) == 0)
        return 1;
    if (strcmp(operation, OP_WAIT) == 0 || strcmp(operation, OP_RECOVER) == 0
        || strcmp(operation, OP_REVOKE) == 0)
        return strcmp(key, KEY_START_OPERATION) == 0;
    if (strcmp(operation, OP_START) != 0)
        return 0;
    return strcmp(key, KEY_EXECUTABLE) == 0 || strcmp(key, KEY_CWD) == 0
        || strcmp(key, KEY_STDIN) == 0
        || strcmp(key, KEY_EXECUTABLE_PATH) == 0
        || strcmp(key, KEY_ARGV) == 0 || strcmp(key, KEY_TIMEOUT) == 0
        || strcmp(key, KEY_STDOUT_LIMIT) == 0
        || strcmp(key, KEY_STDERR_LIMIT) == 0
        || strcmp(key, KEY_EXECUTABLE_SHA) == 0
        || strcmp(key, KEY_SIGNING) == 0 || strcmp(key, KEY_TEAM) == 0
        || strcmp(key, KEY_PROCESS_SPEC_VERSION) == 0
        || strcmp(key, KEY_ENVIRONMENT_POLICY) == 0
        || strcmp(key, KEY_ENVIRONMENT) == 0
        || strcmp(key, KEY_FD_MAPS) == 0;
}

static int
exact_shape(xpc_object_t message, const char *operation)
{
    uint8_t session[32];
    __block int valid = 1;
    __block size_t count = 0;
    size_t expected = strcmp(operation, OP_STATUS) == 0 ? 2U
        : (strcmp(operation, OP_START) == 0 ? 21U
        : (strcmp(operation, OP_ADOPT) == 0 ? 6U : 7U));
    if (xpc_get_type(message) != XPC_TYPE_DICTIONARY)
        return 0;
    xpc_dictionary_apply(message, ^bool(const char *key, xpc_object_t value) {
        (void)value;
        ++count;
        if (!known_key(operation, key))
            valid = 0;
        return valid != 0;
    });
    return valid && count == expected
        && data32(message, KEY_BROKER_SESSION, session) == 0;
}

static int
exact_fd_map_shape(xpc_object_t item)
{
    __block size_t count = 0;
    __block int valid = 1;
    if (item == NULL || xpc_get_type(item) != XPC_TYPE_DICTIONARY)
        return 0;
    xpc_dictionary_apply(item, ^bool(const char *key, xpc_object_t value) {
        ++count;
        if ((strcmp(key, KEY_FD_SOURCE) == 0
                && xpc_get_type(value) == XPC_TYPE_FD)
            || (strcmp(key, KEY_FD_TARGET) == 0
                && xpc_get_type(value) == XPC_TYPE_UINT64))
            return true;
        valid = 0;
        return false;
    });
    return valid && count == 2;
}

static xpc_object_t
new_reply(xpc_object_t request, int status)
{
    uint8_t session[32];
    xpc_object_t reply = xpc_dictionary_create_reply(request);
    if (reply != NULL && data32(request, KEY_BROKER_SESSION, session) == 0) {
        xpc_dictionary_set_uint64(reply, KEY_STATUS, (uint64_t)(uint32_t)status);
        xpc_dictionary_set_data(reply, KEY_BROKER_SESSION, session, 32);
    }
    return reply;
}

static int
set_start_receipt(xpc_object_t response,
    const struct plamen_broker_v2_process_custodian_start_receipt *receipt)
{
    xpc_object_t value = xpc_dictionary_create(NULL, NULL, 0);
    if (value == NULL)
        return -1;
    xpc_dictionary_set_data(value, KEY_OPERATION_KEY,
        receipt->operation_key, 32);
    xpc_dictionary_set_data(value, KEY_REQUEST, receipt->request_sha256, 32);
    xpc_dictionary_set_data(value, KEY_PRIOR,
        receipt->prior_checkpoint_sha256, 32);
    xpc_dictionary_set_data(value, KEY_CLAIM, receipt->claim_owner_sha256, 32);
    xpc_dictionary_set_data(value, "process_spec_sha256",
        receipt->process_spec_sha256, 32);
    xpc_dictionary_set_data(value, "prepared_checkpoint_sha256",
        receipt->prepared_checkpoint_sha256, 32);
    xpc_dictionary_set_data(value, "started_checkpoint_sha256",
        receipt->started_checkpoint_sha256, 32);
    xpc_dictionary_set_int64(value, "child_pid", receipt->identity.child_pid);
    xpc_dictionary_set_int64(value, "process_group_id",
        receipt->identity.process_group_id);
    xpc_dictionary_set_uint64(value, "child_birth_us",
        receipt->identity.child_birth_us);
    xpc_dictionary_set_uint64(value, "executable_device",
        receipt->identity.executable_device);
    xpc_dictionary_set_uint64(value, "executable_inode",
        receipt->identity.executable_inode);
    xpc_dictionary_set_data(value, KEY_EXECUTABLE_SHA,
        receipt->identity.executable_sha256, 32);
    xpc_dictionary_set_data(value, "executable_identity_sha256",
        receipt->identity.executable_identity_sha256, 32);
    xpc_dictionary_set_data(value, "native_process_handle_sha256",
        receipt->identity.native_process_handle_sha256, 32);
    xpc_dictionary_set_data(value, "cdhash", receipt->identity.cdhash,
        receipt->identity.cdhash_size);
    xpc_dictionary_set_string(value, KEY_SIGNING,
        receipt->identity.signing_identifier);
    xpc_dictionary_set_string(value, KEY_TEAM,
        receipt->identity.team_identifier);
    xpc_dictionary_set_value(response, KEY_RECEIPT, value);
    xpc_release(value);
    return 0;
}

static int
set_terminal_receipt(xpc_object_t response,
    const struct plamen_broker_v2_process_custodian_terminal_receipt *receipt)
{
    xpc_object_t value = xpc_dictionary_create(NULL, NULL, 0);
    if (value == NULL)
        return -1;
    xpc_dictionary_set_data(value, KEY_START_OPERATION,
        receipt->start_operation_key, 32);
    xpc_dictionary_set_data(value, KEY_OPERATION_KEY,
        receipt->operation_key, 32);
    xpc_dictionary_set_data(value, KEY_REQUEST, receipt->request_sha256, 32);
    xpc_dictionary_set_data(value, KEY_PRIOR,
        receipt->prior_checkpoint_sha256, 32);
    xpc_dictionary_set_data(value, KEY_CLAIM, receipt->claim_owner_sha256, 32);
    xpc_dictionary_set_data(value, "process_spec_sha256",
        receipt->process_spec_sha256, 32);
    xpc_dictionary_set_data(value, "native_process_handle_sha256",
        receipt->native_process_handle_sha256, 32);
    xpc_dictionary_set_uint64(value, "terminal_status",
        receipt->terminal.status);
    xpc_dictionary_set_int64(value, "exit_code", receipt->terminal.exit_code);
    xpc_dictionary_set_int64(value, "signal_number",
        receipt->terminal.signal_number);
    xpc_dictionary_set_int64(value, "child_pid", receipt->terminal.child_pid);
    xpc_dictionary_set_int64(value, "process_group_id",
        receipt->terminal.process_group_id);
    xpc_dictionary_set_uint64(value, "child_birth_us",
        receipt->terminal.child_birth_us);
    xpc_dictionary_set_uint64(value, "stdout_observed",
        receipt->terminal.stdout_size);
    xpc_dictionary_set_uint64(value, "stderr_observed",
        receipt->terminal.stderr_size);
    xpc_dictionary_set_data(value, "stdout_observed_sha256",
        receipt->terminal.stdout_sha256, 32);
    xpc_dictionary_set_data(value, "stderr_observed_sha256",
        receipt->terminal.stderr_sha256, 32);
    xpc_dictionary_set_data(value, "stdout_retained_sha256",
        receipt->stdout_retained_sha256, 32);
    xpc_dictionary_set_data(value, "stderr_retained_sha256",
        receipt->stderr_retained_sha256, 32);
    xpc_dictionary_set_data(value, "stdout_spool_checkpoint_sha256",
        receipt->stdout_spool_checkpoint_sha256, 32);
    xpc_dictionary_set_data(value, "stderr_spool_checkpoint_sha256",
        receipt->stderr_spool_checkpoint_sha256, 32);
    xpc_dictionary_set_bool(value, "child_reaped",
        receipt->terminal.child_reaped != 0);
    xpc_dictionary_set_bool(value, "process_group_extinct",
        receipt->terminal.process_group_extinct != 0);
    xpc_dictionary_set_data(value, "prepared_checkpoint_sha256",
        receipt->prepared_checkpoint_sha256, 32);
    xpc_dictionary_set_data(value, "terminal_checkpoint_sha256",
        receipt->terminal_checkpoint_sha256, 32);
    xpc_dictionary_set_data(value, KEY_STDOUT, receipt->stdout_retained,
        receipt->stdout_retained_size);
    xpc_dictionary_set_data(value, KEY_STDERR, receipt->stderr_retained,
        receipt->stderr_retained_size);
    xpc_dictionary_set_value(response, KEY_RECEIPT, value);
    xpc_release(value);
    return 0;
}

static int
parse_common(xpc_object_t message, uint8_t operation[32], uint8_t request[32],
    uint8_t prior[32], uint8_t claim[32])
{
    return data32(message, KEY_OPERATION_KEY, operation) == 0
        && data32(message, KEY_REQUEST, request) == 0
        && data32(message, KEY_PRIOR, prior) == 0
        && data32(message, KEY_CLAIM, claim) == 0 ? 0 : -1;
}

static int
handle_start(struct daemon_context *context, xpc_object_t message,
    xpc_object_t response)
{
    struct plamen_broker_v2_process_custodian_start_request request;
    struct plamen_broker_v2_process_custodian_start_receipt receipt;
    struct plamen_broker_v2_process_spec spec;
    struct plamen_broker_v2_process_fd_map
        descriptor_maps[PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX];
    xpc_object_t arguments, environment_values, descriptor_values;
    const char **argv = NULL, **environment = NULL;
    const char *path, *signing, *team;
    const void *executable_sha;
    xpc_object_t executable_sha_object;
    uint32_t timeout, stdout_limit, stderr_limit, wire_version;
    uint32_t environment_policy;
    size_t executable_sha_size = 0, argc, environment_count;
    size_t descriptor_count, index;
    int executable = -1, cwd = -1, input = -1, status;

    memset(&request, 0, sizeof(request));
    memset(&receipt, 0, sizeof(receipt));
    memset(&spec, 0, sizeof(spec));
    for (index = 0; index < PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX; ++index)
        descriptor_maps[index].source_fd = -1;
    path = xpc_dictionary_get_string(message, KEY_EXECUTABLE_PATH);
    signing = xpc_dictionary_get_string(message, KEY_SIGNING);
    team = xpc_dictionary_get_string(message, KEY_TEAM);
    executable_sha_object = xpc_dictionary_get_value(message,
        KEY_EXECUTABLE_SHA);
    executable_sha = executable_sha_object != NULL
        && xpc_get_type(executable_sha_object) == XPC_TYPE_DATA
        ? xpc_data_get_bytes_ptr(executable_sha_object) : NULL;
    executable_sha_size = executable_sha_object != NULL
        && xpc_get_type(executable_sha_object) == XPC_TYPE_DATA
        ? xpc_data_get_length(executable_sha_object) : 0;
    arguments = xpc_dictionary_get_value(message, KEY_ARGV);
    argc = arguments != NULL && xpc_get_type(arguments) == XPC_TYPE_ARRAY
        ? xpc_array_get_count(arguments) : 0;
    environment_values = xpc_dictionary_get_value(message, KEY_ENVIRONMENT);
    environment_count = environment_values != NULL
            && xpc_get_type(environment_values) == XPC_TYPE_ARRAY
        ? xpc_array_get_count(environment_values) : SIZE_MAX;
    descriptor_values = xpc_dictionary_get_value(message, KEY_FD_MAPS);
    descriptor_count = descriptor_values != NULL
            && xpc_get_type(descriptor_values) == XPC_TYPE_ARRAY
        ? xpc_array_get_count(descriptor_values) : SIZE_MAX;
    if (path == NULL || signing == NULL || team == NULL
        || executable_sha == NULL || executable_sha_size != 32 || argc == 0
        || argc > PLAMEN_BROKER_V2_PROCESS_ARGC_MAX
        || uint32_value(message, KEY_PROCESS_SPEC_VERSION,
            &wire_version) != 0
        || wire_version != PROCESS_SPEC_WIRE_VERSION
        || uint32_value(message, KEY_ENVIRONMENT_POLICY,
            &environment_policy) != 0
        || (environment_policy == PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED
            && environment_count != 0)
        || (environment_policy == PLAMEN_BROKER_V2_PROCESS_ENV_EXACT
            && (environment_count == 0
                || environment_count > PLAMEN_BROKER_V2_PROCESS_ENVC_MAX))
        || (environment_policy != PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED
            && environment_policy != PLAMEN_BROKER_V2_PROCESS_ENV_EXACT)
        || descriptor_count > PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX
        || uint32_value(message, KEY_TIMEOUT, &timeout) != 0
        || uint32_value(message, KEY_STDOUT_LIMIT, &stdout_limit) != 0
        || uint32_value(message, KEY_STDERR_LIMIT, &stderr_limit) != 0
        || xpc_get_type(xpc_dictionary_get_value(message, KEY_EXECUTABLE))
            != XPC_TYPE_FD
        || xpc_get_type(xpc_dictionary_get_value(message, KEY_CWD))
            != XPC_TYPE_FD
        || xpc_get_type(xpc_dictionary_get_value(message, KEY_STDIN))
            != XPC_TYPE_FD)
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    argv = calloc(argc + 1U, sizeof(*argv));
    environment = calloc(environment_count + 1U, sizeof(*environment));
    if (argv == NULL || environment == NULL) {
        free(environment);
        free(argv);
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
    }
    for (index = 0; index < argc; ++index) {
        xpc_object_t item = xpc_array_get_value(arguments, index);
        if (item == NULL || xpc_get_type(item) != XPC_TYPE_STRING
            || (argv[index] = xpc_string_get_string_ptr(item)) == NULL)
            goto invalid;
    }
    for (index = 0; index < environment_count; ++index) {
        xpc_object_t item = xpc_array_get_value(environment_values, index);
        if (item == NULL || xpc_get_type(item) != XPC_TYPE_STRING
            || (environment[index] = xpc_string_get_string_ptr(item)) == NULL)
            goto invalid;
    }
    for (index = 0; index < descriptor_count; ++index) {
        xpc_object_t item = xpc_array_get_value(descriptor_values, index);
        uint64_t target;
        size_t prior;
        if (!exact_fd_map_shape(item)
            || (target = xpc_dictionary_get_uint64(item, KEY_FD_TARGET)) < 3
            || target >= 1024)
            goto invalid;
        descriptor_maps[index].source_fd = xpc_fd_dup(
            xpc_dictionary_get_value(item, KEY_FD_SOURCE));
        descriptor_maps[index].target_fd = (int)target;
        if (descriptor_maps[index].source_fd < 0
            || fcntl(descriptor_maps[index].source_fd, F_SETFD,
                FD_CLOEXEC) != 0)
            goto invalid;
        for (prior = 0; prior < index; ++prior)
            if (descriptor_maps[index].target_fd
                    == descriptor_maps[prior].target_fd
                || descriptor_maps[index].source_fd
                    == descriptor_maps[prior].source_fd)
                goto invalid;
    }
    executable = xpc_dictionary_dup_fd(message, KEY_EXECUTABLE);
    cwd = xpc_dictionary_dup_fd(message, KEY_CWD);
    input = xpc_dictionary_dup_fd(message, KEY_STDIN);
    if (executable < 0 || cwd < 0 || input < 0)
        goto invalid;
    request.version = 1;
    if (parse_common(message, request.operation_key, request.request_sha256,
            request.prior_checkpoint_sha256, request.claim_owner_sha256) != 0)
        goto invalid;
    spec.version = 1; spec.executable_fd = executable;
    spec.executable_path = path; spec.argv = argv; spec.argc = argc;
    spec.environment_policy = environment_policy;
    spec.environment = environment_count == 0 ? NULL : environment;
    spec.environment_count = environment_count;
    spec.cwd_fd = cwd; spec.stdin_fd = input;
    spec.fd_maps = descriptor_count == 0 ? NULL : descriptor_maps;
    spec.fd_map_count = descriptor_count;
    spec.timeout_seconds = timeout;
    spec.stdout_spool_limit = stdout_limit;
    spec.stderr_spool_limit = stderr_limit;
    spec.expected_executable_sha256 = executable_sha;
    spec.expected_signing_identifier = signing;
    spec.expected_team_identifier = team;
    request.process_spec = &spec;
    status = plamen_broker_v2_process_custodian_start(context->custodian,
        &request, &receipt);
    if (status == PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK
        || status == PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED) {
        if (set_start_receipt(response, &receipt) != 0)
            status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
    }
    close(executable); close(cwd); close(input);
    for (index = 0; index < descriptor_count; ++index)
        close(descriptor_maps[index].source_fd);
    free(environment); free(argv);
    return status;
invalid:
    if (executable >= 0) close(executable);
    if (cwd >= 0) close(cwd);
    if (input >= 0) close(input);
    for (index = 0; index < PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX; ++index)
        if (descriptor_maps[index].source_fd >= 0)
            close(descriptor_maps[index].source_fd);
    free(environment); free(argv);
    return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
}

static int
handle_adopt(struct daemon_context *context, xpc_object_t message,
    xpc_object_t response)
{
    struct plamen_broker_v2_process_custodian_start_recovery_request request;
    struct plamen_broker_v2_process_custodian_start_receipt receipt;
    int status;
    memset(&request, 0, sizeof(request)); request.version = 1;
    if (parse_common(message, request.operation_key, request.request_sha256,
            request.prior_checkpoint_sha256, request.claim_owner_sha256) != 0)
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    status = plamen_broker_v2_process_custodian_adopt_start(context->custodian,
        &request, &receipt);
    if (status == PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED
        && set_start_receipt(response, &receipt) != 0)
        status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
    return status;
}

static int
handle_terminal(struct daemon_context *context, xpc_object_t message,
    xpc_object_t response, const char *operation)
{
    struct plamen_broker_v2_process_custodian_terminal_request request;
    struct plamen_broker_v2_process_custodian_terminal_receipt receipt;
    int status;
    memset(&request, 0, sizeof(request)); request.version = 1;
    if (data32(message, KEY_START_OPERATION, request.start_operation_key) != 0
        || parse_common(message, request.operation_key, request.request_sha256,
            request.prior_checkpoint_sha256, request.claim_owner_sha256) != 0)
        return PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    if (strcmp(operation, OP_WAIT) == 0)
        status = plamen_broker_v2_process_custodian_wait(context->custodian,
            &request, &receipt);
    else if (strcmp(operation, OP_REVOKE) == 0)
        status = plamen_broker_v2_process_custodian_revoke(context->custodian,
            &request, &receipt);
    else
        status = plamen_broker_v2_process_custodian_recover_terminal(
            context->custodian, &request, &receipt);
    if (status == PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK
        || status == PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED) {
        if (set_terminal_receipt(response, &receipt) != 0)
            status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_RESTART_AMBIGUOUS;
    }
    plamen_broker_v2_process_custodian_terminal_dispose(&receipt);
    return status;
}

static void
execute_message(struct daemon_context *context, const char *operation,
    xpc_object_t message, xpc_object_t response)
{
    int status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT;
    if (strcmp(operation, OP_STATUS) == 0) {
        xpc_object_t value = xpc_dictionary_create(NULL, NULL, 0);
        if (value == NULL) {
            status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR;
        } else {
            xpc_dictionary_set_data(value, "installation_receipt_sha256",
                context->readiness.installation_receipt_sha256, 32);
            xpc_dictionary_set_data(value, "generation_id_sha256",
                context->readiness.generation_id_sha256, 32);
            xpc_dictionary_set_data(value, "service_sha256",
                context->readiness.service_sha256, 32);
            xpc_dictionary_set_value(response, KEY_RECEIPT, value);
            xpc_release(value);
            status = PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK;
        }
    } else if (strcmp(operation, OP_START) == 0)
        status = handle_start(context, message, response);
    else if (strcmp(operation, OP_ADOPT) == 0)
        status = handle_adopt(context, message, response);
    else if (strcmp(operation, OP_WAIT) == 0
        || strcmp(operation, OP_RECOVER) == 0
        || strcmp(operation, OP_REVOKE) == 0)
        status = handle_terminal(context, message, response, operation);
    xpc_dictionary_set_uint64(response, KEY_STATUS, (uint64_t)(uint32_t)status);
}

static void
handle_message(struct daemon_context *context, xpc_connection_t peer,
    xpc_object_t message)
{
    const char *operation;
    xpc_object_t response;
    if (xpc_get_type(message) != XPC_TYPE_DICTIONARY)
        return;
    if (context->admit(peer) != 0
        || (operation = xpc_dictionary_get_string(message, KEY_OPERATION)) == NULL
        || !exact_shape(message, operation)) {
        xpc_connection_cancel(peer);
        return;
    }
    response = new_reply(message, PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_CONFLICT);
    if (response == NULL)
        return;
    execute_message(context, operation, message, response);
    xpc_connection_send_message(peer, response);
    xpc_release(response);
}

void
plamen_broker_v2_process_custody_daemon_run(
    struct plamen_broker_v2_process_custodian *custodian,
    const struct plamen_broker_v2_custody_daemon_readiness *readiness,
    const char *peer_code_requirement,
    plamen_broker_v2_custody_daemon_peer_admit admit)
{
    xpc_connection_t listener;
    struct daemon_context *context;
    if (custodian == NULL || readiness == NULL || peer_code_requirement == NULL
        || admit == NULL)
        exit(78);
    context = calloc(1, sizeof(*context));
    if (context == NULL)
        exit(78);
    context->custodian = custodian; context->admit = admit;
    memcpy(&context->readiness, readiness, sizeof(*readiness));
    context->work_queue = dispatch_queue_create(
        "com.plamen.audit.process-custody.v2.requests",
        DISPATCH_QUEUE_CONCURRENT);
    if (context->work_queue == NULL)
        exit(78);
    listener = xpc_connection_create_mach_service(
        PLAMEN_BROKER_V2_CUSTODY_DAEMON_SERVICE_NAME,
        dispatch_get_main_queue(), XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (listener == NULL
        || xpc_connection_set_peer_code_signing_requirement(listener,
            peer_code_requirement) != 0)
        exit(78);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION)
            return;
        xpc_connection_t peer = (xpc_connection_t)event;
        xpc_connection_set_target_queue(peer, context->work_queue);
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            handle_message(context, peer, message);
        });
        xpc_connection_activate(peer);
    });
    xpc_connection_activate(listener);
    dispatch_main();
}

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
int
plamen_broker_v2_process_custody_daemon_TEST_ONLY_dispatch(
    struct plamen_broker_v2_process_custodian *custodian,
    xpc_object_t request, xpc_object_t *response)
{
    struct plamen_broker_v2_custody_daemon_readiness readiness;
    memset(&readiness, 0, sizeof(readiness));
    return plamen_broker_v2_process_custody_daemon_TEST_ONLY_dispatch_readiness(
        custodian, &readiness, request, response);
}

int
plamen_broker_v2_process_custody_daemon_TEST_ONLY_dispatch_readiness(
    struct plamen_broker_v2_process_custodian *custodian,
    const struct plamen_broker_v2_custody_daemon_readiness *readiness,
    xpc_object_t request, xpc_object_t *response)
{
    struct daemon_context context;
    const char *operation;
    if (response != NULL)
        *response = NULL;
    if (custodian == NULL || request == NULL || response == NULL
        || readiness == NULL || xpc_get_type(request) != XPC_TYPE_DICTIONARY
        || (operation = xpc_dictionary_get_string(request, KEY_OPERATION)) == NULL
        || !exact_shape(request, operation))
        return -1;
    *response = xpc_dictionary_create(NULL, NULL, 0);
    if (*response == NULL)
        return -1;
    {
        uint8_t session[32];
        if (data32(request, KEY_BROKER_SESSION, session) != 0) {
            xpc_release(*response); *response = NULL; return -1;
        }
        xpc_dictionary_set_data(*response, KEY_BROKER_SESSION, session, 32);
    }
    memset(&context, 0, sizeof(context)); context.custodian = custodian;
    memcpy(&context.readiness, readiness, sizeof(*readiness));
    execute_message(&context, operation, request, *response);
    return 0;
}
#endif
