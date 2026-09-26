#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_process_custody_client.h"
#include "plamen_broker_v2_process_custody_daemon.h"

#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define K_OPERATION "operation"
#define K_SESSION "broker_session_id"
#define K_START_OPERATION "start_operation"
#define K_OPERATION_KEY "operation_key"
#define K_REQUEST "request_sha256"
#define K_PRIOR "prior_checkpoint_sha256"
#define K_CLAIM "claim_owner_sha256"
#define K_RECEIPT "receipt"
#define K_STATUS "status"
#define K_INSTALLATION_RECEIPT "installation_receipt_sha256"
#define K_GENERATION_ID "generation_id_sha256"
#define K_SERVICE_SHA "service_sha256"
#define K_PROCESS_SPEC_VERSION "process_spec_version"
#define K_ENVIRONMENT_POLICY "environment_policy"
#define K_ENVIRONMENT "environment"
#define K_FD_MAPS "fd_maps"
#define K_FD_SOURCE "source"
#define K_FD_TARGET "target"

#define PROCESS_SPEC_WIRE_VERSION 2U

struct plamen_broker_v2_process_custody_client {
    pthread_mutex_t lock;
    xpc_connection_t connection;
    char *requirement;
    plamen_broker_v2_custody_client_peer_admit admit;
    uint8_t session_id[32];
#ifdef PLAMEN_BROKER_V2_TEST_ONLY
    xpc_endpoint_t endpoint;
#endif
};

static int constant_equal(const void *left, const void *right, size_t size)
{
    const uint8_t *a = left, *b = right; uint8_t difference = 0; size_t index;
    for (index = 0; index < size; ++index) difference |= a[index] ^ b[index];
    return difference == 0;
}

static int data_exact(xpc_object_t dictionary, const char *key, void *output,
    size_t expected)
{
    xpc_object_t value = xpc_dictionary_get_value(dictionary, key);
    const void *bytes;
    if (value == NULL || xpc_get_type(value) != XPC_TYPE_DATA
        || xpc_data_get_length(value) != expected
        || (bytes = xpc_data_get_bytes_ptr(value)) == NULL)
        return -1;
    if (expected != 0) memcpy(output, bytes, expected);
    return 0;
}

static int int64_exact(xpc_object_t dictionary, const char *key,
    int64_t *output)
{
    xpc_object_t value = xpc_dictionary_get_value(dictionary, key);
    if (value == NULL || xpc_get_type(value) != XPC_TYPE_INT64) return -1;
    *output = xpc_int64_get_value(value); return 0;
}

static int uint64_exact(xpc_object_t dictionary, const char *key,
    uint64_t *output)
{
    xpc_object_t value = xpc_dictionary_get_value(dictionary, key);
    if (value == NULL || xpc_get_type(value) != XPC_TYPE_UINT64) return -1;
    *output = xpc_uint64_get_value(value); return 0;
}

static int bool_exact(xpc_object_t dictionary, const char *key, int *output)
{
    xpc_object_t value = xpc_dictionary_get_value(dictionary, key);
    if (value == NULL || xpc_get_type(value) != XPC_TYPE_BOOL) return -1;
    *output = xpc_bool_get_value(value) ? 1 : 0; return 0;
}

static int data_view(xpc_object_t dictionary, const char *key,
    const void **bytes, size_t *size)
{
    xpc_object_t value = xpc_dictionary_get_value(dictionary, key);
    if (value == NULL || xpc_get_type(value) != XPC_TYPE_DATA) return -1;
    *size = xpc_data_get_length(value);
    *bytes = xpc_data_get_bytes_ptr(value);
    return *size != 0 && *bytes == NULL ? -1 : 0;
}

static int exact_keys(xpc_object_t dictionary, const char *const *keys,
    size_t expected)
{
    __block size_t count = 0; __block int valid = 1;
    if (dictionary == NULL || xpc_get_type(dictionary) != XPC_TYPE_DICTIONARY)
        return 0;
    xpc_dictionary_apply(dictionary, ^bool(const char *key, xpc_object_t value) {
        size_t index; (void)value; ++count;
        for (index = 0; index < expected; ++index)
            if (strcmp(key, keys[index]) == 0) return true;
        valid = 0; return false;
    });
    return valid && count == expected;
}

static void disconnect_locked(
    struct plamen_broker_v2_process_custody_client *client)
{
    if (client->connection != NULL) {
        xpc_connection_cancel(client->connection);
        xpc_release(client->connection); client->connection = NULL;
    }
    memset(client->session_id, 0, sizeof(client->session_id));
}

static void reject_connection(
    struct plamen_broker_v2_process_custody_client *client)
{
    pthread_mutex_lock(&client->lock);
    disconnect_locked(client);
    pthread_mutex_unlock(&client->lock);
}

static int connect_locked(
    struct plamen_broker_v2_process_custody_client *client)
{
    if (client->connection != NULL) return 0;
#ifdef PLAMEN_BROKER_V2_TEST_ONLY
    if (client->endpoint != NULL)
        client->connection = xpc_connection_create_from_endpoint(client->endpoint);
    else
#endif
        client->connection = xpc_connection_create_mach_service(
            PLAMEN_BROKER_V2_CUSTODY_DAEMON_SERVICE_NAME, NULL, 0);
    if (client->connection == NULL
        || (client->requirement != NULL
            && xpc_connection_set_peer_code_signing_requirement(
                client->connection, client->requirement) != 0)) {
        disconnect_locked(client); return -1;
    }
    xpc_connection_set_event_handler(client->connection,
        ^(xpc_object_t event) { (void)event; });
    xpc_connection_activate(client->connection);
    if (getentropy(client->session_id, sizeof(client->session_id)) != 0) {
        disconnect_locked(client); return -1;
    }
    return 0;
}

static int transact(struct plamen_broker_v2_process_custody_client *client,
    xpc_object_t request, xpc_object_t *response, uint32_t *daemon_status)
{
    static const char *const failure_keys[] = {K_SESSION, K_STATUS};
    uint8_t echoed[32]; uint64_t status;
    *response = NULL; *daemon_status = UINT32_MAX;
    pthread_mutex_lock(&client->lock);
    if (connect_locked(client) != 0) {
        pthread_mutex_unlock(&client->lock);
        return PLAMEN_BROKER_V2_CUSTODY_CLIENT_TRANSPORT_AMBIGUOUS;
    }
    xpc_dictionary_set_data(request, K_SESSION, client->session_id, 32);
    *response = xpc_connection_send_message_with_reply_sync(
        client->connection, request);
    if (*response == NULL || xpc_get_type(*response) == XPC_TYPE_ERROR) {
        if (*response != NULL) { xpc_release(*response); *response = NULL; }
        disconnect_locked(client); pthread_mutex_unlock(&client->lock);
        return PLAMEN_BROKER_V2_CUSTODY_CLIENT_TRANSPORT_AMBIGUOUS;
    }
    if (client->admit != NULL && client->admit(client->connection) != 0) {
        xpc_release(*response); *response = NULL; disconnect_locked(client);
        pthread_mutex_unlock(&client->lock);
        return PLAMEN_BROKER_V2_CUSTODY_CLIENT_PEER_REJECTED;
    }
    if (data_exact(*response, K_SESSION, echoed, 32) != 0
        || !constant_equal(echoed, client->session_id, 32)
        || xpc_get_type(xpc_dictionary_get_value(*response, K_STATUS))
            != XPC_TYPE_UINT64
        || (status = xpc_dictionary_get_uint64(*response, K_STATUS))
            > PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_INTERNAL_ERROR) {
        xpc_release(*response); *response = NULL; disconnect_locked(client);
        pthread_mutex_unlock(&client->lock);
        return PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
    }
    *daemon_status = (uint32_t)status;
    if (status != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK
        && status != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_REPLAYED
        && !exact_keys(*response, failure_keys, 2)) {
        xpc_release(*response); *response = NULL; disconnect_locked(client);
        pthread_mutex_unlock(&client->lock);
        return PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
    }
    pthread_mutex_unlock(&client->lock);
    return PLAMEN_BROKER_V2_CUSTODY_CLIENT_OK;
}

static xpc_object_t common_request(const char *operation,
    const uint8_t operation_key[32], const uint8_t request_sha256[32],
    const uint8_t prior[32], const uint8_t claim[32])
{
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    if (message == NULL) return NULL;
    xpc_dictionary_set_string(message, K_OPERATION, operation);
    xpc_dictionary_set_data(message, K_OPERATION_KEY, operation_key, 32);
    xpc_dictionary_set_data(message, K_REQUEST, request_sha256, 32);
    xpc_dictionary_set_data(message, K_PRIOR, prior, 32);
    xpc_dictionary_set_data(message, K_CLAIM, claim, 32);
    return message;
}

static int parse_start_receipt(xpc_object_t response, uint32_t status,
    struct plamen_broker_v2_process_custodian_start_receipt *receipt)
{
    static const char *const response_keys[] = {K_SESSION, K_STATUS, K_RECEIPT};
    static const char *const keys[] = {
        K_OPERATION_KEY, K_REQUEST, K_PRIOR, K_CLAIM, "process_spec_sha256",
        "prepared_checkpoint_sha256", "started_checkpoint_sha256", "child_pid",
        "process_group_id", "child_birth_us", "executable_device",
        "executable_inode", "executable_sha256", "executable_identity_sha256",
        "native_process_handle_sha256", "cdhash", "signing_identifier",
        "team_identifier"
    };
    xpc_object_t value; const char *signing, *team; size_t cdhash_size = 0;
    int64_t child_pid, process_group_id;
    uint64_t child_birth_us, executable_device, executable_inode;
    const void *cdhash;
    if (!exact_keys(response, response_keys, 3)
        || (value = xpc_dictionary_get_value(response, K_RECEIPT)) == NULL
        || !exact_keys(value, keys, sizeof(keys) / sizeof(keys[0]))
        || data_exact(value, K_OPERATION_KEY, receipt->operation_key, 32) != 0
        || data_exact(value, K_REQUEST, receipt->request_sha256, 32) != 0
        || data_exact(value, K_PRIOR, receipt->prior_checkpoint_sha256, 32) != 0
        || data_exact(value, K_CLAIM, receipt->claim_owner_sha256, 32) != 0
        || data_exact(value, "process_spec_sha256", receipt->process_spec_sha256, 32) != 0
        || data_exact(value, "prepared_checkpoint_sha256", receipt->prepared_checkpoint_sha256, 32) != 0
        || data_exact(value, "started_checkpoint_sha256", receipt->started_checkpoint_sha256, 32) != 0
        || int64_exact(value, "child_pid", &child_pid) != 0
        || int64_exact(value, "process_group_id", &process_group_id) != 0
        || uint64_exact(value, "child_birth_us", &child_birth_us) != 0
        || uint64_exact(value, "executable_device", &executable_device) != 0
        || uint64_exact(value, "executable_inode", &executable_inode) != 0)
        return -1;
    receipt->identity.version = 1;
    if (child_pid <= 0 || child_pid > INT32_MAX
        || process_group_id != child_pid || child_birth_us == 0)
        return -1;
    receipt->identity.child_pid = (int32_t)child_pid;
    receipt->identity.process_group_id = (int32_t)process_group_id;
    receipt->identity.child_birth_us = child_birth_us;
    receipt->identity.executable_device = executable_device;
    receipt->identity.executable_inode = executable_inode;
    if (receipt->identity.child_pid <= 0
        || receipt->identity.process_group_id != receipt->identity.child_pid
        || receipt->identity.child_birth_us == 0
        || data_exact(value, "executable_sha256", receipt->identity.executable_sha256, 32) != 0
        || data_exact(value, "executable_identity_sha256", receipt->identity.executable_identity_sha256, 32) != 0
        || data_exact(value, "native_process_handle_sha256", receipt->identity.native_process_handle_sha256, 32) != 0)
        return -1;
    cdhash = xpc_dictionary_get_data(value, "cdhash", &cdhash_size);
    signing = xpc_dictionary_get_string(value, "signing_identifier");
    team = xpc_dictionary_get_string(value, "team_identifier");
    if (cdhash == NULL || !(cdhash_size == 20 || cdhash_size == 32)
        || signing == NULL || team == NULL
        || strlen(signing) >= sizeof(receipt->identity.signing_identifier)
        || strlen(team) >= sizeof(receipt->identity.team_identifier)) return -1;
    memcpy(receipt->identity.cdhash, cdhash, cdhash_size);
    receipt->identity.cdhash_size = (uint32_t)cdhash_size;
    strcpy(receipt->identity.signing_identifier, signing);
    strcpy(receipt->identity.team_identifier, team);
    receipt->version = 1; receipt->status = status; return 0;
}

static int start_like(struct plamen_broker_v2_process_custody_client *client,
    xpc_object_t request,
    struct plamen_broker_v2_process_custodian_start_receipt *receipt,
    uint32_t *daemon_status)
{
    xpc_object_t response = NULL; int result;
    memset(receipt, 0, sizeof(*receipt));
    result = transact(client, request, &response, daemon_status);
    if (result == 0 && (*daemon_status == 0 || *daemon_status == 1)
        && parse_start_receipt(response, *daemon_status, receipt) != 0) {
        reject_connection(client);
        result = PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
    }
    if (response != NULL) xpc_release(response);
    return result;
}

int plamen_broker_v2_process_custody_client_readiness(
    struct plamen_broker_v2_process_custody_client *client,
    const struct plamen_broker_v2_custody_daemon_readiness *expected,
    uint32_t *daemon_status)
{
    static const char *const response_keys[] = {
        K_SESSION, K_STATUS, K_RECEIPT
    };
    static const char *const receipt_keys[] = {
        K_INSTALLATION_RECEIPT, K_GENERATION_ID, K_SERVICE_SHA
    };
    struct plamen_broker_v2_custody_daemon_readiness observed;
    xpc_object_t request = NULL, response = NULL, receipt;
    int result;
    memset(&observed, 0, sizeof(observed));
    if (client == NULL || expected == NULL || daemon_status == NULL)
        return PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
    request = xpc_dictionary_create(NULL, NULL, 0);
    if (request == NULL)
        return PLAMEN_BROKER_V2_CUSTODY_CLIENT_INTERNAL_ERROR;
    xpc_dictionary_set_string(request, K_OPERATION, "status");
    result = transact(client, request, &response, daemon_status);
    if (result == PLAMEN_BROKER_V2_CUSTODY_CLIENT_OK
        && (*daemon_status != PLAMEN_BROKER_V2_PROCESS_CUSTODIAN_OK
            || !exact_keys(response, response_keys, 3)
            || (receipt = xpc_dictionary_get_value(response, K_RECEIPT)) == NULL
            || !exact_keys(receipt, receipt_keys, 3)
            || data_exact(receipt, K_INSTALLATION_RECEIPT,
                observed.installation_receipt_sha256, 32) != 0
            || data_exact(receipt, K_GENERATION_ID,
                observed.generation_id_sha256, 32) != 0
            || data_exact(receipt, K_SERVICE_SHA,
                observed.service_sha256, 32) != 0
            || !constant_equal(&observed, expected, sizeof(observed)))) {
        reject_connection(client);
        result = PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
    }
    if (response != NULL)
        xpc_release(response);
    xpc_release(request);
    memset(&observed, 0, sizeof(observed));
    return result;
}

int plamen_broker_v2_process_custody_client_start(
    struct plamen_broker_v2_process_custody_client *client,
    const struct plamen_broker_v2_process_custodian_start_request *input,
    struct plamen_broker_v2_process_custodian_start_receipt *receipt,
    uint32_t *daemon_status)
{
    const struct plamen_broker_v2_process_spec *spec;
    xpc_object_t request, argv, environment, fd_maps;
    size_t index;
    int result;
    if (client == NULL || input == NULL || input->version != 1
        || (spec = input->process_spec) == NULL || spec->version != 1
        || receipt == NULL || daemon_status == NULL || spec->argv == NULL
        || spec->argc == 0 || spec->argc > PLAMEN_BROKER_V2_PROCESS_ARGC_MAX
        || spec->argv[spec->argc] != NULL
        || spec->executable_fd < 0 || spec->cwd_fd < 0 || spec->stdin_fd < 0
        || spec->fd_map_count > PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX
        || (spec->fd_map_count != 0 && spec->fd_maps == NULL)
        || spec->executable_path == NULL || spec->expected_executable_sha256 == NULL
        || spec->expected_signing_identifier == NULL
        || spec->expected_team_identifier == NULL)
        return PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
    if (spec->environment_policy == PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED) {
        if (spec->environment != NULL || spec->environment_count != 0)
            return PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
    } else if (spec->environment_policy
            == PLAMEN_BROKER_V2_PROCESS_ENV_EXACT) {
        if (spec->environment == NULL || spec->environment_count == 0
            || spec->environment_count > PLAMEN_BROKER_V2_PROCESS_ENVC_MAX
            || spec->environment[spec->environment_count] != NULL)
            return PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
    } else {
        return PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
    }
    request = common_request("start", input->operation_key,
        input->request_sha256, input->prior_checkpoint_sha256,
        input->claim_owner_sha256);
    argv = xpc_array_create(NULL, 0);
    environment = xpc_array_create(NULL, 0);
    fd_maps = xpc_array_create(NULL, 0);
    if (request == NULL || argv == NULL || environment == NULL
        || fd_maps == NULL) {
        if (request != NULL) xpc_release(request);
        if (argv != NULL) xpc_release(argv);
        if (environment != NULL) xpc_release(environment);
        if (fd_maps != NULL) xpc_release(fd_maps);
        return PLAMEN_BROKER_V2_CUSTODY_CLIENT_INTERNAL_ERROR;
    }
    for (index = 0; index < spec->argc; ++index) {
        if (spec->argv[index] == NULL) goto protocol_rejected;
        xpc_array_set_string(argv, XPC_ARRAY_APPEND, spec->argv[index]);
    }
    for (index = 0; index < spec->environment_count; ++index) {
        if (spec->environment[index] == NULL) goto protocol_rejected;
        xpc_array_set_string(environment, XPC_ARRAY_APPEND,
            spec->environment[index]);
    }
    for (index = 0; index < spec->fd_map_count; ++index) {
        xpc_object_t item = NULL, source = NULL;
        size_t prior;
        if (spec->fd_maps[index].source_fd < 0
            || spec->fd_maps[index].target_fd < 3
            || spec->fd_maps[index].target_fd >= 1024)
            goto protocol_rejected;
        for (prior = 0; prior < index; ++prior)
            if (spec->fd_maps[index].target_fd
                    == spec->fd_maps[prior].target_fd
                || spec->fd_maps[index].source_fd
                    == spec->fd_maps[prior].source_fd)
                goto protocol_rejected;
        item = xpc_dictionary_create(NULL, NULL, 0);
        source = xpc_fd_create(spec->fd_maps[index].source_fd);
        if (item == NULL || source == NULL) {
            if (item != NULL) xpc_release(item);
            if (source != NULL) xpc_release(source);
            xpc_release(fd_maps); xpc_release(environment);
            xpc_release(argv); xpc_release(request);
            return PLAMEN_BROKER_V2_CUSTODY_CLIENT_INTERNAL_ERROR;
        }
        xpc_dictionary_set_value(item, K_FD_SOURCE, source);
        xpc_dictionary_set_uint64(item, K_FD_TARGET,
            (uint64_t)spec->fd_maps[index].target_fd);
        xpc_array_set_value(fd_maps, XPC_ARRAY_APPEND, item);
        xpc_release(source); xpc_release(item);
    }
    xpc_dictionary_set_fd(request, "executable", spec->executable_fd);
    xpc_dictionary_set_fd(request, "cwd", spec->cwd_fd);
    xpc_dictionary_set_fd(request, "stdin", spec->stdin_fd);
    xpc_dictionary_set_string(request, "executable_path", spec->executable_path);
    xpc_dictionary_set_value(request, "argv", argv); xpc_release(argv);
    xpc_dictionary_set_uint64(request, "timeout_seconds", spec->timeout_seconds);
    xpc_dictionary_set_uint64(request, "stdout_limit", spec->stdout_spool_limit);
    xpc_dictionary_set_uint64(request, "stderr_limit", spec->stderr_spool_limit);
    xpc_dictionary_set_data(request, "executable_sha256", spec->expected_executable_sha256, 32);
    xpc_dictionary_set_string(request, "signing_identifier", spec->expected_signing_identifier);
    xpc_dictionary_set_string(request, "team_identifier", spec->expected_team_identifier);
    xpc_dictionary_set_uint64(request, K_PROCESS_SPEC_VERSION,
        PROCESS_SPEC_WIRE_VERSION);
    xpc_dictionary_set_uint64(request, K_ENVIRONMENT_POLICY,
        spec->environment_policy);
    xpc_dictionary_set_value(request, K_ENVIRONMENT, environment);
    xpc_dictionary_set_value(request, K_FD_MAPS, fd_maps);
    xpc_release(fd_maps); xpc_release(environment);
    result = start_like(client, request, receipt, daemon_status);
    xpc_release(request); return result;
protocol_rejected:
    xpc_release(fd_maps); xpc_release(environment);
    xpc_release(argv); xpc_release(request);
    return PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
}

int plamen_broker_v2_process_custody_client_adopt(
    struct plamen_broker_v2_process_custody_client *client,
    const struct plamen_broker_v2_process_custodian_start_recovery_request *input,
    struct plamen_broker_v2_process_custodian_start_receipt *receipt,
    uint32_t *daemon_status)
{
    xpc_object_t request; int result;
    if (client == NULL || input == NULL || input->version != 1
        || receipt == NULL || daemon_status == NULL) return 2;
    request = common_request("adopt", input->operation_key,
        input->request_sha256, input->prior_checkpoint_sha256,
        input->claim_owner_sha256);
    if (request == NULL) return 4;
    result = start_like(client, request, receipt, daemon_status);
    xpc_release(request); return result;
}

static int parse_terminal_receipt(xpc_object_t response, uint32_t status,
    struct plamen_broker_v2_process_custodian_terminal_receipt *receipt)
{
    static const char *const response_keys[] = {K_SESSION, K_STATUS, K_RECEIPT};
    static const char *const keys[] = {
        K_START_OPERATION, K_OPERATION_KEY, K_REQUEST, K_PRIOR, K_CLAIM,
        "process_spec_sha256", "native_process_handle_sha256", "terminal_status",
        "exit_code", "signal_number", "child_pid", "process_group_id",
        "child_birth_us", "stdout_observed", "stderr_observed",
        "stdout_observed_sha256", "stderr_observed_sha256", "child_reaped",
        "stdout_retained_sha256", "stderr_retained_sha256",
        "stdout_spool_checkpoint_sha256", "stderr_spool_checkpoint_sha256",
        "process_group_extinct", "prepared_checkpoint_sha256",
        "terminal_checkpoint_sha256", "stdout", "stderr"
    };
    xpc_object_t value; const void *bytes; size_t size;
    int64_t exit_code, signal_number, child_pid, process_group_id;
    uint64_t terminal_status, child_birth_us, stdout_observed, stderr_observed;
    int child_reaped, process_group_extinct;
    if (!exact_keys(response, response_keys, 3)
        || (value = xpc_dictionary_get_value(response, K_RECEIPT)) == NULL
        || !exact_keys(value, keys, sizeof(keys) / sizeof(keys[0]))
        || data_exact(value, K_START_OPERATION, receipt->start_operation_key, 32) != 0
        || data_exact(value, K_OPERATION_KEY, receipt->operation_key, 32) != 0
        || data_exact(value, K_REQUEST, receipt->request_sha256, 32) != 0
        || data_exact(value, K_PRIOR, receipt->prior_checkpoint_sha256, 32) != 0
        || data_exact(value, K_CLAIM, receipt->claim_owner_sha256, 32) != 0
        || data_exact(value, "process_spec_sha256", receipt->process_spec_sha256, 32) != 0
        || data_exact(value, "native_process_handle_sha256", receipt->native_process_handle_sha256, 32) != 0
        || data_exact(value, "stdout_observed_sha256", receipt->terminal.stdout_sha256, 32) != 0
        || data_exact(value, "stderr_observed_sha256", receipt->terminal.stderr_sha256, 32) != 0
        || data_exact(value, "stdout_retained_sha256", receipt->stdout_retained_sha256, 32) != 0
        || data_exact(value, "stderr_retained_sha256", receipt->stderr_retained_sha256, 32) != 0
        || data_exact(value, "stdout_spool_checkpoint_sha256", receipt->stdout_spool_checkpoint_sha256, 32) != 0
        || data_exact(value, "stderr_spool_checkpoint_sha256", receipt->stderr_spool_checkpoint_sha256, 32) != 0
        || data_exact(value, "prepared_checkpoint_sha256", receipt->prepared_checkpoint_sha256, 32) != 0
        || data_exact(value, "terminal_checkpoint_sha256", receipt->terminal_checkpoint_sha256, 32) != 0
        || uint64_exact(value, "terminal_status", &terminal_status) != 0
        || int64_exact(value, "exit_code", &exit_code) != 0
        || int64_exact(value, "signal_number", &signal_number) != 0
        || int64_exact(value, "child_pid", &child_pid) != 0
        || int64_exact(value, "process_group_id", &process_group_id) != 0
        || uint64_exact(value, "child_birth_us", &child_birth_us) != 0
        || uint64_exact(value, "stdout_observed", &stdout_observed) != 0
        || uint64_exact(value, "stderr_observed", &stderr_observed) != 0
        || bool_exact(value, "child_reaped", &child_reaped) != 0
        || bool_exact(value, "process_group_extinct", &process_group_extinct) != 0)
        return -1;
    receipt->terminal.version = 1;
    if (terminal_status > PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR
        || exit_code < INT32_MIN || exit_code > INT32_MAX
        || signal_number < INT32_MIN || signal_number > INT32_MAX
        || child_pid <= 0 || child_pid > INT32_MAX
        || process_group_id != child_pid || child_birth_us == 0
        || stdout_observed > PLAMEN_BROKER_V2_OBSERVED_MAX
        || stderr_observed > PLAMEN_BROKER_V2_OBSERVED_MAX
        || child_reaped != 1 || process_group_extinct != 1) return -1;
    receipt->terminal.status = (uint32_t)terminal_status;
    receipt->terminal.exit_code = (int32_t)exit_code;
    receipt->terminal.signal_number = (int32_t)signal_number;
    receipt->terminal.child_pid = (int32_t)child_pid;
    receipt->terminal.process_group_id = (int32_t)process_group_id;
    receipt->terminal.child_birth_us = child_birth_us;
    receipt->terminal.stdout_size = stdout_observed;
    receipt->terminal.stderr_size = stderr_observed;
    receipt->terminal.child_reaped = child_reaped;
    receipt->terminal.process_group_extinct = process_group_extinct;
    if (data_view(value, "stdout", &bytes, &size) != 0
        || size > PLAMEN_BROKER_V2_RETAIN_MAX || size > stdout_observed)
        return -1;
    receipt->stdout_retained_size = (uint32_t)size;
    if (size != 0 && (receipt->stdout_retained = malloc(size)) == NULL) return -1;
    if (size != 0) memcpy(receipt->stdout_retained, bytes, size);
    if (data_view(value, "stderr", &bytes, &size) != 0
        || size > PLAMEN_BROKER_V2_RETAIN_MAX || size > stderr_observed)
        goto fail;
    receipt->stderr_retained_size = (uint32_t)size;
    if (size != 0 && (receipt->stderr_retained = malloc(size)) == NULL) goto fail;
    if (size != 0) memcpy(receipt->stderr_retained, bytes, size);
    {
        uint8_t digest[32];
        if (plamen_broker_v2_sha256(receipt->stdout_retained,
                receipt->stdout_retained_size, digest) != 0
            || !constant_equal(digest, receipt->stdout_retained_sha256, 32)
            || plamen_broker_v2_sha256(receipt->stderr_retained,
                receipt->stderr_retained_size, digest) != 0
            || !constant_equal(digest, receipt->stderr_retained_sha256, 32))
            goto fail;
    }
    receipt->version = 1; receipt->status = status; return 0;
fail:
    plamen_broker_v2_process_custodian_terminal_dispose(receipt); return -1;
}

static int terminal_like(struct plamen_broker_v2_process_custody_client *client,
    const char *operation,
    const struct plamen_broker_v2_process_custodian_terminal_request *input,
    struct plamen_broker_v2_process_custodian_terminal_receipt *receipt,
    uint32_t *daemon_status)
{
    xpc_object_t request, response = NULL; int result;
    if (client == NULL || input == NULL || input->version != 1
        || receipt == NULL || daemon_status == NULL) return 2;
    memset(receipt, 0, sizeof(*receipt));
    request = common_request(operation, input->operation_key,
        input->request_sha256, input->prior_checkpoint_sha256,
        input->claim_owner_sha256);
    if (request == NULL) return 4;
    xpc_dictionary_set_data(request, K_START_OPERATION,
        input->start_operation_key, 32);
    result = transact(client, request, &response, daemon_status);
    if (result == 0 && (*daemon_status == 0 || *daemon_status == 1)
        && parse_terminal_receipt(response, *daemon_status, receipt) != 0) {
        reject_connection(client);
        result = PLAMEN_BROKER_V2_CUSTODY_CLIENT_PROTOCOL_REJECTED;
    }
    if (response != NULL) xpc_release(response);
    xpc_release(request); return result;
}

#define TERMINAL_CLIENT(name, operation) \
int plamen_broker_v2_process_custody_client_##name( \
    struct plamen_broker_v2_process_custody_client *client, \
    const struct plamen_broker_v2_process_custodian_terminal_request *request, \
    struct plamen_broker_v2_process_custodian_terminal_receipt *receipt, \
    uint32_t *status) \
{ return terminal_like(client, operation, request, receipt, status); }
TERMINAL_CLIENT(wait, "wait")
TERMINAL_CLIENT(recover, "recover")
TERMINAL_CLIENT(revoke, "revoke")

int plamen_broker_v2_process_custody_client_frame_mapping(
    uint16_t request_type, uint16_t *response_type, const char **operation)
{
    if (response_type == NULL || operation == NULL) return -1;
    switch (request_type) {
    case PLAMEN_BROKER_V2_START_PREPARE:
        *response_type = PLAMEN_BROKER_V2_STARTED; *operation = "start"; return 0;
    case PLAMEN_BROKER_V2_START_RECOVER:
        *response_type = PLAMEN_BROKER_V2_STARTED; *operation = "adopt"; return 0;
    case PLAMEN_BROKER_V2_WAIT_PREPARE:
        *response_type = PLAMEN_BROKER_V2_EXITED; *operation = "wait"; return 0;
    case PLAMEN_BROKER_V2_WAIT_RECOVER:
        *response_type = PLAMEN_BROKER_V2_EXITED; *operation = "recover"; return 0;
    case PLAMEN_BROKER_V2_REVOKE_PREPARE:
        *response_type = PLAMEN_BROKER_V2_REVOKED; *operation = "revoke"; return 0;
    default: return -1;
    }
}

static int client_allocate(const char *requirement,
    plamen_broker_v2_custody_client_peer_admit admit,
    struct plamen_broker_v2_process_custody_client **output)
{
    struct plamen_broker_v2_process_custody_client *client;
    if (output == NULL) return -1; *output = NULL;
    client = calloc(1, sizeof(*client));
    if (client == NULL || pthread_mutex_init(&client->lock, NULL) != 0) {
        free(client); return -1;
    }
    if (requirement != NULL && (client->requirement = strdup(requirement)) == NULL) {
        pthread_mutex_destroy(&client->lock); free(client); return -1;
    }
    client->admit = admit; *output = client; return 0;
}

int plamen_broker_v2_process_custody_client_open(const char *requirement,
    plamen_broker_v2_custody_client_peer_admit admit,
    struct plamen_broker_v2_process_custody_client **output)
{
    if (requirement == NULL || requirement[0] == '\0' || admit == NULL) return -1;
    return client_allocate(requirement, admit, output);
}

void plamen_broker_v2_process_custody_client_close(
    struct plamen_broker_v2_process_custody_client *client)
{
    if (client == NULL) return;
    pthread_mutex_lock(&client->lock); disconnect_locked(client);
#ifdef PLAMEN_BROKER_V2_TEST_ONLY
    if (client->endpoint != NULL) xpc_release(client->endpoint);
#endif
    pthread_mutex_unlock(&client->lock); pthread_mutex_destroy(&client->lock);
    free(client->requirement); memset(client, 0, sizeof(*client)); free(client);
}

#ifdef PLAMEN_BROKER_V2_TEST_ONLY
int plamen_broker_v2_process_custody_client_TEST_ONLY_open_endpoint(
    xpc_endpoint_t endpoint,
    struct plamen_broker_v2_process_custody_client **output)
{
    int result;
    if (endpoint == NULL) return -1;
    result = client_allocate(NULL, NULL, output);
    if (result == 0) { (*output)->endpoint = endpoint; xpc_retain(endpoint); }
    return result;
}
void plamen_broker_v2_process_custody_client_TEST_ONLY_disconnect(
    struct plamen_broker_v2_process_custody_client *client)
{
    if (client == NULL) return;
    pthread_mutex_lock(&client->lock); disconnect_locked(client);
    pthread_mutex_unlock(&client->lock);
}
#endif
