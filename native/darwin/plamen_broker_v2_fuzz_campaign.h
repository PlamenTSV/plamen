#ifndef PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_H
#define PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_H

#include "plamen_broker_v2_apple_container_lifecycle.h"
#include "plamen_broker_v2_process_custody_client.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A dedicated Apple Container effect for one Forge or Medusa campaign.  This
 * is deliberately not an alias for ProviderAuthority.start_driver: that
 * authority is committed to the audit driver and its stage journal.
 */
#define PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_VERSION 1U
#define PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_RESULT_VERSION 1U
#define PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX 8U
#define PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ENV_MAX 1U
#define PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARGUMENT_TEXT_MAX 4097U
#define PLAMEN_BROKER_V2_FUZZ_FORGE_ANCHOR \
    "/usr/local/lib/plamen/toolchains/foundry/bin/forge"
#define PLAMEN_BROKER_V2_FUZZ_MEDUSA_ANCHOR \
    "/usr/local/lib/plamen/toolchains/medusa/bin/medusa"
#define PLAMEN_BROKER_V2_FUZZ_CWD "/workspace/scratch/fuzz/active"
#define PLAMEN_BROKER_V2_FUZZ_PATH \
    "PATH=/usr/local/lib/plamen/toolchains/foundry/bin:" \
    "/usr/local/lib/plamen/toolchains/medusa/bin:/usr/bin:/bin"

/*
 * Required next-generation service boundary.  Admission deliberately omits
 * both the prepared-campaign digest and the secure-receipt digest: those are
 * outputs of admission, not caller-controlled prerequisites.  The service
 * must atomically return canonical receipt bytes and an opaque continuation;
 * EXECUTE consumes that continuation while joining the subsequently derived
 * prepared-campaign digest to the retained admission request.
 *
 * This is a source ABI contract, not evidence that the installed service
 * implements it.  Production callers must require the matching extension
 * type/function roster before accepting any receipt bytes.
 */
#define PLAMEN_BROKER_V2_FUZZ_SERVICE_ADMISSION_VERSION 1U
#define PLAMEN_BROKER_V2_FUZZ_SERVICE_ABI_SCHEMA \
    "plamen.apple-fuzz-service-admission.v1"
#define PLAMEN_BROKER_V2_FUZZ_SERVICE_REQUEST_SCHEMA \
    "plamen.apple-fuzz-service-admission-request.v1"
#define PLAMEN_BROKER_V2_FUZZ_SERVICE_EXECUTE_SCHEMA \
    "plamen.apple-fuzz-service-execute-request.v1"
#define PLAMEN_BROKER_V2_FUZZ_SERVICE_RECEIPT_SCHEMA \
    "plamen.secure-fuzz-launcher-receipt.v1"

struct plamen_broker_v2_fuzz_service_admission_request {
    uint32_t version;
    uint16_t tool;
    uint8_t authority_sha256[32];
    uint8_t phase_io_binding_sha256[32];
    uint8_t admission_request_sha256[32];
    /* Authenticated by the Python preflight authority and retained only as a
     * provenance binding.  It is deliberately distinct from the native
     * Apple Container admission digest held by the broker. */
    uint8_t provider_preflight_sha256[32];
    const char *attempt_id;
    const char *workspace_root;
    const char *const *guest_argv;
    size_t guest_argc;
    uint32_t timeout_seconds;
    uint8_t rosetta_required;
};

struct plamen_broker_v2_fuzz_service_admission_receipt {
    uint32_t version;
    uint8_t admission_request_sha256[32];
    uint8_t authority_sha256[32];
    uint8_t phase_io_binding_sha256[32];
    uint8_t provider_preflight_sha256[32];
    uint8_t provider_provenance_sha256[32];
    uint8_t cli_executable_sha256[32];
    uint8_t guest_executable_sha256[32];
    uint8_t spec_sha256[32];
    uint8_t launch_policy_sha256[32];
    uint8_t secure_receipt_sha256[32];
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    const uint8_t *canonical_secure_receipt;
    size_t canonical_secure_receipt_size;
};

struct plamen_broker_v2_fuzz_service_admission_storage {
    struct plamen_broker_v2_fuzz_service_admission_request request;
    char attempt_id[129];
    char workspace_root[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX + 1U];
    char argv_text[PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX]
        [PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARGUMENT_TEXT_MAX];
    const char *argv[PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX];
};

struct plamen_broker_v2_fuzz_service_execute_request {
    uint8_t prepared_campaign_sha256[32];
    uint8_t secure_receipt_sha256[32];
};

/* Service-private: it must never be serialized or reconstructed in Python. */
struct plamen_broker_v2_fuzz_campaign_authority;
struct plamen_broker_v2_fuzz_campaign_result;
struct plamen_broker_v2_fuzz_service_continuation;
struct plamen_broker_v2_fuzz_service_session;
struct plamen_broker_v2_fuzz_service_terminal;

struct plamen_broker_v2_fuzz_service_api {
    uint32_t version;
    int (*acquire)(
        const struct plamen_broker_v2_fuzz_campaign_authority *,
        struct plamen_broker_v2_fuzz_service_session **);
    int (*admit_and_issue)(
        struct plamen_broker_v2_fuzz_service_session *,
        const struct plamen_broker_v2_fuzz_service_admission_request *,
        const struct plamen_broker_v2_apple_lifecycle_mount *, size_t,
        struct plamen_broker_v2_fuzz_service_admission_receipt *,
        struct plamen_broker_v2_fuzz_service_continuation **);
    int (*project_secure_receipt)(
        const struct plamen_broker_v2_fuzz_service_continuation *,
        uint8_t **, size_t *);
    int (*execute_and_consume)(
        struct plamen_broker_v2_fuzz_service_session *,
        struct plamen_broker_v2_fuzz_service_continuation *,
        const uint8_t prepared_campaign_sha256[32],
        const uint8_t secure_receipt_sha256[32],
        struct plamen_broker_v2_fuzz_service_terminal **);
    int (*project_terminal)(
        const struct plamen_broker_v2_fuzz_service_terminal *,
        uint8_t **, size_t *);
    void (*dispose_session)(struct plamen_broker_v2_fuzz_service_session *);
    void (*dispose_continuation)(
        struct plamen_broker_v2_fuzz_service_continuation *);
    void (*dispose_terminal)(struct plamen_broker_v2_fuzz_service_terminal *);
};

/*
 * Concrete one-shot service capability API.  All returned objects are opaque
 * and process-local.  Acquisition duplicates every descriptor in authority;
 * admission duplicates every mount descriptor, derives the Apple lifecycle
 * commitments from those retained identities, and mints the canonical secure
 * receipt.  Execute burns the continuation before any external effect.
 */
int plamen_broker_v2_fuzz_service_acquire(
    const struct plamen_broker_v2_fuzz_campaign_authority *,
    struct plamen_broker_v2_fuzz_service_session **);
void plamen_broker_v2_fuzz_service_session_dispose(
    struct plamen_broker_v2_fuzz_service_session *);

int plamen_broker_v2_fuzz_service_admit(
    struct plamen_broker_v2_fuzz_service_session *,
    const struct plamen_broker_v2_fuzz_service_admission_request *,
    const struct plamen_broker_v2_apple_lifecycle_mount *, size_t,
    struct plamen_broker_v2_fuzz_service_admission_receipt *,
    struct plamen_broker_v2_fuzz_service_continuation **);
int plamen_broker_v2_fuzz_service_project_secure_receipt(
    const struct plamen_broker_v2_fuzz_service_continuation *,
    uint8_t **, size_t *);
int plamen_broker_v2_fuzz_service_execute(
    struct plamen_broker_v2_fuzz_service_session *,
    struct plamen_broker_v2_fuzz_service_continuation *,
    const uint8_t prepared_campaign_sha256[32],
    const uint8_t secure_receipt_sha256[32],
    struct plamen_broker_v2_fuzz_service_terminal **);
int plamen_broker_v2_fuzz_service_project_terminal(
    const struct plamen_broker_v2_fuzz_service_terminal *,
    uint8_t **, size_t *);
void plamen_broker_v2_fuzz_service_continuation_dispose(
    struct plamen_broker_v2_fuzz_service_continuation *);
void plamen_broker_v2_fuzz_service_terminal_dispose(
    struct plamen_broker_v2_fuzz_service_terminal *);

enum plamen_broker_v2_fuzz_campaign_tool {
    PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_FORGE = 1,
    PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_MEDUSA = 2
};

struct plamen_broker_v2_fuzz_campaign_request {
    uint32_t version;
    uint16_t tool;
    uint8_t request_sha256[32];
    uint8_t operation_key[32];
    uint8_t authority_sha256[32];
    uint8_t prepared_campaign_sha256[32];
    uint8_t secure_launcher_sha256[32];
    uint8_t phase_io_binding_sha256[32];
    uint8_t provider_preflight_sha256[32];
    uint8_t provider_provenance_sha256[32];
    uint8_t cli_executable_sha256[32];
    uint8_t guest_executable_sha256[32];
    uint8_t spec_sha256[32];
    uint8_t launch_policy_sha256[32];
    const char *container_id;
    const char *attempt_id;
    const char *guest_executable;
    const char *const *guest_argv;
    size_t guest_argc;
    const char *const *guest_environment;
    size_t guest_environment_count;
    const char *guest_cwd;
    uint32_t timeout_seconds;
    const struct plamen_broker_v2_apple_lifecycle_mount *mounts;
    size_t mount_count;
    uint8_t rosetta_required;
};

struct plamen_broker_v2_tool_effect_plan_view;

/* Decoder-owned backing for every pointer in a wire request. */
struct plamen_broker_v2_fuzz_campaign_request_storage {
    struct plamen_broker_v2_fuzz_campaign_request request;
    char container_id[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE];
    char attempt_id[129];
    char guest_cwd[PLAMEN_BROKER_V2_APPLE_LIFECYCLE_PATH_MAX + 1U];
    char argv_text[PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX]
        [PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARGUMENT_TEXT_MAX];
    const char *argv[PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ARG_MAX];
    const char *environment[PLAMEN_BROKER_V2_FUZZ_CAMPAIGN_ENV_MAX];
};

/* Every descriptor is retained and authenticated by the owning broker
 * context.  This structure is never accepted from Python or the wire. */
struct plamen_broker_v2_fuzz_campaign_authority {
    uint32_t version;
    int cli_fd;
    const char *cli_path;
    int cwd_fd;
    int stdin_fd;
    int state_directory_fd;
    const struct plamen_broker_v2_apple_container_admission_receipt *admission;
    struct plamen_broker_v2_process_custody_client *custody_client;
    uint8_t authority_binding_sha256[32];
    uint8_t provider_preflight_sha256[32];
    uint8_t forge_executable_sha256[32];
    uint8_t medusa_executable_sha256[32];
    const char *runtime_image_reference;
    uint32_t cpus;
    uint64_t memory_bytes;
};

struct plamen_broker_v2_fuzz_campaign_result {
    uint32_t version;
    uint8_t request_sha256[32];
    struct plamen_broker_v2_apple_lifecycle_commitments commitments;
    struct plamen_broker_v2_apple_lifecycle_create_receipt created;
    struct plamen_broker_v2_apple_lifecycle_start_receipt started;
    struct plamen_broker_v2_apple_lifecycle_terminal_receipt terminal;
    struct plamen_broker_v2_apple_lifecycle_delete_receipt deleted;
    uint8_t lifecycle_sha256[32];
};

int plamen_broker_v2_fuzz_campaign_request_validate(
    const struct plamen_broker_v2_fuzz_campaign_request *);
int plamen_broker_v2_fuzz_campaign_result_validate(
    const struct plamen_broker_v2_fuzz_campaign_request *,
    const struct plamen_broker_v2_fuzz_campaign_result *);

int plamen_broker_v2_fuzz_campaign_request_decode(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    struct plamen_broker_v2_fuzz_campaign_request_storage *);
int plamen_broker_v2_fuzz_service_admission_request_decode(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    struct plamen_broker_v2_fuzz_service_admission_storage *);
int plamen_broker_v2_fuzz_service_execute_request_decode(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    struct plamen_broker_v2_fuzz_service_execute_request *);

int plamen_broker_v2_fuzz_campaign_result_render(
    const struct plamen_broker_v2_fuzz_campaign_request *,
    const struct plamen_broker_v2_fuzz_campaign_authority *,
    const struct plamen_broker_v2_fuzz_campaign_result *,
    uint8_t **, size_t *);

/* Derives the exact native admission/mount/argv-bound lifecycle authority
 * without creating a container.  PREPARE publishes this result and the
 * execute lease re-derives it from the same retained descriptors. */
int plamen_broker_v2_fuzz_campaign_prepare(
    const struct plamen_broker_v2_fuzz_campaign_authority *,
    const struct plamen_broker_v2_fuzz_campaign_request *,
    struct plamen_broker_v2_apple_lifecycle_commitments *);

/* Runs create/start/wait/mandatory-stop/delete, with durable reopen support.
 * Any non-terminal failure invokes revoke-delete before returning. */
int plamen_broker_v2_fuzz_campaign_execute(
    const struct plamen_broker_v2_fuzz_campaign_authority *,
    const struct plamen_broker_v2_fuzz_campaign_request *,
    struct plamen_broker_v2_fuzz_campaign_result *);

void plamen_broker_v2_fuzz_campaign_result_dispose(
    struct plamen_broker_v2_fuzz_campaign_result *);

#ifdef __cplusplus
}
#endif
#endif
