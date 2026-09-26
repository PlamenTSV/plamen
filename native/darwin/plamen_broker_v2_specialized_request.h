#ifndef PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_H
#define PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_H

#include "plamen_broker_v2_tool_custody.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_CODEC_VERSION 1U
#define PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ROLE_COUNT 8U
#define PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ARG_MAX 1024U
#define PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ENV_MAX 128U
#define PLAMEN_BROKER_V2_SPECIALIZED_DERIVED_TEXT_MAX 131072U
#define PLAMEN_BROKER_V2_SPECIALIZED_WORKER_REQUEST_MAX 1048576U
#define PLAMEN_BROKER_V2_SPECIALIZED_WORKER_TERMINAL_MAX 2097152U

enum plamen_broker_v2_specialized_request_codec_status {
    PLAMEN_BROKER_V2_SPECIALIZED_CODEC_OK = 0,
    PLAMEN_BROKER_V2_SPECIALIZED_CODEC_INVALID = -1,
    PLAMEN_BROKER_V2_SPECIALIZED_CODEC_PAYLOAD = -2,
    PLAMEN_BROKER_V2_SPECIALIZED_CODEC_ROSTER = -3,
    PLAMEN_BROKER_V2_SPECIALIZED_CODEC_LAUNCH = -4,
    PLAMEN_BROKER_V2_SPECIALIZED_CODEC_CRYPTO = -5,
    PLAMEN_BROKER_V2_SPECIALIZED_CODEC_OUTPUT = -6
};

enum plamen_broker_v2_specialized_worker_role {
    PLAMEN_BROKER_V2_WORKER_ACQUISITION = 1,
    PLAMEN_BROKER_V2_WORKER_CACHE = 2,
    PLAMEN_BROKER_V2_WORKER_GENERATION = 3,
    PLAMEN_BROKER_V2_WORKER_PROJECT = 4,
    PLAMEN_BROKER_V2_WORKER_SCRATCH = 5,
    PLAMEN_BROKER_V2_WORKER_SOURCE = 6,
    PLAMEN_BROKER_V2_WORKER_STATE = 7,
    PLAMEN_BROKER_V2_WORKER_TOOL = 8
};

enum plamen_broker_v2_specialized_worker_fd_kind {
    PLAMEN_BROKER_V2_WORKER_REGULAR_FILE = 1,
    PLAMEN_BROKER_V2_WORKER_DIRECTORY = 2,
    PLAMEN_BROKER_V2_WORKER_IMAGE_MEMBER = 3
};

enum plamen_broker_v2_specialized_worker_provider_mode {
    PLAMEN_BROKER_V2_WORKER_RETAINED_FD = 1,
    PLAMEN_BROKER_V2_WORKER_APPLE_IMAGE_MEMBER = 2
};

enum plamen_broker_v2_specialized_worker_fd_provenance {
    PLAMEN_BROKER_V2_WORKER_FD_FROM_PLAN = 1,
    PLAMEN_BROKER_V2_WORKER_FD_FROM_AUTHENTICATED_CONTEXT = 2
};

struct plamen_broker_v2_specialized_worker_fd {
    uint32_t version;
    uint16_t role;
    uint16_t purpose;
    uint16_t target;
    uint8_t access_mode;
    uint8_t kind;
    uint8_t provenance;
    uint8_t native_identity[32];
    int host_fd;
    uint32_t guest_fd;
    uint8_t payload_sha256[32];
    uint64_t payload_bytes;
    uint64_t payload_entries;
};

struct plamen_broker_v2_specialized_worker_env {
    const char *name;
    const char *value;
};

struct plamen_broker_v2_specialized_worker_limits {
    uint64_t duration_ms;
    uint64_t memory_bytes;
    uint64_t open_fds;
    uint64_t output_bytes;
    uint64_t output_files;
    uint64_t stderr_bytes;
    uint64_t stdout_bytes;
};

/*
 * All argv/environment/cwd paths are already closed symbolic guest paths.
 * The native provider derives this launch specification from the authenticated
 * method payload; the codec rejects ambient absolute paths, URLs, PATH/loader
 * variables, and any incomplete or aliased retained descriptor roster.
 */
struct plamen_broker_v2_specialized_worker_launch {
    uint32_t version;
    uint16_t provider_mode;
    const char *request_id;
    uint8_t worker_runtime_sha256[32];
    uint64_t worker_runtime_size;
    const char *tool_anchor_id;
    uint8_t oci_image_sha256[32];
    uint8_t runtime_manifest_sha256[32];
    uint8_t tool_image_member_sha256[32];
    uint64_t tool_image_member_size;
    uint8_t managed_provisioner_sha256[32];
    uint64_t managed_provisioner_size;
    uint8_t js_offline_materializer_sha256[32];
    uint64_t js_offline_materializer_size;
    const char *const *argv;
    size_t argc;
    const struct plamen_broker_v2_specialized_worker_env *environment;
    size_t environment_count;
    uint16_t cwd_role;
    const char *cwd_relative;
    struct plamen_broker_v2_specialized_worker_limits limits;
    uint8_t slither_forge_sha256[32];
    uint64_t slither_forge_size;
    uint8_t slither_solc_sha256[32];
    uint64_t slither_solc_size;
    uint8_t slither_python_sha256[32];
    uint64_t slither_python_size;
    uint8_t slither_internal_environment_sha256[32];
};

struct plamen_broker_v2_specialized_apple_runtime {
    uint32_t version;
    uint8_t oci_image_sha256[32];
    uint8_t runtime_manifest_sha256[32];
    uint8_t worker_runtime_sha256[32];
    uint64_t worker_runtime_size;
    uint8_t tool_image_member_sha256[32];
    uint64_t tool_image_member_size;
    uint8_t managed_provisioner_sha256[32];
    uint64_t managed_provisioner_size;
    uint8_t js_offline_materializer_sha256[32];
    uint64_t js_offline_materializer_size;
    uint8_t slither_forge_sha256[32];
    uint64_t slither_forge_size;
    uint8_t slither_solc_sha256[32];
    uint64_t slither_solc_size;
    uint8_t slither_python_sha256[32];
    uint64_t slither_python_size;
    uint8_t slither_internal_environment_sha256[32];
};

/* Caller-owned storage; every pointer in launch points into this object. */
struct plamen_broker_v2_specialized_derived_launch {
    struct plamen_broker_v2_specialized_worker_launch launch;
    const char *argv[PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ARG_MAX];
    struct plamen_broker_v2_specialized_worker_env
        environment[PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ENV_MAX];
    char request_id[129];
    char tool_anchor_id[32];
    char text[PLAMEN_BROKER_V2_SPECIALIZED_DERIVED_TEXT_MAX];
    size_t text_size;
};

struct plamen_broker_v2_specialized_worker_request_binding {
    uint32_t version;
    uint16_t provider_mode;
    uint16_t lane;
    uint16_t method;
    char operation[32];
    char request_id[129];
    uint8_t method_payload_sha256[32];
    uint8_t effects_binding_sha256[32];
    uint8_t worker_runtime_sha256[32];
    uint64_t worker_runtime_size;
    uint8_t runtime_closure_sha256[32];
    uint8_t apple_mount_payload_sha256[32];
    uint8_t tool_image_member_sha256[32];
    uint64_t tool_image_member_size;
    uint8_t managed_provisioner_sha256[32];
    uint64_t managed_provisioner_size;
    uint8_t js_offline_materializer_sha256[32];
    uint64_t js_offline_materializer_size;
    char tool_anchor_id[32];
    uint8_t worker_request_sha256[32];
    uint8_t descriptor_identity_sha256
        [PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ROLE_COUNT][32];
    uint8_t role_present[PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ROLE_COUNT];
    struct plamen_broker_v2_specialized_worker_limits limits;
    uint8_t slither_forge_sha256[32];
    uint64_t slither_forge_size;
    uint8_t slither_solc_sha256[32];
    uint64_t slither_solc_size;
    uint8_t slither_python_sha256[32];
    uint64_t slither_python_size;
    uint8_t slither_internal_environment_sha256[32];
};

struct plamen_broker_v2_specialized_worker_terminal_auth {
    uint32_t version;
    uint8_t terminal_hmac_key[32];
    uint8_t terminal_hmac_sha256[32];
};

/* Observation only.  No field claims host lifecycle, population or cleanup. */
struct plamen_broker_v2_specialized_worker_terminal_observation {
    uint32_t version;
    char status[40];
    int32_t returncode;
    uint64_t duration_ms;
    uint64_t peak_memory_bytes;
    uint64_t stdout_observed_bytes;
    uint64_t stdout_retained_bytes;
    uint8_t stdout_sha256[32];
    uint64_t stderr_observed_bytes;
    uint64_t stderr_retained_bytes;
    uint8_t stderr_sha256[32];
    uint64_t output_file_count;
    uint64_t output_bytes;
    uint8_t output_manifest_sha256[32];
    uint8_t projection_observation_sha256[32];
    uint8_t observed_egress_sha256[32];
    uint8_t descriptor_post_sha256
        [PLAMEN_BROKER_V2_SPECIALIZED_WORKER_ROLE_COUNT][32];
    uint8_t terminal_sha256[32];
    uint8_t terminal_hmac_sha256[32];
};

struct plamen_broker_v2_specialized_projection_observation {
    uint32_t version;
    uint8_t original_source_scope_sha256[32];
    uint8_t dependency_materialization_receipt_sha256[32];
    uint8_t js_lock_selection_sha256[32];
    uint8_t source_copy_closure_sha256[32];
    uint64_t source_copy_file_count;
    uint64_t source_copy_directory_count;
    uint64_t source_copy_bytes;
    uint8_t materialized_node_modules_closure_sha256[32];
    uint64_t materialized_node_modules_file_count;
    uint64_t materialized_node_modules_directory_count;
    uint64_t materialized_node_modules_bytes;
    uint8_t analysis_workspace_closure_sha256[32];
    uint64_t analysis_workspace_file_count;
    uint64_t analysis_workspace_directory_count;
    uint64_t analysis_workspace_bytes;
    uint8_t materialization_lineage_sha256[32];
    uint64_t materialization_lineage_byte_count;
    uint8_t native_materialization_request_sha256[32];
};

int plamen_broker_v2_specialized_projection_observation_parse(
    const uint8_t *, size_t,
    struct plamen_broker_v2_specialized_projection_observation *);

struct plamen_broker_v2_specialized_output_spec;
struct plamen_broker_v2_specialized_output_receipt;

int plamen_broker_v2_specialized_method_output_specs(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    const struct plamen_broker_v2_specialized_worker_request_binding *,
    struct plamen_broker_v2_specialized_output_spec *, size_t *);

int plamen_broker_v2_specialized_js_method_terminal_render(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    const struct plamen_broker_v2_specialized_worker_request_binding *,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *,
    const struct plamen_broker_v2_specialized_output_receipt *,
    const uint8_t [32], const uint8_t [32],
    uint8_t **, size_t *);

int plamen_broker_v2_specialized_snapshot_method_terminal_render(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    const struct plamen_broker_v2_specialized_worker_request_binding *,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *,
    const struct plamen_broker_v2_specialized_output_receipt *,
    const uint8_t [32], const uint8_t [32],
    uint8_t **, size_t *);

/* Seals lifecycle-only snapshot host authority.  Its zero tree roster is
 * deliberate: output_tree_sha256 comes exclusively from the authenticated
 * guest observation, never from an invented host census. */
int plamen_broker_v2_specialized_snapshot_host_authority_seal(
    struct plamen_broker_v2_specialized_output_receipt *,
    const uint8_t [32]);

int plamen_broker_v2_specialized_slither_internal_environment_sha256(
    uint8_t [32]);

/* Borrowed JSON slice excludes framing LF; digest binds its exact wire form
 * with the single required trailing LF. */
int plamen_broker_v2_specialized_js_replay_terminal_binding(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    const uint8_t **, size_t *, uint8_t [32]);

int plamen_broker_v2_specialized_worker_request_build(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    const struct plamen_broker_v2_specialized_worker_fd *, size_t,
    const struct plamen_broker_v2_specialized_worker_launch *,
    uint8_t *, size_t, size_t *,
    struct plamen_broker_v2_specialized_worker_request_binding *);

int plamen_broker_v2_specialized_worker_launch_derive_apple(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    const struct plamen_broker_v2_specialized_apple_runtime *,
    struct plamen_broker_v2_specialized_derived_launch *);

int plamen_broker_v2_specialized_worker_terminal_parse(
    const uint8_t *, size_t,
    const struct plamen_broker_v2_specialized_worker_request_binding *,
    const struct plamen_broker_v2_specialized_worker_terminal_auth *,
    struct plamen_broker_v2_specialized_worker_terminal_observation *);

/* Returns only compiled guest-image ABI anchors; arbitrary paths are absent. */
int plamen_broker_v2_specialized_worker_tool_anchor_path(
    uint16_t lane, uint16_t method, const char *tool_anchor_id,
    const char **guest_path);

/* Returns the only compiled image-member id selected by the exact payload. */
int plamen_broker_v2_specialized_worker_tool_anchor_id(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    char tool_anchor_id[32]);

#ifdef __cplusplus
}
#endif
#endif
