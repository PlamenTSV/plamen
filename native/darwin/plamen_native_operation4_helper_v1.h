#ifndef PLAMEN_NATIVE_OPERATION4_HELPER_V1_H
#define PLAMEN_NATIVE_OPERATION4_HELPER_V1_H

#include "plamen_native_source_bootstrap_coordinator_v1.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_NATIVE_OPERATION4_HELPER_V1_VERSION 1U
#define PLAMEN_NATIVE_OPERATION4_HELPER_V1_TERMINAL_SIZE 4096U
#define PLAMEN_NATIVE_OPERATION4_HELPER_V1_POLICY_SCHEMA_MAX 96U
#define PLAMEN_NATIVE_OPERATION4_PRODUCER_FOOTER_V1_SIZE 512U
#define PLAMEN_NATIVE_OPERATION4_PRODUCER_VERSION_MAX 128U
#define PLAMEN_NATIVE_OPERATION4_PRODUCER_RECEIPT_MAX (16U * 1024U * 1024U)

enum plamen_native_operation4_identity_mode_v1 {
    PLAMEN_NATIVE_OPERATION4_STATIC_PAYLOAD_V1 = 1,
    PLAMEN_NATIVE_OPERATION4_LATEST_BACKEND_RECEIPT_V1 = 2,
    PLAMEN_NATIVE_OPERATION4_FROZEN_SOURCE_PROJECTION_V1 = 3
};

enum plamen_native_operation4_receipt_validator_v1 {
    PLAMEN_NATIVE_OPERATION4_DEBIAN_RECEIPT_V1 = 1,
    PLAMEN_NATIVE_OPERATION4_PLAMEN_SOURCE_RECEIPT_V1 = 2,
    PLAMEN_NATIVE_OPERATION4_CPYTHON_RECEIPT_V1 = 3,
    PLAMEN_NATIVE_OPERATION4_BACKEND_RECEIPT_V1 = 4,
    PLAMEN_NATIVE_OPERATION4_FOUNDRY_RECEIPT_V1 = 5,
    PLAMEN_NATIVE_OPERATION4_MEDUSA_RECEIPT_V1 = 6,
    PLAMEN_NATIVE_OPERATION4_SOLC_RECEIPT_V1 = 7,
    PLAMEN_NATIVE_OPERATION4_AMD64_COMPAT_RECEIPT_V1 = 8
};

/*
 * This table is generated from the reviewed acquisition policies and frozen
 * source projection before the helper is compiled and signed.  Codex and
 * Claude deliberately use LATEST_BACKEND_RECEIPT: the policy and receipt
 * schema are fixed, while the authenticated receipt supplies the resolved
 * version and exact payload identity at install time.
 */
struct plamen_native_operation4_policy_row_v1 {
    uint16_t role;
    uint16_t identity_mode;
    uint16_t receipt_validator;
    uint16_t reserved;
    uint64_t payload_size;
    uint64_t source_manifest_size;
    uint64_t semantic_receipt_size;
    uint8_t payload_sha256[32];
    uint8_t source_manifest_sha256[32];
    uint8_t semantic_receipt_sha256[32];
    uint8_t policy_sha256[32];
    char receipt_schema[PLAMEN_NATIVE_OPERATION4_HELPER_V1_POLICY_SCHEMA_MAX];
};

struct plamen_native_operation4_fixed_policy_v1 {
    uint32_t version;
    uint32_t role_count;
    uint8_t roster_sha256[32];
    struct plamen_native_operation4_policy_row_v1
        rows[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT];
};

/* Strong definition is generated from reviewed acquisition inputs at build. */
extern const struct plamen_native_operation4_fixed_policy_v1
    plamen_native_operation4_generated_policy_v1;

/*
 * The producer FD is `semantic_receipt_bytes || footer`. The footer commits
 * the exact retained semantic prefix; acquisition-specific validator dispatch
 * authenticates that prefix before this wrapper can be admitted.
 */
struct plamen_native_operation4_producer_footer_v1 {
    uint16_t role;
    uint16_t identity_mode;
    uint16_t receipt_validator;
    uint64_t payload_size;
    uint64_t source_manifest_size;
    uint64_t semantic_receipt_size;
    uint8_t policy_sha256[32];
    uint8_t payload_sha256[32];
    uint8_t source_manifest_sha256[32];
    uint8_t semantic_receipt_sha256[32];
    char receipt_schema[PLAMEN_NATIVE_OPERATION4_HELPER_V1_POLICY_SCHEMA_MAX];
    char resolved_version[PLAMEN_NATIVE_OPERATION4_PRODUCER_VERSION_MAX];
    uint8_t footer_sha256[32];
};

int plamen_native_operation4_producer_footer_decode_exact_v1(
    const uint8_t bytes[PLAMEN_NATIVE_OPERATION4_PRODUCER_FOOTER_V1_SIZE],
    struct plamen_native_operation4_producer_footer_v1 *footer);

/* Private retained context. No pathname, key, or descriptor is projected. */
struct plamen_native_operation4_context_v1;

/*
 * `runtime_root_fd` names the already-authenticated installed runtime root;
 * python/transform name retained members beneath that root.  The grouped and
 * terminal pairs must each name a distinct, initially-empty, already-unlinked
 * private-store vnode.  The helper duplicates only those descriptor
 * capabilities and never creates or reopens a pathname.  The caller must close
 * its transferred aliases before invocation.  The function duplicates every
 * authority descriptor and creates a process-private terminal MAC key.
 */
int plamen_native_operation4_context_create_fixed_v1(uid_t owner_uid,
    int runtime_root_fd, int python_fd, int transform_fd,
    int install_verifier_public_key_fd,
    int grouped_writer_fd, int grouped_reader_fd,
    int terminal_writer_fd, int terminal_reader_fd,
    struct plamen_native_operation4_context_v1 **context);
#if defined(PLAMEN_NATIVE_OPERATION4_TESTING)
int plamen_native_operation4_policy_finalize_for_testing_v1(
    struct plamen_native_operation4_fixed_policy_v1 *fixed_policy);
int plamen_native_operation4_context_create_for_testing_v1(uid_t owner_uid,
    int runtime_root_fd, int python_fd, int transform_fd,
    int install_verifier_public_key_fd,
    int grouped_writer_fd, int grouped_reader_fd,
    int terminal_writer_fd, int terminal_reader_fd,
    const struct plamen_native_operation4_fixed_policy_v1 *fixed_policy,
    struct plamen_native_operation4_context_v1 **context);
int plamen_native_operation4_attest_python_for_testing_v1(
    int python_fd, int expected_python_fd);
#endif
void plamen_native_operation4_context_dispose_v1(
    struct plamen_native_operation4_context_v1 *context);

/* Fill coordinator expectations only from the compiled fixed policy. */
int plamen_native_operation4_policy_fill_fixed_v1(
    const struct plamen_native_operation4_context_v1 *context,
    struct plamen_source_bootstrap_input_v1
        inputs[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT]);

/* Exact coordinator callback: dispatches the compiled receipt validator. */
int plamen_native_operation4_authenticate_source_fixed_v1(void *context,
    uint16_t role, int retained_producer_receipt_fd,
    const struct plamen_source_bootstrap_input_v1 *expected,
    const struct plamen_source_bootstrap_fd_identity_v1 *payload,
    const struct plamen_source_bootstrap_fd_identity_v1 *producer_receipt,
    const struct plamen_source_bootstrap_fd_identity_v1 *source_manifest);

/* Exact coordinator callback: accepts only this signed executable identity. */
int plamen_native_operation4_authenticate_executable_fixed_v1(void *context,
    const uint8_t executable_sha256[32]);
int plamen_native_operation4_executable_sha256_fixed_v1(
    const struct plamen_native_operation4_context_v1 *context,
    uint8_t executable_sha256[32]);

/*
 * Exact coordinator callback. It constructs the immutable PLMRHG1 group,
 * launches the fixed inherited-FD-only helper, verifies its MACed terminal,
 * and returns an O_RDONLY|CLOEXEC duplicate. No executable/path/callback is
 * accepted from the request or environment.
 */
int plamen_native_operation4_invoke_fixed_v1(void *context,
    int composition_manifest_fd,
    const int payload_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT],
    const int source_manifest_fds[
        PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT],
    int output_writer_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT],
    int scratch_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT],
    int *terminal_receipt_fd);

/*
 * Authenticate the MACed terminal again at the coordinator's final output
 * census and require its five size/digest/mode commitments to match exactly.
 */
int plamen_native_operation4_rejoin_terminal_outputs_fixed_v1(void *context,
    int terminal_receipt_fd,
    const struct plamen_source_bootstrap_fd_identity_v1
        outputs[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT]);

#ifdef __cplusplus
}
#endif

#endif
