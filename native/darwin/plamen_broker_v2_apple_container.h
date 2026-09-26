#ifndef PLAMEN_BROKER_V2_APPLE_CONTAINER_H
#define PLAMEN_BROKER_V2_APPLE_CONTAINER_H

#include "plamen_broker_v2_process.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_APPLE_CONTAINER_VERSION 1U
#define PLAMEN_BROKER_V2_APPLE_CONTAINER_RECEIPT_VERSION 2U
#define PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT 8U
#define PLAMEN_BROKER_V2_APPLE_CONTAINER_REFERENCE_MAX 512U
#define PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE 40U

/*
 * Admission deliberately has no lifecycle verb.  These are the only Apple
 * Container commands it can construct:
 *
 *   system version --format json
 *   system status --format json
 *   image inspect <immutable-init-reference>
 *   image inspect <immutable-runtime-reference>
 *
 * In particular there is no build, pull, tag, run, exec, stop, kill or delete
 * surface in this API.
 */
enum plamen_broker_v2_apple_container_status {
    PLAMEN_BROKER_V2_APPLE_CONTAINER_OK = 0,
    PLAMEN_BROKER_V2_APPLE_CONTAINER_REJECTED = 1,
    PLAMEN_BROKER_V2_APPLE_CONTAINER_COMMAND_FAILED = 2,
    PLAMEN_BROKER_V2_APPLE_CONTAINER_INTERNAL_ERROR = 3
};

enum plamen_broker_v2_apple_container_closure_role {
    PLAMEN_BROKER_V2_APPLE_CONTAINER_SERVER = 0,
    PLAMEN_BROKER_V2_APPLE_CONTAINER_CONTAINERIZATION = 1,
    PLAMEN_BROKER_V2_APPLE_CONTAINER_CORE_IMAGES = 2,
    PLAMEN_BROKER_V2_APPLE_CONTAINER_NETWORK_VMNET = 3,
    PLAMEN_BROKER_V2_APPLE_CONTAINER_RUNTIME_LINUX = 4,
    PLAMEN_BROKER_V2_APPLE_CONTAINER_MACHINE_APISERVER = 5,
    PLAMEN_BROKER_V2_APPLE_CONTAINER_PACKAGE_RECEIPT = 6,
    PLAMEN_BROKER_V2_APPLE_CONTAINER_KERNEL = 7
};

struct plamen_broker_v2_apple_container_binding {
    int fd;
    uint8_t expected_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
};

struct plamen_broker_v2_apple_container_admission_spec {
    uint32_t version;
    int cli_fd;
    const char *cli_path;
    int cwd_fd;
    int stdin_fd;
    uint32_t timeout_seconds;
    uint8_t cli_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t request_fingerprint_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t provider_provenance_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t image_closure_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    struct plamen_broker_v2_apple_container_binding
        closure[PLAMEN_BROKER_V2_APPLE_CONTAINER_CLOSURE_COUNT];
    /* These two variable receipts must themselves come from native install
     * authority; their exact bytes are descriptor-bound above. */
    uint8_t package_signed;
    uint8_t package_notarized;
    uint8_t package_timestamped;
    uint8_t implicit_kernel_install_disabled;
    const char *runtime_image_reference;
    const char *runtime_index_digest;
    const char *runtime_manifest_digest;
};

struct plamen_broker_v2_apple_container_admission_receipt {
    uint32_t version;
    uint32_t status;
    uint8_t cli_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t request_fingerprint_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t provider_provenance_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t image_closure_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t closure_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t version_stdout_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t status_stdout_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t init_image_stdout_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t runtime_image_stdout_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t init_image_postcondition_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t runtime_image_postcondition_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
    uint8_t command_count;
    uint8_t commands_read_only;
    uint8_t lifecycle_authority_granted;
    uint8_t mutable_identifier_accepted;
    uint8_t control_processes_reaped;
    uint8_t control_process_groups_extinct;
    char runtime_image_reference[PLAMEN_BROKER_V2_APPLE_CONTAINER_REFERENCE_MAX];
    uint8_t admission_sha256[PLAMEN_BROKER_V2_SHA256_SIZE];
};

int plamen_broker_v2_apple_container_admit(
    const struct plamen_broker_v2_apple_container_admission_spec *,
    struct plamen_broker_v2_apple_container_admission_receipt *);

int plamen_broker_v2_apple_container_receipt_validate(
    const struct plamen_broker_v2_apple_container_admission_receipt *);

/* Fixed-format IDs prevent the container/exec identifier path-traversal class.
 * The result is always "plamen-" followed by 32 lowercase hexadecimal bytes. */
int plamen_broker_v2_apple_container_derive_id(
    const uint8_t request_fingerprint[PLAMEN_BROKER_V2_SHA256_SIZE],
    const uint8_t operation_key[PLAMEN_BROKER_V2_SHA256_SIZE],
    char output[PLAMEN_BROKER_V2_APPLE_CONTAINER_ID_SIZE]);

int plamen_broker_v2_apple_container_id_validate(const char *);

/* Exact state proof used by the native lifecycle owner.  The document must be
 * one `container inspect` object with the bound ID, immutable image reference,
 * zero network attachments, and the requested stopped/running state. */
int plamen_broker_v2_apple_container_validate_state(
    const uint8_t *, size_t, const char *container_id,
    const char *runtime_image_reference, const char *state,
    uint8_t observation_sha256[PLAMEN_BROKER_V2_SHA256_SIZE]);

/* The independently provisioned Kata kernel is an explicit toolchain pin.
 * Installed Apple CLI/server/plugin bytes are instead authenticated and
 * descriptor-bound at runtime, so this API deliberately exposes no CLI pin. */
int plamen_broker_v2_apple_container_production_closure_sha256(
    uint32_t role, uint8_t output[PLAMEN_BROKER_V2_SHA256_SIZE]);

#ifdef PLAMEN_BROKER_V2_APPLE_CONTAINER_TEST_ONLY
/* Parser seam only.  It cannot execute or admit a provider. */
int plamen_broker_v2_apple_container_test_validate_version(
    const uint8_t *, size_t);
int plamen_broker_v2_apple_container_test_validate_status(
    const uint8_t *, size_t);
int plamen_broker_v2_apple_container_test_validate_image(
    const uint8_t *, size_t, const char *, const char *, const char *);
#endif

#ifdef __cplusplus
}
#endif

#endif
