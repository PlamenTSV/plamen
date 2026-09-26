#ifndef PLAMEN_BROKER_V2_PODMAN_ADMISSION_H
#define PLAMEN_BROKER_V2_PODMAN_ADMISSION_H

#include "../include/plamen_broker_v2.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Linux outer-provider slice 1: read-only admission and retained descriptor
 * custody only.  This ABI intentionally contains no create, start, wait,
 * signal, export, or cleanup operation.  A successful receipt is evidence
 * suitable for a broker-authenticated envelope; it is not a lifecycle
 * capability and cannot unlock the Python adapter by itself.
 */
#define PLAMEN_BROKER_V2_PODMAN_ADMISSION_VERSION 1U
#define PLAMEN_BROKER_V2_PODMAN_RECEIPT_VERSION 1U
#define PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT 7U
#define PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT 10U
#define PLAMEN_BROKER_V2_PODMAN_COMMAND_MAX_ARGS 40U
#define PLAMEN_BROKER_V2_PODMAN_COMMAND_ARG_MAX 512U
#define PLAMEN_BROKER_V2_PODMAN_TRANSCRIPT_MAX (1024U * 1024U)
#define PLAMEN_BROKER_V2_PODMAN_REFERENCE_MAX 512U
#define PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE PLAMEN_BROKER_V2_DIGEST_SIZE

enum plamen_broker_v2_podman_admission_status {
    PLAMEN_BROKER_V2_PODMAN_ADMISSION_OK = 0,
    PLAMEN_BROKER_V2_PODMAN_ADMISSION_REJECTED = 1,
    PLAMEN_BROKER_V2_PODMAN_ADMISSION_UNSUPPORTED = 78
};

enum plamen_broker_v2_podman_component_role {
    PLAMEN_BROKER_V2_PODMAN_COMPONENT_PODMAN = 0,
    PLAMEN_BROKER_V2_PODMAN_COMPONENT_CONMON = 1,
    PLAMEN_BROKER_V2_PODMAN_COMPONENT_CRUN = 2,
    PLAMEN_BROKER_V2_PODMAN_COMPONENT_NEWUIDMAP = 3,
    PLAMEN_BROKER_V2_PODMAN_COMPONENT_NEWGIDMAP = 4,
    PLAMEN_BROKER_V2_PODMAN_COMPONENT_FUSE_OVERLAYFS = 5,
    PLAMEN_BROKER_V2_PODMAN_COMPONENT_SYSTEMD = 6
};

enum plamen_broker_v2_podman_root_role {
    PLAMEN_BROKER_V2_PODMAN_ROOT_STORAGE = 0,
    PLAMEN_BROKER_V2_PODMAN_ROOT_RUNROOT = 1,
    PLAMEN_BROKER_V2_PODMAN_ROOT_TMP = 2,
    PLAMEN_BROKER_V2_PODMAN_ROOT_HOME = 3,
    PLAMEN_BROKER_V2_PODMAN_ROOT_RUNTIME = 4,
    PLAMEN_BROKER_V2_PODMAN_ROOT_OVERLAY = 5,
    PLAMEN_BROKER_V2_PODMAN_ROOT_LOWER = 6,
    PLAMEN_BROKER_V2_PODMAN_ROOT_UPPER = 7,
    PLAMEN_BROKER_V2_PODMAN_ROOT_WORK = 8,
    PLAMEN_BROKER_V2_PODMAN_ROOT_MERGED = 9
};

enum plamen_broker_v2_podman_architecture {
    PLAMEN_BROKER_V2_PODMAN_ARCH_AMD64 = 1,
    PLAMEN_BROKER_V2_PODMAN_ARCH_ARM64 = 2
};

enum plamen_broker_v2_podman_read_operation {
    PLAMEN_BROKER_V2_PODMAN_READ_COMPONENT_VERSION_BASE = 16,
    PLAMEN_BROKER_V2_PODMAN_READ_IMAGE_INSPECT = 32
};

struct plamen_broker_v2_podman_component_binding {
    uint32_t role;
    int executable_fd;
    int package_receipt_fd;
    uint64_t executable_device;
    uint64_t executable_inode;
    uint64_t executable_size;
    uint8_t executable_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t package_receipt_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t package_manifest_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t package_signature_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t package_signer_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t version_transcript_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    const char *package_manager;
    const char *package_name;
    const char *package_version;
    const char *package_architecture;
    const char *exact_version_line;
    const uint8_t *version_transcript;
    size_t version_transcript_size;
    /* These fields must come from the descriptor-bound native installation
     * receipt.  They are deliberately not inferred from a version banner.
     * newuidmap/newgidmap have no command-line options, so those two roles
     * must use NULL/zero version-transcript fields and are versioned solely
     * by this signed package receipt plus their exact executable digest. */
    uint8_t offline_signature_verified;
    uint8_t package_file_manifest_verified;
};

struct plamen_broker_v2_podman_root_binding {
    uint32_t role;
    int fd;
    uint64_t device;
    uint64_t inode;
    uint64_t mount_id;
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;
};

struct plamen_broker_v2_podman_admission_spec {
    uint32_t version;
    uint32_t native_uid;
    uint32_t native_gid;
    uint32_t architecture;
    uint8_t request_fingerprint_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t provider_provenance_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t installed_closure_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    struct plamen_broker_v2_podman_component_binding
        components[PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT];
    struct plamen_broker_v2_podman_root_binding
        roots[PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT];
    int systemd_unit_fd;
    uint8_t systemd_unit_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    int cgroup_fd;
    uint64_t cgroup_device;
    uint64_t cgroup_inode;
    uint64_t cgroup_mount_id;
    const char *image_reference;
    const char *image_index_digest;
    const char *image_manifest_digest;
    const char *image_config_digest;
    const uint8_t *image_inspect_transcript;
    size_t image_inspect_transcript_size;
    uint8_t image_inspect_transcript_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
};

struct plamen_broker_v2_podman_read_command {
    uint32_t operation;
    size_t argc;
    char storage[PLAMEN_BROKER_V2_PODMAN_COMMAND_MAX_ARGS]
        [PLAMEN_BROKER_V2_PODMAN_COMMAND_ARG_MAX];
    const char *argv[PLAMEN_BROKER_V2_PODMAN_COMMAND_MAX_ARGS + 1U];
};

struct plamen_broker_v2_podman_admission_receipt {
    uint32_t version;
    uint32_t status;
    uint32_t native_uid;
    uint32_t native_gid;
    uint32_t architecture;
    uint8_t request_fingerprint_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t provider_provenance_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t installed_closure_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t component_closure_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t package_closure_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t root_closure_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t cgroup_identity_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t systemd_unit_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t image_inspect_transcript_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t image_identity_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t admission_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t component_descriptors_retained;
    uint8_t package_receipts_retained;
    uint8_t roots_componentwise_nofollow;
    uint8_t roots_descriptors_retained;
    uint8_t rootless_user_proven;
    uint8_t cgroup_v2_leaf_empty;
    uint8_t cgroup_kill_available;
    uint8_t overlay_topology_proven;
    uint8_t image_immutable_and_platform_exact;
    uint8_t commands_read_only;
    uint8_t receipt_requires_broker_authentication;
    uint8_t lifecycle_authority_granted;
};

struct plamen_broker_v2_podman_admission_custody {
    int component_fds[PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT];
    int package_receipt_fds[PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT];
    int root_fds[PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT];
    int systemd_unit_fd;
    int cgroup_fd;
    uint8_t component_sha256[PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT]
        [PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    uint8_t package_receipt_sha256[PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT]
        [PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE];
    struct plamen_broker_v2_podman_root_binding
        root_identity[PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT];
    uint64_t cgroup_device;
    uint64_t cgroup_inode;
    uint64_t cgroup_mount_id;
    struct plamen_broker_v2_podman_admission_receipt receipt;
    uint8_t sealed;
};

/* Acquire an exact relative path beneath an already-retained directory.  On
 * Linux this uses openat2(RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV).
 * It never accepts absolute paths, empty components, `.` or `..`. */
int plamen_broker_v2_podman_open_beneath(
    int parent_fd, const char *relative_path, int flags, unsigned int mode);

/* Render one of the only admitted read commands.  Component operations are
 * READ_COMPONENT_VERSION_BASE + component_role. */
int plamen_broker_v2_podman_render_read_command(
    const struct plamen_broker_v2_podman_admission_spec *, uint32_t operation,
    struct plamen_broker_v2_podman_read_command *);

int plamen_broker_v2_podman_admit(
    const struct plamen_broker_v2_podman_admission_spec *,
    struct plamen_broker_v2_podman_admission_custody *);

int plamen_broker_v2_podman_custody_revalidate(
    const struct plamen_broker_v2_podman_admission_custody *);

void plamen_broker_v2_podman_custody_close(
    struct plamen_broker_v2_podman_admission_custody *);

int plamen_broker_v2_podman_receipt_validate(
    const struct plamen_broker_v2_podman_admission_receipt *);

#ifdef PLAMEN_BROKER_V2_PODMAN_ADMISSION_TEST_ONLY
int plamen_broker_v2_podman_test_validate_component_version(
    uint32_t role, const uint8_t *, size_t, const char *exact_line,
    const uint8_t expected_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE]);
int plamen_broker_v2_podman_test_validate_image(
    const uint8_t *, size_t, const char *reference,
    const char *manifest_digest, uint32_t architecture,
    const uint8_t expected_sha256[PLAMEN_BROKER_V2_PODMAN_SHA256_SIZE]);
int plamen_broker_v2_podman_test_render_read_command(
    uint32_t operation,
    const int component_fds[PLAMEN_BROKER_V2_PODMAN_COMPONENT_COUNT],
    const int root_fds[PLAMEN_BROKER_V2_PODMAN_ROOT_COUNT],
    const char *reference, const char *manifest_digest,
    uint8_t *output, size_t capacity, size_t *output_size);
int plamen_broker_v2_podman_test_relative_path_valid(const char *);
int plamen_broker_v2_podman_test_receipt_integrity(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
