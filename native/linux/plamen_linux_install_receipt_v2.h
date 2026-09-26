#ifndef PLAMEN_LINUX_INSTALL_RECEIPT_V2_H
#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_H

#include "../include/plamen_broker_v2.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Linux intentionally has its own install authority.  The Darwin receipt is
 * bound to launchd and Mach-O code-signing and is not meaningful on ELF.
 * Version 2 is fixed-size and append-only: reserved bytes must remain zero;
 * adding or reinterpreting fields requires a new version and magic.
 */
#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_VERSION 2U
#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_SIZE 8192U
#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_HASHED_SIZE 8160U
#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_MEMBER_COUNT 4U
#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX 256U
#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_SOABI_MAX 128U
#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_IMPLEMENTATION_MAX 64U
#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_FD 198
#define PLAMEN_LINUX_INSTALL_ROOT_V2_FD 199
#define PLAMEN_LINUX_INSTALL_RECEIPT_V2_RELATIVE_PATH \
    "share/plamen/linux-install-receipt-v2.bin"
#define PLAMEN_LINUX_OUTER_SOCKET_PREFIX "/run/user/"
#define PLAMEN_LINUX_OUTER_SOCKET_SUFFIX "/plamen/broker-v2.sock"
#define PLAMEN_LINUX_GUEST_SOCKET_PATH "/run/plamen/broker-v2.sock"

enum plamen_linux_install_scope_v2 {
    PLAMEN_LINUX_INSTALL_SCOPE_OUTER_USER = 1,
    PLAMEN_LINUX_INSTALL_SCOPE_GUEST_ROOT = 2
};

enum plamen_linux_install_arch_v2 {
    PLAMEN_LINUX_INSTALL_ARCH_X86_64 = 1,
    PLAMEN_LINUX_INSTALL_ARCH_AARCH64 = 2
};

enum plamen_linux_install_trust_boundary_v2 {
    PLAMEN_LINUX_INSTALL_TRUST_RETAINED_IMMUTABLE_SIGNED_GENERATION = 1
};

enum plamen_linux_install_member_role_v2 {
    PLAMEN_LINUX_INSTALL_MEMBER_BROKER = 1,
    PLAMEN_LINUX_INSTALL_MEMBER_EXTENSION = 2,
    PLAMEN_LINUX_INSTALL_MEMBER_INTERPRETER = 3,
    PLAMEN_LINUX_INSTALL_MEMBER_SERVICE_BOOTSTRAP = 4
};

struct plamen_linux_install_member_v2 {
    uint16_t role;
    char relative_path[PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX + 1];
    char elf_interp_path[PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX + 1];
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t byte_count;
    uint64_t device;
    uint64_t inode;
    uint64_t link_count;
    uint8_t sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t fd_identity[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t elf_interp_identity_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t elf_needed_closure_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
};

struct plamen_linux_install_receipt_v2 {
    uint16_t scope;
    uint16_t target_arch;
    uint16_t elf_class;
    uint16_t elf_data;
    uint32_t elf_machine;
    uint16_t trust_boundary;
    uint32_t expected_uid;
    uint32_t expected_gid;
    uint16_t python_major;
    uint16_t python_minor;
    char socket_path[PLAMEN_LINUX_INSTALL_RECEIPT_V2_PATH_MAX + 1];
    char python_soabi[PLAMEN_LINUX_INSTALL_RECEIPT_V2_SOABI_MAX + 1];
    char python_implementation[
        PLAMEN_LINUX_INSTALL_RECEIPT_V2_IMPLEMENTATION_MAX + 1];
    uint8_t generation_id_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t install_provenance_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t installed_closure_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t protocol_schema_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t runtime_package_manifest_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t native_deployment_receipt_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t install_root_fd_identity[PLAMEN_BROKER_V2_DIGEST_SIZE];
    uint8_t receipt_producer_identity_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
    struct plamen_linux_install_member_v2
        members[PLAMEN_LINUX_INSTALL_RECEIPT_V2_MEMBER_COUNT];
    uint8_t receipt_sha256[PLAMEN_BROKER_V2_DIGEST_SIZE];
};

/* Canonical fixed-size network-byte-order codec. */
int plamen_linux_install_receipt_v2_encode_exact(
    const struct plamen_linux_install_receipt_v2 *, uint8_t *, size_t);
int plamen_linux_install_receipt_v2_decode_exact(
    const uint8_t *, size_t, struct plamen_linux_install_receipt_v2 *);

/*
 * Authenticate and retain the complete Linux install authority.  Expected
 * digests are compiled/pinned caller policy; receipt fields never self-attest.
 * The caller passes already-CLOEXEC duplicates, not ambient path authority.
 */
int plamen_linux_install_receipt_v2_revalidate_authority(
    int receipt_fd, int install_root_fd, uint16_t expected_scope,
    uint32_t expected_uid, uint32_t expected_gid,
    const uint8_t expected_install_provenance_sha256[32],
    const uint8_t expected_protocol_schema_sha256[32],
    const uint8_t expected_native_deployment_receipt_sha256[32],
    struct plamen_linux_install_receipt_v2 *);

/* Opens and validates one exact member beneath the retained immutable root. */
int plamen_linux_install_receipt_v2_open_member(
    int install_root_fd, const struct plamen_linux_install_member_v2 *,
    int *member_fd);

/* Session binding includes the authenticated receipt self-digest. */
int plamen_linux_install_receipt_v2_session_binding(
    const struct plamen_linux_install_receipt_v2 *, uint8_t output[32]);

#ifdef __cplusplus
}
#endif

#endif
