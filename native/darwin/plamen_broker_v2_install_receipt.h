#ifndef PLAMEN_BROKER_V2_INSTALL_RECEIPT_H
#define PLAMEN_BROKER_V2_INSTALL_RECEIPT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_INSTALL_RECEIPT_VERSION 2U
#define PLAMEN_INSTALL_RECEIPT_SIZE 16384U
#define PLAMEN_INSTALL_RECEIPT_HASHED_SIZE 16352U
#define PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT 10U
#define PLAMEN_INSTALL_RECEIPT_PATH_MAX 1024U
#define PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH_MAX 256U
#define PLAMEN_INSTALL_RECEIPT_ABI_TAG_MAX 64U
#define PLAMEN_INSTALL_RECEIPT_SIGNING_ID_MAX 128U
#define PLAMEN_INSTALL_RECEIPT_TEAM_ID_MAX 128U
#define PLAMEN_INSTALL_RECEIPT_CDHASH_MAX 32U
#define PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH \
    "share/plamen/native-install-receipt-v2.bin"
#define PLAMEN_INSTALL_RECEIPT_FLAG_SPECIALIZED_AUTHORITY 1U
#define PLAMEN_INSTALL_RECEIPT_FLAG_SOURCE_BOOTSTRAP_AUTHORITY 2U
#define PLAMEN_INSTALL_SPECIALIZED_AUTHORITY_PATH \
    "share/plamen/image-member-receipt-v2.bin"
#define PLAMEN_INSTALL_SOURCE_BOOTSTRAP_AUTHORITY_PATH \
    "share/plamen/native-source-bootstrap-coordinator-receipt-v1.bin"

enum plamen_install_receipt_member_role {
    PLAMEN_INSTALL_MEMBER_LAUNCHER = 1,
    PLAMEN_INSTALL_MEMBER_SERVICE = 2,
    PLAMEN_INSTALL_MEMBER_EXTENSION = 3,
    PLAMEN_INSTALL_MEMBER_SHARED_ABI = 4,
    PLAMEN_INSTALL_MEMBER_SCHEMA = 5,
    PLAMEN_INSTALL_MEMBER_PYTHON = 6,
    PLAMEN_INSTALL_MEMBER_OUTER_ENTRYPOINT = 7,
    PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST = 8,
    PLAMEN_INSTALL_MEMBER_INSTALL_COORDINATOR = 9,
    PLAMEN_INSTALL_MEMBER_SOURCE_BOOTSTRAP_COORDINATOR = 10
};

struct plamen_install_receipt_member {
    uint16_t role;
    char relative_path[PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH_MAX + 1];
    uint8_t sha256[32];
    uint64_t size;
    uint32_t mode;
    uint64_t device;
    uint64_t inode;
    uint32_t uid;
    uint32_t gid;
    char signing_identifier[PLAMEN_INSTALL_RECEIPT_SIGNING_ID_MAX + 1];
    char team_identifier[PLAMEN_INSTALL_RECEIPT_TEAM_ID_MAX + 1];
    uint8_t cdhash[PLAMEN_INSTALL_RECEIPT_CDHASH_MAX];
    uint16_t cdhash_size;
};

struct plamen_install_receipt_launchd_plist {
    char path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    uint8_t sha256[32];
    uint64_t size;
    uint32_t mode;
    uint64_t device;
    uint64_t inode;
    uint32_t uid;
    uint32_t gid;
};

struct plamen_install_receipt_specialized_authority {
    char relative_path[PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH_MAX + 1];
    uint8_t runtime_package_manifest_sha256[32];
    uint8_t sha256[32];
    uint64_t size;
    uint32_t mode;
    uint64_t device;
    uint64_t inode;
    uint32_t uid;
    uint32_t gid;
};

struct plamen_install_receipt_source_bootstrap_authority {
    char relative_path[PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH_MAX + 1];
    uint8_t acquisition_roster_sha256[32];
    uint8_t producer_verifier_key_sha256[32];
    uint8_t installed_authority_roster_sha256[32];
    uint8_t coordinator_member_identity_sha256[32];
    uint8_t coordinator_code_identity_sha256[32];
    uint8_t sha256[32];
    uint64_t size;
    uint32_t mode;
    uint64_t device;
    uint64_t inode;
    uint32_t uid;
    uint32_t gid;
};

struct plamen_install_receipt {
    uint8_t generation_id_sha256[32];
    uint8_t intrinsic_roster_sha256[32];
    uint8_t service_readiness_checkpoint_sha256[32];
    uint8_t projection_schema_sha256[32];
    uint8_t protocol_schema_sha256[32];
    uint16_t python_major;
    uint16_t python_minor;
    uint16_t python_micro;
    char python_abi_tag[PLAMEN_INSTALL_RECEIPT_ABI_TAG_MAX + 1];
    char generation_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    struct plamen_install_receipt_launchd_plist broker_launchd_plist;
    struct plamen_install_receipt_launchd_plist custody_launchd_plist;
    struct plamen_install_receipt_member
        members[PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT];
    uint16_t specialized_present;
    struct plamen_install_receipt_specialized_authority
        specialized_authority;
    uint16_t source_bootstrap_present;
    struct plamen_install_receipt_source_bootstrap_authority
        source_bootstrap_authority;
    uint8_t receipt_sha256[32];
};

/* Strict fixed-size network-byte-order parser. */
int plamen_install_receipt_decode_exact(const uint8_t *, size_t,
    struct plamen_install_receipt *);

/* Open/hash/revalidate a roster member beneath a retained generation FD. */
int plamen_install_receipt_open_member(int generation_fd,
    const struct plamen_install_receipt_member *, int *member_fd);

/* Compare every bound stat field after an operation using a retained FD. */
int plamen_install_receipt_member_revalidate(int,
    const struct plamen_install_receipt_member *);

/* Open/revalidate the specialized companion beneath a retained generation. */
int plamen_install_receipt_open_specialized_authority(int generation_fd,
    const struct plamen_install_receipt *, int *authority_fd);
int plamen_install_receipt_specialized_authority_revalidate(int,
    const struct plamen_install_receipt_specialized_authority *);

/* Open/revalidate the installed acquisition receipt companion. */
int plamen_install_receipt_open_source_bootstrap_authority(int generation_fd,
    const struct plamen_install_receipt *, int *authority_fd);
int plamen_install_receipt_source_bootstrap_authority_revalidate(int,
    const struct plamen_install_receipt_source_bootstrap_authority *);

/* Canonical fixed managed-Python argv/environment commitment. */
int plamen_install_receipt_python_invocation_digests(
    const struct plamen_install_receipt *, uint8_t argv_sha256[32],
    uint8_t environment_sha256[32]);

#ifdef __cplusplus
}
#endif

#endif
