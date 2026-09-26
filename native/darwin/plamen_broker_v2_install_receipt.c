#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_install_receipt.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define RECEIPT_HEADER_SIZE 256U
#define RECEIPT_ABI_OFFSET 256U
#define RECEIPT_GENERATION_PATH_OFFSET 320U
#define RECEIPT_BROKER_PLIST_PATH_OFFSET 1344U
#define RECEIPT_BROKER_PLIST_IDENTITY_OFFSET 2368U
#define RECEIPT_MEMBERS_OFFSET 2496U
#define RECEIPT_MEMBER_SIZE 896U
#define RECEIPT_CUSTODY_PLIST_PATH_OFFSET 11456U
#define RECEIPT_CUSTODY_PLIST_IDENTITY_OFFSET 12480U
#define RECEIPT_RESERVED_OFFSET 12608U
#define RECEIPT_HEADER_FLAGS_OFFSET 192U
#define RECEIPT_SPECIALIZED_OFFSET 12608U
#define RECEIPT_SPECIALIZED_SIZE 512U
#define RECEIPT_SPECIALIZED_PATH_OFFSET 128U
#define RECEIPT_SPECIALIZED_PATH_SIZE 256U
#define RECEIPT_SOURCE_BOOTSTRAP_OFFSET 13120U
#define RECEIPT_SOURCE_BOOTSTRAP_SIZE 512U
#define RECEIPT_SOURCE_BOOTSTRAP_PATH_OFFSET 192U
#define RECEIPT_SOURCE_BOOTSTRAP_PATH_SIZE 256U

static const uint8_t receipt_magic[8] = {
    'P', 'L', 'M', 'I', 'N', 'S', '2', '\0'
};
static const uint8_t specialized_magic[8] = {
    'P', 'L', 'M', 'I', 'R', 'A', '1', 0
};
static const char *const expected_paths[PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT] = {
    "bin/plamen-native-launcher",
    "lib/plamen/plamen-audit-broker-v2",
    "lib/plamen/_plamen_native_supervisor.cpython-312-darwin.so",
    "share/plamen/plamen_broker_v2.h",
    "share/plamen/native-supervisor-schema-v2.json",
    "bin/python3.12",
    "lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
    "share/plamen/runtime-package-manifest-v2.bin",
    "libexec/plamen-native-installer-v2",
    "libexec/plamen-native-source-bootstrap-coordinator-v1"
};
static const uint32_t expected_modes[PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT] = {
    0500, 0500, 0400, 0400, 0400, 0500, 0400, 0400, 0500, 0500
};
static const char *const expected_identifiers[5] = {
    "com.plamen.audit.launcher.v2",
    "com.plamen.audit.broker.v2",
    "com.plamen.audit.native-supervisor.v2",
    "com.plamen.audit.installer.v2",
    "com.plamen.audit.source-bootstrap.v1"
};
static const uint8_t source_bootstrap_magic[8] = {
    'P', 'L', 'M', 'S', 'B', 'A', '1', '\0'
};

static uint16_t
load_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t
load_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t
load_u64(const uint8_t *p)
{
    return ((uint64_t)load_u32(p) << 32) | load_u32(p + 4);
}

static int
member_code_identity_sha256(
    const struct plamen_install_receipt_member *member, uint8_t output[32])
{
    static const uint8_t domain[] =
        "PLAMEN-INSTALL-CODE-IDENTITY-V1\0";
    uint8_t preimage[sizeof(domain) + 6U
        + PLAMEN_INSTALL_RECEIPT_SIGNING_ID_MAX
        + PLAMEN_INSTALL_RECEIPT_TEAM_ID_MAX
        + PLAMEN_INSTALL_RECEIPT_CDHASH_MAX];
    size_t identifier_size, team_size, offset = 0U, index;
    uint8_t aggregate = 0U;
    if (member == NULL || output == NULL)
        return -1;
    identifier_size = strlen(member->signing_identifier);
    team_size = strlen(member->team_identifier);
    if (identifier_size > PLAMEN_INSTALL_RECEIPT_SIGNING_ID_MAX
        || team_size > PLAMEN_INSTALL_RECEIPT_TEAM_ID_MAX
        || member->cdhash_size > PLAMEN_INSTALL_RECEIPT_CDHASH_MAX)
        return -1;
    memset(preimage, 0, sizeof(preimage));
    memcpy(preimage + offset, domain, sizeof(domain)); offset += sizeof(domain);
    preimage[offset++] = (uint8_t)(identifier_size >> 8);
    preimage[offset++] = (uint8_t)identifier_size;
    preimage[offset++] = (uint8_t)(team_size >> 8);
    preimage[offset++] = (uint8_t)team_size;
    preimage[offset++] = (uint8_t)(member->cdhash_size >> 8);
    preimage[offset++] = (uint8_t)member->cdhash_size;
    memcpy(preimage + offset, member->signing_identifier, identifier_size);
    offset += identifier_size;
    memcpy(preimage + offset, member->team_identifier, team_size);
    offset += team_size;
    memcpy(preimage + offset, member->cdhash, member->cdhash_size);
    offset += member->cdhash_size;
    if (CC_SHA256(preimage, (CC_LONG)offset, output) != output) {
        memset(preimage, 0, sizeof(preimage));
        return -1;
    }
    memset(preimage, 0, sizeof(preimage));
    for (index = 0U; index < 32U; ++index)
        aggregate |= output[index];
    return aggregate == 0U ? -1 : 0;
}

static void
store_u32(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

int
plamen_install_receipt_python_invocation_digests(
    const struct plamen_install_receipt *receipt,
    uint8_t argv_sha256[32], uint8_t environment_sha256[32])
{
    uint8_t encoded[4 + 4 * 4 + 2 * PLAMEN_INSTALL_RECEIPT_PATH_MAX + 8];
    char python_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    char entrypoint_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    const char *values[4];
    uint8_t empty_environment[4] = { 0 };
    size_t offset = 0, index;
    int result = -1;

    memset(encoded, 0, sizeof(encoded));
    memset(python_path, 0, sizeof(python_path));
    memset(entrypoint_path, 0, sizeof(entrypoint_path));
    if (receipt == NULL || argv_sha256 == NULL || environment_sha256 == NULL
        || snprintf(python_path, sizeof(python_path), "%s/%s",
            receipt->generation_path,
            receipt->members[PLAMEN_INSTALL_MEMBER_PYTHON - 1].relative_path)
            >= (int)sizeof(python_path)
        || snprintf(entrypoint_path, sizeof(entrypoint_path), "%s/%s",
            receipt->generation_path,
            receipt->members[PLAMEN_INSTALL_MEMBER_OUTER_ENTRYPOINT - 1]
                .relative_path) >= (int)sizeof(entrypoint_path))
        goto done;
    values[0] = python_path;
    values[1] = "-I";
    values[2] = "-B";
    values[3] = entrypoint_path;
    store_u32(encoded + offset, 4);
    offset += 4;
    for (index = 0; index < 4; ++index) {
        size_t length = strlen(values[index]);
        if (length > UINT32_MAX || offset + 4 + length > sizeof(encoded))
            goto done;
        store_u32(encoded + offset, (uint32_t)length);
        offset += 4;
        memcpy(encoded + offset, values[index], length);
        offset += length;
    }
    if (CC_SHA256(encoded, (CC_LONG)offset, argv_sha256) != argv_sha256
        || CC_SHA256(empty_environment, sizeof(empty_environment),
            environment_sha256) != environment_sha256)
        goto done;
    result = 0;
done:
    memset(encoded, 0, sizeof(encoded));
    memset(python_path, 0, sizeof(python_path));
    memset(entrypoint_path, 0, sizeof(entrypoint_path));
    if (result != 0) {
        if (argv_sha256 != NULL)
            memset(argv_sha256, 0, 32);
        if (environment_sha256 != NULL)
            memset(environment_sha256, 0, 32);
    }
    return result;
}

static int
all_zero(const uint8_t *value, size_t size)
{
    uint8_t aggregate = 0;
    size_t index;
    for (index = 0; index < size; ++index)
        aggregate |= value[index];
    return aggregate == 0;
}

static int
zero_region(const uint8_t *value, size_t size)
{
    return all_zero(value, size);
}

static int
copy_fixed_string(const uint8_t *slot, size_t slot_size, uint16_t length,
    char *output, size_t output_size, int absolute)
{
    size_t index;
    if (length == 0 || length >= output_size || length > slot_size
        || !zero_region(slot + length, slot_size - length))
        return -1;
    for (index = 0; index < length; ++index) {
        uint8_t byte = slot[index];
        if (byte < 0x21 || byte > 0x7e || byte == '\\')
            return -1;
    }
    if ((absolute && slot[0] != '/') || (!absolute && slot[0] == '/'))
        return -1;
    memcpy(output, slot, length);
    output[length] = '\0';
    if (strstr(output, "//") != NULL || strstr(output, "/./") != NULL
        || strstr(output, "/../") != NULL
        || strcmp(output + (length > 2 ? length - 2 : 0), "/.") == 0
        || strcmp(output + (length > 3 ? length - 3 : 0), "/..") == 0)
        return -1;
    return 0;
}

static int
copy_identity_string(const uint8_t *slot, size_t slot_size, uint16_t length,
    char *output, size_t output_size, int permit_empty)
{
    size_t index;
    if ((!permit_empty && length == 0) || length >= output_size
        || length > slot_size || !zero_region(slot + length, slot_size - length))
        return -1;
    for (index = 0; index < length; ++index) {
        uint8_t byte = slot[index];
        if (!((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z')
                || (byte >= '0' && byte <= '9') || byte == '.'
                || byte == '-'))
            return -1;
    }
    memcpy(output, slot, length);
    output[length] = '\0';
    return 0;
}

static int
sha256_fd(int fd, uint8_t output[32], struct stat *identity)
{
    CC_SHA256_CTX context;
    struct stat before, after;
    uint8_t buffer[65536];
    off_t offset = 0;

    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size <= 0 || CC_SHA256_Init(&context) != 1)
        return -1;
    while (offset < before.st_size) {
        size_t wanted = sizeof(buffer);
        ssize_t amount;
        if ((off_t)wanted > before.st_size - offset)
            wanted = (size_t)(before.st_size - offset);
        do {
            amount = pread(fd, buffer, wanted, offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0
            || CC_SHA256_Update(&context, buffer, (CC_LONG)amount) != 1)
            return -1;
        offset += amount;
    }
    if (fstat(fd, &after) != 0 || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid || before.st_gid != after.st_gid
        || before.st_nlink != after.st_nlink || before.st_size != after.st_size
        || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec
        || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec
        || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec
        || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec
        || CC_SHA256_Final(output, &context) != 1)
        return -1;
    if (identity != NULL)
        *identity = after;
    return 0;
}

static int
member_decode(const uint8_t *record, uint16_t expected_role,
    struct plamen_install_receipt_member *member)
{
    uint16_t path_size = load_u16(record + 2);
    uint16_t identifier_size = load_u16(record + 4);
    uint16_t team_size = load_u16(record + 6);
    uint16_t cdhash_size = load_u16(record + 8);
    int signed_member = expected_role <= PLAMEN_INSTALL_MEMBER_EXTENSION
        || expected_role == PLAMEN_INSTALL_MEMBER_PYTHON
        || expected_role == PLAMEN_INSTALL_MEMBER_INSTALL_COORDINATOR
        || expected_role == PLAMEN_INSTALL_MEMBER_SOURCE_BOOTSTRAP_COORDINATOR;

    memset(member, 0, sizeof(*member));
    if (load_u16(record) != expected_role || load_u16(record + 10) != 0
        || !zero_region(record + 624, 272)
        || copy_fixed_string(record + 112, 256, path_size,
            member->relative_path, sizeof(member->relative_path), 0) != 0
        || strcmp(member->relative_path, expected_paths[expected_role - 1]) != 0
        || copy_identity_string(record + 368, 128, identifier_size,
            member->signing_identifier, sizeof(member->signing_identifier),
            !signed_member) != 0
        || copy_identity_string(record + 496, 128, team_size,
            member->team_identifier, sizeof(member->team_identifier), 1) != 0
        || cdhash_size > PLAMEN_INSTALL_RECEIPT_CDHASH_MAX
        || (signed_member && !(cdhash_size == 20 || cdhash_size == 32))
        || (!signed_member && cdhash_size != 0)
        || !zero_region(record + 80 + cdhash_size, 32 - cdhash_size))
        return -1;
    member->role = expected_role;
    member->mode = load_u32(record + 12);
    member->size = load_u64(record + 16);
    member->device = load_u64(record + 24);
    member->inode = load_u64(record + 32);
    member->uid = load_u32(record + 40);
    member->gid = load_u32(record + 44);
    memcpy(member->sha256, record + 48, 32);
    memcpy(member->cdhash, record + 80, cdhash_size);
    member->cdhash_size = cdhash_size;
    if (member->mode != expected_modes[expected_role - 1]
        || member->size == 0 || member->device == 0 || member->inode == 0
        || all_zero(member->sha256, 32)
        || ((expected_role <= PLAMEN_INSTALL_MEMBER_EXTENSION
                || expected_role == PLAMEN_INSTALL_MEMBER_INSTALL_COORDINATOR
                || expected_role
                    == PLAMEN_INSTALL_MEMBER_SOURCE_BOOTSTRAP_COORDINATOR)
            && (strcmp(member->signing_identifier,
                    expected_identifiers[
                        expected_role == PLAMEN_INSTALL_MEMBER_INSTALL_COORDINATOR
                            ? 3
                            : expected_role
                                == PLAMEN_INSTALL_MEMBER_SOURCE_BOOTSTRAP_COORDINATOR
                                ? 4 : expected_role - 1]) != 0
                || member->team_identifier[0] != '\0'))
        || (!signed_member && (member->signing_identifier[0] != '\0'
                || member->team_identifier[0] != '\0')))
        return -1;
    return 0;
}

int
plamen_install_receipt_decode_exact(const uint8_t *bytes, size_t size,
    struct plamen_install_receipt *receipt)
{
    uint8_t digest[32];
    uint16_t abi_size, generation_size, broker_plist_path_size;
    uint16_t custody_plist_path_size, index;
    uint32_t receipt_flags;
    char expected_plist_path[PLAMEN_INSTALL_RECEIPT_PATH_MAX + 1];
    struct plamen_install_receipt_launchd_plist *plists[2];
    const size_t identity_offsets[2] = {
        RECEIPT_BROKER_PLIST_IDENTITY_OFFSET,
        RECEIPT_CUSTODY_PLIST_IDENTITY_OFFSET
    };
    size_t plist_index;

    if (bytes == NULL || receipt == NULL || size != PLAMEN_INSTALL_RECEIPT_SIZE)
        return -1;
    memset(receipt, 0, sizeof(*receipt));
    abi_size = load_u16(bytes + 120);
    generation_size = load_u16(bytes + 122);
    broker_plist_path_size = load_u16(bytes + 124);
    custody_plist_path_size = load_u16(bytes + 126);
    receipt_flags = load_u32(bytes + RECEIPT_HEADER_FLAGS_OFFSET);
    if (memcmp(bytes, receipt_magic, sizeof(receipt_magic)) != 0
        || load_u16(bytes + 8) != PLAMEN_INSTALL_RECEIPT_VERSION
        || load_u16(bytes + 10) != RECEIPT_HEADER_SIZE
        || load_u32(bytes + 12) != PLAMEN_INSTALL_RECEIPT_SIZE
        || load_u16(bytes + 112) != PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT
        || (receipt_flags & ~(PLAMEN_INSTALL_RECEIPT_FLAG_SPECIALIZED_AUTHORITY
                | PLAMEN_INSTALL_RECEIPT_FLAG_SOURCE_BOOTSTRAP_AUTHORITY)) != 0U
        || !zero_region(bytes + 196, 60)
        || CC_SHA256(bytes, PLAMEN_INSTALL_RECEIPT_HASHED_SIZE, digest) != digest
        || memcmp(digest, bytes + PLAMEN_INSTALL_RECEIPT_HASHED_SIZE, 32) != 0
        || all_zero(bytes + 16, 32) || all_zero(bytes + 48, 32)
        || all_zero(bytes + 80, 32) || all_zero(bytes + 128, 32)
        || all_zero(bytes + 160, 32)
        || load_u16(bytes + 114) != 3 || load_u16(bytes + 116) != 12
        || load_u16(bytes + 118) == 0
        || copy_fixed_string(bytes + RECEIPT_ABI_OFFSET, 64, abi_size,
            receipt->python_abi_tag, sizeof(receipt->python_abi_tag), 0) != 0
        || copy_fixed_string(bytes + RECEIPT_GENERATION_PATH_OFFSET, 1024,
            generation_size, receipt->generation_path,
            sizeof(receipt->generation_path), 1) != 0
        || copy_fixed_string(bytes + RECEIPT_BROKER_PLIST_PATH_OFFSET, 1024,
            broker_plist_path_size, receipt->broker_launchd_plist.path,
            sizeof(receipt->broker_launchd_plist.path), 1) != 0
        || copy_fixed_string(bytes + RECEIPT_CUSTODY_PLIST_PATH_OFFSET, 1024,
            custody_plist_path_size, receipt->custody_launchd_plist.path,
            sizeof(receipt->custody_launchd_plist.path), 1) != 0
        || strcmp(receipt->python_abi_tag, "cpython-312-darwin") != 0)
        goto invalid;
    if (snprintf(expected_plist_path, sizeof(expected_plist_path),
            "%s/Library/LaunchAgents/com.plamen.audit.broker.v2.plist",
            receipt->generation_path) >= (int)sizeof(expected_plist_path)
        || strcmp(expected_plist_path,
            receipt->broker_launchd_plist.path) != 0
        || snprintf(expected_plist_path, sizeof(expected_plist_path),
            "%s/Library/LaunchAgents/"
            "com.plamen.audit.process-custody.v2.plist",
            receipt->generation_path) >= (int)sizeof(expected_plist_path)
        || strcmp(expected_plist_path,
            receipt->custody_launchd_plist.path) != 0)
        goto invalid;
    memcpy(receipt->generation_id_sha256, bytes + 16, 32);
    memcpy(receipt->intrinsic_roster_sha256, bytes + 48, 32);
    memcpy(receipt->service_readiness_checkpoint_sha256, bytes + 80, 32);
    memcpy(receipt->projection_schema_sha256, bytes + 128, 32);
    memcpy(receipt->protocol_schema_sha256, bytes + 160, 32);
    receipt->python_major = load_u16(bytes + 114);
    receipt->python_minor = load_u16(bytes + 116);
    receipt->python_micro = load_u16(bytes + 118);
    plists[0] = &receipt->broker_launchd_plist;
    plists[1] = &receipt->custody_launchd_plist;
    for (plist_index = 0; plist_index < 2; ++plist_index) {
        struct plamen_install_receipt_launchd_plist *plist =
            plists[plist_index];
        size_t offset = identity_offsets[plist_index];
        memcpy(plist->sha256, bytes + offset, 32);
        plist->size = load_u64(bytes + offset + 32);
        plist->device = load_u64(bytes + offset + 40);
        plist->inode = load_u64(bytes + offset + 48);
        plist->mode = load_u32(bytes + offset + 56);
        plist->uid = load_u32(bytes + offset + 60);
        plist->gid = load_u32(bytes + offset + 64);
        if (plist->size == 0 || plist->device == 0 || plist->inode == 0
            || plist->mode != 0400 || all_zero(plist->sha256, 32)
            || !zero_region(bytes + offset + 68, 60))
            goto invalid;
    }
    if (receipt->broker_launchd_plist.device
            == receipt->custody_launchd_plist.device
        && receipt->broker_launchd_plist.inode
            == receipt->custody_launchd_plist.inode)
        goto invalid;
    for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
        if (member_decode(bytes + RECEIPT_MEMBERS_OFFSET
                + (size_t)index * RECEIPT_MEMBER_SIZE,
                (uint16_t)(index + 1), &receipt->members[index]) != 0)
            goto invalid;
    }
    if ((receipt_flags
            & PLAMEN_INSTALL_RECEIPT_FLAG_SPECIALIZED_AUTHORITY) != 0U) {
        const uint8_t *specialized = bytes + RECEIPT_SPECIALIZED_OFFSET;
        struct plamen_install_receipt_specialized_authority *authority =
            &receipt->specialized_authority;
        uint16_t path_size = load_u16(specialized + 16U);
        if (memcmp(specialized, specialized_magic,
                sizeof(specialized_magic)) != 0
            || load_u16(specialized + 8U) != 1U
            || load_u16(specialized + 10U) != RECEIPT_SPECIALIZED_SIZE
            || load_u32(specialized + 12U) != 1U
            || !zero_region(specialized + 18U, 6U)
            || copy_fixed_string(specialized + RECEIPT_SPECIALIZED_PATH_OFFSET,
                RECEIPT_SPECIALIZED_PATH_SIZE, path_size,
                authority->relative_path, sizeof(authority->relative_path), 0)
                != 0
            || strcmp(authority->relative_path,
                PLAMEN_INSTALL_SPECIALIZED_AUTHORITY_PATH) != 0
            || all_zero(specialized + 24U, 32U)
            || all_zero(specialized + 56U, 32U)
            || load_u64(specialized + 88U) == 0U
            || load_u64(specialized + 96U) == 0U
            || load_u64(specialized + 104U) == 0U
            || load_u32(specialized + 112U) != 0400U
            || !zero_region(specialized + 124U, 4U)
            || !zero_region(specialized + 384U,
                RECEIPT_SPECIALIZED_SIZE - 384U)
            || memcmp(specialized + 24U,
                receipt->members[PLAMEN_INSTALL_MEMBER_RUNTIME_MANIFEST - 1]
                    .sha256, 32U) != 0)
            goto invalid;
        receipt->specialized_present = 1U;
        memcpy(authority->runtime_package_manifest_sha256,
            specialized + 24U, 32U);
        memcpy(authority->sha256, specialized + 56U, 32U);
        authority->size = load_u64(specialized + 88U);
        authority->device = load_u64(specialized + 96U);
        authority->inode = load_u64(specialized + 104U);
        authority->mode = load_u32(specialized + 112U);
        authority->uid = load_u32(specialized + 116U);
        authority->gid = load_u32(specialized + 120U);
    } else if (!zero_region(bytes + RECEIPT_SPECIALIZED_OFFSET,
            RECEIPT_SPECIALIZED_SIZE)) {
        goto invalid;
    }
    if ((receipt_flags
            & PLAMEN_INSTALL_RECEIPT_FLAG_SOURCE_BOOTSTRAP_AUTHORITY) != 0U) {
        const uint8_t *source = bytes + RECEIPT_SOURCE_BOOTSTRAP_OFFSET;
        struct plamen_install_receipt_source_bootstrap_authority *authority =
            &receipt->source_bootstrap_authority;
        uint8_t member_identity_sha256[32];
        uint8_t code_identity_sha256[32];
        uint16_t path_size = load_u16(source + 16U);
        if (memcmp(source, source_bootstrap_magic,
                sizeof(source_bootstrap_magic)) != 0
            || load_u16(source + 8U) != 1U
            || load_u16(source + 10U) != RECEIPT_SOURCE_BOOTSTRAP_SIZE
            || load_u32(source + 12U) != 1U
            || !zero_region(source + 18U, 6U)
            || copy_fixed_string(source + RECEIPT_SOURCE_BOOTSTRAP_PATH_OFFSET,
                RECEIPT_SOURCE_BOOTSTRAP_PATH_SIZE, path_size,
                authority->relative_path, sizeof(authority->relative_path), 0)
                != 0
            || strcmp(authority->relative_path,
                PLAMEN_INSTALL_SOURCE_BOOTSTRAP_AUTHORITY_PATH) != 0
            || all_zero(source + 24U, 32U)
            || all_zero(source + 56U, 32U)
            || all_zero(source + 88U, 32U)
            || all_zero(source + 120U, 32U)
            || all_zero(source + 448U, 32U)
            || all_zero(source + 480U, 32U)
            || load_u64(source + 152U) != 8192U
            || load_u64(source + 160U) == 0U
            || load_u64(source + 168U) == 0U
            || load_u32(source + 176U) != 0400U
            || !zero_region(source + 188U, 4U)
            || CC_SHA256(bytes + RECEIPT_MEMBERS_OFFSET
                    + (PLAMEN_INSTALL_MEMBER_SOURCE_BOOTSTRAP_COORDINATOR - 1U)
                        * RECEIPT_MEMBER_SIZE,
                RECEIPT_MEMBER_SIZE, member_identity_sha256)
                != member_identity_sha256
            || memcmp(member_identity_sha256, source + 56U, 32U) != 0
            || member_code_identity_sha256(
                &receipt->members[
                    PLAMEN_INSTALL_MEMBER_SOURCE_BOOTSTRAP_COORDINATOR - 1U],
                code_identity_sha256) != 0
            || memcmp(code_identity_sha256, source + 88U, 32U) != 0)
            goto invalid;
        receipt->source_bootstrap_present = 1U;
        memcpy(authority->acquisition_roster_sha256, source + 24U, 32U);
        memcpy(authority->producer_verifier_key_sha256,
            source + 448U, 32U);
        memcpy(authority->installed_authority_roster_sha256,
            source + 480U, 32U);
        memcpy(authority->coordinator_member_identity_sha256,
            source + 56U, 32U);
        memcpy(authority->coordinator_code_identity_sha256,
            source + 88U, 32U);
        memcpy(authority->sha256, source + 120U, 32U);
        authority->size = load_u64(source + 152U);
        authority->device = load_u64(source + 160U);
        authority->inode = load_u64(source + 168U);
        authority->mode = load_u32(source + 176U);
        authority->uid = load_u32(source + 180U);
        authority->gid = load_u32(source + 184U);
    } else if (!zero_region(bytes + RECEIPT_SOURCE_BOOTSTRAP_OFFSET,
            RECEIPT_SOURCE_BOOTSTRAP_SIZE)) {
        goto invalid;
    }
    if (!zero_region(bytes + RECEIPT_SOURCE_BOOTSTRAP_OFFSET
            + RECEIPT_SOURCE_BOOTSTRAP_SIZE,
        PLAMEN_INSTALL_RECEIPT_HASHED_SIZE
            - RECEIPT_SOURCE_BOOTSTRAP_OFFSET
            - RECEIPT_SOURCE_BOOTSTRAP_SIZE))
        goto invalid;
    memcpy(receipt->receipt_sha256,
        bytes + PLAMEN_INSTALL_RECEIPT_HASHED_SIZE, 32);
    return 0;
invalid:
    memset(receipt, 0, sizeof(*receipt));
    return -1;
}

int
plamen_install_receipt_member_revalidate(int fd,
    const struct plamen_install_receipt_member *member)
{
    struct stat information;
    uint8_t digest[32];
    int flags;

    if (fd < 0 || member == NULL || (flags = fcntl(fd, F_GETFL)) < 0
        || (flags & O_ACCMODE) != O_RDONLY
        || sha256_fd(fd, digest, &information) != 0
        || information.st_nlink == 0
        || (uint64_t)information.st_dev != member->device
        || (uint64_t)information.st_ino != member->inode
        || (uint64_t)information.st_size != member->size
        || (uint32_t)(information.st_mode & 07777) != member->mode
        || information.st_uid != member->uid || information.st_gid != member->gid
        || memcmp(digest, member->sha256, 32) != 0)
        return -1;
    return 0;
}

int
plamen_install_receipt_specialized_authority_revalidate(int fd,
    const struct plamen_install_receipt_specialized_authority *authority)
{
    struct stat information;
    uint8_t digest[32];
    int flags;
    if (fd < 0 || authority == NULL
        || strcmp(authority->relative_path,
            PLAMEN_INSTALL_SPECIALIZED_AUTHORITY_PATH) != 0
        || authority->mode != 0400U
        || (flags = fcntl(fd, F_GETFL)) < 0
        || (flags & O_ACCMODE) != O_RDONLY
        || sha256_fd(fd, digest, &information) != 0
        || information.st_nlink != 1
        || (uint64_t)information.st_dev != authority->device
        || (uint64_t)information.st_ino != authority->inode
        || (uint64_t)information.st_size != authority->size
        || (uint32_t)(information.st_mode & 07777) != authority->mode
        || information.st_uid != authority->uid
        || information.st_gid != authority->gid
        || memcmp(digest, authority->sha256, 32U) != 0)
        return -1;
    return 0;
}

int
plamen_install_receipt_open_specialized_authority(int generation_fd,
    const struct plamen_install_receipt *receipt, int *authority_fd)
{
    struct plamen_install_receipt_member synthetic;
    int opened = -1;
    if (generation_fd < 0 || receipt == NULL || authority_fd == NULL
        || receipt->specialized_present != 1U)
        return -1;
    *authority_fd = -1;
    memset(&synthetic, 0, sizeof(synthetic));
    memcpy(synthetic.relative_path,
        receipt->specialized_authority.relative_path,
        strlen(receipt->specialized_authority.relative_path) + 1U);
    memcpy(synthetic.sha256, receipt->specialized_authority.sha256, 32U);
    synthetic.size = receipt->specialized_authority.size;
    synthetic.mode = receipt->specialized_authority.mode;
    synthetic.device = receipt->specialized_authority.device;
    synthetic.inode = receipt->specialized_authority.inode;
    synthetic.uid = receipt->specialized_authority.uid;
    synthetic.gid = receipt->specialized_authority.gid;
    if (plamen_install_receipt_open_member(generation_fd, &synthetic,
            &opened) != 0
        || plamen_install_receipt_specialized_authority_revalidate(opened,
            &receipt->specialized_authority) != 0) {
        if (opened >= 0)
            (void)close(opened);
        return -1;
    }
    *authority_fd = opened;
    return 0;
}

int
plamen_install_receipt_source_bootstrap_authority_revalidate(int fd,
    const struct plamen_install_receipt_source_bootstrap_authority *authority)
{
    struct stat information;
    uint8_t digest[32];
    int flags;
    if (fd < 0 || authority == NULL
        || strcmp(authority->relative_path,
            PLAMEN_INSTALL_SOURCE_BOOTSTRAP_AUTHORITY_PATH) != 0
        || authority->size != 8192U || authority->mode != 0400U
        || all_zero(authority->acquisition_roster_sha256, 32U)
        || all_zero(authority->producer_verifier_key_sha256, 32U)
        || all_zero(authority->installed_authority_roster_sha256, 32U)
        || all_zero(authority->coordinator_member_identity_sha256, 32U)
        || all_zero(authority->coordinator_code_identity_sha256, 32U)
        || (flags = fcntl(fd, F_GETFL)) < 0
        || (flags & O_ACCMODE) != O_RDONLY
        || sha256_fd(fd, digest, &information) != 0
        || information.st_nlink != 1
        || (uint64_t)information.st_dev != authority->device
        || (uint64_t)information.st_ino != authority->inode
        || (uint64_t)information.st_size != authority->size
        || (uint32_t)(information.st_mode & 07777) != authority->mode
        || information.st_uid != authority->uid
        || information.st_gid != authority->gid
        || memcmp(digest, authority->sha256, 32U) != 0)
        return -1;
    return 0;
}

int
plamen_install_receipt_open_source_bootstrap_authority(int generation_fd,
    const struct plamen_install_receipt *receipt, int *authority_fd)
{
    struct plamen_install_receipt_member synthetic;
    int opened = -1;
    if (generation_fd < 0 || receipt == NULL || authority_fd == NULL
        || receipt->source_bootstrap_present != 1U)
        return -1;
    *authority_fd = -1;
    memset(&synthetic, 0, sizeof(synthetic));
    memcpy(synthetic.relative_path,
        receipt->source_bootstrap_authority.relative_path,
        strlen(receipt->source_bootstrap_authority.relative_path) + 1U);
    memcpy(synthetic.sha256, receipt->source_bootstrap_authority.sha256, 32U);
    synthetic.size = receipt->source_bootstrap_authority.size;
    synthetic.mode = receipt->source_bootstrap_authority.mode;
    synthetic.device = receipt->source_bootstrap_authority.device;
    synthetic.inode = receipt->source_bootstrap_authority.inode;
    synthetic.uid = receipt->source_bootstrap_authority.uid;
    synthetic.gid = receipt->source_bootstrap_authority.gid;
    if (plamen_install_receipt_open_member(generation_fd, &synthetic,
            &opened) != 0
        || plamen_install_receipt_source_bootstrap_authority_revalidate(opened,
            &receipt->source_bootstrap_authority) != 0) {
        if (opened >= 0)
            (void)close(opened);
        return -1;
    }
    *authority_fd = opened;
    return 0;
}

int
plamen_install_receipt_open_member(int generation_fd,
    const struct plamen_install_receipt_member *member, int *member_fd)
{
    char copy[PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH_MAX + 1];
    char *component, *next;
    int current = -1, child = -1, result = -1;

    if (generation_fd < 0 || member == NULL || member_fd == NULL
        || member->relative_path[0] == '\0')
        return -1;
    *member_fd = -1;
    current = openat(generation_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0)
        return -1;
    memcpy(copy, member->relative_path, strlen(member->relative_path) + 1);
    component = copy;
    while ((next = strchr(component, '/')) != NULL) {
        *next = '\0';
        if (component[0] == '\0' || strcmp(component, ".") == 0
            || strcmp(component, "..") == 0)
            goto done;
        child = openat(current, component,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child < 0)
            goto done;
        close(current);
        current = child;
        child = -1;
        component = next + 1;
    }
    if (component[0] == '\0' || strcmp(component, ".") == 0
        || strcmp(component, "..") == 0)
        goto done;
    child = openat(current, component, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (child < 0 || plamen_install_receipt_member_revalidate(child, member) != 0)
        goto done;
    *member_fd = child;
    child = -1;
    result = 0;
done:
    if (child >= 0)
        close(child);
    if (current >= 0)
        close(current);
    memset(copy, 0, sizeof(copy));
    return result;
}
