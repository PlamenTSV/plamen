#include "plamen_native_image_member_receipt_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint8_t magic[8] = {'P','L','I','M','G','V','2',0};

struct fixed_member {
    const char *id;
    const char *path;
    uint16_t flags;
};

static const struct fixed_member fixed_members[] = {
    {"forge", "/usr/local/lib/plamen/toolchains/foundry/bin/forge", 1U},
    {"js_offline_materializer", "/usr/local/libexec/plamen-js-offline-materializer.py", 2U},
    {"managed_provisioner", "/usr/local/libexec/plamen-managed-evm-provisioner.py", 2U},
    {"managed_python", "/usr/local/lib/plamen/python/bin/python3.12", 1U},
    /* Release provenance binds Medusa v1.5.1; this row binds its exact bytes. */
    {"medusa", "/usr/local/lib/plamen/toolchains/medusa/bin/medusa", 1U},
    {"opengrep", "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep", 1U},
    {"slither", "/usr/local/lib/plamen/toolchains/managed-evm/bin/slither", 1U},
    {"solc", "/usr/local/lib/plamen/toolchains/solc-amd64/solc", 1U},
    {"specialized_worker", "/opt/plamen/scripts/posix_specialized_tool_worker.py", 2U},
};

static uint16_t be16(const uint8_t *value)
{
    return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static void store16(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)(value >> 8U);
    output[1] = (uint8_t)value;
}

static uint64_t be64(const uint8_t *value)
{
    uint64_t result = 0;
    size_t index;
    for (index = 0; index < 8U; ++index)
        result = (result << 8) | value[index];
    return result;
}

static int constant_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < size; ++index) difference |= left[index] ^ right[index];
    return difference == 0;
}

static int all_zero(const uint8_t *value, size_t size)
{
    uint8_t result = 0;
    size_t index;
    for (index = 0; index < size; ++index) result |= value[index];
    return result == 0;
}

static int zero_bytes(const uint8_t *value, size_t size)
{
    return all_zero(value, size);
}

static int complete_exact_record(int fd, const uint8_t *record, size_t size,
    uid_t owner, const struct stat *before)
{
    uint8_t buffer[512];
    struct stat after_read, after_write;
    size_t offset = 0U, prefix;
    int flags;
    if (before == NULL || before->st_size < 0
            || (uint64_t)before->st_size > size
            || (flags = fcntl(fd, F_GETFL)) < 0
            || ((before->st_mode & 07777U) == 0600U
                ? (flags & O_ACCMODE) != O_RDWR
                : ((before->st_mode & 07777U) != 0400U
                    || before->st_size != (off_t)size
                    || (flags & O_ACCMODE) != O_RDONLY)))
        return -1;
    prefix = (size_t)before->st_size;
    while (offset < prefix) {
        size_t amount = prefix - offset;
        ssize_t observed;
        if (amount > sizeof(buffer)) amount = sizeof(buffer);
        observed = pread(fd, buffer, amount, (off_t)offset);
        if (observed <= 0 || (size_t)observed != amount
                || memcmp(buffer, record + offset, amount) != 0) {
            memset(buffer, 0, sizeof(buffer));
            return -1;
        }
        offset += amount;
    }
    memset(buffer, 0, sizeof(buffer));
    if (fstat(fd, &after_read) != 0
            || after_read.st_dev != before->st_dev
            || after_read.st_ino != before->st_ino
            || after_read.st_mode != before->st_mode
            || after_read.st_uid != before->st_uid
            || after_read.st_gid != before->st_gid
            || after_read.st_nlink != before->st_nlink
            || after_read.st_size != before->st_size)
        return -1;
    if ((before->st_mode & 07777U) == 0400U)
        return 0;
    while (offset < size) {
        ssize_t amount = pwrite(fd, record + offset, size - offset,
            (off_t)offset);
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    if (fsync(fd) != 0 || fchmod(fd, 0400U) != 0 || fsync(fd) != 0
            || fstat(fd, &after_write) != 0
            || after_write.st_dev != before->st_dev
            || after_write.st_ino != before->st_ino
            || after_write.st_uid != owner || after_write.st_nlink != 1
            || after_write.st_size != (off_t)size
            || (after_write.st_mode & 07777U) != 0400U)
        return -1;
    return 0;
}

static int expected_valid(
    const struct plamen_image_member_receipt_v2_expected *expected)
{
    const uint8_t *bytes = (const uint8_t *)expected;
    size_t index;
    if (expected == NULL) return 0;
    for (index = 0; index < 7U; ++index)
        if (all_zero(bytes + index * 32U, 32U)) return 0;
    return 1;
}

int plamen_image_member_receipt_v2_validate(
    const uint8_t *bytes,
    size_t size,
    const struct plamen_image_member_receipt_v2_expected *expected,
    struct plamen_image_member_receipt_v2 *output)
{
    uint8_t roster[32];
    size_t index;
    if (bytes == NULL || output == NULL || !expected_valid(expected)
            || size != PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE
            || !constant_equal(bytes, magic, sizeof(magic))
            || be16(bytes + 8U) != PLAMEN_IMAGE_MEMBER_RECEIPT_V2_VERSION
            || be16(bytes + 10U) != PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE
            || be16(bytes + 12U) != PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ROW_SIZE
            || be16(bytes + 14U) != PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT
            || !constant_equal(bytes + 16U, expected->oci_manifest_sha256, 32U)
            || !constant_equal(bytes + 48U, expected->runtime_package_manifest_sha256, 32U)
            || !constant_equal(bytes + 80U, expected->image_closure_sha256, 32U)
            || !constant_equal(bytes + 112U, expected->closure_census_sha256, 32U)
            || !constant_equal(bytes + 144U, expected->materialization_receipt_sha256, 32U)
            || !constant_equal(bytes + 176U, expected->roster_sha256, 32U)
            || !constant_equal(bytes + 208U, expected->policy_sha256, 32U)
            || !zero_bytes(bytes + 240U, 16U)) return -1;
    if (CC_SHA256(bytes + PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE,
            (CC_LONG)(PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT
                * PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ROW_SIZE), roster) == NULL
            || !constant_equal(roster, bytes + 176U, 32U)) return -1;
    memset(output, 0, sizeof(*output));
    memcpy(&output->bindings, expected, sizeof(*expected));
    output->member_count = PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT;
    for (index = 0; index < PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT; ++index) {
        const uint8_t *row = bytes + PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE
            + index * PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ROW_SIZE;
        struct plamen_image_member_receipt_v2_member *member = &output->members[index];
        size_t id_size = row[6U], path_size = row[7U];
        uint16_t mode = be16(row + 4U), flags = be16(row + 2U);
        if (be16(row) != index || flags != fixed_members[index].flags
                || id_size == 0U || id_size > 32U
                || path_size == 0U || path_size > 240U
                || strlen(fixed_members[index].id) != id_size
                || strlen(fixed_members[index].path) != path_size
                || !constant_equal(row + 48U,
                    (const uint8_t *)fixed_members[index].id, id_size)
                || !constant_equal(row + 80U,
                    (const uint8_t *)fixed_members[index].path, path_size)
                || !zero_bytes(row + 48U + id_size, 32U - id_size)
                || !zero_bytes(row + 80U + path_size, 240U - path_size)
                || be64(row + 8U) == 0U
                || all_zero(row + 16U, 32U)
                || (mode & 0022U) != 0U || (mode & 0400U) == 0U
                || (flags == PLAMEN_IMAGE_MEMBER_RECEIPT_V2_FLAG_EXECUTABLE
                    && (mode & 0111U) == 0U)) return -1;
        member->ordinal = (uint16_t)index;
        member->flags = flags;
        member->mode = mode;
        member->size = be64(row + 8U);
        memcpy(member->sha256, row + 16U, 32U);
        memcpy(member->id, row + 48U, id_size);
        memcpy(member->path, row + 80U, path_size);
    }
    return 0;
}

int plamen_image_member_receipt_v2_read_fd(
    int fd,
    const struct plamen_image_member_receipt_v2_expected *expected,
    struct plamen_image_member_receipt_v2 *output,
    uint8_t receipt_sha256[32])
{
    uint8_t bytes[PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE];
    struct stat before, after;
    size_t offset = 0;
    if (fd < 0 || receipt_sha256 == NULL || fstat(fd, &before) != 0
            || !S_ISREG(before.st_mode) || before.st_nlink != 1
            || before.st_size != (off_t)sizeof(bytes)
            || (before.st_mode & 0022) != 0) return -1;
    while (offset < sizeof(bytes)) {
        ssize_t amount = pread(fd, bytes + offset, sizeof(bytes) - offset,
            (off_t)offset);
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    if (fstat(fd, &after) != 0
            || before.st_dev != after.st_dev || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode || before.st_size != after.st_size
            || before.st_nlink != after.st_nlink) return -1;
    if (plamen_image_member_receipt_v2_validate(
            bytes, sizeof(bytes), expected, output) != 0
            || CC_SHA256(bytes, (CC_LONG)sizeof(bytes), receipt_sha256) == NULL)
        return -1;
    return 0;
}

int
plamen_image_member_rows_v2_validate_fd(int rows_fd,
    uint8_t roster_sha256[32])
{
    enum { ROW_BYTES = PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT
        * PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ROW_SIZE };
    uint8_t record[PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE];
    struct plamen_image_member_receipt_v2_expected expected;
    struct plamen_image_member_receipt_v2 decoded;
    struct stat before, after;
    size_t offset = 0U;
    int flags, result = -1;
    if (roster_sha256 != NULL) memset(roster_sha256, 0, 32U);
    memset(record, 0, sizeof(record));
    memset(&expected, 0x5a, sizeof(expected));
    memset(&decoded, 0, sizeof(decoded));
    if (rows_fd < 0 || roster_sha256 == NULL
            || (flags = fcntl(rows_fd, F_GETFL)) < 0
            || (flags & O_ACCMODE) != O_RDONLY
            || fstat(rows_fd, &before) != 0
            || !S_ISREG(before.st_mode) || before.st_nlink != 1
            || before.st_size != ROW_BYTES || (before.st_mode & 0022U) != 0U)
        goto done;
    while (offset < ROW_BYTES) {
        ssize_t amount = pread(rows_fd,
            record + PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE + offset,
            ROW_BYTES - offset, (off_t)offset);
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    if (fstat(rows_fd, &after) != 0
            || before.st_dev != after.st_dev || before.st_ino != after.st_ino
            || before.st_mode != after.st_mode || before.st_size != after.st_size
            || before.st_nlink != after.st_nlink)
        goto done;
    memcpy(record, magic, sizeof(magic));
    store16(record + 8U, PLAMEN_IMAGE_MEMBER_RECEIPT_V2_VERSION);
    store16(record + 10U, PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE);
    store16(record + 12U, PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ROW_SIZE);
    store16(record + 14U, PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT);
    memcpy(record + 16U, expected.oci_manifest_sha256, 32U);
    memcpy(record + 48U, expected.runtime_package_manifest_sha256, 32U);
    memcpy(record + 80U, expected.image_closure_sha256, 32U);
    memcpy(record + 112U, expected.closure_census_sha256, 32U);
    memcpy(record + 144U, expected.materialization_receipt_sha256, 32U);
    if (CC_SHA256(record + PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE,
            (CC_LONG)ROW_BYTES, expected.roster_sha256) == NULL)
        goto done;
    memcpy(record + 176U, expected.roster_sha256, 32U);
    memcpy(record + 208U, expected.policy_sha256, 32U);
    if (plamen_image_member_receipt_v2_validate(record, sizeof(record),
            &expected, &decoded) != 0)
        goto done;
    memcpy(roster_sha256, expected.roster_sha256, 32U);
    result = 0;
done:
    if (result != 0 && roster_sha256 != NULL)
        memset(roster_sha256, 0, 32U);
    memset(record, 0, sizeof(record));
    memset(&expected, 0, sizeof(expected));
    memset(&decoded, 0, sizeof(decoded));
    return result;
}

int plamen_image_member_receipt_v2_encode_rows_fd(
    int rows_fd, int output_fd, uid_t owner,
    const struct plamen_image_member_receipt_v2_encode_bindings *bindings,
    uint8_t roster_sha256[32], uint8_t receipt_sha256[32])
{
    enum { ROW_BYTES = PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT
        * PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ROW_SIZE };
    uint8_t record[PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE];
    struct plamen_image_member_receipt_v2_expected expected;
    struct plamen_image_member_receipt_v2 decoded;
    struct stat rows_before, rows_after, output_before;
    int rows_flags, output_flags;
    size_t offset = 0U;
    int result = -1;
    if (roster_sha256 != NULL) memset(roster_sha256, 0, 32U);
    if (receipt_sha256 != NULL) memset(receipt_sha256, 0, 32U);
    memset(record, 0, sizeof(record));
    memset(&expected, 0, sizeof(expected));
    memset(&decoded, 0, sizeof(decoded));
    if (rows_fd < 0 || output_fd < 0 || bindings == NULL
            || roster_sha256 == NULL || receipt_sha256 == NULL
            || (rows_flags = fcntl(rows_fd, F_GETFL)) < 0
            || (rows_flags & O_ACCMODE) != O_RDONLY
            || (output_flags = fcntl(output_fd, F_GETFL)) < 0
            || fstat(rows_fd, &rows_before) != 0
            || fstat(output_fd, &output_before) != 0
            || !S_ISREG(rows_before.st_mode) || rows_before.st_nlink != 1
            || rows_before.st_size != ROW_BYTES
            || (rows_before.st_mode & 0022U) != 0U
            || !S_ISREG(output_before.st_mode) || output_before.st_nlink != 1
            || output_before.st_uid != owner || output_before.st_size < 0)
        goto done;
    while (offset < ROW_BYTES) {
        ssize_t amount = pread(rows_fd,
            record + PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE + offset,
            ROW_BYTES - offset, (off_t)offset);
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    if (fstat(rows_fd, &rows_after) != 0
            || rows_before.st_dev != rows_after.st_dev
            || rows_before.st_ino != rows_after.st_ino
            || rows_before.st_mode != rows_after.st_mode
            || rows_before.st_size != rows_after.st_size
            || rows_before.st_nlink != rows_after.st_nlink)
        goto done;
    memcpy(record, magic, sizeof(magic));
    store16(record + 8U, PLAMEN_IMAGE_MEMBER_RECEIPT_V2_VERSION);
    store16(record + 10U, PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE);
    store16(record + 12U, PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ROW_SIZE);
    store16(record + 14U, PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT);
    memcpy(record + 16U, bindings->oci_manifest_sha256, 32U);
    memcpy(record + 48U, bindings->runtime_package_manifest_sha256, 32U);
    memcpy(record + 80U, bindings->image_closure_sha256, 32U);
    memcpy(record + 112U, bindings->closure_census_sha256, 32U);
    memcpy(record + 144U, bindings->materialization_receipt_sha256, 32U);
    if (CC_SHA256(record + PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE,
            (CC_LONG)ROW_BYTES, expected.roster_sha256) == NULL)
        goto done;
    memcpy(record + 176U, expected.roster_sha256, 32U);
    memcpy(record + 208U, bindings->policy_sha256, 32U);
    memcpy(expected.oci_manifest_sha256,
        bindings->oci_manifest_sha256, 32U);
    memcpy(expected.runtime_package_manifest_sha256,
        bindings->runtime_package_manifest_sha256, 32U);
    memcpy(expected.image_closure_sha256,
        bindings->image_closure_sha256, 32U);
    memcpy(expected.closure_census_sha256,
        bindings->closure_census_sha256, 32U);
    memcpy(expected.materialization_receipt_sha256,
        bindings->materialization_receipt_sha256, 32U);
    memcpy(expected.policy_sha256, bindings->policy_sha256, 32U);
    if (plamen_image_member_receipt_v2_validate(record, sizeof(record),
            &expected, &decoded) != 0
            || CC_SHA256(record, (CC_LONG)sizeof(record),
                receipt_sha256) == NULL)
        goto done;
    if (complete_exact_record(output_fd, record, sizeof(record), owner,
            &output_before) != 0)
        goto done;
    memcpy(roster_sha256, expected.roster_sha256, 32U);
    result = 0;
done:
    if (result != 0) {
        memset(roster_sha256, 0, 32U);
        memset(receipt_sha256, 0, 32U);
    }
    memset(record, 0, sizeof(record));
    memset(&expected, 0, sizeof(expected));
    memset(&decoded, 0, sizeof(decoded));
    return result;
}
