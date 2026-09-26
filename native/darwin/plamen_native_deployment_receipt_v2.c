#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_native_deployment_receipt_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void store_u16(uint8_t *p, uint16_t value)
{ p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value; }

static void
store_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

int
plamen_native_darwin_deployment_receipt_bytes_v2(
    const struct plamen_install_receipt *receipt,
    uint8_t output[PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_SIZE])
{
    static const uint8_t magic[8] = {
        'P', 'L', 'M', 'D', 'P', 'R', '2', 0
    };
    if (receipt == NULL || output == NULL) { errno = EINVAL; return -1; }
    memset(output, 0, PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_SIZE);
    memcpy(output, magic, sizeof(magic));
    store_u16(output + 8U, 2U); store_u16(output + 10U, 224U);
    store_u32(output + 12U, PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_SIZE);
    memcpy(output + 16U, receipt->generation_id_sha256, 32U);
    memcpy(output + 48U, receipt->receipt_sha256, 32U);
    memcpy(output + 80U,
        receipt->members[PLAMEN_INSTALL_MEMBER_LAUNCHER - 1U].sha256, 32U);
    memcpy(output + 112U,
        receipt->members[PLAMEN_INSTALL_MEMBER_SERVICE - 1U].sha256, 32U);
    memcpy(output + 144U, receipt->broker_launchd_plist.sha256, 32U);
    memcpy(output + 176U, receipt->custody_launchd_plist.sha256, 32U);
    store_u32(output + 208U, 7U);
    if (CC_SHA256(output, 224U, output + 224U) == NULL) {
        errno = EIO; return -1;
    }
    return 0;
}

static int
read_exact_bytes(int fd, uint8_t *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = pread(fd, bytes + offset, size - offset,
            (off_t)offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return pread(fd, bytes, 1, (off_t)size) == 0 ? 0 : -1;
}

int
plamen_native_darwin_deployment_receipt_validate_v2(int fd,
    const struct plamen_install_receipt *receipt)
{
    uint8_t expected[PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_SIZE];
    uint8_t observed[PLAMEN_DARWIN_DEPLOYMENT_RECEIPT_V2_SIZE];
    struct stat before, after;
    int result = -1;
    memset(expected, 0, sizeof(expected)); memset(observed, 0, sizeof(observed));
    if (fd < 0
        || plamen_native_darwin_deployment_receipt_bytes_v2(
            receipt, expected) != 0
        || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size != (off_t)sizeof(observed)
        || (before.st_mode & 07777) != 0400 || before.st_uid != getuid()
        || read_exact_bytes(fd, observed, sizeof(observed)) != 0
        || fstat(fd, &after) != 0 || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid || before.st_gid != after.st_gid
        || before.st_nlink != after.st_nlink || before.st_size != after.st_size
        || memcmp(expected, observed, sizeof(expected)) != 0)
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        memset(expected, 0, sizeof(expected)); memset(observed, 0, sizeof(observed));
        if (result != 0) errno = saved;
        return result;
    }
}
