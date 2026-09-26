#include "../darwin/plamen_native_image_member_receipt_v2.h"

#include <CommonCrypto/CommonDigest.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct member_fixture { const char *id; const char *path; uint16_t flags; };

static const struct member_fixture fixtures[] = {
    {"forge", "/usr/local/lib/plamen/toolchains/foundry/bin/forge", 1U},
    {"js_offline_materializer", "/usr/local/libexec/plamen-js-offline-materializer.py", 2U},
    {"managed_provisioner", "/usr/local/libexec/plamen-managed-evm-provisioner.py", 2U},
    {"managed_python", "/usr/local/lib/plamen/python/bin/python3.12", 1U},
    {"medusa", "/usr/local/lib/plamen/toolchains/medusa/bin/medusa", 1U},
    {"opengrep", "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep", 1U},
    {"slither", "/usr/local/lib/plamen/toolchains/managed-evm/bin/slither", 1U},
    {"solc", "/usr/local/lib/plamen/toolchains/solc-amd64/solc", 1U},
    {"specialized_worker", "/opt/plamen/scripts/posix_specialized_tool_worker.py", 2U},
};

static void put16(uint8_t *out, uint16_t value)
{ out[0] = (uint8_t)(value >> 8); out[1] = (uint8_t)value; }

static void put64(uint8_t *out, uint64_t value)
{
    size_t index;
    for (index = 0; index < 8U; ++index) {
        out[7U - index] = (uint8_t)value;
        value >>= 8;
    }
}

static int make_receipt(
    uint8_t bytes[PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE],
    struct plamen_image_member_receipt_v2_expected *expected)
{
    size_t index;
    memset(bytes, 0, PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE);
    memset(expected, 0, sizeof(*expected));
    memcpy(bytes, "PLIMGV2", 7U);
    put16(bytes + 8U, 2U); put16(bytes + 10U, 256U);
    put16(bytes + 12U, 320U);
    put16(bytes + 14U, PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT);
    for (index = 0; index < 7U; ++index)
        memset((uint8_t *)expected + index * 32U, (int)(index + 1U), 32U);
    memcpy(bytes + 16U, expected->oci_manifest_sha256, 32U);
    memcpy(bytes + 48U, expected->runtime_package_manifest_sha256, 32U);
    memcpy(bytes + 80U, expected->image_closure_sha256, 32U);
    memcpy(bytes + 112U, expected->closure_census_sha256, 32U);
    memcpy(bytes + 144U, expected->materialization_receipt_sha256, 32U);
    memcpy(bytes + 208U, expected->policy_sha256, 32U);
    for (index = 0; index < PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT; ++index) {
        uint8_t *row = bytes + 256U + index * 320U;
        size_t id_size = strlen(fixtures[index].id);
        size_t path_size = strlen(fixtures[index].path);
        put16(row, (uint16_t)index); put16(row + 2U, fixtures[index].flags);
        put16(row + 4U, fixtures[index].flags == 1U ? 0555U : 0444U);
        row[6U] = (uint8_t)id_size; row[7U] = (uint8_t)path_size;
        put64(row + 8U, 100U + index);
        memset(row + 16U, (int)(0x20U + index), 32U);
        memcpy(row + 48U, fixtures[index].id, id_size);
        memcpy(row + 80U, fixtures[index].path, path_size);
    }
    if (CC_SHA256(bytes + 256U,
            PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT * 320U,
            expected->roster_sha256) == NULL)
        return -1;
    memcpy(bytes + 176U, expected->roster_sha256, 32U);
    return 0;
}

int main(void)
{
    uint8_t bytes[PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE];
    struct plamen_image_member_receipt_v2_expected expected;
    struct plamen_image_member_receipt_v2 output;
    if (make_receipt(bytes, &expected) != 0
            || plamen_image_member_receipt_v2_validate(
                bytes, sizeof(bytes), &expected, &output) != 0
            || output.member_count != PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT
            || strcmp(output.members[3].id, "managed_python") != 0
            || strcmp(output.members[4].id, "medusa") != 0
            || strcmp(output.members[8].path,
                "/opt/plamen/scripts/posix_specialized_tool_worker.py") != 0)
        return 1;
    bytes[256U + 4U * 320U + 80U] ^= 1U;
    if (plamen_image_member_receipt_v2_validate(
            bytes, sizeof(bytes), &expected, &output) == 0)
        return 2;
    bytes[256U + 4U * 320U + 80U] ^= 1U;
    bytes[240U] = 1U;
    if (plamen_image_member_receipt_v2_validate(
            bytes, sizeof(bytes), &expected, &output) == 0)
        return 3;
    puts("native image-member receipt v2: ok");
    return 0;
}
