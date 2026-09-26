#ifndef PLAMEN_NATIVE_IMAGE_MEMBER_RECEIPT_V2_H
#define PLAMEN_NATIVE_IMAGE_MEMBER_RECEIPT_V2_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_IMAGE_MEMBER_RECEIPT_V2_VERSION 2U
#define PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE 256U
#define PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ROW_SIZE 320U
#define PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT 9U
#define PLAMEN_IMAGE_MEMBER_RECEIPT_V2_SIZE \
    (PLAMEN_IMAGE_MEMBER_RECEIPT_V2_HEADER_SIZE \
    + PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT \
        * PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ROW_SIZE)
#define PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ID_SIZE 33U
#define PLAMEN_IMAGE_MEMBER_RECEIPT_V2_PATH_SIZE 241U
#define PLAMEN_IMAGE_MEMBER_RECEIPT_V2_FLAG_EXECUTABLE 1U
#define PLAMEN_IMAGE_MEMBER_RECEIPT_V2_FLAG_PYTHON_OR_JS 2U

struct plamen_image_member_receipt_v2_expected {
    uint8_t oci_manifest_sha256[32];
    uint8_t runtime_package_manifest_sha256[32];
    uint8_t image_closure_sha256[32];
    uint8_t closure_census_sha256[32];
    uint8_t materialization_receipt_sha256[32];
    uint8_t roster_sha256[32];
    uint8_t policy_sha256[32];
};

struct plamen_image_member_receipt_v2_encode_bindings {
    uint8_t oci_manifest_sha256[32];
    uint8_t runtime_package_manifest_sha256[32];
    uint8_t image_closure_sha256[32];
    uint8_t closure_census_sha256[32];
    uint8_t materialization_receipt_sha256[32];
    uint8_t policy_sha256[32];
};

struct plamen_image_member_receipt_v2_member {
    uint16_t ordinal;
    uint16_t flags;
    uint16_t mode;
    uint64_t size;
    uint8_t sha256[32];
    char id[PLAMEN_IMAGE_MEMBER_RECEIPT_V2_ID_SIZE];
    char path[PLAMEN_IMAGE_MEMBER_RECEIPT_V2_PATH_SIZE];
};

struct plamen_image_member_receipt_v2 {
    struct plamen_image_member_receipt_v2_expected bindings;
    uint16_t member_count;
    struct plamen_image_member_receipt_v2_member
        members[PLAMEN_IMAGE_MEMBER_RECEIPT_V2_MEMBER_COUNT];
};

int plamen_image_member_receipt_v2_validate(
    const uint8_t *bytes,
    size_t size,
    const struct plamen_image_member_receipt_v2_expected *expected,
    struct plamen_image_member_receipt_v2 *output);

/* Reads the exact retained inode with pre/post fstat and pread.  The caller
 * keeps ownership of fd.  receipt_sha256 is the SHA-256 of all receipt bytes. */
int plamen_image_member_receipt_v2_read_fd(
    int fd,
    const struct plamen_image_member_receipt_v2_expected *expected,
    struct plamen_image_member_receipt_v2 *output,
    uint8_t receipt_sha256[32]);

/*
 * Encode an exact receipt from one retained, read-only 9*320-byte row FD.
 * The native encoder derives the row-roster digest; the caller cannot supply
 * it.  output_fd must be a new empty regular read/write file owned by owner.
 */
int plamen_image_member_receipt_v2_encode_rows_fd(
    int rows_fd,
    int output_fd,
    uid_t owner,
    const struct plamen_image_member_receipt_v2_encode_bindings *bindings,
    uint8_t roster_sha256[32],
    uint8_t receipt_sha256[32]);

/* Validate the retained row preimage and derive its native roster digest. */
int plamen_image_member_rows_v2_validate_fd(
    int rows_fd, uint8_t roster_sha256[32]);

#ifdef __cplusplus
}
#endif

#endif
