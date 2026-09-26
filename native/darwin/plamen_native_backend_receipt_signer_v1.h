#ifndef PLAMEN_NATIVE_BACKEND_RECEIPT_SIGNER_V1_H
#define PLAMEN_NATIVE_BACKEND_RECEIPT_SIGNER_V1_H

#include "plamen_native_source_bootstrap_coordinator_v1.h"

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_NATIVE_BACKEND_RECEIPT_SIGNER_V1_VERSION 1U
#define PLAMEN_NATIVE_BACKEND_RECEIPT_SIGNER_V1_FOOTER_SIZE 512U
#define PLAMEN_NATIVE_BACKEND_RECEIPT_SIGNER_V1_MAX_UNSIGNED_SIZE \
    (16U * 1024U * 1024U)

/* Private signing authority.  Its Ed25519 private key has no export API. */
struct plamen_native_backend_receipt_signer_v1;

struct plamen_native_backend_signed_projection_v1 {
    uint16_t role;
    int verifier_public_key_fd;
    int semantic_receipt_fd;
    uint64_t semantic_receipt_size;
    uint8_t verifier_public_key_sha256[32];
    uint8_t semantic_receipt_sha256[32];
    uint8_t payload_sha256[32];
    uint64_t payload_size;
    uint8_t source_manifest_sha256[32];
    uint64_t source_manifest_size;
    uint8_t policy_sha256[32];
};

/*
 * Create one install-generation signer and publish its exact 32-byte public
 * key.  `public_key_writer_fd` and later semantic writers are ownership-
 * transferring descriptors: they are invalidated and closed on every return.
 * Each reader names the same initially-empty owner-private regular vnode and
 * remains caller-owned.  No function exposes private-key bytes or a generic
 * byte-signing primitive.
 */
int plamen_native_backend_receipt_signer_create_v1(uid_t owner_uid,
    int public_key_writer_fd, int public_key_reader_fd,
    struct plamen_native_backend_receipt_signer_v1 **signer);

/*
 * Sign only a canonical unsigned Codex/Claude acquisition receipt.  Payload,
 * source-manifest, and fixed compiled policy identities are recomputed by the
 * native authority; no caller-provided digest is accepted.  The published
 * descriptor contains exact canonical signed JSON followed immediately by the
 * PLMOP4R1 512-byte native producer footer consumed by operation 4.
 */
int plamen_native_backend_receipt_sign_v1(
    struct plamen_native_backend_receipt_signer_v1 *signer,
    uint16_t role, int unsigned_receipt_fd, int payload_fd,
    int source_manifest_fd, int semantic_writer_fd, int semantic_reader_fd,
    struct plamen_native_backend_signed_projection_v1 *projection);

void plamen_native_backend_signed_projection_dispose_v1(
    struct plamen_native_backend_signed_projection_v1 *projection);
void plamen_native_backend_receipt_signer_dispose_v1(
    struct plamen_native_backend_receipt_signer_v1 *signer);

#ifdef __cplusplus
}
#endif

#endif
