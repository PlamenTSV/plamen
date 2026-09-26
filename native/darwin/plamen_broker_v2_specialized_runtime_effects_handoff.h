#ifndef PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_EFFECTS_HANDOFF_H
#define PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_EFFECTS_HANDOFF_H

#include "plamen_broker_v2_specialized_request.h"
#include "plamen_broker_v2_specialized_runtime_authority.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_HANDOFF_VERSION 1U

struct plamen_broker_v2_specialized_runtime_handoff;

struct plamen_broker_v2_specialized_runtime_handoff_open {
    uint32_t version;
    /* Retained installed-generation root; create opens lib/plamen/runtime. */
    int generation_fd;
    int runtime_manifest_fd;
    const struct plamen_install_receipt_member *runtime_manifest_member;
    int image_member_receipt_fd;
    const struct plamen_install_receipt_specialized_authority *auxiliary;
};

/*
 * Opens the fixed runtime root descriptor-relative beneath generation_fd,
 * duplicates the other two descriptors, and copies both signed authority
 * rows.  The handoff owns every resulting descriptor until destroy.
 */
int plamen_broker_v2_specialized_runtime_handoff_create(
    const struct plamen_broker_v2_specialized_runtime_handoff_open *,
    struct plamen_broker_v2_specialized_runtime_handoff **);

/* Replays the complete role8/root/auxiliary/member chain byte-for-byte. */
int plamen_broker_v2_specialized_runtime_handoff_revalidate(
    const struct plamen_broker_v2_specialized_runtime_handoff *);

/*
 * Selects one exact fixed member by ID.  The lane controls whether the JS or
 * managed provisioner is present; unrelated auxiliary fields stay zero so the
 * specialized request codec cannot accept a cross-lane launch.
 */
int plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
    struct plamen_broker_v2_specialized_runtime_handoff *,
    uint16_t lane, const char *tool_member_id,
    struct plamen_broker_v2_specialized_apple_runtime *);

int plamen_broker_v2_specialized_runtime_handoff_authority_sha256(
    const struct plamen_broker_v2_specialized_runtime_handoff *, uint8_t [32]);

void plamen_broker_v2_specialized_runtime_handoff_destroy(
    struct plamen_broker_v2_specialized_runtime_handoff *);

#ifdef __cplusplus
}
#endif

#endif
