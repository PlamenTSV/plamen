#define _DARWIN_C_SOURCE 1

#include "plamen_broker_v2_specialized_runtime_effects_handoff.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HANDOFF_MAGIC UINT32_C(0x504c5348)

struct plamen_broker_v2_specialized_runtime_handoff {
    uint32_t magic;
    int runtime_root_fd;
    int runtime_manifest_fd;
    int image_member_receipt_fd;
    struct plamen_install_receipt_member runtime_manifest_member;
    struct plamen_install_receipt_specialized_authority auxiliary;
    struct plamen_broker_v2_specialized_runtime_authority authority;
};

static int duplicate_cloexec(int descriptor);

/*
 * The install receipt retains the generation root, while role-8 recensuses
 * only lib/plamen/runtime.  Walk every fixed component nofollow so an
 * intermediate alias cannot silently change which tree role-8 authenticates.
 */
static int
open_runtime_root(int generation_fd)
{
    static const char *const components[] = { "lib", "plamen", "runtime" };
    struct stat information;
    int current = -1, next = -1;
    size_t index;
    if (generation_fd < 0 || fstat(generation_fd, &information) != 0
        || !S_ISDIR(information.st_mode))
        return -1;
    current = duplicate_cloexec(generation_fd);
    if (current < 0) return -1;
    for (index = 0; index < sizeof(components) / sizeof(components[0]); ++index) {
        next = openat(current, components[index],
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0 || fstat(next, &information) != 0
            || !S_ISDIR(information.st_mode)) {
            if (next >= 0) close(next);
            close(current);
            return -1;
        }
        close(current);
        current = next;
        next = -1;
    }
    return current;
}

static int
duplicate_cloexec(int descriptor)
{
#ifdef F_DUPFD_CLOEXEC
    return fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
#else
    int duplicate = dup(descriptor), flags;
    if (duplicate < 0) return -1;
    flags = fcntl(duplicate, F_GETFD);
    if (flags < 0 || fcntl(duplicate, F_SETFD, flags | FD_CLOEXEC) != 0) {
        close(duplicate); return -1;
    }
    return duplicate;
#endif
}

static const struct plamen_image_member_receipt_v2_member *
member_by_id(const struct plamen_broker_v2_specialized_runtime_authority *authority,
    const char *identifier)
{
    size_t index;
    if (authority == NULL || identifier == NULL) return NULL;
    for (index = 0; index < authority->image_members.member_count; ++index)
        if (strcmp(authority->image_members.members[index].id, identifier) == 0)
            return &authority->image_members.members[index];
    return NULL;
}

static int
load_handoff(const struct plamen_broker_v2_specialized_runtime_handoff *handoff,
    struct plamen_broker_v2_specialized_runtime_authority *authority)
{
    struct plamen_broker_v2_specialized_runtime_authority_open open;
    if (handoff == NULL || authority == NULL) return -1;
    memset(&open, 0, sizeof(open));
    open.version = PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_AUTHORITY_VERSION;
    /* Legacy field name; the manifest API requires the runtime-root FD. */
    open.generation_fd = handoff->runtime_root_fd;
    open.runtime_manifest_fd = handoff->runtime_manifest_fd;
    open.runtime_manifest_member = &handoff->runtime_manifest_member;
    open.image_member_receipt_fd = handoff->image_member_receipt_fd;
    open.auxiliary = &handoff->auxiliary;
    return plamen_broker_v2_specialized_runtime_authority_load(
        &open, authority);
}

int
plamen_broker_v2_specialized_runtime_handoff_create(
    const struct plamen_broker_v2_specialized_runtime_handoff_open *open,
    struct plamen_broker_v2_specialized_runtime_handoff **output)
{
    struct plamen_broker_v2_specialized_runtime_handoff *handoff = NULL;
    if (output != NULL) *output = NULL;
    if (open == NULL || output == NULL
        || open->version != PLAMEN_BROKER_V2_SPECIALIZED_RUNTIME_HANDOFF_VERSION
        || open->generation_fd < 0 || open->runtime_manifest_fd < 0
        || open->runtime_manifest_member == NULL
        || open->image_member_receipt_fd < 0 || open->auxiliary == NULL)
        return -1;
    handoff = calloc(1, sizeof(*handoff));
    if (handoff == NULL) return -1;
    handoff->runtime_root_fd = handoff->runtime_manifest_fd = -1;
    handoff->image_member_receipt_fd = -1;
    handoff->runtime_root_fd = open_runtime_root(open->generation_fd);
    handoff->runtime_manifest_fd = duplicate_cloexec(open->runtime_manifest_fd);
    handoff->image_member_receipt_fd =
        duplicate_cloexec(open->image_member_receipt_fd);
    handoff->runtime_manifest_member = *open->runtime_manifest_member;
    handoff->auxiliary = *open->auxiliary;
    if (handoff->runtime_root_fd < 0 || handoff->runtime_manifest_fd < 0
        || handoff->image_member_receipt_fd < 0
        || load_handoff(handoff, &handoff->authority) != 0) {
        plamen_broker_v2_specialized_runtime_handoff_destroy(handoff);
        return -1;
    }
    handoff->magic = HANDOFF_MAGIC; *output = handoff; return 0;
}

int
plamen_broker_v2_specialized_runtime_handoff_revalidate(
    const struct plamen_broker_v2_specialized_runtime_handoff *handoff)
{
    struct plamen_broker_v2_specialized_runtime_authority observed;
    int result;
    memset(&observed, 0, sizeof(observed));
    if (handoff == NULL || handoff->magic != HANDOFF_MAGIC) return -1;
    result = load_handoff(handoff, &observed) == 0
        && memcmp(observed.authority_sha256,
            handoff->authority.authority_sha256, 32) == 0 ? 0 : -1;
    memset(&observed, 0, sizeof(observed)); return result;
}

int
plamen_broker_v2_specialized_runtime_handoff_apple_runtime(
    struct plamen_broker_v2_specialized_runtime_handoff *handoff,
    uint16_t lane, const char *tool_member_id,
    struct plamen_broker_v2_specialized_apple_runtime *output)
{
    const struct plamen_image_member_receipt_v2_member *worker, *tool;
    const struct plamen_image_member_receipt_v2_member *managed, *js;
    if (output != NULL) memset(output, 0, sizeof(*output));
    if (handoff == NULL || handoff->magic != HANDOFF_MAGIC || output == NULL
        || plamen_broker_v2_specialized_runtime_handoff_revalidate(handoff) != 0
        || (worker = member_by_id(&handoff->authority,
            "specialized_worker")) == NULL
        || (tool = member_by_id(&handoff->authority, tool_member_id)) == NULL
        || (managed = member_by_id(&handoff->authority,
            "managed_provisioner")) == NULL
        || (js = member_by_id(&handoff->authority,
            "js_offline_materializer")) == NULL)
        return -1;
    output->version = PLAMEN_BROKER_V2_SPECIALIZED_REQUEST_CODEC_VERSION;
    memcpy(output->oci_image_sha256,
        handoff->authority.runtime_digests[
            PLAMEN_RUNTIME_PACKAGE_IMAGE_MANIFEST_V2], 32);
    memcpy(output->runtime_manifest_sha256,
        handoff->authority.runtime_manifest_sha256, 32);
    memcpy(output->worker_runtime_sha256, worker->sha256, 32);
    output->worker_runtime_size = worker->size;
    memcpy(output->tool_image_member_sha256, tool->sha256, 32);
    output->tool_image_member_size = tool->size;
    if (lane == PLAMEN_BROKER_V2_SPECIALIZED_MANAGED_EVM) {
        memcpy(output->managed_provisioner_sha256, managed->sha256, 32);
        output->managed_provisioner_size = managed->size;
    } else if (lane == PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER) {
        memcpy(output->js_offline_materializer_sha256, js->sha256, 32);
        output->js_offline_materializer_size = js->size;
    } else if (lane != PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL
        && lane != PLAMEN_BROKER_V2_SPECIALIZED_EVM_PROJECTION)
        return -1;
    return 0;
}

int
plamen_broker_v2_specialized_runtime_handoff_authority_sha256(
    const struct plamen_broker_v2_specialized_runtime_handoff *handoff,
    uint8_t output[32])
{
    if (handoff == NULL || handoff->magic != HANDOFF_MAGIC || output == NULL
        || plamen_broker_v2_specialized_runtime_handoff_revalidate(handoff) != 0)
        return -1;
    memcpy(output, handoff->authority.authority_sha256, 32); return 0;
}

void
plamen_broker_v2_specialized_runtime_handoff_destroy(
    struct plamen_broker_v2_specialized_runtime_handoff *handoff)
{
    if (handoff == NULL) return;
    if (handoff->runtime_root_fd >= 0) close(handoff->runtime_root_fd);
    if (handoff->runtime_manifest_fd >= 0) close(handoff->runtime_manifest_fd);
    if (handoff->image_member_receipt_fd >= 0)
        close(handoff->image_member_receipt_fd);
    memset(handoff, 0, sizeof(*handoff)); free(handoff);
}
