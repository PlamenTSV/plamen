#ifndef PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_CENSUS_H
#define PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_CENSUS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_CENSUS_VERSION 1U
#define PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_NAME_MAX 31U
#define PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RELATIVE_MAX 127U
#define PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_COUNT_MAX 2U
#define PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_ROLE_SCRATCH 5U

struct plamen_broker_v2_specialized_output_spec {
    uint32_t version;
    char name[PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_NAME_MAX + 1U];
    uint16_t role;
    char relative_path[PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RELATIVE_MAX + 1U];
    uint64_t max_entries;
    uint64_t max_expanded_bytes;
};

struct plamen_broker_v2_specialized_output_tree {
    uint32_t version;
    uint16_t role;
    char name[PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_NAME_MAX + 1U];
    char relative_path[PLAMEN_BROKER_V2_SPECIALIZED_OUTPUT_RELATIVE_MAX + 1U];
    uint8_t tree_sha256[32];
    uint64_t entry_count;
    uint64_t expanded_bytes;
};

struct plamen_broker_v2_specialized_tree_identity {
    uint32_t version;
    uint8_t tree_sha256[32];
    uint64_t entry_count;
    uint64_t expanded_bytes;
};

/* Census an already retained directory root without reopening by pathname. */
int plamen_broker_v2_specialized_tree_recensus_fd(
    int root_fd, uint64_t max_entries, uint64_t max_expanded_bytes,
    struct plamen_broker_v2_specialized_tree_identity *identity);

/*
 * Recensuses exact output roots beneath one retained scratch directory.
 * The digest is byte-identical to Python's PLAMEN_CANONICAL_TREE_SHA256_V1:
 * sorted raw filesystem names and canonical JSON directory/file rows.  The
 * walk never follows symlinks, crosses devices, accepts hardlinks/special
 * files, or reopens an absolute pathname.
 */
int plamen_broker_v2_specialized_output_recensus(
    int scratch_fd,
    const struct plamen_broker_v2_specialized_output_spec *specs,
    size_t spec_count,
    struct plamen_broker_v2_specialized_output_tree *trees);

#ifdef __cplusplus
}
#endif

#endif
