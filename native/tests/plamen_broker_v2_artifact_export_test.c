#define _DARWIN_C_SOURCE 1

#include "../darwin/plamen_broker_v2_artifact_export.h"
#include "../include/plamen_broker_v2.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static int
write_file_at(int parent, const char *name, const char *value)
{
    size_t size = strlen(value), offset = 0;
    int descriptor = openat(parent, name,
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) return -1;
    while (offset < size) {
        ssize_t amount = write(descriptor, value + offset, size - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) { (void)close(descriptor); return -1; }
        offset += (size_t)amount;
    }
    if (fsync(descriptor) != 0 || close(descriptor) != 0) return -1;
    return fsync(parent);
}

static int
read_file_at(int parent, const char *name, char *output, size_t capacity)
{
    ssize_t amount;
    int descriptor = openat(parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || capacity < 2U) return -1;
    amount = read(descriptor, output, capacity - 1U);
    if (amount < 0 || close(descriptor) != 0) return -1;
    output[(size_t)amount] = '\0';
    return 0;
}

static void
fill_digest(uint8_t output[32], uint8_t seed)
{
    size_t index;
    for (index = 0; index < 32U; ++index)
        output[index] = (uint8_t)(seed + (uint8_t)index);
}

static int
decode_hex32(const char *value, uint8_t output[32])
{
    size_t index;
    for (index = 0; index < 32U; ++index) {
        unsigned char a = (unsigned char)value[index * 2U];
        unsigned char b = (unsigned char)value[index * 2U + 1U];
        unsigned int high = a <= '9' ? (unsigned int)(a - '0')
            : (unsigned int)(a - 'a' + 10U);
        unsigned int low = b <= '9' ? (unsigned int)(b - '0')
            : (unsigned int)(b - 'a' + 10U);
        if (!((a >= '0' && a <= '9') || (a >= 'a' && a <= 'f'))
            || !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')))
            return -1;
        output[index] = (uint8_t)((high << 4U) | low);
    }
    return value[64] == '\0' ? 0 : -1;
}

static int
make_directory_at(int parent, const char *name)
{
    return mkdirat(parent, name, 0700);
}

int
main(void)
{
    char root_template[] = "/tmp/plamen-artifact-export.XXXXXX";
    char *root_path;
    char output[128];
    uint8_t terminal[32], destination[32], source_content[32], existing[32];
    uint8_t expected_census[32], expected_manifest[32], expected_export[32];
    uint8_t expected_postpublication[32];
    struct plamen_broker_v2_artifact_session session;
    struct plamen_broker_v2_artifact_census census, replacement_census;
    struct plamen_broker_v2_artifact_publication publication;
    struct plamen_broker_v2_artifact_export_receipt receipt;
    struct plamen_broker_v2_artifact_export_receipt published_receipt;
    struct plamen_broker_v2_artifact_export_receipt reopened_receipt;
    struct plamen_broker_v2_artifact_export_receipt tampered_receipt;
    struct plamen_broker_v2_artifact_spec specs[3];
    struct stat source_before, source_after, target_before, target_after;
    int root = -1, scratch = -1, target = -1, failed_target = -1;
    int existing_fd = -1;
    const char first[] = "# Audit report\n\nfirst\n";
    const char second[] = "# Audit report\n\nsecond\n";
    const char checkpoint[] = "{\"stage\":\"done\"}\n";

    root_path = mkdtemp(root_template);
    if (root_path == NULL) return 1;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0 || make_directory_at(root, "scratch") != 0
        || make_directory_at(root, "target") != 0
        || make_directory_at(root, "failed-target") != 0)
        return 2;
    scratch = openat(root, "scratch",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    target = openat(root, "target",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    failed_target = openat(root, "failed-target",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scratch < 0 || target < 0 || failed_target < 0
        || write_file_at(scratch, "AUDIT_REPORT.md", first) != 0
        || write_file_at(scratch, "_v2_checkpoint.json", checkpoint) != 0)
        return 3;

    fill_digest(terminal, 11U);
    fill_digest(destination, 71U);
    fill_digest(source_content, 101U);
    memset(&session, 0, sizeof(session));
    session.version = PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION;
    session.scratch_fd = scratch;
    session.target_fd = target;
    session.attempt_id = "attempt-1";
    session.run_id = "run-1";
    session.census_handle = "opaque:1111111111111111111111111111111111111111111111111111111111111111";
    session.destination_handle = "opaque:2222222222222222222222222222222222222222222222222222222222222222";
    session.terminal_sha256 = terminal;
    session.destination_identity_sha256 = destination;
    session.source_content_sha256 = source_content;
    memset(specs, 0, sizeof(specs));
    specs[0].parent_fd = scratch;
    specs[0].physical_path = "AUDIT_REPORT.md";
    specs[0].logical_path = "project/AUDIT_REPORT.md";
    specs[0].required_on_success = 1;
    specs[1].parent_fd = scratch;
    specs[1].physical_path = "_plamen.log";
    specs[1].logical_path = "scratch/_plamen.log";
    specs[1].required_on_failure = 1;
    specs[2].parent_fd = scratch;
    specs[2].physical_path = "_v2_checkpoint.json";
    specs[2].logical_path = "scratch/_v2_checkpoint.json";
    specs[2].required_on_success = 1;
    session.artifacts = specs;
    session.artifact_count = 3;
    session.export_max_total_bytes = 1024U * 1024U;
    session.driver_exit_code = 0;
    session.terminal_authenticated = 1;
    session.extinction_proven = 1;
    session.driver_terminal_proven = 1;
    memset(&census, 0, sizeof(census));
    if (plamen_broker_v2_artifact_census_report(&session, &census)
            != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || census.report_size != strlen(first)
        || plamen_broker_v2_sha256(first, strlen(first), existing) != 0
        || memcmp(existing, census.report_sha256, 32U) != 0
        || decode_hex32(
            "63c120f7489f3828a28a91a39499c5f47f64a374c10d8fc69804fb919fab2d4c",
            expected_census) != 0
        || memcmp(expected_census, census.census_sha256, 32U) != 0)
        return 4;

    memset(&publication, 0, sizeof(publication));
    publication.version = PLAMEN_BROKER_V2_ARTIFACT_EXPORT_VERSION;
    if (plamen_broker_v2_artifact_publish_report(
            &session, &census, &publication, &receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || receipt.complete != 1 || receipt.exported_count != 2
        || receipt.exported_bytes != strlen(first) + strlen(checkpoint)
        || read_file_at(target, "AUDIT_REPORT.md", output, sizeof(output)) != 0
        || strcmp(output, first) != 0
        || decode_hex32(
            "41bda46eeaa22eba05bb5f9f1b8aaac902e3fa48602f8332b242083f6223a71e",
            expected_manifest) != 0
        || decode_hex32(
            "ea0e524128072835c3e1a8a0331d50628b993a6bd493d5209ddbce65166e23cb",
            expected_export) != 0
        || decode_hex32(
            "c97f6f7b51237ad38802ff91fd346ce6322aa21666c9120b46671888065c161e",
            expected_postpublication) != 0
        || memcmp(expected_manifest, receipt.manifest_sha256, 32U) != 0
        || memcmp(expected_export, receipt.export_sha256, 32U) != 0
        || memcmp(expected_postpublication,
            receipt.postpublication_sha256, 32U) != 0)
        return 5;

    memcpy(&published_receipt, &receipt, sizeof(published_receipt));
    if (fstatat(scratch, "AUDIT_REPORT.md", &source_before,
            AT_SYMLINK_NOFOLLOW) != 0
        || fstatat(target, "AUDIT_REPORT.md", &target_before,
            AT_SYMLINK_NOFOLLOW) != 0
        || plamen_broker_v2_artifact_reopen_publication(
            &session, &census, &reopened_receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || memcmp(&published_receipt, &reopened_receipt,
            sizeof(published_receipt)) != 0
        || plamen_broker_v2_artifact_validate_publication_receipt(
            &session, &census, &published_receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || fstatat(scratch, "AUDIT_REPORT.md", &source_after,
            AT_SYMLINK_NOFOLLOW) != 0
        || fstatat(target, "AUDIT_REPORT.md", &target_after,
            AT_SYMLINK_NOFOLLOW) != 0
        || source_before.st_dev != source_after.st_dev
        || source_before.st_ino != source_after.st_ino
        || source_before.st_size != source_after.st_size
        || source_before.st_ctime != source_after.st_ctime
        || target_before.st_dev != target_after.st_dev
        || target_before.st_ino != target_after.st_ino
        || target_before.st_size != target_after.st_size
        || target_before.st_ctime != target_after.st_ctime)
        return 6;

    memcpy(&tampered_receipt, &published_receipt, sizeof(tampered_receipt));
    tampered_receipt.export_sha256[0] ^= UINT8_C(1);
    if (plamen_broker_v2_artifact_validate_publication_receipt(
            &session, &census, &tampered_receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_ERROR)
        return 7;

    if (write_file_at(target, "AUDIT_REPORT.md", second) != 0
        || plamen_broker_v2_artifact_reopen_publication(
            &session, &census, &reopened_receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_ERROR
        || write_file_at(target, "AUDIT_REPORT.md", first) != 0
        || linkat(target, "AUDIT_REPORT.md", target, "report-alias", 0) != 0
        || plamen_broker_v2_artifact_reopen_publication(
            &session, &census, &reopened_receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_ERROR
        || unlinkat(target, "report-alias", 0) != 0)
        return 8;

    if (renameat(target, "AUDIT_REPORT.md", target, "held-report") != 0
        || symlinkat("held-report", target, "AUDIT_REPORT.md") != 0
        || plamen_broker_v2_artifact_reopen_publication(
            &session, &census, &reopened_receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_ERROR
        || unlinkat(target, "AUDIT_REPORT.md", 0) != 0
        || renameat(target, "held-report", target, "AUDIT_REPORT.md") != 0)
        return 9;

    if (renameat(scratch, "AUDIT_REPORT.md", scratch,
            "held-source-report") != 0
        || plamen_broker_v2_artifact_reopen_publication(
            &session, &census, &reopened_receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_ERROR
        || renameat(scratch, "held-source-report", scratch,
            "AUDIT_REPORT.md") != 0)
        return 10;

    if (renameat(scratch, "AUDIT_REPORT.md", scratch,
            "held-source-report") != 0
        || write_file_at(scratch, "AUDIT_REPORT.md", first) != 0
        || plamen_broker_v2_artifact_reopen_publication(
            &session, &census, &reopened_receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_ERROR
        || unlinkat(scratch, "AUDIT_REPORT.md", 0) != 0
        || renameat(scratch, "held-source-report", scratch,
            "AUDIT_REPORT.md") != 0)
        return 11;

    session.target_fd = scratch;
    if (plamen_broker_v2_artifact_reopen_publication(
            &session, &census, &reopened_receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_ERROR)
        return 12;
    session.target_fd = target;

    if (plamen_broker_v2_artifact_publish_report(
            &session, &census, &publication, &receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_ERROR)
        return 13;
    plamen_broker_v2_artifact_census_dispose(&census);

    if (write_file_at(scratch, "AUDIT_REPORT.md", second) != 0
        || plamen_broker_v2_artifact_census_report(&session,
            &replacement_census) != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE)
        return 14;
    existing_fd = openat(target, "AUDIT_REPORT.md",
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (existing_fd < 0 || plamen_broker_v2_sha256(first, strlen(first),
            existing) != 0 || close(existing_fd) != 0)
        return 15;
    existing_fd = -1;
    publication.authorize_replace = 1;
    publication.expected_existing_sha256 = existing;
    if (plamen_broker_v2_artifact_publish_report(&session,
            &replacement_census, &publication, &receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || read_file_at(target, "AUDIT_REPORT.md", output, sizeof(output)) != 0
        || strcmp(output, second) != 0)
        return 16;

    session.target_fd = failed_target;
    session.driver_exit_code = 9;
    if (plamen_broker_v2_artifact_census_report(&session, &census)
            != PLAMEN_BROKER_V2_ARTIFACT_ERROR
        || write_file_at(scratch, "_plamen.log", "failure\n") != 0
        || plamen_broker_v2_artifact_census_report(&session, &census)
            != PLAMEN_BROKER_V2_ARTIFACT_COMPLETE
        || decode_hex32(
            "c32e3a2443108d8bc1ba6bf8726523e82052e4c93f16ffa4c5da4d8dda6f5f7b",
            expected_census) != 0
        || memcmp(expected_census, census.census_sha256, 32U) != 0
        || plamen_broker_v2_artifact_publish_report(
            &session, &census, &publication, &receipt)
            != PLAMEN_BROKER_V2_ARTIFACT_SUPPRESSED
        || openat(failed_target, "AUDIT_REPORT.md",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW) >= 0
        || errno != ENOENT)
        return 17;

    plamen_broker_v2_artifact_census_dispose(&census);
    plamen_broker_v2_artifact_census_dispose(&replacement_census);

    if (close(failed_target) != 0 || close(target) != 0
        || close(scratch) != 0 || close(root) != 0)
        return 18;
    (void)printf("artifact-export-ok:%s\n", root_path);
    return 0;
}
