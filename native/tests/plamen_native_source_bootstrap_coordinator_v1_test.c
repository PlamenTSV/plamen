#include "../darwin/plamen_native_source_bootstrap_coordinator_v1.h"

#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct fixture {
    struct plamen_source_bootstrap_issue_request_v1 request;
    int owned[128];
    size_t owned_count;
    char linked_paths[64][512];
    size_t linked_path_count;
    int terminal_writer;
    int terminal_reader;
    int mutation_writer;
    int mutate;
    int mutate_output_after_commit;
    int deny_source;
    uint64_t terminal_output_sizes[
        PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT];
    uint8_t terminal_output_sha256[
        PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT][32];
};

static int remember(struct fixture *fixture, int fd)
{
    if (fd < 0 || fixture->owned_count >= 128U) return -1;
    fixture->owned[fixture->owned_count++] = fd;
    return fd;
}

static int cloexec(int fd)
{ return fcntl(fd, F_SETFD, FD_CLOEXEC); }

static int temporary_file(struct fixture *fixture, char *path, size_t capacity)
{
    int fd;
    if (snprintf(path, capacity, "/tmp/plamen-source-v1-XXXXXX")
            >= (int)capacity) return -1;
    fd = mkstemp(path);
    if (fd < 0 || cloexec(fd) != 0 || remember(fixture, fd) < 0) return -1;
    return fd;
}

static int source_file(struct fixture *fixture, const char *value,
    int keep_writer, int *writer_output)
{
    char path[128]; size_t size = strlen(value); int writer, reader;
    writer = temporary_file(fixture, path, sizeof(path));
    if (writer < 0 || write(writer, value, size) != (ssize_t)size
            || fsync(writer) != 0 || fchmod(writer, 0400U) != 0) return -1;
    reader = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (reader < 0 || remember(fixture, reader) < 0) return -1;
    if (fixture->linked_path_count >= 64U) return -1;
    memcpy(fixture->linked_paths[fixture->linked_path_count++], path,
        strlen(path) + 1U);
    if (!keep_writer) {
        close(writer); fixture->owned[fixture->owned_count - 2U] = -1;
    } else if (writer_output != NULL) *writer_output = writer;
    return reader;
}

static int empty_pair(struct fixture *fixture, int *writer, int *reader)
{
    char path[128]; int value = temporary_file(fixture, path, sizeof(path));
    if (value < 0 || fchmod(value, 0600U) != 0) return -1;
    *reader = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (*reader < 0 || remember(fixture, *reader) < 0) return -1;
    if (fixture->linked_path_count >= 64U) return -1;
    memcpy(fixture->linked_paths[fixture->linked_path_count++], path,
        strlen(path) + 1U);
    *writer = value; return 0;
}

static int empty_private_pair(struct fixture *fixture, int *writer, int *reader)
{
    if (empty_pair(fixture, writer, reader) != 0) return -1;
    if (fixture->linked_path_count == 0U
            || unlink(fixture->linked_paths[fixture->linked_path_count - 1U]) != 0)
        return -1;
    --fixture->linked_path_count;
    return 0;
}

static int empty_writer(struct fixture *fixture)
{
    char path[128]; int fd = temporary_file(fixture, path, sizeof(path));
    if (fd >= 0) unlink(path);
    return fd;
}

static int relocate_linked_fd(struct fixture *fixture, int fd,
    const char *target)
{
    struct stat wanted, observed;
    size_t index, size;
    if (fstat(fd, &wanted) != 0 || target == NULL
            || (size = strlen(target)) >= sizeof(fixture->linked_paths[0]))
        return -1;
    for (index = 0U; index < fixture->linked_path_count; ++index) {
        if (stat(fixture->linked_paths[index], &observed) == 0
                && wanted.st_dev == observed.st_dev
                && wanted.st_ino == observed.st_ino) {
            if (rename(fixture->linked_paths[index], target) != 0) return -1;
            memcpy(fixture->linked_paths[index], target, size + 1U);
            return 0;
        }
    }
    return -1;
}

static int digest_fd(int fd, uint64_t *size, uint8_t digest[32])
{
    struct stat state; uint8_t buffer[4096]; CC_SHA256_CTX context;
    uint64_t offset = 0U;
    if (fstat(fd, &state) != 0 || state.st_size < 0
            || CC_SHA256_Init(&context) != 1) return -1;
    *size = (uint64_t)state.st_size;
    while (offset < *size) {
        size_t wanted = *size - offset > sizeof(buffer)
            ? sizeof(buffer) : (size_t)(*size - offset);
        ssize_t amount = pread(fd, buffer, wanted, (off_t)offset);
        if (amount != (ssize_t)wanted
                || CC_SHA256_Update(&context, buffer, (CC_LONG)wanted) != 1)
            return -1;
        offset += wanted;
    }
    return CC_SHA256_Final(digest, &context) == 1 ? 0 : -1;
}

static int authenticate_source(void *opaque, uint16_t role, int producer_fd,
    const struct plamen_source_bootstrap_input_v1 *expected,
    const struct plamen_source_bootstrap_fd_identity_v1 *payload,
    const struct plamen_source_bootstrap_fd_identity_v1 *producer,
    const struct plamen_source_bootstrap_fd_identity_v1 *manifest)
{
    struct fixture *fixture = opaque; char prefix[32]; char observed[32];
    int size = snprintf(prefix, sizeof(prefix), "producer-%u", role);
    if (fixture->deny_source || size <= 0
            || pread(producer_fd, observed, (size_t)size, 0) != size
            || memcmp(prefix, observed, (size_t)size) != 0
            || (expected->identity_mode
                    != PLAMEN_SOURCE_BOOTSTRAP_LATEST_BACKEND_RECEIPT_V1
                && (expected->expected_payload_size != payload->size
                    || expected->expected_producer_receipt_size != producer->size
                    || expected->expected_source_manifest_size != manifest->size))
            || expected->policy_sha256[0] != (uint8_t)(0x40U + role))
        return -1;
    return 0;
}

static int authenticate_operation4(void *unused,
    const uint8_t executable_sha256[32])
{
    size_t index; (void)unused;
    for (index = 0U; index < 32U; ++index)
        if (executable_sha256[index] != 0xeeU) return -1;
    return 0;
}

static int invoke_operation4(void *opaque, int composition_fd,
    const int payload_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT],
    const int manifest_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT],
    int output_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT],
    int scratch_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT],
    int *terminal_receipt_fd)
{
    struct fixture *fixture = opaque; size_t index; char byte;
    (void)manifest_fds; (void)scratch_fds;
    if (pread(composition_fd, &byte, 1U, 0) != 1
            || pread(payload_fds[10], &byte, 1U, 0) != 1) return -1;
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) {
        char value[32]; int size = snprintf(value, sizeof(value), "output-%zu", index);
        if (size <= 0 || pwrite(output_fds[index], value, (size_t)size, 0) != size
                || fsync(output_fds[index]) != 0
                || digest_fd(output_fds[index],
                    &fixture->terminal_output_sizes[index],
                    fixture->terminal_output_sha256[index]) != 0) return -1;
    }
    if (fixture->mutate_output_after_commit
            && pwrite(output_fds[0], "X", 1U, 0) != 1) return -1;
    if (fixture->mutate
            && pwrite(fixture->mutation_writer, "X", 1U, 0) != 1)
        return -1;
    if (write(fixture->terminal_writer, "signed-operation4-terminal", 26U) != 26
            || fsync(fixture->terminal_writer) != 0
            || fchmod(fixture->terminal_writer, 0400U) != 0
            || fsync(fixture->terminal_writer) != 0) return -1;
    close(fixture->terminal_writer);
    fixture->terminal_writer = -1;
    *terminal_receipt_fd = fcntl(fixture->terminal_reader, F_DUPFD_CLOEXEC, 3);
    return *terminal_receipt_fd < 0 ? -1 : 0;
}

static int rejoin_terminal_outputs(void *opaque, int terminal_receipt_fd,
    const struct plamen_source_bootstrap_fd_identity_v1 outputs[
        PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT])
{
    struct fixture *fixture = opaque; size_t index; char marker[26];
    if (pread(terminal_receipt_fd, marker, sizeof(marker), 0)
            != (ssize_t)sizeof(marker)
            || memcmp(marker, "signed-operation4-terminal", sizeof(marker)) != 0)
        return -1;
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index)
        if (outputs[index].size != fixture->terminal_output_sizes[index]
                || outputs[index].links != 0U
                || (outputs[index].mode & 07777U) != 0400U
                || memcmp(outputs[index].sha256,
                    fixture->terminal_output_sha256[index], 32U) != 0)
            return -1;
    return 0;
}

static void dispose_fixture(struct fixture *fixture)
{
    size_t index;
    for (index = 0U; index < fixture->owned_count; ++index)
        if (fixture->owned[index] >= 0) close(fixture->owned[index]);
    for (index = 0U; index < fixture->linked_path_count; ++index)
        unlink(fixture->linked_paths[index]);
    memset(fixture, 0, sizeof(*fixture));
}

static int build_fixture(struct fixture *fixture, int retain_mutation_writer)
{
    size_t index; int ignored_reader;
    memset(fixture, 0, sizeof(*fixture)); fixture->mutation_writer = -1;
    fixture->request.owner_uid = getuid();
    fixture->request.producer_verifier_key_fd = source_file(
        fixture, "0123456789abcdef0123456789abcdef", 0, NULL);
    fixture->request.composition_manifest_fd = source_file(
        fixture, "canonical-composition", 0, NULL);
    if (fixture->request.producer_verifier_key_fd < 0
            || fixture->request.composition_manifest_fd < 0) return -1;
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;
            ++index) {
        char payload[32], producer[32], manifest[32];
        struct plamen_source_bootstrap_input_v1 *input = &fixture->request.inputs[index];
        snprintf(payload, sizeof(payload), "payload-%zu", index);
        snprintf(producer, sizeof(producer), "producer-%zu", index);
        snprintf(manifest, sizeof(manifest), "manifest-%zu", index);
        input->payload_fd = source_file(fixture, payload,
            index == 0U && retain_mutation_writer,
            index == 0U && retain_mutation_writer
                ? &fixture->mutation_writer : NULL);
        input->producer_receipt_fd = source_file(fixture, producer, 0, NULL);
        input->source_manifest_fd = source_file(fixture, manifest, 0, NULL);
        input->identity_mode = PLAMEN_SOURCE_BOOTSTRAP_STATIC_PAYLOAD_V1;
        if (input->payload_fd < 0 || input->producer_receipt_fd < 0
                || input->source_manifest_fd < 0
                || digest_fd(input->payload_fd, &input->expected_payload_size,
                    input->expected_payload_sha256) != 0
                || digest_fd(input->producer_receipt_fd,
                    &input->expected_producer_receipt_size,
                    input->expected_producer_receipt_sha256) != 0
                || digest_fd(input->source_manifest_fd,
                    &input->expected_source_manifest_size,
                    input->expected_source_manifest_sha256) != 0) return -1;
        memset(input->policy_sha256, (int)(0x40U + index), 32U);
        if (index == PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1
                || index == PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1) {
            input->identity_mode =
                PLAMEN_SOURCE_BOOTSTRAP_LATEST_BACKEND_RECEIPT_V1;
            input->expected_payload_size = 0U;
            input->expected_producer_receipt_size = 0U;
            input->expected_source_manifest_size = 0U;
            memset(input->expected_payload_sha256, 0, 32U);
            memset(input->expected_producer_receipt_sha256, 0, 32U);
            memset(input->expected_source_manifest_sha256, 0, 32U);
        }
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;
            ++index) {
        if (empty_private_pair(fixture, &fixture->request.output_writer_fds[index],
                &fixture->request.output_reader_fds[index]) != 0) return -1;
    }
    for (index = 0U; index < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT;
            ++index) {
        fixture->request.scratch_fds[index] = empty_writer(fixture);
        if (fixture->request.scratch_fds[index] < 0) return -1;
    }
    if (empty_pair(fixture, &fixture->terminal_writer,
            &fixture->terminal_reader) != 0
            || empty_pair(fixture, &fixture->request.receipt_writer_fd,
                &fixture->request.receipt_reader_fd) != 0) return -1;
    ignored_reader = fixture->terminal_reader; (void)ignored_reader;
    fixture->request.policy_authority.context = fixture;
    fixture->request.policy_authority.authenticate_source = authenticate_source;
    fixture->request.policy_authority.authenticate_operation4 = authenticate_operation4;
    fixture->request.operation4.context = fixture;
    fixture->request.operation4.invoke = invoke_operation4;
    fixture->request.operation4.rejoin_terminal_outputs =
        rejoin_terminal_outputs;
    memset(fixture->request.operation4.executable_sha256, 0xeeU, 32U);
    return 0;
}

static int success_and_readmit(void)
{
    struct fixture fixture;
    struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_installed_authority_v1 *installed = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt, decoded;
    struct plamen_source_bootstrap_projection_v1 live;
    struct plamen_source_bootstrap_installed_projection_v1 projected;
    struct plamen_source_bootstrap_installed_binding_v1 binding;
    struct plamen_source_bootstrap_installed_binding_v1 wrong_binding;
    struct plamen_source_bootstrap_installed_authority_v1 *wrong = NULL;
    uint8_t bytes[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_SIZE];
    uint8_t staged_roster[32];
    char stage_root[] = "/tmp/plamen-source-stage-v1-XXXXXX";
    char share_path[512] = {0}, plamen_path[512] = {0};
    char authority_path[512] = {0}, target[512], extra_path[512];
    char substitute_path[512], backup_path[512];
    int result = -1, transferred_writer, copied_payload_fd = -1;
    int generation_root_fd = -1;
    memset(&binding, 0, sizeof(binding));
    memset(&live, 0, sizeof(live));
    live.payload_fd = live.producer_receipt_fd = live.source_manifest_fd =
        live.coordinator_receipt_fd = -1;
    memset(&projected, 0, sizeof(projected));
    projected.payload_fd = projected.producer_receipt_fd =
        projected.source_manifest_fd = -1;
    projected.coordinator_receipt_fd = -1;
    if (build_fixture(&fixture, 0) != 0) { fprintf(stderr, "fixture\n"); goto done; }
    if (mkdtemp(stage_root) == NULL
            || snprintf(share_path, sizeof(share_path), "%s/share", stage_root)
                >= (int)sizeof(share_path)
            || snprintf(plamen_path, sizeof(plamen_path), "%s/plamen", share_path)
                >= (int)sizeof(plamen_path)
            || snprintf(authority_path, sizeof(authority_path),
                "%s/native-source-authority-v1", plamen_path)
                >= (int)sizeof(authority_path)
            || mkdir(share_path, 0700U) != 0 || mkdir(plamen_path, 0700U) != 0
            || mkdir(authority_path, 0700U) != 0) {
        fprintf(stderr, "stage-directories\n");
        goto done;
    }
    {
        size_t role, kind;
        for (role = 0U;
                role < PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;
                ++role) {
            for (kind = 0U; kind < 3U; ++kind) {
                int descriptor = kind == 0U
                    ? fixture.request.inputs[role].payload_fd
                    : kind == 1U
                        ? fixture.request.inputs[role].producer_receipt_fd
                        : fixture.request.inputs[role].source_manifest_fd;
                const char *relative =
                    plamen_source_bootstrap_installed_member_relative_path_v1(
                        (uint16_t)role, (uint16_t)kind);
                if (relative == NULL
                        || snprintf(target, sizeof(target), "%s/%s", stage_root,
                            relative) >= (int)sizeof(target)
                        || relocate_linked_fd(&fixture, descriptor, target) != 0) {
                    fprintf(stderr, "stage-member\n");
                    goto done;
                }
            }
        }
    }
    if (snprintf(target, sizeof(target), "%s/%s", stage_root,
            PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_RECEIPT_RELATIVE_PATH)
            >= (int)sizeof(target)
            || relocate_linked_fd(&fixture, fixture.request.receipt_reader_fd,
                target) != 0) {
        fprintf(stderr, "stage-receipt\n");
        goto done;
    }
    transferred_writer = fixture.request.output_writer_fds[4];
    if (plamen_source_bootstrap_coordinator_issue_v1(&fixture.request,
                &authority, &receipt) != 0) { fprintf(stderr, "issue\n"); goto done; }
    if (fixture.request.output_writer_fds[4] != -1
            || fcntl(transferred_writer, F_GETFD) >= 0
            || pwrite(fixture.request.output_reader_fds[4], "x", 1U, 0) >= 0
            || receipt.rows[8].ordinal != 8U
            || strcmp(receipt.rows[8].role, "medusa") != 0
            || plamen_source_bootstrap_authority_project_role_v1(authority,
                PLAMEN_SOURCE_BOOTSTRAP_SOLC_AMD64_V1, &live) != 0
            || strcmp(live.role, "solc_amd64") != 0
            || memcmp(live.producer_verifier_key_sha256,
                receipt.producer_verifier_key.sha256, 32U) != 0
            || pread(live.payload_fd, bytes, 7U, 0) != 7
            || pread(fixture.request.receipt_reader_fd, bytes, sizeof(bytes), 0)
                != (ssize_t)sizeof(bytes)
            || plamen_source_bootstrap_receipt_decode_exact_v1(bytes,
                sizeof(bytes), &decoded) != 0
            || memcmp(decoded.receipt_sha256, receipt.receipt_sha256, 32U) != 0) {
        fprintf(stderr, "live/decode\n");
        goto done;
    }
    binding.receipt_size = sizeof(bytes);
    memcpy(binding.receipt_sha256, receipt.receipt_sha256, 32U);
    memcpy(binding.acquisition_roster_sha256,
        receipt.acquisition_roster_sha256, 32U);
    memcpy(binding.producer_verifier_key_sha256,
        receipt.producer_verifier_key.sha256, 32U);
    if (plamen_source_bootstrap_installed_authority_roster_sha256_v1(
            &receipt, binding.installed_authority_roster_sha256) != 0) {
        fprintf(stderr, "installed-roster\n");
        goto done;
    }
    if ((generation_root_fd = open(stage_root,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0
            || plamen_source_bootstrap_staged_authority_validate_v1(
                generation_root_fd, fixture.request.receipt_reader_fd,
                getuid(), staged_roster) != 0
            || memcmp(staged_roster,
                binding.installed_authority_roster_sha256, 32U) != 0) {
        fprintf(stderr, "stage-validate\n");
        goto done;
    }
    if (snprintf(extra_path, sizeof(extra_path), "%s/extra", authority_path)
            >= (int)sizeof(extra_path)
            || (copied_payload_fd = open(extra_path,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400U)) < 0
            || close(copied_payload_fd) != 0) {
        fprintf(stderr, "stage-extra-create\n");
        goto done;
    }
    copied_payload_fd = -1;
    if (plamen_source_bootstrap_staged_authority_validate_v1(
            generation_root_fd, fixture.request.receipt_reader_fd,
            getuid(), staged_roster) == 0 || unlink(extra_path) != 0) {
        fprintf(stderr, "stage-extra-admitted\n");
        goto done;
    }
    {
        const char *relative =
            plamen_source_bootstrap_installed_member_relative_path_v1(
                PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1,
                PLAMEN_SOURCE_BOOTSTRAP_INSTALLED_PAYLOAD_V1);
        struct stat payload_state;
        uint8_t copy_buffer[64];
        ssize_t amount;
        if (relative == NULL
                || snprintf(substitute_path, sizeof(substitute_path), "%s/%s",
                    stage_root, relative) >= (int)sizeof(substitute_path)
                || snprintf(backup_path, sizeof(backup_path), "%s/original",
                    authority_path) >= (int)sizeof(backup_path)
                || rename(substitute_path, backup_path) != 0
                || fstat(fixture.request.inputs[PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1]
                    .payload_fd, &payload_state) != 0
                || payload_state.st_size <= 0
                || payload_state.st_size > (off_t)sizeof(copy_buffer)
                || (amount = pread(fixture.request.inputs[
                        PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1].payload_fd,
                    copy_buffer, (size_t)payload_state.st_size, 0))
                    != payload_state.st_size
                || (copied_payload_fd = open(substitute_path,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600U)) < 0
                || write(copied_payload_fd, copy_buffer, (size_t)amount) != amount
                || fsync(copied_payload_fd) != 0
                || fchmod(copied_payload_fd, 0400U) != 0
                || close(copied_payload_fd) != 0) {
            fprintf(stderr, "stage-substitute-create\n");
            goto done;
        }
        copied_payload_fd = -1;
        if (plamen_source_bootstrap_staged_authority_validate_v1(
                generation_root_fd, fixture.request.receipt_reader_fd,
                getuid(), staged_roster) == 0
                || unlink(substitute_path) != 0
                || rename(backup_path, substitute_path) != 0) {
            fprintf(stderr, "stage-substitute-admitted\n");
            goto done;
        }
    }
    memset(binding.coordinator_member_identity_sha256, 0xa1, 32U);
    memset(binding.coordinator_code_identity_sha256, 0xb2, 32U);
    if (plamen_source_bootstrap_installed_readmit_v1(
            fixture.request.receipt_reader_fd, getuid(), &binding,
            &installed) != 0
            || plamen_source_bootstrap_installed_project_role_v1(installed,
                PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1,
                fixture.request.inputs[PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1]
                    .payload_fd,
                fixture.request.inputs[PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1]
                    .producer_receipt_fd,
                fixture.request.inputs[PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1]
                    .source_manifest_fd,
                &projected) != 0
            || strcmp(projected.role, "medusa") != 0
            || projected.payload_fd < 0 || projected.producer_receipt_fd < 0
            || projected.source_manifest_fd < 0
            || projected.row.payload.size != receipt.rows[8].payload.size
            || memcmp(projected.producer_verifier_key_sha256,
                binding.producer_verifier_key_sha256, 32U) != 0) {
        fprintf(stderr, "readmit/project\n");
        goto done;
    }
    plamen_source_bootstrap_installed_projection_dispose_v1(&projected);
    if (plamen_source_bootstrap_installed_project_role_v1(installed,
            PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1,
            fixture.request.inputs[PLAMEN_SOURCE_BOOTSTRAP_SOLC_AMD64_V1]
                .payload_fd,
            fixture.request.inputs[PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1]
                .producer_receipt_fd,
            fixture.request.inputs[PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1]
                .source_manifest_fd,
            &projected) == 0) {
        fprintf(stderr, "installed-inode-substitution\n");
        goto done;
    }
    copied_payload_fd = source_file(&fixture, "payload-8", 0, NULL);
    if (copied_payload_fd < 0
            || plamen_source_bootstrap_installed_project_role_v1(installed,
                PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1, copied_payload_fd,
                fixture.request.inputs[PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1]
                    .producer_receipt_fd,
                fixture.request.inputs[PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1]
                    .source_manifest_fd,
                &projected) == 0) {
        fprintf(stderr, "installed-copy-after-issue\n");
        goto done;
    }
    wrong_binding = binding;
    wrong_binding.acquisition_roster_sha256[0] ^= 1U;
    if (plamen_source_bootstrap_installed_readmit_v1(
            fixture.request.receipt_reader_fd, getuid(), &wrong_binding,
            &wrong) == 0) {
        fprintf(stderr, "tampered-readmit\n");
        goto done;
    }
    wrong_binding = binding;
    wrong_binding.producer_verifier_key_sha256[0] ^= 1U;
    if (plamen_source_bootstrap_installed_readmit_v1(
            fixture.request.receipt_reader_fd, getuid(), &wrong_binding,
            &wrong) == 0) {
        fprintf(stderr, "tampered-verifier-key-readmit\n");
        goto done;
    }
    wrong_binding = binding;
    wrong_binding.installed_authority_roster_sha256[0] ^= 1U;
    if (plamen_source_bootstrap_installed_readmit_v1(
            fixture.request.receipt_reader_fd, getuid(), &wrong_binding,
            &wrong) == 0) {
        fprintf(stderr, "tampered-installed-roster-readmit\n");
        goto done;
    }
    plamen_source_bootstrap_installed_projection_dispose_v1(&projected);
    result = 0;
done:
    if (generation_root_fd >= 0) close(generation_root_fd);
    if (copied_payload_fd >= 0) close(copied_payload_fd);
    plamen_source_bootstrap_projection_dispose_v1(&live);
    plamen_source_bootstrap_installed_authority_dispose_v1(wrong);
    plamen_source_bootstrap_installed_authority_dispose_v1(installed);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture);
    if (authority_path[0] != '\0') (void)rmdir(authority_path);
    if (plamen_path[0] != '\0') (void)rmdir(plamen_path);
    if (share_path[0] != '\0') (void)rmdir(share_path);
    if (stage_root[0] != '\0') (void)rmdir(stage_root);
    return result;
}

static int expected_digest_rejected(void)
{
    struct fixture fixture; struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt; int result;
    if (build_fixture(&fixture, 0) != 0) return -1;
    fixture.request.inputs[3].expected_payload_sha256[0] ^= 1U;
    result = plamen_source_bootstrap_coordinator_issue_v1(
        &fixture.request, &authority, &receipt);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture); return result == 0 ? -1 : 0;
}

static int policy_denial_rejected(void)
{
    struct fixture fixture; struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt; int result;
    if (build_fixture(&fixture, 0) != 0) return -1;
    fixture.deny_source = 1;
    result = plamen_source_bootstrap_coordinator_issue_v1(
        &fixture.request, &authority, &receipt);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture); return result == 0 ? -1 : 0;
}

static int post_transform_mutation_rejected(void)
{
    struct fixture fixture; struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt; int result;
    if (build_fixture(&fixture, 1) != 0) return -1;
    fixture.mutate = 1;
    result = plamen_source_bootstrap_coordinator_issue_v1(
        &fixture.request, &authority, &receipt);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture); return result == 0 ? -1 : 0;
}

static int retained_writable_alias_rejected(void)
{
    struct fixture fixture; struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt; int alias, result;
    if (build_fixture(&fixture, 0) != 0) return -1;
    alias = fcntl(fixture.request.output_writer_fds[0], F_DUPFD_CLOEXEC, 3);
    if (alias < 0 || remember(&fixture, alias) < 0) {
        dispose_fixture(&fixture); return -1;
    }
    result = plamen_source_bootstrap_coordinator_issue_v1(
        &fixture.request, &authority, &receipt);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture); return result == 0 ? -1 : 0;
}

static int retained_scratch_alias_rejected(void)
{
    struct fixture fixture; struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt; int alias, result;
    if (build_fixture(&fixture, 0) != 0) return -1;
    alias = fcntl(fixture.request.scratch_fds[0], F_DUPFD_CLOEXEC, 3);
    if (alias < 0 || remember(&fixture, alias) < 0) {
        dispose_fixture(&fixture); return -1;
    }
    result = plamen_source_bootstrap_coordinator_issue_v1(
        &fixture.request, &authority, &receipt);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture); return result == 0 ? -1 : 0;
}

static int terminal_hash_rejoin_mutation_rejected(void)
{
    struct fixture fixture;
    struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt; int result;
    if (build_fixture(&fixture, 0) != 0) return -1;
    fixture.mutate_output_after_commit = 1;
    result = plamen_source_bootstrap_coordinator_issue_v1(
        &fixture.request, &authority, &receipt);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture); return result == 0 ? -1 : 0;
}

static int external_process_writable_alias_rejected(void)
{
    struct fixture fixture;
    struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt;
    int ready[2] = {-1, -1}, release[2] = {-1, -1}, result = -1, status = 0;
    pid_t child = -1; char byte = 0;
    if (build_fixture(&fixture, 0) != 0 || pipe(ready) != 0
            || pipe(release) != 0) goto done;
    child = fork();
    if (child < 0) goto done;
    if (child == 0) {
        close(ready[0]); close(release[1]);
        if (write(ready[1], "R", 1U) != 1
                || read(release[0], &byte, 1U) != 1) _exit(2);
        _exit(0);
    }
    close(ready[1]); ready[1] = -1;
    close(release[0]); release[0] = -1;
    if (read(ready[0], &byte, 1U) != 1) goto done;
    result = plamen_source_bootstrap_coordinator_issue_v1(
        &fixture.request, &authority, &receipt);
    if (write(release[1], "X", 1U) != 1) goto done;
    close(release[1]); release[1] = -1;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)
            || WEXITSTATUS(status) != 0) goto done;
    child = -1;
    result = result == 0 ? -1 : 0;
done:
    if (release[1] >= 0) { (void)write(release[1], "X", 1U); close(release[1]); }
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (release[0] >= 0) close(release[0]);
    if (child > 0) (void)waitpid(child, &status, 0);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture);
    return result;
}

static int linked_input_alias_rejected(void)
{
    struct fixture fixture; struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt; char alias[128]; int result;
    if (build_fixture(&fixture, 0) != 0) return -1;
    if (snprintf(alias, sizeof(alias), "/tmp/plamen-source-alias-%ld",
            (long)getpid()) >= (int)sizeof(alias)
            || fixture.linked_path_count >= 64U
            || link(fixture.linked_paths[0], alias) != 0) {
        dispose_fixture(&fixture); return -1;
    }
    memcpy(fixture.linked_paths[fixture.linked_path_count++], alias,
        strlen(alias) + 1U);
    result = plamen_source_bootstrap_coordinator_issue_v1(
        &fixture.request, &authority, &receipt);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture); return result == 0 ? -1 : 0;
}

static int mismatched_owner_rejected(void)
{
    struct fixture fixture; struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt; int result;
    if (build_fixture(&fixture, 0) != 0) return -1;
    fixture.request.owner_uid = getuid() + 1U;
    result = plamen_source_bootstrap_coordinator_issue_v1(
        &fixture.request, &authority, &receipt);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture); return result == 0 ? -1 : 0;
}

static int zero_verifier_key_rejected(void)
{
    struct fixture fixture; struct plamen_source_bootstrap_authority_v1 *authority = NULL;
    struct plamen_source_bootstrap_receipt_v1 receipt; uint8_t zero[32] = {0};
    int writer, result;
    if (build_fixture(&fixture, 0) != 0) return -1;
    if (chmod(fixture.linked_paths[0], 0600U) != 0
            || (writer = open(fixture.linked_paths[0],
                O_WRONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
            || pwrite(writer, zero, sizeof(zero), 0) != (ssize_t)sizeof(zero)
            || fsync(writer) != 0 || close(writer) != 0
            || chmod(fixture.linked_paths[0], 0400U) != 0) {
        dispose_fixture(&fixture); return -1;
    }
    result = plamen_source_bootstrap_coordinator_issue_v1(
        &fixture.request, &authority, &receipt);
    plamen_source_bootstrap_authority_dispose_v1(authority);
    dispose_fixture(&fixture); return result == 0 ? -1 : 0;
}

int main(void)
{
    if (success_and_readmit() != 0) return 1;
    if (expected_digest_rejected() != 0) return 2;
    if (policy_denial_rejected() != 0) return 3;
    if (post_transform_mutation_rejected() != 0) return 4;
    if (retained_writable_alias_rejected() != 0) return 5;
    if (retained_scratch_alias_rejected() != 0) return 6;
    if (linked_input_alias_rejected() != 0) return 7;
    if (mismatched_owner_rejected() != 0) return 8;
    if (zero_verifier_key_rejected() != 0) return 9;
    if (terminal_hash_rejoin_mutation_rejected() != 0) return 10;
    if (external_process_writable_alias_rejected() != 0) return 11;
    puts("native source-bootstrap coordinator v1: ok");
    return 0;
}
