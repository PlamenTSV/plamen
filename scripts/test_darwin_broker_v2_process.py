from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="Darwin suspended-spawn substrate"
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native" / "darwin" / "plamen_broker_v2_process.c"
CUSTODIAN = ROOT / "native" / "darwin" / "plamen_broker_v2_process_custodian.c"
CUSTODY_DAEMON = ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_daemon.c"
CUSTODY_CLIENT = ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_client.c"
LAUNCHER = ROOT / "native" / "darwin" / "plamen_native_launcher.c"
SERVICE = ROOT / "native" / "darwin" / "plamen_broker_v2_service.c"
SERVICE_STORE = ROOT / "native" / "darwin" / "plamen_broker_v2_service_store.c"
INSTALL_RECEIPT = ROOT / "native" / "darwin" / "plamen_broker_v2_install_receipt.c"
DEPLOYMENT_RECEIPT = (
    ROOT / "native" / "darwin" / "plamen_native_deployment_receipt_v2.c"
)
EFFECTS = ROOT / "native" / "darwin" / "plamen_broker_v2_effects.c"
SPECIALIZED_REQUEST = (
    ROOT / "native" / "darwin" / "plamen_broker_v2_specialized_request.c"
)
SPECIALIZED_RUNTIME_AUTHORITY = (
    ROOT / "native" / "darwin"
    / "plamen_broker_v2_specialized_runtime_authority.c"
)
SPECIALIZED_RUNTIME_EFFECTS_HANDOFF = (
    ROOT / "native" / "darwin"
    / "plamen_broker_v2_specialized_runtime_effects_handoff.c"
)
SPECIALIZED_EFFECT_STORE = (
    ROOT / "native" / "darwin" / "plamen_broker_v2_specialized_effect_store.c"
)
SPECIALIZED_APPLE_EFFECT_EXECUTION = (
    ROOT / "native" / "darwin"
    / "plamen_broker_v2_specialized_apple_effect_execution.c"
)
FUZZ_CAMPAIGN = (
    ROOT / "native" / "darwin" / "plamen_broker_v2_fuzz_campaign.c"
)
SPECIALIZED_OUTPUT_CENSUS = (
    ROOT / "native" / "darwin" / "plamen_broker_v2_specialized_output_census.c"
)
SPECIALIZED_OUTPUT_RECEIPT = (
    ROOT / "native" / "darwin" / "plamen_broker_v2_specialized_output_receipt.c"
)
IMAGE_MEMBER_RECEIPT = (
    ROOT / "native" / "darwin" / "plamen_native_image_member_receipt_v2.c"
)
ARTIFACT_EXPORT = (
    ROOT / "native" / "darwin" / "plamen_broker_v2_artifact_export.c"
)
NATIVE_BUILDER = ROOT / "native" / "posix" / "plamen_native_builder_v2.c"
APPLE_CONTAINER = (
    ROOT / "native" / "darwin" / "plamen_broker_v2_apple_container.c"
)
APPLE_LIFECYCLE = (
    ROOT / "native" / "darwin"
    / "plamen_broker_v2_apple_container_lifecycle.c"
)
TOOL_CUSTODY = (
    ROOT / "native" / "darwin" / "plamen_broker_v2_tool_custody.c"
)
WORKSPACE_EFFECTS = (
    ROOT / "native" / "darwin" / "plamen_broker_v2_workspace_effects.c"
)
OPERATIONS = ROOT / "native" / "darwin" / "plamen_broker_v2_operations.c"
PROTOCOL = ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"
CLANG = Path("/usr/bin/clang")

PROFILE_TEST_SOURCE = r"""
#include <fcntl.h>
#include <unistd.h>
int plamen_native_launcher_TEST_ONLY_profile_validate(int, int);
int main(int argc, char **argv) {
    int profile = -1, manifest = -1, result = 1;
    if (argc != 3) return 64;
    profile = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    manifest = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (profile >= 0 && manifest >= 0)
        result = plamen_native_launcher_TEST_ONLY_profile_validate(
            profile, manifest) == 0 ? 0 : 1;
    if (profile >= 0) close(profile);
    if (manifest >= 0) close(manifest);
    return result;
}
"""

CREDENTIAL_TEST_SOURCE = r"""
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
int plamen_native_launcher_TEST_ONLY_create_unlinked_credential(
    int, const uint8_t *, size_t, int *);
int main(int argc, char **argv) {
    static const uint8_t secret[] = "{\"claudeAiOauth\":{\"accessToken\":\"private\"}}";
    uint8_t observed[sizeof(secret) - 1];
    struct stat information;
    int root = -1, credential = -1, result = 1;
    if (argc != 2) return 64;
    root = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) return 65;
    if (plamen_native_launcher_TEST_ONLY_create_unlinked_credential(
            root, secret, sizeof(secret) - 1, &credential) != 0)
        goto done;
    if (fstat(credential, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_nlink != 0
        || (information.st_mode & 07777) != 0600
        || (fcntl(credential, F_GETFL) & O_ACCMODE) != O_RDONLY
        || (fcntl(credential, F_GETFD) & FD_CLOEXEC) == 0
        || pread(credential, observed, sizeof(observed), 0)
            != (ssize_t)sizeof(observed)
        || memcmp(observed, secret, sizeof(observed)) != 0)
        goto done;
    result = 0;
done:
    memset(observed, 0, sizeof(observed));
    if (credential >= 0) close(credential);
    close(root);
    return result;
}
"""

HELPER_SOURCE = r"""
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
extern char **environ;

static int marker(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return 70;
    if (write(fd, "effect\n", 7) != 7) return 71;
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    char block[65536];
    if (argc < 2) return 64;
    if (strcmp(argv[1], "ok") == 0) {
        if (environ != NULL && environ[0] != NULL) return 90;
        write(1, "stdout-evidence\n", 16);
        write(2, "stderr-evidence\n", 16);
        return argc > 2 ? atoi(argv[2]) : 0;
    }
    if (strcmp(argv[1], "env") == 0) {
        if (environ == NULL || environ[0] == NULL || environ[1] != NULL
            || strcmp(environ[0], "ONLY=value") != 0) return 91;
        write(1, "exact-environment\n", 18);
        return 0;
    }
    if (strcmp(argv[1], "marker") == 0 && argc == 3)
        return marker(argv[2]);
    if (strcmp(argv[1], "timeout") == 0) {
        for (;;) pause();
    }
    if (strcmp(argv[1], "overflow") == 0) {
        memset(block, 'x', sizeof(block));
        for (int i = 0; i < 300; i++) {
            size_t offset = 0;
            while (offset < sizeof(block)) {
                ssize_t amount = write(1, block + offset, sizeof(block) - offset);
                if (amount < 0 && errno == EINTR) continue;
                if (amount <= 0) return 72;
                offset += (size_t)amount;
            }
        }
        return 0;
    }
    if (strcmp(argv[1], "fds") == 0) {
        int open_count = 0;
        int open_fd = -1;
        for (int fd = 3; fd < 256; fd++) {
            if (fcntl(fd, F_GETFD) >= 0) { open_count++; open_fd = fd; }
        }
        dprintf(1, "%d:%d\n", open_count, open_fd);
        return open_count == 1 && open_fd == 9 ? 0 : 73;
    }
    if (strcmp(argv[1], "fds-max") == 0) {
        int open_count = 0;
        int first = -1, last = -1;
        for (int fd = 3; fd < 256; fd++) {
            if (fcntl(fd, F_GETFD) >= 0) {
                if (first < 0) first = fd;
                last = fd;
                open_count++;
            }
        }
        dprintf(1, "%d:%d:%d\n", open_count, first, last);
        return open_count == 15 && first == 20 && last == 34 ? 0 : 73;
    }
    if (strcmp(argv[1], "tree") == 0) {
        pid_t descendant = fork();
        if (descendant < 0) return 74;
        if (descendant == 0) for (;;) pause();
        dprintf(1, "%d\n", descendant);
        return 0;
    }
    if (strcmp(argv[1], "started") == 0 && argc == 3) {
        int value = marker(argv[2]);
        if (value != 0) return value;
        for (;;) pause();
    }
    return 65;
}
"""

PRODUCTION_DRIVER_SOURCE = r"""
#include "plamen_broker_v2_process.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static int hex_digest(const char *text, uint8_t output[32]) {
    size_t index;
    if (text == NULL || strlen(text) != 64) return -1;
    for (index = 0; index < 32; ++index) {
        char pair[3] = {text[index * 2], text[index * 2 + 1], '\0'};
        char *end = NULL;
        unsigned long value;
        errno = 0;
        value = strtoul(pair, &end, 16);
        if (errno != 0 || end != pair + 2 || value > 255) return -1;
        output[index] = (uint8_t)value;
    }
    return 0;
}

static int nonzero(const uint8_t value[32]) {
    uint8_t seen = 0;
    size_t index;
    for (index = 0; index < 32; ++index) seen |= value[index];
    return seen != 0;
}

int main(int argc, char **argv) {
    struct plamen_broker_v2_process_spec spec;
    struct plamen_broker_v2_process_prepared_identity prepared;
    struct plamen_broker_v2_process_start_identity started;
    struct plamen_broker_v2_process_terminal terminal;
    struct plamen_broker_v2_process *process = NULL;
    uint8_t executable_sha[32], chunk_sha[32], full_sha[32];
    uint8_t chunk[262144];
    uint8_t first_chunk[8];
    uint32_t chunk_size = 0;
    uint64_t full_size = 0;
    uint8_t eof = 0;
    const char *child_argv[4];
    const char *exact_environment[2] = {"ONLY=value", NULL};
    const char *duplicate_environment[3] = {
        "ONLY=value", "ONLY=other", NULL};
    const char *invalid_environment[2] = {"BAD-NAME=value", NULL};
    struct plamen_broker_v2_process_fd_map fd_maps[16];
    int mapped_pipes[16][2];
    size_t fd_count = 0, fd_index;
    int executable_fd = -1, cwd_fd = -1, stdin_fd = -1;
    int status, close_live = -1, read_status = -1, replay_equal = 0;

    if (argc != 6 || hex_digest(argv[3], executable_sha) != 0) return 64;
    for (fd_index = 0; fd_index < 16; ++fd_index)
        mapped_pipes[fd_index][0] = mapped_pipes[fd_index][1] = -1;
    executable_fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    cwd_fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    stdin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (executable_fd < 0 || cwd_fd < 0 || stdin_fd < 0) return 65;
    memset(&spec, 0, sizeof(spec));
    child_argv[0] = argv[1];
    child_argv[1] = strcmp(argv[4], "extinguish") == 0
        ? "timeout" : (strcmp(argv[4], "fds-max") == 0
            ? "fds-max" : argv[4]);
    child_argv[2] = strcmp(argv[4], "ok") == 0 ? "7" : NULL;
    child_argv[3] = NULL;
    spec.version = 1;
    spec.executable_fd = executable_fd;
    spec.executable_path = argv[1];
    spec.argv = child_argv;
    spec.argc = child_argv[2] == NULL ? 2 : 3;
    spec.environment_policy = (strcmp(argv[4], "env") == 0
            || strcmp(argv[4], "duplicate-env") == 0
            || strcmp(argv[4], "invalid-env") == 0)
        ? PLAMEN_BROKER_V2_PROCESS_ENV_EXACT
        : PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED;
    spec.environment = strcmp(argv[4], "duplicate-env") == 0
        ? duplicate_environment : strcmp(argv[4], "invalid-env") == 0
            ? invalid_environment : strcmp(argv[4], "env") == 0
                ? exact_environment : NULL;
    spec.environment_count = strcmp(argv[4], "duplicate-env") == 0
        ? 2 : spec.environment == NULL ? 0 : 1;
    spec.cwd_fd = cwd_fd;
    spec.stdin_fd = stdin_fd;
    spec.timeout_seconds = strcmp(argv[4], "max-timeout") == 0
        ? PLAMEN_BROKER_V2_PROCESS_TIMEOUT_SECONDS_MAX
        : strcmp(argv[4], "over-timeout") == 0
            ? PLAMEN_BROKER_V2_PROCESS_TIMEOUT_SECONDS_MAX + 1U : 1U;
    spec.stdout_spool_limit = strcmp(argv[4], "overflow") == 0
        ? 4096 : strcmp(argv[4], "max-spool") == 0
            ? PLAMEN_BROKER_V2_OBSERVED_MAX
            : strcmp(argv[4], "over-spool") == 0
                ? PLAMEN_BROKER_V2_OBSERVED_MAX + 1U : 1048576;
    spec.stderr_spool_limit = 1048576;
    spec.expected_executable_sha256 = executable_sha;
    spec.expected_signing_identifier = argv[5];
    spec.expected_team_identifier = "";
    if (strcmp(argv[4], "fds") == 0) {
        fd_count = 1;
    } else if (strcmp(argv[4], "fds-max") == 0
        || strcmp(argv[4], "fds-over") == 0
        || strcmp(argv[4], "fds-rlimit") == 0) {
        fd_count = strcmp(argv[4], "fds-over") == 0 ? 16 : 15;
    } else if (strcmp(argv[4], "fds-duplicate-source") == 0
        || strcmp(argv[4], "fds-duplicate-target") == 0) {
        fd_count = 2;
    } else if (strcmp(argv[4], "fds-target-over") == 0) {
        fd_count = 1;
    }
    for (fd_index = 0; fd_index < fd_count; ++fd_index) {
        if (pipe(mapped_pipes[fd_index]) != 0) return 66;
        fd_maps[fd_index].source_fd = mapped_pipes[fd_index][0];
        fd_maps[fd_index].target_fd = strcmp(argv[4], "fds") == 0
            ? 9 : (int)(20 + fd_index);
    }
    if (fd_count != 0) {
        if (strcmp(argv[4], "fds-duplicate-source") == 0)
            fd_maps[1].source_fd = fd_maps[0].source_fd;
        if (strcmp(argv[4], "fds-duplicate-target") == 0)
            fd_maps[1].target_fd = fd_maps[0].target_fd;
        if (strcmp(argv[4], "fds-target-over") == 0)
            fd_maps[0].target_fd = 1024;
        spec.fd_maps = fd_maps;
        spec.fd_map_count = fd_count;
    }
    if (strcmp(argv[4], "fds-rlimit") == 0) {
        struct rlimit limit;
        if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return 67;
        limit.rlim_cur = 1041;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) return 68;
    }
    status = plamen_broker_v2_process_prepare(&spec, &prepared, &process);
    printf("AVAILABLE=%d\nPREPARE=%d\nPREPARED_SHA=%d\n",
        plamen_broker_v2_production_available(), status,
        nonzero(prepared.executable_identity_sha256));
    if (status != 0) return status;
    close(executable_fd);
    close(cwd_fd);
    close(stdin_fd);
    executable_fd = cwd_fd = stdin_fd = -1;
    for (fd_index = 0; fd_index < 16; ++fd_index) {
        if (mapped_pipes[fd_index][0] >= 0) close(mapped_pipes[fd_index][0]);
        if (mapped_pipes[fd_index][1] >= 0) close(mapped_pipes[fd_index][1]);
    }
    if (strcmp(argv[4], "max-timeout") == 0
        || strcmp(argv[4], "max-spool") == 0) {
        printf("CLOSE=%d\n", plamen_broker_v2_process_close(process));
        return 0;
    }
    status = plamen_broker_v2_process_start(process, &started);
    printf("START=%d\nHANDLE_SHA=%d\nPID=%d\nPGID=%d\n",
        status, nonzero(started.native_process_handle_sha256),
        started.child_pid, started.process_group_id);
    if (status != 0) {
        (void)plamen_broker_v2_process_close(process);
        return status;
    }
    close_live = plamen_broker_v2_process_close(process);
    status = strcmp(argv[4], "extinguish") == 0
        ? plamen_broker_v2_process_extinguish(process, &terminal)
        : plamen_broker_v2_process_wait(process, &terminal);
    if (strcmp(argv[4], "overflow") != 0) {
        read_status = plamen_broker_v2_process_read_output(process,
            PLAMEN_BROKER_V2_PROCESS_STREAM_STDOUT, 0, 8, chunk, 8,
            &chunk_size, &eof, chunk_sha, full_sha, &full_size);
        memcpy(first_chunk, chunk, sizeof(first_chunk));
        if (read_status == 0) {
            uint32_t replay_size = 0;
            uint64_t replay_full_size = 0;
            uint8_t replay_eof = 0, replay[8], replay_chunk_sha[32];
            uint8_t replay_full_sha[32];
            int replay_status = plamen_broker_v2_process_read_output(process,
                PLAMEN_BROKER_V2_PROCESS_STREAM_STDOUT, 0, 8, replay, 8,
                &replay_size, &replay_eof, replay_chunk_sha,
                replay_full_sha, &replay_full_size);
            replay_equal = replay_status == 0 && replay_size == chunk_size
                && replay_full_size == full_size
                && memcmp(replay, first_chunk, chunk_size) == 0
                && memcmp(replay_chunk_sha, chunk_sha, 32) == 0
                && memcmp(replay_full_sha, full_sha, 32) == 0;
        }
    } else {
        read_status = plamen_broker_v2_process_read_output(process,
            PLAMEN_BROKER_V2_PROCESS_STREAM_STDOUT, 0, 8, chunk, 8,
            &chunk_size, &eof, chunk_sha, full_sha, &full_size);
    }
    printf("CLOSE_LIVE=%d\nWAIT=%d\nTERMINAL=%u\nEXIT=%d\nSIGNAL=%d\n"
        "REAPED=%u\nEXTINCT=%u\nSTDOUT_SIZE=%llu\nSTDOUT_OVERFLOW=%u\n"
        "READ=%d\nREAD_SIZE=%u\nFULL_SIZE=%llu\nREPLAY_EQUAL=%d\n",
        close_live, status, terminal.status, terminal.exit_code,
        terminal.signal_number, terminal.child_reaped,
        terminal.process_group_extinct,
        (unsigned long long)terminal.stdout_size,
        terminal.stdout_overflow, read_status, chunk_size,
        (unsigned long long)full_size, replay_equal);
    printf("REWAIT=%d\n", plamen_broker_v2_process_wait(process, &terminal));
    printf("CLOSE=%d\n", plamen_broker_v2_process_close(process));
    close(executable_fd);
    close(cwd_fd);
    close(stdin_fd);
    return 0;
}
"""

STORE_BURN_TEST_SOURCE = r"""
#define _DARWIN_C_SOURCE 1
#include "plamen_broker_v2.h"
#include "plamen_broker_v2_service_store.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int touch_at(int root, const char *name) {
    int fd = openat(root, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0400);
    if (fd < 0) return -1;
    return close(fd);
}

int main(int argc, char **argv) {
    struct plamen_broker_v2_service_store *store = NULL;
    struct plamen_broker_v2_peer_identity peer;
    struct plamen_broker_v2_service_registration registration;
    struct plamen_broker_v2_service_registration_ack ack;
    static const char unused[] =
        "registration-1111111111111111111111111111111111111111111111111111111111111111.unused";
    static const char consumed[] =
        "registration-1111111111111111111111111111111111111111111111111111111111111111.consumed";
    int parent = -1, records = -1, status;
    if (argc != 2 || mkdir(argv[1], 0700) != 0) return 64;
    parent = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent < 0 || plamen_broker_v2_service_store_open(parent, &store) != 0)
        return 65;
    records = openat(parent, "registrations-v2",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (records < 0 || touch_at(records, unused) != 0
        || touch_at(records, consumed) != 0)
        return 66;
    memset(&peer, 0, sizeof(peer));
    status = plamen_broker_v2_service_store_lookup_unused(
        store, &peer, &registration, &ack);
    if (status != PLAMEN_BROKER_V2_CONFLICT) {
        dprintf(2, "first-status=%d expected=%d\n", status,
            PLAMEN_BROKER_V2_CONFLICT);
        return 67;
    }
    if (unlinkat(records, consumed, 0) != 0) return 68;
    status = plamen_broker_v2_service_store_lookup_unused(
        store, &peer, &registration, &ack);
    if (status != PLAMEN_BROKER_V2_CORRUPT) {
        dprintf(2, "second-status=%d expected=%d\n", status,
            PLAMEN_BROKER_V2_CORRUPT);
        return 69;
    }
    plamen_broker_v2_service_store_close(store);
    close(records);
    close(parent);
    return 0;
}
"""

SESSION_WIRE_TEST_SOURCE = r"""
#define _DARWIN_C_SOURCE 1
#include "plamen_broker_v2.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

extern int plamen_broker_v2_service_TEST_ONLY_serve_session(int,
    const uint8_t[32], const uint8_t *, size_t,
    const struct plamen_broker_v2_service_session_challenge *,
    const struct plamen_broker_v2_service_session_ack *,
    const struct plamen_broker_v2_authority_bundle_binding *);

struct thread_args {
    int fd;
    const uint8_t *key;
    const uint8_t *projection;
    size_t projection_size;
    const struct plamen_broker_v2_service_session_challenge *challenge;
    const struct plamen_broker_v2_service_session_ack *ack;
    const struct plamen_broker_v2_authority_bundle_binding *bundle;
    int result;
};

static void fill(uint8_t value[32], uint8_t byte) {
    memset(value, byte, 32);
}

static int write_full(int fd, const uint8_t *bytes, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = write(fd, bytes + offset, size - offset);
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static int read_full(int fd, uint8_t *bytes, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        ssize_t amount = read(fd, bytes + offset, size - offset);
        if (amount <= 0) return -1;
        offset += (size_t)amount;
    }
    return 0;
}

static uint32_t payload_size(const uint8_t *header) {
    return ((uint32_t)header[20] << 24) | ((uint32_t)header[21] << 16)
        | ((uint32_t)header[22] << 8) | header[23];
}

static int receive_frame(int fd, uint8_t **frame, size_t *size) {
    uint8_t header[PLAMEN_BROKER_V2_HEADER_SIZE];
    uint32_t payload;
    if (read_full(fd, header, sizeof(header)) != 0) return -1;
    payload = payload_size(header);
    if (payload > PLAMEN_BROKER_V2_MAX_PAYLOAD) return -1;
    *size = sizeof(header) + payload;
    *frame = malloc(*size);
    if (*frame == NULL) return -1;
    memcpy(*frame, header, sizeof(header));
    if (payload != 0
        && read_full(fd, *frame + sizeof(header), payload) != 0) return -1;
    return 0;
}

static int send_frame(int fd, struct plamen_broker_v2_session *session,
    uint16_t type, const uint8_t nonce[32], const uint8_t *payload,
    uint32_t payload_size) {
    uint8_t *frame = NULL;
    size_t frame_size = 0;
    int result = plamen_broker_v2_frame_build(session, type, nonce, payload,
        payload_size, 0, &frame, &frame_size);
    if (result == 0) result = write_full(fd, frame, frame_size);
    free(frame);
    return result;
}

static void *run_server(void *opaque) {
    struct thread_args *args = opaque;
    args->result = plamen_broker_v2_service_TEST_ONLY_serve_session(args->fd,
        args->key, args->projection, args->projection_size, args->challenge,
        args->ack, args->bundle);
    return NULL;
}

int main(void) {
    static const uint8_t projection[] = "exact-durable-projection";
    struct plamen_broker_v2_commitment commitment, decoded_commitment;
    struct plamen_broker_v2_service_session_challenge challenge;
    struct plamen_broker_v2_service_session_ack ack;
    struct plamen_broker_v2_authority_bundle_binding bundle, decoded_bundle;
    struct plamen_broker_v2_operation_request operation_request;
    struct plamen_broker_v2_operation_error operation_error;
    struct plamen_broker_v2_session client;
    struct plamen_broker_v2_frame_view view;
    struct plamen_broker_v2_writer writer;
    struct thread_args args;
    pthread_t thread;
    uint8_t key[32], zeros[32] = { 0 };
    uint8_t commitment_bytes[PLAMEN_BROKER_V2_COMMITMENT_MAX_SIZE];
    uint8_t bundle_bytes[PLAMEN_BROKER_V2_OUTER_AUTHORITY_BUNDLE_SIZE];
    uint8_t operation_bytes[PLAMEN_BROKER_V2_OPERATION_REQUEST_PREFIX_SIZE + 5];
    static const uint8_t call_bytes[] = "call\n";
    uint8_t *frame = NULL;
    size_t commitment_size, bundle_size, frame_size, operation_size;
    int sockets[2], index;

    memset(&commitment, 0, sizeof(commitment));
    memset(&decoded_commitment, 0, sizeof(decoded_commitment));
    memset(&challenge, 0, sizeof(challenge));
    memset(&ack, 0, sizeof(ack));
    memset(&bundle, 0, sizeof(bundle));
    memset(&decoded_bundle, 0, sizeof(decoded_bundle));
    memset(&operation_request, 0, sizeof(operation_request));
    memset(&operation_error, 0, sizeof(operation_error));
    memset(&client, 0, sizeof(client));
    memset(&args, 0, sizeof(args));
    fill(key, 1);
    fill(commitment.request_fingerprint, 2);
    strcpy(commitment.attempt_id, "attempt-1");
    strcpy(commitment.run_identity, "run-1");
    fill(commitment.config_sha256, 3);
    fill(commitment.runtime_closure_sha256, 4);
    fill(commitment.image_closure_sha256, 5);
    fill(commitment.provider_provenance_sha256, 6);
    fill(commitment.backend_admission_sha256, 7);
    fill(commitment.credential_isolation_sha256, 8);
    fill(commitment.egress_admission_sha256, 9);
    plamen_broker_v2_writer_init(&writer, commitment_bytes,
        sizeof(commitment_bytes));
    if (plamen_broker_v2_encode_commitment(&writer, &commitment) != 0)
        return 10;
    commitment_size = writer.offset;
    memcpy(challenge.commitment, commitment_bytes, commitment_size);
    challenge.commitment_size = (uint16_t)commitment_size;
    if (plamen_broker_v2_sha256(commitment_bytes, commitment_size,
            challenge.commitment_sha256) != 0)
        return 11;
    fill(challenge.session_id, 10);
    bundle.role = PLAMEN_BROKER_V2_INITIAL_OUTER_SUPERVISOR;
    bundle.member_count = PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT;
    fill(bundle.registration_sha256, 11);
    fill(bundle.issuance_checkpoint_sha256, 12);
    for (index = 0; index < (int)bundle.member_count; ++index)
        fill(bundle.member_sha256[index], (uint8_t)(20 + index));
    memcpy(ack.registration_sha256, bundle.registration_sha256, 32);
    memcpy(ack.registration_burn_checkpoint_sha256,
        bundle.issuance_checkpoint_sha256, 32);
    memcpy(ack.session_id, challenge.session_id, 32);
    ack.initial_authority_role = bundle.role;
    if (plamen_broker_v2_authority_bundle_binding_encode(&bundle,
            bundle_bytes, sizeof(bundle_bytes), &bundle_size) != 0
        || plamen_broker_v2_sha256(bundle_bytes, bundle_size,
            ack.authority_bundle_sha256) != 0
        || socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return 12;
    args.fd = sockets[0];
    args.key = key;
    args.projection = projection;
    args.projection_size = sizeof(projection) - 1;
    args.challenge = &challenge;
    args.ack = &ack;
    args.bundle = &bundle;
    if (pthread_create(&thread, NULL, run_server, &args) != 0
        || plamen_broker_v2_session_init(&client,
            PLAMEN_BROKER_V2_ROLE_EXTENSION, key, challenge.session_id) != 0)
        return 13;
    if (receive_frame(sockets[1], &frame, &frame_size) != 0
        || plamen_broker_v2_frame_accept(&client, frame, frame_size, 0,
            &view) != 0 || view.type != PLAMEN_BROKER_V2_HELLO)
        return 14;
    free(frame); frame = NULL;
    if (send_frame(sockets[1], &client, PLAMEN_BROKER_V2_REQUEST_PROJECTION,
            zeros, NULL, 0) != 0
        || receive_frame(sockets[1], &frame, &frame_size) != 0
        || plamen_broker_v2_frame_accept(&client, frame, frame_size, 0,
            &view) != 0 || view.type != PLAMEN_BROKER_V2_REQUEST_PROJECTED
        || view.payload_size != sizeof(projection) - 1
        || memcmp(view.payload, projection, sizeof(projection) - 1) != 0)
        return 15;
    free(frame); frame = NULL;
    if (send_frame(sockets[1], &client, PLAMEN_BROKER_V2_AUTH_CONSUME,
            zeros, commitment_bytes, (uint32_t)commitment_size) != 0
        || receive_frame(sockets[1], &frame, &frame_size) != 0
        || plamen_broker_v2_frame_accept(&client, frame, frame_size, 0,
            &view) != 0 || view.type != PLAMEN_BROKER_V2_AUTH_ACCEPTED
        || plamen_broker_v2_auth_accepted_matches_session_ack(&ack,
            view.payload, view.payload_size, &decoded_bundle) != 0
        || memcmp(&decoded_bundle, &bundle, sizeof(bundle)) != 0)
        return 16;
    free(frame); frame = NULL;
    operation_request.authority_role = bundle.role;
    operation_request.member = PLAMEN_BROKER_V2_AUTHORITY_PROVIDER_LIFECYCLE;
    operation_request.method = PLAMEN_BROKER_V2_METHOD_PROVIDER_KIND;
    fill(operation_request.prior_checkpoint_sha256, 40);
    memcpy(operation_request.request_fingerprint,
        commitment.request_fingerprint, 32);
    operation_request.payload = call_bytes;
    operation_request.payload_size = sizeof(call_bytes) - 1;
    if (plamen_broker_v2_sha256(call_bytes, sizeof(call_bytes) - 1,
            operation_request.payload_sha256) != 0
        || plamen_broker_v2_derive_rpc_operation_key(&commitment,
            bundle.member_sha256[operation_request.member - 1], bundle.role,
            operation_request.member, operation_request.method,
            operation_request.payload_sha256,
            operation_request.prior_checkpoint_sha256,
            operation_request.operation_key) != 0
        || plamen_broker_v2_operation_request_encode(&operation_request,
            operation_bytes, sizeof(operation_bytes), &operation_size) != 0
        || send_frame(sockets[1], &client, PLAMEN_BROKER_V2_OPERATION_REQUEST,
            operation_request.operation_key, operation_bytes,
            (uint32_t)operation_size) != 0
        || receive_frame(sockets[1], &frame, &frame_size) != 0
        || plamen_broker_v2_frame_accept(&client, frame, frame_size, 0,
            &view) != 0 || view.type != PLAMEN_BROKER_V2_OPERATION_ERROR
        || plamen_broker_v2_operation_error_decode(view.payload,
            view.payload_size, &operation_error) != 0
        || !plamen_broker_v2_operation_error_matches_request(operation_bytes,
            operation_size, &operation_request, &operation_error)
        || operation_error.error_code != PLAMEN_BROKER_V2_SERVICE_ERR_UNSUPPORTED
        || operation_error.flags
            != PLAMEN_BROKER_V2_SERVICE_DURABLE_EFFECT_UNCHANGED)
        return 17;
    free(frame);
    close(sockets[1]);
    if (pthread_join(thread, NULL) != 0 || args.result != 0)
        return 18;
    return 0;
}
"""


def _compile_from_stdin(output: Path, source: str, *extra: str) -> None:
    subprocess.run(
        [str(CLANG), "-std=c11", "-Wall", "-Wextra", "-Werror", *extra,
         "-x", "c", "-", "-o", str(output)],
        input=source.encode(), check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


@pytest.fixture(scope="module")
def native_tools(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, Path]:
    directory = tmp_path_factory.mktemp("darwin-broker-v2")
    driver = directory / "plamen_broker_v2_process_TEST_ONLY"
    launcher = directory / "plamen_native_launcher"
    helper = directory / "plamen_process_fixture_TEST_ONLY"
    subprocess.run(
        [str(CLANG), "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-DPLAMEN_BROKER_V2_TEST_ONLY=1",
         "-DPLAMEN_BROKER_V2_TEST_DRIVER=1", str(SOURCE),
         "-framework", "Security", "-framework", "CoreFoundation",
         "-o", str(driver)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    subprocess.run(
        [str(CLANG), "-std=c11", "-Wall", "-Wextra", "-Werror", "-fblocks",
         "-I", str(ROOT / "native" / "include"),
         "-I", str(ROOT / "native" / "darwin"),
         str(LAUNCHER), str(INSTALL_RECEIPT), str(DEPLOYMENT_RECEIPT),
         str(PROTOCOL),
         "-framework", "Security",
         "-framework", "CoreFoundation", "-o", str(launcher)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    _compile_from_stdin(helper, HELPER_SOURCE)
    return driver, launcher, helper


@pytest.fixture(scope="module")
def production_tools(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path]:
    directory = tmp_path_factory.mktemp("darwin-broker-v2-production")
    driver = directory / "plamen_broker_v2_process_production"
    helper = directory / "plamen_process_fixture_production"
    _compile_from_stdin(helper, HELPER_SOURCE)
    _compile_from_stdin(
        driver,
        PRODUCTION_DRIVER_SOURCE,
        "-I", str(ROOT / "native" / "darwin"),
        str(SOURCE),
        "-framework", "Security", "-framework", "CoreFoundation",
    )
    return driver, helper


def _parse(output: bytes) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.decode().splitlines())


def _command(
    driver: Path,
    executable: Path,
    executable_fd: int,
    argv: list[str],
    *,
    expected_sha: str | None = None,
    signing_id: str | None = None,
    team_id: str = "",
    timeout_ms: int = 5000,
    stdout_limit: int = 1024 * 1024,
    stderr_limit: int = 1024 * 1024,
    cwd_fd: int,
    stdin_fd: int,
    pass_fd: int = -1,
    pass_target: int = -1,
    gate_fd: int = -1,
    cancel_fd: int = -1,
) -> list[str]:
    command = [
        str(driver),
        "--executable-fd", str(executable_fd),
        "--path", str(executable),
        "--sha256", expected_sha or hashlib.sha256(executable.read_bytes()).hexdigest(),
        "--signing-id", signing_id if signing_id is not None else executable.name,
        "--team-id", team_id,
        "--timeout-ms", str(timeout_ms),
        "--stdout-limit", str(stdout_limit),
        "--stderr-limit", str(stderr_limit),
        "--cwd-fd", str(cwd_fd),
        "--stdin-fd", str(stdin_fd),
    ]
    if pass_fd >= 0:
        command += ["--pass-fd", str(pass_fd), "--pass-target", str(pass_target)]
    if gate_fd >= 0:
        command += ["--gate-fd", str(gate_fd)]
    if cancel_fd >= 0:
        command += ["--cancel-fd", str(cancel_fd)]
    return command + ["--", *argv]


def _run(
    driver: Path,
    executable: Path,
    argv: list[str],
    **options: object,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, str]]:
    executable_fd = os.open(executable, os.O_RDONLY)
    cwd_fd = os.open(executable.parent, os.O_RDONLY | os.O_DIRECTORY)
    stdin_fd = os.open(os.devnull, os.O_RDONLY)
    extra_fds = [
        int(options[key]) for key in ("pass_fd", "gate_fd", "cancel_fd")
        if key in options and int(options[key]) >= 0
    ]
    try:
        command = _command(
            driver, executable, executable_fd, argv,
            cwd_fd=cwd_fd, stdin_fd=stdin_fd, **options,
        )
        completed = subprocess.run(
            command, pass_fds=(executable_fd, cwd_fd, stdin_fd, *extra_fds),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        return completed, _parse(completed.stdout)
    finally:
        os.close(executable_fd)
        os.close(cwd_fd)
        os.close(stdin_fd)


def _pid_is_gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _external_profile_bytes(backend_selector: str = "codex") -> bytes:
    if backend_selector == "codex":
        backend_team = b"2DC432GLL2"
        backend_version = b"codex-cli 0.153.4"
        backend_release = b"0.153.4-aarch64-apple-darwin"
    elif backend_selector == "claude":
        backend_team = b"Q6L2SF6YDW"
        backend_version = b"2.1.252 (Claude Code)"
        backend_release = b"2.1.252"
    else:
        raise ValueError("unsupported test backend selector")
    selector = backend_selector.encode("ascii")
    data = bytearray(2048)
    data[:8] = b"PLMBPF2\0"
    struct.pack_into(">HHII", data, 8, 2, 256, 2048, 1)
    data[32:64] = hashlib.sha256(b"provider executable").digest()
    data[64:96] = hashlib.sha256(b"backend executable").digest()
    data[96:116] = b"p" * 20
    data[128:148] = b"b" * 20
    data[182:214] = bytes.fromhex(
        "20e6dcb3db56225d5615e58c5bf56ff1bc5854cf550abf41afc80e4efb7cee61"
    )
    fields = (
        (256, 128, b"com.apple.container.cli"),
        (384, 128, b"UPBK2H6LZM"),
        (512, 128, b"container CLI version 1.3.1"),
        (640, 128, b"com.anthropic.claude-code" if backend_selector == "claude" else b"codex"),
        (768, 128, backend_team),
        (896, 128, backend_version),
        (1024, 256, backend_release),
        (1280, 32, selector),
        (1312, 32, b"apple-container-v2"),
    )
    lengths = [20, 20, *(len(value) for _, _, value in fields)]
    struct.pack_into(">" + "H" * len(lengths), data, 160, *lengths)
    for offset, capacity, value in fields:
        assert len(value) < capacity
        data[offset:offset + len(value)] = value
    data[2016:] = hashlib.sha256(data[:2016]).digest()
    return bytes(data)


def _runtime_manifest_for_profile(
    profile: bytes, backend_selector: str = "codex",
) -> bytes:
    data = bytearray(256 + 2048 + 640 + 32)
    data[:8] = b"PLMRPM2\0"
    struct.pack_into(">HHII", data, 8, 2, 256, len(data), 640)
    struct.pack_into(">I", data, 20, 1)
    row = 256 + 2048
    path = f"profiles/{backend_selector}-v2.bin".encode("ascii")
    struct.pack_into(">HHIQI", data, row, 2, len(path), 0o400, len(profile), 1)
    data[row + 24:row + 56] = hashlib.sha256(profile).digest()
    data[row + 56:row + 56 + len(path)] = path
    return bytes(data)


@pytest.mark.parametrize("backend_selector", ["codex", "claude"])
def test_external_profile_is_exact_and_role8_bound(
    tmp_path: Path, backend_selector: str,
) -> None:
    launcher_object = tmp_path / "launcher_TEST_ONLY.o"
    driver = tmp_path / "profile_TEST_ONLY"
    subprocess.run(
        [str(CLANG), "-std=c11", "-Wall", "-Wextra", "-Werror", "-fblocks",
         "-DPLAMEN_BROKER_V2_TEST_ONLY=1",
         "-Dmain=plamen_native_launcher_main_TEST_ONLY",
         "-I", str(ROOT / "native" / "include"),
         "-I", str(ROOT / "native" / "darwin"),
         "-c", str(LAUNCHER), "-o", str(launcher_object)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    _compile_from_stdin(
        driver, PROFILE_TEST_SOURCE,
        "-I", str(ROOT / "native" / "include"),
        "-I", str(ROOT / "native" / "darwin"),
        str(launcher_object), str(INSTALL_RECEIPT), str(DEPLOYMENT_RECEIPT),
        str(PROTOCOL), "-fblocks",
        "-framework", "Security", "-framework", "CoreFoundation",
    )
    profile_bytes = _external_profile_bytes(backend_selector)
    profile = tmp_path / f"{backend_selector}-v2.bin"
    manifest = tmp_path / "runtime-package-manifest-v2.bin"
    profile.write_bytes(profile_bytes)
    profile.chmod(0o400)
    manifest.write_bytes(
        _runtime_manifest_for_profile(profile_bytes, backend_selector)
    )
    manifest.chmod(0o400)
    assert subprocess.run([str(driver), str(profile), str(manifest)]).returncode == 0

    profile.chmod(0o600)
    tampered = bytearray(profile_bytes)
    tampered[512] ^= 1
    profile.write_bytes(tampered)
    profile.chmod(0o400)
    assert subprocess.run([str(driver), str(profile), str(manifest)]).returncode == 1

    profile.chmod(0o600)
    profile.write_bytes(profile_bytes)
    profile.chmod(0o400)
    manifest.chmod(0o600)
    tampered_manifest = bytearray(
        _runtime_manifest_for_profile(profile_bytes, backend_selector)
    )
    tampered_manifest[256 + 2048 + 24] ^= 1
    manifest.write_bytes(tampered_manifest)
    manifest.chmod(0o400)
    assert subprocess.run([str(driver), str(profile), str(manifest)]).returncode == 1


def test_credential_authority_is_unlinked_before_secret_copy(
    tmp_path: Path,
) -> None:
    launcher_object = tmp_path / "launcher_credential_TEST_ONLY.o"
    driver = tmp_path / "credential_TEST_ONLY"
    install_root = tmp_path / "install-root"
    install_root.mkdir(mode=0o700)
    subprocess.run(
        [str(CLANG), "-std=c11", "-Wall", "-Wextra", "-Werror", "-fblocks",
         "-DPLAMEN_BROKER_V2_TEST_ONLY=1",
         "-Dmain=plamen_native_launcher_main_TEST_ONLY",
         "-I", str(ROOT / "native" / "include"),
         "-I", str(ROOT / "native" / "darwin"),
         "-c", str(LAUNCHER), "-o", str(launcher_object)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    _compile_from_stdin(
        driver, CREDENTIAL_TEST_SOURCE,
        "-I", str(ROOT / "native" / "include"),
        "-I", str(ROOT / "native" / "darwin"),
        str(launcher_object), str(INSTALL_RECEIPT), str(DEPLOYMENT_RECEIPT),
        str(PROTOCOL), "-fblocks",
        "-framework", "Security", "-framework", "CoreFoundation",
    )
    assert subprocess.run([str(driver), str(install_root)]).returncode == 0
    authority_directory = (
        install_root / "service-state-v2" / "launcher-authority-v2"
    )
    assert list(authority_directory.iterdir()) == []


def test_production_launcher_is_fixed_and_hardstopped(native_tools: tuple[Path, Path, Path]) -> None:
    _, launcher, _ = native_tools
    result = subprocess.run([str(launcher)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode == 64
    assert result.stderr == b""
    assert subprocess.run([str(launcher), "attacker.py"]).returncode == 64
    result = subprocess.run(
        [str(launcher), "start-config", "/does/not/exist.json"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert result.returncode == 78
    assert result.stderr == (
        b"PLAMEN_NATIVE_LAUNCHER_HARDSTOP_NATIVE_AUDIT_AUTHORITY_REQUIRED\n"
    )
    readiness = subprocess.run(
        [str(launcher), "readiness"], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert readiness.returncode == 78
    assert readiness.stderr == (
        b"PLAMEN_NATIVE_LAUNCHER_HARDSTOP_NATIVE_AUDIT_AUTHORITY_REQUIRED\n"
    )
    overlong = "/" + "x" * 1025
    assert subprocess.run(
        [str(launcher), "resume", overlong], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).returncode == 64


def test_xpc_service_is_native_and_hardstopped_without_durable_authority(
    tmp_path: Path,
) -> None:
    service = tmp_path / "plamen_broker_v2_service"
    subprocess.run(
        [str(CLANG), "-std=c11", "-Wall", "-Wextra", "-Werror", "-fblocks",
         "-I", str(ROOT / "native" / "include"),
         "-I", str(ROOT / "native" / "darwin"),
         "-I", str(ROOT / "native" / "posix"),
         str(SERVICE), str(SERVICE_STORE), str(INSTALL_RECEIPT), str(SOURCE),
         str(CUSTODIAN), str(CUSTODY_DAEMON), str(CUSTODY_CLIENT),
             str(APPLE_CONTAINER), str(APPLE_LIFECYCLE), str(TOOL_CUSTODY),
             str(EFFECTS), str(SPECIALIZED_REQUEST),
             str(SPECIALIZED_RUNTIME_AUTHORITY),
             str(SPECIALIZED_RUNTIME_EFFECTS_HANDOFF),
             str(SPECIALIZED_EFFECT_STORE),
                 str(SPECIALIZED_APPLE_EFFECT_EXECUTION),
                 str(FUZZ_CAMPAIGN),
             str(SPECIALIZED_OUTPUT_CENSUS),
             str(SPECIALIZED_OUTPUT_RECEIPT), str(IMAGE_MEMBER_RECEIPT),
             str(ARTIFACT_EXPORT), str(NATIVE_BUILDER), str(WORKSPACE_EFFECTS),
         str(OPERATIONS), str(PROTOCOL),
         "-framework", "Security",
         "-framework", "CoreFoundation", "-o", str(service)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    completed = subprocess.run(
        [str(service)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert completed.returncode == 78
    assert completed.stdout == b""
    assert completed.stderr == (
        b"PLAMEN_BROKER_V2_SERVICE_HARDSTOP_NATIVE_INSTALL_RECEIPT_REQUIRED\n"
    )
    assert subprocess.run([str(service), "--forged"]).returncode == 64


def test_authenticated_session_streams_projection_and_exact_capability_bundle(
    tmp_path: Path,
) -> None:
    service_object = tmp_path / "plamen_broker_v2_service_TEST_ONLY.o"
    driver = tmp_path / "plamen_broker_v2_session_wire_TEST_ONLY"
    subprocess.run(
        [str(CLANG), "-std=c11", "-Wall", "-Wextra", "-Werror", "-fblocks",
         "-DPLAMEN_BROKER_V2_TEST_ONLY=1",
         "-Dmain=plamen_broker_v2_service_main_TEST_ONLY",
         "-I", str(ROOT / "native" / "include"),
         "-I", str(ROOT / "native" / "darwin"),
         "-I", str(ROOT / "native" / "posix"),
         "-c", str(SERVICE), "-o", str(service_object)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    _compile_from_stdin(
        driver, SESSION_WIRE_TEST_SOURCE,
        "-I", str(ROOT / "native" / "include"),
        "-I", str(ROOT / "native" / "darwin"),
        "-I", str(ROOT / "native" / "posix"),
            str(service_object), str(SERVICE_STORE), str(INSTALL_RECEIPT),
            str(SOURCE), str(CUSTODIAN), str(CUSTODY_DAEMON),
            str(CUSTODY_CLIENT),
                str(APPLE_CONTAINER), str(APPLE_LIFECYCLE),
                str(TOOL_CUSTODY), str(EFFECTS),
        str(SPECIALIZED_REQUEST), str(SPECIALIZED_RUNTIME_AUTHORITY),
        str(SPECIALIZED_RUNTIME_EFFECTS_HANDOFF),
        str(SPECIALIZED_EFFECT_STORE),
            str(SPECIALIZED_APPLE_EFFECT_EXECUTION),
            str(FUZZ_CAMPAIGN),
        str(SPECIALIZED_OUTPUT_CENSUS), str(SPECIALIZED_OUTPUT_RECEIPT),
        str(IMAGE_MEMBER_RECEIPT), str(ARTIFACT_EXPORT), str(NATIVE_BUILDER),
        str(WORKSPACE_EFFECTS), str(OPERATIONS),
        str(PROTOCOL), "-fblocks",
        "-framework", "Security",
        "-framework", "CoreFoundation",
    )
    completed = subprocess.run(
        [str(driver)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr.decode()


def test_consumed_registration_is_never_returned_as_unused(tmp_path: Path) -> None:
    driver = tmp_path / "plamen_service_store_burn_TEST_ONLY"
    _compile_from_stdin(
        driver, STORE_BURN_TEST_SOURCE,
        "-I", str(ROOT / "native" / "include"),
        "-I", str(ROOT / "native" / "darwin"),
        str(SERVICE_STORE), str(PROTOCOL),
        "-framework", "Security", "-framework", "CoreFoundation",
    )
    state = tmp_path / "state"
    completed = subprocess.run(
        [str(driver), str(state)], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert completed.returncode == 0, completed.stderr.decode()


def test_suspended_spawn_attests_and_captures(native_tools: tuple[Path, Path, Path]) -> None:
    driver, _, helper = native_tools
    completed, result = _run(driver, helper, [str(helper), "ok", "7"])
    assert completed.returncode == 0
    assert result["STATUS"] == "0"
    assert result["EXIT"] == "7"
    assert result["SIGNAL"] == "0"
    assert int(result["BIRTH_US"]) > 0
    assert result["SIGNING_ID"] == helper.name
    assert result["TEAM_ID"] == ""
    assert len(result["CDHASH"]) in (40, 64)
    assert bytes.fromhex(result["STDOUT_HEX"]) == b"stdout-evidence\n"
    assert bytes.fromhex(result["STDERR_HEX"]) == b"stderr-evidence\n"
    assert result["STDOUT_SHA256"] == hashlib.sha256(b"stdout-evidence\n").hexdigest()
    assert result["STDERR_SHA256"] == hashlib.sha256(b"stderr-evidence\n").hexdigest()
    assert result["REAPED"] == result["EXTINCT"] == "1"


@pytest.mark.parametrize(
    ("mode", "terminal_status", "stdout_size", "overflow", "read_status"),
    [
        ("ok", "0", "16", "0", "0"),
        ("env", "0", "18", "0", "0"),
        ("fds", "0", "4", "0", "0"),
        ("fds-max", "0", "9", "0", "0"),
        ("extinguish", "3", "0", "0", "0"),
        ("timeout", "1", "0", "0", "0"),
        ("overflow", "2", "16777217", "1", "4"),
    ],
)
def test_production_custody_lifecycle_and_replay(
    production_tools: tuple[Path, Path], mode: str, terminal_status: str,
    stdout_size: str, overflow: str, read_status: str,
) -> None:
    driver, helper = production_tools
    completed = subprocess.run(
        [str(driver), str(helper), str(helper.parent),
         hashlib.sha256(helper.read_bytes()).hexdigest(), mode, helper.name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    result = _parse(completed.stdout)
    assert result["AVAILABLE"] == "1"
    assert result["PREPARE"] == result["START"] == "0"
    assert result["PREPARED_SHA"] == result["HANDLE_SHA"] == "1"
    assert int(result["PID"]) > 0
    assert result["PGID"] == result["PID"]
    assert result["CLOSE_LIVE"] == "4"
    assert result["WAIT"] == result["TERMINAL"] == terminal_status
    assert result["REWAIT"] == terminal_status
    assert result["REAPED"] == result["EXTINCT"] == "1"
    assert result["STDOUT_SIZE"] == stdout_size
    assert result["STDOUT_OVERFLOW"] == overflow
    assert result["READ"] == read_status
    assert result["CLOSE"] == "0"
    if mode != "overflow":
        assert result["REPLAY_EQUAL"] == "1"


def test_production_symbols_do_not_enable_test_spawn_seam(tmp_path: Path) -> None:
    source = r'''
#include "plamen_broker_v2_process.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    struct plamen_broker_v2_test_result result;
    memset(&result, 0, sizeof(result));
    printf("%d\n", plamen_broker_v2_test_spawn_wait(NULL, &result));
    return 0;
}
'''
    binary = tmp_path / "production-test-seam-check"
    _compile_from_stdin(
        binary, source, "-I", str(ROOT / "native" / "darwin"),
        str(SOURCE), "-framework", "Security", "-framework", "CoreFoundation",
    )
    completed = subprocess.run(
        [str(binary)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=True,
    )
    assert completed.stdout == b"78\n"


def test_production_timeout_boundary_is_exact(
    production_tools: tuple[Path, Path],
) -> None:
    driver, helper = production_tools
    common = [
        str(driver), str(helper), str(helper.parent),
        hashlib.sha256(helper.read_bytes()).hexdigest(),
    ]
    maximum = subprocess.run(
        [*common, "max-timeout", helper.name], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10,
    )
    assert maximum.returncode == 0, maximum.stderr.decode()
    maximum_result = _parse(maximum.stdout)
    assert maximum_result["PREPARE"] == "0"
    assert maximum_result["CLOSE"] == "0"
    over = subprocess.run(
        [*common, "over-timeout", helper.name], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10,
    )
    assert over.returncode == 4
    assert _parse(over.stdout)["PREPARE"] == "4"


def test_production_spool_boundary_is_exact(
    production_tools: tuple[Path, Path],
) -> None:
    driver, helper = production_tools
    common = [
        str(driver), str(helper), str(helper.parent),
        hashlib.sha256(helper.read_bytes()).hexdigest(),
    ]
    maximum = subprocess.run(
        [*common, "max-spool", helper.name], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10,
    )
    assert maximum.returncode == 0, maximum.stderr.decode()
    maximum_result = _parse(maximum.stdout)
    assert maximum_result["PREPARE"] == "0"
    assert maximum_result["CLOSE"] == "0"
    over = subprocess.run(
        [*common, "over-spool", helper.name], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10,
    )
    assert over.returncode == 4
    assert _parse(over.stdout)["PREPARE"] == "4"


@pytest.mark.parametrize("mode", ["duplicate-env", "invalid-env"])
def test_production_rejects_ambiguous_environment_before_spawn(
    production_tools: tuple[Path, Path], mode: str,
) -> None:
    driver, helper = production_tools
    completed = subprocess.run(
        [str(driver), str(helper), str(helper.parent),
         hashlib.sha256(helper.read_bytes()).hexdigest(), mode, helper.name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    assert completed.returncode == 4
    assert _parse(completed.stdout)["PREPARE"] == "4"


@pytest.mark.parametrize(
    "mode",
    [
        "fds-over",
        "fds-duplicate-source",
        "fds-duplicate-target",
        "fds-target-over",
        "fds-rlimit",
    ],
)
def test_production_rejects_invalid_fd_map_before_spawn(
    production_tools: tuple[Path, Path], mode: str,
) -> None:
    driver, helper = production_tools
    completed = subprocess.run(
        [str(driver), str(helper), str(helper.parent),
         hashlib.sha256(helper.read_bytes()).hexdigest(), mode, helper.name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    assert completed.returncode == 4, completed.stderr.decode()
    assert _parse(completed.stdout)["PREPARE"] == "4"


@pytest.mark.parametrize(
    ("options", "status"),
    [
        ({"expected_sha": "00" * 32}, "4"),
        ({"signing_id": "dev.plamen.impossible"}, "4"),
        ({"team_id": "IMPOSSIBLETEAM"}, "4"),
    ],
)
def test_hash_and_code_signing_mismatch_have_no_effect(
    native_tools: tuple[Path, Path, Path], tmp_path: Path,
    options: dict[str, str], status: str,
) -> None:
    driver, _, helper = native_tools
    marker = tmp_path / "must-not-exist"
    completed, result = _run(
        driver, helper, [str(helper), "marker", str(marker)], **options,
    )
    assert completed.returncode == int(status)
    assert result["STATUS"] == status
    assert not marker.exists()
    if options.get("signing_id") or options.get("team_id"):
        assert result["REAPED"] == result["EXTINCT"] == "1"


def test_path_substitution_is_killed_before_user_code(
    native_tools: tuple[Path, Path, Path], tmp_path: Path,
) -> None:
    driver, _, helper = native_tools
    target = tmp_path / helper.name
    attacker = tmp_path / "attacker"
    pinned = tmp_path / "pinned"
    marker = tmp_path / "attacker-effect"
    shutil.copy2(helper, target)
    _compile_from_stdin(attacker, HELPER_SOURCE)
    expected_sha = hashlib.sha256(target.read_bytes()).hexdigest()
    executable_fd = os.open(target, os.O_RDONLY)
    cwd_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    stdin_fd = os.open(os.devnull, os.O_RDONLY)
    parent_gate, child_gate = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        process = subprocess.Popen(
            _command(
                driver, target, executable_fd,
                [str(target), "marker", str(marker)],
                expected_sha=expected_sha, signing_id=helper.name,
                cwd_fd=cwd_fd, stdin_fd=stdin_fd, gate_fd=child_gate.fileno(),
            ),
            pass_fds=(executable_fd, cwd_fd, stdin_fd, child_gate.fileno()),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        child_gate.close()
        assert parent_gate.recv(1) == b"\x5a"
        target.rename(pinned)
        attacker.rename(target)
        parent_gate.sendall(b"\xa5")
        stdout, stderr = process.communicate(timeout=10)
        result = _parse(stdout)
        assert process.returncode == 4, stderr.decode()
        assert result["STATUS"] == "4"
        assert result["REAPED"] == result["EXTINCT"] == "1"
        assert not marker.exists()
    finally:
        parent_gate.close()
        child_gate.close()
        os.close(executable_fd)
        os.close(cwd_fd)
        os.close(stdin_fd)


def test_timeout_revokes_and_reaps(native_tools: tuple[Path, Path, Path]) -> None:
    driver, _, helper = native_tools
    completed, result = _run(
        driver, helper, [str(helper), "timeout"], timeout_ms=100,
    )
    assert completed.returncode == 1
    assert result["STATUS"] == "1"
    assert result["REAPED"] == result["EXTINCT"] == "1"


def test_overflow_revokes_and_bounds_retention(native_tools: tuple[Path, Path, Path]) -> None:
    driver, _, helper = native_tools
    completed, result = _run(
        driver, helper, [str(helper), "overflow"], stdout_limit=4096,
    )
    assert completed.returncode == 2
    assert result["STATUS"] == "2"
    assert int(result["STDOUT_OBSERVED"]) > 16 * 1024 * 1024
    assert len(bytes.fromhex(result["STDOUT_HEX"])) == 4096
    assert result["STDOUT_TRUNCATED"] == "1"
    assert result["REAPED"] == result["EXTINCT"] == "1"


def test_cloexec_default_preserves_only_allowlisted_pass_fd(
    native_tools: tuple[Path, Path, Path],
) -> None:
    driver, _, helper = native_tools
    pass_read, pass_write = os.pipe()
    try:
        completed, result = _run(
            driver, helper, [str(helper), "fds"],
            pass_fd=pass_read, pass_target=9,
        )
        assert completed.returncode == 0
        assert bytes.fromhex(result["STDOUT_HEX"]) == b"1:9\n"
    finally:
        os.close(pass_read)
        os.close(pass_write)


def test_cancel_fd_interrupts_after_effect_and_reaps(
    native_tools: tuple[Path, Path, Path], tmp_path: Path,
) -> None:
    driver, _, helper = native_tools
    marker = tmp_path / "started"
    cancel_read, cancel_write = os.pipe()
    executable_fd = os.open(helper, os.O_RDONLY)
    cwd_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    stdin_fd = os.open(os.devnull, os.O_RDONLY)
    try:
        process = subprocess.Popen(
            _command(
                driver, helper, executable_fd,
                [str(helper), "started", str(marker)], cwd_fd=cwd_fd,
                stdin_fd=stdin_fd, cancel_fd=cancel_read,
            ),
            pass_fds=(executable_fd, cwd_fd, stdin_fd, cancel_read),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for _ in range(200):
            if marker.exists():
                break
            time.sleep(0.01)
        assert marker.read_bytes() == b"effect\n"
        os.write(cancel_write, b"cancel")
        stdout, stderr = process.communicate(timeout=10)
        result = _parse(stdout)
        assert process.returncode == 3, stderr.decode()
        assert result["STATUS"] == "3"
        assert result["REAPED"] == result["EXTINCT"] == "1"
    finally:
        os.close(cancel_read)
        os.close(cancel_write)
        os.close(executable_fd)
        os.close(cwd_fd)
        os.close(stdin_fd)
        if process.poll() is None:
            process.send_signal(signal.SIGKILL)
            process.wait()


def test_descendant_process_group_is_extinct_before_success(
    native_tools: tuple[Path, Path, Path],
) -> None:
    driver, _, helper = native_tools
    completed, result = _run(driver, helper, [str(helper), "tree"])
    assert completed.returncode == 0
    descendant = int(bytes.fromhex(result["STDOUT_HEX"]).strip())
    assert result["REAPED"] == result["EXTINCT"] == "1"
    assert _pid_is_gone(descendant)


def test_source_contains_no_python_or_path_resume_shortcut() -> None:
    source = SOURCE.read_text()
    assert "ctypes" not in source
    assert "POSIX_SPAWN_START_SUSPENDED" in source
    assert source.index("authenticate_suspended_image") < source.index("kill(child, SIGCONT)")
    assert "SecCodeCopyGuestWithAttributes" in source
    assert "SecCodeCheckValidity" in source
    assert "proc_pidpath" in source


def test_launcher_and_service_use_only_native_shared_bootstrap_contract() -> None:
    launcher = LAUNCHER.read_text()
    service = SERVICE.read_text()
    assert "ctypes" not in launcher + service
    assert "xpc_connection_set_peer_code_signing_requirement" in launcher
    assert "plamen_broker_v2_service_registration_encode" in launcher
    assert "plamen_broker_v2_service_registration_ack_decode" in launcher
    assert "PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE" in launcher
    assert "POSIX_SPAWN_START_SUSPENDED" in launcher
    assert launcher.index("register_suspended_child(authority") < launcher.index(
        "kill(child, SIGCONT)"
    )
    assert "xpc_connection_get_pid" in service
    assert "xpc_connection_get_euid" in service
    assert "xpc_connection_get_egid" in service
    assert "plamen_broker_v2_service_envelope_accept" in service
    assert "PLAMEN_BROKER_V2_SERVICE_ERR_DURABILITY" in service
    assert "open_install_root_from_generation" in launcher
    assert "open_install_root" in service
    assert "open_relative_file(install_root_fd" in launcher
    assert "open_relative_file(install_root_fd" in service
    assert "strcmp(self_path, stable_self_path) == 0" in launcher
    assert "strcmp(self_path, generation_self_path) == 0" in launcher
    assert "strlen(self_path) - strlen(PLAMEN_LAUNCHER_SUFFIX)" not in launcher
    store = SERVICE_STORE.read_text()
    lookup = store[store.index("plamen_broker_v2_service_store_lookup_unused"):]
    assert lookup.index("record_exists(store, registration_sha256") < lookup.index(
        "load_registration(store, registration_sha256"
    )
