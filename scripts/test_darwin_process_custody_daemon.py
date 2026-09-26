from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="Darwin launchd/XPC custody daemon only"
)

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include "plamen_broker_v2_process_custody_daemon.h"
#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

struct plamen_broker_v2_process { int state; };
static int starts, waits;
static const uint8_t out_bytes[] = "daemon-owned-output\n";

int plamen_broker_v2_process_prepare(const struct plamen_broker_v2_process_spec *s,
    struct plamen_broker_v2_process_prepared_identity *i,
    struct plamen_broker_v2_process **p) {
    (void)s; memset(i, 0, sizeof(*i)); i->version = 1;
    *p = calloc(1, sizeof(**p)); if (*p == NULL) return 4; (*p)->state = 1; return 0;
}
int plamen_broker_v2_process_start(struct plamen_broker_v2_process *p,
    struct plamen_broker_v2_process_start_identity *i) {
    if (p == NULL || p->state != 1) return 4; starts++; p->state = 2;
    memset(i, 0, sizeof(*i)); i->version = 1; i->child_pid = 5151;
    i->process_group_id = 5151; i->child_birth_us = 77;
    memset(i->executable_sha256, 1, 32); memset(i->executable_identity_sha256, 2, 32);
    memset(i->native_process_handle_sha256, 3, 32); memset(i->cdhash, 4, 20);
    i->cdhash_size = 20; strcpy(i->signing_identifier, "test.helper");
    strcpy(i->team_identifier, "TEAM"); return 0;
}
int plamen_broker_v2_process_wait(struct plamen_broker_v2_process *p,
    struct plamen_broker_v2_process_terminal *t) {
    if (p == NULL || t == NULL || (p->state != 2 && p->state != 3)) return 4;
    if (p->state == 2) { waits++; p->state = 3; }
    memset(t, 0, sizeof(*t)); t->version = 1; t->exit_code = 9;
    t->child_pid = 5151; t->process_group_id = 5151; t->child_birth_us = 77;
    t->stdout_size = sizeof(out_bytes) - 1; CC_SHA256(out_bytes, sizeof(out_bytes)-1, t->stdout_sha256);
    CC_SHA256(NULL, 0, t->stderr_sha256); t->child_reaped = 1; t->process_group_extinct = 1;
    return 0;
}
int plamen_broker_v2_process_extinguish(struct plamen_broker_v2_process *p,
    struct plamen_broker_v2_process_terminal *t) { return plamen_broker_v2_process_wait(p, t); }
int plamen_broker_v2_process_read_output(struct plamen_broker_v2_process *p,
    uint32_t stream, uint64_t offset, uint32_t maximum, uint8_t *output,
    uint32_t capacity, uint32_t *size, uint8_t *eof, uint8_t chunk[32],
    uint8_t full[32], uint64_t *full_size) {
    const uint8_t *source = stream == 1 ? out_bytes : (const uint8_t *)"";
    size_t total = stream == 1 ? sizeof(out_bytes) - 1 : 0, amount;
    if (p == NULL || p->state != 3 || offset > total || capacity < maximum) return 4;
    amount = total - (size_t)offset; if (amount > maximum) amount = maximum;
    memcpy(output, source + offset, amount); *size = (uint32_t)amount;
    *eof = offset + amount == total; CC_SHA256(output, amount, chunk);
    CC_SHA256(source, total, full); *full_size = total; return 0;
}
int plamen_broker_v2_process_close(struct plamen_broker_v2_process *p) {
    if (p == NULL || p->state != 3) return 4; free(p); return 0;
}

static void fill(uint8_t value[32], uint8_t byte) { memset(value, byte, 32); }
static void common(xpc_object_t message, const char *operation, uint8_t opbyte,
    uint8_t requestbyte, const uint8_t prior[32], uint8_t claimbyte) {
    uint8_t value[32]; xpc_dictionary_set_string(message, "operation", operation);
    fill(value, 0x91); xpc_dictionary_set_data(message, "broker_session_id", value, 32);
    fill(value, opbyte); xpc_dictionary_set_data(message, "operation_key", value, 32);
    fill(value, requestbyte); xpc_dictionary_set_data(message, "request_sha256", value, 32);
    xpc_dictionary_set_data(message, "prior_checkpoint_sha256", prior, 32);
    fill(value, claimbyte); xpc_dictionary_set_data(message, "claim_owner_sha256", value, 32);
}
static uint64_t dispatch(struct plamen_broker_v2_process_custodian *custodian,
    xpc_object_t request, xpc_object_t *response) {
    if (plamen_broker_v2_process_custody_daemon_TEST_ONLY_dispatch(
            custodian, request, response) != 0) return 99;
    return xpc_dictionary_get_uint64(*response, "status");
}

int main(int argc, char **argv) {
    struct plamen_broker_v2_process_custodian *custodian = NULL;
    struct plamen_broker_v2_custody_daemon_readiness readiness;
    uint8_t prior[32], executable_sha[32], start_operation[32];
    int state, executable, cwd, input;
    xpc_object_t request, response, receipt, arguments, environment, fd_maps;
    size_t checkpoint_size = 0, output_size = 0; const void *checkpoint, *output;
    if (argc != 2) return 64;
    state = open(argv[1], O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    executable = open(argv[0], O_RDONLY|O_CLOEXEC); cwd = open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    input = open("/dev/null", O_RDONLY|O_CLOEXEC);
    if (state < 0 || executable < 0 || cwd < 0 || input < 0
        || plamen_broker_v2_process_custodian_open(state, &custodian) != 0) return 65;
    memset(&readiness, 0, sizeof(readiness));
    fill(readiness.installation_receipt_sha256, 0xa1);
    fill(readiness.generation_id_sha256, 0xa2);
    fill(readiness.service_sha256, 0xa3);
    request = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(request, "operation", "status");
    { uint8_t session[32]; fill(session, 0x91);
      xpc_dictionary_set_data(request, "broker_session_id", session, 32); }
    if (plamen_broker_v2_process_custody_daemon_TEST_ONLY_dispatch_readiness(
            custodian, &readiness, request, &response) != 0) return 70;
    receipt = xpc_dictionary_get_value(response, "receipt");
    { size_t n = 0; const void *digest = receipt == NULL ? NULL
          : xpc_dictionary_get_data(receipt, "installation_receipt_sha256", &n);
      if (xpc_dictionary_get_uint64(response, "status") != 0 || n != 32
          || digest == NULL || memcmp(digest, readiness.installation_receipt_sha256, 32) != 0)
          return 71; }
    xpc_release(response); xpc_release(request);
    fill(prior, 0x13); fill(executable_sha, 9); fill(start_operation, 0x11);
    request = xpc_dictionary_create(NULL, NULL, 0); common(request, "start", 0x11, 0x12, prior, 0x14);
    xpc_dictionary_set_fd(request, "executable", executable); xpc_dictionary_set_fd(request, "cwd", cwd);
    xpc_dictionary_set_fd(request, "stdin", input); xpc_dictionary_set_string(request, "executable_path", "/fake");
    arguments = xpc_array_create(NULL, 0); xpc_array_set_string(arguments, XPC_ARRAY_APPEND, "/fake");
    xpc_array_set_string(arguments, XPC_ARRAY_APPEND, "run"); xpc_dictionary_set_value(request, "argv", arguments);
    xpc_release(arguments);
    environment = xpc_array_create(NULL, 0); fd_maps = xpc_array_create(NULL, 0);
    xpc_dictionary_set_uint64(request, "process_spec_version", 2);
    xpc_dictionary_set_uint64(request, "environment_policy", 1);
    xpc_dictionary_set_value(request, "environment", environment);
    xpc_dictionary_set_value(request, "fd_maps", fd_maps);
    xpc_release(environment); xpc_release(fd_maps);
    xpc_dictionary_set_uint64(request, "timeout_seconds", 30);
    xpc_dictionary_set_uint64(request, "stdout_limit", 1024); xpc_dictionary_set_uint64(request, "stderr_limit", 1024);
    xpc_dictionary_set_data(request, "executable_sha256", executable_sha, 32);
    xpc_dictionary_set_string(request, "signing_identifier", "test.helper"); xpc_dictionary_set_string(request, "team_identifier", "TEAM");
    uint64_t started = dispatch(custodian, request, &response); receipt = xpc_dictionary_get_value(response, "receipt");
    checkpoint = receipt == NULL ? NULL : xpc_dictionary_get_data(receipt, "started_checkpoint_sha256", &checkpoint_size);
    if (checkpoint == NULL || checkpoint_size != 32) return 66; memcpy(prior, checkpoint, 32);
    xpc_release(response);
    xpc_dictionary_set_uint64(request, "timeout_seconds", UINT64_MAX);
    uint64_t overflow = dispatch(custodian, request, &response);
    printf("READY=0 OVERFLOW=%llu\n", (unsigned long long)overflow);
    xpc_release(response); xpc_release(request); /* broker session/process may now disappear */

    request = xpc_dictionary_create(NULL, NULL, 0); common(request, "adopt", 0x11, 0x12, (uint8_t[32]){[0 ... 31]=0x13}, 0x14);
    uint64_t adopted = dispatch(custodian, request, &response); xpc_release(response); xpc_release(request);

    request = xpc_dictionary_create(NULL, NULL, 0); common(request, "wait", 0x21, 0x22, prior, 0x14);
    xpc_dictionary_set_data(request, "start_operation", start_operation, 32);
    uint64_t waited = dispatch(custodian, request, &response); receipt = xpc_dictionary_get_value(response, "receipt");
    output = receipt == NULL ? NULL : xpc_dictionary_get_data(receipt, "stdout", &output_size);
    printf("START=%llu ADOPT=%llu WAIT=%llu STARTS=%d WAITS=%d OUT=%.*s",
        started, adopted, waited, starts, waits, (int)output_size, output == NULL ? "" : (const char *)output);
    xpc_release(response); xpc_release(request);

    request = xpc_dictionary_create(NULL, NULL, 0); common(request, "recover", 0x21, 0x22, prior, 0x14);
    xpc_dictionary_set_data(request, "start_operation", start_operation, 32);
    uint64_t recovered = dispatch(custodian, request, &response); printf("RECOVER=%llu\n", recovered);
    xpc_release(response); xpc_release(request);

    request = xpc_dictionary_create(NULL, NULL, 0); common(request, "adopt", 0x11, 0x12, (uint8_t[32]){[0 ... 31]=0x13}, 0x14);
    xpc_dictionary_set_bool(request, "forged", true);
    printf("EXTRA=%d\n", plamen_broker_v2_process_custody_daemon_TEST_ONLY_dispatch(custodian, request, &response));
    xpc_release(request); plamen_broker_v2_process_custodian_close(custodian);
    close(input); close(cwd); close(executable); close(state); return 0;
}
'''


def test_daemon_owned_operation_survives_broker_session_loss_and_adopts(
    tmp_path: Path,
) -> None:
    source = tmp_path / "harness.c"
    source.write_text(HARNESS)
    harness = tmp_path / "harness"
    subprocess.run(
        [
            "/usr/bin/clang", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            "-fblocks", "-DPLAMEN_BROKER_V2_TEST_ONLY=1",
            "-I", str(ROOT / "native" / "include"),
            "-I", str(ROOT / "native" / "darwin"), str(source),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custodian.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_daemon.c"),
            str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
            "-framework", "Security", "-framework", "CoreFoundation",
            "-o", str(harness),
        ],
        check=True, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    completed = subprocess.run(
        [str(harness), str(state)], cwd=ROOT, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    assert "START=0 ADOPT=1 WAIT=0 STARTS=1 WAITS=1 OUT=daemon-owned-output" in completed.stdout
    assert "RECOVER=1" in completed.stdout
    assert "EXTRA=-1" in completed.stdout
    assert "READY=0" in completed.stdout
    assert "OVERFLOW=2" in completed.stdout


def test_production_daemon_is_separate_exactly_authenticated_launchd_mode() -> None:
    service = (ROOT / "native" / "darwin" / "plamen_broker_v2_service.c").read_text()
    daemon = (ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_daemon.c").read_text()
    manifest = (ROOT / "native" / "darwin" / "com.plamen.audit.process-custody.v2.plist").read_text()
    assert "PLAMEN_BROKER_V2_CUSTODY_DAEMON_MODE" in service
    assert "admit_peer_code(peer, PLAMEN_INSTALL_MEMBER_SERVICE)" in service
    assert 'and cdhash H\\"%s\\"' in service
    assert "xpc_connection_set_peer_code_signing_requirement" in daemon
    assert "DISPATCH_QUEUE_CONCURRENT" in daemon
    assert "xpc_connection_set_target_queue(peer, context->work_queue)" in daemon
    assert "com.plamen.audit.process-custody.v2" in manifest
    assert "--process-custody-daemon" in manifest
    assert "lifecycle_authority_granted" not in daemon


def test_daemon_source_compiles_in_production_mode(tmp_path: Path) -> None:
    subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-fblocks", "-I", str(ROOT / "native" / "include"),
            "-I", str(ROOT / "native" / "darwin"), "-c",
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_daemon.c"),
            "-o", str(tmp_path / "daemon.o"),
        ], check=True, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
