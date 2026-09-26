from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="Darwin native process custodian only"
)

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include "plamen_broker_v2_process_custodian.h"
#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct plamen_broker_v2_process { int state; };
static int prepares, starts, waits, revokes, corrupt_output_digest;
static const uint8_t out_bytes[] = "stdout-evidence\n";
static const uint8_t err_bytes[] = "stderr-evidence\n";

int plamen_broker_v2_process_prepare(const struct plamen_broker_v2_process_spec *s,
    struct plamen_broker_v2_process_prepared_identity *i,
    struct plamen_broker_v2_process **p) {
    (void)s; prepares++; *p = calloc(1, sizeof(**p));
    if (*p == NULL) return PLAMEN_BROKER_V2_PROCESS_INTERNAL_ERROR;
    (*p)->state = 1; memset(i, 0, sizeof(*i)); i->version = 1; return 0;
}
int plamen_broker_v2_process_start(struct plamen_broker_v2_process *p,
    struct plamen_broker_v2_process_start_identity *i) {
    if (p == NULL || p->state != 1) return 4;
    starts++; p->state = 2; memset(i, 0, sizeof(*i)); i->version = 1;
    i->child_pid = 4242; i->process_group_id = 4242; i->child_birth_us = 99;
    memset(i->executable_sha256, 1, 32); memset(i->executable_identity_sha256, 2, 32);
    memset(i->native_process_handle_sha256, 3, 32); memset(i->cdhash, 4, 20);
    i->cdhash_size = 20; strcpy(i->signing_identifier, "test.helper");
    strcpy(i->team_identifier, "TEAM"); return 0;
}
static int terminal(struct plamen_broker_v2_process *p,
    struct plamen_broker_v2_process_terminal *t, int revoke) {
    if (p == NULL || t == NULL || (p->state != 2 && p->state != 3)) return 4;
    if (p->state == 2) { if (revoke) revokes++; else waits++; p->state = 3; }
    memset(t, 0, sizeof(*t)); t->version = 1;
    t->status = revoke ? PLAMEN_BROKER_V2_PROCESS_CANCELLED : 0;
    t->exit_code = revoke ? -1 : 7; t->child_pid = 4242;
    t->process_group_id = 4242; t->child_birth_us = 99;
    t->stdout_size = sizeof(out_bytes) - 1; t->stderr_size = sizeof(err_bytes) - 1;
    CC_SHA256(out_bytes, sizeof(out_bytes) - 1, t->stdout_sha256);
    CC_SHA256(err_bytes, sizeof(err_bytes) - 1, t->stderr_sha256);
    t->child_reaped = 1; t->process_group_extinct = 1; return (int)t->status;
}
int plamen_broker_v2_process_wait(struct plamen_broker_v2_process *p,
    struct plamen_broker_v2_process_terminal *t) { return terminal(p, t, 0); }
int plamen_broker_v2_process_extinguish(struct plamen_broker_v2_process *p,
    struct plamen_broker_v2_process_terminal *t) { return terminal(p, t, 1); }
int plamen_broker_v2_process_read_output(struct plamen_broker_v2_process *p,
    uint32_t stream, uint64_t offset, uint32_t maximum, uint8_t *output,
    uint32_t capacity, uint32_t *size, uint8_t *eof, uint8_t chunk[32],
    uint8_t full[32], uint64_t *full_size) {
    const uint8_t *source; size_t total, amount;
    if (p == NULL || p->state != 3 || maximum == 0 || capacity < maximum) return 4;
    source = stream == 1 ? out_bytes : err_bytes;
    total = stream == 1 ? sizeof(out_bytes) - 1 : sizeof(err_bytes) - 1;
    if (offset > total) return 4; amount = total - (size_t)offset;
    if (amount > maximum) amount = maximum; memcpy(output, source + offset, amount);
    *size = (uint32_t)amount; *eof = offset + amount == total;
    CC_SHA256(output, amount, chunk); CC_SHA256(source, total, full); *full_size = total;
    if (corrupt_output_digest) full[0] ^= 1;
    return 0;
}
int plamen_broker_v2_process_close(struct plamen_broker_v2_process *p) {
    if (p == NULL || p->state != 3) return 4; free(p); return 0;
}

static void fill32(uint8_t value[32], uint8_t byte) { memset(value, byte, 32); }
static void print_hex32(const uint8_t value[32]) {
    for (size_t index = 0; index < 32; index++) printf("%02x", value[index]);
}
static int parse_hex32(const char *text, uint8_t value[32]) {
    if (text == NULL || strlen(text) != 64) return -1;
    for (size_t index = 0; index < 32; index++) {
        unsigned int byte = 0;
        if (sscanf(text + (index * 2), "%2x", &byte) != 1) return -1;
        value[index] = (uint8_t)byte;
    }
    return 0;
}
static void make_requests(int executable, int cwd, int input,
    struct plamen_broker_v2_process_spec *spec,
    struct plamen_broker_v2_process_custodian_start_request *start,
    struct plamen_broker_v2_process_custodian_terminal_request *term) {
    static const char *argv[] = { "/fake", "run" };
    static uint8_t executable_sha[32];
    memset(spec, 0, sizeof(*spec)); spec->version = 1; spec->executable_fd = executable;
    spec->executable_path = "/fake"; spec->argv = argv; spec->argc = 2;
    spec->environment_policy = PLAMEN_BROKER_V2_PROCESS_ENV_CLOSED;
    spec->cwd_fd = cwd; spec->stdin_fd = input; spec->timeout_seconds = 30;
    spec->stdout_spool_limit = 1024; spec->stderr_spool_limit = 1024;
    fill32(executable_sha, 9); spec->expected_executable_sha256 = executable_sha;
    spec->expected_signing_identifier = "test.helper"; spec->expected_team_identifier = "TEAM";
    memset(start, 0, sizeof(*start)); start->version = 1;
    fill32(start->operation_key, 0x11); fill32(start->request_sha256, 0x12);
    fill32(start->prior_checkpoint_sha256, 0x13); fill32(start->claim_owner_sha256, 0x14);
    start->process_spec = spec;
    memset(term, 0, sizeof(*term)); term->version = 1;
    memcpy(term->start_operation_key, start->operation_key, 32);
    fill32(term->operation_key, 0x21); fill32(term->request_sha256, 0x22);
    fill32(term->prior_checkpoint_sha256, 0x23);
    memcpy(term->claim_owner_sha256, start->claim_owner_sha256, 32);
}

struct start_thread { struct plamen_broker_v2_process_custodian *c;
    struct plamen_broker_v2_process_custodian_start_request *r; int status; };
static void *start_thread(void *opaque) { struct start_thread *t = opaque;
    struct plamen_broker_v2_process_custodian_start_receipt receipt;
    t->status = plamen_broker_v2_process_custodian_start(t->c, t->r, &receipt); return NULL; }

int main(int argc, char **argv) {
    struct plamen_broker_v2_process_custodian *custodian = NULL;
    struct plamen_broker_v2_process_spec spec;
    struct plamen_broker_v2_process_custodian_start_request start_request;
    struct plamen_broker_v2_process_custodian_terminal_request terminal_request;
    struct plamen_broker_v2_process_custodian_start_receipt started;
    struct plamen_broker_v2_process_custodian_terminal_receipt terminal_receipt;
    int state = -1, executable = -1, cwd = -1, input = -1, one, two, mode_fault = 0;
    if (argc < 3) return 64;
    state = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    executable = open(argv[0], O_RDONLY | O_CLOEXEC); cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (state < 0 || executable < 0 || cwd < 0 || input < 0) return 65;
    if (plamen_broker_v2_process_custodian_open(state, &custodian) != 0) return 66;
    make_requests(executable, cwd, input, &spec, &start_request, &terminal_request);
    if (strcmp(argv[1], "fault-start") == 0) {
        mode_fault = atoi(argv[3]); plamen_broker_v2_process_custodian_TEST_ONLY_fail_once(mode_fault);
        one = plamen_broker_v2_process_custodian_start(custodian, &start_request, &started);
        two = plamen_broker_v2_process_custodian_recover_start(custodian, &start_request, &started);
        printf("ONE=%d TWO=%d PREPARES=%d STARTS=%d PID=%d\n", one, two, prepares, starts, started.identity.child_pid);
        memcpy(terminal_request.prior_checkpoint_sha256, started.started_checkpoint_sha256, 32);
        fill32(terminal_request.operation_key, 0x31); fill32(terminal_request.request_sha256, 0x32);
        (void)plamen_broker_v2_process_custodian_revoke(custodian, &terminal_request, &terminal_receipt);
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal_receipt);
    } else if (strcmp(argv[1], "fault-wait") == 0) {
        if (plamen_broker_v2_process_custodian_start(custodian, &start_request, &started) != 0) return 67;
        memcpy(terminal_request.prior_checkpoint_sha256, started.started_checkpoint_sha256, 32);
        mode_fault = atoi(argv[3]); plamen_broker_v2_process_custodian_TEST_ONLY_fail_once(mode_fault);
        one = plamen_broker_v2_process_custodian_wait(custodian, &terminal_request, &terminal_receipt);
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal_receipt);
        two = plamen_broker_v2_process_custodian_wait(custodian, &terminal_request, &terminal_receipt);
        printf("ONE=%d TWO=%d WAITS=%d EXIT=%d OUT=%.*s", one, two, waits,
            terminal_receipt.terminal.exit_code, (int)terminal_receipt.stdout_retained_size,
            terminal_receipt.stdout_retained == NULL ? (uint8_t *)"" : terminal_receipt.stdout_retained);
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal_receipt);
    } else if (strcmp(argv[1], "concurrent") == 0) {
        pthread_t a, b; struct start_thread ta = {custodian, &start_request, -1};
        struct start_thread tb = {custodian, &start_request, -1};
        pthread_create(&a, NULL, start_thread, &ta); pthread_create(&b, NULL, start_thread, &tb);
        pthread_join(a, NULL); pthread_join(b, NULL);
        struct plamen_broker_v2_process_custodian_start_receipt replay;
        (void)plamen_broker_v2_process_custodian_recover_start(custodian, &start_request, &replay);
        memcpy(terminal_request.prior_checkpoint_sha256, replay.started_checkpoint_sha256, 32);
        one = plamen_broker_v2_process_custodian_wait(custodian, &terminal_request, &terminal_receipt);
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal_receipt);
        two = plamen_broker_v2_process_custodian_wait(custodian, &terminal_request, &terminal_receipt);
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal_receipt);
        printf("A=%d B=%d STARTS=%d W1=%d W2=%d WAITS=%d\n", ta.status, tb.status, starts, one, two, waits);
    } else if (strcmp(argv[1], "wrong-claim") == 0) {
        one = plamen_broker_v2_process_custodian_start(custodian, &start_request, &started);
        memcpy(terminal_request.prior_checkpoint_sha256, started.started_checkpoint_sha256, 32);
        terminal_request.claim_owner_sha256[0] ^= 1;
        two = plamen_broker_v2_process_custodian_wait(custodian, &terminal_request, &terminal_receipt);
        terminal_request.claim_owner_sha256[0] ^= 1;
        fill32(terminal_request.operation_key, 0x31); fill32(terminal_request.request_sha256, 0x32);
        (void)plamen_broker_v2_process_custodian_revoke(custodian, &terminal_request, &terminal_receipt);
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal_receipt);
        printf("START=%d WRONG=%d WAITS=%d\n", one, two, waits);
    } else if (strcmp(argv[1], "bad-output-digest") == 0) {
        one = plamen_broker_v2_process_custodian_start(custodian, &start_request, &started);
        memcpy(terminal_request.prior_checkpoint_sha256, started.started_checkpoint_sha256, 32);
        corrupt_output_digest = 1;
        two = plamen_broker_v2_process_custodian_wait(custodian, &terminal_request, &terminal_receipt);
        printf("START=%d WAIT=%d WAITS=%d\n", one, two, waits);
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal_receipt);
    } else if (strcmp(argv[1], "terminal") == 0) {
        one = plamen_broker_v2_process_custodian_start(custodian, &start_request, &started);
        memcpy(terminal_request.prior_checkpoint_sha256, started.started_checkpoint_sha256, 32);
        two = plamen_broker_v2_process_custodian_wait(custodian, &terminal_request, &terminal_receipt);
        printf("PRIOR="); print_hex32(started.started_checkpoint_sha256); printf("\n");
        printf("START=%d WAIT=%d EXIT=%d OUT=%.*s", one, two, terminal_receipt.terminal.exit_code,
            (int)terminal_receipt.stdout_retained_size, terminal_receipt.stdout_retained);
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal_receipt);
    } else if (strcmp(argv[1], "recover-terminal") == 0) {
        if (argc != 4 || parse_hex32(argv[3], terminal_request.prior_checkpoint_sha256) != 0) return 70;
        one = plamen_broker_v2_process_custodian_recover_terminal(custodian, &terminal_request, &terminal_receipt);
        printf("RECOVER=%d EXIT=%d OUT=%.*s", one, terminal_receipt.terminal.exit_code,
            (int)terminal_receipt.stdout_retained_size,
            terminal_receipt.stdout_retained == NULL ? (uint8_t *)"" : terminal_receipt.stdout_retained);
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal_receipt);
    } else if (strcmp(argv[1], "leave-started") == 0) {
        one = plamen_broker_v2_process_custodian_start(custodian, &start_request, &started);
        printf("START=%d STARTS=%d\n", one, starts);
    } else if (strcmp(argv[1], "hold-start") == 0) {
        one = plamen_broker_v2_process_custodian_start(custodian, &start_request, &started);
        printf("START=%d STARTS=%d\n", one, starts); fflush(stdout); sleep(5);
    } else if (strcmp(argv[1], "recover-start") == 0) {
        one = plamen_broker_v2_process_custodian_recover_start(custodian, &start_request, &started);
        printf("RECOVER=%d STARTS=%d\n", one, starts);
    } else if (strcmp(argv[1], "reconnect-live") == 0) {
        one = plamen_broker_v2_process_custodian_start(custodian, &start_request, &started);
        plamen_broker_v2_process_custodian_close(custodian); custodian = NULL;
        if (plamen_broker_v2_process_custodian_open(state, &custodian) != 0) return 69;
        two = plamen_broker_v2_process_custodian_recover_start(custodian, &start_request, &started);
        memcpy(terminal_request.prior_checkpoint_sha256, started.started_checkpoint_sha256, 32);
        int waited = plamen_broker_v2_process_custodian_wait(custodian, &terminal_request, &terminal_receipt);
        printf("START=%d RECONNECT=%d STARTS=%d WAIT=%d WAITS=%d EXIT=%d\n",
            one, two, starts, waited, waits, terminal_receipt.terminal.exit_code);
        plamen_broker_v2_process_custodian_terminal_dispose(&terminal_receipt);
    } else if (strcmp(argv[1], "reclaim") == 0) {
        for (uint8_t index = 1; index <= 80; ++index) {
            fill32(start_request.operation_key, index);
            fill32(start_request.request_sha256, (uint8_t)(index + 80));
            memcpy(terminal_request.start_operation_key,
                start_request.operation_key, 32);
            fill32(terminal_request.operation_key, (uint8_t)(index + 160));
            fill32(terminal_request.request_sha256, (uint8_t)(index + 81));
            one = plamen_broker_v2_process_custodian_start(custodian,
                &start_request, &started);
            if (one != 0) {
                printf("FAIL_START=%u STATUS=%d STARTS=%d WAITS=%d\n",
                    index, one, starts, waits); return 71;
            }
            memcpy(terminal_request.prior_checkpoint_sha256,
                started.started_checkpoint_sha256, 32);
            if (plamen_broker_v2_process_custodian_wait(custodian,
                    &terminal_request, &terminal_receipt) != 0) return 72;
            plamen_broker_v2_process_custodian_terminal_dispose(
                &terminal_receipt);
        }
        fill32(start_request.operation_key, 1);
        fill32(start_request.request_sha256, 81);
        one = plamen_broker_v2_process_custodian_start(custodian,
            &start_request, &started);
        printf("COUNT=%d STARTS=%d WAITS=%d REPLAY=%d\n",
            80, starts, waits, one);
    } else return 68;
    plamen_broker_v2_process_custodian_close(custodian);
    close(input); close(cwd); close(executable); close(state); return 0;
}
'''


@pytest.fixture(scope="module")
def harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("process-custodian")
    source = directory / "harness.c"
    source.write_text(HARNESS)
    output = directory / "harness"
    subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-fblocks", "-DPLAMEN_BROKER_V2_TEST_ONLY=1",
            "-I", str(ROOT / "native" / "include"),
            "-I", str(ROOT / "native" / "darwin"),
            str(source),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custodian.c"),
            str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
            "-framework", "Security", "-framework", "CoreFoundation",
            "-o", str(output),
        ],
        check=True, cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    return output


def _run(harness: Path, mode: str, state: Path, extra: int | str | None = None) -> str:
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    command = [str(harness), mode, str(state)]
    if extra is not None:
        command.append(str(extra))
    return subprocess.run(
        command, check=True, cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
    ).stdout


@pytest.mark.parametrize("fault", range(1, 5))
def test_start_fault_boundaries_replay_without_duplicate(
    harness: Path, tmp_path: Path, fault: int
) -> None:
    output = _run(harness, "fault-start", tmp_path / f"start-{fault}", fault)
    assert "ONE=4" in output
    assert "STARTS=1" in output
    assert "PID=4242" in output
    assert "TWO=0" in output or "TWO=1" in output


@pytest.mark.parametrize("fault", range(5, 10))
def test_terminal_fault_boundaries_recover_identical_bytes(
    harness: Path, tmp_path: Path, fault: int
) -> None:
    output = _run(harness, "fault-wait", tmp_path / f"wait-{fault}", fault)
    assert "ONE=4" in output
    assert "TWO=0" in output or "TWO=1" in output
    assert "WAITS=1" in output
    assert "EXIT=7" in output
    assert "OUT=stdout-evidence" in output


def test_concurrent_start_and_wait_are_exactly_once(
    harness: Path, tmp_path: Path
) -> None:
    output = _run(harness, "concurrent", tmp_path / "concurrent")
    assert "STARTS=1" in output
    assert "WAITS=1" in output
    assert {part for part in output.split() if part.startswith(("A=", "B="))} == {"A=0", "B=1"}
    assert "W1=0" in output and "W2=1" in output


def test_claim_loser_cannot_wait(harness: Path, tmp_path: Path) -> None:
    output = _run(harness, "wrong-claim", tmp_path / "wrong-claim")
    assert "START=0" in output and "WRONG=2" in output and "WAITS=0" in output


def test_output_capture_rejects_native_observed_digest_mismatch(
    harness: Path, tmp_path: Path
) -> None:
    output = _run(harness, "bad-output-digest", tmp_path / "bad-output-digest")
    assert "START=0 WAIT=4 WAITS=1" in output


def test_terminal_is_byte_recoverable_after_registry_loss(
    harness: Path, tmp_path: Path
) -> None:
    state = tmp_path / "terminal-restart"
    first = _run(harness, "terminal", state)
    prior = next(line.removeprefix("PRIOR=") for line in first.splitlines() if line.startswith("PRIOR="))
    second = _run(harness, "recover-terminal", state, prior)
    assert "WAIT=0 EXIT=7 OUT=stdout-evidence" in first
    assert "RECOVER=1 EXIT=7 OUT=stdout-evidence" in second


@pytest.mark.parametrize("suffix", ["stdout", "terminal"])
def test_terminal_recovery_rejects_tampered_durable_records(
    harness: Path, tmp_path: Path, suffix: str
) -> None:
    state = tmp_path / f"tampered-{suffix}"
    first = _run(harness, "terminal", state)
    prior = next(line.removeprefix("PRIOR=") for line in first.splitlines() if line.startswith("PRIOR="))
    record = state / "process-custody-v1" / (("21" * 32) + f".{suffix}")
    payload = bytearray(record.read_bytes())
    payload[len(payload) // 2] ^= 1
    record.write_bytes(payload)
    assert "RECOVER=2" in _run(harness, "recover-terminal", state, prior)


def test_client_session_disconnect_keeps_service_owned_live_claim(
    harness: Path, tmp_path: Path
) -> None:
    output = _run(harness, "reconnect-live", tmp_path / "session-reconnect")
    assert "START=0 RECONNECT=1 STARTS=1 WAIT=0 WAITS=1 EXIT=7" in output


def test_terminal_slots_are_reclaimed_without_losing_durable_start_replay(
    harness: Path, tmp_path: Path
) -> None:
    output = _run(harness, "reclaim", tmp_path / "reclaim")
    assert "COUNT=80 STARTS=80 WAITS=80 REPLAY=1" in output


def test_live_started_record_after_custody_daemon_restart_is_ambiguous_not_replayed(
    harness: Path, tmp_path: Path
) -> None:
    state = tmp_path / "active-restart"
    assert "START=0 STARTS=1" in _run(harness, "leave-started", state)
    output = _run(harness, "recover-start", state)
    assert "RECOVER=4 STARTS=0" in output


def test_cross_process_claim_has_exactly_one_owner(
    harness: Path, tmp_path: Path
) -> None:
    state = tmp_path / "cross-process"
    state.mkdir(mode=0o700)
    owner = subprocess.Popen(
        [str(harness), "hold-start", str(state)], cwd=ROOT,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert owner.stdout is not None
        assert owner.stdout.readline().strip() == "START=0 STARTS=1"
        challenger = _run(harness, "recover-start", state)
        assert "RECOVER=3 STARTS=0" in challenger
    finally:
        owner.terminate()
        owner.wait(timeout=5)


def test_source_compiles_in_production_mode(tmp_path: Path) -> None:
    output = tmp_path / "custodian.o"
    subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-fblocks", "-I", str(ROOT / "native" / "include"),
            "-I", str(ROOT / "native" / "darwin"), "-c",
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custodian.c"),
            "-o", str(output),
        ],
        check=True, cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
