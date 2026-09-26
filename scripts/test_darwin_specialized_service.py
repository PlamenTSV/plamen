from __future__ import annotations

from pathlib import Path
import platform
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "native" / "darwin" / "plamen_broker_v2_service.c"
STORE = ROOT / "native" / "darwin" / "plamen_broker_v2_service_store.c"
STORE_HEADER = ROOT / "native" / "darwin" / "plamen_broker_v2_service_store.h"

pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="Darwin XPC specialized service"
)


def _syntax(source: Path, *, blocks: bool = False) -> None:
    command = [
        "/usr/bin/clang",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-DPLAMEN_BROKER_V2_TEST_ONLY=1",
        "-I",
        str(ROOT / "native" / "include"),
        "-I",
        str(ROOT / "native" / "darwin"),
        "-I",
        str(ROOT / "native" / "posix"),
    ]
    if blocks:
        command.append("-fblocks")
    command.extend(["-fsyntax-only", str(source)])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def test_specialized_service_and_store_compile_with_warnings_as_errors() -> None:
    _syntax(STORE)
    _syntax(SERVICE, blocks=True)


def test_all_four_handshake_messages_have_explicit_service_dispatch() -> None:
    source = SERVICE.read_text(encoding="utf-8")
    for symbol in (
        "PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_LOOKUP",
        "PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_CHALLENGE",
        "PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN",
        "PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_ACCEPTED",
    ):
        assert symbol in source
    assert "handle_specialized_session_lookup(peer, message, &view)" in source
    assert "handle_specialized_session_open(peer, message, &view)" in source
    assert "active_session_find(&lookup, &actual_peer, &parent)" in source
    assert "parent->authority_bundle.role" in source


def test_specialized_open_requires_fresh_exact_socket_and_key_pipe_pair() -> None:
    source = SERVICE.read_text(encoding="utf-8")
    assert source.count("PLAMEN_BROKER_V2_SERVICE_SPECIALIZED_SESSION_OPEN") >= 4
    assert "view->fd_count != 2" in source
    assert "PLAMEN_BROKER_V2_XPC_KEY_CONTROL_SOCKET" in source
    assert "PLAMEN_BROKER_V2_XPC_KEY_KEY_PIPE_READ" in source
    assert "read_session_key(descriptors[1], key)" in source
    assert "plamen_broker_v2_specialized_session_binding" in STORE.read_text(
        encoding="utf-8"
    )


def test_operation_replay_precedes_effect_and_missing_effects_fail_closed() -> None:
    source = SERVICE.read_text(encoding="utf-8")
    replay = source.index("/* Exact operation replay is resolved before any external effect. */")
    store = source.index(
        "plamen_broker_v2_service_store_specialized_operation(", replay
    )
    preflight = source.index(
        "plamen_broker_v2_service_store_specialized_preflight(", store
    )
    callback = source.index("plamen_broker_v2_effects_dispatch_specialized(", preflight)
    assert replay < store < preflight < callback
    assert "store_result != PLAMEN_BROKER_V2_CONFLICT" in source
    assert "__attribute__((weak_import))" not in source
    assert "terminal == NULL || terminal_size == 0" in source


def test_store_uses_atomic_immutable_records_and_owns_capability_state() -> None:
    source = STORE.read_text(encoding="utf-8")
    header = STORE_HEADER.read_text(encoding="utf-8")
    assert "STORE_SPECIALIZED_SESSION" in source
    assert "STORE_SPECIALIZED_OPERATION" in source
    assert "publish_record(store, name, STORE_SPECIALIZED_SESSION" in source
    assert "publish_record(store, name, STORE_SPECIALIZED_OPERATION" in source
    assert "O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW" in source
    assert "renameatx_np" in source and "RENAME_EXCL" in source
    assert "fsync(store->directory_fd)" in source
    assert "specialized_capability_authorized_locked" in source
    assert "getentropy(issued_capability" in source
    assert "plamen_broker_v2_service_store_recover_specialized" in header
    assert "plamen_broker_v2_service_store_specialized_preflight" in header
    assert "plamen_broker_v2_service_store_specialized_operation" in header
    assert "memcmp(computed_request_sha256, request_sha256, 32)" in source
    assert "memcmp(observed + STORE_HEADER_SIZE + 4U," in source


def test_specialized_socket_accepts_exact_scm_rights_roster_only() -> None:
    source = SERVICE.read_text(encoding="utf-8")
    start = source.index("receive_frame_with_descriptors(")
    end = source.index("static int\nwrite_bytes", start)
    receiver = source[start:end]
    assert "MSG_CTRUNC | MSG_TRUNC" in receiver
    assert "entry->cmsg_level != SOL_SOCKET" in receiver
    assert "entry->cmsg_type != SCM_RIGHTS" in receiver
    assert "ancillary_seen" in receiver
    assert "plamen_broker_v2_close_fds" in receiver
    assert "plamen_broker_v2_specialized_request_validate_fds" in source


def test_durable_specialized_session_has_only_one_live_worker() -> None:
    source = SERVICE.read_text(encoding="utf-8")
    assert "active_specialized_session_register(worker)" in source
    assert "active_specialized_session_unregister(worker)" in source
    assert "specialized_session_id, 32" in source
    register = source.index("active_specialized_session_register(worker)")
    spawn = source.index("pthread_create(&thread, &thread_attributes,", register)
    assert register < spawn


SPECIALIZED_ATTACHMENT_STORE_SOURCE = r"""
#define PLAMEN_BROKER_V2_TEST_ONLY 1
#include "native/darwin/plamen_broker_v2_service_store.c"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define CHECK(value) do { if (!(value)) return __LINE__; } while (0)

static void fill(uint8_t output[32], uint8_t value) {
    memset(output, value, 32);
}

int main(int argc, char **argv) {
    static const uint8_t request_payload[] = "{\"schema\":\"fixture\"}";
    static const uint8_t attachment_bytes[] =
        "{\"schema\":\"plamen.js-workspace-materializer-planning-projection.v2\"}";
    static const uint8_t terminal[] = "{\"disposition\":\"READY\"}";
    struct plamen_broker_v2_service_store *store = NULL;
    struct plamen_broker_v2_service_specialized_session_ack session;
    struct plamen_broker_v2_specialized_request request;
    struct plamen_broker_v2_specialized_response response;
    struct plamen_broker_v2_specialized_attachment prepared, replayed, attempted;
    uint8_t registration[32], request_envelope[32], parent_binding[32];
    uint8_t key_sha[32], *session_record = NULL, *response_wire = NULL;
    uint8_t *replayed_response_wire = NULL;
    uint8_t request_sha[32], request_wire[512], session_payload[1] = { 0 };
    size_t request_wire_size = 0, record_size = 0, response_wire_size = 0;
    size_t replayed_response_wire_size = 0;
    char session_name[96];
    int parent_fd = -1, result;
    if (argc != 2) return 2;
    parent_fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(parent_fd >= 0);
    CHECK(plamen_broker_v2_service_store_open(parent_fd, &store) == 0);
    memset(&session, 0, sizeof(session));
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&prepared, 0, sizeof(prepared)); prepared.descriptor = -1;
    memset(&replayed, 0, sizeof(replayed)); replayed.descriptor = -1;
    memset(&attempted, 0, sizeof(attempted)); attempted.descriptor = -1;
    fill(registration, 1); fill(request_envelope, 2); fill(parent_binding, 3);
    fill(key_sha, 4); fill(session.parent_session_id, 5);
    fill(session.specialized_session_id, 6);
    fill(session.authority_binding_sha256, 7);
    fill(session.session_binding_sha256, 8);
    memcpy(session.request_envelope_sha256, request_envelope, 32);
    session.version = PLAMEN_BROKER_V2_SERVICE_ABI_VERSION;
    session.lane = PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER;
    CHECK(build_specialized_record(STORE_SPECIALIZED_SESSION, registration,
        request_envelope, parent_binding, session.session_binding_sha256,
        key_sha, session.authority_binding_sha256,
        session.specialized_session_id, session.lane, session.version,
        session_payload, sizeof(session_payload), &session_record,
        &record_size) == 0);
    CHECK(specialized_name(session.specialized_session_id, NULL,
        session_name, sizeof(session_name)) == 0);
    CHECK(set_lock(store->lock_fd, F_WRLCK) == 0);
    result = publish_record(store, session_name, STORE_SPECIALIZED_SESSION,
        session_record, record_size);
    CHECK(set_lock(store->lock_fd, F_UNLCK) == 0);
    CHECK(result == 0);

    request.lane = session.lane;
    request.method = PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_AUTHENTICATE;
    fill(request.operation_nonce, 9);
    memcpy(request.authority_binding_sha256,
        session.authority_binding_sha256, 32);
    request.payload = request_payload;
    request.payload_size = sizeof(request_payload) - 1U;
    CHECK(plamen_broker_v2_specialized_request_encode(&request, request_wire,
        sizeof(request_wire), &request_wire_size) == 0);
    CHECK(plamen_broker_v2_sha256(request_wire, request_wire_size,
        request_sha) == 0);
    CHECK(plamen_broker_v2_service_store_specialized_attachment_prepare(store,
        &session, &request, request_sha, attachment_bytes,
        sizeof(attachment_bytes) - 1U, &prepared) == 0);
    CHECK(prepared.version == PLAMEN_BROKER_V2_SPECIALIZED_ATTACHMENT_VERSION);
    CHECK(prepared.descriptor >= 0);
    CHECK(plamen_broker_v2_service_store_specialized_operation(store,
        &session, &request, request_sha, terminal, sizeof(terminal) - 1U, 1,
        &response, &response_wire, &response_wire_size) == 0);
    CHECK(response_wire != NULL && response_wire_size != 0U);
    memset(&response, 0, sizeof(response));
    CHECK(plamen_broker_v2_service_store_specialized_operation(store,
        &session, &request, request_sha, NULL, 0U, 0, &response,
        &replayed_response_wire, &replayed_response_wire_size) == 0);
    CHECK(replayed_response_wire_size == response_wire_size);
    CHECK(memcmp(replayed_response_wire, response_wire, response_wire_size) == 0);
    CHECK(plamen_broker_v2_service_store_specialized_attachment_reopen(store,
        &session, &request, request_sha, prepared.sha256, prepared.size,
        &replayed) == 0);
    CHECK(replayed.descriptor >= 0 && replayed.size == prepared.size);
    CHECK(memcmp(replayed.sha256, prepared.sha256, 32) == 0);
    plamen_broker_v2_service_store_specialized_attachment_dispose(&replayed);
    CHECK(plamen_broker_v2_service_store_specialized_attachment_prepare(store,
        &session, &request, request_sha, attachment_bytes,
        sizeof(attachment_bytes) - 1U, &attempted)
        == PLAMEN_BROKER_V2_CONFLICT);
    request_sha[0] ^= 1U;
    CHECK(plamen_broker_v2_service_store_specialized_attachment_reopen(store,
        &session, &request, request_sha, prepared.sha256, prepared.size,
        &attempted) != 0);

    plamen_broker_v2_service_store_specialized_attachment_dispose(&attempted);
    plamen_broker_v2_service_store_specialized_attachment_dispose(&prepared);
    if (response_wire != NULL) {
        plamen_broker_v2_secure_zero(response_wire, response_wire_size);
        free(response_wire);
    }
    if (replayed_response_wire != NULL) {
        plamen_broker_v2_secure_zero(replayed_response_wire,
            replayed_response_wire_size);
        free(replayed_response_wire);
    }
    if (session_record != NULL) {
        plamen_broker_v2_secure_zero(session_record, record_size);
        free(session_record);
    }
    plamen_broker_v2_service_store_close(store);
    close(parent_fd);
    return 0;
}
"""


def test_specialized_attachment_is_reopened_only_after_exact_operation_commit(
    tmp_path: Path,
) -> None:
    source = tmp_path / "specialized_attachment_store.c"
    binary = tmp_path / "specialized_attachment_store"
    state = tmp_path / "state"
    source.write_text(SPECIALIZED_ATTACHMENT_STORE_SOURCE, encoding="utf-8")
    state.mkdir(mode=0o700)
    completed = subprocess.run(
        [
            "/usr/bin/clang",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fblocks",
            "-D_DARWIN_C_SOURCE",
            "-I",
            str(ROOT),
            "-I",
            str(ROOT / "native" / "include"),
            "-I",
            str(ROOT / "native" / "posix"),
            "-I",
            str(ROOT / "native" / "darwin"),
            str(source),
            str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
            "-framework",
            "Security",
            "-framework",
            "CoreFoundation",
            "-o",
            str(binary),
        ],
        cwd=ROOT,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    completed = subprocess.run(
        [str(binary), str(state)],
        cwd=ROOT,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
