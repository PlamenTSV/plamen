from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

import posix_specialized_tool_worker as worker


def _seal(value: dict[str, object]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("request_sha256", None)
    value["request_sha256"] = hashlib.sha256(worker.canonical_bytes(unsigned)).hexdigest()
    return worker.canonical_bytes(value)


def _fixture_request(tmp_path: Path) -> tuple[dict[str, object], list[int]]:
    tool_fd = os.open("/bin/echo", os.O_RDONLY)
    source = tmp_path / "source.sol"
    source.write_bytes(b"contract C {}\n")
    source_fd = os.open(source, os.O_RDONLY)
    opened = [tool_fd, source_fd]
    rows: dict[str, object] = {}
    for role in worker._ROLES:
        if role in {"cache", "generation", "scratch", "state"}:
            path = tmp_path / role
            path.mkdir()
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            kind, access = "DIRECTORY", "READ_WRITE"
        elif role in {"acquisition", "project"}:
            path = tmp_path / role
            path.mkdir()
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            kind, access = "DIRECTORY", "READ_ONLY"
        elif role == "source":
            fd, kind, access = source_fd, "REGULAR_FILE", "READ_ONLY"
        else:
            fd, kind, access = tool_fd, "REGULAR_FILE", "READ_ONLY"
        if fd not in opened:
            opened.append(fd)
        rows[role] = {
            "access": access,
            "fd": fd,
            "identity_sha256": worker.descriptor_identity(role, fd, kind, access),
            "kind": kind,
        }
    request: dict[str, object] = {
        "argv": ["@fd:tool", "hello"],
        "cwd": {"relative": ".", "role": "scratch"},
        "descriptors": rows,
        "effects_binding_sha256": "1" * 64,
        "environment": [],
        "limits": {
            "duration_ms": 5_000,
            "memory_bytes": 512 * 1024 * 1024,
            "open_fds": 32,
            "output_bytes": 1024 * 1024,
            "output_files": 128,
            "stderr_bytes": 4096,
            "stdout_bytes": 4096,
        },
        "network_mode": "DENY_ALL",
        "operation": "OFFLINE_REPLAY",
        "request_id": "run-1",
        "request_sha256": "0" * 64,
        "schema": worker.REQUEST_SCHEMA,
        "worker_runtime_sha256": "2" * 64,
    }
    return request, opened


def _apple_request(request: dict[str, object]) -> dict[str, object]:
    apple = dict(request)
    apple["schema"] = worker.APPLE_REQUEST_SCHEMA
    apple["operation"] = "MANAGED_EVM_EXECUTE"
    apple["runtime_closure_sha256"] = "3" * 64
    apple["tool_anchor_id"] = "managed-python"
    apple["managed_provisioner_sha256"] = "4" * 64
    apple["managed_provisioner_size"] = 4096
    apple["method_payload_ascii"] = '{"schema":"test"}'
    apple["method_payload_sha256"] = hashlib.sha256(
        apple["method_payload_ascii"].encode("ascii")
    ).hexdigest()
    physical = request["descriptors"]
    logical: dict[str, object] = {}
    for role in worker._ROLES:
        row = physical[role]
        observed = worker._apple_payload_observation(
            row["fd"], row["kind"], request["limits"]
        )
        logical[role] = {
            "access": row["access"],
            "kind": "IMAGE_MEMBER" if role == "tool" else row["kind"],
            **observed,
        }
    apple["descriptors"] = logical
    apple["limits"] = dict(request["limits"])
    apple["limits"]["open_fds"] = 32
    return apple


def _apple_slither_request(request: dict[str, object]) -> dict[str, object]:
    apple = _apple_request(request)
    apple["operation"] = "SNAPSHOT_TOOL_EXECUTE"
    apple["tool_anchor_id"] = "slither"
    for key in (
        "managed_provisioner_sha256", "managed_provisioner_size",
        "method_payload_ascii", "method_payload_sha256",
    ):
        apple.pop(key)
    for role in ("acquisition", "cache", "generation"):
        apple["descriptors"][role] = None
    apple.update({
        "slither_forge_sha256": "4" * 64,
        "slither_forge_size": 4096,
        "slither_internal_environment_sha256": (
            worker.SLITHER_INTERNAL_ENVIRONMENT_SHA256
        ),
        "slither_python_sha256": "5" * 64,
        "slither_python_size": 8192,
        "slither_solc_sha256": "6" * 64,
        "slither_solc_size": 16384,
    })
    return apple


def _apple_js_request(request: dict[str, object]) -> dict[str, object]:
    apple = _apple_request(request)
    apple["operation"] = "OFFLINE_REPLAY"
    apple["tool_anchor_id"] = "js-python"
    for key in ("managed_provisioner_sha256", "managed_provisioner_size"):
        apple.pop(key)
    apple["js_offline_materializer_sha256"] = "8" * 64
    apple["js_offline_materializer_size"] = 2048
    for role in ("cache", "generation", "project"):
        apple["descriptors"][role] = None
    return apple


def _projection_request(
    tmp_path: Path,
) -> tuple[dict[str, object], dict[str, dict[str, object]], list[int]]:
    project = tmp_path / "project-projection"
    modules = tmp_path / "modules-projection"
    scratch = tmp_path / "scratch-projection"
    state = tmp_path / "state-projection"
    project.mkdir()
    modules.mkdir()
    scratch.mkdir()
    state.mkdir()
    (project / "contracts").mkdir()
    (project / "contracts" / "C.sol").write_text("contract C {}\n")
    (modules / "dep").mkdir()
    (modules / "dep" / "index.js").write_text("module.exports = 1;\n")
    fds = {
        role: os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        for role, path in {
            "project": project,
            "source": modules,
            "scratch": scratch,
            "state": state,
        }.items()
    }
    rows: list[dict[str, object]] = []
    counts = [0, 0]
    worker._manifest_directory(
        fds["source"], "", rows, counts,
        {
            "output_files": worker.MAX_OUTPUT_FILES,
            "output_bytes": worker.MAX_OUTPUT_BYTES,
        },
    )
    receipt_body = {
        "lock_selection_sha256": "6" * 64,
        "modules_tree": {
            "algorithm": "PLAMEN_CANONICAL_TREE_SHA256_V1",
            "entry_count": counts[0],
            "expanded_bytes": counts[1],
            "sha256": hashlib.sha256(worker.canonical_bytes(rows)).hexdigest(),
        },
        "schema": "plamen.js-dependency-materialization-receipt.v2",
    }
    receipt = {
        **receipt_body,
        "receipt_sha256": hashlib.sha256(
            worker.canonical_bytes(receipt_body)
        ).hexdigest(),
    }
    payload = worker.canonical_bytes(
        {
            "dependency_materialization_receipt": receipt,
            "original_source_scope_sha256": "7" * 64,
            "run_id": "run-projection-1",
            "schema": "plamen.evm-analysis-projection-native-request.v1",
        }
    ).decode("ascii")
    request = {
        "limits": {
            "output_files": worker.MAX_OUTPUT_FILES,
            "output_bytes": worker.MAX_OUTPUT_BYTES,
        },
        "method_payload_ascii": payload,
        "projection_solc_sha256": "8" * 64,
        "projection_solc_size": 12345,
        "request_sha256": "9" * 64,
        "runtime_closure_sha256": "a" * 64,
    }
    observations = {
        role: {"fd": fd} for role, fd in fds.items()
    }
    return request, observations, list(fds.values())


def test_projection_engine_creates_fresh_out_of_tree_workspace(
    tmp_path: Path,
) -> None:
    request, observations, opened = _projection_request(tmp_path)
    try:
        result = worker._materialize_evm_projection(request, observations)
        workspace = tmp_path / "scratch-projection" / "analysis-workspace"
        assert (workspace / "contracts" / "C.sol").is_file()
        assert (workspace / "node_modules" / "dep" / "index.js").is_file()
        assert not (tmp_path / "project-projection" / "node_modules").exists()
        assert (tmp_path / "project-projection" / "contracts" / "C.sol").read_text() == (
            "contract C {}\n"
        )
        assert result["schema"] == (
            "plamen.evm-analysis-projection-worker-observation.v1"
        )
        assert result["workspace_relative_path"] == "analysis-workspace"
        assert (tmp_path / "state-projection" / "projection-observation.json").is_file()
    finally:
        for fd in opened:
            os.close(fd)


def test_projection_engine_rejects_existing_project_node_modules(
    tmp_path: Path,
) -> None:
    request, observations, opened = _projection_request(tmp_path)
    (tmp_path / "project-projection" / "node_modules").mkdir()
    try:
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker._materialize_evm_projection(request, observations)
        assert raised.value.code == "PROJECT_NODE_MODULES_PREEXISTING"
    finally:
        for fd in opened:
            os.close(fd)


def test_projection_payload_rejects_compiler_and_path_substitution(
    tmp_path: Path,
) -> None:
    request, _observations, opened = _projection_request(tmp_path)
    try:
        payload = json.loads(request["method_payload_ascii"])
        payload["projection_solc_sha256"] = "f" * 64
        request["method_payload_ascii"] = worker.canonical_bytes(payload).decode(
            "ascii"
        )
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker._projection_payload(request["method_payload_ascii"])
        assert raised.value.code == "PROJECTION_PAYLOAD_INVALID"
        payload.pop("projection_solc_sha256")
        payload["workspace_path"] = "/tmp/caller-controlled"
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker._projection_payload(
                worker.canonical_bytes(payload).decode("ascii")
            )
        assert raised.value.code == "PROJECTION_PAYLOAD_INVALID"
    finally:
        for fd in opened:
            os.close(fd)


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(),
    reason="direct retained-FD exec is performed inside the production Linux guest",
)
def test_exact_request_executes_retained_tool_and_emits_no_lf_terminal(tmp_path: Path) -> None:
    request, opened = _fixture_request(tmp_path)
    try:
        raw = _seal(request)
        parsed, observed = worker.parse_request(raw)
        assert parsed["operation"] == "OFFLINE_REPLAY"
        assert set(observed) == set(worker._ROLES)
        terminal_raw = worker.execute_request(raw)
        assert not terminal_raw.endswith(b"\n")
        terminal = json.loads(terminal_raw)
        assert terminal["schema"] == worker.TERMINAL_SCHEMA
        assert terminal["status"] == "COMPLETE"
        assert terminal["returncode"] == 0
        assert terminal["stdout"] == {
            "observed_bytes": 6,
            "retained_bytes": 6,
            "sha256": hashlib.sha256(b"hello\n").hexdigest(),
        }
        assert terminal["network"] == {
            "guest_observation": "NATIVE_PROVIDER_EVIDENCE_REQUIRED",
            "mode": "DENY_ALL",
            "observed_egress_sha256": worker.EMPTY_LIST_SHA256,
        }
        assert terminal["host_authority_required"] == [
            "HMAC_AUTHENTICATION", "MOUNT_RECENSUS", "NETWORK_DENIAL", "POPULATION_ZERO"
        ]
    finally:
        for fd in opened:
            os.close(fd)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda request: request.update(operation="JS_ONLINE_ACQUIRE"), "ONLINE_OR_UNSUPPORTED_OPERATION_DENIED"),
        (lambda request: request.update(network_mode="ALLOWLIST"), "NETWORK_MODE_NOT_DENY_ALL"),
        (lambda request: request.update(environment=[["PATH", "@fd:tool"]]), "AMBIENT_OR_LOADER_ENVIRONMENT_DENIED"),
        (lambda request: request.update(argv=["@fd:tool", "/tmp/ambient"]), "AMBIENT_PATH_OR_NETWORK_TOKEN_DENIED"),
        (lambda request: request["limits"].update(stdout_bytes=worker.MAX_STDOUT_BYTES + 1), "STDOUT_LIMIT_INVALID"),
    ],
)
def test_online_ambient_and_unbounded_requests_fail_closed(
    tmp_path: Path, mutation: object, code: str
) -> None:
    request, opened = _fixture_request(tmp_path)
    try:
        mutation(request)
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker.parse_request(_seal(request))
        assert raised.value.code == code
    finally:
        for fd in opened:
            os.close(fd)


def test_noncanonical_bytes_aliases_and_descriptor_drift_are_rejected(tmp_path: Path) -> None:
    request, opened = _fixture_request(tmp_path)
    try:
        raw = _seal(request)
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker.parse_request(raw + b"\n")
        assert raised.value.code == "REQUEST_BYTES_INVALID"

        aliases = json.loads(raw)
        aliases["descriptors"]["source"]["fd"] = aliases["descriptors"]["tool"]["fd"]
        aliases["descriptors"]["source"]["identity_sha256"] = worker.descriptor_identity(
            "source", aliases["descriptors"]["tool"]["fd"],
            "REGULAR_FILE", "READ_ONLY",
        )
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker.parse_request(_seal(aliases))
        assert raised.value.code == "DESCRIPTOR_ALIAS_DENIED"

        os.close(opened[1])
        opened.remove(opened[1])
        replacement = tmp_path / "replacement.sol"
        replacement.write_bytes(b"different\n")
        replacement_fd = os.open(replacement, os.O_RDONLY)
        opened.append(replacement_fd)
        drifted = json.loads(raw)
        drifted["descriptors"]["source"]["fd"] = replacement_fd
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker.parse_request(_seal(drifted))
        assert raised.value.code == "DESCRIPTOR_IDENTITY_MISMATCH"
    finally:
        for fd in opened:
            os.close(fd)


def test_snapshot_lane_has_exact_smaller_descriptor_roster(tmp_path: Path) -> None:
    request, opened = _fixture_request(tmp_path)
    try:
        request["operation"] = "SNAPSHOT_TOOL_EXECUTE"
        for role in ("acquisition", "cache", "generation"):
            request["descriptors"][role] = None
        parsed, observations = worker.parse_request(_seal(request))
        assert parsed["operation"] == "SNAPSHOT_TOOL_EXECUTE"
        assert set(observations) == {"project", "scratch", "source", "state", "tool"}
    finally:
        for fd in opened:
            os.close(fd)


def test_rejection_response_is_canonical_no_lf_and_never_claims_authority() -> None:
    request_read, request_write = os.pipe()
    response_read, response_write = os.pipe()
    try:
        os.write(request_write, b"{}")
        os.close(request_write)
        request_write = -1
        assert worker.serve_once(request_read, response_write) == 2
        os.close(response_write)
        response_write = -1
        raw = os.read(response_read, worker.MAX_RESPONSE_BYTES)
        assert not raw.endswith(b"\n")
        assert raw == worker.canonical_bytes(json.loads(raw))
        assert json.loads(raw)["schema"] == worker.REJECTION_SCHEMA
    finally:
        for fd in (request_read, request_write, response_read, response_write):
            if fd >= 0:
                os.close(fd)


def test_apple_attached_mode_has_exact_argv_and_fixed_mount_abi(monkeypatch: pytest.MonkeyPatch) -> None:
    assert worker.APPLE_MOUNT_ROLE_PATHS == (
        ("acquisition", "/plamen/retained/acquisition"),
        ("cache", "/plamen/retained/cache"),
        ("generation", "/plamen/retained/generation"),
        ("project", "/plamen/retained/project"),
        ("scratch", "/plamen/retained/scratch"),
        ("source", "/plamen/retained/source"),
        ("state", "/plamen/retained/state"),
    )
    assert worker.APPLE_TOOL_ANCHORS == (
        ("forge", "/usr/local/lib/plamen/toolchains/foundry/bin/forge"),
        ("js-python", "/usr/local/lib/plamen/python/bin/python3.12"),
        (
            "managed-python",
            "/usr/local/lib/plamen/python/bin/python3.12",
        ),
        ("opengrep", "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep"),
        ("slither", "/usr/local/lib/plamen/toolchains/managed-evm/bin/slither"),
        ("solc", "/usr/local/lib/plamen/toolchains/solc-amd64/solc"),
    )
    assert worker.APPLE_INTERNAL_FDS == (
        ("acquisition", 10), ("cache", 11), ("generation", 12),
        ("project", 13), ("scratch", 14), ("source", 15),
        ("state", 16), ("tool", 17),
    )
    monkeypatch.setattr(worker, "serve_apple_attached_stdio_v1", lambda: 23)
    assert worker.main(["--apple-attached-stdio-v1"]) == 23
    assert worker.main(["--apple-attached-stdio-v1", "extra"]) == 64
    with pytest.raises(worker.SpecializedToolWorkerError) as raised:
        worker.main(["--request-fd", "0", "--response-fd", "1"])
    assert raised.value.code == "CONTROL_DESCRIPTOR_INVALID"


def test_apple_request_is_canonical_and_has_no_guest_paths(tmp_path: Path) -> None:
    request, opened = _fixture_request(tmp_path)
    try:
        apple = _apple_request(request)
        raw = _seal(apple)
        parsed = worker._parse_apple_attached_request(raw)
        assert parsed["schema"] == worker.APPLE_REQUEST_SCHEMA
        encoded = raw.decode("ascii")
        assert "/plamen/retained" not in encoded
        assert '"fd"' not in encoded
    finally:
        for fd in opened:
            os.close(fd)


def test_apple_slither_request_binds_fixed_dependency_closure_and_environment(
    tmp_path: Path,
) -> None:
    request, opened = _fixture_request(tmp_path)
    try:
        apple = _apple_slither_request(request)
        parsed = worker._parse_apple_attached_request(_seal(apple))
        assert parsed["slither_internal_environment_sha256"] == hashlib.sha256(
            worker.canonical_bytes((
                ("FOUNDRY_CACHE_PATH", "@fd:state/foundry-cache"),
                ("FOUNDRY_OUT", "@fd:scratch/foundry-out"),
                ("HOME", "@fd:state/home"),
                (
                    "PATH",
                    "/usr/local/lib/plamen/toolchains/managed-evm/bin:"
                    "/usr/local/lib/plamen/toolchains/foundry/bin:"
                    "/usr/local/lib/plamen/toolchains/solc-amd64:/usr/bin:/bin",
                ),
                ("XDG_CACHE_HOME", "@fd:state/cache"),
            ))
        ).hexdigest()

        apple["slither_internal_environment_sha256"] = "7" * 64
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker._parse_apple_attached_request(_seal(apple))
        assert raised.value.code == "SLITHER_INTERNAL_ENVIRONMENT_DIGEST_INVALID"
    finally:
        for fd in opened:
            os.close(fd)


def test_apple_js_uses_five_mount_abi_without_weakening_retained_fd_mode(
    tmp_path: Path,
) -> None:
    request, opened = _fixture_request(tmp_path)
    try:
        apple = _apple_js_request(request)
        assert worker._parse_apple_attached_request(_seal(apple))["operation"] == (
            "OFFLINE_REPLAY"
        )

        retained = dict(request)
        retained["descriptors"] = dict(request["descriptors"])
        for role in ("cache", "generation", "project"):
            retained["descriptors"][role] = None
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker.parse_request(_seal(retained))
        assert raised.value.code == "REQUIRED_DESCRIPTOR_ABSENT"
        _parsed, observed = worker.parse_request(
            _seal(retained),
            _apple_attached_token=worker._APPLE_ATTACHED_REQUEST_TOKEN,
        )
        assert set(observed) == {
            "acquisition", "scratch", "source", "state", "tool"
        }
    finally:
        for fd in opened:
            os.close(fd)


def test_slither_internal_environment_cannot_be_requested_or_forged(
    tmp_path: Path,
) -> None:
    request, opened = _fixture_request(tmp_path)
    try:
        request["operation"] = "SNAPSHOT_TOOL_EXECUTE"
        for role in ("acquisition", "cache", "generation"):
            request["descriptors"][role] = None
        request["environment"] = [["FOUNDRY_OUT", "caller-controlled"]]
        raw = _seal(request)
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker.execute_request(
                raw,
                _internal_environment_token=worker._SLITHER_INTERNAL_ENVIRONMENT_TOKEN,
            )
        assert raised.value.code == "INTERNAL_ENVIRONMENT_COLLISION"

        request["environment"] = []
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker.execute_request(
                _seal(request), _internal_environment_token=object()
            )
        assert raised.value.code == "INTERNAL_ENVIRONMENT_AUTHORITY_INVALID"
    finally:
        for fd in opened:
            os.close(fd)


def test_image_member_is_accepted_only_for_compiled_tool_anchor(
    tmp_path: Path,
) -> None:
    request, opened = _fixture_request(tmp_path)
    try:
        apple = _apple_request(request)
        assert worker._parse_apple_attached_request(_seal(apple))[
            "tool_anchor_id"
        ] == "managed-python"
        apple["descriptors"]["source"]["kind"] = "IMAGE_MEMBER"
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker._parse_apple_attached_request(_seal(apple))
        assert raised.value.code == "IMAGE_MEMBER_ROLE_INVALID"
    finally:
        for fd in opened:
            os.close(fd)


def test_apple_missing_and_wrong_fixed_mounts_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, opened = _fixture_request(tmp_path)
    try:
        apple = _apple_request(request)
        monkeypatch.setattr(worker.os, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError()))
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker._open_fixed_apple_mounts(apple)
        assert raised.value.code == "FIXED_APPLE_MOUNT_UNAVAILABLE"

        regular_fd = os.dup(opened[0])
        monkeypatch.setattr(worker.os, "open", lambda *_args, **_kwargs: os.dup(regular_fd))
        readonly = type("StatVFS", (), {"f_flag": os.ST_RDONLY})
        monkeypatch.setattr(worker.os, "fstatvfs", lambda _fd: readonly)
        with pytest.raises(worker.SpecializedToolWorkerError) as raised:
            worker._open_fixed_apple_mounts(apple)
        assert raised.value.code == "APPLE_MOUNT_PAYLOAD_KIND_MISMATCH"
        os.close(regular_fd)
    finally:
        for fd in opened:
            os.close(fd)


def test_apple_stdio_rejects_tty_alias_and_ambient_fds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker.os, "isatty", lambda fd: fd == 0)
    with pytest.raises(worker.SpecializedToolWorkerError) as raised:
        worker._validate_apple_attached_stdio()
    assert raised.value.code == "ATTACHED_STDIO_TTY_DENIED"

    pipe_mode = stat.S_IFIFO | 0o600
    fake = type("FakeStat", (), {"st_mode": pipe_mode, "st_dev": 1, "st_ino": 9})
    monkeypatch.setattr(worker.os, "isatty", lambda _fd: False)
    monkeypatch.setattr(worker.os, "fstat", lambda _fd: fake)
    with pytest.raises(worker.SpecializedToolWorkerError) as raised:
        worker._validate_apple_attached_stdio()
    assert raised.value.code == "ATTACHED_STDIO_ALIAS_DENIED"

    monkeypatch.setattr(worker.os, "listdir", lambda _path: ["0", "1", "2", "9"])
    with pytest.raises(worker.SpecializedToolWorkerError) as raised:
        worker._initial_apple_fd_census()
    assert raised.value.code == "AMBIENT_DESCRIPTOR_PRESENT"


def test_apple_mount_access_must_match_native_readonly_state(monkeypatch: pytest.MonkeyPatch) -> None:
    read_write = type("StatVFS", (), {"f_flag": 0})
    read_only = type("StatVFS", (), {"f_flag": os.ST_RDONLY})
    monkeypatch.setattr(worker.os, "fstatvfs", lambda _fd: read_write)
    with pytest.raises(worker.SpecializedToolWorkerError) as raised:
        worker._require_apple_mount_access(9, "READ_ONLY")
    assert raised.value.code == "FIXED_APPLE_MOUNT_ACCESS_MISMATCH"
    monkeypatch.setattr(worker.os, "fstatvfs", lambda _fd: read_only)
    with pytest.raises(worker.SpecializedToolWorkerError) as raised:
        worker._require_apple_mount_access(9, "READ_WRITE")
    assert raised.value.code == "FIXED_APPLE_MOUNT_ACCESS_MISMATCH"


def test_apple_attached_rejection_is_canonical_stdout_and_silent_stderr() -> None:
    completed = subprocess.run(
        [sys.executable, "-I", "-S", str(Path(worker.__file__).resolve()), "--apple-attached-stdio-v1"],
        input=b"{}",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
        env={},
    )
    assert completed.returncode == 2
    assert completed.stderr == b""
    assert completed.stdout == worker.canonical_bytes(json.loads(completed.stdout))
    assert not completed.stdout.endswith(b"\n")
    assert json.loads(completed.stdout)["schema"] == worker.REJECTION_SCHEMA
