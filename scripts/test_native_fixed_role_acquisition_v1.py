from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

import native_fixed_role_acquisition as custody


ROOT = Path(__file__).resolve().parents[1]
FIXED = custody.FIXED_ROLE_ORDINALS
ROLE_NAMES = (
    "base_rootfs", "debian_package_state", "plamen_guest", "cpython",
    "plamen_package", "codex", "claude", "foundry", "medusa",
    "solc_amd64", "amd64_compat",
)


class NativeInput(ctypes.Structure):
    _fields_ = [
        ("role", ctypes.c_uint16), ("reserved", ctypes.c_uint16),
        ("payload_fd", ctypes.c_int),
        ("semantic_receipt_fd", ctypes.c_int),
        ("source_manifest_fd", ctypes.c_int),
        ("reviewed_policy_fd", ctypes.c_int),
    ]


class NativeProjectionRow(ctypes.Structure):
    _fields_ = [
        ("role", ctypes.c_uint16), ("reserved", ctypes.c_uint16),
        ("payload_fd", ctypes.c_int),
        ("producer_receipt_fd", ctypes.c_int),
        ("source_manifest_fd", ctypes.c_int),
        ("payload_size", ctypes.c_uint64),
        ("producer_receipt_size", ctypes.c_uint64),
        ("source_manifest_size", ctypes.c_uint64),
        ("policy_sha256", ctypes.c_ubyte * 32),
        ("payload_sha256", ctypes.c_ubyte * 32),
        ("producer_receipt_sha256", ctypes.c_ubyte * 32),
        ("source_manifest_sha256", ctypes.c_ubyte * 32),
    ]


class NativeProjection(ctypes.Structure):
    _fields_ = [("roles", NativeProjectionRow * len(FIXED))]


def _builder():
    path = ROOT / "scripts/build_posix_native_supervisor.py"
    spec = importlib.util.spec_from_file_location("_fixed_role_builder", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _read_fd(descriptor: int) -> bytes:
    size = os.fstat(descriptor).st_size
    return os.pread(descriptor, size, 0)


def _retained(path: Path, raw: bytes) -> int:
    path.write_bytes(raw)
    path.chmod(0o400)
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)


@pytest.fixture(scope="module")
def native_library(tmp_path_factory: pytest.TempPathFactory):
    builder = _builder()
    temporary = tmp_path_factory.mktemp("fixed-role-native")
    generated = temporary / "generated-policy.c"
    raw_by_role: dict[int, tuple[bytes, bytes, bytes, bytes]] = {}
    rows = []
    for role in range(11):
        dynamic = role in (5, 6)
        payload = f"payload:{ROLE_NAMES[role]}".encode("ascii")
        semantic = _canonical({
            "role": ROLE_NAMES[role],
            "schema": builder._OPERATION4_POLICY_SCHEMAS[role],
        })
        manifest = _canonical({"role": ROLE_NAMES[role]}) + b"\n"
        policy = _canonical({"policy": ROLE_NAMES[role]}) + b"\n"
        raw_by_role[role] = payload, semantic, manifest, policy
        rows.append({
            "role": role,
            "identity_mode": builder._OPERATION4_IDENTITY_MODES[role],
            "receipt_validator": builder._OPERATION4_RECEIPT_VALIDATORS[role],
            "payload_size": 0 if dynamic else len(payload),
            "source_manifest_size": 0 if dynamic else len(manifest),
            "semantic_receipt_size": 0 if dynamic else len(semantic),
            "payload_sha256": "0" * 64 if dynamic else hashlib.sha256(payload).hexdigest(),
            "source_manifest_sha256": (
                "0" * 64 if dynamic else hashlib.sha256(manifest).hexdigest()
            ),
            "semantic_receipt_sha256": (
                "0" * 64 if dynamic else hashlib.sha256(semantic).hexdigest()
            ),
            "policy_sha256": hashlib.sha256(policy).hexdigest(),
            "receipt_schema": builder._OPERATION4_POLICY_SCHEMAS[role],
        })
    generated.write_bytes(builder._render_operation4_fixed_policy_source(rows))
    library_path = temporary / "libfixed-role.dylib"
    completed = subprocess.run([
        "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-dynamiclib", "-I", str(ROOT / "native/darwin"),
        str(ROOT / "native/darwin/plamen_native_fixed_role_acquisition_v1.c"),
        str(generated), "-o", str(library_path),
    ], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    library = ctypes.CDLL(str(library_path), use_errno=True)
    library.plamen_native_fixed_role_acquisition_issue_v1.argtypes = [
        ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(NativeInput),
        ctypes.POINTER(NativeProjection),
    ]
    library.plamen_native_fixed_role_acquisition_issue_v1.restype = ctypes.c_int
    library.plamen_native_fixed_role_projection_dispose_v1.argtypes = [
        ctypes.POINTER(NativeProjection),
    ]
    return library, raw_by_role, rows


def _issue_case(
    tmp_path: Path, native_library, *, corrupt_policy: bool = False,
    corrupt_payload: bool = False,
):
    library, raw_by_role, rows = native_library
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700, exist_ok=True)
    stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    inputs = (NativeInput * len(FIXED))()
    descriptors: list[int] = [stage_fd]
    for index, role in enumerate(FIXED):
        payload, semantic, manifest, policy = raw_by_role[role]
        if corrupt_policy and index == 3:
            policy += b"x"
        if corrupt_payload and index == 0:
            payload = bytes([payload[0] ^ 1]) + payload[1:]
        values = [payload, semantic, manifest, policy]
        fds = [
            _retained(tmp_path / f"input-{role}-{kind}", raw)
            for kind, raw in zip(("payload", "semantic", "manifest", "policy"), values)
        ]
        descriptors.extend(fds)
        inputs[index] = NativeInput(role, 0, *fds)
    projection = NativeProjection()
    result = library.plamen_native_fixed_role_acquisition_issue_v1(
        os.getuid(), stage_fd, inputs, ctypes.byref(projection),
    )
    return result, projection, descriptors, stage, raw_by_role, rows


def test_fixed_native_producer_publishes_exact_policy_bound_triples(
    tmp_path: Path, native_library,
) -> None:
    result, projection, descriptors, stage, raw_by_role, rows = _issue_case(
        tmp_path, native_library,
    )
    library = native_library[0]
    try:
        assert result == 0, ctypes.get_errno()
        authority = stage / "share/plamen/native-source-authority-v1"
        assert sorted(path.name for path in authority.iterdir()) == sorted(
            name
            for role in FIXED
            for name in (
                f"{role:02d}-{ROLE_NAMES[role]}.payload",
                f"{role:02d}-{ROLE_NAMES[role]}.producer-receipt",
                f"{role:02d}-{ROLE_NAMES[role]}.source-manifest",
            )
        )
        for index, role in enumerate(FIXED):
            output = projection.roles[index]
            payload, semantic, manifest, policy = raw_by_role[role]
            producer = _read_fd(output.producer_receipt_fd)
            assert output.role == role
            assert _read_fd(output.payload_fd) == payload
            assert _read_fd(output.source_manifest_fd) == manifest
            assert producer[:-512] == semantic
            footer = producer[-512:]
            assert footer[:8] == b"PLMOP4R1"
            assert int.from_bytes(footer[12:14], "big") == role
            assert footer[44:76] == hashlib.sha256(policy).digest()
            assert footer[76:108] == hashlib.sha256(payload).digest()
            assert footer[108:140] == hashlib.sha256(manifest).digest()
            assert footer[140:172] == hashlib.sha256(semantic).digest()
            assert footer[480:] == hashlib.sha256(footer[:480]).digest()
            assert bytes(output.policy_sha256) == bytes.fromhex(
                rows[role]["policy_sha256"]
            )
            for descriptor in (
                output.payload_fd, output.producer_receipt_fd,
                output.source_manifest_fd,
            ):
                assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o400
                assert fcntl_getfd(descriptor) & 1
    finally:
        library.plamen_native_fixed_role_projection_dispose_v1(
            ctypes.byref(projection)
        )
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def fcntl_getfd(descriptor: int) -> int:
    import fcntl
    return fcntl.fcntl(descriptor, fcntl.F_GETFD)


def test_fixed_native_producer_rejects_policy_substitution_and_cleans(
    tmp_path: Path, native_library,
) -> None:
    result, projection, descriptors, stage, _raw, _rows = _issue_case(
        tmp_path, native_library, corrupt_policy=True,
    )
    try:
        assert result != 0
        authority = stage / "share/plamen/native-source-authority-v1"
        assert not authority.exists() or list(authority.iterdir()) == []
        for row in projection.roles:
            assert row.payload_fd == -1
            assert row.producer_receipt_fd == -1
            assert row.source_manifest_fd == -1
    finally:
        native_library[0].plamen_native_fixed_role_projection_dispose_v1(
            ctypes.byref(projection)
        )
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def test_fixed_native_producer_rejects_payload_substitution_against_compiled_row(
    tmp_path: Path, native_library,
) -> None:
    result, projection, descriptors, stage, _raw, _rows = _issue_case(
        tmp_path, native_library, corrupt_payload=True,
    )
    try:
        assert result != 0
        authority = stage / "share/plamen/native-source-authority-v1"
        assert not authority.exists() or list(authority.iterdir()) == []
        assert all(row.payload_fd == -1 for row in projection.roles)
    finally:
        native_library[0].plamen_native_fixed_role_projection_dispose_v1(
            ctypes.byref(projection)
        )
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def test_fixed_native_producer_rolls_back_partial_output_without_unlinking_prestate(
    tmp_path: Path, native_library,
) -> None:
    precreated = tmp_path / "stage/share/plamen/native-source-authority-v1"
    precreated.mkdir(parents=True, mode=0o700)
    collision = precreated / "04-plamen_package.producer-receipt"
    collision.write_bytes(b"preexisting")
    collision.chmod(0o400)
    result, projection, descriptors, stage, _raw, _rows = _issue_case(
        tmp_path, native_library,
    )
    try:
        assert result != 0
        assert collision.read_bytes() == b"preexisting"
        assert sorted(path.name for path in precreated.iterdir()) == [collision.name]
        for row in projection.roles:
            assert row.payload_fd == -1
            assert row.producer_receipt_fd == -1
            assert row.source_manifest_fd == -1
    finally:
        native_library[0].plamen_native_fixed_role_projection_dispose_v1(
            ctypes.byref(projection)
        )
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _fake_native_issue(tmp_path: Path, inputs):
    rows = []
    for item in inputs:
        descriptors = tuple(
            _retained(tmp_path / f"issued-{item.ordinal}-{kind}", raw)
            for kind, raw in (
                ("payload", b"p"), ("producer", b"r"), ("manifest", b"m")
            )
        )
        rows.append(custody.FixedRoleRecord(
            ordinal=item.ordinal,
            policy_sha256=format(item.ordinal + 1, "064x"),
            payload_fd=descriptors[0], producer_receipt_fd=descriptors[1],
            source_manifest_fd=descriptors[2],
        ))
    return tuple(rows)


def _materialized(tmp_path: Path):
    result = []
    for ordinal in FIXED:
        descriptors = tuple(
            _retained(tmp_path / f"materialized-{ordinal}-{kind}", raw)
            for kind, raw in (
                ("payload", b"p"), ("semantic", b"s"),
                ("manifest", b"m"), ("policy", b"q"),
            )
        )
        result.append(custody.FixedRoleMaterializedInput(ordinal, *descriptors))
    return tuple(result)


def test_python_custody_allocates_exact_private_store_roster_and_consumes_once(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    inputs = _materialized(tmp_path)
    source_fds = [
        descriptor for row in inputs for descriptor in (
            row.payload_fd, row.semantic_receipt_fd,
            row.source_manifest_fd, row.reviewed_policy_fd,
        )
    ]
    authority = custody.acquire_fixed_role_inputs(
        staged_generation_root_fd=root_fd,
        materialized_inputs=inputs,
        native_issue=lambda _root_fd, values: _fake_native_issue(tmp_path, values),
        private_store=custody.RetainedPrivateStoreFactory(root_fd),
    )
    try:
        transfer = authority.consume()
        assert len(transfer.fixed_roles) == 7
        assert len(transfer.output_pairs) == 5
        assert len(transfer.scratch_fds) == 24
        assert len(transfer.descriptors()) == 63
        assert len(set(transfer.descriptors())) == 63
        assert os.fstat(transfer.grouped_pair[0]).st_nlink == 0
        assert os.fstat(transfer.terminal_pair[0]).st_nlink == 0
        assert all(os.fstat(pair[0]).st_nlink == 0 for pair in transfer.output_pairs)
        assert all(os.fstat(fd).st_nlink == 0 for fd in transfer.scratch_fds)
        assert os.fstat(transfer.verifier_key_pair[0]).st_nlink == 1
        assert os.fstat(transfer.coordinator_receipt_pair[0]).st_nlink == 1
        with pytest.raises(
            custody.NativeFixedRoleAcquisitionError, match="already consumed",
        ):
            authority.consume()
    finally:
        authority.close()
        authority.close()
        if "transfer" in locals():
            for descriptor in transfer.descriptors():
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        for descriptor in [*source_fds, root_fd]:
            try:
                os.close(descriptor)
            except OSError:
                pass


def test_unconsumed_python_custody_closes_and_unlinks_linked_stores(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    inputs = _materialized(tmp_path)
    source_fds = [
        descriptor for row in inputs for descriptor in (
            row.payload_fd, row.semantic_receipt_fd,
            row.source_manifest_fd, row.reviewed_policy_fd,
        )
    ]
    authority = custody.acquire_fixed_role_inputs(
        staged_generation_root_fd=root_fd, materialized_inputs=inputs,
        native_issue=lambda _root_fd, values: _fake_native_issue(tmp_path, values),
        private_store=custody.RetainedPrivateStoreFactory(root_fd),
    )
    authority.close()
    authority.close()
    assert not (root / "producer-verifier-key").exists()
    assert not (root / "coordinator-receipt").exists()
    for descriptor in [*source_fds, root_fd]:
        try:
            os.close(descriptor)
        except OSError:
            pass


def test_python_native_issue_adapter_uses_retained_rejoined_closed_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    executable = tmp_path / "native-coordinator"
    executable.write_bytes(b"native-test-executable")
    executable.chmod(0o500)
    executable_fd = os.open(
        executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    inputs = _materialized(tmp_path)
    source_fds = [
        descriptor for row in inputs for descriptor in (
            row.payload_fd, row.semantic_receipt_fd,
            row.source_manifest_fd, row.reviewed_policy_fd,
        )
    ]

    def fake_run(argv, **kwargs):
        assert len(argv) == 31
        assert argv[:2] == [str(executable.resolve()), "sign-fixed-roles-v1"]
        assert argv[2:] == [str(stage_fd), *(str(fd) for fd in source_fds)]
        assert kwargs["env"] == {
            "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
            "PYTHONHASHSEED": "0",
        }
        assert kwargs["close_fds"] is True
        assert kwargs["pass_fds"] == (stage_fd, *source_fds, executable_fd)
        authority = stage / "share/plamen/native-source-authority-v1"
        authority.mkdir(parents=True, mode=0o700)
        for row in inputs:
            prefix = f"{row.ordinal:02d}-{ROLE_NAMES[row.ordinal]}"
            payload = os.pread(row.payload_fd, os.fstat(row.payload_fd).st_size, 0)
            manifest = os.pread(
                row.source_manifest_fd, os.fstat(row.source_manifest_fd).st_size, 0,
            )
            policy = os.pread(
                row.reviewed_policy_fd, os.fstat(row.reviewed_policy_fd).st_size, 0,
            )
            footer = bytearray(512)
            footer[:8] = b"PLMOP4R1"
            footer[12:14] = row.ordinal.to_bytes(2, "big")
            footer[44:76] = hashlib.sha256(policy).digest()
            footer[480:] = hashlib.sha256(footer[:480]).digest()
            for suffix, raw in (
                ("payload", payload),
                ("producer-receipt", b"{}" + bytes(footer)),
                ("source-manifest", manifest),
            ):
                path = authority / f"{prefix}.{suffix}"
                path.write_bytes(raw)
                path.chmod(0o400)
        return SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(custody.subprocess, "run", fake_run)
    rows = custody.run_native_fixed_role_issue_cli(
        executable_fd=executable_fd, staged_generation_root_fd=stage_fd,
        executable_path=str(executable.resolve()), inputs=inputs,
        timeout_seconds=60,
    )
    try:
        assert tuple(row.ordinal for row in rows) == FIXED
        assert tuple(row.policy_sha256 for row in rows) == tuple(
            hashlib.sha256(os.pread(
                item.reviewed_policy_fd,
                os.fstat(item.reviewed_policy_fd).st_size, 0,
            )).hexdigest()
            for item in inputs
        )
    finally:
        for row in rows:
            for descriptor in (
                row.payload_fd, row.producer_receipt_fd,
                row.source_manifest_fd,
            ):
                os.close(descriptor)
        for descriptor in [*source_fds, executable_fd, stage_fd]:
            os.close(descriptor)
