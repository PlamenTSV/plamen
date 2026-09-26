"""Production-readiness gates for the unified CPython 3.12 native closure."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from types import MappingProxyType, ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_posix_native_supervisor.py"
RECEIPT_SOURCE = ROOT / "native" / "darwin" / "plamen_broker_v2_install_receipt.c"
DEPLOYMENT_RECEIPT_SOURCE = (
    ROOT / "native" / "darwin" / "plamen_native_deployment_receipt_v2.c"
)
LAUNCHER_SOURCE = ROOT / "native" / "darwin" / "plamen_native_launcher.c"
PROTOCOL_SOURCE = ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"
NATIVE_BUILDER_SOURCE = ROOT / "native" / "posix" / "plamen_native_builder_v2.c"
NATIVE_BUILDER_HEADER = ROOT / "native" / "posix" / "plamen_native_builder_v2.h"


def _load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_plamen_native_production_readiness_test", BUILDER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _operation4_policy_rows(builder: ModuleType) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for role in range(11):
        dynamic = role in (5, 6)
        rows.append({
            "role": role,
            "identity_mode": builder._OPERATION4_IDENTITY_MODES[role],
            "receipt_validator": builder._OPERATION4_RECEIPT_VALIDATORS[role],
            "payload_size": 0 if dynamic else 1000 + role,
            "source_manifest_size": 0 if dynamic else 2000 + role,
            "semantic_receipt_size": 0 if dynamic else 3000 + role,
            "payload_sha256": "0" * 64 if dynamic else format(10 + role, "064x"),
            "source_manifest_sha256": (
                "0" * 64 if dynamic else format(30 + role, "064x")
            ),
            "semantic_receipt_sha256": (
                "0" * 64 if dynamic else format(50 + role, "064x")
            ),
            "policy_sha256": format(70 + role, "064x"),
            "receipt_schema": builder._OPERATION4_POLICY_SCHEMAS[role],
        })
    return rows


def test_operation4_strong_policy_renderer_is_compilable_and_fail_closed(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    rows = _operation4_policy_rows(builder)
    source = builder._render_operation4_fixed_policy_source(rows)
    assert source.count(b".role=") == 11
    assert b"plamen_native_operation4_generated_policy_v1" in source
    assert (
        b".roster_sha256={0x62,0xbd,0xec,0x80,0x12,0xe4,0x92,0x95,"
        b"0xd4,0x7c,0xb4,0xad,0x9b,0x7f,0x26,0x60,0x39,0x3a,0xba,0xd6,"
        b"0x83,0x7d,0x73,0x55,0xbf,0xe2,0xe4,0x4d,0x94,0xb8,0xc3,0xc7}"
        in source
    )
    generated = tmp_path / "generated-operation4-policy.c"
    generated.write_bytes(source)
    compiled = subprocess.run([
        "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-I", str(ROOT / "native" / "darwin"), "-c", str(generated),
        "-o", str(tmp_path / "generated-operation4-policy.o"),
    ], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert compiled.returncode == 0, compiled.stderr.decode("utf-8", "replace")
    probe = tmp_path / "operation4-policy-kat.c"
    probe.write_text(
        '#include "plamen_native_operation4_helper_v1.h"\n'
        '#include <string.h>\n'
        'int main(void){struct plamen_native_operation4_fixed_policy_v1 p='
        'plamen_native_operation4_generated_policy_v1;unsigned char expected[32];'
        'memcpy(expected,p.roster_sha256,32);memset(p.roster_sha256,0,32);'
        'return plamen_native_operation4_policy_finalize_for_testing_v1(&p)!=0'
        '||memcmp(expected,p.roster_sha256,32)!=0;}\n',
        encoding="ascii",
    )
    linked = subprocess.run([
        "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-DPLAMEN_NATIVE_OPERATION4_TESTING",
        "-I", str(ROOT / "native" / "darwin"), str(probe), str(generated),
        str(ROOT / "native" / "darwin" / "plamen_native_operation4_helper_v1.c"),
        "-lproc", "-o", str(tmp_path / "operation4-policy-kat"),
    ], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert linked.returncode == 0, linked.stderr.decode("utf-8", "replace")
    checked = subprocess.run(
        [str(tmp_path / "operation4-policy-kat")], check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert checked.returncode == 0, checked.stderr.decode("utf-8", "replace")
    # The renderer is one-pass: its output is deterministic and never an input
    # to any frozen-source payload or semantic identity row.
    assert builder._render_operation4_fixed_policy_source(rows) == source
    assert all(
        "operation4_generated_policy" not in str(row)
        and "operation4_helper" not in str(row)
        and "source_bootstrap_coordinator" not in str(row)
        for role, row in enumerate(rows) if role in (2, 4)
    )

    substituted = [dict(row) for row in rows]
    substituted[5]["payload_sha256"] = "1" * 64
    with pytest.raises(builder.BuildError, match="dynamic backend policy"):
        builder._render_operation4_fixed_policy_source(substituted)
    substituted = [dict(row) for row in rows]
    substituted[8]["policy_sha256"] = "0" * 64
    with pytest.raises(builder.BuildError, match="fixed policy row"):
        builder._render_operation4_fixed_policy_source(substituted)


def test_operation4_policy_has_no_self_referential_extension_consumer() -> None:
    builder = _load_builder()
    assert builder.PRODUCTION_OPERATION4_POLICY_CONSUMERS == {
        "retained-source-bootstrap-coordinator",
    }
    extension = next(
        row for row in builder.PRODUCTION_DARWIN_LINK_ROSTER
        if row["kind"] == "cpython-extension"
    )
    coordinator = next(
        row for row in builder.PRODUCTION_DARWIN_LINK_ROSTER
        if row["kind"] == "retained-source-bootstrap-coordinator"
    )
    assert extension["kind"] not in builder.PRODUCTION_OPERATION4_POLICY_CONSUMERS
    assert coordinator["kind"] in builder.PRODUCTION_OPERATION4_POLICY_CONSUMERS
    source = BUILDER.read_text(encoding="utf-8")
    assert (
        '),) if row["kind"] == "cpython-extension" else ())'
        not in source
    )
    # The two frozen projections whose payloads can contain release products
    # remain ordinary role inputs; neither is allowed to become a generated
    # policy source role in its own denominator.
    assert all(
        "operation4_generated_policy" not in row["source_roles"]
        for row in (extension, coordinator)
    )


def test_release_compile_tranches_break_operation4_projection_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    calls: list[object] = []

    def render(rows: object) -> bytes:
        calls.append(rows)
        return b"exact-generated-policy"

    monkeypatch.setattr(builder, "_render_operation4_fixed_policy_source", render)
    extension_rows, generated = builder._select_darwin_release_compile_rows(
        ("cpython-extension",), None,
    )
    assert [row["kind"] for row in extension_rows] == ["cpython-extension"]
    assert generated is None
    assert calls == []

    policy = _operation4_policy_rows(builder)
    coordinator_rows, generated = builder._select_darwin_release_compile_rows(
        ("retained-source-bootstrap-coordinator",), policy,
    )
    assert [row["kind"] for row in coordinator_rows] == [
        "retained-source-bootstrap-coordinator",
    ]
    assert generated == b"exact-generated-policy"
    assert calls == [policy]

    with pytest.raises(builder.BuildError, match="unused operation-4"):
        builder._select_darwin_release_compile_rows(
            ("cpython-extension",), policy,
        )
    with pytest.raises(builder.BuildError, match="fixed policy rows"):
        builder._select_darwin_release_compile_rows(
            ("retained-source-bootstrap-coordinator",), None,
        )
    with pytest.raises(builder.BuildError, match="selection order"):
        builder._select_darwin_release_compile_rows(
            ("retained-source-bootstrap-coordinator", "cpython-extension"),
            policy,
        )
    with pytest.raises(builder.BuildError, match="selection differs"):
        builder._select_darwin_release_compile_rows(("unknown",), None)


def test_operation4_retained_roster_fold_replays_all_receipt_footers(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    opened: list[int] = []
    records: dict[int, object] = {}

    class Fixed:
        pass

    for role in range(11):
        payload = f"payload-{role}".encode("ascii")
        manifest = f"manifest-{role}\n".encode("ascii")
        semantic = json.dumps(
            {"role": role, "schema": builder._OPERATION4_POLICY_SCHEMAS[role]},
            sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
        policy_sha256 = format(role + 100, "064x")
        footer = bytearray(512)
        footer[:8] = b"PLMOP4R1"
        struct.pack_into(
            ">HHHHH", footer, 8, 1, 512, role,
            builder._OPERATION4_IDENTITY_MODES[role],
            builder._OPERATION4_RECEIPT_VALIDATORS[role],
        )
        struct.pack_into(">QQQ", footer, 20, len(payload), len(manifest),
                         len(semantic))
        footer[44:76] = bytes.fromhex(policy_sha256)
        footer[76:108] = hashlib.sha256(payload).digest()
        footer[108:140] = hashlib.sha256(manifest).digest()
        footer[140:172] = hashlib.sha256(semantic).digest()
        schema = builder._OPERATION4_POLICY_SCHEMAS[role].encode("ascii")
        footer[172:172 + len(schema)] = schema
        footer[480:] = hashlib.sha256(footer[:480]).digest()
        descriptors = []
        for suffix, raw in (
            ("payload", payload), ("receipt", semantic + footer),
            ("manifest", manifest),
        ):
            path = tmp_path / f"{role}-{suffix}"
            path.write_bytes(raw); path.chmod(0o400)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            opened.append(descriptor); descriptors.append(descriptor)
        if role in {0, 1, 2, 3, 4, 7, 10}:
            value = Fixed()
            value.ordinal = role
            value.policy_sha256 = policy_sha256
            value.payload_fd, value.producer_receipt_fd, value.source_manifest_fd = (
                descriptors
            )
            records[role] = value
        else:
            records[role] = MappingProxyType({
                "role": role, "policy_sha256": policy_sha256,
                "payload_fd": descriptors[0],
                "producer_receipt_fd": descriptors[1],
                "source_manifest_fd": descriptors[2],
            })

    class Backends:
        _PLAMEN_RETAINED_PRODUCTION_BACKEND_ROLES_V1 = True

        @staticmethod
        def role_records():
            return records[5], records[6]

    class EVM:
        _PLAMEN_RETAINED_PRODUCTION_EVM_STATIC_ROLES_V1 = True

        @staticmethod
        def role_records():
            return records[8], records[9]

    try:
        folded = builder._compose_production_operation4_inputs(
            fixed_role_records=tuple(
                records[role] for role in (0, 1, 2, 3, 4, 7, 10)
            ), backend_authority=Backends(), evm_static_authority=EVM(),
        )
        assert len(folded["role_fds"]) == 11
        assert [row["role"] for row in folded["policy_rows"]] == list(range(11))
        assert all(
            folded["policy_rows"][role][field] in {0, "0" * 64}
            for role in (5, 6)
            for field in (
                "payload_size", "source_manifest_size",
                "semantic_receipt_size", "payload_sha256",
                "source_manifest_sha256", "semantic_receipt_sha256",
            )
        )
        assert folded["policy_rows"][8]["payload_size"] == len(b"payload-8")

        payload_fd = records[8]["payload_fd"]
        path = tmp_path / "8-payload"; path.chmod(0o600)
        with path.open("r+b") as stream:
            stream.seek(0); stream.write(b"X"); stream.flush(); os.fsync(stream.fileno())
        with pytest.raises(builder.BuildError, match="producer authority"):
            builder._compose_production_operation4_inputs(
                fixed_role_records=tuple(
                    records[role] for role in (0, 1, 2, 3, 4, 7, 10)
                ), backend_authority=Backends(), evm_static_authority=EVM(),
            )
        assert os.fstat(payload_fd).st_size == len(b"payload-8")
    finally:
        for descriptor in opened:
            os.close(descriptor)


def test_operation4_compile_policy_is_derived_before_native_signers(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    opened: list[int] = []
    source_paths: dict[str, Path] = {}
    source_rows: list[dict[str, object]] = []

    def retained(name: str, raw: bytes) -> int:
        path = tmp_path / name
        path.write_bytes(raw); path.chmod(0o400)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        opened.append(descriptor)
        return descriptor

    def frozen(name: str, raw: bytes) -> None:
        path = tmp_path / name
        path.write_bytes(raw); path.chmod(0o400); source_paths[name] = path
        source_rows.append({
            "role": name, "path": name, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })

    backend_policy = _canonical({"schema": "fixture.backend-policy"})
    frozen("native_backend_latest_acquisition_policy", backend_policy)
    for role, name, stem in (
        (8, "medusa", "medusa"), (9, "solc_amd64", "solc_amd64"),
    ):
        payload = f"static-{name}".encode("ascii")
        policy = _canonical({
            "artifact": {
                ("executable" if role == 8 else "binary"): {
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                },
            },
        })
        receipt = json.dumps({
            "schema": builder._OPERATION4_POLICY_SCHEMAS[role],
        }, sort_keys=True, separators=(",", ":")).encode("ascii")
        manifest = _canonical({"role": name})
        frozen(f"{stem}_acquisition_policy", policy)
        frozen(f"{stem}_acquisition_receipt", receipt)
        frozen(f"{stem}_runtime_source_manifest", manifest)

    class Roster:
        _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True

        @staticmethod
        def duplicate_member(role):
            return os.open(source_paths[role], os.O_RDONLY | os.O_CLOEXEC)

    class Materialized:
        pass

    materialized = []
    for role in (0, 1, 2, 3, 4, 7, 10):
        row = Materialized(); row.ordinal = role
        row.payload_fd = retained(f"fixed-{role}-payload", b"payload")
        row.semantic_receipt_fd = retained(
            f"fixed-{role}-semantic", b"semantic",
        )
        row.source_manifest_fd = retained(
            f"fixed-{role}-manifest", b"manifest\n",
        )
        row.reviewed_policy_fd = retained(
            f"fixed-{role}-policy", b"policy\n",
        )
        materialized.append(row)
    try:
        rows = builder._derive_production_operation4_policy_rows(
            source_freeze={"sources": source_rows}, source_roster=Roster(),
            fixed_materialized_inputs=tuple(materialized),
        )
        assert [row["role"] for row in rows] == list(range(11))
        assert rows[5]["policy_sha256"] == hashlib.sha256(
            backend_policy,
        ).hexdigest()
        assert rows[5]["payload_size"] == 0
        assert rows[6]["semantic_receipt_sha256"] == "0" * 64
        assert rows[8]["payload_size"] == len(b"static-medusa")
        assert rows[9]["payload_sha256"] == hashlib.sha256(
            b"static-solc_amd64",
        ).hexdigest()
        os.chmod(tmp_path / "fixed-2-payload", 0o600)
        with (tmp_path / "fixed-2-payload").open("r+b") as stream:
            stream.write(b"X"); stream.flush(); os.fsync(stream.fileno())
        changed = builder._derive_production_operation4_policy_rows(
            source_freeze={"sources": source_rows}, source_roster=Roster(),
            fixed_materialized_inputs=tuple(materialized),
        )
        assert changed[2]["payload_sha256"] != rows[2]["payload_sha256"]
    finally:
        for descriptor in opened:
            os.close(descriptor)


def _receipt_inputs(builder: ModuleType) -> dict[str, object]:
    members = []
    for index, expected in enumerate(builder.DARWIN_INSTALL_RECEIPT_V2_MEMBERS):
        role, _role_id, relative, mode, identifier, signed = expected
        members.append({
            "role": role,
            "relative_path": relative,
            "sha256": format(index + 10, "064x"),
            "size": 100 + index,
            "mode": mode,
            "device": 200 + index,
            "inode": 300 + index,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "signing_identifier": (
                "org.python.python" if role == "python" else identifier or ""
            ),
            "team_identifier": "",
            "cdhash": "ab" * 20 if signed else "",
        })
    generation_id, _preimage = builder.production_intrinsic_generation_id([
        {
            "role": member["role"],
            "relative_path": member["relative_path"],
            "sha256": member["sha256"],
            "size": member["size"],
            "mode": member["mode"],
        }
        for member in members
    ])
    generation_path = "/Users/test/.local/share/plamen/generations/" + generation_id
    return {
        "projection_schema_sha256": "44" * 32,
        "protocol_schema_sha256": "55" * 32,
        "python_micro": 10,
        "generation_path": generation_path,
        "broker_launchd_plist": {
            "path": (
                generation_path
                + "/Library/LaunchAgents/com.plamen.audit.broker.v2.plist"
            ),
            "sha256": "66" * 32,
            "size": 401,
            "mode": 0o400,
            "device": 501,
            "inode": 601,
            "uid": os.getuid(),
            "gid": os.getgid(),
        },
        "custody_launchd_plist": {
            "path": (
                generation_path
                + "/Library/LaunchAgents/"
                "com.plamen.audit.process-custody.v2.plist"
            ),
            "sha256": "77" * 32,
            "size": 419,
            "mode": 0o400,
            "device": 502,
            "inode": 602,
            "uid": os.getuid(),
            "gid": os.getgid(),
        },
        "members": members,
    }


def _runtime_bindings(builder: ModuleType, seed: int = 1) -> dict[str, object]:
    digests = {
        field: format(seed + index + 1, "064x")
        for index, field in enumerate(
            builder.RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS
        )
    }
    index_digest = digests["oci_index_digest"]
    return {
        "target_arch": "arm64",
        "oci_image_reference": (
            "registry.example/plamen/audit@sha256:" + index_digest
        ),
        "oci_init_reference": "/usr/local/libexec/plamen-guest",
        **digests,
    }


def _thaw_runtime_tree(root: Path) -> None:
    if not root.exists():
        return
    for directory, _names, files in os.walk(root, topdown=False):
        parent = Path(directory)
        for name in files:
            try:
                (parent / name).chmod(0o600, follow_symlinks=False)
            except (NotImplementedError, OSError):
                pass
        try:
            parent.chmod(0o700)
        except OSError:
            pass


def _materialize_runtime_tree(
    root: Path, *, defect: str | None = None,
) -> Path:
    scripts = root / "scripts"
    package = root / "plamen_runtime"
    profiles = root / "profiles"
    empty = package / "assets"
    empty.mkdir(parents=True)
    scripts.mkdir(parents=True)
    profiles.mkdir(parents=True)
    files = {
        profiles / "claude-v2.bin": bytes(2048),
        profiles / "codex-v2.bin": bytes(2048),
        scripts / "posix_audit_entrypoint.py": b"from plamen_runtime.run import main\nmain()\n",
        scripts / "posix_native_authority_adapter.py": b"def project(authority):\n    return authority\n",
        scripts / "posix_specialized_tool_worker.py": b"def execute():\n    return 0\n",
        scripts / "report_output_routing.py": b"def route():\n    return 0\n",
        scripts / "native_managed_evm_driver_preflight.py": b"def prepare():\n    return 0\n",
        scripts / "native_managed_evm_setup_effects.py": b"class Effects:\n    pass\n",
        scripts / "posix_managed_evm_setup_transaction.py": b"def execute():\n    return 0\n",
        scripts / "plamen_driver.py": b"def drive():\n    return 0\n",
        package / "__init__.py": b"\n",
        package / "run.py": b"def main():\n    return 0\n",
        empty / "policy.json": b'{"network":"closed"}\n',
    }
    if defect == "missing-entrypoint":
        del files[scripts / "posix_audit_entrypoint.py"]
    elif defect == "missing-profile":
        del files[profiles / "codex-v2.bin"]
    for path, raw in files.items():
        path.write_bytes(raw)
        path.chmod(0o400)
    if defect == "symlink":
        (package / "alias.py").symlink_to("run.py")
    elif defect == "hardlink":
        os.link(package / "run.py", package / "run-copy.py")
    elif defect == "file-mode":
        (package / "run.py").chmod(0o600)
    for directory in sorted(
        (item for item in root.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts), reverse=True,
    ):
        directory.chmod(0o500)
    root.chmod(0o700 if defect == "root-mode" else 0o500)
    return root


@pytest.fixture
def runtime_tree_factory(tmp_path: Path):
    roots: list[Path] = []

    def make(name: str, *, defect: str | None = None) -> Path:
        root = _materialize_runtime_tree(tmp_path / name, defect=defect)
        roots.append(root)
        return root

    yield make
    for root in roots:
        _thaw_runtime_tree(root)


def test_production_readiness_binds_the_fixed_source_and_install_rosters() -> None:
    builder = _load_builder()
    report = builder.production_readiness()

    assert report["schema"] == "plamen.native-supervisor.production-readiness.v2"
    assert report["authority"] == (
        "DIAGNOSTIC_ONLY_LOADED_PYTHON_NO_BUILD_AUTHORITY"
    )
    assert report["production_build_allowed"] is False
    closure = report["closure"]
    assert closure["cpython_abi"] == [3, 12]
    assert closure["framework_roster"] == [
        "CoreFoundation.framework",
        "Security.framework",
        "libSystem",
    ]
    assert closure["generation_install_roster"] == [
        "bin/python3.12",
        "bin/plamen-native-launcher",
        "lib/plamen/plamen-audit-broker-v2",
        "lib/plamen/_plamen_native_supervisor.cpython-312-darwin.so",
        "share/plamen/plamen_broker_v2.h",
        "share/plamen/native-supervisor-schema-v2.json",
        "Library/LaunchAgents/com.plamen.audit.broker.v2.plist",
        "Library/LaunchAgents/com.plamen.audit.process-custody.v2.plist",
        "lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
            "share/plamen/runtime-package-manifest-v2.bin",
            "libexec/plamen-native-installer-v2",
            "libexec/plamen-native-source-bootstrap-coordinator-v1",
    ]
    assert closure["install_root_deployment_roster"] == [
        "bin/plamen-native-launcher",
        "generations/{generation_id}/libexec/plamen-native-installer-v2",
        (
            "generations/{generation_id}/libexec/"
            "plamen-native-source-bootstrap-coordinator-v1"
        ),
        "share/plamen/native-install-receipt-v2.bin",
        "share/plamen/native-deployment-receipt-v2.bin",
    ]
    assert closure["public_topology"] == {
        "native_home_authority": "getpwuid_r(getuid()).pw_dir",
        "install_root": "{pw_dir}/.local/share/plamen",
        "public_command": "{pw_dir}/.local/bin/plamen",
        "public_command_role": "ORDINARY_V3_FRONT_SHIM_NOT_AUTHORITY",
        "installed_source": "{pw_dir}/.plamen",
        "managed_python": (
            "{pw_dir}/.local/share/plamen/runtime/py312/bin/python"
        ),
        "front_script": "{pw_dir}/.plamen/plamen.py",
        "internal_launcher": (
            "{pw_dir}/.local/share/plamen/generations/{generation_id}/"
            "bin/plamen-native-launcher"
        ),
        "stable_internal_launcher": (
            "{pw_dir}/.local/share/plamen/bin/plamen-native-launcher"
        ),
        "stable_internal_launcher_publication": (
            "ATOMIC_HARDLINK_AFTER_AUTHENTICATED_SERVICE_READINESS"
        ),
        "native_child_argv": (
            "{generation}/bin/python3.12", "-I", "-B",
            "{generation}/lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
        ),
        "outer_entrypoint_request_source": (
            "INITIAL_AUTHORITY.request_projection"
        ),
        "native_transition": (
            "start-config-or-resume -> internal-launcher exactly once -> "
            "fixed-generation-python-and-driver"
        ),
        "environment_recursion_marker_allowed": False,
    }
    assert [row["role"] for row in closure["source_roster"]] == [
        role for role, _relative in builder.PRODUCTION_DARWIN_SOURCE_ROSTER
    ]
    assert [row["path"] for row in closure["source_roster"]] == [
        relative for _role, relative in builder.PRODUCTION_DARWIN_SOURCE_ROSTER
    ]
    source_roles = {row["role"] for row in closure["source_roster"]}
    assert {
        "package_front", "cold_install_transaction",
        "cold_install_publication", "cold_install_effects",
        "runtime_source_projection", "runtime_source_projection_manifest",
    } <= source_roles
    for row in closure["source_roster"]:
        if row["status"] != "OBSERVED_DIAGNOSTIC_ONLY":
            assert row["status"] in {"MISSING", "ALIASED", "INVALID"}
            continue
        # The descriptor capture itself performs a before/after identity and
        # content replay.  Do not reopen the mutable development pathname here:
        # another implementation owner may legitimately edit it after this
        # diagnostic report and before the assertion executes.
        assert type(row["size"]) is int and row["size"] > 0
        assert len(row["sha256"]) == 64
        int(row["sha256"], 16)
        if row["expected_sha256"] is not None:
            mismatch = (
                f"SOURCE_HASH_MISMATCH:{row['role']}:{row['path']}"
            )
            assert (row["sha256"] != row["expected_sha256"]) == (
                mismatch in report["blockers"]
            )
    freeze = closure["source_freeze_manifest"]
    assert freeze["schema"] == "plamen.native-production-source-freeze.v2"
    assert freeze["path"] == str(
        ROOT / "native" / "darwin"
        / "native-production-source-freeze-v2.json"
    )
    assert freeze["status"] in {
        "MISSING", "INVALID", "OBSERVED_DIAGNOSTIC_ONLY",
    }

    observed = dict(report)
    digest = observed.pop("observation_sha256")
    assert digest == hashlib.sha256(_canonical(observed)).hexdigest()


def test_production_roster_keeps_test_only_and_production_identities_distinct() -> None:
    builder = _load_builder()

    assert builder.PRODUCTION_MODULE == "_plamen_native_supervisor"
    assert builder.TEST_ONLY_MODULE == "_plamen_native_supervisor_testonly"
    assert builder.PRODUCTION_MODULE != builder.TEST_ONLY_MODULE
    extension = builder.SOURCE.read_bytes()
    assert b"PyInit__plamen_native_supervisor" in extension
    assert b"PyInit__plamen_native_supervisor_testonly" in extension
    assert b"PLAMEN_NATIVE_SUPERVISOR_TEST_ONLY" in extension
    for row in builder.PRODUCTION_DARWIN_LINK_ROSTER:
        if row["kind"] == "cpython-extension":
            assert row["init_symbol"] == "PyInit__plamen_native_supervisor"
            assert "testonly" not in row["artifact"]
            assert "-fblocks" in row["compile_flags"]
            assert row["flags"][-4:] == (
                "-framework", "CoreFoundation", "-framework", "Security",
            )
        if row["kind"] == "launchd-xpc-service":
            assert {
                "darwin_tool_custody", "darwin_tool_custody_header",
            } <= set(row["source_roles"])


def test_runtime_package_requires_managed_evm_driver_cutover_closure() -> None:
    builder = _load_builder()
    assert {
        "scripts/native_managed_evm_driver_preflight.py",
        "scripts/native_managed_evm_setup_effects.py",
        "scripts/posix_managed_evm_setup_transaction.py",
    } <= set(builder.RUNTIME_PACKAGE_MANIFEST_V2_REQUIRED_FILES)


def test_source_freeze_candidate_is_deterministic_exact_and_non_authorizing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    # This tests source-freeze serialization, not the availability of a
    # release projection in the developer's checkout. The production
    # projection is deliberately not published until all source owners stop.
    fixture_root = tmp_path / "source"
    for role, relative in builder.PRODUCTION_DARWIN_SOURCE_ROSTER:
        destination = fixture_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if role == "runtime_source_projection_manifest":
            destination.write_bytes(b'{"schema":"TEST_ONLY.source-member"}\n')
        else:
            shutil.copyfile(ROOT / relative, destination)
    monkeypatch.setattr(builder, "REPOSITORY_ROOT", fixture_root)
    first = builder.TEST_ONLY_render_production_source_freeze_candidate()
    second = builder.TEST_ONLY_render_production_source_freeze_candidate()

    assert first == second
    decoded = builder.TEST_ONLY_decode_production_source_freeze_manifest(first)
    assert decoded["schema"] == "plamen.native-production-source-freeze.v2"
    assert decoded["source_count"] == len(
        builder.PRODUCTION_DARWIN_SOURCE_ROSTER
    )
    assert [(row["role"], row["path"]) for row in decoded["sources"]] == list(
        builder.PRODUCTION_DARWIN_SOURCE_ROSTER
    )
    assert decoded["sources"][0]["role"] == "source_build_dispatch"
    assert {
        "darwin_tool_custody", "darwin_tool_custody_header",
    } <= {row["role"] for row in decoded["sources"]}

    tampered = json.loads(first)
    tampered["sources"][0]["sha256"] = "ff" * 32
    with pytest.raises(builder.BuildError, match="roster digest"):
        builder.TEST_ONLY_decode_production_source_freeze_manifest(
            _canonical(tampered)
        )
    pretty = json.dumps(decoded, indent=2).encode("ascii") + b"\n"
    with pytest.raises(builder.BuildError, match="bytes are not canonical"):
        builder.TEST_ONLY_decode_production_source_freeze_manifest(pretty)
    duplicate = first.replace(
        b'{"platform":', b'{"platform":"darwin-arm64","platform":', 1
    )
    with pytest.raises(builder.BuildError, match="strict canonical JSON"):
        builder.TEST_ONLY_decode_production_source_freeze_manifest(duplicate)

    report = builder.production_readiness()
    assert report["production_build_allowed"] is False
    assert report["authority"] == (
        "DIAGNOSTIC_ONLY_LOADED_PYTHON_NO_BUILD_AUTHORITY"
    )
    # Even a previously observed candidate cannot excuse a missing member.
    (fixture_root / "verification_policy/runtime_source_projection.v1.json").unlink()
    with pytest.raises(builder.BuildError, match="SOURCE_MISSING:runtime_source_projection_manifest"):
        builder.TEST_ONLY_render_production_source_freeze_candidate()


def _production_freeze_fixture(
    builder: ModuleType, root: Path, *, projection_valid: bool,
) -> None:
    validator_source = b'''\
import hashlib
def validate_manifest(raw, source_root_fd, *, require_frozen=True,
                      expected_manifest_sha256=None):
    if require_frozen is not True:
        raise ValueError("frozen authority required")
    if hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
        raise ValueError("manifest digest differs")
    if raw != b'{"schema":"fixture-projection","state":"FROZEN"}':
        raise ValueError("projection semantics differ")
    return {"schema":"plamen.runtime-source-projection.v1",
            "state":"FROZEN", "rows":[], "counts":{"total":0},
            "roster_sha256":"00" * 32, "source_commit":"11" * 20}
'''
    for role, relative in builder.PRODUCTION_DARWIN_SOURCE_ROSTER:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if role == "runtime_source_projection":
            destination.write_bytes(validator_source)
        elif role == "runtime_source_projection_manifest":
            destination.write_bytes(
                b'{"schema":"fixture-projection","state":"FROZEN"}'
                if projection_valid
                else b'{"schema":"decoy","state":"CANDIDATE"}'
            )
        else:
            shutil.copyfile(ROOT / relative, destination)


def test_exact_source_freeze_replays_runtime_projection_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    fixture_root = tmp_path / "source"
    _production_freeze_fixture(builder, fixture_root, projection_valid=True)
    freeze_path = (
        fixture_root / "native" / "darwin"
        / "native-production-source-freeze-v2.json"
    )
    monkeypatch.setattr(builder, "REPOSITORY_ROOT", fixture_root)
    monkeypatch.setattr(builder, "PRODUCTION_SOURCE_FREEZE_MANIFEST", freeze_path)
    freeze_path.write_bytes(
        builder.TEST_ONLY_render_production_source_freeze_candidate()
    )

    loaded = builder._load_exact_production_source_freeze()
    assert loaded["source_count"] == len(builder.PRODUCTION_DARWIN_SOURCE_ROSTER)
    report = builder.production_readiness()
    assert report["closure"]["source_freeze_manifest"]["status"] == (
        "OBSERVED_DIAGNOSTIC_ONLY"
    )
    assert not any(
        code.startswith((
            "SOURCE_MISSING:", "SOURCE_ALIASED:", "SOURCE_INVALID:",
            "SOURCE_HASH_", "SOURCE_FREEZE_",
        ))
        or code == "RUNTIME_SOURCE_PROJECTION_INVALID"
        for code in report["blockers"]
    )


def test_exact_source_freeze_rejects_semantically_invalid_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    fixture_root = tmp_path / "source"
    _production_freeze_fixture(builder, fixture_root, projection_valid=False)
    freeze_path = (
        fixture_root / "native" / "darwin"
        / "native-production-source-freeze-v2.json"
    )
    monkeypatch.setattr(builder, "REPOSITORY_ROOT", fixture_root)
    monkeypatch.setattr(builder, "PRODUCTION_SOURCE_FREEZE_MANIFEST", freeze_path)
    freeze_path.write_bytes(
        builder.TEST_ONLY_render_production_source_freeze_candidate()
    )

    with pytest.raises(builder.BuildError, match="projection semantics differ"):
        builder._load_exact_production_source_freeze()
    report = builder.production_readiness()
    assert "RUNTIME_SOURCE_PROJECTION_INVALID" in report["blockers"]


def test_source_install_handoff_detection_is_structural_not_a_self_marker() -> None:
    builder = _load_builder()
    dispatch = b"argv = ['--install-codex']\n"
    marker_only = b"CHECK = '_execute_native_source_install_transaction'\n"
    assert builder._source_install_handoff_present({
        "source_install_dispatch": dispatch,
        "source_build_dispatch": marker_only,
    }) is False
    structural = b"""
def _execute_native_source_install_transaction(readiness):
    raise RuntimeError
def install_codex_from_source():
    return _execute_native_source_install_transaction({})
"""
    assert builder._source_install_handoff_present({
        "source_install_dispatch": dispatch,
        "source_build_dispatch": structural,
    }) is True


def test_committed_codex_package_replay_uses_counts_rows_and_terminal_hashes(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    home = tmp_path / "account"
    codex = home / ".codex"
    plamen = home / ".plamen"
    codex.mkdir(parents=True)
    plamen.mkdir()
    anchor = codex / ".plamen-install.admission.lock"
    anchor.write_bytes(b"")

    def authority(path: Path) -> dict:
        observed = path.stat()
        raw = path.read_bytes()
        return {
            "kind": "file", "device": observed.st_dev,
            "inode": observed.st_ino, "mode": observed.st_mode,
            "links": observed.st_nlink, "size": len(raw),
            "attributes": (
                0 if observed.st_mode & 0o222 else 1
            ),
            "reparse_tag": 0,
            "sha256": hashlib.sha256(raw).hexdigest(), "name": path.name,
            "streams": [],
        }

    members = (
        ("plamen", "runtime.py", "runtime/runtime.py", b"runtime\n"),
        ("codex", "adapter.py", "adapter/adapter.py", b"adapter\n"),
    )
    rows = []
    journal = []
    manifest_rows = {"plamen": [], "codex": []}
    for index, (root_name, relative, source, raw) in enumerate(members):
        root = plamen if root_name == "plamen" else codex
        destination = root / relative
        destination.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        retained = authority(destination)
        row = {
            "source_path": source, "install_kind": "copied",
            "destination_root": root_name, "destination_path": relative,
            "destination_key": f"{root_name}/{relative}".casefold(),
            "size": len(raw), "sha256": digest,
            "destination": str(destination), "stage": str(destination),
            "terminal_authority": retained,
        }
        rows.append(row)
        journal.append({
            "index": index, "destination": str(destination),
            "sha256": digest, "terminal_authority": retained,
        })
        manifest_rows[root_name].append((
            source, f"{source}|{len(raw)}|{digest}\n".encode(),
        ))

    def fold(named):
        return hashlib.sha256(
            b"".join(raw for _name, raw in sorted(named))
        ).hexdigest()

    runtime_sha = fold(manifest_rows["plamen"])
    adapter_sha = fold(manifest_rows["codex"])
    combined_sha = fold(manifest_rows["plamen"] + manifest_rows["codex"])
    transaction_id = "12" * 16
    terminal_root = (
        codex / ".plamen-install-transactions" / transaction_id
        / "terminal-evidence"
    )
    terminal_root.mkdir(parents=True)
    inverse_sha = "cd" * 32
    rows_fold = hashlib.sha256(_canonical([
        [row["destination_root"], row["destination_path"], row["size"],
         row["sha256"]]
        for row in rows
    ])).hexdigest()
    journal_fold = hashlib.sha256(_canonical(journal)).hexdigest()
    terminal_prefix = {"event_count": 0}
    pending_suffix = []
    terminal_fold = hashlib.sha256(_canonical([
        terminal_prefix, pending_suffix,
    ])).hexdigest()
    payload_values = {
        "precommit.json": {
            "schema": "plamen.install.terminal.precommit.v1",
            "transaction_id": transaction_id,
            "writer_generation": "writer-1", "source_count": 2,
            "source_manifest_sha256": combined_sha,
            "inverse_sha256": inverse_sha, "prior_receipt_authority": None,
        },
        "transaction.json": {
            "schema": "plamen.install.terminal.transaction.v1",
            "transaction_id": transaction_id, "state": "COMMITTED",
            "row_count": 2, "rows_fold_sha256": rows_fold,
            "journal_fold_sha256": journal_fold,
        },
        "smoke.json": {
            "schema": "plamen.install.terminal.smoke.v1",
            "provider_invocations": 0, "result_count": 0, "results": [],
        },
        "recovery.json": {
            "schema": "plamen.install.terminal.recovery.v1",
            "outcome": "NOT_REQUIRED", "keeper_state": "BOUND",
            "recovery_command": ["python", "--recover"],
        },
        "broker.json": {
            "schema": "plamen.install.terminal.broker.v1",
            "event_count": 0, "event_fold_sha256": "ef" * 32,
        },
        "process.json": {
            "schema": "plamen.install.terminal.process.v1",
            "installer_pid": 1, "keeper_pid": 2, "smoke_pids": [],
            "provider_processes": 0,
        },
        "environment.json": {
            "schema": "plamen.install.terminal.environment.v1",
            "sanitized_environment_sha256": "01" * 32,
            "interpreter_sha256": "02" * 32, "script_sha256": "03" * 32,
        },
        "sentinel.json": {
            "schema": "plamen.install.terminal.sentinel.v1",
            "terminal_prefix": terminal_prefix,
            "pending_suffix": pending_suffix,
            "terminal_fold_sha256": terminal_fold,
        },
    }
    for name, value in payload_values.items():
        (terminal_root / name).write_bytes(_canonical(value))
    payload_rows = []
    for ordinal, name in enumerate(
        builder.CODEX_TERMINAL_EVIDENCE_FILENAMES[:8]
    ):
        path = terminal_root / name
        raw = path.read_bytes()
        payload_rows.append({
            "ordinal": ordinal, "name": name, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "terminal_authority": authority(path),
        })
    manifest = {
        "schema": "plamen.install.terminal.manifest.v1",
        "transaction_id": transaction_id, "payload_count": 8,
        "payloads": payload_rows,
    }
    manifest_raw = _canonical(manifest)
    (terminal_root / "manifest.json").write_bytes(manifest_raw)
    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    seal = {
        "schema": "plamen.install.terminal.folder_seal.v1",
        "transaction_id": transaction_id,
        "file_count": len(builder.CODEX_TERMINAL_EVIDENCE_FILENAMES),
        "filenames": list(builder.CODEX_TERMINAL_EVIDENCE_FILENAMES),
        "folder_authority": {}, "manifest_sha256": manifest_sha,
        "reserved_terminal_authority": {}, "extras": 0,
    }
    seal_raw = _canonical(seal)
    (terminal_root / "folder-seal.json").write_bytes(seal_raw)
    seal_sha = hashlib.sha256(seal_raw).hexdigest()
    pointer = {
        "schema": "plamen.install.terminal.pointer.v1",
        "writer_generation": "writer-1", "folder": str(terminal_root),
        "folder_authority": {}, "payload_count": 8,
        "file_count": len(builder.CODEX_TERMINAL_EVIDENCE_FILENAMES),
        "manifest_sha256": manifest_sha, "folder_seal_sha256": seal_sha,
        "reserved_terminal_authority": {},
    }
    anchor_stat = anchor.stat()
    receipt = {
        key: None for key in builder.CODEX_COMMITTED_RECEIPT_FIELDS
    }
    receipt.update({
        "schema": "plamen.codex_install.v2", "transaction_id": transaction_id,
        "state": "COMMITTED", "source_count": 2, "runtime_count": 1,
        "adapter_count": 1, "source_manifest_sha256": combined_sha,
        "runtime_manifest_sha256": runtime_sha,
        "adapter_manifest_sha256": adapter_sha,
        "source_root": str(tmp_path / "source"), "plamen_root": str(plamen),
        "codex_root": str(codex),
        "lock_identity": [anchor_stat.st_dev, anchor_stat.st_ino],
        "owner": {
            "pid": 1, "executable": "/usr/bin/python3",
            "executable_sha256": "04" * 32, "principal": "test",
            "started_ns": 1,
        },
        "transaction_root": str(terminal_root.parent),
        "stage_root": str(terminal_root.parent / "stage"),
        "backup_root": str(terminal_root.parent / "backup"),
        "inverse_path": str(terminal_root.parent / "inverse.json"),
        "journal_path": str(terminal_root.parent / "journal.json"),
        "created_junction": False, "last_transition_ns": 1,
        "inverse_sha256": inverse_sha, "junction_identity": None,
        "rows": rows, "journal": journal,
        "terminal_verification": {
            "verified_count": 2,
            "verified_manifest_sha256": combined_sha,
            "completed_ns": 1,
        },
        "terminal_evidence": pointer,
    })
    receipt_raw = _canonical(receipt)
    terminal_last = {
        "schema": "plamen.install.terminal.last.v1", "outcome": "COMMITTED",
        "transaction_id": transaction_id, "writer_generation": "writer-1",
        "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "manifest_sha256": manifest_sha, "folder_seal_sha256": seal_sha,
        "postclose_required": True, "keeper_disposition": "RELEASE_UNUSED",
        "terminal_fold_sha256": terminal_fold, "actual_suffix": [],
    }
    (terminal_root / "terminal-last.json").write_bytes(
        _canonical(terminal_last)
    )
    (codex / ".plamen-codex-install.json").write_bytes(receipt_raw)

    replay = builder.TEST_ONLY_validate_codex_committed_package_v2(home)
    assert replay["status"] == (
        "EXACT_PACKAGE_RECEIPT_REPLAYED_DIAGNOSTIC_ONLY"
    )
    assert replay["source_count"] == 2
    (plamen / "runtime.py").write_bytes(b"tampered\n")
    with pytest.raises(builder.BuildError, match="member.*differs"):
        builder.TEST_ONLY_validate_codex_committed_package_v2(home)


def test_committed_package_authority_requires_the_exact_posix_shape(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    member = tmp_path / "member"
    member.write_bytes(b"exact\n")
    observed = member.stat()
    digest = hashlib.sha256(member.read_bytes()).hexdigest()
    authority = {
        "kind": "file", "device": observed.st_dev,
        "inode": observed.st_ino, "mode": observed.st_mode,
        "links": observed.st_nlink, "size": observed.st_size,
        "attributes": 0 if observed.st_mode & 0o222 else 1,
        "reparse_tag": 0, "name": member.name,
        "sha256": digest, "streams": [],
    }
    assert builder._receipt_authority_matches(
        authority, observed, digest, member.name,
    )
    partial = dict(authority)
    del partial["streams"]
    assert not builder._receipt_authority_matches(
        partial, observed, digest, member.name,
    )
    extra = dict(authority, ambient=True)
    assert not builder._receipt_authority_matches(
        extra, observed, digest, member.name,
    )


def test_darwin_signing_contract_is_post_sign_and_identity_exact() -> None:
    builder = _load_builder()
    contract = builder.production_readiness()["closure"][
        "generation_contract"
    ]["code_signature_contract"]

    assert contract["identifiers"] == {
        "launcher": "com.plamen.audit.launcher.v2",
        "service": "com.plamen.audit.broker.v2",
        "extension": "com.plamen.audit.native-supervisor.v2",
            "installer": "com.plamen.audit.installer.v2",
            "source_bootstrap": "com.plamen.audit.source-bootstrap.v1",
        }
    assert contract["team_identifier"] == ""
    assert contract["sign_command_template"] == [
        "/usr/bin/codesign", "--force", "--sign", "-",
        "--identifier", "{exact_identifier}", "--timestamp=none",
        "{retained_staged_artifact}",
    ]
    ordering = contract["ordering"]
    assert ordering.index("deterministic-ad-hoc-sign") < ordering.index(
        "final SHA256"
    )
    assert set(contract["receipt_binds"]) == {
        "post_sign_sha256", "identifier", "empty_team_identifier",
        "cdhash", "mode", "vnode",
    }


def test_native_supervisor_schema_validation_is_semantic_and_fail_closed() -> None:
    builder = _load_builder()
    source = ROOT / "native" / "darwin" / "native-supervisor-schema-v2.json"
    document = json.loads(source.read_bytes())
    document["service_bootstrap"]["service_envelope"]["maximum_fds"] = 15
    valid = json.dumps(document, indent=2, sort_keys=True).encode("ascii") + b"\n"
    evidence = builder.TEST_ONLY_validate_native_supervisor_schema_v2(valid)
    assert evidence["schema"] == "plamen.native-supervisor.schema.v2"
    assert evidence["status"] == "EXACT_ABI_VALIDATED_DIAGNOSTIC_ONLY"
    assert evidence["sha256"] == hashlib.sha256(valid).hexdigest()

    stale = json.loads(valid)
    stale["service_bootstrap"]["service_envelope"]["maximum_fds"] = 2
    with pytest.raises(builder.BuildError, match="service envelope ABI"):
        builder.TEST_ONLY_validate_native_supervisor_schema_v2(
            _canonical(stale)
        )
    duplicate = valid.replace(b'{\n  "authority_surface":', (
        b'{\n  "schema":"plamen.native-supervisor.schema.v2",'
        b'\n  "authority_surface":'
    ), 1)
    with pytest.raises(builder.BuildError, match="strict canonical JSON"):
        builder.TEST_ONLY_validate_native_supervisor_schema_v2(duplicate)


def test_receipt_v2_serializer_is_exact_and_rejects_noncanonical_inputs() -> None:
    builder = _load_builder()
    inputs = _receipt_inputs(builder)
    receipt = builder.TEST_ONLY_encode_darwin_install_receipt_v2(**inputs)

    assert len(receipt) == 16384
    assert receipt[:8] == b"PLMINS2\0"
    assert struct.unpack_from(">HHI", receipt, 8) == (2, 256, 16384)
    assert struct.unpack_from(">HHH", receipt, 112) == (10, 3, 12)
    checkpoint_view = bytearray(receipt[:16352])
    checkpoint = bytes(checkpoint_view[80:112])
    checkpoint_view[80:112] = bytes(32)
    assert checkpoint == hashlib.sha256(
        b"PLAMEN-INSTALL-PRECOMMIT-V2\0" + checkpoint_view
    ).digest()
    assert receipt[16352:] == hashlib.sha256(receipt[:16352]).digest()
    assert receipt[192:256] == bytes(64)
    assert receipt[2436:2496] == bytes(60)
    assert receipt[2496 + 624:2496 + 896] == bytes(272)
    assert receipt[12548:12608] == bytes(60)
    assert receipt[12608:16352] == bytes(3744)

    invalid = _receipt_inputs(builder)
    invalid["generation_path"] = "/Users/test/../escape"
    with pytest.raises(builder.BuildError, match="normalized path"):
        builder.TEST_ONLY_encode_darwin_install_receipt_v2(**invalid)
    invalid = _receipt_inputs(builder)
    invalid["members"][0]["team_identifier"] = "FORGEDTEAM"
    with pytest.raises(builder.BuildError, match="team must be empty"):
        builder.TEST_ONLY_encode_darwin_install_receipt_v2(**invalid)
    invalid = _receipt_inputs(builder)
    invalid["members"][3]["signing_identifier"] = "forged.unsigned"
    with pytest.raises(builder.BuildError, match="unsigned receipt member"):
        builder.TEST_ONLY_encode_darwin_install_receipt_v2(**invalid)
    invalid = _receipt_inputs(builder)
    invalid["broker_launchd_plist"]["path"] = (
        "/Users/test/Library/LaunchAgents/com.plamen.audit.broker.v2.plist"
    )
    with pytest.raises(builder.BuildError, match="descriptor-ancestry bound"):
        builder.TEST_ONLY_encode_darwin_install_receipt_v2(**invalid)
    invalid = _receipt_inputs(builder)
    invalid["custody_launchd_plist"]["path"] = (
        "/Users/test/Library/LaunchAgents/"
        "com.plamen.audit.process-custody.v2.plist"
    )
    with pytest.raises(builder.BuildError, match="descriptor-ancestry bound"):
        builder.TEST_ONLY_encode_darwin_install_receipt_v2(**invalid)


def test_runtime_package_manifest_v2_is_deterministic_and_exact(
    runtime_tree_factory,
) -> None:
    builder = _load_builder()
    first_root = runtime_tree_factory("runtime-first")
    second_root = runtime_tree_factory("runtime-second")
    bindings = _runtime_bindings(builder)

    first = builder.TEST_ONLY_build_runtime_package_manifest_v2(
        first_root, bindings=bindings
    )
    second = builder.TEST_ONLY_build_runtime_package_manifest_v2(
        second_root, bindings=bindings
    )
    assert first == second
    assert first[:8] == b"PLMRPM2\0"
    assert first[256:264] == b"PLMRPB2\0"
    assert first[-32:] == hashlib.sha256(first[:-32]).digest()

    decoded = builder.TEST_ONLY_decode_runtime_package_manifest_v2(first)
    assert decoded["schema"] == "plamen.runtime-package-manifest.v2"
    assert decoded["root"] == "lib/plamen/runtime"
    assert decoded["entry_count"] == 17
    assert decoded["directory_count"] == 4
    assert decoded["file_count"] == 13
    assert decoded["total_file_bytes"] == sum(
        row["size"] for row in decoded["rows"] if row["kind"] == 2
    )
    assert [row["path"] for row in decoded["rows"]] == sorted(
        row["path"] for row in decoded["rows"]
    )
    assert decoded["external_bindings"] == bindings
    assert decoded["manifest_sha256"] == hashlib.sha256(first).hexdigest()
    validated = builder.TEST_ONLY_validate_runtime_package_manifest_v2(
        first_root, first
    )
    assert validated == decoded


def test_darwin_codex_profile_v2_is_exact_and_tamper_evident() -> None:
    builder = _load_builder()
    values = {
        "provider_sha256": "11" * 32,
        "backend_sha256": "22" * 32,
        "provider_cdhash": "33" * 20,
        "backend_cdhash": "44" * 20,
        "provider_identifier": "com.apple.container.cli",
        "provider_team": "UPBK2H6LZM",
        "provider_version": (
            "container CLI version 1.3.1 (build: release, commit: a9a62e2)"
        ),
        "backend_identifier": "codex",
        "backend_team": "2DC432GLL2",
        "backend_version": "codex-cli 9.8.7",
        "backend_release": "9.8.7-aarch64-apple-darwin",
        "backend_selector": "codex",
        "provider_selector": "apple-container-v2",
        "acquisition_policy_sha256": "55" * 32,
    }
    profile = builder.encode_darwin_codex_profile_v2(**values)
    assert len(profile) == 2048
    assert profile[:8] == b"PLMBPF2\0"
    assert profile[2016:] == hashlib.sha256(profile[:2016]).digest()
    assert builder.decode_darwin_codex_profile_v2(profile) == values
    assert "profiles/codex-v2.bin" in (
        builder.RUNTIME_PACKAGE_MANIFEST_V2_REQUIRED_FILES
    )
    tampered = bytearray(profile)
    tampered[32] ^= 1
    with pytest.raises(builder.BuildError, match="trailer digest"):
        builder.decode_darwin_codex_profile_v2(bytes(tampered))
    forged = dict(values)
    forged["backend_team"] = "FORGEDTEAM"
    with pytest.raises(builder.BuildError, match="fixed identity"):
        builder.encode_darwin_codex_profile_v2(**forged)
    wrong_release = dict(values)
    wrong_release["backend_version"] = "codex-cli 9.8.6"
    with pytest.raises(builder.BuildError, match="resolved release"):
        builder.encode_darwin_codex_profile_v2(**wrong_release)


def test_production_builder_has_no_stale_fixed_backend_release_path() -> None:
    builder = _load_builder()
    source = BUILDER.read_text(encoding="utf-8")
    for stale in (
        "0.152.0", "2.1.252", "native_backend_acquisition.v1",
        "materialize_darwin_backend_v1", "observe_darwin_backend_profile_v2",
    ):
        assert stale not in source
    callbacks = builder._production_native_builder_callbacks()
    assert callable(callbacks["bind_retained_backend_generation"])
    assert "observe_codex_profile" not in callbacks
    assert "observe_claude_profile" not in callbacks
    assert builder.NATIVE_BACKEND_ACQUISITION_POLICY_V2.name == (
        "native_backend_acquisition.v2.json"
    )


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin Clang VFS")
def test_retained_clang_vfs_rejects_named_source_and_overlay_substitution(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    header = tmp_path / "retained.h"
    source = tmp_path / "retained.c"
    overlay_path = tmp_path / "overlay.json"
    output = tmp_path / "retained.o"
    header.write_bytes(b"#define RETAINED_VALUE 41\n")
    source.write_bytes(
        b'#include "retained.h"\nint retained_value = RETAINED_VALUE;\n'
    )
    descriptors: list[int] = []
    try:
        header_fd = os.open(header, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        descriptors.extend((header_fd, source_fd))
        overlay_path.write_bytes(builder._clang_retained_vfs_overlay({
            header: header_fd, source: source_fd,
        }))
        overlay_fd = os.open(
            overlay_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        output_fd = os.open(
            output,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        descriptors.extend((overlay_fd, output_fd))

        # Replace every named input after descriptor admission.  Clang must
        # still compile the retained vnodes named only by the inherited overlay.
        for path in (header, source, overlay_path):
            replacement = path.with_name(path.name + ".replacement")
            replacement.write_bytes(b"#error substituted named compiler input\n")
            os.replace(replacement, path)
        completed = subprocess.run(
            [
                "/usr/bin/clang", "-ivfsoverlay", f"/dev/fd/{overlay_fd}",
                "-I" + str(tmp_path), "-c", str(source),
                "-o", f"/dev/fd/{output_fd}",
            ],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env={"LANG": "C", "LC_ALL": "C"},
            pass_fds=tuple(descriptors), close_fds=True, timeout=30,
        )
        assert completed.returncode == 0, completed.stdout.decode(
            "utf-8", "replace"
        )
        assert os.fstat(output_fd).st_size > 0
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_release_workspace_path_must_rejoin_retained_directory(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    descriptor = os.open(
        workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        builder._require_path_descriptor_rejoin(
            workspace, descriptor, "fixture workspace",
        )
        moved = tmp_path / "retained-workspace"
        workspace.rename(moved)
        workspace.mkdir(mode=0o700)
        with pytest.raises(builder.BuildError, match="pathname authority differs"):
            builder._require_path_descriptor_rejoin(
                workspace, descriptor, "fixture workspace",
            )
    finally:
        os.close(descriptor)


def test_code_identity_rejects_path_substitution_around_codesign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    executable = tmp_path / "signed-executable"
    executable.write_bytes(b"retained-vnode")
    executable.chmod(0o700)
    descriptor = os.open(
        executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    calls = 0

    def observe(_argv, *, label):
        nonlocal calls
        calls += 1
        if calls == 1:
            replacement = tmp_path / "replacement"
            replacement.write_bytes(b"substituted-vnode")
            replacement.chmod(0o700)
            os.replace(replacement, executable)
            return b""
        raise AssertionError("identity display must not run after substitution")

    monkeypatch.setattr(builder, "_run_profile_observation", observe)
    try:
        with pytest.raises(builder.BuildError, match="pathname authority differs"):
            builder._darwin_ad_hoc_code_identity(
                executable, "fixture executable", retained_fd=descriptor,
            )
    finally:
        os.close(descriptor)


def test_darwin_claude_profile_v2_is_exact_and_selector_bound() -> None:
    builder = _load_builder()
    values = {
        "provider_sha256": "11" * 32,
        "backend_sha256": "22" * 32,
        "provider_cdhash": "33" * 20,
        "backend_cdhash": "44" * 20,
        "provider_identifier": "com.apple.container.cli",
        "provider_team": "UPBK2H6LZM",
        "provider_version": (
            "container CLI version 1.3.1 (build: release, commit: a9a62e2)"
        ),
        "backend_identifier": "com.anthropic.claude-code",
        "backend_team": "Q6L2SF6YDW",
        "backend_version": "8.7.6 (Claude Code)",
        "backend_release": "8.7.6",
        "backend_selector": "claude",
        "provider_selector": "apple-container-v2",
        "acquisition_policy_sha256": "55" * 32,
    }
    profile = builder.encode_darwin_claude_profile_v2(**values)
    assert builder.decode_darwin_claude_profile_v2(profile) == values
    assert builder.decode_darwin_backend_profile_v2(profile) == values
    assert "profiles/claude-v2.bin" in (
        builder.RUNTIME_PACKAGE_MANIFEST_V2_REQUIRED_FILES
    )
    with pytest.raises(builder.BuildError, match="Codex profile selector"):
        builder.decode_darwin_codex_profile_v2(profile)
    wrong_team = dict(values, backend_team="FORGEDTEAM")
    with pytest.raises(builder.BuildError, match="fixed identity"):
        builder.encode_darwin_claude_profile_v2(**wrong_team)


def test_darwin_backend_profiles_stage_into_runtime_manifest_authority(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    runtime = tmp_path / "runtime-profile-stage"
    runtime.mkdir(mode=0o700)
    common = {
        "provider_sha256": "11" * 32,
        "backend_sha256": "22" * 32,
        "provider_cdhash": "33" * 20,
        "backend_cdhash": "44" * 20,
        "provider_identifier": "com.apple.container.cli",
        "provider_team": "UPBK2H6LZM",
        "provider_version": (
            "container CLI version 1.3.1 (build: release, commit: a9a62e2)"
        ),
        "provider_selector": "apple-container-v2",
        "acquisition_policy_sha256": "55" * 32,
    }
    codex = builder.encode_darwin_codex_profile_v2(**common, **{
        "backend_identifier": "codex", "backend_team": "2DC432GLL2",
        "backend_version": "codex-cli 9.8.7",
        "backend_release": "9.8.7-aarch64-apple-darwin",
        "backend_selector": "codex",
    })
    claude = builder.encode_darwin_claude_profile_v2(**common, **{
        "backend_identifier": "com.anthropic.claude-code",
        "backend_team": "Q6L2SF6YDW",
        "backend_version": "8.7.6 (Claude Code)",
        "backend_release": "8.7.6", "backend_selector": "claude",
    })
    result = builder.stage_darwin_backend_profiles_v2(runtime, codex, claude)
    assert result["acquisition_policy_sha256"] == (
        "55" * 32
    )
    for selector, raw in (("codex", codex), ("claude", claude)):
        path = runtime / "profiles" / f"{selector}-v2.bin"
        assert path.read_bytes() == raw
        assert path.stat().st_mode & 0o777 == 0o400
        assert result["profiles"][selector]["sha256"] == hashlib.sha256(
            raw
        ).hexdigest()
    assert (runtime / "profiles").stat().st_mode & 0o777 == 0o500


def test_native_runtime_manifest_v2_matches_python_reference_exactly(
    runtime_tree_factory, tmp_path: Path,
) -> None:
    builder = _load_builder()
    root = runtime_tree_factory("runtime-native")
    expected = builder.TEST_ONLY_build_runtime_package_manifest_v2(
        root, bindings=_runtime_bindings(builder)
    )
    helper_source = tmp_path / "runtime_manifest_helper.c"
    helper_binary = tmp_path / "runtime_manifest_helper"
    output = tmp_path / "runtime-package-manifest-v2.bin"
    helper_source.write_text(
        r'''#define _DARWIN_C_SOURCE 1
#include "plamen_native_builder_v2.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    static const char image[] =
        "registry.example/plamen/audit@sha256:"
        "0000000000000000000000000000000000000000000000000000000000000002";
    static const char init[] = "/usr/local/libexec/plamen-guest";
    static const char *const generation_paths[] = {
        "bin/plamen-native-launcher",
        "lib/plamen/plamen-audit-broker-v2",
        "lib/plamen/_plamen_native_supervisor.cpython-312-darwin.so",
        "share/plamen/plamen_broker_v2.h",
        "share/plamen/native-supervisor-schema-v2.json",
        "bin/python3.12",
            "lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
            "share/plamen/runtime-package-manifest-v2.bin",
            "libexec/plamen-native-installer-v2"
            , "libexec/plamen-native-source-bootstrap-coordinator-v1"
        };
        static const uint32_t generation_modes[] = {
            0500U, 0500U, 0400U, 0400U, 0400U, 0500U, 0400U, 0400U,
            0500U, 0500U
        };
        static const uint8_t expected_generation_id[32] = {
            0x0e, 0x25, 0x29, 0x1c, 0xdc, 0xf2, 0x68, 0x51,
            0x21, 0x0c, 0x1b, 0xb9, 0xd1, 0xc6, 0x84, 0x32,
            0xef, 0x73, 0x2c, 0xb9, 0xa8, 0xc0, 0x76, 0xef,
            0xa8, 0x8f, 0xc5, 0xd4, 0xdc, 0x0c, 0x2a, 0x9a
        };
        static const uint8_t expected_roster_sha256[32] = {
            0xf2, 0xbf, 0x70, 0xf5, 0xc6, 0x00, 0x34, 0xa5,
            0x28, 0x13, 0x31, 0xc8, 0x91, 0x05, 0xde, 0x6a,
            0x7f, 0x76, 0xdf, 0xec, 0xb0, 0x68, 0xed, 0xd2,
            0x34, 0x9b, 0xfc, 0x11, 0x87, 0x8b, 0x08, 0x69
    };
    struct plamen_runtime_package_bindings_v2 bindings;
    struct plamen_runtime_package_manifest_result_v2 rendered;
    struct plamen_runtime_package_manifest_result_v2 decoded;
    struct plamen_runtime_package_manifest_result_v2 validated;
        struct plamen_intrinsic_generation_member_v2 generation_members[10];
    uint8_t generation_id[32];
    uint8_t roster_sha256[32];
    int root_fd;
    int output_fd;
    unsigned int index;
    if (argc != 3) return 100;
    root_fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) return 101;
    output_fd = open(argv[2], O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (output_fd < 0) return 102;
    memset(&bindings, 0, sizeof(bindings));
    bindings.target_arch = PLAMEN_RUNTIME_PACKAGE_TARGET_ARCH_ARM64_V2;
    bindings.oci_image_reference = image;
    bindings.oci_image_reference_size = strlen(image);
    bindings.oci_init_reference = init;
    bindings.oci_init_reference_size = strlen(init);
    for (index = 0;
            index < PLAMEN_RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_COUNT; ++index)
        bindings.digests[index][31] = (uint8_t)(index + 2U);
    if (plamen_runtime_package_manifest_render_v2(root_fd, &bindings,
            output_fd, getuid(), &rendered) != 0) return 103;
    if (plamen_runtime_package_manifest_revalidate_v2(root_fd, output_fd,
            getuid(), &validated) != 0) return 104;
    {
        uint8_t *bytes;
        struct stat identity;
        ssize_t amount;
        if (fstat(output_fd, &identity) != 0 || identity.st_size <= 0) return 105;
        bytes = (uint8_t *)malloc((size_t)identity.st_size);
        if (bytes == NULL) return 106;
        amount = pread(output_fd, bytes, (size_t)identity.st_size, 0);
        if (amount != identity.st_size) return 107;
        if (plamen_runtime_package_manifest_decode_exact_v2(bytes,
                (size_t)identity.st_size, &decoded) != 0) return 108;
        free(bytes);
    }
    if (memcmp(&rendered, &decoded, sizeof(rendered)) != 0
            || memcmp(&rendered, &validated, sizeof(rendered)) != 0) return 109;
    memset(generation_members, 0, sizeof(generation_members));
        for (index = 0; index < 10U; ++index) {
        generation_members[index].role = (uint16_t)(index + 1U);
        generation_members[index].relative_path = generation_paths[index];
        generation_members[index].relative_path_size = strlen(generation_paths[index]);
        generation_members[index].mode = generation_modes[index];
        generation_members[index].size = 100U + index;
        generation_members[index].sha256[31] = (uint8_t)(index + 1U);
    }
    if (plamen_intrinsic_generation_id_and_roster_v2(generation_members,
            generation_id, roster_sha256) != 0) return 111;
    if (memcmp(generation_id, expected_generation_id, 32U) != 0) return 112;
    if (memcmp(roster_sha256, expected_roster_sha256, 32U) != 0) return 113;
    if (close(output_fd) != 0 || close(root_fd) != 0) return 110;
    return 0;
}
''',
        encoding="ascii",
    )
    compiler = Path("/usr/bin/clang")
    assert compiler.is_file()
    subprocess.run(
        [
            str(compiler), "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(NATIVE_BUILDER_HEADER.parent),
            str(NATIVE_BUILDER_SOURCE), str(helper_source),
            "-o", str(helper_binary),
        ],
        check=True,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        capture_output=True,
    )
    subprocess.run(
        [str(helper_binary), str(root), str(output)],
        check=True,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        capture_output=True,
    )
    try:
        assert output.read_bytes() == expected
    finally:
        output.chmod(0o600)


def test_runtime_package_manifest_v2_binds_external_runtime_authorities(
    runtime_tree_factory,
) -> None:
    builder = _load_builder()
    root = runtime_tree_factory("runtime-bindings")
    bindings = _runtime_bindings(builder, seed=30)
    manifest = builder.TEST_ONLY_build_runtime_package_manifest_v2(
        root, bindings=bindings
    )
    decoded = builder.TEST_ONLY_decode_runtime_package_manifest_v2(manifest)
    assert list(builder.RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS) == [
        "oci_index_digest",
        "image_manifest_digest",
        "oci_config_digest",
        "image_closure_sha256",
        "apple_container_configuration_sha256",
        "seccomp_profile_sha256",
        "baked_toolchain_closure_sha256",
        "oci_lock_sha256",
        "materialization_receipt_sha256",
        "rootfs_archive_sha256",
        "rootfs_diff_id_sha256",
        "closure_census_sha256",
        "sbom_sha256",
        "provenance_sha256",
    ]
    assert decoded["external_bindings"] == bindings
    assert manifest[288:320] == builder.RUNTIME_PACKAGE_MANIFEST_V2_FIELD_ORDER_KAT
    assert manifest[256 + 512:256 + 1024].rstrip(b"\0") == (
        bindings["oci_image_reference"].encode("utf-8")
    )
    assert manifest[256 + 1024:256 + 1536].rstrip(b"\0") == (
        b"/usr/local/libexec/plamen-guest"
    )
    contract = builder.production_readiness()["closure"][
        "generation_contract"
    ]["runtime_package_manifest_v2"]
    assert contract["external_binding_size"] == 2048
    assert contract["field_order_kat_sha256"] == (
        builder.RUNTIME_PACKAGE_MANIFEST_V2_FIELD_ORDER_KAT.hex()
    )
    assert contract["runtime_layout_request_value"] == (
        "SHA256_FULL_MANIFEST_BYTES"
    )
    assert contract["manifest_in_runtime_census"] is False


@pytest.mark.parametrize(
    ("defect", "message"),
    [
        ("missing-entrypoint", "required entrypoints"),
        ("missing-profile", "required entrypoints"),
        ("symlink", "symlink or special file"),
        ("hardlink", "link count"),
        ("file-mode", "file mode"),
        ("root-mode", "root mode"),
    ],
)
def test_runtime_package_manifest_v2_rejects_nonexact_trees(
    runtime_tree_factory, defect: str, message: str,
) -> None:
    builder = _load_builder()
    root = runtime_tree_factory(f"runtime-{defect}", defect=defect)
    with pytest.raises(builder.BuildError, match=message):
        builder.TEST_ONLY_build_runtime_package_manifest_v2(
            root, bindings=_runtime_bindings(builder)
        )


def test_runtime_package_manifest_v2_detects_tree_and_binary_tamper(
    runtime_tree_factory,
) -> None:
    builder = _load_builder()
    root = runtime_tree_factory("runtime-tamper")
    manifest = builder.TEST_ONLY_build_runtime_package_manifest_v2(
        root, bindings=_runtime_bindings(builder)
    )

    file_path = root / "plamen_runtime" / "run.py"
    file_path.chmod(0o600)
    file_path.write_bytes(b"def main():\n    return 99\n")
    file_path.chmod(0o400)
    with pytest.raises(builder.BuildError, match="differs from its exact manifest"):
        builder.TEST_ONLY_validate_runtime_package_manifest_v2(root, manifest)

    trailer_tamper = bytearray(manifest)
    trailer_tamper[-1] ^= 1
    with pytest.raises(builder.BuildError, match="trailer digest"):
        builder.TEST_ONLY_decode_runtime_package_manifest_v2(
            bytes(trailer_tamper)
        )

    zero_digest = bytearray(manifest)
    zero_digest[256 + 64:256 + 96] = bytes(32)
    zero_digest[-32:] = hashlib.sha256(zero_digest[:-32]).digest()
    with pytest.raises(builder.BuildError, match="zero digest"):
        builder.TEST_ONLY_decode_runtime_package_manifest_v2(bytes(zero_digest))

    padded = bytearray(manifest)
    padded[256 + 1536] = 1
    padded[-32:] = hashlib.sha256(padded[:-32]).digest()
    with pytest.raises(builder.BuildError, match="reserved bytes"):
        builder.TEST_ONLY_decode_runtime_package_manifest_v2(bytes(padded))


def test_runtime_package_manifest_v2_rejects_ambient_or_unbound_inputs(
    runtime_tree_factory,
) -> None:
    builder = _load_builder()
    root = runtime_tree_factory("runtime-inputs")
    base = _runtime_bindings(builder)

    missing = dict(base)
    del missing["seccomp_profile_sha256"]
    with pytest.raises(builder.BuildError, match="fields are not exact"):
        builder.TEST_ONLY_build_runtime_package_manifest_v2(
            root, bindings=missing
        )
    zero = dict(base)
    zero["oci_lock_sha256"] = "0" * 64
    with pytest.raises(builder.BuildError, match="zero digest"):
        builder.TEST_ONLY_build_runtime_package_manifest_v2(root, bindings=zero)
    floating = dict(base)
    floating["oci_image_reference"] = "registry.example/plamen/audit:latest"
    with pytest.raises(builder.BuildError, match="digest-selected"):
        builder.TEST_ONLY_build_runtime_package_manifest_v2(
            root, bindings=floating
        )
    ambient_init = dict(base)
    ambient_init["oci_init_reference"] = "/opt/plamen/scripts/plamen_driver.py"
    with pytest.raises(builder.BuildError, match="frozen bootstrap"):
        builder.TEST_ONLY_build_runtime_package_manifest_v2(
            root, bindings=ambient_init
        )


def test_receipt_v2_round_trips_through_native_parser_and_rejects_tamper(
    tmp_path: Path,
) -> None:
    if sys.platform != "darwin":
        pytest.skip("Darwin receipt parser")
    builder = _load_builder()
    inputs = _receipt_inputs(builder)
    generation = tmp_path / "generations" / "staging"
    generation.mkdir(parents=True)
    for index, member in enumerate(inputs["members"]):
        path = generation / member["relative_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"member-{index}\n".encode("ascii"))
        path.chmod(member["mode"])
        identity = path.stat()
        member.update({
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": identity.st_size,
            "device": identity.st_dev,
            "inode": identity.st_ino,
            "uid": identity.st_uid,
            "gid": identity.st_gid,
        })
    generation_id, _preimage = builder.production_intrinsic_generation_id([
        {
            "role": member["role"],
            "relative_path": member["relative_path"],
            "sha256": member["sha256"],
            "size": member["size"],
            "mode": member["mode"],
        }
        for member in inputs["members"]
    ])
    final_generation = generation.parent / generation_id
    generation.rename(final_generation)
    generation = final_generation
    plist = (
        generation / "Library" / "LaunchAgents"
        / "com.plamen.audit.broker.v2.plist"
    )
    plist.parent.mkdir(parents=True)
    plist.write_bytes(b"<plist/>\n")
    plist.chmod(0o400)
    plist_identity = plist.stat()
    custody_plist = (
        generation / "Library" / "LaunchAgents"
        / "com.plamen.audit.process-custody.v2.plist"
    )
    custody_plist.write_bytes(b"<plist><key>custody</key></plist>\n")
    custody_plist.chmod(0o400)
    custody_plist_identity = custody_plist.stat()
    inputs["generation_path"] = str(generation)
    inputs["broker_launchd_plist"].update({
        "path": str(plist),
        "sha256": hashlib.sha256(plist.read_bytes()).hexdigest(),
        "size": plist_identity.st_size,
        "device": plist_identity.st_dev,
        "inode": plist_identity.st_ino,
        "uid": plist_identity.st_uid,
        "gid": plist_identity.st_gid,
    })
    inputs["custody_launchd_plist"].update({
        "path": str(custody_plist),
        "sha256": hashlib.sha256(custody_plist.read_bytes()).hexdigest(),
        "size": custody_plist_identity.st_size,
        "device": custody_plist_identity.st_dev,
        "inode": custody_plist_identity.st_ino,
        "uid": custody_plist_identity.st_uid,
        "gid": custody_plist_identity.st_gid,
    })
    receipt = builder.TEST_ONLY_encode_darwin_install_receipt_v2(**inputs)
    receipt_path = tmp_path / "native-install-receipt-v2.bin"
    receipt_path.write_bytes(receipt)
    helper_source = tmp_path / "receipt_probe.c"
    helper_source.write_text(
        r'''#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "plamen_broker_v2_install_receipt.h"
int main(int argc, char **argv) {
    unsigned char bytes[PLAMEN_INSTALL_RECEIPT_SIZE];
    struct plamen_install_receipt receipt;
    FILE *stream;
    if (argc != 3 || (stream = fopen(argv[2], "rb")) == NULL) return 64;
    if (fread(bytes, 1, sizeof(bytes), stream) != sizeof(bytes)
            || fgetc(stream) != EOF || fclose(stream) != 0) return 65;
    int accepted = plamen_install_receipt_decode_exact(
        bytes, sizeof(bytes), &receipt) == 0;
    if (strcmp(argv[1], "accept") == 0) {
        int generation_fd, member_fd;
        unsigned int index;
        if (!accepted || receipt.python_major != 3 || receipt.python_minor != 12
                || receipt.python_micro != 10
                || strcmp(receipt.python_abi_tag, "cpython-312-darwin") != 0)
            return 66;
        generation_fd = open(receipt.generation_path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (generation_fd < 0) return 68;
        for (index = 0; index < PLAMEN_INSTALL_RECEIPT_MEMBER_COUNT; ++index) {
            if (plamen_install_receipt_open_member(generation_fd,
                    &receipt.members[index], &member_fd) != 0
                    || plamen_install_receipt_member_revalidate(member_fd,
                        &receipt.members[index]) != 0) {
                close(generation_fd);
                return 69;
            }
            close(member_fd);
        }
        close(generation_fd);
        return 0;
    }
    return accepted ? 67 : 0;
}
''',
        encoding="ascii",
    )
    helper = tmp_path / "receipt_probe"
    compiled = subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-Wno-deprecated-declarations", str(helper_source),
            str(RECEIPT_SOURCE), "-I", str(RECEIPT_SOURCE.parent),
            "-o", str(helper),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr.decode("utf-8", "replace")
    accepted = subprocess.run(
        [str(helper), "accept", str(receipt_path)], check=False, timeout=10
    )
    assert accepted.returncode == 0

    first_member = generation / inputs["members"][0]["relative_path"]
    displaced = first_member.with_name("displaced-launcher")
    first_member.rename(displaced)
    first_member.symlink_to(displaced)
    assert subprocess.run(
        [str(helper), "accept", str(receipt_path)], check=False, timeout=10
    ).returncode != 0
    first_member.unlink()
    displaced.rename(first_member)

    raw_tamper = bytearray(receipt)
    raw_tamper[20] ^= 1
    receipt_path.write_bytes(raw_tamper)
    assert subprocess.run(
        [str(helper), "reject", str(receipt_path)], check=False, timeout=10
    ).returncode == 0

    semantic_tamper = bytearray(receipt)
    semantic_tamper[2496 + 112] = ord("x")
    semantic_tamper[16352:] = hashlib.sha256(
        semantic_tamper[:16352]
    ).digest()
    receipt_path.write_bytes(semantic_tamper)
    assert subprocess.run(
        [str(helper), "reject", str(receipt_path)], check=False, timeout=10
    ).returncode == 0


def test_native_receipt_v2_serializer_matches_python_reference_exactly(
    tmp_path: Path,
) -> None:
    if sys.platform != "darwin":
        pytest.skip("Darwin receipt serializer")
    builder = _load_builder()
    inputs = _receipt_inputs(builder)
    generation = tmp_path / "generations" / "staging"
    generation.mkdir(parents=True, mode=0o700)
    for index, member in enumerate(inputs["members"]):
        path = generation / member["relative_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"native-member-{index}\n".encode("ascii"))
        path.chmod(member["mode"])
        identity = path.stat()
        member.update({
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": identity.st_size,
            "device": identity.st_dev,
            "inode": identity.st_ino,
            "uid": identity.st_uid,
            "gid": identity.st_gid,
        })
    generation_id, _preimage = builder.production_intrinsic_generation_id([
        {
            "role": member["role"],
            "relative_path": member["relative_path"],
            "sha256": member["sha256"],
            "size": member["size"],
            "mode": member["mode"],
        }
        for member in inputs["members"]
    ])
    final_generation = generation.parent / generation_id
    generation.rename(final_generation)
    generation = final_generation
    plist = (
        generation / "Library" / "LaunchAgents"
        / "com.plamen.audit.broker.v2.plist"
    )
    plist.parent.mkdir(parents=True)
    plist.write_bytes(b"<plist/>\n")
    plist.chmod(0o400)
    plist_identity = plist.stat()
    custody_plist = (
        generation / "Library" / "LaunchAgents"
        / "com.plamen.audit.process-custody.v2.plist"
    )
    custody_plist.write_bytes(b"<plist><key>custody</key></plist>\n")
    custody_plist.chmod(0o400)
    custody_plist_identity = custody_plist.stat()
    inputs["generation_path"] = str(generation)
    inputs["broker_launchd_plist"].update({
        "path": str(plist),
        "sha256": hashlib.sha256(plist.read_bytes()).hexdigest(),
        "size": plist_identity.st_size,
        "device": plist_identity.st_dev,
        "inode": plist_identity.st_ino,
        "uid": plist_identity.st_uid,
        "gid": plist_identity.st_gid,
    })
    inputs["custody_launchd_plist"].update({
        "path": str(custody_plist),
        "sha256": hashlib.sha256(custody_plist.read_bytes()).hexdigest(),
        "size": custody_plist_identity.st_size,
        "device": custody_plist_identity.st_dev,
        "inode": custody_plist_identity.st_ino,
        "uid": custody_plist_identity.st_uid,
        "gid": custody_plist_identity.st_gid,
    })
    expected = builder.TEST_ONLY_encode_darwin_install_receipt_v2(**inputs)
    output = tmp_path / "native-install-receipt-v2.bin"
    output.touch(mode=0o600)
    helper_source = tmp_path / "native_receipt_writer.c"
    helper_source.write_text(
        r'''#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "plamen_native_builder_v2.h"

    static const char *const paths[10] = {
    "bin/plamen-native-launcher",
    "lib/plamen/plamen-audit-broker-v2",
    "lib/plamen/_plamen_native_supervisor.cpython-312-darwin.so",
    "share/plamen/plamen_broker_v2.h",
    "share/plamen/native-supervisor-schema-v2.json",
    "bin/python3.12",
    "lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
        "share/plamen/runtime-package-manifest-v2.bin",
        "libexec/plamen-native-installer-v2",
        "libexec/plamen-native-source-bootstrap-coordinator-v1"
    };
    static const char *const identifiers[10] = {
    "com.plamen.audit.launcher.v2",
    "com.plamen.audit.broker.v2",
    "com.plamen.audit.native-supervisor.v2",
        "", "", "org.python.python", "", "",
        "com.plamen.audit.installer.v2",
        "com.plamen.audit.source-bootstrap.v1"
};

int main(int argc, char **argv) {
    struct plamen_darwin_install_receipt_request_v2 request;
    struct plamen_darwin_install_receipt_result_v2 result;
    int generation_fd = -1, broker_plist_fd = -1;
    int custody_plist_fd = -1, output_fd = -1;
    unsigned int index;
    int rc = 70;
    if (argc != 5) return 64;
    memset(&request, 0, sizeof(request));
        for (index = 0; index < 10; ++index)
        request.members[index].fd = -1;
    memset(request.projection_schema_sha256, 0x44,
        sizeof(request.projection_schema_sha256));
    memset(request.protocol_schema_sha256, 0x55,
        sizeof(request.protocol_schema_sha256));
    request.python_micro = 10;
    request.generation_absolute_path = argv[1];
    request.generation_absolute_path_size = strlen(argv[1]);
    request.broker_launchd_plist.absolute_path = argv[2];
    request.broker_launchd_plist.absolute_path_size = strlen(argv[2]);
    request.custody_launchd_plist.absolute_path = argv[3];
    request.custody_launchd_plist.absolute_path_size = strlen(argv[3]);
    generation_fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    broker_plist_fd = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    custody_plist_fd = open(argv[3], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    output_fd = open(argv[4], O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (generation_fd < 0 || broker_plist_fd < 0
            || custody_plist_fd < 0 || output_fd < 0) goto out;
    request.broker_launchd_plist.fd = broker_plist_fd;
    request.custody_launchd_plist.fd = custody_plist_fd;
        for (index = 0; index < 10; ++index) {
        request.members[index].fd = openat(generation_fd, paths[index],
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (request.members[index].fd < 0) goto out;
        request.members[index].code_identity.signing_identifier =
            identifiers[index];
        request.members[index].code_identity.signing_identifier_size =
            strlen(identifiers[index]);
        request.members[index].code_identity.team_identifier = "";
            if (index < 3 || index == 5 || index == 8 || index == 9) {
            memset(request.members[index].code_identity.cdhash, 0xab, 20);
            request.members[index].code_identity.cdhash_size = 20;
        }
    }
    rc = plamen_darwin_install_receipt_encode_v2(
        &request, output_fd, getuid(), &result) == 0 ? 0 : 71;
out:
        for (index = 0; index < 10; ++index)
        if (request.members[index].fd >= 0)
            close(request.members[index].fd);
    if (output_fd >= 0) close(output_fd);
    if (custody_plist_fd >= 0) close(custody_plist_fd);
    if (broker_plist_fd >= 0) close(broker_plist_fd);
    if (generation_fd >= 0) close(generation_fd);
    return rc;
}
''',
        encoding="ascii",
    )
    helper = tmp_path / "native_receipt_writer"
    compiled = subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            str(helper_source), str(NATIVE_BUILDER_SOURCE),
            "-I", str(NATIVE_BUILDER_SOURCE.parent), "-o", str(helper),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr.decode("utf-8", "replace")
    written = subprocess.run(
        [str(helper), str(generation), str(plist), str(custody_plist),
         str(output)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    assert written.returncode == 0, written.stderr.decode("utf-8", "replace")
    assert output.read_bytes() == expected
    output.chmod(0o600)


def test_native_builder_stages_one_exact_private_generation(
    runtime_tree_factory, tmp_path: Path,
) -> None:
    builder = _load_builder()
    runtime = runtime_tree_factory("stage-runtime")
    manifest = builder.TEST_ONLY_build_runtime_package_manifest_v2(
        runtime, bindings=_runtime_bindings(builder)
    )
    sources = tmp_path / "stage-sources"
    sources.mkdir(mode=0o700)
    source_rows = (
        ("launcher", b"launcher-v2\n", 0o500),
        ("service", b"service-v2\n", 0o500),
        ("extension", b"extension-v2\n", 0o400),
        ("abi", b"abi-v2\n", 0o400),
        ("schema", b"schema-v2\n", 0o400),
        ("python", b"python-v2\n", 0o500),
        ("installer", b"installer-v2\n", 0o500),
        ("source-bootstrap", b"source-bootstrap-v1\n", 0o500),
    )
    member_sources: list[Path] = []
    for name, raw, mode in source_rows:
        path = sources / name
        path.write_bytes(raw)
        path.chmod(mode)
        member_sources.append(path)
    # Receipt order keeps the runtime entrypoint and manifest before the
    # dedicated installed coordinator.
    source_bootstrap_source = member_sources.pop()
    installer_source = member_sources.pop()
    member_sources.append(runtime / "scripts" / "posix_audit_entrypoint.py")
    manifest_source = sources / "runtime-manifest"
    manifest_source.write_bytes(manifest)
    manifest_source.chmod(0o400)
    member_sources.append(manifest_source)
    member_sources.append(installer_source)
    member_sources.append(source_bootstrap_source)

    staging = tmp_path / "stage-parent"
    staging.mkdir(mode=0o700)
    helper_source = tmp_path / "stage_generation_helper.c"
    helper_binary = tmp_path / "stage_generation_helper"
    helper_source.write_text(
        r'''#include "plamen_native_builder_v2.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void print_digest(const uint8_t value[32]) {
    size_t i;
    for (i = 0; i < 32; ++i) printf("%02x", value[i]);
}

int main(int argc, char **argv) {
    struct plamen_native_generation_stage_request_v2 request;
    struct plamen_native_generation_stage_result_v2 result;
    struct stat info;
    size_t i;
    int rc = 1;
        if (argc != 13) return 64;
    memset(&request, 0, sizeof(request));
        for (i = 0; i < 10; ++i) request.member_source_fds[i] = -1;
    request.staging_parent_fd = -1;
    request.runtime_root_source_fd = -1;
    request.staging_parent_fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    request.runtime_root_source_fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    request.staged_generation_name = "candidate";
    request.owner_uid = getuid();
    if (request.staging_parent_fd < 0 || request.runtime_root_source_fd < 0) goto out;
        for (i = 0; i < 10; ++i) {
        request.member_source_fds[i] = open(argv[3 + i], O_RDONLY | O_CLOEXEC);
        if (request.member_source_fds[i] < 0) goto out;
    }
    if (plamen_native_generation_stage_v2(&request, &result) != 0) goto out;
    if (fstat(result.generation_root_fd, &info) != 0
            || (info.st_mode & 07777) != 0700) {
        plamen_native_generation_stage_result_dispose_v2(&result);
        goto out;
    }
    print_digest(result.generation_id);
    putchar(' ');
    print_digest(result.intrinsic_roster_sha256);
    putchar('\n');
    plamen_native_generation_stage_result_dispose_v2(&result);
    rc = 0;
out:
        for (i = 0; i < 10; ++i) {
        if (request.member_source_fds[i] >= 0) close(request.member_source_fds[i]);
    }
    if (request.runtime_root_source_fd >= 0) close(request.runtime_root_source_fd);
    if (request.staging_parent_fd >= 0) close(request.staging_parent_fd);
    return rc;
}
''',
        encoding="utf-8",
    )
    compiled = subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(NATIVE_BUILDER_HEADER.parent), str(helper_source),
            str(NATIVE_BUILDER_SOURCE), "-o", str(helper_binary),
        ],
        cwd=ROOT, check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr.decode("utf-8", "replace")
    command = [
        str(helper_binary), str(staging), str(runtime),
        *(str(path) for path in member_sources),
    ]
    candidate = staging / "candidate"
    try:
        staged = subprocess.run(
            command, cwd=ROOT, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        assert staged.returncode == 0, staged.stderr.decode("utf-8", "replace")
        generation, roster_digest = staged.stdout.decode("ascii").strip().split()
        artifact_roster = []
        for expected in builder.DARWIN_INSTALL_RECEIPT_V2_MEMBERS:
            role, _role_id, relative, mode, _identifier, _signed = expected
            path = candidate / relative
            raw = path.read_bytes()
            info = path.stat(follow_symlinks=False)
            assert info.st_nlink == 1
            assert info.st_mode & 0o7777 == mode
            artifact_roster.append({
                "role": role,
                "relative_path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
                "mode": mode,
            })
        expected_generation, _preimage = (
            builder.production_intrinsic_generation_id(artifact_roster)
        )
        assert generation == expected_generation
        assert roster_digest == builder.production_intrinsic_roster_sha256(
            artifact_roster
        )
        assert candidate.stat().st_mode & 0o7777 == 0o700
        assert all(
            path.stat().st_mode & 0o7777 == 0o500
            for path in candidate.rglob("*") if path.is_dir()
        )
        builder.TEST_ONLY_validate_runtime_package_manifest_v2(
            candidate / "lib" / "plamen" / "runtime",
            (candidate / "share" / "plamen"
             / "runtime-package-manifest-v2.bin").read_bytes(),
        )
        repeated = subprocess.run(
            command, cwd=ROOT, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        assert repeated.returncode != 0
        assert candidate.is_dir()
    finally:
        _thaw_runtime_tree(candidate)


def test_deterministic_adhoc_signing_ids_pass_native_strict_probe(
    tmp_path: Path,
) -> None:
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        pytest.skip("first deterministic signing closure is Darwin arm64")
    builder = _load_builder()
    executable_source = tmp_path / "executable.c"
    executable_source.write_text("int main(void){return 0;}\n", encoding="ascii")
    extension_source = tmp_path / "extension.c"
    extension_source.write_text(
        "__attribute__((visibility(\"default\"))) int plamen_probe(void){return 0;}\n",
        encoding="ascii",
    )
    artifacts = {
        "launcher": tmp_path / "plamen-native-launcher",
        "service": tmp_path / "plamen-audit-broker-v2",
        "extension": tmp_path / "_plamen_native_supervisor.so",
    }
    for role, artifact in artifacts.items():
        command = [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            str(extension_source if role == "extension" else executable_source),
        ]
        if role == "extension":
            command.extend(["-bundle", "-undefined", "dynamic_lookup"])
        command.extend(["-o", str(artifact)])
        subprocess.run(
            command, check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )

    probe_source = tmp_path / "strict_code_probe.c"
    probe_source.write_text(
        r'''#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <string.h>
int main(int argc, char **argv) {
    CFURLRef url = NULL;
    SecStaticCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    CFStringRef expected = NULL;
    CFStringRef identifier;
    CFStringRef team;
    CFDataRef cdhash;
    int result = 70;
    if (argc != 3) return 64;
    url = CFURLCreateFromFileSystemRepresentation(NULL,
        (const UInt8 *)argv[1], (CFIndex)strlen(argv[1]), false);
    expected = CFStringCreateWithCString(NULL, argv[2], kCFStringEncodingASCII);
    if (url == NULL || expected == NULL
            || SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) != errSecSuccess
            || SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL) != errSecSuccess
            || SecCodeCopySigningInformation((SecCodeRef)code,
                kSecCSSigningInformation, &information) != errSecSuccess)
        goto done;
    identifier = CFDictionaryGetValue(information, kSecCodeInfoIdentifier);
    team = CFDictionaryGetValue(information, kSecCodeInfoTeamIdentifier);
    cdhash = CFDictionaryGetValue(information, kSecCodeInfoUnique);
    if (identifier == NULL || !CFEqual(identifier, expected)
            || (team != NULL && CFStringGetLength(team) != 0)
            || cdhash == NULL
            || !(CFDataGetLength(cdhash) == 20 || CFDataGetLength(cdhash) == 32))
        goto done;
    result = 0;
done:
    if (information != NULL) CFRelease(information);
    if (code != NULL) CFRelease(code);
    if (expected != NULL) CFRelease(expected);
    if (url != NULL) CFRelease(url);
    return result;
}
''',
        encoding="ascii",
    )
    probe = tmp_path / "strict_code_probe"
    subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            str(probe_source), "-framework", "Security", "-framework",
            "CoreFoundation", "-o", str(probe),
        ],
        check=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )

    observations: dict[str, dict[str, str]] = {}
    for role, artifact in artifacts.items():
        identifier = builder.PRODUCTION_DARWIN_SIGNING_IDENTIFIERS[role]
        subprocess.run(
            [
                "/usr/bin/codesign", "--force", "--sign", "-",
                "--identifier", identifier, "--timestamp=none", str(artifact),
            ],
            check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", str(artifact)],
            check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        details = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(artifact)],
            check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        ).stderr.decode("utf-8", "strict")
        fields = {
            key: value
            for line in details.splitlines()
            if "=" in line
            for key, value in [line.split("=", 1)]
        }
        assert fields["Identifier"] == identifier
        assert fields["TeamIdentifier"] == "not set"
        assert len(fields["CDHash"]) in {40, 64}
        int(fields["CDHash"], 16)
        subprocess.run(
            [str(probe), str(artifact), identifier],
            check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        observations[role] = {
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "identifier": fields["Identifier"],
            "team_identifier": "",
            "cdhash": fields["CDHash"],
        }
    assert set(observations) == {"launcher", "service", "extension"}


def test_real_launcher_binary_has_no_default_or_generation_placeholder_path(
    tmp_path: Path,
) -> None:
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        pytest.skip("first launcher closure is Darwin arm64")
    launcher = tmp_path / "plamen-native-launcher"
    compiled = subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-Wno-deprecated-declarations", "-fblocks", str(LAUNCHER_SOURCE),
            str(PROTOCOL_SOURCE), str(RECEIPT_SOURCE),
            str(DEPLOYMENT_RECEIPT_SOURCE),
            "-framework", "Security", "-framework", "CoreFoundation",
            "-o", str(launcher),
        ],
        check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr.decode("utf-8", "replace")
    binary = launcher.read_bytes()
    assert b"/Library/Application Support" not in binary
    assert b"__PLAMEN_GENERATION" not in binary
    assert b"{generation_id}" not in binary
    assert b"share/plamen/native-install-receipt-v2.bin" in binary
    assert b"share/plamen/native-deployment-receipt-v2.bin" in binary
    assert b"lib/plamen/runtime/scripts/posix_audit_entrypoint.py" in binary

def test_production_readiness_names_every_unproved_authority(
) -> None:
    builder = _load_builder()
    readiness = builder.production_readiness()
    blockers = set(readiness["blockers"])

    assert {
        "SOURCE_INSTALL_COORDINATOR_TRANSACTION_ABSENT",
        "PRODUCTION_COMPILE_LINK_CLOSURE_UNOBSERVED",
        "MULTI_ARTIFACT_RETAINED_INSTALL_HANDOFF_ABSENT",
        "INTRINSIC_GENERATION_ARTIFACT_ROSTER_UNBUILT",
        "INSTALLED_CLOSURE_CODE_REQUIREMENT_RECEIPT_ABSENT",
        "RUNTIME_PACKAGE_MANIFEST_UNBUILT",
        "CODEX_COMMITTED_PACKAGE_TRANSACTION_ABSENT",
        "EVM_SIGNED_TOOL_AUTHORITY_PRODUCER_ABSENT",
        "PROVIDER_LIFECYCLE_AUTHORITY_UNREACHABLE",
    } <= blockers
    assert "APPLE_FUZZ_ATOMIC_ADMISSION_PRODUCERS_ABSENT" not in blockers
    assert (
        "APPLE_FUZZ_ATOMIC_ADMISSION_PRODUCERS_ABSENT"
        not in readiness["closure"]["release_gate_evidence"]
    )
    schema_status = readiness["closure"][
        "native_supervisor_schema_artifact"
    ]["status"]
    if schema_status == "INVALID":
        assert "NATIVE_SUPERVISOR_SCHEMA_ARTIFACT_INVALID" in blockers
    elif schema_status == "MISSING":
        assert "NATIVE_SUPERVISOR_SCHEMA_ARTIFACT_UNDEFINED" in blockers
    else:
        assert schema_status == "EXACT_ABI_VALIDATED_DIAGNOSTIC_ONLY"
        assert blockers.isdisjoint({
            "NATIVE_SUPERVISOR_SCHEMA_ARTIFACT_INVALID",
            "NATIVE_SUPERVISOR_SCHEMA_ARTIFACT_UNDEFINED",
        })
    # The exact native execution seams are now present in the live source;
    # packaging readiness must not continue reporting their former stubs.
    assert blockers.isdisjoint({
        "EXTENSION_SERVICE_BOOTSTRAP_NOT_INTEGRATED",
        "LAUNCHD_XPC_BROKER_SERVICE_NOT_INTEGRATED",
        "LAUNCHD_MANIFEST_NOT_INTEGRATED",
        "DARWIN_SUSPENDED_LAUNCHER_NOT_INTEGRATED",
        "LAUNCHER_NATIVE_PROJECTION_BUILDER_NOT_INTEGRATED",
        "SERVICE_OPERATION_DISPATCH_NOT_INTEGRATED",
        "SERVICE_PROCESS_CUSTODY_NOT_INTEGRATED",
    })
    for selector in ("CODEX", "CLAUDE"):
        assert f"DARWIN_{selector}_PROFILE_NOT_MATERIALIZED" in blockers


def test_intrinsic_generation_id_is_acyclic_and_excludes_deployment_state() -> None:
    builder = _load_builder()
    roster = [
        {
            "role": role,
            "relative_path": relative,
            "sha256": format(number + 1, "064x"),
            "size": number + 1,
            "mode": mode,
        }
        for number, (role, _role_id, relative, mode, _identifier, _signed)
        in enumerate(builder.DARWIN_INSTALL_RECEIPT_V2_MEMBERS)
    ]
    generation, preimage = builder.production_intrinsic_generation_id(roster)
    roster_digest = builder.production_intrinsic_roster_sha256(roster)

    assert generation == hashlib.sha256(preimage).hexdigest()
    row_offset = len(b"PLAMEN-INTRINSIC-GENERATION-V2\0") + 8
    assert roster_digest == hashlib.sha256(
        b"PLAMEN-INTRINSIC-ROSTER-V2\0"
        + struct.pack(">H", 10) + preimage[row_offset:]
    ).hexdigest()
    assert roster_digest != generation
    domain = b"PLAMEN-INTRINSIC-GENERATION-V2\0"
    assert preimage.startswith(domain)
    assert struct.unpack_from(">HHHH", preimage, len(domain)) == (2, 1, 1, 10)
    assert b"launchd" not in preimage
    assert b"receipt" not in preimage
    contract = builder.production_readiness()["closure"]["generation_contract"]
    assert contract["directory_template"] == (
        "{store_root}/generations/{generation_id}"
    )
    assert contract["deployment_roles_excluded_from_generation_id"] == [
        "launchd_plist", "install_receipt",
    ]
    assert contract["publication_order"][-3:] == [
        "launchctl-bootstrap",
        "authenticated-service-handshake",
        "publish-stable-internal-launcher-last",
    ]
    linux = contract["linux_reserved_denominator"]
    assert linux["status"] == (
        "NATIVE_DESCRIPTOR_EXECUTOR_AND_DURABLE_RECOVERY_"
        "IMPLEMENTED_LIVE_ROOTLESS_LINUX_RECEIPTS_PENDING"
    )
    assert linux["admission_source_roster"] == [
        "native/linux/plamen_broker_v2_linux.h",
        "native/linux/plamen_broker_v2_linux_process.c",
        "native/linux/plamen_linux_install_receipt_v2.h",
        "native/linux/plamen_linux_install_receipt_v2.c",
        "native/linux/plamen_broker_v2_podman_admission.h",
        "native/linux/plamen_broker_v2_podman_admission.c",
        "native/linux/plamen_broker_v2_podman_lifecycle.h",
        "native/linux/plamen_broker_v2_podman_lifecycle.c",
    ]
    assert linux["admission_does_not_grant"] == [
        "container-lifecycle",
        "cgroup-population-zero-after-execution",
        "overlay-cleanup",
        "durable-recovery",
        "artifact-export",
        "python-authority",
    ]
    assert linux["lifecycle_still_unverified"] == [
        "live-podman-postcondition-reconciliation",
        "overlay-mount-and-upper-work-cleanup",
        "live-rootless-receipt-authentication",
    ]
    assert [row["role"] for row in linux["intrinsic_roster"]] == [
        "systemd_user_unit", "guest_bootstrap", "broker",
    ]
    assert linux["native_endpoints"] == {
        "outer_host": "/run/user/{native_uid}/plamen/broker-v2.sock",
        "guest": "/run/plamen/broker-v2.sock",
        "environment_token_allowed": False,
    }
    assert linux["install_receipt"]["schema"] == (
        "plamen.linux-install-receipt.v2"
    )
    assert linux["install_receipt"]["magic"] == "PLNLIR2\\0"
    assert linux["install_receipt"]["receipt_fd"] == 198
    assert linux["install_receipt"]["install_root_fd"] == 199
    assert linux["install_receipt"]["member_roles"] == [
        "broker", "extension", "interpreter", "service_bootstrap",
    ]
    assert linux["install_receipt"]["same_uid_sufficient"] is False
    assert linux["install_receipt"]["live_receipt_observed"] is False
    assert linux["process_custody_functions"] == [
        "plamen_broker_v2_linux_cgroup_leaf_admit",
        "plamen_broker_v2_linux_process_spawn_retained",
        "plamen_broker_v2_linux_process_revalidate",
        "plamen_broker_v2_linux_process_wait_or_extinguish",
        "plamen_broker_v2_linux_process_extinguish",
        "plamen_broker_v2_linux_process_close",
    ]
    assert linux["lifecycle_functions"] == [
        "plamen_broker_v2_podman_cgroup_path_revalidate",
        "plamen_broker_v2_podman_lifecycle_execute_journaled",
    ]
    assert linux["guest_runtime"] == {
        "source_mount": "/opt/plamen",
        "source_mount_mode": "READ_ONLY_AUTHENTICATED_V3_ARCHIVE",
        "driver": "/opt/plamen/scripts/plamen_driver.py",
        "guest_bootstrap": "/usr/local/libexec/plamen-guest",
        "interpreter": "/usr/bin/python3",
        "interpreter_argv": ["-B", "/opt/plamen/scripts/plamen_driver.py"],
        "extension": (
            "/usr/local/lib/plamen/native/cpython-312/"
            "_plamen_native_supervisor.so"
        ),
        "native_receipt": (
            "/usr/local/share/plamen/native-install-receipt-v2.bin"
        ),
        "tool_root": "/usr/local/lib/plamen",
        "solc": "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
        "forge": "/usr/local/lib/plamen/toolchains/foundry/bin/forge",
        "foundry_offline_environment": "FOUNDRY_OFFLINE=true",
        "forge_required_flags": [
            "--offline", "--use",
            "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
        ],
        "environment_discovery_allowed": False,
    }


def test_intrinsic_generation_id_rejects_nonexact_or_deployment_rosters() -> None:
    builder = _load_builder()
    roster = [
        {
            "role": role,
            "relative_path": relative,
            "sha256": format(number + 1, "064x"),
            "size": number + 1,
            "mode": mode,
        }
        for number, (role, _role_id, relative, mode, _identifier, _signed)
        in enumerate(builder.DARWIN_INSTALL_RECEIPT_V2_MEMBERS)
    ]
    invalid = [dict(row) for row in roster]
    invalid[0]["vnode"] = {"device": 1, "inode": 2}
    with pytest.raises(builder.BuildError, match="fields are not exact"):
        builder.production_intrinsic_generation_id(invalid)
    with pytest.raises(builder.BuildError, match="roster is not exact"):
        builder.production_intrinsic_generation_id(roster + [{
            "role": "install_receipt",
            "relative_path": "share/plamen/native-install-receipt-v2.bin",
            "sha256": "a" * 64,
            "size": 1,
            "mode": 0o400,
        }])


def test_exact_cpython_312_can_observe_the_darwin_toolchain_closure() -> None:
    if sys.platform != "darwin":
        pytest.skip("first production closure is Darwin arm64")
    interpreter = shutil.which("python3.12")
    if interpreter is None:
        pytest.skip("CPython 3.12 is required for the production closure")
    completed = subprocess.run(
        [interpreter, os.fspath(BUILDER), "--production-readiness"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    report = json.loads(completed.stdout)
    assert report["observed_python_version"][:2] == [3, 12]
    assert "CPYTHON_ABI_NOT_EXACT_3_12" not in report["blockers"]
    assert report["closure"]["toolchain"]["status"] == (
        "OBSERVED_DIAGNOSTIC_ONLY"
    )
    assert report["closure"]["toolchain"]["compiler"]["path"].startswith(
        "/Library/Developer/CommandLineTools/"
    )
    assert report["closure"]["toolchain"]["sdk"]["kind"] == (
        "DARWIN_XCRUN_PINNED_SDK"
    )


def test_install_codex_dispatch_entrypoint_is_closed_and_fail_closed() -> None:
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        pytest.skip("first source installer is Darwin arm64")
    interpreter = shutil.which("python3.12")
    if interpreter is None:
        pytest.skip("CPython 3.12 is required for the source installer")
    completed = subprocess.run(
        [interpreter, "-I", "-B", os.fspath(BUILDER), "--install-codex"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONHASHSEED": "0",
        },
        check=False,
        timeout=120,
    )
    assert completed.returncode == 2
    assert completed.stdout == b""
    assert b"source install transaction is not complete" in completed.stderr
    assert b"SOURCE_FREEZE_MANIFEST_UNAVAILABLE" in completed.stderr


def _transaction_ready_observation(builder: ModuleType) -> dict[str, object]:
    report: dict[str, object] = {
        "schema": "plamen.native-supervisor.production-readiness.v2",
        "authority": "DIAGNOSTIC_ONLY_LOADED_PYTHON_NO_BUILD_AUTHORITY",
        "production_build_allowed": True,
        "observed_python_version": [3, 12, 10],
        "platform": "darwin", "machine": "arm64", "closure": {},
        "blockers": sorted(builder.PRODUCTION_COLD_INSTALL_OUTPUT_BLOCKERS),
        "transaction_admission_blockers": [],
    }
    report["observation_sha256"] = hashlib.sha256(_canonical(report)).hexdigest()
    return report


def test_source_install_transaction_hands_exact_freeze_to_explicit_coordinator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    home = tmp_path / "account"; home.mkdir()
    source = tmp_path / "source"; source.mkdir()
    freeze = {
        "schema": "plamen.native-production-source-freeze.v2",
        "version": 2, "platform": "darwin-arm64",
        "roster_definition_sha256": "1" * 64,
        "source_roster_sha256": "2" * 64,
        "source_count": 1,
        "sources": [{
            "role": "fixture", "path": "fixture.py", "size": 1,
            "sha256": "3" * 64,
        }],
        "manifest_sha256": "4" * 64,
    }
    monkeypatch.setattr(builder, "REPOSITORY_ROOT", source)
    monkeypatch.setattr(
        builder, "_load_exact_production_source_freeze", lambda: freeze,
    )
    events: list[tuple[str, object]] = []
    source_authority = {
        "schema": "fixture.source", "digest": "5" * 64,
    }

    class Coordinator:
        @staticmethod
        def source_authority_from_validated_freeze(root, observed):
            events.append(("source", (root, observed)))
            return source_authority

        @staticmethod
        def execute_cold_install_transaction(*, home, source_authority, effects):
            events.append(("execute", (home, source_authority, effects)))
            return {"schema": "fixture.receipt", "state": "COMMITTED"}

    sentinel = object()
    package_snapshot = {"schema": "fixture.package-snapshot"}

    def effects_factory(**values):
        callbacks = values["builder_callbacks"]
        assert type(callbacks).__name__ == "mappingproxy"
        assert {
            "compile_release_artifacts", "retain_cpython_312",
            "render_runtime_manifest", "run_generation_stage",
            "run_native_prepare_publish",
        } <= set(callbacks)
        assert values["source_freeze"] is freeze
        assert values["source_authority"] is source_authority
        assert values["package_snapshot"] is package_snapshot
        assert values["home"] == home
        events.append(("effects", values))
        return sentinel

    result = builder._execute_native_source_install_transaction(
        _transaction_ready_observation(builder), home=home,
        coordinator_module=Coordinator, effects_factory=effects_factory,
        package_snapshot_factory=lambda workspace, account, observed: (
            package_snapshot
        ),
    )
    assert result == {"schema": "fixture.receipt", "state": "COMMITTED"}
    assert [name for name, _value in events] == ["source", "effects", "execute"]
    assert list(home.iterdir()) == []


def test_production_effect_factory_binds_frozen_package_and_native_callbacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    home = tmp_path / "account"; home.mkdir()
    durable_source = tmp_path / "durable-source"; durable_source.mkdir()
    events: list[tuple[str, object]] = []

    class Package:
        _FROZEN_PACKAGE_FRONT_STDLIB_ONLY = True

        @staticmethod
        def _install_codex_package_transaction(**values):
            events.append(("package-commit", values))
            return {"transaction_id": "a" * 32}

        @staticmethod
        def _rollback_committed_codex_package_transaction(
            receipt, prior, **values,
        ):
            events.append(("package-rollback", (receipt, prior, values)))
            return True

    captured: dict[str, object] = {}

    def constructor(**values):
        captured.update(values)
        return "effects"

    class NativeTransaction:
        _PLAMEN_RETAINED_NATIVE_TRANSACTION_V1 = True

        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True
            return True

        def stage(self, *args):
            events.append(("native-stage", args))
            return {"schema": "fixture.native-stage"}

        def validate_stage(self, *args):
            events.append(("native-stage-validate", args)); return True

        def commit(self, *args):
            events.append(("native-commit", args))
            return {"schema": "fixture.native-commit"}

        def validate_installed(self, *args):
            events.append(("native-validate", args))
            return {"schema": "fixture.native-validate"}

        def rollback(self, *args):
            events.append(("native-rollback", args)); return True

        def cleanup(self, *args):
            events.append(("native-cleanup", args)); return True

    native_transaction = NativeTransaction()

    def prepare_native(**values):
        events.append(("native-prepare", values))
        return native_transaction

    defaults = builder._production_native_builder_callbacks()
    callbacks = MappingProxyType({
        **dict(defaults),
        "prepare_production_native_transaction": prepare_native,
    })
    monkeypatch.setattr(
        builder, "validate_codex_committed_package_v2",
        lambda account: {"transaction_id": "b" * 32, "account": account},
    )
    freeze = {"schema": "fixture.freeze"}
    authority = {"schema": "fixture.authority"}
    snapshot = {"schema": "fixture.snapshot"}
    result = builder._create_production_cold_install_effects(
        home=home, source_freeze=freeze, source_authority=authority,
        package_snapshot=snapshot, builder_callbacks=callbacks,
        cold_stack={
            "publication": object(), "transaction": object(),
            "effects": type("Effects", (), {"DarwinColdInstallEffects": constructor}),
            "package": Package,
        },
    )
    assert isinstance(result, builder._ProductionColdInstallEffectsLease)
    assert result._effects == "effects"
    assert captured["home"] == home
    assert captured["package_snapshot"] is snapshot
    assert captured["package_commit"](
        home, durable_source, {}, {},
    ) == {"transaction_id": "a" * 32}
    assert captured["package_validate"](home) == {
        "transaction_id": "b" * 32, "account": home,
    }
    receipt = {"schema": "fixture.receipt"}
    prior = {"schema": "fixture.prior"}
    assert captured["package_rollback"](home, receipt, prior) is True
    stage = captured["native_stage"](home, tmp_path, {}, {})
    assert stage == {"schema": "fixture.native-stage"}
    assert events[-1] == ("native-stage", (home, tmp_path, {}, {}))
    assert captured["native_stage_validate"](stage, {}, {}) is True
    assert events[-1] == ("native-stage-validate", (stage, {}, {}))
    assert captured["native_commit"](
        home, stage, {}, receipt,
    ) == {"schema": "fixture.native-commit"}
    assert events[-1] == ("native-commit", (home, stage, {}, receipt))
    assert captured["native_validate"](
        home, receipt,
    ) == {"schema": "fixture.native-validate"}
    assert events[-1] == ("native-validate", (home, receipt))
    assert captured["native_rollback"](home, receipt, prior) is True
    assert events[-1] == ("native-rollback", (home, receipt, prior))
    assert captured["cleanup"](home, {}, stage) is True
    assert events[-1] == ("native-cleanup", (home, {}, stage))
    prepare_event = next(value for name, value in events if name == "native-prepare")
    assert prepare_event["home"] == home
    assert prepare_event["source_freeze"] is freeze
    assert prepare_event["source_authority"] is authority
    assert prepare_event["builder_callbacks"] is callbacks
    # The session marker, not a serialized mapping, is the authority routed by
    # every native effect wrapper.
    assert native_transaction._PLAMEN_RETAINED_NATIVE_TRANSACTION_V1 is True
    expected_context = {
        "source_freeze": freeze, "source_authority": authority,
        "builder_callbacks": callbacks,
        "native_transaction": native_transaction,
    }
    # Inspecting the wrapper closure would make its cell order part of the
    # contract; behavior above is the stable assertion.  Keep the exact
    # context shape asserted through the builder helper itself.
    assert builder._production_native_session(
        expected_context, "stage",
    )[0] is native_transaction
    result.close(); result.close()
    assert native_transaction.closed is True
    package_event = next(value for name, value in events if name == "package-commit")
    assert package_event["source_root"] == durable_source
    assert package_event["plamen_root"] == home / ".plamen"
    assert package_event["codex_home"] == home / ".codex"


def test_default_native_acquisition_denies_before_effect_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    home = tmp_path / "account"; home.mkdir()
    constructed: list[bool] = []

    class Package:
        _FROZEN_PACKAGE_FRONT_STDLIB_ONLY = True
        _install_codex_package_transaction = staticmethod(lambda **_values: {})
        _rollback_committed_codex_package_transaction = staticmethod(
            lambda *_args, **_values: True
        )

    def constructor(**_values):
        constructed.append(True)
        return object()

    class Roster:
        _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True
        closed = False

        def close(self):
            self.closed = True
            return True

    roster = Roster()
    monkeypatch.setattr(
        builder, "_retain_exact_frozen_source_roster", lambda _freeze: roster,
    )
    callbacks = builder._production_native_builder_callbacks()
    assert {
        "prepare_production_native_transaction",
        "production_native_stage", "production_native_stage_validate",
        "production_native_commit", "production_native_validate",
        "production_native_rollback", "production_native_cleanup",
    } <= set(callbacks)
    with pytest.raises(
        builder.BuildError,
        match="PRODUCTION_NATIVE_RETAINED_ACQUISITION_UNAVAILABLE",
    ):
        builder._create_production_cold_install_effects(
            home=home, source_freeze={"schema": "fixture.freeze"},
            source_authority={"schema": "fixture.authority"},
            package_snapshot={"schema": "fixture.snapshot"},
            builder_callbacks=callbacks,
            cold_stack={
                "publication": object(), "transaction": object(),
                "effects": type(
                    "Effects", (), {"DarwinColdInstallEffects": constructor},
                ),
                "package": Package,
            },
        )
    assert constructed == []
    assert roster.closed is True
    assert list(home.iterdir()) == []


def test_retained_production_native_transaction_binds_and_replays_exact_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    home = tmp_path / "account"; home.mkdir()
    transaction_root = tmp_path / ("a" * 32); transaction_root.mkdir()
    source = {"schema": "fixture.source", "manifest_sha256": "1" * 64}
    package_stage = {"transaction_id": transaction_root.name}
    events: list[tuple[str, object]] = []

    class Roster:
        _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True
        closed = False

        def close(self):
            self.closed = True
            return True

    roster = Roster()

    class Acquisition:
        _PLAMEN_PRODUCTION_NATIVE_ACQUISITION_V1 = True
        closed = False

        def stage(self, *args):
            events.append(("stage", args))
            return {
                "schema": "plamen.posix-native-install.stage.v1",
                "kind": "native", "transaction_id": transaction_root.name,
                "manifest_sha256": "2" * 64, "artifact_count": 33,
            }

        def validate_stage(self, *args):
            events.append(("validate-stage", args)); return True

        def commit(self, *args):
            events.append(("commit", args)); return {"schema": "committed"}

        def validate_installed(self, *args):
            events.append(("validate", args)); return {"schema": "installed"}

        def rollback(self, *args):
            events.append(("rollback", args)); return True

        def cleanup(self, *args):
            events.append(("cleanup", args)); return True

        def close(self):
            self.closed = True
            return True

    acquisition = Acquisition()
    monkeypatch.setattr(
        builder, "_retain_exact_frozen_source_roster", lambda _freeze: roster,
    )
    defaults = builder._production_native_builder_callbacks()
    callbacks = MappingProxyType({
        **dict(defaults),
        "acquire_production_native_authority": lambda **_values: acquisition,
    })
    session = builder._prepare_production_native_transaction(
        home=home, source_freeze={"schema": "fixture.freeze"},
        source_authority=source, builder_callbacks=callbacks,
    )
    stage = session.stage(home, transaction_root, source, package_stage)
    assert session.validate_stage(stage, source, package_stage) is True
    package_receipt = {"schema": "fixture.package"}
    assert session.commit(home, stage, source, package_receipt) == {
        "schema": "committed",
    }
    assert session.validate_installed(home, package_receipt) == {
        "schema": "installed",
    }
    assert session.rollback(home, {"schema": "receipts"}, {
        "schema": "prior",
    }) is True
    assert session.cleanup(home, package_stage, stage) is True
    assert [name for name, _value in events] == [
        "stage", "validate-stage", "commit", "validate", "rollback",
        "cleanup",
    ]
    assert session.close() is True
    assert session.close() is True
    assert acquisition.closed is True
    assert roster.closed is True


def test_retained_production_native_transaction_rejects_malformed_stage_and_closes(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    home = tmp_path / "account"; home.mkdir()
    transaction_root = tmp_path / ("b" * 32); transaction_root.mkdir()
    source = {"schema": "fixture.source"}

    class Roster:
        _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True
        closed = False

        def close(self):
            self.closed = True
            return True

    class Acquisition:
        _PLAMEN_PRODUCTION_NATIVE_ACQUISITION_V1 = True
        closed = False

        def stage(self, *_args):
            return {
                "schema": "plamen.posix-native-install.stage.v1",
                "kind": "native", "transaction_id": transaction_root.name,
                "manifest_sha256": "not-a-digest", "artifact_count": 1,
            }

        validate_stage = commit = validate_installed = rollback = cleanup = (
            lambda *_args: True
        )

        def close(self):
            self.closed = True
            return True

    roster = Roster(); acquisition = Acquisition()
    session = builder._RetainedProductionNativeTransaction(
        home=home, source=source, authority=acquisition,
        source_roster=roster,
    )
    with pytest.raises(builder.BuildError, match="staged authority differs"):
        session.stage(
            home, transaction_root, source,
            {"transaction_id": transaction_root.name},
        )
    assert list(home.iterdir()) == []
    assert session.close() is True
    assert acquisition.closed is True
    assert roster.closed is True


def test_retained_frozen_source_roster_never_reopens_substituted_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    first = tmp_path / "one"; first.write_bytes(b"reviewed-one")
    second = tmp_path / "two"; second.write_bytes(b"reviewed-two")
    monkeypatch.setattr(builder, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        builder, "PRODUCTION_DARWIN_SOURCE_ROSTER",
        (("alpha", "one"), ("beta", "two")),
    )
    freeze = {
        "schema": builder.PRODUCTION_SOURCE_FREEZE_SCHEMA,
        "sources": [
            {
                "role": role, "path": path, "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            for role, path, raw in (
                ("alpha", "one", b"reviewed-one"),
                ("beta", "two", b"reviewed-two"),
            )
        ],
    }
    authority = builder._retain_exact_frozen_source_roster(freeze)
    moved = tmp_path / "one.retained"; first.rename(moved)
    first.write_bytes(b"attacker-path")
    row, descriptor = authority.duplicate("alpha")
    try:
        assert row["sha256"] == hashlib.sha256(b"reviewed-one").hexdigest()
        assert os.pread(descriptor, row["size"], 0) == b"reviewed-one"
        assert os.stat(descriptor).st_ino == moved.stat().st_ino
        assert os.stat(descriptor).st_ino != first.stat().st_ino
    finally:
        os.close(descriptor)
    assert authority.close() is True
    assert authority.close() is True
    with pytest.raises(builder.BuildError, match="roster is closed"):
        authority.roles()


def test_retained_source_projection_seals_and_duplicates_only_exact_vnodes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    frozen = tmp_path / "frozen"; frozen.write_bytes(b"source\n")
    os.chmod(frozen, 0o400)
    monkeypatch.setattr(builder, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        builder, "PRODUCTION_DARWIN_SOURCE_ROSTER", (("source", "frozen"),),
    )
    freeze = {
        "schema": builder.PRODUCTION_SOURCE_FREEZE_SCHEMA,
        "sources": [{
            "role": "source", "path": "frozen", "size": 7,
            "sha256": hashlib.sha256(b"source\n").hexdigest(),
        }],
    }
    authority = builder._retain_exact_frozen_source_roster(freeze)
    member = tmp_path / "driver"; member.write_bytes(b"driver\n")
    os.chmod(member, 0o400)
    row = {
        "mode": 0o400, "path": "scripts/plamen_driver.py", "size": 7,
        "sha256": hashlib.sha256(b"driver\n").hexdigest(),
    }
    roster = hashlib.sha256(b"PLAMEN-FIXED-ROLE-SOURCE-PROJECTION-V1\0")
    encoded = row["path"].encode("utf-8")
    roster.update(len(encoded).to_bytes(4, "big")); roster.update(encoded)
    roster.update(row["mode"].to_bytes(4, "big"))
    roster.update(row["size"].to_bytes(8, "big"))
    roster.update(bytes.fromhex(row["sha256"]))
    manifest_value = {
        "projection_authority": {
            "schema": "plamen.runtime-source-projection.v1",
            "sha256": "1" * 64, "size": 123,
        },
        "role": "plamen_package", "roster_sha256": roster.hexdigest(),
        "rows": [row], "schema": "plamen.fixed-role-source-projection.v1",
        "source_commit": "2" * 40,
    }
    manifest = tmp_path / "projection"
    manifest.write_bytes(json.dumps(
        manifest_value, sort_keys=True, separators=(",", ":"),
    ).encode("ascii"))
    os.chmod(manifest, 0o400)
    manifest_fd = os.open(manifest, os.O_RDONLY | os.O_CLOEXEC)
    member_fd = os.open(member, os.O_RDONLY | os.O_CLOEXEC)
    try:
        assert authority.seal_projection(
            "plamen_package", manifest_fd, (member_fd,),
        ) is True
    finally:
        os.close(manifest_fd); os.close(member_fd)
    moved = tmp_path / "driver.retained"; member.rename(moved)
    member.write_bytes(b"attack\n"); os.chmod(member, 0o400)
    duplicate = authority.duplicate_projection_member("plamen_package", 0)
    duplicate_manifest = authority.duplicate_projection_manifest(
        "plamen_package"
    )
    try:
        assert os.pread(duplicate, 7, 0) == b"driver\n"
        assert os.stat(duplicate).st_ino == moved.stat().st_ino
        assert os.pread(
            duplicate_manifest, os.fstat(duplicate_manifest).st_size, 0,
        ) == manifest.read_bytes()
    finally:
        os.close(duplicate); os.close(duplicate_manifest)
    with pytest.raises(builder.BuildError, match="seal differs"):
        authority.seal_projection("plamen_package", -1, ())
    assert authority.close() is True
    with pytest.raises(builder.BuildError, match="projection is unavailable"):
        authority.duplicate_projection_manifest("plamen_package")


def test_production_role2_and_role4_projections_are_descriptor_sealed_without_cycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    source_commit = "4" * 40
    runtime_manifest_raw = json.dumps({
        "schema": "plamen.runtime-source-projection.v1",
        "source_commit": source_commit, "state": "FROZEN",
    }, sort_keys=True, separators=(",", ":")).encode("ascii")
    runtime_manifest = tmp_path / "runtime-projection.json"
    runtime_manifest.write_bytes(runtime_manifest_raw); runtime_manifest.chmod(0o400)
    bootstrap = tmp_path / "guest-bootstrap"
    bootstrap.write_bytes(
        b"#!/usr/bin/python3 -I\nimport runpy,sys\n"
        b"sys.path.insert(0,'/opt/plamen/scripts')\n"
        b"runpy.run_path('/opt/plamen/scripts/plamen_driver.py',run_name='__main__')\n"
    )
    bootstrap.chmod(0o400)
    monkeypatch.setattr(builder, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(builder, "PRODUCTION_DARWIN_SOURCE_ROSTER", (
        ("runtime_source_projection_manifest", "runtime-projection.json"),
        ("posix_guest_bootstrap", "guest-bootstrap"),
    ))
    sources = [
        {
            "role": role, "path": path, "size": file.stat().st_size,
            "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
        }
        for role, path, file in (
            ("runtime_source_projection_manifest", "runtime-projection.json", runtime_manifest),
            ("posix_guest_bootstrap", "guest-bootstrap", bootstrap),
        )
    ]
    source_freeze = {
        "schema": builder.PRODUCTION_SOURCE_FREEZE_SCHEMA,
        "manifest_sha256": "5" * 64, "sources": sources,
    }
    source_roster = builder._retain_exact_frozen_source_roster(source_freeze)

    package_root = tmp_path / "snapshot"; package_source = package_root / "package-source"
    driver = package_source / "scripts/plamen_driver.py"
    driver.parent.mkdir(parents=True); driver.write_bytes(b"from plamen_types import SC_PHASES\n")
    driver.chmod(0o400)
    driver.parent.chmod(0o500); package_source.chmod(0o500)
    package_row = {
        "namespace": "package-source", "path": "scripts/plamen_driver.py",
        "mode": 0o400, "size": driver.stat().st_size,
        "sha256": hashlib.sha256(driver.read_bytes()).hexdigest(),
    }
    snapshot_manifest = {
        "schema": "plamen.posix-native-install.package-snapshot.v2",
        "rows": [package_row],
    }
    package_snapshot = {
        **snapshot_manifest, "root": str(package_root),
        "manifest_sha256": hashlib.sha256(_canonical(snapshot_manifest)).hexdigest(),
    }

    extension = tmp_path / "_plamen_native_supervisor.cpython-312-darwin.so"
    extension.write_bytes(b"signed-extension-vnode"); extension.chmod(0o400)
    extension_fd = os.open(extension, os.O_RDONLY | os.O_CLOEXEC)
    extension_info = os.fstat(extension_fd)
    compiled = {"cpython-extension": {
        "artifact": extension.name, "fd": extension_fd,
        "identity": builder._identity(
            extension_info,
            builder._sha256_fd(extension_fd, extension_info.st_size),
        ),
    }}
    private_root = tmp_path / "private"; private_root.mkdir(mode=0o700)
    private_fd = os.open(private_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    class Store:
        used: set[str] = set()

        def pair(self, label, *, linked):
            assert linked is True and label not in self.used
            self.used.add(label)
            writer = os.open(
                label, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600, dir_fd=private_fd,
            )
            reader = os.open(label, os.O_RDONLY | os.O_CLOEXEC, dir_fd=private_fd)
            return writer, reader

    # Substituting the named extension after admission must not affect the
    # retained role-2 member projected into operation 4.
    retained = tmp_path / "extension.retained"
    extension.rename(retained); extension.write_bytes(b"attacker-extension")
    try:
        with pytest.raises(builder.BuildError, match="extension changed"):
            builder._seal_production_fixed_role_source_projections(
                source_freeze=source_freeze, source_roster=source_roster,
                package_snapshot=package_snapshot,
                compiled_artifacts={"cpython-extension": {
                    **compiled["cpython-extension"],
                    "identity": {
                        **compiled["cpython-extension"]["identity"],
                        "sha256": "0" * 64,
                    },
                }}, private_store=Store(),
            )
        result = builder._seal_production_fixed_role_source_projections(
            source_freeze=source_freeze, source_roster=source_roster,
            package_snapshot=package_snapshot, compiled_artifacts=compiled,
            private_store=Store(),
        )
        assert set(result) == {"plamen_guest", "plamen_package"}
        guest_manifest_fd = source_roster.duplicate_projection_manifest(
            "plamen_guest"
        )
        guest_extension_fd = source_roster.duplicate_projection_member(
            "plamen_guest", 0,
        )
        package_member_fd = source_roster.duplicate_projection_member(
            "plamen_package", 0,
        )
        try:
            guest_manifest = json.loads(os.pread(
                guest_manifest_fd, os.fstat(guest_manifest_fd).st_size, 0,
            ))
            assert guest_manifest["source_commit"] == source_commit
            assert [row["path"] for row in guest_manifest["rows"]] == [
                "lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
                "libexec/plamen-guest",
            ]
            serialized = json.dumps(guest_manifest, sort_keys=True)
            assert "operation4" not in serialized.lower()
            assert "source-bootstrap-coordinator" not in serialized
            assert os.pread(
                guest_extension_fd, os.fstat(guest_extension_fd).st_size, 0,
            ) == b"signed-extension-vnode"
            assert os.pread(
                package_member_fd, os.fstat(package_member_fd).st_size, 0,
            ) == driver.read_bytes()
        finally:
            os.close(guest_manifest_fd); os.close(guest_extension_fd)
            os.close(package_member_fd)
    finally:
        source_roster.close(); os.close(extension_fd); os.close(private_fd)


def test_native_acquisition_custody_closes_when_effect_construction_fails(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    home = tmp_path / "account"; home.mkdir()

    class Session:
        _PLAMEN_RETAINED_NATIVE_TRANSACTION_V1 = True
        closed = False

        def close(self):
            self.closed = True
            return True

    session = Session()
    defaults = builder._production_native_builder_callbacks()
    callbacks = MappingProxyType({
        **dict(defaults),
        "prepare_production_native_transaction": lambda **_values: session,
    })

    class Package:
        _FROZEN_PACKAGE_FRONT_STDLIB_ONLY = True
        _install_codex_package_transaction = staticmethod(lambda **_values: {})
        _rollback_committed_codex_package_transaction = staticmethod(
            lambda *_args, **_values: True
        )

    def reject(**_values):
        raise RuntimeError("fixture constructor rejection")

    with pytest.raises(RuntimeError, match="fixture constructor rejection"):
        builder._create_production_cold_install_effects(
            home=home, source_freeze={"schema": "fixture.freeze"},
            source_authority={"schema": "fixture.authority"},
            package_snapshot={"schema": "fixture.snapshot"},
            builder_callbacks=callbacks,
            cold_stack={
                "publication": object(), "transaction": object(),
                "effects": type(
                    "Effects", (), {"DarwinColdInstallEffects": reject},
                ),
                "package": Package,
            },
        )
    assert session.closed is True
    assert list(home.iterdir()) == []


def test_source_install_transaction_loads_exact_frozen_default_stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    home = tmp_path / "account"; home.mkdir()
    freeze = {"schema": "fixture.freeze"}
    authority = {"schema": "fixture.authority"}
    snapshot = {"schema": "fixture.snapshot"}
    effects = object()
    events: list[str] = []

    class Coordinator:
        @staticmethod
        def source_authority_from_validated_freeze(root, observed):
            assert root == builder.REPOSITORY_ROOT
            assert observed is freeze
            events.append("authority")
            return authority

        @staticmethod
        def execute_cold_install_transaction(
            *, home, source_authority, effects,
        ):
            assert home == home_path
            assert source_authority is authority
            assert effects is effects_value
            events.append("execute")
            return {"schema": "fixture.terminal"}

    home_path = home
    effects_value = effects
    stack = {
        "publication": object(), "transaction": Coordinator,
        "effects": object(), "package": object(),
    }
    monkeypatch.setattr(
        builder, "_load_exact_production_source_freeze", lambda: freeze,
    )
    monkeypatch.setattr(
        builder, "_load_frozen_cold_install_stack",
        lambda observed: stack if observed is freeze else None,
    )

    def create(**values):
        assert values["cold_stack"] is stack
        assert values["source_freeze"] is freeze
        assert values["source_authority"] is authority
        assert values["package_snapshot"] is snapshot
        assert values["home"] == home
        events.append("effects")
        return effects

    monkeypatch.setattr(
        builder, "_create_production_cold_install_effects", create,
    )
    result = builder._execute_native_source_install_transaction(
        _transaction_ready_observation(builder), home=home,
        package_snapshot_factory=lambda *_args: snapshot,
    )
    assert result == {"schema": "fixture.terminal"}
    assert events == ["authority", "effects", "execute"]


def test_source_install_transaction_rejects_partial_stack_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    freeze = {"schema": "fixture.freeze"}
    monkeypatch.setattr(
        builder, "_load_exact_production_source_freeze", lambda: freeze,
    )
    with pytest.raises(builder.BuildError, match="selection is partial"):
        builder._execute_native_source_install_transaction(
            _transaction_ready_observation(builder), home=tmp_path,
            coordinator_module=object(), effects_factory=None,
        )


def test_retained_native_executable_rejects_path_substitution(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    executable = tmp_path / "native-helper"
    executable.write_bytes(b"first-helper")
    executable.chmod(0o500)
    descriptor = os.open(
        executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        assert builder._retained_executable_argv(
            executable, descriptor, "fixture helper",
        ) == (
            str(executable)
            if sys.platform == "darwin" else builder._fd_path(descriptor)
        )
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"second-helper")
        replacement.chmod(0o500)
        os.replace(replacement, executable)
        with pytest.raises(builder.BuildError, match="authority differs"):
            builder._retained_executable_argv(
                executable, descriptor, "fixture helper",
            )
    finally:
        os.close(descriptor)
    executable.chmod(0o700)
    writable = os.open(
        executable, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        with pytest.raises(builder.BuildError, match="authority differs"):
            builder._retained_executable_argv(
                executable, writable, "fixture helper",
            )
    finally:
        os.close(writable)


def test_native_prepare_publish_uses_source_bootstrap_fd_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    executable = tmp_path / "coordinator"; executable.write_bytes(b"native")
    descriptors: list[int] = []
    for index in range(19):
        path = tmp_path / f"fd-{index}"
        path.write_bytes(bytes([index + 1]))
        descriptors.append(os.open(path, os.O_RDONLY | os.O_CLOEXEC))
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = b""
        stderr = b""

    def run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["pass_fds"] = tuple(kwargs["pass_fds"])
        return Completed()

    monkeypatch.setattr(builder.subprocess, "run", run)
    identities = [
        {
            "identifier": builder.PRODUCTION_DARWIN_SIGNING_IDENTIFIERS[name],
            "team": "", "cdhash": format(index + 1, "040x"),
        }
        for index, name in enumerate((
            "launcher", "service", "extension", "installer", "source_bootstrap",
        ))
    ] + [{
        "identifier": "org.python.python", "team": "",
        "cdhash": "6" * 40,
    }]
    try:
        builder._run_native_prepare_publish_cli(
            executable, install_root_fd=descriptors[0],
            staging_parent_fd=descriptors[1], runtime_root_fd=descriptors[2],
            receipt_output_fd=descriptors[3],
            broker_plist_output_fd=descriptors[4],
            custody_plist_output_fd=descriptors[5],
            install_root=tmp_path, staged_name="stage",
            generation_id=None, projection_schema_sha256="1" * 64,
            protocol_schema_sha256="2" * 64,
            runtime_bindings=_runtime_bindings(builder),
            member_fds=descriptors[6:16], signed_identities=identities,
            retain_postcommit=True,
            source_bootstrap_receipt_fd=descriptors[16],
            source_bootstrap_producer_verifier_key_fd=descriptors[17],
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    argv = captured["argv"]
    assert argv[1] == "prepare-publish-retained-source-bootstrap-derived-fds"
    assert argv[40:42] == [str(descriptors[16]), str(descriptors[17])]
    assert set(captured["pass_fds"]) == set(descriptors[:18])


def test_native_prepare_publish_uses_authenticated_source_resume_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    executable = tmp_path / "coordinator"; executable.write_bytes(b"native")
    descriptors = []
    for index in range(20):
        path = tmp_path / f"resume-fd-{index}"
        path.write_bytes(bytes([index + 1]))
        descriptors.append(os.open(path, os.O_RDONLY | os.O_CLOEXEC))
    calls: list[list[str]] = []

    class Completed:
        returncode = 0
        stdout = b""
        stderr = b""

    monkeypatch.setattr(
        builder.subprocess, "run",
        lambda argv, **_kwargs: (calls.append(list(argv)) or Completed()),
    )
    identities = [
        {
            "identifier": builder.PRODUCTION_DARWIN_SIGNING_IDENTIFIERS[name],
            "team": "", "cdhash": format(index + 1, "040x"),
        }
        for index, name in enumerate((
            "launcher", "service", "extension", "installer", "source_bootstrap",
        ))
    ] + [{
        "identifier": "org.python.python", "team": "", "cdhash": "6" * 40,
    }]
    try:
        builder._run_native_prepare_publish_cli(
            executable, install_root_fd=descriptors[0],
            staging_parent_fd=descriptors[1], runtime_root_fd=descriptors[2],
            receipt_output_fd=descriptors[3],
            broker_plist_output_fd=descriptors[4],
            custody_plist_output_fd=descriptors[5], install_root=tmp_path,
            staged_name="resume-stage", generation_id=None,
            projection_schema_sha256="1" * 64,
            protocol_schema_sha256="2" * 64,
            runtime_bindings=_runtime_bindings(builder),
            member_fds=descriptors[6:16], signed_identities=identities,
            image_member_rows_fd=descriptors[16],
            image_receipt_output_fd=descriptors[17],
            specialized_policy_self_sha256="3" * 64,
            specialized_policy_bytes_sha256="4" * 64,
            source_bootstrap_receipt_fd=descriptors[18],
            source_bootstrap_producer_verifier_key_fd=descriptors[19],
            resume_specialized=True,
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    assert calls[0][1] == (
        "resume-publish-specialized-source-bootstrap-derived-fds"
    )


def test_source_install_transaction_rejects_forged_admission_before_freeze(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    report = _transaction_ready_observation(builder)
    report["blockers"] = sorted([
        *report["blockers"], "SOURCE_FREEZE_MANIFEST_UNAVAILABLE",
    ])
    report["transaction_admission_blockers"] = ["SOURCE_FREEZE_MANIFEST_UNAVAILABLE"]
    report["production_build_allowed"] = False
    unsigned = dict(report); unsigned.pop("observation_sha256")
    report["observation_sha256"] = hashlib.sha256(_canonical(unsigned)).hexdigest()
    replayed = False

    def forbidden_freeze():
        nonlocal replayed
        replayed = True
        raise AssertionError("freeze replay must not run")

    monkeypatch.setattr(builder, "_load_exact_production_source_freeze", forbidden_freeze)
    with pytest.raises(builder.BuildError, match="prerequisite blockers"):
        builder._execute_native_source_install_transaction(report, home=tmp_path)
    assert replayed is False


def test_retained_cpython_rejects_substitution_after_code_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if sys.platform != "darwin" or os.uname().machine != "arm64" or sys.version_info[:2] != (3, 12):
        pytest.skip("production CPython boundary is Darwin arm64 3.12")
    builder = _load_builder()
    executable = tmp_path / "python3.12"
    executable.write_bytes(b"first-python-image"); executable.chmod(0o700)

    def retained(_path, _label):
        fd = os.open(executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        info = os.fstat(fd)
        return fd, executable, {
            "path": str(executable), **builder._identity(
                info, builder._sha256_fd(fd, info.st_size),
            ),
        }

    def mutate(_path, _label, *, retained_fd=None):
        assert retained_fd is not None
        executable.write_bytes(b"second-python-image")
        return {"identifier": "org.python.python", "team": "", "cdhash": "a" * 40}

    monkeypatch.setattr(builder, "_open_retained_regular", retained)
    monkeypatch.setattr(builder, "_darwin_ad_hoc_code_identity", mutate)
    with pytest.raises(builder.BuildError, match="changed before retained handoff"):
        builder._retain_production_cpython_312()


def test_native_installed_receipt_cli_uses_only_retained_receipt_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "native-root"; root.mkdir()
    executable = tmp_path / "coordinator"; executable.write_bytes(b"native")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    successor = os.open(executable, os.O_RDONLY)
    prior = os.dup(successor)
    calls: list[tuple[list[str], tuple[int, ...]]] = []

    class Completed:
        returncode = 0
        stdout = b""
        stderr = b""

    def run(argv, **kwargs):
        calls.append((list(argv), tuple(kwargs["pass_fds"])))
        assert kwargs["close_fds"] is True
        return Completed()

    monkeypatch.setattr(builder.subprocess, "run", run)
    try:
        builder._run_native_installed_receipt_cli(
            executable, "validate", install_root_fd=root_fd,
            install_root=root, successor_receipt_fd=successor,
        )
        builder._run_native_installed_receipt_cli(
            executable, "rollback", install_root_fd=root_fd,
            install_root=root, successor_receipt_fd=successor,
            prior_receipt_fd=prior,
        )
    finally:
        os.close(prior); os.close(successor); os.close(root_fd)
    assert calls[0] == ([
        str(executable), "validate-installed-fd", str(root_fd),
        str(successor), str(root),
    ], (root_fd, successor))
    assert calls[1] == ([
        str(executable), "rollback-committed-fds", str(root_fd),
        str(successor), str(prior), str(root),
    ], (root_fd, successor, prior))


def test_native_evm_static_cli_has_exact_retained_fd_abi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    executable = tmp_path / "source-bootstrap-coordinator"
    executable.write_bytes(b"native")
    root = tmp_path / "private-generation"; root.mkdir(mode=0o700)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    inputs = [os.open(executable, os.O_RDONLY) for _ in range(4)]
    calls = []

    class Completed:
        returncode = 0
        stdout = b""
        stderr = b""

    def run(argv, **kwargs):
        calls.append((list(argv), tuple(kwargs["pass_fds"])))
        assert kwargs["close_fds"] is True
        assert kwargs["env"] == builder._CLOSED_ENV
        return Completed()

    monkeypatch.setattr(builder.subprocess, "run", run)
    try:
        assert builder._run_native_evm_static_acquisition_cli(
            executable, staged_generation_root_fd=root_fd,
            medusa_archive_fd=inputs[0],
            medusa_sigstore_bundle_fd=inputs[1],
            solc_provider_index_fd=inputs[2], solc_binary_fd=inputs[3],
        ) is True
    finally:
        for descriptor in inputs:
            os.close(descriptor)
        os.close(root_fd)
    assert calls == [([
        str(executable), "sign-evm-static-v1", str(root_fd),
        *(str(descriptor) for descriptor in inputs),
    ], (root_fd, *inputs))]

    with pytest.raises(builder.BuildError, match="descriptor roster"):
        builder._run_native_evm_static_acquisition_cli(
            executable, staged_generation_root_fd=3,
            medusa_archive_fd=4, medusa_sigstore_bundle_fd=5,
            solc_provider_index_fd=6, solc_binary_fd=6,
        )


def test_native_fixed_role_runner_is_loaded_only_from_frozen_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    freeze = {"schema": "fixture.freeze"}
    inputs = tuple(object() for _ in range(7))
    records = tuple(object() for _ in range(7))
    captured: dict[str, object] = {}

    class FrozenAdapter:
        @staticmethod
        def run_native_fixed_role_issue_cli(**values):
            captured.update(values)
            return records

    def load(module_name, role, source_freeze):
        assert module_name == "_plamen_frozen_native_fixed_role_acquisition"
        assert role == "native_fixed_role_acquisition"
        assert source_freeze is freeze
        return FrozenAdapter

    monkeypatch.setattr(builder, "_load_frozen_source_module", load)
    assert builder._run_native_fixed_role_acquisition_cli(
        Path("/private/native/source-bootstrap"),
        source_freeze=freeze, executable_fd=30,
        staged_generation_root_fd=31, inputs=inputs,
        timeout_seconds=29,
    ) is records
    assert captured == {
        "executable_fd": 30,
        "executable_path": (
            "/private/native/source-bootstrap"
            if sys.platform == "darwin" else None
        ),
        "staged_generation_root_fd": 31,
        "inputs": inputs, "timeout_seconds": 29,
    }
    assert callable(
        builder._production_native_builder_callbacks()[
            "run_native_fixed_role_acquisition"
        ]
    )

    class MissingAdapter:
        pass

    monkeypatch.setattr(
        builder, "_load_frozen_source_module",
        lambda *_args, **_kwargs: MissingAdapter,
    )
    with pytest.raises(builder.BuildError, match="adapter is absent"):
        builder._run_native_fixed_role_acquisition_cli(
            Path("/private/native/source-bootstrap"),
            source_freeze=freeze, executable_fd=30,
            staged_generation_root_fd=31, inputs=inputs,
        )


def test_native_source_bootstrap_issue_cli_has_exact_argc80_fd_abi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    executable = tmp_path / "source-bootstrap-coordinator"
    executable.write_bytes(b"native")
    descriptors = [os.open(executable, os.O_RDONLY) for _ in range(78)]
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = b""
        stderr = b""

    def run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["pass_fds"] = tuple(kwargs["pass_fds"])
        assert kwargs["close_fds"] is True
        assert kwargs["env"] == builder._CLOSED_ENV
        return Completed()

    monkeypatch.setattr(builder.subprocess, "run", run)
    try:
        assert builder._run_native_source_bootstrap_issue_cli(
            executable,
            runtime_root_fd=descriptors[0], python_fd=descriptors[1],
            transform_fd=descriptors[2],
            producer_verifier_key_fd=descriptors[3],
            composition_manifest_fd=descriptors[4],
            role_fds=[
                tuple(descriptors[5 + index * 3:8 + index * 3])
                for index in range(11)
            ],
            output_pairs=[
                tuple(descriptors[38 + index * 2:40 + index * 2])
                for index in range(5)
            ],
            scratch_fds=descriptors[48:72],
            coordinator_receipt_pair=tuple(descriptors[72:74]),
            grouped_operation_pair=tuple(descriptors[74:76]),
            operation_terminal_pair=tuple(descriptors[76:78]),
        ) is True
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    assert captured["argv"] == [
        str(executable), "issue-v1", *(str(fd) for fd in descriptors),
    ]
    assert len(captured["argv"]) == 80
    assert captured["pass_fds"] == tuple(descriptors)

    with pytest.raises(builder.BuildError, match="descriptor roster"):
        builder._run_native_source_bootstrap_issue_cli(
            executable, runtime_root_fd=3, python_fd=4, transform_fd=5,
            producer_verifier_key_fd=6, composition_manifest_fd=7,
            role_fds=[(8 + index * 3, 9 + index * 3, 10 + index * 3)
                      for index in range(11)],
            output_pairs=[(50 + index * 2, 51 + index * 2)
                          for index in range(5)],
            scratch_fds=list(range(60, 84)),
            coordinator_receipt_pair=(84, 85),
            grouped_operation_pair=(86, 87),
            operation_terminal_pair=(88, 88),
        )


def test_native_backend_signer_cli_has_exact_argc14_fd_abi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    executable = tmp_path / "source-bootstrap-coordinator"
    executable.write_bytes(b"native")
    descriptors = [os.open(executable, os.O_RDONLY) for _ in range(12)]
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = b""
        stderr = b""

    def run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["pass_fds"] = tuple(kwargs["pass_fds"])
        return Completed()

    monkeypatch.setattr(builder.subprocess, "run", run)
    try:
        assert builder._run_native_backend_receipt_signer_cli(
            executable, public_key_pair=tuple(descriptors[:2]),
            backend_rows=[tuple(descriptors[2:7]), tuple(descriptors[7:12])],
        ) is True
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    assert captured["argv"] == [
        str(executable), "sign-backends-v1",
        *(str(fd) for fd in descriptors),
    ]
    assert len(captured["argv"]) == 14
    assert captured["pass_fds"] == tuple(descriptors)

    with pytest.raises(builder.BuildError, match="descriptor roster"):
        builder._run_native_backend_receipt_signer_cli(
            executable, public_key_pair=(3, 4),
            backend_rows=[(5, 6, 7, 8, 9), (10, 11, 12, 13, 13)],
        )
    assert callable(
        builder._production_native_builder_callbacks()[
            "issue_production_native_backend_roles"
        ]
    )


def test_production_backend_roles_are_native_signed_rebound_and_path_swap_safe(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    policy_value = {
        "schema": "plamen.native-backend-acquisition.v2",
        "selectors": ["codex", "claude"],
    }
    policy_raw = _canonical(policy_value)
    policy = tmp_path / "policy.json"; policy.write_bytes(policy_raw)
    policy.chmod(0o400)
    source_freeze = {
        "schema": builder.PRODUCTION_SOURCE_FREEZE_SCHEMA,
        "sources": [{
            "role": "native_backend_latest_acquisition_policy",
            "path": "policy.json", "size": len(policy_raw),
            "sha256": hashlib.sha256(policy_raw).hexdigest(),
        }],
    }

    class Roster:
        _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True

        @staticmethod
        def duplicate_member(role):
            assert role == "native_backend_latest_acquisition_policy"
            return os.open(policy, os.O_RDONLY | os.O_CLOEXEC)

    coordinator = tmp_path / "source-bootstrap-coordinator"
    coordinator.write_bytes(b"native-signer"); coordinator.chmod(0o500)
    coordinator_fd = os.open(coordinator, os.O_RDONLY | os.O_CLOEXEC)
    private_root = tmp_path / "private"; private_root.mkdir(mode=0o700)
    private_fd = os.open(
        private_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
    )

    class Store:
        used: set[str] = set()

        def pair(self, label, *, linked):
            assert linked is True and label not in self.used
            self.used.add(label)
            writer = os.open(
                label, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600, dir_fd=private_fd,
            )
            reader = os.open(
                label, os.O_RDONLY | os.O_CLOEXEC, dir_fd=private_fd,
            )
            return writer, reader

    input_paths: list[Path] = []
    input_fds: list[int] = []
    rows: list[dict[str, object]] = []
    for role, selector in ((5, "codex"), (6, "claude")):
        values: dict[str, int] = {}
        for field, raw in (
            ("unsigned_receipt_fd", json.dumps({
                "schema": "fixture.backend", "selector": selector,
            }, sort_keys=True, separators=(",", ":")).encode("ascii")),
            ("payload_fd", f"{selector}-retained-payload".encode("ascii")),
            ("source_manifest_fd", f"{selector}-source-manifest".encode("ascii")),
        ):
            path = tmp_path / f"{selector}-{field}"
            path.write_bytes(raw); path.chmod(0o400)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            input_paths.append(path); input_fds.append(descriptor)
            values[field] = descriptor
        rows.append({"selector": selector, "role": role, **values})

    class Inputs:
        _PLAMEN_PRODUCTION_BACKEND_INPUTS_V1 = True

        def __init__(self):
            self.closed = False

        def records(self):
            return tuple(dict(row) for row in rows)

        def close(self):
            if not self.closed:
                self.closed = True
                for descriptor in input_fds:
                    os.close(descriptor)
            return True

    inputs = Inputs()
    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signed_messages: dict[str, bytes] = {}

    def run_signer(
        executable, *, public_key_pair, backend_rows, executable_fd,
    ):
        assert executable == coordinator and executable_fd == coordinator_fd
        os.write(public_key_pair[0], public_raw)
        os.fchmod(public_key_pair[0], 0o400)
        for expected, fds in zip(rows, backend_rows, strict=True):
            unsigned = json.loads(os.pread(
                fds[0], os.fstat(fds[0]).st_size, 0,
            ))
            signing_raw = ("native:" + expected["selector"]).encode("ascii")
            signed_messages[expected["selector"]] = signing_raw
            unsigned["authentication"] = {
                "key_id": hashlib.sha256(public_raw).hexdigest(),
                "signature": private_key.sign(signing_raw).hex(),
            }
            semantic = json.dumps(
                unsigned, sort_keys=True, separators=(",", ":"),
            ).encode("ascii") + b"PLMOP4R1" + bytes(504)
            os.write(fds[3], semantic); os.fchmod(fds[3], 0o400)
        return True

    admitted_payloads: dict[str, bytes] = {}

    def bind(**values):
        selector = values["receipt"]["selector"]
        assert values["verifier"](
            signed_messages[selector], values["receipt"]["authentication"],
        ) is True
        payload_fd = values["payload_fd"]
        admitted_payloads[selector] = os.pread(
            payload_fd, os.fstat(payload_fd).st_size, 0,
        )
        generation = type("Generation", (), {"selector": selector})()
        return type("Authority", (), {
            "generation": generation, "payload_fd": payload_fd,
            "semantic_receipt_fd": values["semantic_receipt_fd"],
            "source_manifest_fd": values["source_manifest_fd"],
            "verifier_public_key_fd": values["verifier_public_key_fd"],
        })()

    # Swap both payload names after descriptor admission.  Role construction
    # must continue to authenticate the original retained vnodes.
    for path in input_paths:
        if path.name.endswith("payload_fd"):
            retained = path.with_suffix(".retained")
            path.rename(retained); path.write_bytes(b"attacker-substitution")
            path.chmod(0o400)
    callbacks = MappingProxyType({
        "run_native_backend_receipt_signer": run_signer,
        "bind_retained_backend_generation": bind,
    })
    try:
        authority = builder._issue_production_native_backend_roles(
            source_freeze=source_freeze, source_roster=Roster(),
            compiled_artifacts={"retained-source-bootstrap-coordinator": {
                "path": coordinator, "fd": coordinator_fd,
            }}, private_store=Store(), input_authority=inputs,
            builder_callbacks=callbacks,
        )
        records = authority.role_records()
        assert [(row["role"], row["selector"]) for row in records] == [
            (5, "codex"), (6, "claude"),
        ]
        assert admitted_payloads == {
            "codex": b"codex-retained-payload",
            "claude": b"claude-retained-payload",
        }
        owned = [
            records[0]["producer_receipt_fd"],
            records[1]["producer_receipt_fd"],
            records[0]["authority"].verifier_public_key_fd,
        ]
        semantic_path = private_root / "backend-codex-semantic-receipt"
        semantic_path.chmod(0o600)
        with semantic_path.open("r+b", buffering=0) as stream:
            stream.write(b"X")
        with pytest.raises(builder.BuildError, match="descriptor changed"):
            authority.role_records()
        assert authority.close() is True
        assert authority.close() is True
        assert inputs.closed is True
        for descriptor in [*input_fds, *owned]:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        if not inputs.closed:
            inputs.close()
        os.close(coordinator_fd); os.close(private_fd)


def test_production_backend_role_signer_failure_closes_every_retained_fd(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    policy_raw = _canonical({
        "schema": "plamen.native-backend-acquisition.v2",
    })
    policy = tmp_path / "policy"; policy.write_bytes(policy_raw); policy.chmod(0o400)
    source_freeze = {"sources": [{
        "role": "native_backend_latest_acquisition_policy",
        "size": len(policy_raw), "sha256": hashlib.sha256(policy_raw).hexdigest(),
    }]}

    class Roster:
        _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True

        @staticmethod
        def duplicate_member(_role):
            return os.open(policy, os.O_RDONLY | os.O_CLOEXEC)

    retained: list[int] = []
    rows = []
    for role, selector in ((5, "codex"), (6, "claude")):
        row = {"selector": selector, "role": role}
        for field in (
            "unsigned_receipt_fd", "payload_fd", "source_manifest_fd",
        ):
            path = tmp_path / f"{selector}-{field}"
            path.write_bytes(field.encode("ascii")); path.chmod(0o400)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            retained.append(descriptor); row[field] = descriptor
        rows.append(row)

    class Inputs:
        _PLAMEN_PRODUCTION_BACKEND_INPUTS_V1 = True
        closed = False

        @staticmethod
        def records():
            return tuple(dict(row) for row in rows)

        def close(self):
            if not self.closed:
                self.closed = True
                for descriptor in retained:
                    os.close(descriptor)
            return True

    outputs: list[int] = []
    private_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    class Store:
        index = 0

        def pair(self, _label, *, linked):
            assert linked is True
            self.index += 1
            name = f"output-{self.index}"
            writer = os.open(
                name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600, dir_fd=private_fd,
            )
            reader = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=private_fd)
            outputs.extend((writer, reader))
            return writer, reader

    coordinator = tmp_path / "coordinator"
    coordinator.write_bytes(b"native"); coordinator.chmod(0o500)
    coordinator_fd = os.open(coordinator, os.O_RDONLY | os.O_CLOEXEC)
    inputs = Inputs()
    try:
        with pytest.raises(RuntimeError, match="injected signer failure"):
            builder._issue_production_native_backend_roles(
                source_freeze=source_freeze, source_roster=Roster(),
                compiled_artifacts={"retained-source-bootstrap-coordinator": {
                    "path": coordinator, "fd": coordinator_fd,
                }}, private_store=Store(), input_authority=inputs,
                builder_callbacks=MappingProxyType({
                    "run_native_backend_receipt_signer": (
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(
                            RuntimeError("injected signer failure")
                        )
                    ),
                    "bind_retained_backend_generation": lambda **_values: None,
                }),
            )
        assert inputs.closed is True
        for descriptor in [*retained, *outputs]:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        if not inputs.closed:
            inputs.close()
        os.close(coordinator_fd); os.close(private_fd)


def test_production_evm_static_upstreams_are_exact_anonymous_and_one_owner(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    payloads = {
        "https://github.com/example/medusa.tar.gz": b"medusa-archive",
        "https://github.com/example/medusa.sigstore.json": b"sigstore",
        "https://binaries.soliditylang.org/linux-amd64/list.json": b"solc-index",
        "https://binaries.soliditylang.org/linux-amd64/solc": b"solc-binary",
    }

    def identity(url):
        raw = payloads[url]
        return {"url": url, "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}

    policies = {
        "medusa_acquisition_policy": _canonical({
            "artifact": {
                "archive": identity("https://github.com/example/medusa.tar.gz"),
                "sigstore": {"bundle": identity(
                    "https://github.com/example/medusa.sigstore.json"
                )},
            },
            "schema": "plamen.medusa-acquisition.v1",
        }),
        "solc_amd64_acquisition_policy": _canonical({
            "artifact": {
                "provider_index": identity(
                    "https://binaries.soliditylang.org/linux-amd64/list.json"
                ),
                "binary": identity(
                    "https://binaries.soliditylang.org/linux-amd64/solc"
                ),
            },
            "schema": "plamen.solc-amd64-acquisition-policy.v1",
        }),
    }
    paths = {}
    source_rows = []
    for role, raw in policies.items():
        path = tmp_path / role; path.write_bytes(raw); path.chmod(0o400)
        paths[role] = path
        source_rows.append({
            "role": role, "path": path.name, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })

    class Roster:
        _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True

        @staticmethod
        def duplicate_member(role):
            return os.open(paths[role], os.O_RDONLY | os.O_CLOEXEC)

    private_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    allocated: list[int] = []

    class Store:
        index = 0

        def pair(self, _label, *, linked):
            assert linked is False
            self.index += 1
            name = f"anonymous-{self.index}"
            writer = os.open(
                name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600, dir_fd=private_fd,
            )
            reader = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=private_fd)
            os.unlink(name, dir_fd=private_fd)
            allocated.extend((writer, reader))
            return writer, reader

    calls = []

    def fetch(url, **values):
        raw = payloads[url]
        calls.append((url, dict(values)))
        assert values["expected_size"] == len(raw)
        assert values["expected_sha256"] == hashlib.sha256(raw).hexdigest()
        assert os.fstat(values["writer_fd"]).st_nlink == 0
        os.write(values["writer_fd"], raw)
        return True

    authority = builder._acquire_production_evm_static_upstreams(
        source_freeze={"sources": source_rows}, source_roster=Roster(),
        private_store=Store(), builder_callbacks=MappingProxyType({
            "fetch_exact_setup_upstream": fetch,
        }),
    )
    descriptors = authority.descriptors()
    try:
        assert tuple(
            os.pread(fd, os.fstat(fd).st_size, 0) for fd in descriptors
        ) == tuple(payloads.values())
        assert all(os.fstat(fd).st_nlink == 0 for fd in descriptors)
        assert [url for url, _values in calls] == list(payloads)
        assert calls[0][1]["initial_host"] == "github.com"
        assert "release-assets.githubusercontent.com" in (
            calls[0][1]["redirect_hosts"]
        )
        assert calls[-1][1]["initial_host"] == "binaries.soliditylang.org"
    finally:
        assert authority.close() is True
        assert authority.close() is True
        os.close(private_fd)
    for descriptor in allocated:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert callable(
        builder._production_native_builder_callbacks()[
            "acquire_production_evm_static_upstreams"
        ]
    )


def test_production_evm_static_upstream_failure_closes_partial_custody(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    values = {
        "artifact": {
            "archive": {"url": "https://github.com/a", "size": 1,
                        "sha256": hashlib.sha256(b"a").hexdigest()},
            "sigstore": {"bundle": {
                "url": "https://github.com/b", "size": 1,
                "sha256": hashlib.sha256(b"b").hexdigest(),
            }},
        },
        "schema": "plamen.medusa-acquisition.v1",
    }
    solc = {
        "artifact": {
            "provider_index": {
                "url": "https://binaries.soliditylang.org/i", "size": 1,
                "sha256": hashlib.sha256(b"i").hexdigest(),
            },
            "binary": {
                "url": "https://binaries.soliditylang.org/s", "size": 1,
                "sha256": hashlib.sha256(b"s").hexdigest(),
            },
        },
        "schema": "plamen.solc-amd64-acquisition-policy.v1",
    }
    paths = {}
    rows = []
    for role, value in (
        ("medusa_acquisition_policy", values),
        ("solc_amd64_acquisition_policy", solc),
    ):
        raw = _canonical(value); path = tmp_path / role
        path.write_bytes(raw); path.chmod(0o400); paths[role] = path
        rows.append({"role": role, "size": len(raw),
                     "sha256": hashlib.sha256(raw).hexdigest()})

    class Roster:
        _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True

        @staticmethod
        def duplicate_member(role):
            return os.open(paths[role], os.O_RDONLY | os.O_CLOEXEC)

    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    allocated = []

    class Store:
        index = 0

        def pair(self, _label, *, linked):
            assert linked is False
            self.index += 1
            name = f"fault-{self.index}"
            writer = os.open(
                name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600, dir_fd=root_fd,
            )
            reader = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=root_fd)
            os.unlink(name, dir_fd=root_fd)
            allocated.extend((writer, reader))
            return writer, reader

    count = 0

    def fail_second(_url, **values):
        nonlocal count
        count += 1
        if count == 2:
            raise RuntimeError("injected acquisition failure")
        os.write(values["writer_fd"], b"a")
        return True

    try:
        with pytest.raises(RuntimeError, match="injected acquisition failure"):
            builder._acquire_production_evm_static_upstreams(
                source_freeze={"sources": rows}, source_roster=Roster(),
                private_store=Store(), builder_callbacks=MappingProxyType({
                    "fetch_exact_setup_upstream": fail_second,
                }),
            )
        for descriptor in allocated:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        os.close(root_fd)


def test_production_evm_static_native_issue_replays_exact_leaves_and_footer(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    role_values = {
        8: {
            "name": "medusa", "validator": 6,
            "policy_role": "medusa_acquisition_policy",
            "receipt_role": "medusa_acquisition_receipt",
            "manifest_role": "medusa_runtime_source_manifest",
            "receipt_schema": "plamen.medusa-acquisition-receipt.v1",
            "payload": b"medusa-executable",
        },
        9: {
            "name": "solc_amd64", "validator": 7,
            "policy_role": "solc_amd64_acquisition_policy",
            "receipt_role": "solc_amd64_acquisition_receipt",
            "manifest_role": "solc_amd64_runtime_source_manifest",
            "receipt_schema": "plamen.solc-amd64-acquisition-receipt.v1",
            "payload": b"solc-executable",
        },
    }
    sources = []
    paths = {}
    frozen_bytes = {}
    for ordinal, value in role_values.items():
        payload = value["payload"]
        executable = {
            "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
        }
        policy = {
            "artifact": {
                ("executable" if ordinal == 8 else "binary"): executable,
            },
            "schema": (
                "plamen.medusa-acquisition.v1" if ordinal == 8
                else "plamen.solc-amd64-acquisition-policy.v1"
            ),
        }
        receipt = {
            "role": value["name"], "schema": value["receipt_schema"],
        }
        manifest = {
            "payload_sha256": executable["sha256"],
            "schema": "plamen.runtime_source_manifest.native-retained.v1",
        }
        for role, raw in (
            (value["policy_role"], _canonical(policy)),
            (value["receipt_role"], _canonical(receipt)[:-1]),
            (value["manifest_role"], _canonical(manifest)),
        ):
            path = tmp_path / role; path.write_bytes(raw); path.chmod(0o400)
            paths[role] = path; frozen_bytes[role] = raw
            sources.append({
                "role": role, "path": path.name, "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })

    class Roster:
        _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True

        @staticmethod
        def duplicate_member(role):
            return os.open(paths[role], os.O_RDONLY | os.O_CLOEXEC)

    upstream_fds = []
    for index in range(4):
        name = tmp_path / f"upstream-{index}"
        name.write_bytes(bytes([65 + index])); name.chmod(0o400)
        upstream_fds.append(os.open(name, os.O_RDONLY | os.O_CLOEXEC))

    class Upstreams:
        _PLAMEN_RETAINED_EVM_STATIC_UPSTREAMS_V1 = True

        def __init__(self):
            self.closed = False

        def descriptors(self):
            return tuple(upstream_fds)

        def close(self):
            if not self.closed:
                self.closed = True
                for descriptor in upstream_fds:
                    os.close(descriptor)
            return True

    upstreams = Upstreams()
    stage = tmp_path / "stage"; stage.mkdir(mode=0o700)
    stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    coordinator = tmp_path / "coordinator"
    coordinator.write_bytes(b"native"); coordinator.chmod(0o500)
    coordinator_fd = os.open(coordinator, os.O_RDONLY | os.O_CLOEXEC)

    def issue(executable, **values):
        assert executable == coordinator
        assert values["executable_fd"] == coordinator_fd
        assert values["staged_generation_root_fd"] == stage_fd
        assert tuple(values[key] for key in (
            "medusa_archive_fd", "medusa_sigstore_bundle_fd",
            "solc_provider_index_fd", "solc_binary_fd",
        )) == tuple(upstream_fds)
        authority_root = stage / "share/plamen/native-source-authority-v1"
        authority_root.mkdir(parents=True, mode=0o700)
        for ordinal, row in role_values.items():
            policy_raw = frozen_bytes[row["policy_role"]]
            receipt_raw = frozen_bytes[row["receipt_role"]]
            manifest_raw = frozen_bytes[row["manifest_role"]]
            payload = row["payload"]
            footer = bytearray(512)
            footer[:8] = b"PLMOP4R1"
            struct.pack_into(">HHHHH", footer, 8, 1, 512, ordinal, 1,
                             row["validator"])
            struct.pack_into(">QQQ", footer, 20, len(payload),
                             len(manifest_raw), len(receipt_raw))
            footer[44:76] = hashlib.sha256(policy_raw).digest()
            footer[76:108] = hashlib.sha256(payload).digest()
            footer[108:140] = hashlib.sha256(manifest_raw).digest()
            footer[140:172] = hashlib.sha256(receipt_raw).digest()
            schema = row["receipt_schema"].encode("ascii")
            footer[172:172 + len(schema)] = schema
            footer[480:] = hashlib.sha256(footer[:480]).digest()
            for suffix, raw in (
                ("payload", payload),
                ("producer-receipt", receipt_raw + footer),
                ("source-manifest", manifest_raw),
            ):
                path = authority_root / f"{ordinal:02d}-{row['name']}.{suffix}"
                path.write_bytes(raw); path.chmod(0o400)
        return True

    try:
        authority = builder._issue_production_native_evm_static_roles(
            source_freeze={"sources": sources}, source_roster=Roster(),
            compiled_artifacts={"retained-source-bootstrap-coordinator": {
                "path": coordinator, "fd": coordinator_fd,
            }}, staged_generation_root_fd=stage_fd,
            upstream_authority=upstreams,
            builder_callbacks=MappingProxyType({
                "run_native_evm_static_acquisition": issue,
            }),
        )
        assert upstreams.closed is True
        records = authority.role_records()
        assert [(row["role"], row["name"]) for row in records] == [
            (8, "medusa"), (9, "solc_amd64"),
        ]
        assert os.pread(
            records[0]["payload_fd"], len(role_values[8]["payload"]), 0,
        ) == role_values[8]["payload"]
        medusa_payload = (
            stage / "share/plamen/native-source-authority-v1/08-medusa.payload"
        )
        medusa_payload.chmod(0o600)
        with medusa_payload.open("r+b", buffering=0) as stream:
            stream.write(b"X")
        with pytest.raises(builder.BuildError, match="descriptor changed"):
            authority.role_records()
        assert authority.close() is True
        assert authority.close() is True
        for row in records:
            for field in (
                "payload_fd", "producer_receipt_fd", "source_manifest_fd",
            ):
                with pytest.raises(OSError):
                    os.fstat(row[field])
    finally:
        if not upstreams.closed:
            upstreams.close()
        os.close(stage_fd); os.close(coordinator_fd)
    assert callable(
        builder._production_native_builder_callbacks()[
            "issue_production_native_evm_static_roles"
        ]
    )


def test_production_evm_static_native_issue_rejects_footer_and_closes_upstream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    # Exercise the post-native failure path without depending on live upstream
    # assets: a forged provider creates one malformed leaf and the descriptor
    # replay must reject it while retiring upstream custody.
    policy = _canonical({
        "artifact": {"executable": {
            "size": 1, "sha256": hashlib.sha256(b"m").hexdigest(),
        }}, "schema": "plamen.medusa-acquisition.v1",
    })
    receipt = json.dumps({
        "schema": "plamen.medusa-acquisition-receipt.v1",
    }, sort_keys=True, separators=(",", ":")).encode("ascii")
    manifest = _canonical({"schema": "plamen.runtime_source_manifest.native-retained.v1"})
    files = {}
    sources = []
    for role, raw in (
        ("medusa_acquisition_policy", policy),
        ("medusa_acquisition_receipt", receipt),
        ("medusa_runtime_source_manifest", manifest),
    ):
        path = tmp_path / role; path.write_bytes(raw); path.chmod(0o400)
        files[role] = path
        sources.append({"role": role, "size": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest()})

    class Roster:
        _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True

        @staticmethod
        def duplicate_member(role):
            # Only role 8 is reached before its malformed footer is rejected.
            return os.open(files[role], os.O_RDONLY | os.O_CLOEXEC)

    upstream_files = []
    upstream_fds = []
    for index in range(4):
        path = tmp_path / f"input-{index}"; path.write_bytes(b"x"); path.chmod(0o400)
        upstream_files.append(path)
        upstream_fds.append(os.open(path, os.O_RDONLY | os.O_CLOEXEC))

    class Upstreams:
        _PLAMEN_RETAINED_EVM_STATIC_UPSTREAMS_V1 = True
        closed = False

        @staticmethod
        def descriptors():
            return tuple(upstream_fds)

        def close(self):
            if not self.closed:
                self.closed = True
                for descriptor in upstream_fds:
                    os.close(descriptor)
            return True

    upstreams = Upstreams()
    stage = tmp_path / "stage"; stage.mkdir(mode=0o700)
    stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    coordinator = tmp_path / "coordinator"; coordinator.write_bytes(b"native")
    coordinator_fd = os.open(coordinator, os.O_RDONLY | os.O_CLOEXEC)
    opened = []
    original_open = builder._open_relative_nofollow

    def observe_open(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(builder, "_open_relative_nofollow", observe_open)

    def issue(_executable, **_values):
        root = stage / "share/plamen/native-source-authority-v1"
        root.mkdir(parents=True, mode=0o700)
        for suffix, raw in (
            ("payload", b"m"),
            ("producer-receipt", receipt + bytes(512)),
            ("source-manifest", manifest),
        ):
            path = root / f"08-medusa.{suffix}"
            path.write_bytes(raw); path.chmod(0o400)
        return True

    try:
        with pytest.raises(builder.BuildError, match="native footer"):
            builder._issue_production_native_evm_static_roles(
                source_freeze={"sources": sources}, source_roster=Roster(),
                compiled_artifacts={"retained-source-bootstrap-coordinator": {
                    "path": coordinator, "fd": coordinator_fd,
                }}, staged_generation_root_fd=stage_fd,
                upstream_authority=upstreams,
                builder_callbacks=MappingProxyType({
                    "run_native_evm_static_acquisition": issue,
                }),
            )
        assert upstreams.closed is True
        for descriptor in opened:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        if not upstreams.closed:
            upstreams.close()
        os.close(stage_fd); os.close(coordinator_fd)


def test_package_snapshot_binds_projection_front_and_host_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    workspace = tmp_path / "workspace"; workspace.mkdir(mode=0o700)
    home = tmp_path / "account"; home.mkdir()
    source = tmp_path / "source"; source.mkdir()
    projection_rows = [
        {
            "class": "runtime", "destination_path": "plamen.py",
            "installed_mode": 0o400, "size": len(b"print('front')\n"),
            "sha256": hashlib.sha256(b"print('front')\n").hexdigest(),
        },
        {
            "class": "adapter", "destination_path": "AGENTS.md",
            "installed_mode": 0o400, "size": len(b"agent\n"),
            "sha256": hashlib.sha256(b"agent\n").hexdigest(),
        },
    ]

    class Projection:
        @staticmethod
        def validate_manifest(*_args, **_kwargs):
            return {"counts": {"total": 2}, "rows": projection_rows}

        @staticmethod
        def materialize_validated(_raw, _source_fd, runtime_fd, adapter_fd, **_kwargs):
            for directory_fd, name, raw in (
                (runtime_fd, "plamen.py", b"print('front')\n"),
                (adapter_fd, "AGENTS.md", b"agent\n"),
            ):
                fd = os.open(
                    name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o400, dir_fd=directory_fd,
                )
                try:
                    os.write(fd, raw); os.fsync(fd)
                finally:
                    os.close(fd)
            return {"count": 2}

    def materialize_runtime(root, final_root, package_source):
        assert final_root == home / ".local/share/plamen/runtime/py312"
        assert package_source == workspace / "package-snapshot/package-source"
        (root / "bin").mkdir(parents=True)
        members = {
            "bin/python": (b"signed-host-python\n", 0o500),
            "pyvenv.cfg": (b"home = /reviewed/cpython\n", 0o400),
            ".plamen-runtime.json": (b'{"schema":"plamen.python_runtime.v1"}\n', 0o400),
        }
        rows = []
        for relative, (raw, mode) in members.items():
            target = root / relative
            target.write_bytes(raw); target.chmod(mode)
            rows.append({
                "namespace": "managed-runtime", "path": relative,
                "mode": mode, "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
        rows.sort(key=lambda row: row["path"].encode("utf-8"))
        return rows

    monkeypatch.setattr(builder, "REPOSITORY_ROOT", source)
    monkeypatch.setattr(builder, "_load_frozen_source_module", lambda *_a: Projection)
    monkeypatch.setattr(builder, "_read_frozen_source_member", lambda *_a: b"{}\n")
    monkeypatch.setattr(
        builder, "_frozen_source_row",
        lambda *_a: {"sha256": hashlib.sha256(b"{}\n").hexdigest()},
    )
    monkeypatch.setattr(
        builder, "_materialize_relocatable_managed_runtime",
        materialize_runtime,
    )
    snapshot = builder._materialize_frozen_package_snapshot(
        workspace, home, {"sources": []},
    )
    assert snapshot["interpreter_authority"]["path"] == str(
        home / ".local/share/plamen/runtime/py312/bin/python"
    )
    assert snapshot["front_authority"]["path"] == str(home / ".plamen/plamen.py")
    assert [(row["namespace"], row["path"]) for row in snapshot["rows"]] == [
        ("managed-runtime", ".plamen-runtime.json"),
        ("managed-runtime", "bin/python"),
        ("managed-runtime", "pyvenv.cfg"),
        ("package-source", "codex-adapter/AGENTS.md"),
        ("package-source", "plamen.py"),
    ]
    manifest = {
        "schema": "plamen.posix-native-install.package-snapshot.v2",
        "rows": snapshot["rows"],
    }
    assert snapshot["manifest_sha256"] == hashlib.sha256(_canonical(manifest)).hexdigest()


def test_published_test_build_manifest_replays_exactly(tmp_path: Path) -> None:
    builder = _load_builder()
    output = tmp_path / "test-build"
    output.mkdir(mode=0o700)
    result = builder.TEST_ONLY_build_production_shape(output)
    try:
        replay = builder.TEST_ONLY_validate_published_build_v2(output, result)
        assert replay == {
            "artifact_sha256": result["artifact_sha256"],
            "build_key_sha256": result["build_key_sha256"],
            "manifest_sha256": result["manifest_sha256"],
            "schema": "plamen-native-supervisor-build-validation-v2",
            "status": "TEST_ONLY_EXACT_REPLAY",
        }
        forged = dict(result)
        forged["artifact_sha256"] = "ff" * 32
        with pytest.raises(builder.BuildError, match="artifact differs"):
            builder.TEST_ONLY_validate_published_build_v2(output, forged)
    finally:
        artifact = Path(result["artifact_path"])
        if hasattr(os, "chflags"):
            os.chflags(artifact, 0)
        artifact.chmod(0o600)


def test_production_build_stays_closed_before_any_output_effect(tmp_path: Path) -> None:
    builder = _load_builder()
    output = tmp_path / "production"
    output.mkdir(mode=0o700)

    with pytest.raises(builder.BuildError, match="production build hard-stop") as rejected:
        builder.build(output, test_only=False)
    assert "SOURCE_INSTALL_COORDINATOR_TRANSACTION_ABSENT" in str(
        rejected.value
    )
    assert list(output.iterdir()) == []
