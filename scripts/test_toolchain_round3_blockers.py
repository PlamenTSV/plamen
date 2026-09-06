"""Round-3 adversarial contracts for toolchain authority.

Every fixture is local and synthetic.  Nothing in this module installs a
package, contacts a registry, or launches a real audit provider.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType

import pytest

import audit_snapshot as SNAP
import plamen as INSTALLER
import recon_prepass as RECON
import tool_coverage_ledger as LEDGER


_ROOT = Path(__file__).resolve().parents[1]
_LOCK = _ROOT / "verification_policy" / "toolchain_version_lock.v1.json"
_GOVERNANCE = (
    _ROOT / "verification_policy" / "toolchain_governance.v1.json"
)


def _controls(tmp_path: Path) -> tuple[Path, Path]:
    lock = tmp_path / "toolchain_version_lock.v1.json"
    governance = tmp_path / "toolchain_governance.v1.json"
    lock.write_bytes(_LOCK.read_bytes())
    governance.write_bytes(_GOVERNANCE.read_bytes())
    return lock, governance


def _rebind_governance(governance: Path, lock: Path) -> None:
    payload = json.loads(governance.read_text(encoding="utf-8"))
    payload["reviewed_version_lock"]["sha256"] = hashlib.sha256(
        lock.read_bytes()
    ).hexdigest()
    governance.write_text(json.dumps(payload), encoding="utf-8")


def test_arbitrary_scip_bytes_cannot_self_attest_authenticity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    executable = tmp_path / "tools" / "scip-go.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"arbitrary non-release executable bytes")
    go = tmp_path / "go.exe"
    go.write_bytes(b"untrusted build-info narrator")

    monkeypatch.setattr(
        SNAP.shutil,
        "which",
        lambda name: (
            str(executable)
            if name == "scip-go"
            else str(go) if name == "go" else None
        ),
    )

    def fake_probe(command: tuple[str, ...]) -> bytes:
        if "--version" in command:
            return b"rc=0\nscip-go version 0.2.7"
        return (
            b"rc=0\n"
            b"path\tgithub.com/scip-code/scip-go/cmd/scip-go\n"
            b"mod\tgithub.com/scip-code/scip-go\tv0.2.7"
        )

    monkeypatch.setattr(SNAP, "_command_version", fake_probe)
    authority = SNAP.capture_command_provider_authority(
        "scip-go",
        ("scip-go", "--version"),
        project_root=project,
    )
    assert authority["deterministic_provider_authority"] is False
    assert authority["authority_status"] == "OBSERVED_NONAUTHORITATIVE"
    assert "authentic" in str(authority["reason"]).casefold()


def test_scip_probe_contract_is_closed_across_all_consumers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock, governance = _controls(tmp_path)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    row = next(
        item
        for item in payload["identities"]
        if item["identity_id"] == "scip-go"
    )
    row["version_probe"] = ["scip-go", "--attacker-selected-mode"]
    lock.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_governance(governance, lock)

    monkeypatch.setattr(SNAP, "_TOOLCHAIN_VERSION_LOCK_PATH", lock)
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_GOVERNANCE_PATH", governance)
    monkeypatch.setattr(INSTALLER, "_TOOLCHAIN_VERSION_LOCK_PATH", str(lock))
    monkeypatch.setattr(
        INSTALLER,
        "_TOOLCHAIN_GOVERNANCE_PATH",
        str(governance),
        raising=False,
    )

    with pytest.raises(SNAP.SnapshotInputError, match="identity|probe"):
        SNAP._load_toolchain_identity_controls()
    with pytest.raises(LEDGER.ToolCoverageLedgerError, match="identity|probe"):
        LEDGER.load_toolchain_governance(governance)
    with pytest.raises(RuntimeError, match="identity|probe"):
        INSTALLER._load_toolchain_version_lock()


@pytest.mark.parametrize(
    ("identity_id", "package_name", "python_module"),
    [
        ("slither", "not-slither", "not_slither"),
        ("protobuf", "not-protobuf", "not_protobuf"),
    ],
)
def test_python_provider_identity_names_are_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    identity_id: str,
    package_name: str,
    python_module: str,
) -> None:
    lock, governance = _controls(tmp_path)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    row = next(
        item
        for item in payload["identities"]
        if item["identity_id"] == identity_id
    )
    row["package_name"] = package_name
    row["python_module"] = python_module
    row["install_spec"] = f"{package_name}=={row['expected_version']}"
    row["version_probe"] = [
        "python-importlib-metadata",
        package_name,
    ]
    lock.write_text(json.dumps(payload), encoding="utf-8")
    _rebind_governance(governance, lock)

    monkeypatch.setattr(SNAP, "_TOOLCHAIN_VERSION_LOCK_PATH", lock)
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_GOVERNANCE_PATH", governance)
    monkeypatch.setattr(INSTALLER, "_TOOLCHAIN_VERSION_LOCK_PATH", str(lock))
    monkeypatch.setattr(
        INSTALLER,
        "_TOOLCHAIN_GOVERNANCE_PATH",
        str(governance),
        raising=False,
    )

    with pytest.raises(SNAP.SnapshotInputError, match="identity"):
        SNAP._load_toolchain_identity_controls()
    with pytest.raises(LEDGER.ToolCoverageLedgerError, match="identity"):
        LEDGER.load_toolchain_governance(governance)
    with pytest.raises(RuntimeError, match="identity"):
        INSTALLER._load_toolchain_version_lock()


def test_setup_rejects_lock_not_bound_by_governance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock, governance = _controls(tmp_path)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    row = next(
        item
        for item in payload["identities"]
        if item["identity_id"] == "scip-go"
    )
    row["expected_version"] = "9.9.9"
    row["install_spec"] = (
        "github.com/scip-code/scip-go/cmd/scip-go@v9.9.9"
    )
    lock.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(INSTALLER, "_TOOLCHAIN_VERSION_LOCK_PATH", str(lock))
    monkeypatch.setattr(
        INSTALLER,
        "_TOOLCHAIN_GOVERNANCE_PATH",
        str(governance),
        raising=False,
    )
    with pytest.raises(RuntimeError, match="digest|governance"):
        INSTALLER._load_toolchain_version_lock()


def test_project_hardlink_alias_cannot_authorize_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    executable = tmp_path / "tools" / "scip-go.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"provider bytes")
    alias = project / "provider-alias.exe"
    try:
        os.link(executable, alias)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    go = tmp_path / "go.exe"
    go.write_bytes(b"go")

    monkeypatch.setattr(
        SNAP.shutil,
        "which",
        lambda name: (
            str(executable)
            if name == "scip-go"
            else str(go) if name == "go" else None
        ),
    )
    monkeypatch.setattr(
        SNAP,
        "_command_version",
        lambda command: (
            b"rc=0\nscip-go 0.2.7"
            if "--version" in command
            else (
                b"rc=0\n"
                b"path\tgithub.com/scip-code/scip-go/cmd/scip-go\n"
                b"mod\tgithub.com/scip-code/scip-go\tv0.2.7"
            )
        ),
    )
    authority = SNAP.capture_command_provider_authority(
        "scip-go",
        ("scip-go", "--version"),
        project_root=project,
    )
    assert authority["deterministic_provider_authority"] is False
    assert authority["authority_status"] == "TARGET_RESOLUTION_REJECTED"
    assert "hardlink" in str(authority["reason"]).casefold()


def test_project_hardlink_alias_rejects_control_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    implementation = tmp_path / "implementation"
    project = tmp_path / "project"
    implementation.mkdir()
    project.mkdir()
    lock = implementation / _LOCK.name
    governance = implementation / _GOVERNANCE.name
    lock.write_bytes(_LOCK.read_bytes())
    governance.write_bytes(_GOVERNANCE.read_bytes())
    try:
        os.link(lock, project / "lock-alias.json")
        os.link(governance, project / "governance-alias.json")
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    monkeypatch.setattr(SNAP, "_TOOLCHAIN_VERSION_LOCK_PATH", lock)
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_GOVERNANCE_PATH", governance)
    with pytest.raises(SNAP.SnapshotInputError, match="hardlink"):
        SNAP._load_toolchain_identity_controls()


def test_protobuf_authority_is_required_before_scip_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    project.mkdir()
    index = scratch / "index.scip"
    index.write_bytes(b"synthetic")
    monkeypatch.setattr(
        RECON,
        "_capture_python_provider_authority",
        lambda *_args, **_kwargs: {
            "authority_status": "MISMATCH",
            "deterministic_provider_authority": False,
            "reason": "unlocked compatible runtime",
        },
    )
    fake = ModuleType("plamen_l1.scip_reader")
    fake.ScipReader = lambda *_args, **_kwargs: pytest.fail(
        "SCIP reader imported before protobuf authority was checked"
    )
    monkeypatch.setitem(sys.modules, "plamen_l1.scip_reader", fake)

    status = RECON._scip_to_graph_artifacts(
        scratch, index, project, ecosystem="go"
    )
    assert "TOOLCHAIN_AUTHORITY_DEBT" in status
    assert not (scratch / "_mechanical_graph.json").exists()


def test_protobuf_authority_replays_before_scip_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    project.mkdir()
    index = scratch / "index.scip"
    index.write_bytes(b"synthetic")
    authority = {
        "authority_status": "MATCH",
        "deterministic_provider_authority": True,
        "tool_id": "protobuf",
    }
    monkeypatch.setattr(
        RECON,
        "_capture_python_provider_authority",
        lambda *_args, **_kwargs: authority,
    )
    monkeypatch.setattr(
        RECON,
        "_provider_authority_replays",
        lambda *_args, **_kwargs: False,
    )

    class Reader:
        _definitions: dict[str, object] = {}
        _symbol_info: dict[str, object] = {}
        _references: dict[str, object] = {}

        def __init__(self, _path: str) -> None:
            pass

        def stats(self) -> dict[str, int]:
            return {"definitions": 5, "documents": 1}

    fake = ModuleType("plamen_l1.scip_reader")
    fake.ScipReader = Reader
    monkeypatch.setitem(sys.modules, "plamen_l1.scip_reader", fake)

    status = RECON._scip_to_graph_artifacts(
        scratch, index, project, ecosystem="go"
    )
    assert "IDENTITY_DRIFT_BEFORE_PUBLICATION" in status
    assert not (scratch / "_mechanical_graph.json").exists()


def test_failed_probe_diagnostics_do_not_change_semantic_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "scip-go.exe"
    executable.write_bytes(b"same bytes")
    go = tmp_path / "go.exe"
    go.write_bytes(b"go")
    counter = {"value": 0}
    monkeypatch.setattr(
        SNAP.shutil,
        "which",
        lambda name: (
            str(executable)
            if name == "scip-go"
            else str(go) if name == "go" else None
        ),
    )

    def probe(command: tuple[str, ...]) -> bytes:
        if "--version" in command:
            counter["value"] += 1
            return (
                "rc=1\n"
                f"nonce={counter['value']} path={tmp_path}"
            ).encode()
        return (
            b"rc=0\n"
            b"path\tgithub.com/scip-code/scip-go/cmd/scip-go\n"
            b"mod\tgithub.com/scip-code/scip-go\tv0.2.7"
        )

    monkeypatch.setattr(SNAP, "_command_version", probe)
    first = SNAP._runtime_tool_fingerprint(("scip-go", "--version"))
    second = SNAP._runtime_tool_fingerprint(("scip-go", "--version"))
    assert first == second
    assert b"nonce=" not in first
    diagnostic = SNAP._TOOL_PROBE_DIAGNOSTICS["scip-go"]
    assert "nonce=2" in diagnostic


@pytest.mark.parametrize(
    "invalid",
    [True, False, "604800", -1, 0, 10**30],
)
def test_advisory_freshness_limits_are_closed(
    tmp_path: Path,
    invalid: object,
) -> None:
    lock, governance = _controls(tmp_path)
    payload = json.loads(governance.read_text(encoding="utf-8"))
    rustsec = next(
        item
        for item in payload["advisory_sources"]
        if item["source_id"] == "rustsec-local"
    )
    rustsec["freshness_policy"]["max_age_seconds"] = invalid
    governance.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        LEDGER.ToolCoverageLedgerError,
        match="freshness",
    ):
        LEDGER.load_toolchain_governance(governance)
