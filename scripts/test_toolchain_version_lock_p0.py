"""Exact toolchain lock and runtime-identity contracts.

No fixture in this file installs a package, contacts a registry, or launches
an audit provider.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

import audit_snapshot as SNAP
import plamen as INSTALLER


_ROOT = Path(__file__).resolve().parents[1]
_LOCK = (
    _ROOT
    / "verification_policy"
    / "toolchain_version_lock.v1.json"
)
_GOVERNANCE = (
    _ROOT
    / "verification_policy"
    / "toolchain_governance.v1.json"
)


def _lock_entries() -> dict[str, dict[str, object]]:
    payload = json.loads(_LOCK.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "plamen.toolchain_version_lock.v1"
    return {
        str(row["identity_id"]): row
        for row in payload["identities"]
    }


def test_reviewed_release_lock_records_exact_primary_evidence() -> None:
    entries = _lock_entries()
    assert {
        identity: entries[identity]["expected_version"]
        for identity in ("slither", "scip-go", "protobuf")
    } == {
        "slither": "0.11.5",
        "scip-go": "0.2.7",
        "protobuf": "7.35.1",
    }
    assert entries["slither"]["install_spec"] == (
        "slither-analyzer==0.11.5"
    )
    assert entries["scip-go"]["install_spec"] == (
        "github.com/scip-code/scip-go/cmd/scip-go@v0.2.7"
    )
    assert entries["protobuf"]["install_spec"] == "protobuf==7.35.1"
    assert entries["protobuf"]["generated_code_version"] == "7.34.1"

    generated = (
        _ROOT / "plamen_l1" / "scip_pb2.py"
    ).read_text(encoding="utf-8")
    assert "# Protobuf Python Version: 7.34.1" in generated

    for identity in ("slither", "scip-go"):
        row = entries[identity]
        assert row["acquisition_scope"] == "SETUP_ONLY"
        assert (
            row["deterministic_provider_authority_requires"]
            == "REVIEWED_CONTENT_MATCH"
        )
        assert row["content_authority"] == {
            "mode": "OBSERVED_NONAUTHORITATIVE",
            "reviewed_content_sha256": [],
        }
        assert str(row["version_rationale"]).strip()
        evidence = row["release_evidence"]
        assert isinstance(evidence, list) and evidence
        assert all(
            str(item["url"]).startswith("https://")
            and item["authority"] in {
                "OFFICIAL_PYPI_RELEASE",
                "OFFICIAL_GITHUB_RELEASE",
                "OFFICIAL_PROTOBUF_COMPATIBILITY_POLICY",
            }
            for item in evidence
        )
    protobuf = entries["protobuf"]
    assert protobuf["acquisition_scope"] == "SETUP_ONLY"
    assert protobuf["deterministic_provider_authority_requires"] == (
        "REVIEWED_CONTENT_MATCH"
    )
    assert protobuf["content_authority"]["mode"] == "REVIEWED_CONTENT_MATCH"
    assert protobuf["content_authority"]["evidence_path"] == (
        "verification_policy/protobuf_reviewed_content.v1.json"
    )
    assert len(protobuf["content_authority"]["reviewed_content_sha256"]) == 7


@pytest.mark.parametrize("platform_name", ["win32", "linux", "darwin"])
def test_cross_os_setup_commands_use_exact_reviewed_versions(
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
) -> None:
    monkeypatch.setattr(INSTALLER.sys, "platform", platform_name)
    slither = INSTALLER._slither_cmds()
    scip_go = INSTALLER._scip_go_cmds()
    assert slither == []
    assert "slither-analyzer==0.11.5" in (
        _ROOT / "requirements-runtime-full.lock"
    ).read_text(encoding="utf-8")
    assert scip_go == [
        "go install "
        "github.com/scip-code/scip-go/cmd/scip-go@v0.2.7"
    ]
    assert "@latest" not in " ".join(slither + scip_go)


def test_generated_protobuf_runtime_is_exactly_compatible_in_requirements() -> None:
    requirements = (
        _ROOT / "requirements.txt"
    ).read_text(encoding="utf-8").splitlines()
    protobuf = [
        row.split("#", 1)[0].strip()
        for row in requirements
        if row.split("#", 1)[0].strip().casefold().startswith("protobuf")
    ]
    assert protobuf == ["protobuf==7.35.1"]


def test_governed_debt_and_external_managers_are_non_authoritative() -> None:
    governance = json.loads(_GOVERNANCE.read_text(encoding="utf-8"))
    reviewed_lock = governance["reviewed_version_lock"]
    assert reviewed_lock["sha256"] == hashlib.sha256(
        _LOCK.read_bytes()
    ).hexdigest()
    assert set(reviewed_lock["runtime_statuses"]) == {
        "MATCH",
        "MISMATCH",
        "UNAVAILABLE",
        "EXTERNAL_MANAGER",
        "DEBT",
        "UNREGISTERED",
        "REVOKED",
        "OBSERVED_NONAUTHORITATIVE",
    }
    rows = {
        str(row["tool_id"]): row
        for row in governance["tools"]
    }
    for row in rows.values():
        state = row["update_policy"]["state"]
        authority = row["runtime_authority"]
        if state == "GOVERNED_DEBT":
            assert row["update_policy"]["acquisition_scope"] == "SETUP_ONLY"
            assert row["update_policy"]["unresolved_debt"] is True
            assert authority == {
                "identity_status": "DEBT",
                "deterministic_provider_authority": False,
                "mismatch_effect": "CAPABILITY_DEBT_NO_CLEAN_AUTHORITY",
            }
        if state in {
            "EXTERNAL_TOOLCHAIN_MANAGER",
            "EXTERNAL_PLATFORM_MANAGER",
        }:
            assert row["update_policy"]["acquisition_scope"] == (
                "EXTERNAL_OPERATOR_SETUP"
            )
            assert authority["identity_status"] == "EXTERNAL_MANAGER"
            assert authority["deterministic_provider_authority"] is False

    for identity in ("slither", "scip-go"):
        row = rows[identity]
        assert (
            row["update_policy"]["state"]
            == "REVIEWED_VERSION_OBSERVED_CONTENT"
        )
        assert row["runtime_authority"] == {
            "identity_status": "OBSERVED_NONAUTHORITATIVE",
            "deterministic_provider_authority": False,
            "mismatch_effect": "NO_AUTHORITY_WITHOUT_REVIEWED_CONTENT",
        }
    protobuf = rows["protobuf"]
    assert protobuf["update_policy"]["state"] == "REVIEWED_CONTENT_MATCH"
    assert protobuf["runtime_authority"] == {
        "identity_status": "MATCH",
        "deterministic_provider_authority": True,
        "mismatch_effect": "REVOKE_ON_REVIEWED_CONTENT_MISMATCH",
    }


def _command_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    tool: str,
    output: str,
) -> dict[str, object]:
    executable = tmp_path / (tool + ".exe")
    executable.write_bytes((tool + "-fixture").encode("ascii"))
    SNAP._TOOL_FINGERPRINT_CACHE.clear()
    monkeypatch.setattr(
        SNAP.shutil,
        "which",
        lambda name: (
            str(executable) if name in {tool, "go"} else None
        ),
    )
    def observed(command):
        if (
            tool == "scip-go"
            and tuple(command[1:3]) == ("version", "-m")
        ):
            return (
                "rc=0\n"
                f"{executable}: go1.25.0\n"
                "\tpath\tgithub.com/scip-code/scip-go/cmd/scip-go\n"
                "\tmod\tgithub.com/scip-code/scip-go\tv0.2.7\n"
            ).encode()
        return output.encode("utf-8")
    monkeypatch.setattr(
        SNAP,
        "_command_version",
        observed,
    )
    return json.loads(
        SNAP._runtime_tool_fingerprint((tool, "--version"))
    )


def test_runtime_fingerprint_reports_expected_and_observed_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _command_identity(
        tmp_path,
        monkeypatch,
        tool="scip-go",
        output="rc=0\nscip-go 0.2.7",
    )
    assert identity["schema"] == "plamen.runtime-tool-identity.v2"
    assert identity["expected_identity"]["version"] == "0.2.7"
    assert identity["observed_identity"]["version"] == (
        "rc=0\nscip-go 0.2.7"
    )
    assert identity["identity_status"] == "OBSERVED_NONAUTHORITATIVE"
    assert identity["deterministic_provider_authority"] is False
    assert identity["toolchain_version_lock_sha256"] == hashlib.sha256(
        _LOCK.read_bytes()
    ).hexdigest()


def test_runtime_fingerprint_reports_mismatch_unavailable_and_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mismatch = _command_identity(
        tmp_path,
        monkeypatch,
        tool="scip-go",
        output="rc=0\nscip-go 0.2.6",
    )
    assert mismatch["expected_identity"]["version"] == "0.2.7"
    assert mismatch["identity_status"] == "MISMATCH"
    assert mismatch["deterministic_provider_authority"] is False

    SNAP._TOOL_FINGERPRINT_CACHE.clear()
    monkeypatch.setattr(SNAP.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        SNAP,
        "_command_version",
        lambda _command: b"UNAVAILABLE",
    )
    unavailable = json.loads(
        SNAP._runtime_tool_fingerprint(("scip-go", "--version"))
    )
    assert unavailable["identity_status"] == "UNAVAILABLE"
    assert unavailable["deterministic_provider_authority"] is False

    debt = _command_identity(
        tmp_path,
        monkeypatch,
        tool="opengrep",
        output="rc=0\nopengrep 1.2.3",
    )
    assert debt["identity_status"] == "DEBT"
    assert debt["deterministic_provider_authority"] is False

    external = _command_identity(
        tmp_path,
        monkeypatch,
        tool="cargo",
        output="rc=0\ncargo 1.99.0",
    )
    assert external["identity_status"] == "EXTERNAL_MANAGER"
    assert external["deterministic_provider_authority"] is False


def test_runtime_fingerprint_cache_and_status_bind_lock_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = tmp_path / "toolchain_version_lock.v1.json"
    governance = tmp_path / "toolchain_governance.v1.json"
    lock.write_bytes(_LOCK.read_bytes())
    governance.write_bytes(_GOVERNANCE.read_bytes())
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_VERSION_LOCK_PATH", lock)
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_GOVERNANCE_PATH", governance)
    first = _command_identity(
        tmp_path,
        monkeypatch,
        tool="scip-go",
        output="rc=0\nscip-go 0.2.7",
    )
    assert first["identity_status"] == "OBSERVED_NONAUTHORITATIVE"

    payload = json.loads(lock.read_text(encoding="utf-8"))
    scip_go = next(
        row
        for row in payload["identities"]
        if row["identity_id"] == "scip-go"
    )
    scip_go["expected_version"] = "0.2.6"
    scip_go["install_spec"] = (
        "github.com/scip-code/scip-go/cmd/scip-go@v0.2.6"
    )
    lock.write_text(json.dumps(payload), encoding="utf-8")
    governance_payload = json.loads(
        governance.read_text(encoding="utf-8")
    )
    governance_payload["reviewed_version_lock"]["sha256"] = hashlib.sha256(
        lock.read_bytes()
    ).hexdigest()
    governance.write_text(
        json.dumps(governance_payload),
        encoding="utf-8",
    )

    with pytest.raises(SNAP.SnapshotInputError, match="identity|probe"):
        SNAP._runtime_tool_fingerprint(("scip-go", "--version"))
    assert SNAP.SNAPSHOT_SCHEMA == "plamen.audit-input-snapshot.v1"


def test_runtime_snapshot_binds_protobuf_expected_and_observed_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        SNAP,
        "_python_distribution_version",
        lambda name: "7.35.1" if name == "protobuf" else "UNAVAILABLE",
    )
    evidence = json.loads(
        (
            _ROOT
            / "verification_policy"
            / "protobuf_reviewed_content.v1.json"
        ).read_text(encoding="utf-8")
    )
    monkeypatch.setattr(
        SNAP,
        "_python_distribution_closure",
        lambda *_args, **_kwargs: {
            "distribution_files_sha256": evidence["installed_closure"][
                "files_sha256"
            ],
            "distribution_path_set_sha256": evidence["installed_closure"][
                "path_set_sha256"
            ],
            "distribution_file_count": evidence["installed_closure"][
                "file_count"
            ],
            "distribution_bytes": evidence["installed_closure"][
                "logical_bytes"
            ],
            "record_sha256": evidence["record"]["sha256"],
            "record_normalized_rows_sha256": evidence["record"][
                "normalized_rows_sha256"
            ],
            "module_sha256": evidence["module"]["sha256"],
        },
    )
    monkeypatch.setattr(SNAP, "_reviewed_wheel_observation", lambda *_a, **_k: {})
    identity = json.loads(
        SNAP._runtime_python_distribution_fingerprint("protobuf")
    )
    assert identity["expected_identity"]["distribution"] == "protobuf"
    assert identity["expected_identity"]["version"] == "7.35.1"
    assert identity["expected_identity"]["generated_code_version"] == "7.34.1"
    assert identity["expected_identity"]["content_authority"]["mode"] == (
        "REVIEWED_CONTENT_MATCH"
    )
    assert identity["observed_identity"]["version"] == "7.35.1"
    assert identity["identity_status"] == "OBSERVED_NONAUTHORITATIVE"
    assert identity["deterministic_provider_authority"] is False


def test_doctor_uses_locked_expected_vs_observed_report() -> None:
    source = inspect.getsource(INSTALLER.run_doctor)
    assert "_locked_toolchain_identity_report" in source
    rows = INSTALLER._locked_toolchain_identity_report(
        command_versions={
            "scip-go": "0.2.6",
        },
        distribution_versions={
            "slither": "0.11.5",
            "protobuf": "7.35.1",
        },
    )
    indexed = {row["identity_id"]: row for row in rows}
    assert indexed["slither"]["identity_status"] == "MATCH"
    assert indexed["scip-go"]["identity_status"] == "MISMATCH"
    assert indexed["protobuf"]["identity_status"] == "MATCH"
    assert all(
        {"expected_version", "observed_version", "identity_status"} <= set(row)
        for row in rows
    )


def test_mutable_acquisition_markers_remain_setup_only() -> None:
    setup_source = inspect.getsource(INSTALLER)
    assert "@latest" in setup_source or "install latest" in setup_source
    for runtime_path in (
        _ROOT / "scripts" / "audit_snapshot.py",
        _ROOT / "scripts" / "recon_prepass.py",
    ):
        source = runtime_path.read_text(encoding="utf-8")
        assert "go install " not in source
        assert "pip install " not in source
        assert "avm install latest" not in source
