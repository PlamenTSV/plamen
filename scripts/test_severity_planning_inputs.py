"""Component tests for authenticated severity-planning input capture.

The fixture builds and replays the real audit snapshot.  Only host runtime-tool
observations are held to a deterministic component value; snapshot
classification, live rebuilding, semantic config, and methodology capture are
never substituted.
The initial snapshot comes from the real source_empty publisher above a typed
component queue producer. This does not claim complete T0-T9 ancestry.
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path

import pytest

import audit_snapshot as snapshot_api
from artifact_ledger import ArtifactLedgerError, LEDGER_NAME, read_artifact_ledger
from severity_planning_inputs import (
    FAULT_POINTS,
    SOURCE_LEDGER_INPUT,
    capture_severity_planning_inputs,
)
from severity_empty_source import run_empty_severity_source
from test_severity_empty_source import _publish_queue


RUN_ID = "12345678-1234-4234-9234-123456789abc"
PREFIX = "_severity_adjudication_inputs"
COMMON_NAMES = (
    f"{PREFIX}/audit_snapshot.json",
    f"{PREFIX}/audit_config.json",
    f"{PREFIX}/finding-output-format.md",
    f"{PREFIX}/poc-execution.md",
)


@pytest.fixture(autouse=True)
def _deterministic_host_tool_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        snapshot_api,
        "_runtime_tool_entries",
        lambda **_kwargs: [("@runtime/test-host", b"stable-toolchain")],
    )


def _implementation(root: Path) -> Path:
    for directory in ("scripts", "prompts", "rules", "agents"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "plamen_driver.py").write_text(
        "VERSION = 1\n", encoding="utf-8"
    )
    (root / "prompts" / "phase.md").write_text(
        "bound phase methodology\n", encoding="utf-8"
    )
    (root / "rules" / "finding-output-format.md").write_text(
        "# Finding format\n", encoding="utf-8"
    )
    (root / "rules" / "phase5-poc-execution.md").write_text(
        "# PoC execution\n", encoding="utf-8"
    )
    (root / "rules" / "report-template.md").write_text(
        "# Report template\n", encoding="utf-8"
    )
    matrix = root / "docs" / "l1-mode" / "severity-matrix.md"
    matrix.parent.mkdir(parents=True)
    matrix.write_text("# L1 severity matrix\n", encoding="utf-8")
    return root


def _fixture(tmp_path: Path, *, pipeline: str = "sc", publish_source: bool = True):
    project = tmp_path / "project"
    if pipeline == "sc":
        source = project / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text(
            "pragma solidity ^0.8.20; contract Vault {}\n",
            encoding="utf-8",
        )
        (project / "foundry.toml").write_text(
            "[profile.default]\nsrc = 'src'\n", encoding="utf-8"
        )
        language = "evm"
    else:
        source = project / "src" / "lib.rs"
        source.parent.mkdir(parents=True)
        source.write_text("pub fn height() -> u64 { 1 }\n", encoding="utf-8")
        (project / "Cargo.toml").write_text(
            "[package]\nname='fixture'\nversion='0.1.0'\n",
            encoding="utf-8",
        )
        language = "rust"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    implementation = _implementation(tmp_path / "plamen")
    config: dict[str, object] = {
        "pipeline": pipeline,
        "mode": "core",
        "language": language,
        "cli_backend": "codex",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "scope_notes": "severity planning input component fixture",
        "_run_id": RUN_ID,
    }
    bound = snapshot_api.build_audit_snapshot(config, implementation)
    config["_audit_snapshot"] = bound
    if publish_source:
        _publish_queue(project, scratchpad, pipeline=pipeline)
        assert run_empty_severity_source(
            scratchpad=scratchpad, project_root=project, config=config,
        ) is True
    return project, scratchpad, implementation, config, bound


def _names(pipeline: str) -> tuple[str, ...]:
    tail = (
        f"{PREFIX}/report-template.md"
        if pipeline == "sc"
        else f"{PREFIX}/l1-severity-matrix.md"
    )
    return (*COMMON_NAMES, tail)


def _capture(
    project: Path,
    root: Path,
    implementation: Path,
    config: dict[str, object],
    *,
    fault_hook=None,
):
    return capture_severity_planning_inputs(
        scratchpad=root,
        project_root=project,
        implementation_root=implementation,
        config=config,
        fault_hook=fault_hook,
    )


def _unit(root: Path):
    matches = [
        row
        for key, row in read_artifact_ledger(root)["work_units"].items()
        if key.endswith("/severity_adjudication_shadow/planning_inputs")
    ]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_live_snapshot_config_and_exact_methodology_are_captured_and_replayed(
    tmp_path: Path, pipeline: str,
) -> None:
    project, root, implementation, config, bound = _fixture(
        tmp_path, pipeline=pipeline
    )
    result = _capture(project, root, implementation, config)

    assert tuple(result["exact_inputs"]) == (SOURCE_LEDGER_INPUT, *_names(pipeline))
    assert result["source_ledger_path"] == root / SOURCE_LEDGER_INPUT
    assert result["source_ledger_digest"] == hashlib.sha256(
        (root / SOURCE_LEDGER_INPUT).read_bytes()
    ).hexdigest()
    assert result["audit_snapshot_digest"] == bound["snapshot_digest"]
    assert result["audit_config_digest"] == (
        bound["components"]["audit_config"]["digest"]
    )
    assert json.loads((root / _names(pipeline)[0]).read_bytes()) == bound
    assert json.loads((root / _names(pipeline)[1]).read_bytes()) == json.loads(
        snapshot_api.canonical_semantic_config_bytes(config)
    )

    expected_methodology = {
        "finding_output_format": implementation / "rules" / "finding-output-format.md",
        "poc_execution": implementation / "rules" / "phase5-poc-execution.md",
        (
            "report_template" if pipeline == "sc" else "l1_severity_matrix"
        ): (
            implementation / "rules" / "report-template.md"
            if pipeline == "sc"
            else implementation / "docs" / "l1-mode" / "severity-matrix.md"
        ),
    }
    assert set(result["methodology_files"]) == set(expected_methodology)
    for logical, source in expected_methodology.items():
        captured = Path(result["methodology_files"][logical])
        assert captured.read_bytes() == source.read_bytes()
        assert captured.parent == root / PREFIX

    unit = _unit(root)
    assert unit["run_id"] == RUN_ID
    assert unit["model_invoked"] is False
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"
    assert set(unit["input_bindings"]) == {f"scratchpad:{SOURCE_LEDGER_INPUT}"}
    assert unit["input_bindings"][f"scratchpad:{SOURCE_LEDGER_INPUT}"][
        "producer_work_unit_key"
    ].endswith("/severity_adjudication_shadow/source_empty")
    assert set(unit["artifacts"]) == {
        f"scratchpad:{name}" for name in _names(pipeline)
    }
    before = {
        name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
        for name in _names(pipeline)
    }
    ledger_before = (root / LEDGER_NAME).read_bytes()
    assert _capture(project, root, implementation, config) == result
    assert {
        name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
        for name in _names(pipeline)
    } == before
    assert (root / LEDGER_NAME).read_bytes() == ledger_before


@pytest.mark.parametrize("fault_point", FAULT_POINTS)
def test_each_capture_fault_recovers_only_the_exact_sealed_prefix(
    tmp_path: Path, fault_point: str,
) -> None:
    project, root, implementation, config, _bound = _fixture(tmp_path)
    fired = False

    def crash(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError(f"fault:{point}")

    with pytest.raises(RuntimeError, match=f"fault:{fault_point}"):
        _capture(project, root, implementation, config, fault_hook=crash)
    assert fired is True
    result = _capture(project, root, implementation, config)
    assert tuple(result["exact_inputs"]) == (SOURCE_LEDGER_INPUT, *_names("sc"))
    assert _unit(root)["execution_state"] == "OUTPUT_COMMITTED"


@pytest.mark.parametrize("drift", ("snapshot_hash", "config", "methodology"))
def test_live_authority_drift_fails_before_publication(
    tmp_path: Path, drift: str,
) -> None:
    project, root, implementation, config, _bound = _fixture(tmp_path)
    if drift == "snapshot_hash":
        forged = dict(config["_audit_snapshot"])
        forged["snapshot_digest"] = "f" * 64
        config["_audit_snapshot"] = forged
    elif drift == "config":
        config["scope_notes"] = "changed after snapshot"
    else:
        (implementation / "rules" / "phase5-poc-execution.md").write_text(
            "# Changed PoC execution\n", encoding="utf-8"
        )
    with pytest.raises((ArtifactLedgerError, snapshot_api.SnapshotInputError)):
        _capture(project, root, implementation, config)
    assert not any((root / name).exists() for name in _names("sc"))
    assert not any(
        key.endswith("/severity_adjudication_shadow/planning_inputs")
        for key in read_artifact_ledger(root)["work_units"]
    )


@pytest.mark.parametrize("run_id", (7, " padded-run ", ""))
def test_run_id_must_be_a_nonempty_exact_string(
    tmp_path: Path, run_id: object,
) -> None:
    project, root, implementation, config, _bound = _fixture(tmp_path)
    config["_run_id"] = run_id
    with pytest.raises(ArtifactLedgerError, match="run"):
        _capture(project, root, implementation, config)
    assert not any((root / name).exists() for name in _names("sc"))
    assert not any(
        key.endswith("/severity_adjudication_shadow/planning_inputs")
        for key in read_artifact_ledger(root)["work_units"]
    )


@pytest.mark.parametrize("collision", ("file", "symlink"))
def test_fresh_capture_refuses_foreign_output_collision(
    tmp_path: Path, collision: str,
) -> None:
    project, root, implementation, config, _bound = _fixture(tmp_path)
    target = root / _names("sc")[0]
    target.parent.mkdir(exist_ok=True)
    if collision == "file":
        target.write_bytes(b"foreign\n")
    else:
        target.symlink_to("missing-target")
    with pytest.raises(ArtifactLedgerError):
        _capture(project, root, implementation, config)
    assert not any(
        key.endswith("/severity_adjudication_shadow/planning_inputs")
        for key in read_artifact_ledger(root)["work_units"]
    )


@pytest.mark.parametrize("damage", ("missing", "tampered"))
def test_committed_capture_damage_is_rejected_without_repair(
    tmp_path: Path, damage: str,
) -> None:
    project, root, implementation, config, _bound = _fixture(tmp_path)
    _capture(project, root, implementation, config)
    target = root / _names("sc")[2]
    if damage == "missing":
        target.unlink()
    else:
        os.chmod(target, 0o600)
        target.write_bytes(b"tampered\n")
    with pytest.raises(ArtifactLedgerError):
        _capture(project, root, implementation, config)
    if damage == "missing":
        assert not target.exists()
    else:
        assert target.read_bytes() == b"tampered\n"


def test_armed_partial_capture_rejects_different_existing_bytes(
    tmp_path: Path,
) -> None:
    project, root, implementation, config, _bound = _fixture(tmp_path)

    def crash(point: str) -> None:
        if point == "after_output_1":
            raise RuntimeError("partial")

    with pytest.raises(RuntimeError, match="partial"):
        _capture(project, root, implementation, config, fault_hook=crash)
    target = root / _names("sc")[0]
    os.chmod(target, 0o600)
    target.write_bytes(b"{}\n")
    with pytest.raises(ArtifactLedgerError):
        _capture(project, root, implementation, config)
    assert target.read_bytes() == b"{}\n"


@pytest.mark.parametrize("drift", ("project_source", "scratchpad_identity"))
def test_mid_publication_live_drift_stops_at_the_exact_written_prefix(
    tmp_path: Path, drift: str,
) -> None:
    project, root, implementation, config, _bound = _fixture(tmp_path)

    def mutate(point: str) -> None:
        if point != "after_output_1":
            return
        if drift == "project_source":
            (project / "src" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault { uint changed; }\n",
                encoding="utf-8",
            )
        else:
            os.chmod(root, 0o711)

    with pytest.raises(ArtifactLedgerError, match="changed|identity|snapshot"):
        _capture(
            project,
            root,
            implementation,
            config,
            fault_hook=mutate,
        )
    assert (root / _names("sc")[0]).is_file()
    assert not any((root / name).exists() for name in _names("sc")[1:])
    unit = _unit(root)
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["semantic_status"] == "INPUTS_BOUND"


@pytest.mark.parametrize("present", (False, True))
def test_snapshot_requires_committed_initial_source_not_raw_bytes(
    tmp_path: Path, present: bool,
) -> None:
    project, root, implementation, config, _bound = _fixture(
        tmp_path, publish_source=False,
    )
    if present:
        from severity_decision_ledger import build_severity_decision_ledger
        target = root / SOURCE_LEDGER_INPUT
        target.parent.mkdir()
        target.write_text(json.dumps(build_severity_decision_ledger(RUN_ID, [])))
    with pytest.raises(ArtifactLedgerError, match="initial source"):
        _capture(project, root, implementation, config)
    assert not any((root / name).exists() for name in _names("sc"))


@pytest.mark.parametrize("damage", ("bytes", "missing", "symlink", "hardlink"))
def test_initial_snapshot_damage_rejected_before_capture_arm(
    tmp_path: Path, damage: str,
) -> None:
    project, root, implementation, config, _bound = _fixture(tmp_path)
    target = root / SOURCE_LEDGER_INPUT
    raw = target.read_bytes()
    if damage == "bytes":
        os.chmod(target, 0o600)
        target.write_bytes(raw + b"\n")
    elif damage == "hardlink":
        os.link(target, root / "extra-snapshot-link")
    else:
        target.unlink()
        if damage == "symlink":
            alternate = root / "unowned-source.json"
            alternate.write_bytes(raw)
            target.symlink_to(alternate)
    ledger_before = (root / LEDGER_NAME).read_bytes()
    with pytest.raises(ArtifactLedgerError, match="initial source"):
        _capture(project, root, implementation, config)
    assert (root / LEDGER_NAME).read_bytes() == ledger_before
    assert not any((root / name).exists() for name in _names("sc"))


@pytest.mark.parametrize("point", ("after_output_1", "after_commit"))
def test_snapshot_drift_at_publication_barrier_cannot_return_success(
    tmp_path: Path, point: str,
) -> None:
    project, root, implementation, config, _bound = _fixture(tmp_path)

    def mutate(current: str) -> None:
        if current == point:
            target = root / SOURCE_LEDGER_INPUT
            os.chmod(target, 0o600)
            target.write_bytes(target.read_bytes() + b"\n")

    with pytest.raises(ArtifactLedgerError, match="initial source"):
        _capture(project, root, implementation, config, fault_hook=mutate)
    assert (root / _names("sc")[0]).exists()
    if point == "after_output_1":
        assert not any((root / name).exists() for name in _names("sc")[1:])
        assert _unit(root)["execution_state"] == "INPUTS_BOUND_PREEXECUTION"


def test_post_commit_output_mutation_is_not_reported_as_success(tmp_path: Path) -> None:
    project, root, implementation, config, _bound = _fixture(tmp_path)

    def mutate(point: str) -> None:
        if point == "after_commit":
            target = root / _names("sc")[2]
            os.chmod(target, 0o600)
            target.write_bytes(b"uncommitted replacement\n")

    with pytest.raises(ArtifactLedgerError, match="final replay"):
        _capture(project, root, implementation, config, fault_hook=mutate)
