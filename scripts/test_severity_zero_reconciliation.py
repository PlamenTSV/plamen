"""Component authority tests for zero-row severity reconciliation.

The fixture uses the actual source_empty, input-capture and planning publishers.
Its typed queue producer is a component fixture, not full T0-T9 ancestry, and
there is no MODEL execution or whole-audit claim.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from artifact_ledger import (
    ArtifactLedgerError,
    LEDGER_NAME,
    read_artifact_ledger,
)
import audit_snapshot as snapshot_api
import severity_adjudication_work as work
from severity_planning import run_severity_planning
from severity_planning_inputs import SOURCE_LEDGER_INPUT, capture_severity_planning_inputs
from severity_empty_source import run_empty_severity_source
from severity_zero_reconciliation import (
    FAULT_POINTS,
    INPUT_NAMES,
    OUTPUT_NAME,
    run_zero_severity_reconciliation,
)
from test_severity_empty_source import RUN_ID, _config, _publish_queue
from test_severity_planning_inputs import _implementation
from worker_execution_receipts import environment_allowlist_sha256


@pytest.fixture(autouse=True)
def _deterministic_host_tool_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        snapshot_api, "_runtime_tool_entries",
        lambda **_kwargs: [("@runtime/test-host", b"stable-toolchain")],
    )


def _publish_component_planning(
    project: Path,
    root: Path,
    config: dict[str, object],
    *,
    publish: bool = True,
) -> dict[str, bytes]:
    """Run the actual publisher, or deliberately leave only raw plan bytes."""
    # Zero findings still require a real auditable source tree. The former
    # synthetic planning producer could hide this missing fixture prerequisite.
    source_root = project / "src"
    source_root.mkdir()
    if config["pipeline"] == "sc":
        (source_root / "Vault.sol").write_text(
            "pragma solidity ^0.8.20; contract Vault {}\n", encoding="utf-8",
        )
        (project / "foundry.toml").write_text(
            "[profile.default]\nsrc = 'src'\n", encoding="utf-8",
        )
    else:
        (source_root / "lib.rs").write_text(
            "pub fn height() -> u64 { 1 }\n", encoding="utf-8",
        )
        (project / "Cargo.toml").write_text(
            "[package]\nname='fixture'\nversion='0.1.0'\n", encoding="utf-8",
        )
    implementation = _implementation(project.parent / "implementation")
    config["_audit_snapshot"] = snapshot_api.build_audit_snapshot(config, implementation)
    args = {
        "backend": "codex", "transport": "posix-v2-compat",
        "effective_model": "gpt-5.6-sol",
        "working_directory": str(project), "source_root": str(project),
        "tool_policy": ["read-bound-inputs-and-source", "write-assigned-staging-only"],
        "environment_allowlist_digest": environment_allowlist_sha256(()),
        "adjudicator_identity": "independent-severity-adjudicator",
        "invocation_prefix": "zero-reconciliation-component",
        "timeout_seconds_per_worker": 30,
        "max_items_per_worker": 4, "max_weight_per_worker": 8,
        "max_context_bytes_per_worker": 65_536,
    }
    if not publish:
        captured = capture_severity_planning_inputs(
            scratchpad=root, project_root=project,
            implementation_root=implementation, config=config,
        )
        _manifest, _plan, outputs = work.derive_adjudication_work(
            root, run_id=RUN_ID,
            audit_snapshot_digest=captured["audit_snapshot_digest"],
            audit_config_digest=captured["audit_config_digest"],
            methodology_files=captured["methodology_files"],
            source_ledger_path=SOURCE_LEDGER_INPUT,
            expected_source_ledger_digest=captured["source_ledger_digest"],
            **args,
        )
        for name, raw in outputs.items():
            (root / name).write_bytes(raw)
        return outputs
    plan = run_severity_planning(
        scratchpad=root, project_root=project,
        implementation_root=implementation, config=config, planning_args=args,
    )
    assert plan["denominator_count"] == 0
    assert plan["launch_count"] == 0
    return {
        name: (root / name).read_bytes()
        for name in (work.MANIFEST_NAME, work.WORK_PLAN_NAME)
    }


def _fixture(tmp_path: Path, *, pipeline: str = "sc"):
    project = tmp_path / "project"
    project.mkdir()
    root = project / ".scratchpad"
    root.mkdir()
    config = _config(project, root, pipeline=pipeline)
    _publish_queue(project, root, pipeline=pipeline, run_id=RUN_ID)
    assert run_empty_severity_source(
        scratchpad=root, project_root=project, config=config
    ) is True
    planning = _publish_component_planning(project, root, config)
    inputs = {name: (root / name).read_bytes() for name in INPUT_NAMES}
    return project, root, config, planning, inputs


def _run(project: Path, root: Path, config: dict[str, object], *, fault_hook=None):
    return run_zero_severity_reconciliation(
        scratchpad=root,
        project_root=project,
        config=config,
        fault_hook=fault_hook,
    )


def _unit(root: Path):
    matches = [
        row
        for key, row in read_artifact_ledger(root)["work_units"].items()
        if key.endswith("/severity_adjudication_shadow/reconcile_empty")
    ]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_zero_plan_commits_exact_reconciliation_and_replays_without_rewrite(
    tmp_path: Path, pipeline: str,
) -> None:
    project, root, config, _planning, inputs = _fixture(
        tmp_path, pipeline=pipeline
    )
    output = root / OUTPUT_NAME

    assert _run(project, root, config) is True
    expected = work.build_adjudication_work_reconciliation(root)
    expected_raw = (
        json.dumps(expected, ensure_ascii=False, allow_nan=False,
                   sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    assert output.read_bytes() == expected_raw
    assert expected["schema_version"] == (
        "plamen.severity_adjudication_reconciliation.v1"
    )
    assert expected["denominator_count"] == 0
    assert expected["denominator_ids"] == []
    assert expected["states"] == {}
    assert expected["all_terminal"] is True
    assert expected["all_resolved"] is True

    unit = _unit(root)
    assert unit["run_id"] == RUN_ID
    assert unit["model_invoked"] is False
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"
    assert set(unit["input_bindings"]) == {
        f"scratchpad:{name}" for name in INPUT_NAMES
    }
    manifest = unit["contract_manifest"]
    assert [row["identity"] for row in manifest["outputs"]] == [
        f"scratchpad:{OUTPUT_NAME}"
    ]
    assert manifest["outputs"][0]["schema_version"] == (
        "plamen.severity_adjudication_reconciliation.v1"
    )

    frozen = output.read_bytes()
    frozen_mtime = output.stat().st_mtime_ns
    frozen_ledger = (root / LEDGER_NAME).read_bytes()
    assert _run(project, root, config) is True
    assert output.read_bytes() == frozen
    assert output.stat().st_mtime_ns == frozen_mtime
    assert (root / LEDGER_NAME).read_bytes() == frozen_ledger
    assert {name: (root / name).read_bytes() for name in INPUT_NAMES} == inputs


@pytest.mark.parametrize("fault_point", FAULT_POINTS)
def test_every_fault_prefix_recovers_exactly(
    tmp_path: Path, fault_point: str,
) -> None:
    project, root, config, _planning, inputs = _fixture(tmp_path)
    fired = False

    def crash(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError(f"fault:{point}")

    with pytest.raises(RuntimeError, match=f"fault:{fault_point}"):
        _run(project, root, config, fault_hook=crash)
    assert fired is True
    assert _run(project, root, config) is True
    assert json.loads((root / OUTPUT_NAME).read_bytes()) == (
        work.build_adjudication_work_reconciliation(root)
    )
    assert {name: (root / name).read_bytes() for name in INPUT_NAMES} == inputs
    assert _unit(root)["execution_state"] == "OUTPUT_COMMITTED"


@pytest.mark.parametrize(
    "name",
    (
        "severity_adjudication_worker_run.zero.json",
        "verify_H-STALE.severity_adjudication_proposal.json",
        "Verify_H-UPPER.severity_adjudication_receipt.json",
    ),
)
def test_stale_worker_transaction_files_refuse_zero_reconciliation(
    tmp_path: Path, name: str,
) -> None:
    project, root, config, _planning, _inputs = _fixture(tmp_path)
    stale = root / name
    stale.write_bytes(b"{}\n")
    with pytest.raises(
        ArtifactLedgerError,
        match=(
            "refuses stale worker|unassigned worker-run receipt"
            "|unassigned adjudication output"
        ),
    ):
        _run(project, root, config)
    assert stale.read_bytes() == b"{}\n"
    assert not (root / OUTPUT_NAME).exists()


@pytest.mark.parametrize("damage", ("missing", "tampered"))
def test_committed_output_damage_is_rejected_without_repair(
    tmp_path: Path, damage: str,
) -> None:
    project, root, config, _planning, _inputs = _fixture(tmp_path)
    assert _run(project, root, config) is True
    output = root / OUTPUT_NAME
    if damage == "missing":
        output.unlink()
    else:
        os.chmod(output, 0o600)
        output.write_bytes(b"{}\n")
    with pytest.raises(ArtifactLedgerError):
        _run(project, root, config)
    if damage == "missing":
        assert not output.exists()
    else:
        assert output.read_bytes() == b"{}\n"


@pytest.mark.parametrize("case", ("malformed", "unowned", "foreign_run"))
def test_invalid_planning_inputs_fail_before_reconciliation_arm(
    tmp_path: Path, case: str,
) -> None:
    if case == "unowned":
        project = tmp_path / "project"
        project.mkdir()
        root = project / ".scratchpad"
        root.mkdir()
        config = _config(project, root)
        _publish_queue(project, root, run_id=RUN_ID)
        assert run_empty_severity_source(
            scratchpad=root, project_root=project, config=config
        ) is True
        _publish_component_planning(project, root, config, publish=False)
    else:
        project, root, config, _planning, _inputs = _fixture(tmp_path)
        if case == "malformed":
            (root / work.MANIFEST_NAME).write_bytes(b"{}\n")
        else:
            config = dict(config)
            config["_run_id"] = "87654321-4321-4321-8321-cba987654321"
    with pytest.raises((ArtifactLedgerError, work.AdjudicationWorkError)):
        _run(project, root, config)
    assert not (root / OUTPUT_NAME).exists()
    assert not any(
        key.endswith("/severity_adjudication_shadow/reconcile_empty")
        for key in read_artifact_ledger(root)["work_units"]
    )


@pytest.mark.parametrize("kind", ("file", "symlink"))
def test_fresh_foreign_output_collision_is_rejected(
    tmp_path: Path, kind: str,
) -> None:
    project, root, config, _planning, _inputs = _fixture(tmp_path)
    output = root / OUTPUT_NAME
    if kind == "file":
        output.write_bytes(b"foreign\n")
    else:
        output.symlink_to("missing-target")
    with pytest.raises(ArtifactLedgerError, match="foreign output"):
        _run(project, root, config)


def test_stale_worker_file_appearing_after_arm_prevents_commit(
    tmp_path: Path,
) -> None:
    project, root, config, _planning, _inputs = _fixture(tmp_path)
    stale = root / "Verify_H-RACE.severity_adjudication_proposal.json"

    def inject(point: str) -> None:
        if point == "after_output_1":
            stale.write_bytes(b"{}\n")

    with pytest.raises(ArtifactLedgerError, match="refuses stale worker"):
        _run(project, root, config, fault_hook=inject)
    assert stale.is_file()
    assert (root / OUTPUT_NAME).is_file()
    unit = _unit(root)
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["semantic_status"] == "INPUTS_BOUND"
