"""Fixture-first P1/P2 tests for authoritative report-source capture."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from artifact_ledger import (  # noqa: E402
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from audit_snapshot import (  # noqa: E402
    build_audit_snapshot,
    build_production_source_path_authority,
)
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
)
import report_capture_phaseio_authority as RCA  # noqa: E402


RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
DIMS = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}
_CONFIG_BY_SCRATCH: dict[Path, dict[str, object]] = {}


def _implementation(root: Path) -> Path:
    for directory in ("scripts", "prompts", "rules", "agents"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "plamen_driver.py").write_text("VERSION = 1\n")
    (root / "prompts" / "phase.md").write_text("method v1\n")
    (root / "rules" / "rule.md").write_text("rule v1\n")
    return root


def _config(scratch: Path) -> dict[str, object]:
    return _CONFIG_BY_SCRATCH[scratch.resolve()]


def _metadata(scratch: Path) -> dict[str, str]:
    config = _config(scratch)
    snapshot = config["_audit_snapshot"]
    return {
        **DIMS,
        "project_name": "fixture-project",
        "report_date": "2026-08-04",
        "run_id": RUN_ID,
        "scope": "contracts/",
        "source_snapshot_sha256": snapshot["snapshot_digest"],
    }


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    (project / "src").mkdir(parents=True)
    (project / "src" / "Vault.sol").write_text("contract Vault {}\n")
    scratch.mkdir(parents=True)
    config: dict[str, object] = {
        "project_root": str(project),
        "scratchpad": str(scratch),
        "mode": "thorough",
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "_run_id": RUN_ID,
    }
    config["_audit_snapshot"] = build_audit_snapshot(
        config, _implementation(tmp_path / "plamen")
    )
    _CONFIG_BY_SCRATCH[scratch.resolve()] = config
    return project, scratch


def _launch(contract: PhaseIOContract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        **DIMS,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )


def _commit_sources(
    project: Path,
    scratch: Path,
    sources: dict[str, bytes],
) -> tuple[PhaseIOContract, LaunchSpec]:
    if not set(sources) <= {"report_index.md", "report_coverage.md"}:
        raise ValueError("fixture source is outside the registered report-index roster")
    contract = resolve_phase_io_contract(
        **DIMS,
        phase="report_index",
        work_unit_id="mechanical",
        exact_inputs=(),
        exact_outputs=("report_coverage.md", "report_index.md"),
    )
    launch = _launch(contract)
    for identity in contract.immutable_inputs:
        _root, relative = identity.split(":", 1)
        target = scratch / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"# Input\n")
    record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    complete_sources = {
        "report_coverage.md": b"# Coverage\n",
        "report_index.md": b"# Index\n",
        **sources,
    }
    for path, raw in complete_sources.items():
        target = scratch / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    return contract, launch


def _commit_generic_sources(
    project: Path,
    scratch: Path,
    sources: dict[str, bytes],
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = "sc/thorough/evm/claude/report_fixture/producer"
    contract = PhaseIOContract(
        **DIMS,
        phase="report_fixture",
        work_unit_id="producer",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=path,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
            )
            for path in sorted(sources)
        ),
        model_invoked=False,
    )
    launch = _launch(contract)
    record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    for path, raw in sources.items():
        target = scratch / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    return contract, launch


def test_prepare_source_capture_derives_exact_current_producer_authority(
    tmp_path: Path,
) -> None:
    project, scratch = _roots(tmp_path)
    producer, producer_launch = _commit_sources(
        project,
        scratch,
        {
            "report_index.md": b"# Index\n",
        },
    )

    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(scratch),
        metadata=_metadata(scratch),
        fixed_source_roles={"report_index.md": "REPORT_INDEX"},
        namespace_roles={},
    )

    assert prepared.exact_input_paths == (
        "report_index.md",
    )
    requirements = {
        row.identity: row
        for row in prepared.contract.input_authority_requirements
    }
    assert set(requirements) == {
        "scratchpad:report_index.md",
    }
    for requirement in requirements.values():
        assert requirement.allow_raw is False
        assert requirement.expected_producer_work_unit_key == producer.key
        assert requirement.expected_contract_digest == producer.digest
        assert requirement.expected_launch_digest == producer_launch.digest
        assert requirement.require_same_run is True
        assert requirement.require_exact_contract is True
        assert requirement.require_exact_launch is True


def test_prepare_source_capture_rejects_unowned_raw_markdown(
    tmp_path: Path,
) -> None:
    project, scratch = _roots(tmp_path)
    (scratch / "report_index.md").write_bytes(b"# Raw index\n")

    with pytest.raises(ValueError, match="binding|producer|authority|RAW"):
        RCA.prepare_report_source_capture(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            metadata=_metadata(scratch),
            fixed_source_roles={"report_index.md": "REPORT_INDEX"},
            namespace_roles={},
        )


def test_source_candidate_validation_rejects_late_namespace_gain_after_arm(
    tmp_path: Path,
) -> None:
    project, scratch = _roots(tmp_path)
    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(scratch),
        metadata=_metadata(scratch),
        fixed_source_roles={},
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    record_work_unit_inputs(
        scratch,
        project,
        prepared.contract,
        prepared.launch,
        run_id=RUN_ID,
    )
    (scratch / "report_semantic_late.md").write_bytes(b"# Late debt\n")

    with pytest.raises(ValueError, match="NAMESPACE|SOURCE|drift"):
        RCA.validate_report_source_candidate_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            source_capture_bytes=prepared.capture_bytes,
            expected_contract=prepared.contract,
            expected_launch=prepared.launch,
        )


def test_committed_source_load_and_extraction_return_frozen_exact_inputs(
    tmp_path: Path,
) -> None:
    project, scratch = _roots(tmp_path)
    _commit_sources(
        project,
        scratch,
        {"report_index.md": b"# Index\n"},
    )
    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(scratch),
        metadata=_metadata(scratch),
        fixed_source_roles={
            "report_index.md": "REPORT_INDEX",
            "report_medium.md": "TIER_MEDIUM",
        },
        namespace_roles={},
    )
    record_work_unit_inputs(
        scratch,
        project,
        prepared.contract,
        prepared.launch,
        run_id=RUN_ID,
    )
    (scratch / "report_assembly_source_capture.json").write_bytes(
        prepared.capture_bytes
    )
    record_work_unit_artifacts(
        scratch,
        project,
        prepared.contract,
        prepared.launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )

    assert RCA.load_committed_report_source_capture_bytes(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(scratch),
    ) == prepared.capture_bytes
    extracted = RCA.extract_committed_report_source_inputs(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(scratch),
    )
    assert [(row.path, row.content) for row in extracted.inputs] == [
        ("report_index.md", b"# Index\n")
    ]
    assert extracted.explicit_absences == ("report_medium.md",)
    assert extracted.namespace_rosters == ()
    with pytest.raises((AttributeError, TypeError)):
        extracted.inputs[0].content = b"mutated"  # type: ignore[misc]


def test_source_candidate_bytes_are_canonical_and_bound_to_expected_launch(
    tmp_path: Path,
) -> None:
    project, scratch = _roots(tmp_path)
    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=_config(scratch),
        metadata=_metadata(scratch),
        fixed_source_roles={},
        namespace_roles={},
    )
    payload = json.loads(prepared.capture_bytes.decode("utf-8"))
    noncanonical = json.dumps(payload, indent=2).encode("utf-8")
    with pytest.raises(ValueError, match="canonical"):
        RCA.validate_report_source_candidate_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=_config(scratch),
            source_capture_bytes=noncanonical,
            expected_contract=prepared.contract,
            expected_launch=prepared.launch,
        )


def test_typed_human_review_transaction_owns_present_and_absent_sections(
    tmp_path: Path,
) -> None:
    project, scratch = _roots(tmp_path)
    _commit_sources(
        project,
        scratch,
        {
            "report_coverage.md": b"# Coverage\n",
            "report_index.md": b"# Index\n",
        },
    )
    import plamen_driver as driver

    config = _config(scratch)
    assert driver._run_report_human_review_authority_transaction(
        scratch,
        config,
        severity_review_bytes=None,
        retention_review_bytes=b"# Retention review\n",
    ) == []
    assert (scratch / "report_human_review_authority.json").is_file()
    assert (scratch / "report_semantic_retention_risks.md").read_bytes() == (
        b"# Retention review\n"
    )
    assert not (scratch / "report_semantic_severity_repairs.md").exists()

    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        expected_config=config,
        metadata=_metadata(scratch),
        fixed_source_roles={
            "report_human_review_authority.json": (
                "REPORT_HUMAN_REVIEW_AUTHORITY"
            ),
            "report_semantic_severity_repairs.md": "SEVERITY_REVIEW_DEBT",
        },
        namespace_roles={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    assert set(prepared.exact_input_paths) == {
        "report_human_review_authority.json",
        "report_semantic_retention_risks.md",
    }
    assert prepared.explicit_absences == (
        "report_semantic_severity_repairs.md",
    )
    assert all(
        not requirement.allow_raw
        for requirement in prepared.contract.input_authority_requirements
    )
