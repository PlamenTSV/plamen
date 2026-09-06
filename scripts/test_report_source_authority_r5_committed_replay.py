"""R5 RED fixtures for committed report-source producer replay.

The source capture and its PhaseIO requirements are deliberately committed as
one circular, internally consistent story.  Public consumers must derive the
requirements again from the live producer ledger and trusted run config rather
than accept that story as authority.
"""
from __future__ import annotations

from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from audit_snapshot import (  # noqa: E402
    build_production_source_path_authority,
    canonical_production_source_path_authority_bytes,
)
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
)
import report_assembly_capture as codec  # noqa: E402
import report_capture_phaseio_authority as RCA  # noqa: E402
from test_report_source_authority_r3_repair import (  # noqa: E402
    DIMS,
    RUN_ID,
    _commit_contract,
    _fixture,
    _generic_commit,
    _input_requirement,
    _launch,
)


def _bound_metadata(config: dict, metadata: dict[str, str]) -> dict[str, str]:
    authority = build_production_source_path_authority(
        config, config["_audit_snapshot"]
    )
    return {
        **metadata,
        "source_roster_authority_sha256": authority["authority_digest"],
    }


def _generic_multi_commit(
    project: Path,
    scratch: Path,
    outputs: dict[str, bytes],
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = "sc/thorough/evm/claude/report_fixture/r5_generic"
    contract = PhaseIOContract(
        **DIMS,
        phase="report_fixture",
        work_unit_id="r5_generic",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
            )
            for relative in sorted(outputs)
        ),
        model_invoked=False,
    )
    launch = _launch(contract)
    _commit_contract(project, scratch, contract, launch, outputs)
    return contract, launch


def _registered_report_index_commit(
    project: Path,
    scratch: Path,
) -> tuple[PhaseIOContract, LaunchSpec]:
    contract = resolve_phase_io_contract(
        **DIMS,
        phase="report_index",
        work_unit_id="mechanical",
        exact_inputs=(
            "dedup_decisions.md",
            "finding_mapping.md",
            "verification_queue.md",
        ),
        exact_outputs=("report_coverage.md", "report_index.md"),
    )
    for identity in contract.immutable_inputs:
        _root, relative = identity.split(":", 1)
        (scratch / relative).write_bytes(b"# Input\n")
    launch = _launch(contract)
    _commit_contract(
        project,
        scratch,
        contract,
        launch,
        {
            "report_coverage.md": b"# Coverage\n",
            "report_index.md": b"# Index\n",
        },
    )
    return contract, launch


def _commit_circular_capture(
    project: Path,
    scratch: Path,
    config: dict,
    metadata: dict[str, str],
    producer: PhaseIOContract,
    producer_launch: LaunchSpec,
    *,
    fixed: dict[str, str],
    namespaces: dict[str, str],
) -> bytes:
    payload = codec._capture_report_assembly_source(
        scratch,
        metadata=_bound_metadata(config, metadata),
        fixed_source_roles=fixed,
        namespace_roles=namespaces,
    )
    raw = codec._canonical_report_assembly_source_capture_bytes(payload)
    requirements = {
        relative: _input_requirement(
            producer,
            producer_launch,
            relative,
            "DRIVER",
        )
        for relative in payload["input_paths"]
    }
    contract = resolve_phase_io_contract(
        **DIMS,
        phase="report_assemble",
        work_unit_id="source_capture",
        exact_inputs=tuple(payload["input_paths"]),
        exact_outputs=("report_assembly_source_capture.json",),
        exact_input_authorities=requirements,
    )
    _commit_contract(
        project,
        scratch,
        contract,
        _launch(contract),
        {"report_assembly_source_capture.json": raw},
    )
    return raw


def _reserved_attack(tmp_path: Path):
    project, scratch, config, snapshot, metadata = _fixture(tmp_path)
    authority = build_production_source_path_authority(config, snapshot)
    raw = canonical_production_source_path_authority_bytes(
        authority,
        expected_snapshot=snapshot,
        expected_config=config,
    )
    producer, launch = _generic_multi_commit(
        project,
        scratch,
        {"report_source_path_authority.json": raw},
    )
    capture = _commit_circular_capture(
        project,
        scratch,
        config,
        metadata,
        producer,
        launch,
        fixed={
            "report_source_path_authority.json": (
                "PRODUCTION_SOURCE_PATH_AUTHORITY"
            )
        },
        namespaces={},
    )
    return project, scratch, config, capture, "report_source_path_authority"


def _fixed_attack(tmp_path: Path):
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    producer, launch = _generic_multi_commit(
        project, scratch, {"report_index.md": b"# Index\n"}
    )
    capture = _commit_circular_capture(
        project,
        scratch,
        config,
        metadata,
        producer,
        launch,
        fixed={"report_index.md": "REPORT_INDEX"},
        namespaces={},
    )
    return project, scratch, config, capture, "report_index.md"


def _namespace_attack(tmp_path: Path):
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    relative = "report_semantic_fixture.md"
    producer, launch = _generic_multi_commit(
        project, scratch, {relative: b"# Semantic\n"}
    )
    capture = _commit_circular_capture(
        project,
        scratch,
        config,
        metadata,
        producer,
        launch,
        fixed={},
        namespaces={
            "report_semantic_*.md": "REPORT_SEMANTIC_NAMESPACE"
        },
    )
    return project, scratch, config, capture, relative


def _blocked_attack(tmp_path: Path):
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    inventory = RCA.report_source_policy_inventory()
    blocked = [row for row in inventory if row["blocker"]]
    assert len(blocked) == 10
    fixed = {
        row["selector"]: row["role"]
        for row in blocked
        if row["kind"] == "FIXED"
    }
    namespaces = {
        row["selector"]: row["role"]
        for row in blocked
        if row["kind"] == "NAMESPACE"
    }
    outputs = {
        relative: (
            b"{}\n" if relative.endswith(".json") else b"# Blocked\n"
        )
        for relative in fixed
    }
    outputs["judge_fixture.md"] = b"# Blocked judge\n"
    outputs[
        "negative_closure_provider_bundles/provider/finding.json"
    ] = b"{}\n"
    producer, launch = _generic_multi_commit(project, scratch, outputs)
    capture = _commit_circular_capture(
        project,
        scratch,
        config,
        metadata,
        producer,
        launch,
        fixed=fixed,
        namespaces=namespaces,
    )
    return project, scratch, config, capture, "_coverage_shortfalls.json"


@pytest.mark.parametrize(
    "builder",
    (_reserved_attack, _fixed_attack, _namespace_attack, _blocked_attack),
)
def test_committed_capture_rederives_live_producer_policy(
    tmp_path: Path,
    builder,
) -> None:
    project, scratch, config, _capture, marker = builder(tmp_path)
    consumers = (
        lambda: RCA.load_committed_report_source_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
        ),
        lambda: RCA.extract_committed_report_source_inputs(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
        ),
        lambda: RCA.build_report_final_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            derived_outputs={
                "project:AUDIT_REPORT.md": ("CLIENT_REPORT", b"# Audit\n"),
                "scratchpad:report_quality.md": (
                    "REPORT_QUALITY",
                    b"# Quality\n",
                ),
            },
        ),
        lambda: RCA.validate_report_final_candidate_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            final_capture_bytes=b"{}\n",
        ),
        lambda: RCA.load_committed_report_final_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
        ),
        lambda: RCA.extract_committed_report_outputs(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
        ),
        lambda: RCA.prepare_committed_report_publication(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
        ),
    )
    for consumer in consumers:
        with pytest.raises(ValueError, match=marker):
            consumer()


def test_source_candidate_rejects_same_circular_requirements(
    tmp_path: Path,
) -> None:
    project, scratch, config, capture, marker = _fixed_attack(tmp_path)
    with pytest.raises(ValueError, match=marker):
        RCA.validate_report_source_candidate_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
            source_capture_bytes=capture,
        )


def test_terminal_live_replay_rejects_producer_successor_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratch, config, _snapshot, metadata = _fixture(tmp_path)
    producer, launch = _registered_report_index_commit(project, scratch)
    _commit_circular_capture(
        project,
        scratch,
        config,
        metadata,
        producer,
        launch,
        fixed={"report_index.md": "REPORT_INDEX"},
        namespaces={},
    )
    original = codec._replay_report_assembly_source_capture
    calls = 0

    def attacked(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            _generic_commit(
                project,
                scratch,
                "report_index.md",
                b"# Index\n",
                writer="DRIVER",
            )
        return result

    monkeypatch.setattr(
        codec, "_replay_report_assembly_source_capture", attacked
    )
    with pytest.raises(ValueError, match="report_index.md|producer|drift"):
        RCA.load_committed_report_source_capture_bytes(
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            expected_config=config,
        )
